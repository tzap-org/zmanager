//! Native single-cabinet reader built on the maintained `cab` crate.

use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use time::PrimitiveDateTime;

/// One normalized cabinet file entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CabEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Cabinet file name.
    pub path: String,
    source_name: String,
    /// Uncompressed file size.
    pub size: u64,
    /// Portable mode derived from cabinet attributes.
    pub mode: u32,
    /// Cabinet timestamp represented as Unix seconds when valid.
    pub modified: Option<String>,
}

/// Normalized CAB operation report.
pub type CabReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by native cabinet operations.
#[derive(Debug)]
pub enum CabError {
    /// Filesystem or cabinet parser I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The cabinet uses a shape this adapter cannot safely materialize.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected a file.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for CabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid CAB {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected cabinet file: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for CabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for CabError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists files in a single cabinet.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<CabEntry>, CabError> {
    let path = path.as_ref();
    let cabinet = open(path)?;
    collect_entries(&cabinet, path)
}

/// Reads selected or all cabinet files to verify their compressed streams.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<CabReport, CabError> {
    let path = path.as_ref();
    let mut cabinet = open(path)?;
    let entries = collect_entries(&cabinet, path)?;
    let mut report = CabReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(CabError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let mut reader = cabinet.read_file(&entry.source_name).map_err(|source| io_error(path, source))?;
        let bytes = io::copy(&mut reader, &mut io::sink()).map_err(|source| io_error(path, source))?;
        if bytes != entry.size {
            return Err(invalid(path, format!("CAB file {} decoded to {bytes} bytes, expected {}", entry.path, entry.size)));
        }
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(bytes);
    }
    Ok(report)
}

/// Extracts all cabinet files through the shared safety and atomic-output path.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<CabReport, CabError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let mut cabinet = open(path)?;
    let entries = collect_entries(&cabinet, path)?;
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = CabReport::default();
    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(CabError::Cancelled);
        }
        let safety_entry =
            ExtractionEntry { archive_path: entry.path.clone(), kind: ExtractionEntryKind::File, uncompressed_size: Some(entry.size), compressed_size: None };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        let mut reader = cabinet.read_file(&entry.source_name).map_err(|source| io_error(path, source))?;
        let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
        let bytes = io::copy(&mut reader, output.file_mut().map_err(|source| io_error(&destination_path, source))?)
            .map_err(|source| io_error(&destination_path, source))?;
        output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
        apply_metadata(&destination_path, &entry)?;
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(bytes);
    }
    Ok(report)
}

/// Copies one retained cabinet file to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, CabError> {
    let path = path.as_ref();
    let mut cabinet = open(path)?;
    let entries = collect_entries(&cabinet, path)?;
    let entry = entries.get(entry_index).ok_or_else(|| invalid(path, "retained CAB entry ID is not present"))?;
    let mut reader = cabinet.read_file(&entry.source_name).map_err(|source| io_error(path, source))?;
    io::copy(&mut reader, writer).map_err(|source| io_error(path, source))
}

/// Copies one retained CAB file by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, CabError> {
    let path = path.as_ref();
    let mut occurrence = 0_usize;
    let entry_index = list(path)?
        .into_iter()
        .find_map(|entry| {
            if entry.path != selected_path {
                return None;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches.then_some(entry.index)
        })
        .ok_or_else(|| invalid(path, "retained CAB entry is not present"))?;
    copy(path, entry_index, writer)
}

fn open(path: &Path) -> Result<cab::Cabinet<File>, CabError> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    cab::Cabinet::new(file).map_err(|source| io_error(path, source))
}

fn collect_entries<R: io::Read + io::Seek>(cabinet: &cab::Cabinet<R>, path: &Path) -> Result<Vec<CabEntry>, CabError> {
    if cabinet.cabinet_set_index() != 0 {
        return Err(invalid(path, "multi-cabinet sets are not supported by the native adapter"));
    }
    let mut entries = Vec::new();
    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            let normalized_path = crate::safety::normalize_archive_path(file.name())?;
            if entries.iter().any(|entry: &CabEntry| entry.path == normalized_path) {
                return Err(invalid(path, format!("CAB contains duplicate file name {}", file.name())));
            }
            entries.push(CabEntry {
                index: entries.len(),
                path: normalized_path,
                source_name: file.name().to_owned(),
                size: u64::from(file.uncompressed_size()),
                mode: cab_mode(file),
                modified: file.datetime().map(datetime_seconds),
            });
        }
    }
    Ok(entries)
}

fn cab_mode(file: &cab::FileEntry) -> u32 {
    if file.is_exec() {
        0o755
    } else if file.is_read_only() {
        0o444
    } else {
        0o644
    }
}

fn datetime_seconds(value: PrimitiveDateTime) -> String {
    value.assume_utc().unix_timestamp().to_string()
}

fn apply_metadata(path: &Path, entry: &CabEntry) -> Result<(), CabError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(entry.mode)).map_err(|source| io_error(path, source))?;
    }
    if let Some(seconds) = entry.modified.as_deref().and_then(|value| value.parse::<i64>().ok()) {
        filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(seconds, 0)).map_err(|source| io_error(path, source))?;
    }
    Ok(())
}

fn invalid(path: &Path, message: impl Into<String>) -> CabError {
    CabError::Invalid { path: path.to_path_buf(), message: message.into() }
}

fn io_error(path: &Path, source: io::Error) -> CabError {
    CabError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs;

    fn build_uncompressed_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cab = Vec::new();
        let num_files = files.len() as u16;

        let header_len = 36_usize;
        let folder_len = 8_usize;
        let mut file_entries_len = 0_usize;
        for &(name, _) in files {
            file_entries_len += 16 + name.len() + 1;
        }

        let first_data_offset = (header_len + folder_len + file_entries_len) as u32;

        let mut data_blocks = Vec::new();

        // Single data block containing concatenated file data
        let mut block_data = Vec::new();
        for &(_, data) in files {
            block_data.extend_from_slice(data);
        }

        let block_len = 8 + block_data.len();
        let mut block_bytes = Vec::with_capacity(block_len);
        block_bytes.extend_from_slice(&0_u32.to_le_bytes()); // checksum
        block_bytes.extend_from_slice(&(block_data.len() as u16).to_le_bytes()); // comp size
        block_bytes.extend_from_slice(&(block_data.len() as u16).to_le_bytes()); // uncomp size
        block_bytes.extend_from_slice(&block_data);
        data_blocks.extend_from_slice(&block_bytes);

        let total_cab_size = (first_data_offset as usize + data_blocks.len()) as u32;

        // 1. CFHEADER (36 bytes)
        cab.extend_from_slice(b"MSCF"); // 0..4
        cab.extend_from_slice(&0_u32.to_le_bytes()); // 4..8 reserved
        cab.extend_from_slice(&total_cab_size.to_le_bytes()); // 8..12 total size
        cab.extend_from_slice(&0_u32.to_le_bytes()); // 12..16 reserved
        cab.extend_from_slice(&((header_len + folder_len) as u32).to_le_bytes()); // 16..20 files offset
        cab.extend_from_slice(&0_u32.to_le_bytes()); // 20..24 reserved
        cab.extend_from_slice(&0x0103_u16.to_le_bytes()); // 24..26 version 1.3
        cab.extend_from_slice(&1_u16.to_le_bytes()); // 26..28 num folders
        cab.extend_from_slice(&num_files.to_le_bytes()); // 28..30 num files
        cab.extend_from_slice(&0_u16.to_le_bytes()); // 30..32 flags
        cab.extend_from_slice(&1234_u16.to_le_bytes()); // 32..34 set ID
        cab.extend_from_slice(&0_u16.to_le_bytes()); // 34..36 cabinet index (0)

        // 2. CFFOLDER (8 bytes)
        cab.extend_from_slice(&first_data_offset.to_le_bytes()); // data offset
        cab.extend_from_slice(&1_u16.to_le_bytes()); // number of data blocks (1)
        cab.extend_from_slice(&0_u16.to_le_bytes()); // comp type: NONE

        // 3. CFFILE entries
        let mut current_offset_in_folder = 0_u32;
        for &(name, data) in files {
            cab.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp size
            cab.extend_from_slice(&current_offset_in_folder.to_le_bytes()); // folder offset
            cab.extend_from_slice(&0_u16.to_le_bytes()); // folder index (0)
            cab.extend_from_slice(&0x5a21_u16.to_le_bytes()); // date
            cab.extend_from_slice(&0x6000_u16.to_le_bytes()); // time
            cab.extend_from_slice(&0x20_u16.to_le_bytes()); // attr: archive
            cab.extend_from_slice(name.as_bytes());
            cab.push(0); // null terminator
            current_offset_in_folder += data.len() as u32;
        }

        // 4. CFDATA
        cab.extend_from_slice(&data_blocks);
        cab
    }

    #[test]
    fn test_cab_list_test_extract_and_copy() {
        let temp = TestDir::new("cab-backend-test");
        let archive_path = temp.path("sample.cab");

        let cab_bytes = build_uncompressed_cab(&[("hello.txt", b"Hello, CAB world!\n"), ("notes.txt", b"Cabinet documentation")]);
        fs::write(&archive_path, cab_bytes).unwrap();

        // 1. List
        let entries = list(&archive_path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "hello.txt");
        assert_eq!(entries[0].size, 18);
        assert_eq!(entries[1].path, "notes.txt");
        assert_eq!(entries[1].size, 21);

        // 2. Test
        let test_report = test(&archive_path, &TestOptions::default()).unwrap();
        assert_eq!(test_report.entries, 2);
        assert_eq!(test_report.bytes, 18 + 21);

        // Test with selection
        let sel_opts = TestOptions { selected_paths: vec!["hello.txt".to_string()], ..TestOptions::default() };
        let sel_report = test(&archive_path, &sel_opts).unwrap();
        assert_eq!(sel_report.entries, 1);
        assert_eq!(sel_report.skipped_entries, 1);

        // 3. Extract
        let dest = temp.path("out");
        let extract_report = extract(&archive_path, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(extract_report.entries, 2);
        assert_eq!(fs::read(dest.join("hello.txt")).unwrap(), b"Hello, CAB world!\n");
        assert_eq!(fs::read(dest.join("notes.txt")).unwrap(), b"Cabinet documentation");

        // 4. Copy by index
        let mut copied = Vec::new();
        let bytes_copied = copy(&archive_path, 0, &mut copied).unwrap();
        assert_eq!(bytes_copied, 18);
        assert_eq!(copied, b"Hello, CAB world!\n");

        // 5. Copy by path occurrence
        let mut copied_occ = Vec::new();
        let bytes_occ = copy_by_path_occurrence(&archive_path, "notes.txt", 0, &mut copied_occ).unwrap();
        assert_eq!(bytes_occ, 21);
        assert_eq!(copied_occ, b"Cabinet documentation");
    }

    #[test]
    fn test_cab_error_handling() {
        let temp = TestDir::new("cab-backend-errors");
        let non_existent = temp.path("missing.cab");
        assert!(list(&non_existent).is_err());
        assert!(test(&non_existent, &TestOptions::default()).is_err());
        assert!(extract(&non_existent, temp.path("out"), ExtractionPolicy::default(), None, None).is_err());
        assert!(copy(&non_existent, 0, &mut Vec::new()).is_err());

        // Corrupt file
        let corrupt = temp.path("corrupt.cab");
        fs::write(&corrupt, b"not a cab archive").unwrap();
        assert!(list(&corrupt).is_err());

        // Error types & Display coverage
        let inv_err = CabError::Invalid { path: PathBuf::from("a.cab"), message: "corrupt".to_string() };
        assert!(inv_err.to_string().contains("invalid CAB"));
        assert!(std::error::Error::source(&inv_err).is_none());

        let io_err = CabError::Io { path: PathBuf::from("b.cab"), source: io::Error::new(io::ErrorKind::NotFound, "err") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());

        let cancelled = CabError::Cancelled;
        assert_eq!(cancelled.to_string(), "job cancelled");

        let safety = CabError::Safety(ExtractionSafetyError::EmptyPath);
        assert!(safety.to_string().contains("extraction safety"));
        assert!(std::error::Error::source(&safety).is_some());
    }
}
