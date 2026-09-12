//! Native LHA/LZH reader backed by `delharc`.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// One normalized LHA entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LhaEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Normalized archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Whether the compression method is supported by `delharc`.
    pub supported: bool,
}

/// Normalized LHA operation report.
pub type LhaReport = crate::backend_impl::backend_report::BackendReport;

/// Native LHA operation error.
#[derive(Debug)]
pub enum LhaError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The archive or one of its members is malformed or unsupported.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for LhaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid LHA {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected LHA entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for LhaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for LhaError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries from an LHA/LZH archive.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<LhaEntry>, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut entries = Vec::new();
    loop {
        let header = reader.header().clone();
        let normalized = normalize_path(&header.parse_pathname_to_str())?;
        let kind = if header.is_directory() { BrowserEntryKind::Directory } else { BrowserEntryKind::File };
        if entries.iter().any(|entry: &LhaEntry| entry.path == normalized) {
            return Err(invalid(path, format!("duplicate path {normalized}")));
        }
        entries.push(LhaEntry {
            index: entries.len(),
            path: normalized,
            kind,
            size: header.original_size,
            supported: header.is_directory() || reader.is_decoder_supported(),
        });
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(entries)
}

/// Verifies selected LHA members and their CRC-16 values.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<LhaReport, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    let mut report = LhaReport::default();
    loop {
        if options.is_cancelled() {
            return Err(LhaError::Cancelled);
        }
        let header = reader.header().clone();
        let entry_path = normalize_path(&header.parse_pathname_to_str())?;
        if !options.selects(&entry_path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
        } else if header.is_directory() {
            report.entries = report.entries.saturating_add(1);
        } else {
            ensure_supported(path, &reader)?;
            let bytes = io::copy(&mut reader, &mut io::sink()).map_err(|source| io_error(path, source))?;
            reader.crc_check().map_err(|error| invalid(path, error))?;
            if bytes != header.original_size {
                return Err(invalid(path, format!("{entry_path} decoded to {bytes} bytes, expected {}", header.original_size)));
            }
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(bytes);
        }
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(report)
}

/// Extracts an LHA archive through the shared safety planner.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<LhaReport, LhaError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let mut reader = open(path)?;
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = LhaReport::default();
    loop {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(LhaError::Cancelled);
        }
        let header = reader.header().clone();
        let entry_path = normalize_path(&header.parse_pathname_to_str())?;
        let entry_kind = if header.is_directory() { ExtractionEntryKind::Directory } else { ExtractionEntryKind::File };
        let safety_entry = ExtractionEntry {
            archive_path: entry_path.clone(),
            kind: entry_kind,
            uncompressed_size: Some(header.original_size),
            compressed_size: Some(header.compressed_size),
        };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            if !reader.next_file().map_err(|error| invalid(path, error))? {
                break;
            }
            continue;
        };
        if header.is_directory() {
            if replace_existing {
                crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            }
            std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            report.entries = report.entries.saturating_add(1);
        } else {
            ensure_supported(path, &reader)?;
            let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            let bytes = io::copy(&mut reader, output.file_mut().map_err(|source| io_error(&destination_path, source))?)
                .map_err(|source| io_error(&destination_path, source))?;
            reader.crc_check().map_err(|error| invalid(path, error))?;
            if bytes != header.original_size {
                return Err(invalid(path, format!("{entry_path} decoded to {bytes} bytes, expected {}", header.original_size)));
            }
            output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(bytes);
        }
        if !reader.next_file().map_err(|error| invalid(path, error))? {
            break;
        }
    }
    Ok(report)
}

/// Copies one retained regular LHA file to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, LhaError> {
    let path = path.as_ref();
    let mut reader = open(path)?;
    for index in 0..=entry_index {
        if index != 0 && !reader.next_file().map_err(|error| invalid(path, error))? {
            return Err(invalid(path, "retained LHA entry ID is not present"));
        }
    }
    if reader.header().is_directory() {
        return Err(invalid(path, "retained LHA entry is not a regular file"));
    }
    ensure_supported(path, &reader)?;
    let expected = reader.header().original_size;
    let bytes = io::copy(&mut reader, writer).map_err(|source| io_error(path, source))?;
    reader.crc_check().map_err(|error| invalid(path, error))?;
    if bytes != expected {
        return Err(invalid(path, format!("decoded to {bytes} bytes, expected {expected}")));
    }
    Ok(bytes)
}

/// Copies one retained LHA file by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, LhaError> {
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
        .ok_or_else(|| invalid(path, "retained LHA entry is not present"))?;
    copy(path, entry_index, writer)
}

fn open(path: &Path) -> Result<delharc::LhaDecodeReader<File>, LhaError> {
    delharc::parse_file(path).map_err(|source| io_error(path, source))
}

fn ensure_supported(path: &Path, reader: &delharc::LhaDecodeReader<File>) -> Result<(), LhaError> {
    if reader.is_decoder_supported() {
        Ok(())
    } else {
        Err(invalid(path, format!("unsupported compression method {:?}", reader.header().compression_method())))
    }
}

fn normalize_path(raw: &str) -> Result<String, LhaError> {
    crate::safety::normalize_archive_path(raw).map_err(LhaError::Safety)
}

fn invalid(path: &Path, error: impl fmt::Display) -> LhaError {
    LhaError::Invalid { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> LhaError {
    LhaError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::engine::types::TestOptions;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs;

    fn lha_crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &byte in data {
            crc ^= u16::from(byte);
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc
    }

    fn build_lha_level0(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut archive = Vec::new();
        for &(name, data, is_dir) in entries {
            let name_bytes = name.as_bytes();
            let header_size = (22 + name_bytes.len()) as u8;
            let mut header = Vec::with_capacity(header_size as usize + 2);
            header.push(header_size);
            header.push(0); // placeholder for checksum
            let method = if is_dir { b"-lhd-" } else { b"-lh0-" };
            header.extend_from_slice(method);
            let comp_size = if is_dir { 0_u32 } else { data.len() as u32 };
            let uncomp_size = comp_size;
            header.extend_from_slice(&comp_size.to_le_bytes());
            header.extend_from_slice(&uncomp_size.to_le_bytes());
            // MS-DOS datetime (2026-01-01 12:00:00)
            let dos_time: u32 = ((2026 - 1980) << 25) | (1 << 21) | (1 << 16) | (12 << 11);
            header.extend_from_slice(&dos_time.to_le_bytes());
            header.push(if is_dir { 0x10 } else { 0x20 });
            header.push(0); // Level 0
            header.push(name_bytes.len() as u8);
            header.extend_from_slice(name_bytes);
            let crc = if is_dir { 0_u16 } else { lha_crc16(data) };
            header.extend_from_slice(&crc.to_le_bytes());

            // Compute header checksum (sum of bytes 2..end of basic header)
            let sum: u8 = header[2..].iter().fold(0_u8, |acc, &b| acc.wrapping_add(b));
            header[1] = sum;

            archive.extend_from_slice(&header);
            if !is_dir {
                archive.extend_from_slice(data);
            }
        }
        archive.push(0); // EOF marker
        archive
    }

    #[test]
    fn test_lha_list_test_extract_and_copy() {
        let temp = TestDir::new("lha-backend-test");
        let archive_path = temp.path("sample.lzh");
        let bytes =
            build_lha_level0(&[("nested", b"", true), ("nested/hello.txt", b"Hello, LHA world!\n", false), ("notes.txt", b"Second file contents", false)]);
        fs::write(&archive_path, bytes).unwrap();

        // 1. List
        let entries = list(&archive_path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "nested");
        assert_eq!(entries[0].kind, BrowserEntryKind::Directory);
        assert_eq!(entries[1].path, "nested/hello.txt");
        assert_eq!(entries[1].kind, BrowserEntryKind::File);
        assert_eq!(entries[1].size, 18);
        assert!(entries[1].supported);
        assert_eq!(entries[2].path, "notes.txt");

        // 2. Test
        let test_opts = TestOptions::default();
        let report = test(&archive_path, &test_opts).unwrap();
        assert_eq!(report.entries, 3);
        assert_eq!(report.bytes, 18 + 20);

        // Test with selective filter
        let selective = TestOptions { selected_paths: vec!["notes.txt".to_string()], ..TestOptions::default() };
        let selective_report = test(&archive_path, &selective).unwrap();
        assert_eq!(selective_report.entries, 1);
        assert_eq!(selective_report.skipped_entries, 2);

        // 3. Extract
        let dest = temp.path("out");
        let policy = ExtractionPolicy { overwrite: crate::safety::OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let extract_report = extract(&archive_path, &dest, policy.clone(), None, None).unwrap();
        assert_eq!(extract_report.entries, 3);
        assert_eq!(fs::read(dest.join("nested/hello.txt")).unwrap(), b"Hello, LHA world!\n");
        assert_eq!(fs::read(dest.join("notes.txt")).unwrap(), b"Second file contents");

        // 4. Copy by index
        let mut copied = Vec::new();
        let written = copy(&archive_path, 1, &mut copied).unwrap();
        assert_eq!(written, 18);
        assert_eq!(copied, b"Hello, LHA world!\n");

        // Copy directory entry should error
        assert!(copy(&archive_path, 0, &mut Vec::new()).is_err());

        // 5. Copy by path occurrence
        let mut copied_path = Vec::new();
        let written_path = copy_by_path_occurrence(&archive_path, "notes.txt", 0, &mut copied_path).unwrap();
        assert_eq!(written_path, 20);
        assert_eq!(copied_path, b"Second file contents");

        // Missing path occurrence
        assert!(copy_by_path_occurrence(&archive_path, "missing.txt", 0, &mut Vec::new()).is_err());
    }

    #[test]
    fn test_lha_error_handling() {
        let temp = TestDir::new("lha-backend-errors");
        let non_existent = temp.path("non_existent.lzh");
        assert!(list(&non_existent).is_err());
        assert!(test(&non_existent, &TestOptions::default()).is_err());
        assert!(extract(&non_existent, temp.path("out"), ExtractionPolicy::default(), None, None).is_err());
        assert!(copy(&non_existent, 0, &mut Vec::new()).is_err());

        // Corrupt archive bytes
        let corrupt_path = temp.path("corrupt.lzh");
        fs::write(&corrupt_path, b"garbage data").unwrap();
        assert!(list(&corrupt_path).is_err());

        // Error Display & Source coverage
        let io_err = LhaError::Io { path: PathBuf::from("foo.lha"), source: io::Error::new(io::ErrorKind::NotFound, "not found") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());

        let invalid_err = LhaError::Invalid { path: PathBuf::from("bar.lha"), message: "bad header".to_string() };
        assert!(invalid_err.to_string().contains("invalid LHA"));
        assert!(std::error::Error::source(&invalid_err).is_none());

        let cancelled_err = LhaError::Cancelled;
        assert_eq!(cancelled_err.to_string(), "job cancelled");

        let safety_err = LhaError::Safety(ExtractionSafetyError::ParentTraversal { path: "../escape".to_string() });
        assert!(safety_err.to_string().contains("extraction safety"));
        assert!(std::error::Error::source(&safety_err).is_some());
    }

    #[test]
    fn test_lha_duplicate_and_cancellation() {
        let temp = TestDir::new("lha-backend-more");
        // Duplicate path
        let dup_bytes = build_lha_level0(&[("dup.txt", b"one", false), ("dup.txt", b"two", false)]);
        let dup_path = temp.path("dup.lzh");
        fs::write(&dup_path, dup_bytes).unwrap();
        assert!(list(&dup_path).is_err());

        // Valid archive for cancellation testing
        let valid_bytes = build_lha_level0(&[("item.txt", b"content", false)]);
        let valid_path = temp.path("valid.lzh");
        fs::write(&valid_path, valid_bytes).unwrap();

        // Cancelled test
        let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let cancel_opts = TestOptions { cancellation: Some(cancel_flag), ..TestOptions::default() };
        assert!(matches!(test(&valid_path, &cancel_opts), Err(LhaError::Cancelled)));

        // Cancelled extract
        let cancel_token = crate::jobs::CancellationToken::new();
        cancel_token.cancel();
        assert!(matches!(extract(&valid_path, temp.path("out"), ExtractionPolicy::default(), None, Some(&cancel_token)), Err(LhaError::Cancelled)));
    }
}
