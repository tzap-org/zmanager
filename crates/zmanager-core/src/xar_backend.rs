//! Native XAR reader backed by the standalone `xara` implementation.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Seek as _};
use std::path::{Path, PathBuf};

/// One normalized XAR entry.
#[derive(Debug, Clone)]
pub struct XarEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Normalized archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Uncompressed file size when present.
    pub size: u64,
    /// Relative target for a symbolic-link entry.
    pub link_target: Option<String>,
    source: dpp::xara::XarFile,
}

/// Normalized XAR operation report.
pub type XarReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by native XAR operations.
#[derive(Debug)]
pub enum XarError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The XAR parser or encoded file payload failed.
    Parser { path: PathBuf, message: String },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for XarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Parser { path, message } => write!(f, "invalid XAR {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected XAR entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for XarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Parser { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for XarError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries from a XAR archive.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<XarEntry>, XarError> {
    let path = path.as_ref();
    let archive = open(path)?;
    collect_entries(&archive, path)
}

/// Verifies selected or all XAR file payloads.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<XarReport, XarError> {
    let path = path.as_ref();
    let archive = open(path)?;
    let entries = collect_entries(&archive, path)?;
    let mut report = XarReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(XarError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if entry.kind == BrowserEntryKind::File {
            let bytes = read_entry_to(path, archive.header(), &entry.source, &mut io::sink())?;
            if bytes != entry.size {
                return Err(parser_error(path, format!("XAR file {} decoded to {bytes} bytes, expected {}", entry.path, entry.size)));
            }
            report.bytes = report.bytes.saturating_add(bytes);
        }
        report.entries = report.entries.saturating_add(1);
    }
    Ok(report)
}

/// Extracts XAR entries using the shared safety planner and atomic output.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<XarReport, XarError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let archive = open(path)?;
    let entries = collect_entries(&archive, path)?;
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = XarReport::default();
    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(XarError::Cancelled);
        }
        let kind = match entry.kind {
            BrowserEntryKind::File => ExtractionEntryKind::File,
            BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
            BrowserEntryKind::Symlink => ExtractionEntryKind::Symlink { target: PathBuf::from(entry.link_target.clone().unwrap_or_default()) },
            BrowserEntryKind::Hardlink | BrowserEntryKind::Special | BrowserEntryKind::FileCopy => {
                return Err(parser_error(path, format!("unsupported XAR entry kind for {}", entry.path)));
            }
        };
        let safety_entry = ExtractionEntry { archive_path: entry.path.clone(), kind, uncompressed_size: Some(entry.size), compressed_size: None };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        match &safety_entry.kind {
            ExtractionEntryKind::Directory => {
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
            }
            ExtractionEntryKind::File => {
                let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                let bytes = read_entry_to(path, archive.header(), &entry.source, output.file_mut().map_err(|source| io_error(&destination_path, source))?)?;
                output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
                report.bytes = report.bytes.saturating_add(bytes);
            }
            ExtractionEntryKind::Symlink { target } => {
                if target.as_os_str().is_empty() {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(format!("skipped symlink {}: XAR symlink target is empty", entry.path));
                    continue;
                }
                if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(crate::safety::unsupported_symlink_warning(&entry.path));
                    continue;
                }
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                crate::extract_materialize::write_symlink(target, &destination_path).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
            }
            ExtractionEntryKind::Hardlink { .. } | ExtractionEntryKind::Device | ExtractionEntryKind::Special => unreachable!(),
        }
    }
    Ok(report)
}

/// Copies one retained regular file to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, XarError> {
    let path = path.as_ref();
    let archive = open(path)?;
    let entries = collect_entries(&archive, path)?;
    let entry = entries.get(entry_index).ok_or_else(|| parser_error(path, "retained XAR entry ID is not present"))?;
    if entry.kind != BrowserEntryKind::File {
        return Err(parser_error(path, "retained XAR entry is not a regular file"));
    }
    read_entry_to(path, archive.header(), &entry.source, writer)
}

/// Copies one retained XAR file by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, XarError> {
    let path = path.as_ref();
    let archive = open(path)?;
    let entries = collect_entries(&archive, path)?;
    let mut occurrence = 0_usize;
    let entry = entries
        .into_iter()
        .find(|entry| {
            if entry.path != selected_path {
                return false;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches
        })
        .ok_or_else(|| parser_error(path, "retained XAR entry is not present"))?;
    read_entry_to(path, archive.header(), &entry.source, writer)
}

fn read_entry_to(path: &Path, header: &dpp::xara::XarHeader, file: &dpp::xara::XarFile, writer: &mut dyn io::Write) -> Result<u64, XarError> {
    let Some(data) = &file.data else {
        return Ok(0);
    };
    let heap_offset = u64::from(header.header_size).checked_add(header.toc_compressed_len).ok_or_else(|| parser_error(path, "XAR heap offset overflows"))?;
    let absolute_offset = heap_offset.checked_add(data.offset).ok_or_else(|| parser_error(path, "XAR file offset overflows"))?;
    let mut source = File::open(path).map_err(|source| io_error(path, source))?;
    source.seek(std::io::SeekFrom::Start(absolute_offset)).map_err(|source| io_error(path, source))?;

    match data.encoding.as_str() {
        "application/octet-stream" => {
            let written = io::copy(&mut source.take(data.length), writer).map_err(|source| io_error(path, source))?;
            if written != data.size {
                return Err(parser_error(path, format!("XAR file {} decoded to {written} bytes, expected {}", file.path, data.size)));
            }
            Ok(written)
        }
        "application/x-gzip" => {
            let mut prefix = [0_u8; 2];
            source.read_exact(&mut prefix).map_err(|source| io_error(path, source))?;
            source.seek(std::io::SeekFrom::Start(absolute_offset)).map_err(|source| io_error(path, source))?;
            if prefix == [0x1f, 0x8b] {
                let decoder = flate2::read::GzDecoder::new(source.take(data.length));
                copy_decoded(path, file, decoder, writer, data.size)
            } else {
                let decoder = flate2::read::ZlibDecoder::new(source.take(data.length));
                copy_decoded(path, file, decoder, writer, data.size)
            }
        }
        "application/zlib" | "application/x-zlib" => {
            let decoder = flate2::read::ZlibDecoder::new(source.take(data.length));
            copy_decoded(path, file, decoder, writer, data.size)
        }
        "application/x-bzip2" => {
            let decoder = bzip2::read::BzDecoder::new(source.take(data.length));
            copy_decoded(path, file, decoder, writer, data.size)
        }
        encoding => Err(parser_error(path, format!("unsupported XAR file encoding {encoding}"))),
    }
}

fn copy_decoded<R: io::Read>(path: &Path, file: &dpp::xara::XarFile, decoder: R, writer: &mut dyn io::Write, expected: u64) -> Result<u64, XarError> {
    let mut bounded = decoder.take(expected.saturating_add(1));
    let written = io::copy(&mut bounded, writer).map_err(|source| io_error(path, source))?;
    if written != expected {
        return Err(parser_error(path, format!("XAR file {} decoded to {written} bytes, expected {expected}", file.path)));
    }
    Ok(written)
}

fn open(path: &Path) -> Result<dpp::xara::XarArchive<File>, XarError> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    dpp::xara::XarArchive::open(file).map_err(|error| parser_error(path, error))
}

fn collect_entries<R: io::Read + io::Seek>(archive: &dpp::xara::XarArchive<R>, path: &Path) -> Result<Vec<XarEntry>, XarError> {
    let mut entries = Vec::new();
    for source in archive.files() {
        let Some(normalized_path) = normalize_xar_path(&source.path)? else {
            continue;
        };
        if entries.iter().any(|entry: &XarEntry| entry.path == normalized_path) {
            return Err(parser_error(path, format!("XAR contains duplicate path {normalized_path}")));
        }
        let kind = match source.file_type {
            dpp::xara::XarFileType::File => BrowserEntryKind::File,
            dpp::xara::XarFileType::Directory => BrowserEntryKind::Directory,
            dpp::xara::XarFileType::Symlink => BrowserEntryKind::Symlink,
        };
        let link_target = if kind == BrowserEntryKind::Symlink { source.link.clone() } else { None };
        entries.push(XarEntry {
            index: entries.len(),
            path: normalized_path,
            kind,
            size: source.data.as_ref().map_or(0, |data| data.size),
            link_target,
            source: source.clone(),
        });
    }
    Ok(entries)
}

fn normalize_xar_path(raw_path: &str) -> Result<Option<String>, XarError> {
    let path = raw_path.strip_prefix("./").unwrap_or(raw_path).strip_prefix('/').unwrap_or(raw_path);
    if path.is_empty() || path == "." {
        return Ok(None);
    }
    Ok(Some(crate::safety::normalize_archive_path(path)?))
}

fn parser_error(path: &Path, error: impl fmt::Display) -> XarError {
    XarError::Parser { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> XarError {
    XarError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.xar")
    }

    #[test]
    fn test_xar_list_test_extract_and_copy() {
        let xar_file = fixture_path();
        if !xar_file.exists() {
            return;
        }

        let temp = TestDir::new("xar-backend-test");

        // 1. List
        let entries = list(&xar_file).unwrap();
        assert!(!entries.is_empty());
        let has_readme = entries.iter().any(|entry| entry.path.ends_with("README.txt"));
        assert!(has_readme, "XAR entries should contain README.txt");
        let readme_link = entries.iter().find(|entry| entry.path.ends_with("readme-link.txt"));
        assert_eq!(readme_link.and_then(|entry| entry.link_target.as_deref()), Some("../README.txt"));

        // 2. Test
        let test_report = test(&xar_file, &TestOptions::default()).unwrap();
        assert!(test_report.entries > 0);
        assert!(test_report.bytes > 0);

        // Test with selection
        let sel_opts = TestOptions { selected_paths: vec!["payload/README.txt".to_string()], ..TestOptions::default() };
        let sel_report = test(&xar_file, &sel_opts).unwrap();
        assert_eq!(sel_report.entries, 1);

        // 3. Extract
        let dest = temp.path("out");
        let extract_report = extract(&xar_file, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert!(extract_report.entries > 0);
        assert!(extract_report.bytes > 0);
        assert!(dest.join("payload/README.txt").exists());

        // 4. Copy by index
        let readme_idx = entries.iter().position(|e| e.path.ends_with("README.txt")).unwrap();
        let mut copied = Vec::new();
        let bytes_copied = copy(&xar_file, readme_idx, &mut copied).unwrap();
        assert!(bytes_copied > 0);
        assert_eq!(bytes_copied, copied.len() as u64);

        // 5. Copy by path occurrence
        let mut copied_occ = Vec::new();
        let occ_bytes = copy_by_path_occurrence(&xar_file, &entries[readme_idx].path, 0, &mut copied_occ).unwrap();
        assert_eq!(occ_bytes, bytes_copied);
        assert_eq!(copied_occ, copied);
    }

    #[test]
    fn test_xar_error_handling() {
        let temp = TestDir::new("xar-backend-errors");
        let non_existent = temp.path("missing.xar");
        assert!(list(&non_existent).is_err());
        assert!(test(&non_existent, &TestOptions::default()).is_err());
        assert!(extract(&non_existent, temp.path("out"), ExtractionPolicy::default(), None, None).is_err());
        assert!(copy(&non_existent, 0, &mut Vec::new()).is_err());

        // Corrupt file
        let corrupt = temp.path("corrupt.xar");
        fs::write(&corrupt, b"not a xar archive").unwrap();
        assert!(list(&corrupt).is_err());

        // Error types & Display coverage
        let parser_err = XarError::Parser { path: PathBuf::from("a.xar"), message: "parse failed".to_string() };
        assert!(parser_err.to_string().contains("invalid XAR"));
        assert!(std::error::Error::source(&parser_err).is_none());

        let io_err = XarError::Io { path: PathBuf::from("b.xar"), source: io::Error::new(io::ErrorKind::NotFound, "err") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());

        let cancelled = XarError::Cancelled;
        assert_eq!(cancelled.to_string(), "job cancelled");

        let safety = XarError::Safety(ExtractionSafetyError::EmptyPath);
        assert!(safety.to_string().contains("extraction safety"));
        assert!(std::error::Error::source(&safety).is_some());
    }
}
