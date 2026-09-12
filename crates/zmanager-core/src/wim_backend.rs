#![allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]

//! Core integration for the read-only WIM library.
//!
//! WIM parsing and resource decoding live in [`zmanager_wim`]. This module
//! adapts its entries to the shared `ZManager` extraction, cancellation, and
//! reporting policies.

use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use sha1::{Digest as _, Sha1};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub use zmanager_wim::{WimArchive, WimCompression, WimEntry, WimEntryKind};

crate::backend_error_from_impls!(WimBackendError);

/// Normalized WIM operation report.
pub type WimReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by native WIM operations.
#[derive(Debug)]
pub enum WimBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// WIM format or decompression error.
    Invalid { path: PathBuf, message: String },
    /// The WIM is well-formed but uses a feature this backend does not decode.
    Unsupported { path: PathBuf, message: String },
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for WimBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Invalid { path, message } => write!(f, "invalid WIM {}: {message}", path.display()),
            Self::Unsupported { path, message } => write!(f, "unsupported WIM {}: {message}", path.display()),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for WimBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Unsupported { .. } | Self::Cancelled => None,
        }
    }
}

impl From<zmanager_wim::WimError> for WimBackendError {
    fn from(error: zmanager_wim::WimError) -> Self {
        match error {
            zmanager_wim::WimError::Io { path, source } => Self::Io { path, source },
            zmanager_wim::WimError::Invalid { path, message } => Self::Invalid { path, message },
            zmanager_wim::WimError::Unsupported { path, message } => Self::Unsupported { path, message },
        }
    }
}

fn io_error(path: impl AsRef<Path>, source: io::Error) -> WimBackendError {
    WimBackendError::Io { path: path.as_ref().to_path_buf(), source }
}

fn invalid(path: impl AsRef<Path>, message: impl Into<String>) -> WimBackendError {
    WimBackendError::Invalid { path: path.as_ref().to_path_buf(), message: message.into() }
}

fn open_and_collect(path: &Path) -> Result<(WimArchive, Vec<WimEntry>), WimBackendError> {
    let mut archive = WimArchive::open(path)?;
    let entries = archive.entries()?;
    Ok((archive, entries))
}

fn read_entry_stream(archive: &mut WimArchive, entry: &WimEntry) -> Result<Option<Vec<u8>>, WimBackendError> {
    archive.read_entry_data(entry).map_err(Into::into)
}

/// Lists every entry of every image in a WIM.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<WimEntry>, WimBackendError> {
    let path = path.as_ref();
    let (_, entries) = open_and_collect(path)?;
    Ok(entries)
}

/// Verifies selected or all WIM files, checking each stream against its
/// recorded SHA-1.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<WimReport, WimBackendError> {
    let path = path.as_ref();
    let (mut archive, entries) = open_and_collect(path)?;

    let mut report = WimReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(WimBackendError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if entry.kind == WimEntryKind::File
            && let Some(data) = read_entry_stream(&mut archive, &entry)?
        {
            if data.len() as u64 != entry.size {
                return Err(invalid(path, format!("WIM entry {} decoded to {} bytes, expected {}", entry.path, data.len(), entry.size)));
            }
            let digest: [u8; 20] = Sha1::digest(&data).into();
            if digest != entry.sha1 {
                return Err(invalid(
                    path,
                    format!("WIM entry {} hashes to {}, but the lookup table records {}", entry.path, hex::encode(digest), hex::encode(entry.sha1)),
                ));
            }
            report.bytes = report.bytes.saturating_add(data.len() as u64);
        }
        report.entries = report.entries.saturating_add(1);
    }
    Ok(report)
}

/// Extracts every WIM entry through the shared safety planner and atomic output.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<WimReport, WimBackendError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let (mut archive, entries) = open_and_collect(path)?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = WimReport::default();

    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(WimBackendError::Cancelled);
        }
        let kind = match entry.kind {
            WimEntryKind::File => ExtractionEntryKind::File,
            WimEntryKind::Directory => ExtractionEntryKind::Directory,
            WimEntryKind::Symlink => {
                let Some(target) = entry.link_target.clone().filter(|target| !target.is_empty()) else {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(format!("skipped reparse point {}: the image does not expose a usable link target", entry.path));
                    continue;
                };
                ExtractionEntryKind::Symlink { target: PathBuf::from(target) }
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
                let data = read_entry_stream(&mut archive, &entry)?.unwrap_or_default();
                let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                let file_out = output.file_mut().map_err(|source| io_error(&destination_path, source))?;
                file_out.write_all(&data).map_err(|source| io_error(&destination_path, source))?;
                output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
                report.bytes = report.bytes.saturating_add(data.len() as u64);
            }
            ExtractionEntryKind::Symlink { target } => {
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
            _ => unreachable!("WIM entries map only to files, directories, and symlinks"),
        }
    }
    Ok(report)
}

/// Copies one file entry to the writer.
pub fn copy_to_writer(path: impl AsRef<Path>, target_path: &str, writer: &mut dyn Write) -> Result<u64, WimBackendError> {
    let path = path.as_ref();
    let (mut archive, entries) = open_and_collect(path)?;

    let Some(entry) = entries.into_iter().find(|entry| entry.path == target_path && entry.kind == WimEntryKind::File) else {
        return Err(invalid(path, format!("file '{target_path}' not found in WIM")));
    };
    let Some(data) = read_entry_stream(&mut archive, &entry)? else { return Ok(0) };
    writer.write_all(&data).map_err(|source| io_error(path, source))?;
    Ok(data.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn require_fixture(name: &str) -> PathBuf {
        let path = fixture(name);
        assert!(path.is_file(), "missing fixture {name}; run scripts/generate_fixtures.sh");
        path
    }

    fn paths_of(entries: &[WimEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.path.as_str()).collect()
    }

    #[test]
    fn reference_wim_fixtures_list_and_extract_for_all_compressions() {
        for name in ["basic-none.wim", "basic-XPRESS.wim", "basic-LZX.wim", "basic.wim"] {
            let archive = require_fixture(name);

            let entries = list(&archive).unwrap_or_else(|error| panic!("{name}: list failed: {error}"));
            let paths = paths_of(&entries);
            for expected in ["README.txt", "nested", "nested/file.txt", "nested/empty-dir", "dir with spaces/file with spaces.txt", "unicode/こんにちは.txt"]
            {
                assert!(paths.contains(&expected), "{name}: missing {expected} in {paths:?}");
            }
            assert!(entries.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "{name}: paths must be normalized: {paths:?}");

            let temp = TestDir::new(&format!("wim-{name}"));
            let dest = temp.path("out");
            let extract_report =
                extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap_or_else(|error| panic!("{name}: extract failed: {error}"));
            assert_eq!(fs::read_to_string(dest.join("README.txt")).unwrap(), "ZManager fixture payload\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("nested/file.txt")).unwrap(), "nested fixture file\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n", "{name}");
            assert!(dest.join("nested/empty-dir").is_dir(), "{name}");

            let declared: u64 = entries.iter().filter(|entry| entry.kind == WimEntryKind::File).map(|entry| entry.size).sum();
            assert_eq!(extract_report.bytes, declared, "{name}: written bytes must sum declared file sizes");

            let test_report = test(&archive, &TestOptions::default()).unwrap_or_else(|error| panic!("{name}: test failed: {error}"));
            assert_eq!(test_report.bytes, declared, "{name}: verified bytes must match declared total");
            assert_eq!(test_report.entries, entries.len(), "{name}: test entries must count all entries");
        }
    }

    #[test]
    fn multi_image_and_split_wim_list_and_extract() {
        let multi = require_fixture("multi-image.wim");
        let multi_entries = list(&multi).unwrap();
        let multi_paths = paths_of(&multi_entries);
        assert!(multi_paths.iter().any(|path| path.starts_with("image1/")), "multi-image WIM must expose image1/: {multi_paths:?}");
        assert!(multi_paths.iter().any(|path| path.starts_with("image2/")), "multi-image WIM must expose image2/: {multi_paths:?}");

        let temp_multi = TestDir::new("wim-multi");
        let dest_multi = temp_multi.path("out");
        let multi_report = extract(&multi, &dest_multi, ExtractionPolicy::default(), None, None).unwrap();
        assert!(multi_report.entries > 0);
        assert!(dest_multi.join("image1/README.txt").is_file());
        assert!(dest_multi.join("image2/README.txt").is_file());

        let split = require_fixture("split.swm");
        let split_entries = list(&split).unwrap();
        assert!(!split_entries.is_empty());
        let temp_split = TestDir::new("wim-split");
        let dest_split = temp_split.path("out");
        let split_report = extract(&split, &dest_split, ExtractionPolicy::default(), None, None).unwrap();
        assert!(split_report.entries > 0);
        assert_eq!(fs::read_to_string(dest_split.join("README.txt")).unwrap(), "ZManager fixture payload\n");
    }

    #[test]
    fn copy_to_writer_streams_selected_entry() {
        let archive = require_fixture("basic.wim");
        let mut readme_bytes = Vec::new();
        let written = copy_to_writer(&archive, "README.txt", &mut readme_bytes).unwrap();
        assert_eq!(readme_bytes, b"ZManager fixture payload\n");
        assert_eq!(written, readme_bytes.len() as u64);

        let mut nested_bytes = Vec::new();
        let written_nested = copy_to_writer(&archive, "nested/file.txt", &mut nested_bytes).unwrap();
        assert_eq!(nested_bytes, b"nested fixture file\n");
        assert_eq!(written_nested, nested_bytes.len() as u64);

        let mut missing_bytes = Vec::new();
        let error = copy_to_writer(&archive, "nonexistent.txt", &mut missing_bytes).unwrap_err();
        assert!(error.to_string().contains("not found"), "{error}");
    }

    #[test]
    fn test_honours_selection_and_cancellation() {
        let archive = require_fixture("basic.wim");

        let options = TestOptions { selected_paths: vec!["README.txt".to_owned()], ..TestOptions::default() };
        let report = test(&archive, &options).unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, "ZManager fixture payload\n".len() as u64);
        assert!(report.skipped_entries > 0);

        let cancelled_token = Arc::new(AtomicBool::new(true));
        let options_cancelled = TestOptions { cancellation: Some(cancelled_token), ..TestOptions::default() };
        assert!(matches!(test(&archive, &options_cancelled), Err(WimBackendError::Cancelled)));

        let cancel_job = crate::jobs::CancellationToken::new();
        cancel_job.cancel();
        let temp = TestDir::new("wim-cancel-extract");
        let dest = temp.path("out");
        assert!(matches!(extract(&archive, &dest, ExtractionPolicy::default(), None, Some(&cancel_job)), Err(WimBackendError::Cancelled)));
    }

    #[test]
    fn non_wim_and_corrupt_inputs_are_rejected() {
        let temp = TestDir::new("wim-reject");

        fs::write(temp.path("empty.wim"), b"").unwrap();
        assert!(list(temp.path("empty.wim")).is_err());

        fs::write(temp.path("garbage.wim"), b"not a wim archive at all").unwrap();
        let error = list(temp.path("garbage.wim")).unwrap_err();
        assert!(error.to_string().contains("invalid WIM") || error.to_string().contains("I/O failed"), "{error}");

        let mut bytes = fs::read(require_fixture("basic-none.wim")).unwrap();
        bytes[0..4].copy_from_slice(b"JUNK");
        fs::write(temp.path("corrupt.wim"), &bytes).unwrap();
        assert!(list(temp.path("corrupt.wim")).is_err());

        let truncated = &bytes[..bytes.len() / 2];
        fs::write(temp.path("truncated.wim"), truncated).unwrap();
        assert!(list(temp.path("truncated.wim")).is_err());
    }
}
