use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{ArchiveManifest, PlanError};
use crate::safety::{ExtractionPolicy, OverwriteResolver};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// `.aar` file extension.
pub const APPLE_ARCHIVE_EXTENSION: &str = "aar";

/// Stub compression enum.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AppleArchiveCompression {
    None,
    Lz4,
    Zlib,
    Lzma,
    #[default]
    Lzfse,
    Lzbitmap,
}

/// Stub creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveCreateOptions {
    pub compression: AppleArchiveCompression,
    pub block_size: usize,
    pub threads: i32,
    pub preserve_metadata: bool,
    pub replace_existing: bool,
}

impl Default for AppleArchiveCreateOptions {
    fn default() -> Self {
        Self {
            compression: AppleArchiveCompression::default(),
            block_size: 4 * 1024 * 1024,
            threads: 0,
            preserve_metadata: true,
            replace_existing: false,
        }
    }
}

/// Stub list entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveListEntry {
    pub path: String,
    pub kind: AppleArchiveEntryKind,
    pub size: Option<u64>,
    pub modified: Option<SystemTime>,
}

/// Stub entry kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AppleArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Device,
    Special,
}

/// Stub listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveListing {
    pub entries: Vec<AppleArchiveListEntry>,
}

/// Stub create report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveCreateReport {
    pub written_entries: usize,
    pub written_bytes: u64,
    pub warnings: Vec<String>,
}

/// Stub extract report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveExtractReport {
    pub written_entries: usize,
    pub skipped_entries: usize,
    pub written_bytes: u64,
    pub warnings: Vec<String>,
}

/// Stub test report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveTestReport {
    pub tested_entries: usize,
    pub skipped_entries: usize,
    pub tested_bytes: u64,
}

/// Stub `AppleArchive` error.
#[derive(Debug)]
pub enum AppleArchiveError {
    Plan(PlanError),
    UnsupportedPlatform,
    Io { path: PathBuf, source: io::Error },
    Safety(crate::safety::ExtractionSafetyError),
    MissingLinkTarget { path: String },
    MissingFileData { path: String },
    EntryNotFound { path: String },
    StdoutSelectionNotSingleFile { selected_files: usize },
    Cancelled,
}

impl fmt::Display for AppleArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::UnsupportedPlatform => {
                write!(f, "AppleArchive is supported only on macOS and iOS")
            }
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { path } => {
                write!(f, "AppleArchive symlink entry has no target: {path}")
            }
            Self::MissingFileData { path } => {
                write!(f, "AppleArchive file entry has no data blob: {path}")
            }
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::StdoutSelectionNotSingleFile { selected_files } => write!(
                f,
                "extract --to-stdout requires exactly one selected regular file; selected {selected_files}"
            ),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for AppleArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::UnsupportedPlatform
            | Self::MissingLinkTarget { .. }
            | Self::MissingFileData { .. }
            | Self::EntryNotFound { .. }
            | Self::StdoutSelectionNotSingleFile { .. }
            | Self::Cancelled => None,
        }
    }
}

impl From<PlanError> for AppleArchiveError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<crate::safety::ExtractionSafetyError> for AppleArchiveError {
    fn from(source: crate::safety::ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for AppleArchiveError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

#[must_use]
pub const fn apple_archive_supported() -> bool {
    false
}

pub fn is_apple_archive_path(_path: impl AsRef<Path>) -> bool {
    false
}

pub fn create_apple_archive_from_path(
    _source: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _options: &AppleArchiveCreateOptions,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn create_apple_archive_from_manifest(
    _manifest: &ArchiveManifest,
    _destination: impl AsRef<Path>,
    _options: &AppleArchiveCreateOptions,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn create_apple_archive_from_manifest_with_context(
    _manifest: &ArchiveManifest,
    _destination: impl AsRef<Path>,
    _options: &AppleArchiveCreateOptions,
    _context: &mut JobContext,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn list_apple_archive(
    _path: impl AsRef<Path>,
) -> Result<AppleArchiveListing, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn extract_apple_archive(
    _archive: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn extract_apple_archive_with_context(
    _archive: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _context: &mut JobContext,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn extract_apple_archive_with_overwrite_resolver(
    _archive: impl AsRef<Path>,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
    _resolver: &mut dyn OverwriteResolver,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn extract_apple_archive_entry(
    _archive: impl AsRef<Path>,
    _entry_path: &str,
    _destination: impl AsRef<Path>,
    _policy: ExtractionPolicy,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn copy_apple_archive_files_to_writer<W: Write>(
    _archive: impl AsRef<Path>,
    _selected: impl FnMut(&str) -> bool,
    _output: &mut W,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

pub fn test_apple_archive_filter(
    _archive: impl AsRef<Path>,
    _filter: impl FnMut(&str) -> bool,
) -> Result<AppleArchiveTestReport, AppleArchiveError> {
    Err(AppleArchiveError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_operations_return_unsupported_on_non_apple_targets() {
        let error = list_apple_archive("archive.aar").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("AppleArchive is supported only on macOS and iOS")
        );
        assert!(!apple_archive_supported());
        assert!(!is_apple_archive_path("archive.aar"));
    }
}
