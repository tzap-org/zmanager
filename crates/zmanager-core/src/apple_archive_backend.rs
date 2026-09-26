//! `AppleArchive` (`.aar`/`.aea`) backend.
//!
//! The portable interface (types, options, errors) compiles on every
//! platform; only the native implementation is gated to macOS/iOS, where the
//! `zmanager-apple-archive` framework wrapper can be linked. On other
//! platforms the [`imp::stub_impl`] entry points return
//! [`AppleArchiveError::Unsupported`], so consumers (CLI, FFI, browser,
//! jobs) carry no platform predicates of their own.

use crate::jobs::JobContext;
use crate::manifest::{ArchiveManifest, PlanError};
use crate::safety::{ExtractionPolicy, ExtractionSafetyError, OverwriteResolver};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Compression used for newly created `.aar` files.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AppleArchiveCompression {
    /// No compression.
    None,
    /// LZ4 compression.
    Lz4,
    /// ZLIB compression.
    Zlib,
    /// LZMA compression.
    Lzma,
    /// LZFSE compression (default).
    #[default]
    Lzfse,
    /// LZBITMAP compression.
    Lzbitmap,
}

/// `.aar` file extension.
pub const APPLE_ARCHIVE_EXTENSION: &str = "aar";

/// `.aea` file extension (encrypted Apple Archive).
pub const APPLE_ARCHIVE_ENCRYPTED_EXTENSION: &str = "aea";

/// `AppleArchive` creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveCreateOptions {
    /// Native `AppleArchive` compression algorithm.
    pub compression: AppleArchiveCompression,
    /// Compression block size in bytes.
    pub block_size: usize,
    /// Native worker count. Zero lets `AppleArchive` choose.
    pub threads: i32,
    /// Preserve portable metadata such as mode and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
    /// Optional password for encrypted archive (`.aea`). When set, uses Apple's
    /// AEA encryption with the SCRYPT profile for password-based key derivation.
    pub password: Option<String>,
}

impl Default for AppleArchiveCreateOptions {
    fn default() -> Self {
        // Matches the native `zmanager_apple_archive::CreateOptions::default()`
        // (LZFSE, 4 MiB blocks, framework-chosen worker count).
        Self {
            compression: AppleArchiveCompression::Lzfse,
            block_size: 4 * 1024 * 1024,
            threads: 0,
            preserve_metadata: true,
            replace_existing: false,
            password: None,
        }
    }
}

/// `AppleArchive` listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveListEntry {
    /// Raw path stored in the archive.
    pub path: String,
    /// Portable entry kind.
    pub kind: AppleArchiveEntryKind,
    /// Uncompressed file size when known.
    pub size: Option<u64>,
    /// Modification time when known.
    pub modified: Option<SystemTime>,
    /// Unix permission bits when present.
    pub mode: Option<u32>,
    /// Creation time when present.
    pub created: Option<SystemTime>,
    /// BSD/macOS file flags.
    pub flags: Option<u32>,
    /// Checksum CRC32.
    pub crc: Option<u32>,
    /// User identifier.
    pub uid: Option<u32>,
    /// Group identifier.
    pub gid: Option<u32>,
    /// Link target path.
    pub link_target: Option<String>,
}

/// `AppleArchive` entry kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AppleArchiveEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Device node.
    Device,
    /// Metadata or another special entry.
    Special,
}

/// `AppleArchive` listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveListing {
    /// Entries in archive order.
    pub entries: Vec<AppleArchiveListEntry>,
}

/// `AppleArchive` creation report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveCreateReport {
    /// Entries written to the archive.
    pub written_entries: usize,
    /// Source file bytes copied into file entries.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `AppleArchive` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveExtractReport {
    /// Entries written to disk.
    pub written_entries: usize,
    /// Entries skipped by policy or unsupported materialization.
    pub skipped_entries: usize,
    /// Regular file bytes copied.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `AppleArchive` data-read test report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveTestReport {
    /// Entries selected and read or skipped through successfully.
    pub tested_entries: usize,
    /// Entries skipped by the supplied filter.
    pub skipped_entries: usize,
    /// Regular file bytes read from selected entries.
    pub tested_bytes: u64,
}

/// Error returned by the `AppleArchive` backend.
#[derive(Debug)]
pub enum AppleArchiveError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Native `AppleArchive` operation failed.
    Native(String),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Link entry had no target.
    MissingLinkTarget { path: String },
    /// A regular file did not carry extractable file data.
    MissingFileData { path: String },
    /// Requested archive entry was not found.
    EntryNotFound { path: String },
    /// Stdout extraction must resolve to one regular file.
    StdoutSelectionNotSingleFile { selected_files: usize },
    /// Job was cancelled cooperatively.
    Cancelled,
    /// Native `AppleArchive` APIs are unavailable on this platform.
    Unsupported,
}

impl fmt::Display for AppleArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Native(message) => write!(f, "AppleArchive operation failed: {message}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { path } => {
                write!(f, "AppleArchive symlink entry has no target: {path}")
            }
            Self::MissingFileData { path } => {
                write!(f, "AppleArchive file entry has no data blob: {path}")
            }
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::StdoutSelectionNotSingleFile { selected_files } => {
                write!(f, "extract --to-stdout requires exactly one selected regular file; selected {selected_files}")
            }
            Self::Cancelled => write!(f, "job cancelled"),
            Self::Unsupported => write!(f, "AppleArchive is supported only on macOS and iOS"),
        }
    }
}

impl std::error::Error for AppleArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Native(_)
            | Self::Unsupported
            | Self::MissingLinkTarget { .. }
            | Self::MissingFileData { .. }
            | Self::EntryNotFound { .. }
            | Self::StdoutSelectionNotSingleFile { .. }
            | Self::Cancelled => None,
        }
    }
}

crate::backend_error_from_impls!(AppleArchiveError);

/// Returns whether this build can use native `AppleArchive` APIs.
#[must_use]
pub const fn apple_archive_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "ios"))
}

/// Returns whether a path has an Apple Archive extension (`.aar` or `.aea`).
#[must_use]
pub fn is_apple_archive_path(path: impl AsRef<Path>) -> bool {
    path.as_ref()
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(APPLE_ARCHIVE_EXTENSION) || extension.eq_ignore_ascii_case(APPLE_ARCHIVE_ENCRYPTED_EXTENSION))
}

/// Platform-specific implementation. [`apple_impl`] carries the native
/// `AppleArchive` code where the framework is linkable; [`stub_impl`] fails
/// with [`AppleArchiveError::Unsupported`] elsewhere.
mod imp {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    mod apple_impl {
        use super::super::{
            AppleArchiveCompression, AppleArchiveCreateOptions, AppleArchiveCreateReport, AppleArchiveEntryKind, AppleArchiveError, AppleArchiveExtractReport,
            AppleArchiveListEntry, AppleArchiveListing, AppleArchiveTestReport,
        };
        use crate::jobs::JobContext;
        use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanOptions, plan_archive};
        use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyPlanner, OverwriteResolver};
        use std::fs::{self, File};
        use std::io::{self, Seek, SeekFrom, Write};
        use std::path::{Path, PathBuf};
        use std::time::SystemTime;
        use zmanager_apple_archive::{ArchiveReader, ArchiveWriter};

        /// Maps the portable compression enum to the native framework's.
        impl From<AppleArchiveCompression> for zmanager_apple_archive::CompressionAlgorithm {
            fn from(compression: AppleArchiveCompression) -> Self {
                match compression {
                    AppleArchiveCompression::None => Self::None,
                    AppleArchiveCompression::Lz4 => Self::Lz4,
                    AppleArchiveCompression::Zlib => Self::Zlib,
                    AppleArchiveCompression::Lzma => Self::Lzma,
                    AppleArchiveCompression::Lzfse => Self::Lzfse,
                    AppleArchiveCompression::Lzbitmap => Self::Lzbitmap,
                }
            }
        }

        impl From<zmanager_apple_archive::Error> for AppleArchiveError {
            fn from(source: zmanager_apple_archive::Error) -> Self {
                match source {
                    zmanager_apple_archive::Error::Cancelled => Self::Cancelled,
                    source => Self::Native(source.to_string()),
                }
            }
        }

        /// Opens an `ArchiveReader`, using the encrypted path when a password is
        /// supplied and falling back to the plain path otherwise.
        fn open_apple_archive_reader(path: impl AsRef<Path>, password: Option<&str>) -> Result<ArchiveReader, AppleArchiveError> {
            if let Some(password) = password { Ok(ArchiveReader::open_encrypted(path, password.as_bytes())?) } else { Ok(ArchiveReader::open(path)?) }
        }

        /// Creates an `AppleArchive` from a source path.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when planning, filesystem reads, native
        /// writing, or commit fails.
        pub(crate) fn create_apple_archive_from_path(
            source: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            let manifest = plan_archive(source, &PlanOptions::default())?;
            create_apple_archive_from_manifest(&manifest, destination, options)
        }

        /// Creates an `AppleArchive` from a manifest.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when source files cannot be read, native
        /// writing fails, or commit fails.
        pub(crate) fn create_apple_archive_from_manifest(
            manifest: &ArchiveManifest,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            create_apple_archive_from_manifest_inner(manifest, destination, options, None)
        }

        /// Creates an `AppleArchive` from a manifest while emitting job events.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when source files cannot be read, native
        /// writing fails, commit fails, or cancellation is requested.
        pub(crate) fn create_apple_archive_from_manifest_with_context(
            manifest: &ArchiveManifest,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            create_apple_archive_from_manifest_inner(manifest, destination, options, Some(context))
        }

        fn create_apple_archive_from_manifest_inner(
            manifest: &ArchiveManifest,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
            mut context: Option<&mut JobContext<'_>>,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            let destination = destination.as_ref();
            let mut output = crate::atomic_file::AtomicOutputFile::create(destination)
                .map_err(|source| AppleArchiveError::Io { path: destination.to_path_buf(), source })?;
            let temp_path = output.temp_path().to_path_buf();
            output.close();

            let native_options =
                zmanager_apple_archive::CreateOptions { compression: options.compression.into(), block_size: options.block_size, threads: options.threads };
            let mut writer = if let Some(ref password) = options.password {
                ArchiveWriter::create_encrypted(&temp_path, native_options, password.as_bytes())?
            } else {
                ArchiveWriter::create(&temp_path, native_options)?
            };
            let mut report = AppleArchiveCreateReport { written_entries: 0, written_bytes: 0, warnings: Vec::new() };

            for entry in &manifest.entries {
                append_manifest_entry(&mut writer, entry, options, &mut report, context.as_deref_mut())?;
            }

            writer.finish()?;
            output.commit_with_file_replace(options.replace_existing).map_err(|source| AppleArchiveError::Io { path: destination.to_path_buf(), source })?;

            Ok(report)
        }

        /// Lists entries in an `AppleArchive`.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the native reader cannot open or read the
        /// archive.
        pub(crate) fn list_apple_archive(path: impl AsRef<Path>, password: Option<&str>) -> Result<AppleArchiveListing, AppleArchiveError> {
            let mut reader = open_apple_archive_reader(path, password)?;
            let mut entries = Vec::new();

            while let Some(entry) = reader.next_entry()? {
                let metadata = entry.metadata();
                entries.push(AppleArchiveListEntry {
                    path: entry.path().to_owned(),
                    kind: apple_entry_kind(entry.kind()),
                    size: entry.size(),
                    modified: metadata.modified,
                    mode: metadata.mode,
                    created: metadata.created,
                    flags: metadata.flags,
                    crc: metadata.crc,
                    uid: metadata.uid,
                    gid: metadata.gid,
                    link_target: entry.link_target().map(|p| p.to_string_lossy().into_owned()),
                });
                reader.skip_entry_data(&entry)?;
            }

            Ok(AppleArchiveListing { entries })
        }

        /// Extracts an `AppleArchive` through the shared extraction safety policy.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
        /// unsafe, or filesystem writes fail.
        pub(crate) fn extract_apple_archive(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, None, None, None, password)
        }

        /// Extracts an `AppleArchive` while emitting job events.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
        /// unsafe, filesystem writes fail, or cancellation is requested.
        pub(crate) fn extract_apple_archive_with_context(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, None, None, Some(context), password)
        }

        pub(crate) fn extract_apple_archive_with_context_and_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, None, Some(overwrite_resolver), Some(context), password)
        }

        /// Extracts an `AppleArchive` with an overwrite resolver.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
        /// unsafe, filesystem writes fail, or the resolver aborts extraction.
        pub(crate) fn extract_apple_archive_with_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, None, Some(overwrite_resolver), None, password)
        }

        /// Extracts one selected `AppleArchive` entry.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be read, the entry is
        /// unsafe, the selected entry is not found, or filesystem writes fail.
        pub(crate) fn extract_apple_archive_entry(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, Some(entry_path), None, None, password)
        }

        pub(crate) fn extract_apple_archive_entry_with_context(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, Some(entry_path), None, Some(context), password)
        }

        pub(crate) fn extract_apple_archive_entry_with_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, Some(entry_path), Some(overwrite_resolver), None, password)
        }

        pub(crate) fn extract_apple_archive_entry_with_context_and_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            extract_apple_archive_inner(archive_path, destination, policy, Some(entry_path), Some(overwrite_resolver), Some(context), password)
        }

        /// Copies the one selected regular file entry to a writer.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be read, the
        /// selection does not resolve to exactly one regular file, or output writing
        /// fails.
        pub(crate) fn copy_apple_archive_files_to_writer<W: Write + ?Sized>(
            archive_path: impl AsRef<Path>,
            mut selected: impl FnMut(&str) -> bool,
            output: &mut W,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            let archive_path = archive_path.as_ref();
            let mut reader = open_apple_archive_reader(archive_path, password)?;
            let mut report = AppleArchiveExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
            let mut selected_files = 0_usize;
            let mut staged_file = None;

            while let Some(entry) = reader.next_entry()? {
                if !selected(entry.path()) || !matches!(entry.kind(), zmanager_apple_archive::EntryKind::File) {
                    reader.skip_entry_data(&entry)?;
                    report.skipped_entries += 1;
                    continue;
                }

                selected_files += 1;
                if selected_files > 1 {
                    reader.skip_entry_data(&entry)?;
                    report.skipped_entries += 1;
                    continue;
                }

                ensure_file_entry_has_data(&entry)?;
                let mut staged = crate::atomic_file::TemporaryFile::create("apple-archive-stdout")
                    .map_err(|source| AppleArchiveError::Io { path: std::env::temp_dir(), source })?;
                let copied = reader.read_entry_data(&entry, staged.file_mut(), |_| true)?;
                report.written_entries += 1;
                report.written_bytes += copied;
                staged_file = Some(staged);
            }

            if selected_files != 1 {
                return Err(AppleArchiveError::StdoutSelectionNotSingleFile { selected_files });
            }

            let mut staged = staged_file.ok_or(AppleArchiveError::StdoutSelectionNotSingleFile { selected_files: 0 })?;
            staged.file_mut().seek(SeekFrom::Start(0)).map_err(|source| AppleArchiveError::Io { path: staged.path().to_path_buf(), source })?;
            io::copy(staged.file_mut(), output).map_err(|source| AppleArchiveError::Io { path: staged.path().to_path_buf(), source }).map(|_| report)
        }

        /// Reads selected `AppleArchive` entries to validate data streams.
        ///
        /// # Errors
        ///
        /// Returns [`AppleArchiveError`] when the archive cannot be opened or read.
        pub(crate) fn test_apple_archive_filter(
            archive_path: impl AsRef<Path>,
            mut selected: impl FnMut(&str) -> bool,
            password: Option<&str>,
        ) -> Result<AppleArchiveTestReport, AppleArchiveError> {
            let mut reader = open_apple_archive_reader(archive_path, password)?;
            let mut report = AppleArchiveTestReport { tested_entries: 0, skipped_entries: 0, tested_bytes: 0 };
            let mut sink = io::sink();

            while let Some(entry) = reader.next_entry()? {
                if !selected(entry.path()) {
                    reader.skip_entry_data(&entry)?;
                    report.skipped_entries += 1;
                    continue;
                }
                if matches!(entry.kind(), zmanager_apple_archive::EntryKind::File) {
                    ensure_file_entry_has_data(&entry)?;
                    report.tested_bytes += reader.read_entry_data(&entry, &mut sink, |_| true)?;
                } else {
                    reader.skip_entry_data(&entry)?;
                }
                report.tested_entries += 1;
            }

            Ok(report)
        }

        fn extract_apple_archive_inner(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            selected_entry: Option<&str>,
            overwrite_resolver: Option<&mut dyn OverwriteResolver>,
            mut context: Option<&mut JobContext<'_>>,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            let destination = destination.as_ref();
            let destination_root =
                crate::safety::prepare_destination_root(destination).map_err(|source| AppleArchiveError::Io { path: destination.to_path_buf(), source })?;
            let mut reader = open_apple_archive_reader(archive_path, password)?;
            let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
            let mut report = AppleArchiveExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
            let mut found_selected_entry = selected_entry.is_none();
            let mut deferred_directories = Vec::new();

            while let Some(entry) = reader.next_entry()? {
                if let Some(selected_entry) = selected_entry
                    && !crate::safety::archive_entry_matches_selected(entry.path(), selected_entry)
                {
                    reader.skip_entry_data(&entry)?;
                    continue;
                }
                found_selected_entry = true;
                let safety_entry = ExtractionEntry {
                    archive_path: entry.path().to_owned(),
                    kind: extraction_kind(&entry)?,
                    uncompressed_size: entry.size(),
                    compressed_size: None,
                };

                crate::extract_loop::process_extraction_entry(
                    &mut report,
                    context.as_deref_mut(),
                    &mut planner,
                    &safety_entry,
                    &mut |action, report, context| match action {
                        crate::extract_loop::EntryAction::Skip => {
                            reader.skip_entry_data(&entry)?;
                            Ok(0)
                        }
                        crate::extract_loop::EntryAction::Write(decision) => {
                            materialize_entry(&mut reader, &entry, &safety_entry, &decision, context, &mut deferred_directories, report)
                        }
                    },
                )?;
            }

            if !found_selected_entry && let Some(path) = selected_entry {
                return Err(AppleArchiveError::EntryNotFound { path: path.to_owned() });
            }

            apply_deferred_directory_metadata(&deferred_directories)?;
            Ok(report)
        }

        fn materialize_entry(
            reader: &mut ArchiveReader,
            entry: &zmanager_apple_archive::Entry,
            safety_entry: &ExtractionEntry,
            decision: &crate::extract_loop::WriteDecision<'_>,
            mut context: Option<&mut JobContext<'_>>,
            deferred_directories: &mut Vec<(PathBuf, zmanager_apple_archive::EntryMetadata)>,
            report: &mut AppleArchiveExtractReport,
        ) -> Result<u64, AppleArchiveError> {
            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                reader.skip_entry_data(entry)?;
                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                return Ok(0);
            }

            if decision.replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                crate::safety::remove_destination_for_replace(decision.destination_path)
                    .map_err(|source| AppleArchiveError::Io { path: decision.destination_path.to_path_buf(), source })?;
            }

            let written_bytes = match &safety_entry.kind {
                ExtractionEntryKind::Directory => {
                    reader.skip_entry_data(entry)?;
                    fs::create_dir_all(decision.destination_path)
                        .map_err(|source| AppleArchiveError::Io { path: decision.destination_path.to_path_buf(), source })?;
                    deferred_directories.push((decision.destination_path.to_path_buf(), entry.metadata()));
                    0
                }
                ExtractionEntryKind::File => write_file_entry(reader, entry, safety_entry, decision, context.as_deref_mut())?,
                ExtractionEntryKind::Symlink { target } => {
                    reader.skip_entry_data(entry)?;
                    write_symlink(target, decision.destination_path)?;
                    apply_symlink_mtime(decision.destination_path, entry.metadata().modified)?;
                    zmanager_apple_archive::apply_native_metadata(decision.destination_path, entry.metadata(), true)?;
                    0
                }
                ExtractionEntryKind::Hardlink { .. } => {
                    reader.skip_entry_data(entry)?;
                    let source_path = decision.link_target_path.ok_or_else(|| AppleArchiveError::Io {
                        path: decision.destination_path.to_path_buf(),
                        source: crate::extract_loop::unresolved_hardlink_target(),
                    })?;
                    write_hardlink(source_path, decision.destination_path)?;
                    0
                }
                ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                    reader.skip_entry_data(entry)?;
                    crate::extract_loop::skip_entry(report, context, format!("skipped unsupported special entry {}", safety_entry.archive_path));
                    return Ok(0);
                }
            };

            report.written_entries += 1;
            report.written_bytes += written_bytes;
            Ok(written_bytes)
        }

        fn write_file_entry(
            reader: &mut ArchiveReader,
            entry: &zmanager_apple_archive::Entry,
            safety_entry: &ExtractionEntry,
            decision: &crate::extract_loop::WriteDecision<'_>,
            mut context: Option<&mut JobContext<'_>>,
        ) -> Result<u64, AppleArchiveError> {
            ensure_file_entry_has_data(entry)?;
            let mut output = crate::atomic_file::AtomicOutputFile::create(decision.destination_path)
                .map_err(|source| AppleArchiveError::Io { path: decision.destination_path.to_path_buf(), source })?;
            let written_bytes = reader.read_entry_data(
                entry,
                output.file_mut().map_err(|source| AppleArchiveError::Io { path: decision.destination_path.to_path_buf(), source })?,
                |bytes| {
                    if let Some(context) = context.as_deref_mut() {
                        if context.check_cancelled().is_err() {
                            return false;
                        }
                        context.bytes_processed(Some(&safety_entry.archive_path), bytes);
                    }
                    true
                },
            )?;
            output
                .commit_with_replace(decision.replace_existing)
                .map_err(|source| AppleArchiveError::Io { path: decision.destination_path.to_path_buf(), source })?;
            apply_metadata(decision.destination_path, entry.metadata())?;
            Ok(written_bytes)
        }

        fn append_manifest_entry(
            writer: &mut ArchiveWriter,
            entry: &ManifestEntry,
            options: &AppleArchiveCreateOptions,
            report: &mut AppleArchiveCreateReport,
            mut context: Option<&mut JobContext<'_>>,
        ) -> Result<(), AppleArchiveError> {
            if let Some(context) = context.as_deref_mut() {
                context.check_cancelled()?;
                context.entry_started(&entry.archive_path, Some(entry.size));
                context.check_cancelled()?;
            }

            let metadata = if options.preserve_metadata {
                use std::os::unix::fs::MetadataExt as _;

                let source_metadata =
                    fs::symlink_metadata(&entry.source_path).map_err(|source| AppleArchiveError::Io { path: entry.source_path.clone(), source })?;
                zmanager_apple_archive::EntryMetadata {
                    mode: entry.permissions.unix_mode,
                    modified: entry.modified,
                    created: source_metadata.created().ok(),
                    flags: apple_file_flags(&source_metadata),
                    crc: None,
                    uid: Some(source_metadata.uid()),
                    gid: Some(source_metadata.gid()),
                }
            } else {
                zmanager_apple_archive::EntryMetadata::default()
            };
            let processed = match entry.file_type {
                ManifestFileType::Directory => {
                    writer.append_directory(&entry.archive_path, metadata)?;
                    report.written_entries += 1;
                    0
                }
                ManifestFileType::File => {
                    let mut source = File::open(&entry.source_path).map_err(|source| AppleArchiveError::Io { path: entry.source_path.clone(), source })?;
                    let mut cancelled = false;
                    let written = writer.append_file(&entry.archive_path, entry.size, metadata, &mut source, |bytes| {
                        if let Some(context) = context.as_deref_mut() {
                            if context.check_cancelled().is_err() {
                                cancelled = true;
                                return false;
                            }
                            context.bytes_processed(Some(&entry.archive_path), bytes);
                        }
                        true
                    })?;
                    if cancelled {
                        return Err(AppleArchiveError::Cancelled);
                    }
                    report.written_entries += 1;
                    report.written_bytes += written;
                    written
                }
                ManifestFileType::Symlink => {
                    let Some(target) = &entry.symlink_target else {
                        let warning = format!("skipped symlink {}: missing target", entry.archive_path);
                        report.warnings.push(warning.clone());
                        if let Some(context) = context.as_deref_mut() {
                            context.warning(warning);
                        }
                        return Ok(());
                    };
                    writer.append_symlink(&entry.archive_path, target, metadata)?;
                    report.written_entries += 1;
                    0
                }
                ManifestFileType::Other => {
                    let warning = format!("skipped special file {}: AppleArchive backend only writes files, directories, and symlinks", entry.archive_path);
                    report.warnings.push(warning.clone());
                    if let Some(context) = context.as_deref_mut() {
                        context.warning(warning);
                    }
                    0
                }
            };

            if let Some(context) = context {
                context.entry_finished(&entry.archive_path, processed);
            }
            Ok(())
        }

        // The `Option` here is deliberate: the non-macos variant below cannot read
        // flags, and callers distinguish "no flags read" (`None`) from "flags are
        // zero" (`Some(0)`).
        #[cfg(target_os = "macos")]
        #[allow(clippy::unnecessary_wraps)]
        fn apple_file_flags(metadata: &fs::Metadata) -> Option<u32> {
            use std::os::macos::fs::MetadataExt as _;

            Some(metadata.st_flags())
        }

        #[cfg(not(target_os = "macos"))]
        fn apple_file_flags(_metadata: &fs::Metadata) -> Option<u32> {
            None
        }

        fn ensure_file_entry_has_data(entry: &zmanager_apple_archive::Entry) -> Result<(), AppleArchiveError> {
            if entry.has_data_blob() || entry.size().unwrap_or(0) == 0 {
                Ok(())
            } else {
                Err(AppleArchiveError::MissingFileData { path: entry.path().to_owned() })
            }
        }

        fn apple_entry_kind(kind: zmanager_apple_archive::EntryKind) -> AppleArchiveEntryKind {
            match kind {
                zmanager_apple_archive::EntryKind::File => AppleArchiveEntryKind::File,
                zmanager_apple_archive::EntryKind::Directory => AppleArchiveEntryKind::Directory,
                zmanager_apple_archive::EntryKind::Symlink => AppleArchiveEntryKind::Symlink,
                zmanager_apple_archive::EntryKind::Device => AppleArchiveEntryKind::Device,
                zmanager_apple_archive::EntryKind::Metadata | zmanager_apple_archive::EntryKind::Special => AppleArchiveEntryKind::Special,
            }
        }

        fn extraction_kind(entry: &zmanager_apple_archive::Entry) -> Result<ExtractionEntryKind, AppleArchiveError> {
            match entry.kind() {
                zmanager_apple_archive::EntryKind::File => Ok(ExtractionEntryKind::File),
                zmanager_apple_archive::EntryKind::Directory => Ok(ExtractionEntryKind::Directory),
                zmanager_apple_archive::EntryKind::Symlink => {
                    let target = entry.link_target().ok_or_else(|| AppleArchiveError::MissingLinkTarget { path: entry.path().to_owned() })?;
                    Ok(ExtractionEntryKind::Symlink { target: target.to_path_buf() })
                }
                zmanager_apple_archive::EntryKind::Device => Ok(ExtractionEntryKind::Device),
                zmanager_apple_archive::EntryKind::Metadata | zmanager_apple_archive::EntryKind::Special => Ok(ExtractionEntryKind::Special),
            }
        }

        fn apply_deferred_directory_metadata(directories: &[(PathBuf, zmanager_apple_archive::EntryMetadata)]) -> Result<(), AppleArchiveError> {
            crate::extract_loop::apply_deferred_directory_metadata(directories, |(path, metadata)| apply_metadata(path, *metadata))
        }

        pub(crate) fn apply_metadata(path: &Path, metadata: zmanager_apple_archive::EntryMetadata) -> Result<(), AppleArchiveError> {
            fs::symlink_metadata(path).map_err(|source| AppleArchiveError::Io { path: path.to_path_buf(), source })?;

            crate::extract_materialize::apply_metadata(path, metadata.mode, metadata.modified.map(system_time_to_filetime))
                .map_err(|source| AppleArchiveError::Io { path: path.to_path_buf(), source })?;

            zmanager_apple_archive::apply_native_metadata(path, metadata, false)?;

            Ok(())
        }

        /// Uses `set_symlink_file_times` to avoid following the link. Errors are
        /// reported so extraction cannot claim metadata was restored when it was not.
        fn apply_symlink_mtime(path: &Path, modified: Option<SystemTime>) -> Result<(), AppleArchiveError> {
            crate::extract_materialize::apply_symlink_mtime(path, modified.map(system_time_to_filetime))
                .map_err(|source| AppleArchiveError::Io { path: path.to_path_buf(), source })
        }

        fn system_time_to_filetime(time: SystemTime) -> filetime::FileTime {
            filetime::FileTime::from_system_time(time)
        }

        fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
            crate::extract_materialize::write_hardlink(source_path, destination_path)
                .map_err(|source| AppleArchiveError::Io { path: destination_path.to_path_buf(), source })
        }

        #[cfg(unix)]
        fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
            crate::extract_materialize::write_symlink(target, destination_path)
                .map_err(|source| AppleArchiveError::Io { path: destination_path.to_path_buf(), source })
        }

        #[cfg(not(unix))]
        fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
            Err(AppleArchiveError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::Unsupported, "symlink extraction is not supported on this platform"),
            })
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[allow(unused_variables, clippy::needless_pass_by_value)] // parameters mirror the Apple implementation's signatures
    mod stub_impl {
        use super::super::{
            AppleArchiveCreateOptions, AppleArchiveCreateReport, AppleArchiveError, AppleArchiveExtractReport, AppleArchiveListing, AppleArchiveTestReport,
        };
        use crate::jobs::JobContext;
        use crate::manifest::ArchiveManifest;
        use crate::safety::{ExtractionPolicy, OverwriteResolver};
        use std::io::Write;
        use std::path::Path;

        pub(crate) fn create_apple_archive_from_path(
            source: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn create_apple_archive_from_manifest(
            manifest: &ArchiveManifest,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn create_apple_archive_from_manifest_with_context(
            manifest: &ArchiveManifest,
            destination: impl AsRef<Path>,
            options: &AppleArchiveCreateOptions,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn list_apple_archive(path: impl AsRef<Path>, password: Option<&str>) -> Result<AppleArchiveListing, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_with_context(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_with_context_and_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_with_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_entry(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_entry_with_context(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_entry_with_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn extract_apple_archive_entry_with_context_and_overwrite_resolver(
            archive_path: impl AsRef<Path>,
            entry_path: &str,
            destination: impl AsRef<Path>,
            policy: ExtractionPolicy,
            overwrite_resolver: &mut dyn OverwriteResolver,
            password: Option<&str>,
            context: &mut JobContext<'_>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn copy_apple_archive_files_to_writer<W: Write + ?Sized>(
            archive_path: impl AsRef<Path>,
            selected: impl FnMut(&str) -> bool,
            output: &mut W,
            password: Option<&str>,
        ) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }

        pub(crate) fn test_apple_archive_filter(
            archive_path: impl AsRef<Path>,
            selected: impl FnMut(&str) -> bool,
            password: Option<&str>,
        ) -> Result<AppleArchiveTestReport, AppleArchiveError> {
            Err(AppleArchiveError::Unsupported)
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(super) use apple_impl::*;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    pub(super) use stub_impl::*;
}

/// Creates an `AppleArchive` from a source path.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when planning, filesystem reads, native
/// writing, or commit fails. On platforms without native `AppleArchive`
/// support this returns [`AppleArchiveError::Unsupported`].
pub fn create_apple_archive_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &AppleArchiveCreateOptions,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    imp::create_apple_archive_from_path(source, destination, options)
}

/// Creates an `AppleArchive` from a manifest.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when source files cannot be read, native
/// writing fails, or commit fails. On platforms without native `AppleArchive`
/// support this returns [`AppleArchiveError::Unsupported`].
pub fn create_apple_archive_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &AppleArchiveCreateOptions,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    imp::create_apple_archive_from_manifest(manifest, destination, options)
}

/// Creates an `AppleArchive` from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when source files cannot be read, native
/// writing fails, commit fails, or cancellation is requested. On platforms
/// without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn create_apple_archive_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &AppleArchiveCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    imp::create_apple_archive_from_manifest_with_context(manifest, destination, options, context)
}

/// Lists entries in an `AppleArchive`.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the native reader cannot open or read the
/// archive. On platforms without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn list_apple_archive(path: impl AsRef<Path>, password: Option<&str>) -> Result<AppleArchiveListing, AppleArchiveError> {
    imp::list_apple_archive(path, password)
}

/// Extracts an `AppleArchive` through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
/// unsafe, or filesystem writes fail. On platforms without native
/// `AppleArchive` support this returns [`AppleArchiveError::Unsupported`].
pub fn extract_apple_archive(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive(archive_path, destination, policy, password)
}

/// Extracts an `AppleArchive` while emitting job events.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
/// unsafe, filesystem writes fail, or cancellation is requested. On platforms
/// without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn extract_apple_archive_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_with_context(archive_path, destination, policy, password, context)
}

/// Extracts an `AppleArchive` while emitting job events and resolving overwrites.
pub fn extract_apple_archive_with_context_and_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_with_context_and_overwrite_resolver(archive_path, destination, policy, overwrite_resolver, password, context)
}

/// Extracts an `AppleArchive` with an overwrite resolver.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
/// unsafe, filesystem writes fail, or the resolver aborts extraction. On
/// platforms without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn extract_apple_archive_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
    password: Option<&str>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_with_overwrite_resolver(archive_path, destination, policy, overwrite_resolver, password)
}

/// Extracts one selected `AppleArchive` entry.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, the entry is
/// unsafe, the selected entry is not found, or filesystem writes fail. On
/// platforms without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn extract_apple_archive_entry(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_entry(archive_path, entry_path, destination, policy, password)
}

/// Extracts one selected `AppleArchive` entry while emitting job events.
pub fn extract_apple_archive_entry_with_context(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_entry_with_context(archive_path, entry_path, destination, policy, password, context)
}

/// Extracts one selected `AppleArchive` entry with an overwrite resolver.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, the entry is
/// unsafe, the selected entry is not found, filesystem writes fail, or the
/// resolver aborts extraction. On platforms without native `AppleArchive`
/// support this returns [`AppleArchiveError::Unsupported`].
pub fn extract_apple_archive_entry_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
    password: Option<&str>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_entry_with_overwrite_resolver(archive_path, entry_path, destination, policy, overwrite_resolver, password)
}

/// Extracts one selected `AppleArchive` entry while emitting job events and
/// resolving overwrites.
pub fn extract_apple_archive_entry_with_context_and_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::extract_apple_archive_entry_with_context_and_overwrite_resolver(archive_path, entry_path, destination, policy, overwrite_resolver, password, context)
}

/// Copies the one selected regular file entry to a writer.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, the
/// selection does not resolve to exactly one regular file, or output writing
/// fails. On platforms without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn copy_apple_archive_files_to_writer<W: Write + ?Sized>(
    archive_path: impl AsRef<Path>,
    selected: impl FnMut(&str) -> bool,
    output: &mut W,
    password: Option<&str>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    imp::copy_apple_archive_files_to_writer(archive_path, selected, output, password)
}

/// Reads selected `AppleArchive` entries to validate data streams.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be opened or read.
/// On platforms without native `AppleArchive` support this returns
/// [`AppleArchiveError::Unsupported`].
pub fn test_apple_archive_filter(
    archive_path: impl AsRef<Path>,
    selected: impl FnMut(&str) -> bool,
    password: Option<&str>,
) -> Result<AppleArchiveTestReport, AppleArchiveError> {
    imp::test_apple_archive_filter(archive_path, selected, password)
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use super::{AppleArchiveCompression, AppleArchiveCreateOptions, create_apple_archive_from_path, extract_apple_archive, test_apple_archive_filter};
    use super::{apple_archive_supported, is_apple_archive_path, list_apple_archive};
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use crate::safety::ExtractionPolicy;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use crate::test_support::TestDir;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use std::fs;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use std::time::UNIX_EPOCH;

    #[test]
    fn detects_aar_extension_case_insensitively() {
        assert!(is_apple_archive_path("archive.aar"));
        assert!(is_apple_archive_path("archive.AAR"));
        assert!(!is_apple_archive_path("archive.zip"));
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn application_of_metadata_propagates_io_errors() {
        use super::AppleArchiveError;
        use std::path::Path;
        let nonexistent = Path::new("does_not_exist_aar");
        let metadata = zmanager_apple_archive::EntryMetadata { mode: Some(0o644), ..zmanager_apple_archive::EntryMetadata::default() };

        let result = super::imp::apply_metadata(nonexistent, metadata);

        // This should fail because the file doesn't exist
        assert!(matches!(result, Err(AppleArchiveError::Io { .. })));
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn creates_lists_tests_and_extracts_apple_archive() {
        let temp = TestDir::new("apple_archive_roundtrip");
        temp.write_file("project/README.md", b"hello aar");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        fs::create_dir_all(temp.path("project/empty")).unwrap();
        let archive = temp.path("project.aar");

        let create_report = create_apple_archive_from_path(
            temp.path("project"),
            &archive,
            &AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, ..AppleArchiveCreateOptions::default() },
        )
        .unwrap();
        assert!(create_report.written_entries >= 3);
        assert_eq!(create_report.written_bytes, 22);

        let listing = list_apple_archive(&archive, None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/README.md"));
        test_apple_archive_filter(&archive, |_| true, None).unwrap();

        let extract_report = extract_apple_archive(&archive, temp.path("out"), ExtractionPolicy::default(), None).unwrap();
        assert!(extract_report.written_entries >= 3);
        assert_eq!(fs::read_to_string(temp.path("out/project/README.md")).unwrap(), "hello aar");
        assert!(temp.path("out/project/empty").is_dir());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn create_and_extract_preserve_complete_apple_archive_metadata() {
        use std::os::macos::fs::MetadataExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let temp = TestDir::new("apple_archive_complete_metadata");
        temp.write_file("project/native.txt", b"native metadata");
        let source = temp.path("project/native.txt");
        assert!(std::process::Command::new("/usr/bin/chflags").arg("hidden").arg(&source).status().unwrap().success());
        let expected = fs::metadata(&source).unwrap();
        let archive = temp.path("metadata.aar");

        create_apple_archive_from_path(
            temp.path("project"),
            &archive,
            &AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, preserve_metadata: true, ..AppleArchiveCreateOptions::default() },
        )
        .unwrap();

        let listing = list_apple_archive(&archive, None).unwrap();
        let entry = listing.entries.iter().find(|entry| entry.path == "project/native.txt").unwrap();
        assert_eq!(entry.flags, Some(expected.st_flags()));
        assert_eq!(entry.uid, Some(expected.uid()));
        assert_eq!(entry.gid, Some(expected.gid()));
        assert!(entry.created.is_some());

        let destination = temp.path("out");
        extract_apple_archive(&archive, &destination, ExtractionPolicy::default(), None).unwrap();
        let restored = fs::metadata(destination.join("project/native.txt")).unwrap();
        assert_eq!(restored.st_flags(), expected.st_flags());
        assert_eq!(restored.uid(), expected.uid());
        assert_eq!(restored.gid(), expected.gid());
        assert_eq!(restored.created().unwrap(), expected.created().unwrap());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn extracts_symlinks_and_preserves_metadata() {
        use filetime::{FileTime, set_symlink_file_times};
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("apple_archive_symlink_meta");
        temp.write_file("project/target.txt", b"target");
        let symlink_path = temp.path("project/link");
        symlink("target.txt", &symlink_path).unwrap();

        // Set a specific timestamp on the symlink
        let past = FileTime::from_unix_time(1_000_000_000, 0);
        set_symlink_file_times(&symlink_path, past, past).unwrap();

        let archive = temp.path("project.aar");

        create_apple_archive_from_path(
            temp.path("project"),
            &archive,
            &AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, ..AppleArchiveCreateOptions::default() },
        )
        .unwrap();

        let out_dir = temp.path("out");
        extract_apple_archive(&archive, &out_dir, ExtractionPolicy::default(), None).unwrap();

        let extracted_symlink = out_dir.join("project/link");
        let metadata = fs::symlink_metadata(&extracted_symlink).unwrap();

        let mtime = metadata.modified().unwrap();
        let mtime_secs = i64::try_from(mtime.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let diff = (mtime_secs - 1_000_000_000).abs();
        assert!(diff <= 2, "extracted mtime diff {diff} is greater than 2 seconds");
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn preserves_pre_epoch_file_modification_time() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("apple_archive_pre_epoch_mtime");
        temp.write_file("project/old.txt", b"old");
        let source = temp.path("project/old.txt");
        let old_time = filetime::FileTime::from_unix_time(-2, 750_000_000);
        filetime::set_file_mtime(&source, old_time).unwrap();
        let archive = temp.path("project.aar");

        create_apple_archive_from_path(
            temp.path("project"),
            &archive,
            &AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, ..AppleArchiveCreateOptions::default() },
        )
        .unwrap();
        extract_apple_archive(&archive, temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let metadata = fs::metadata(temp.path("out/project/old.txt")).unwrap();
        assert_eq!(metadata.mtime(), -2);
        assert_eq!(metadata.mtime_nsec(), 750_000_000);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn native_operations_return_unsupported_on_non_apple_targets() {
        let error = list_apple_archive("archive.aar", None).unwrap_err();
        assert!(error.to_string().contains("supported only on macOS and iOS"));
        assert!(!apple_archive_supported());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn native_operations_report_supported_on_apple_targets() {
        assert!(apple_archive_supported());
    }
}
