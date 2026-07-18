use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{
    ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive,
};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_apple_archive::{ArchiveReader, ArchiveWriter};

pub use zmanager_apple_archive::CompressionAlgorithm as AppleArchiveCompression;

#[cfg(unix)]
const APPLE_ARCHIVE_MODE_MASK: u32 = 0o7777;

/// `.aar` file extension.
pub const APPLE_ARCHIVE_EXTENSION: &str = "aar";

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
}

impl Default for AppleArchiveCreateOptions {
    fn default() -> Self {
        let native = zmanager_apple_archive::CreateOptions::default();
        Self {
            compression: native.compression,
            block_size: native.block_size,
            threads: native.threads,
            preserve_metadata: true,
            replace_existing: false,
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
    Native(zmanager_apple_archive::Error),
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
}

impl fmt::Display for AppleArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Native(source) => write!(f, "AppleArchive operation failed: {source}"),
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
            Self::Native(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingLinkTarget { .. }
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

impl From<zmanager_apple_archive::Error> for AppleArchiveError {
    fn from(source: zmanager_apple_archive::Error) -> Self {
        match source {
            zmanager_apple_archive::Error::Cancelled => Self::Cancelled,
            source => Self::Native(source),
        }
    }
}

impl From<ExtractionSafetyError> for AppleArchiveError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for AppleArchiveError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Returns whether this build can use native `AppleArchive` APIs.
#[must_use]
pub const fn apple_archive_supported() -> bool {
    zmanager_apple_archive::is_supported()
}

/// Returns whether a path has the `.aar` extension.
#[must_use]
pub fn is_apple_archive_path(path: impl AsRef<Path>) -> bool {
    path.as_ref()
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(APPLE_ARCHIVE_EXTENSION))
}

/// Creates an `AppleArchive` from a source path.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when planning, filesystem reads, native
/// writing, or commit fails.
pub fn create_apple_archive_from_path(
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
pub fn create_apple_archive_from_manifest(
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
pub fn create_apple_archive_from_manifest_with_context(
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
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            AppleArchiveError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let temp_path = output.temp_path().to_path_buf();
    output.close();

    let native_options = zmanager_apple_archive::CreateOptions {
        compression: options.compression,
        block_size: options.block_size,
        threads: options.threads,
    };
    let mut writer = ArchiveWriter::create(&temp_path, native_options)?;
    let mut report = AppleArchiveCreateReport {
        written_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in &manifest.entries {
        append_manifest_entry(
            &mut writer,
            entry,
            options,
            &mut report,
            context.as_deref_mut(),
        )?;
    }

    writer.finish()?;
    output
        .commit_with_file_replace(options.replace_existing)
        .map_err(|source| AppleArchiveError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

    Ok(report)
}

/// Lists entries in an `AppleArchive`.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the native reader cannot open or read the
/// archive.
pub fn list_apple_archive(
    path: impl AsRef<Path>,
) -> Result<AppleArchiveListing, AppleArchiveError> {
    let mut reader = ArchiveReader::open(path)?;
    let mut entries = Vec::new();

    while let Some(entry) = reader.next_entry()? {
        entries.push(AppleArchiveListEntry {
            path: entry.path().to_owned(),
            kind: apple_entry_kind(entry.kind()),
            size: entry.size(),
            modified: entry.metadata().modified,
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
pub fn extract_apple_archive(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    extract_apple_archive_inner(archive_path, destination, policy, None, None, None)
}

/// Extracts an `AppleArchive` while emitting job events.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
/// unsafe, filesystem writes fail, or cancellation is requested.
pub fn extract_apple_archive_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    extract_apple_archive_inner(archive_path, destination, policy, None, None, Some(context))
}

/// Extracts an `AppleArchive` with an overwrite resolver.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, an entry is
/// unsafe, filesystem writes fail, or the resolver aborts extraction.
pub fn extract_apple_archive_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    extract_apple_archive_inner(
        archive_path,
        destination,
        policy,
        None,
        Some(overwrite_resolver),
        None,
    )
}

/// Extracts one selected `AppleArchive` entry.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, the entry is
/// unsafe, the selected entry is not found, or filesystem writes fail.
pub fn extract_apple_archive_entry(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    extract_apple_archive_inner(
        archive_path,
        destination,
        policy,
        Some(entry_path),
        None,
        None,
    )
}

/// Copies the one selected regular file entry to a writer.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be read, the
/// selection does not resolve to exactly one regular file, or output writing
/// fails.
pub fn copy_apple_archive_files_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    let archive_path = archive_path.as_ref();
    let mut reader = ArchiveReader::open(archive_path)?;
    let mut report = AppleArchiveExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut selected_files = 0_usize;
    let mut staged_file = None;

    while let Some(entry) = reader.next_entry()? {
        if !selected(entry.path())
            || !matches!(entry.kind(), zmanager_apple_archive::EntryKind::File)
        {
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
            .map_err(|source| AppleArchiveError::Io {
                path: std::env::temp_dir(),
                source,
            })?;
        let copied = reader.read_entry_data(&entry, staged.file_mut(), |_| true)?;
        report.written_entries += 1;
        report.written_bytes += copied;
        staged_file = Some(staged);
    }

    if selected_files != 1 {
        return Err(AppleArchiveError::StdoutSelectionNotSingleFile { selected_files });
    }

    let mut staged =
        staged_file.ok_or(AppleArchiveError::StdoutSelectionNotSingleFile { selected_files: 0 })?;
    staged
        .file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|source| AppleArchiveError::Io {
            path: staged.path().to_path_buf(),
            source,
        })?;
    io::copy(staged.file_mut(), output)
        .map_err(|source| AppleArchiveError::Io {
            path: staged.path().to_path_buf(),
            source,
        })
        .map(|_| report)
}

/// Reads selected `AppleArchive` entries to validate data streams.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when the archive cannot be opened or read.
pub fn test_apple_archive_filter(
    archive_path: impl AsRef<Path>,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<AppleArchiveTestReport, AppleArchiveError> {
    let mut reader = ArchiveReader::open(archive_path)?;
    let mut report = AppleArchiveTestReport {
        tested_entries: 0,
        skipped_entries: 0,
        tested_bytes: 0,
    };
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
) -> Result<AppleArchiveExtractReport, AppleArchiveError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            AppleArchiveError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let mut reader = ArchiveReader::open(archive_path)?;
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = AppleArchiveExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut found_selected_entry = selected_entry.is_none();
    let mut deferred_directories = Vec::new();

    while let Some(entry) = reader.next_entry()? {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        if let Some(selected_entry) = selected_entry
            && entry.path() != selected_entry
        {
            reader.skip_entry_data(&entry)?;
            continue;
        }
        found_selected_entry = true;
        let extraction_kind = extraction_kind(&entry)?;
        if is_archive_root_directory(entry.path(), &extraction_kind) {
            reader.skip_entry_data(&entry)?;
            report.skipped_entries += 1;
            let warning = "skipped archive root directory entry".to_owned();
            report.warnings.push(warning.clone());
            if let Some(context) = context.as_deref_mut() {
                context.warning(warning);
            }
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: entry.path().to_owned(),
            kind: extraction_kind,
            uncompressed_size: entry.size(),
            compressed_size: None,
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&safety_entry.archive_path, entry.size());
            context.check_cancelled()?;
        }

        let processed = match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => materialize_entry(
                &mut reader,
                &entry,
                &safety_entry,
                WriteDecision {
                    destination_path: &destination_path,
                    replace_existing,
                    link_target_path: link_target_path.as_deref(),
                },
                context.as_deref_mut(),
                &mut deferred_directories,
                &mut report,
            )?,
            ExtractionDecision::Skip { reason, .. } => {
                reader.skip_entry_data(&entry)?;
                report.skipped_entries += 1;
                let warning = format!("skipped {}: {reason}", safety_entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                }
                0
            }
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_finished(&safety_entry.archive_path, processed);
        }
    }

    if !found_selected_entry && let Some(path) = selected_entry {
        return Err(AppleArchiveError::EntryNotFound {
            path: path.to_owned(),
        });
    }

    apply_deferred_directory_metadata(&deferred_directories)?;
    Ok(report)
}

struct WriteDecision<'a> {
    destination_path: &'a Path,
    replace_existing: bool,
    link_target_path: Option<&'a Path>,
}

fn materialize_entry(
    reader: &mut ArchiveReader,
    entry: &zmanager_apple_archive::Entry,
    safety_entry: &ExtractionEntry,
    decision: WriteDecision<'_>,
    mut context: Option<&mut JobContext<'_>>,
    deferred_directories: &mut Vec<(PathBuf, zmanager_apple_archive::EntryMetadata)>,
    report: &mut AppleArchiveExtractReport,
) -> Result<u64, AppleArchiveError> {
    if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
        reader.skip_entry_data(entry)?;
        report.skipped_entries += 1;
        let warning = crate::safety::unsupported_symlink_warning(&safety_entry.archive_path);
        report.warnings.push(warning.clone());
        if let Some(context) = context.as_deref_mut() {
            context.warning(warning);
        }
        return Ok(0);
    }

    if decision.replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
        crate::safety::remove_destination_for_replace(decision.destination_path).map_err(
            |source| AppleArchiveError::Io {
                path: decision.destination_path.to_path_buf(),
                source,
            },
        )?;
    }

    let written_bytes = match &safety_entry.kind {
        ExtractionEntryKind::Directory => {
            reader.skip_entry_data(entry)?;
            fs::create_dir_all(decision.destination_path).map_err(|source| {
                AppleArchiveError::Io {
                    path: decision.destination_path.to_path_buf(),
                    source,
                }
            })?;
            deferred_directories.push((decision.destination_path.to_path_buf(), entry.metadata()));
            0
        }
        ExtractionEntryKind::File => write_file_entry(
            reader,
            entry,
            safety_entry,
            &decision,
            context.as_deref_mut(),
        )?,
        ExtractionEntryKind::Symlink { target } => {
            reader.skip_entry_data(entry)?;
            write_symlink(target, decision.destination_path)?;
            apply_symlink_mtime(decision.destination_path, entry.metadata().modified);
            0
        }
        ExtractionEntryKind::Hardlink { .. } => {
            reader.skip_entry_data(entry)?;
            let source_path = decision
                .link_target_path
                .ok_or_else(|| AppleArchiveError::Io {
                    path: decision.destination_path.to_path_buf(),
                    source: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hardlink target was not resolved by extraction safety planning",
                    ),
                })?;
            write_hardlink(source_path, decision.destination_path)?;
            0
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
            reader.skip_entry_data(entry)?;
            report.skipped_entries += 1;
            let warning = format!(
                "skipped unsupported special entry {}",
                safety_entry.archive_path
            );
            report.warnings.push(warning.clone());
            if let Some(context) = context {
                context.warning(warning);
            }
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
    decision: &WriteDecision<'_>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<u64, AppleArchiveError> {
    ensure_file_entry_has_data(entry)?;
    let mut output = crate::atomic_file::AtomicOutputFile::create(decision.destination_path)
        .map_err(|source| AppleArchiveError::Io {
            path: decision.destination_path.to_path_buf(),
            source,
        })?;
    let written_bytes = reader.read_entry_data(
        entry,
        output.file_mut().map_err(|source| AppleArchiveError::Io {
            path: decision.destination_path.to_path_buf(),
            source,
        })?,
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
        .map_err(|source| AppleArchiveError::Io {
            path: decision.destination_path.to_path_buf(),
            source,
        })?;
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
        zmanager_apple_archive::EntryMetadata {
            mode: entry.permissions.unix_mode,
            modified: entry.modified,
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
            let mut source =
                File::open(&entry.source_path).map_err(|source| AppleArchiveError::Io {
                    path: entry.source_path.clone(),
                    source,
                })?;
            let mut cancelled = false;
            let written = writer.append_file(
                &entry.archive_path,
                entry.size,
                metadata,
                &mut source,
                |bytes| {
                    if let Some(context) = context.as_deref_mut() {
                        if context.check_cancelled().is_err() {
                            cancelled = true;
                            return false;
                        }
                        context.bytes_processed(Some(&entry.archive_path), bytes);
                    }
                    true
                },
            )?;
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
            let warning = format!(
                "skipped special file {}: AppleArchive backend only writes files, directories, and symlinks",
                entry.archive_path
            );
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

fn ensure_file_entry_has_data(
    entry: &zmanager_apple_archive::Entry,
) -> Result<(), AppleArchiveError> {
    if entry.has_data_blob() || entry.size().unwrap_or(0) == 0 {
        Ok(())
    } else {
        Err(AppleArchiveError::MissingFileData {
            path: entry.path().to_owned(),
        })
    }
}

fn apple_entry_kind(kind: zmanager_apple_archive::EntryKind) -> AppleArchiveEntryKind {
    match kind {
        zmanager_apple_archive::EntryKind::File => AppleArchiveEntryKind::File,
        zmanager_apple_archive::EntryKind::Directory => AppleArchiveEntryKind::Directory,
        zmanager_apple_archive::EntryKind::Symlink => AppleArchiveEntryKind::Symlink,
        zmanager_apple_archive::EntryKind::Device => AppleArchiveEntryKind::Device,
        zmanager_apple_archive::EntryKind::Metadata
        | zmanager_apple_archive::EntryKind::Special => AppleArchiveEntryKind::Special,
    }
}

fn extraction_kind(
    entry: &zmanager_apple_archive::Entry,
) -> Result<ExtractionEntryKind, AppleArchiveError> {
    match entry.kind() {
        zmanager_apple_archive::EntryKind::File => Ok(ExtractionEntryKind::File),
        zmanager_apple_archive::EntryKind::Directory => Ok(ExtractionEntryKind::Directory),
        zmanager_apple_archive::EntryKind::Symlink => {
            let target =
                entry
                    .link_target()
                    .ok_or_else(|| AppleArchiveError::MissingLinkTarget {
                        path: entry.path().to_owned(),
                    })?;
            Ok(ExtractionEntryKind::Symlink {
                target: target.to_path_buf(),
            })
        }
        zmanager_apple_archive::EntryKind::Device => Ok(ExtractionEntryKind::Device),
        zmanager_apple_archive::EntryKind::Metadata
        | zmanager_apple_archive::EntryKind::Special => Ok(ExtractionEntryKind::Special),
    }
}

fn is_archive_root_directory(path: &str, kind: &ExtractionEntryKind) -> bool {
    matches!(kind, ExtractionEntryKind::Directory) && is_root_entry_path(path)
}

fn is_root_entry_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    trimmed.is_empty() || trimmed == "."
}

fn apply_deferred_directory_metadata(
    directories: &[(PathBuf, zmanager_apple_archive::EntryMetadata)],
) -> Result<(), AppleArchiveError> {
    for (path, metadata) in directories.iter().rev() {
        apply_metadata(path, *metadata)?;
    }
    Ok(())
}

fn apply_metadata(
    path: &Path,
    metadata: zmanager_apple_archive::EntryMetadata,
) -> Result<(), AppleArchiveError> {
    #[cfg(unix)]
    if let Some(mode) = metadata.mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            path,
            fs::Permissions::from_mode(mode & APPLE_ARCHIVE_MODE_MASK),
        )
        .map_err(|source| AppleArchiveError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }

    #[cfg(not(unix))]
    if let Some(mode) = metadata.mode {
        if mode & 0o222 == 0 {
            if let Ok(fs_metadata) = fs::metadata(path) {
                let mut perms = fs_metadata.permissions();
                perms.set_readonly(true);
                fs::set_permissions(path, perms).map_err(|source| AppleArchiveError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            }
        }
    }

    if let Some(modified) = metadata.modified
        && let Some(mtime) = system_time_to_filetime(modified)
    {
        filetime::set_file_mtime(path, mtime).map_err(|source| AppleArchiveError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }

    Ok(())
}

/// Best-effort mtime restoration for symlinks.
///
/// Uses `set_symlink_file_times` to avoid following the link. Errors are
/// silently ignored because some filesystems do not support symlink timestamps.
fn apply_symlink_mtime(path: &Path, modified: Option<SystemTime>) {
    if let Some(modified) = modified {
        if let Some(ft) = system_time_to_filetime(modified) {
            let _ = filetime::set_symlink_file_times(path, ft, ft);
        }
    }
}

fn system_time_to_filetime(time: SystemTime) -> Option<filetime::FileTime> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let seconds = i64::try_from(duration.as_secs()).ok()?;
    Some(filetime::FileTime::from_unix_time(
        seconds,
        duration.subsec_nanos(),
    ))
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
    ensure_parent_dir(destination_path)?;
    fs::hard_link(source_path, destination_path).map_err(|source| AppleArchiveError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
    use std::os::unix::fs::symlink;

    ensure_parent_dir(destination_path)?;
    symlink(target, destination_path).map_err(|source| AppleArchiveError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), AppleArchiveError> {
    Err(AppleArchiveError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

fn ensure_parent_dir(path: &Path) -> Result<(), AppleArchiveError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AppleArchiveError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use super::{
        AppleArchiveCompression, AppleArchiveCreateOptions, create_apple_archive_from_path,
        extract_apple_archive, test_apple_archive_filter,
    };
    use super::{apple_archive_supported, is_apple_archive_path, list_apple_archive};
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use crate::safety::ExtractionPolicy;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use std::fs;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use std::path::{Path, PathBuf};
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_aar_extension_case_insensitively() {
        assert!(is_apple_archive_path("archive.aar"));
        assert!(is_apple_archive_path("archive.AAR"));
        assert!(!is_apple_archive_path("archive.zip"));
    }

    #[test]
    fn application_of_metadata_propagates_io_errors() {
        use super::AppleArchiveError;
        use std::path::Path;
        let nonexistent = Path::new("does_not_exist_aar");
        let metadata = zmanager_apple_archive::EntryMetadata {
            mode: Some(0o644),
            ..zmanager_apple_archive::EntryMetadata::default()
        };
        
        let result = super::apply_metadata(
            nonexistent,
            metadata,
        );
        
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
            &AppleArchiveCreateOptions {
                compression: AppleArchiveCompression::None,
                ..AppleArchiveCreateOptions::default()
            },
        )
        .unwrap();
        assert!(create_report.written_entries >= 3);
        assert_eq!(create_report.written_bytes, 22);

        let listing = list_apple_archive(&archive).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "project/README.md")
        );
        test_apple_archive_filter(&archive, |_| true).unwrap();

        let extract_report =
            extract_apple_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        assert!(extract_report.written_entries >= 3);
        assert_eq!(
            fs::read_to_string(temp.path("out/project/README.md")).unwrap(),
            "hello aar"
        );
        assert!(temp.path("out/project/empty").is_dir());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn extracts_symlinks_and_preserves_metadata() {
        use std::os::unix::fs::symlink;
        use filetime::{set_symlink_file_times, FileTime};

        let temp = TestDir::new("apple_archive_symlink_meta");
        temp.write_file("project/target.txt", b"target");
        let symlink_path = temp.path("project/link");
        symlink("target.txt", &symlink_path).unwrap();

        // Set a specific timestamp on the symlink
        let past = FileTime::from_unix_time(1000000000, 0);
        set_symlink_file_times(&symlink_path, past, past).unwrap();

        let archive = temp.path("project.aar");

        create_apple_archive_from_path(
            temp.path("project"),
            &archive,
            &AppleArchiveCreateOptions {
                compression: AppleArchiveCompression::None,
                ..AppleArchiveCreateOptions::default()
            },
        )
        .unwrap();

        let out_dir = temp.path("out");
        extract_apple_archive(&archive, &out_dir, ExtractionPolicy::default()).unwrap();

        let extracted_symlink = out_dir.join("project/link");
        let metadata = fs::symlink_metadata(&extracted_symlink).unwrap();
        
        let mtime = metadata.modified().unwrap();
        let mtime_secs = mtime.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let diff = (mtime_secs - 1000000000).abs();
        assert!(diff <= 2, "extracted mtime diff {diff} is greater than 2 seconds");
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn native_operations_return_unsupported_on_non_apple_targets() {
        let error = list_apple_archive("archive.aar").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("supported only on macOS and iOS")
        );
        assert!(!apple_archive_supported());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn native_operations_report_supported_on_apple_targets() {
        assert!(apple_archive_supported());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    struct TestDir {
        root: PathBuf,
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let root = std::env::temp_dir()
                .join(format!("zmanager-core-{name}-{}-{now}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }

        fn write_file(&self, relative: impl AsRef<Path>, data: &[u8]) {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, data).unwrap();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
