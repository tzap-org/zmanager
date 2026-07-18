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
use std::io::{self, Read, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::{Archive, Builder, EntryType, Header};

#[cfg(unix)]
const TAR_MODE_MASK: u32 = 0o0777;

/// Options for `.tar.zst` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdCreateOptions {
    /// Zstd compression level.
    pub level: i32,
    /// Zstd worker count. `None` chooses a sensible local default.
    pub threads: Option<u32>,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
}

impl Default for TarZstdCreateOptions {
    fn default() -> Self {
        Self {
            level: 3,
            threads: default_zstd_threads(),
            preserve_metadata: true,
            replace_existing: false,
        }
    }
}

/// `.tar.zst` creation report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdCreateReport {
    /// Number of tar entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into regular file entries.
    pub written_bytes: u64,
    /// Zstd level used.
    pub level: i32,
    /// Zstd thread count requested.
    pub threads: Option<u32>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tar.zst` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tar.zst` backend error.
#[derive(Debug)]
pub enum TarZstdError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Tar link entry did not include a target.
    MissingLinkTarget { archive_path: String },
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TarZstdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { archive_path } => {
                write!(f, "tar link entry has no target: {archive_path}")
            }
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TarZstdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingLinkTarget { .. } | Self::Cancelled => None,
        }
    }
}

impl From<PlanError> for TarZstdError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<ExtractionSafetyError> for TarZstdError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TarZstdError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Creates a `.tar.zst` archive from one source path.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, filesystem reads, tar writing, or
/// zstd compression fail.
pub fn create_tar_zst_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
) -> Result<TarZstdCreateReport, TarZstdError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_tar_zst_from_manifest(&manifest, destination, options)
}

/// Creates a `.tar.zst` archive from a manifest.
///
/// # Errors
///
/// Returns [`TarZstdError`] when source files cannot be read, tar writing fails,
/// or zstd compression fails.
pub fn create_tar_zst_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
) -> Result<TarZstdCreateReport, TarZstdError> {
    create_tar_zst_from_manifest_inner(manifest, destination, options, None)
}

/// Creates a `.tar.zst` archive from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`TarZstdError`] when source files cannot be read, tar writing fails,
/// zstd compression fails, or cancellation is requested.
pub fn create_tar_zst_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TarZstdCreateReport, TarZstdError> {
    create_tar_zst_from_manifest_inner(manifest, destination, options, Some(context))
}

fn create_tar_zst_from_manifest_inner(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TarZstdCreateReport, TarZstdError> {
    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            TarZstdError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let file = output.file_mut().map_err(|source| TarZstdError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut encoder = zstd::stream::write::Encoder::new(file, options.level).map_err(|source| {
        TarZstdError::Io {
            path: destination.to_path_buf(),
            source,
        }
    })?;

    if let Some(threads) = options.threads
        && threads > 0
    {
        encoder
            .multithread(threads)
            .map_err(|source| TarZstdError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
    }

    let mut builder = Builder::new(encoder);
    builder.follow_symlinks(false);
    let mut report = TarZstdCreateReport {
        written_entries: 0,
        written_bytes: 0,
        level: options.level,
        threads: options.threads,
        warnings: Vec::new(),
    };

    for entry in &manifest.entries {
        append_manifest_entry(
            &mut builder,
            entry,
            options.preserve_metadata,
            &mut report,
            context.as_deref_mut(),
        )?;
    }

    let encoder = builder.into_inner().map_err(|source| TarZstdError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    encoder.finish().map_err(|source| TarZstdError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    output
        .commit_with_file_replace(options.replace_existing)
        .map_err(|source| TarZstdError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

    Ok(report)
}

/// Extracts a `.tar.zst` archive through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`TarZstdError`] when the archive cannot be read, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tar_zst(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<TarZstdExtractReport, TarZstdError> {
    extract_tar_zst_inner(archive_path, destination, policy, None, None)
}

/// Estimates the uncompressed byte size of a `.tar.zst` archive by summing
/// entry headers.
///
/// # Errors
///
/// Returns [`TarZstdError`] when the archive cannot be opened or read.
pub fn estimate_tar_zst_uncompressed_size(
    archive_path: impl AsRef<Path>,
) -> Result<u64, TarZstdError> {
    let archive_path = archive_path.as_ref();
    let file = File::open(archive_path).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let decoder = zstd::stream::read::Decoder::new(file).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = Archive::new(decoder);
    let mut total = 0_u64;

    for entry in archive.entries().map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| TarZstdError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
        total = total.saturating_add(entry.header().size().unwrap_or(0));
    }

    Ok(total)
}

/// Copies selected regular `.tar.zst` file entries to a writer in archive order.
///
/// # Errors
///
/// Returns [`TarZstdError`] when the archive cannot be read or output writing
/// fails.
pub fn copy_tar_zst_files_to_writer<W: io::Write>(
    archive_path: impl AsRef<Path>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<TarZstdExtractReport, TarZstdError> {
    let archive_path = archive_path.as_ref();
    let file = File::open(archive_path).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let decoder = zstd::stream::read::Decoder::new(file).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = Archive::new(decoder);
    let mut report = TarZstdExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in archive.entries().map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })? {
        let mut entry = entry.map_err(|source| TarZstdError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
        let archive_entry_path = entry_path_string(&entry)?;
        if !selected(&archive_entry_path) {
            report.skipped_entries += 1;
            continue;
        }
        let kind = extraction_kind(&mut entry, &archive_entry_path)?;
        if !matches!(kind, ExtractionEntryKind::File) {
            report.skipped_entries += 1;
            continue;
        }

        let copied = io::copy(&mut entry, output).map_err(|source| TarZstdError::Io {
            path: PathBuf::from(&archive_entry_path),
            source,
        })?;
        report.written_entries += 1;
        report.written_bytes += copied;
    }

    Ok(report)
}

/// Extracts a `.tar.zst` archive through the shared extraction safety policy
/// while emitting job events.
///
/// # Errors
///
/// Returns [`TarZstdError`] when the archive cannot be read, an entry is unsafe,
/// filesystem writes fail, or cancellation is requested.
pub fn extract_tar_zst_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<TarZstdExtractReport, TarZstdError> {
    extract_tar_zst_inner(archive_path, destination, policy, Some(context), None)
}

/// Extracts a `.tar.zst` archive with an overwrite resolver.
///
/// # Errors
///
/// Returns [`TarZstdError`] when the archive cannot be read, an entry is unsafe,
/// filesystem writes fail, or the resolver aborts extraction.
pub fn extract_tar_zst_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<TarZstdExtractReport, TarZstdError> {
    extract_tar_zst_inner(
        archive_path,
        destination,
        policy,
        None,
        Some(overwrite_resolver),
    )
}

fn extract_tar_zst_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<TarZstdExtractReport, TarZstdError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            TarZstdError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;

    let file = File::open(archive_path).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let decoder = zstd::stream::read::Decoder::new(file).map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = Archive::new(decoder);
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = TarZstdExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut deferred_directories = Vec::new();

    for entry in archive.entries().map_err(|source| TarZstdError::Io {
        path: archive_path.to_path_buf(),
        source,
    })? {
        let mut entry = entry.map_err(|source| TarZstdError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let archive_entry_path = entry_path_string(&entry)?;
        let entry_size = entry.header().size().unwrap_or(0);
        let kind = extraction_kind(&mut entry, &archive_entry_path)?;
        if is_archive_root_directory(&archive_entry_path, &kind) {
            report.skipped_entries += 1;
            let warning = "skipped archive root directory entry".to_owned();
            report.warnings.push(warning.clone());
            if let Some(context) = context.as_deref_mut() {
                context.warning(warning);
            }
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: archive_entry_path,
            kind,
            uncompressed_size: Some(entry_size),
            compressed_size: None,
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&safety_entry.archive_path, Some(entry_size));
            context.check_cancelled()?;
        }

        let processed = match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => materialize_tar_write_decision(
                &mut entry,
                TarWriteDecision {
                    safety_entry: &safety_entry,
                    destination_path: &destination_path,
                    replace_existing,
                    link_target_path: link_target_path.as_deref(),
                },
                context.as_deref_mut(),
                &mut deferred_directories,
                &mut report,
            )?,
            ExtractionDecision::Skip { reason, .. } => {
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

    apply_deferred_directory_metadata(&deferred_directories)?;

    Ok(report)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct TarEntryMetadata {
    mode: Option<u32>,
    mtime: Option<u64>,
}

#[derive(Clone, Copy)]
struct TarWriteDecision<'a> {
    safety_entry: &'a ExtractionEntry,
    destination_path: &'a Path,
    replace_existing: bool,
    link_target_path: Option<&'a Path>,
}

fn materialize_tar_write_decision<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    decision: TarWriteDecision<'_>,
    mut context: Option<&mut JobContext<'_>>,
    deferred_directories: &mut Vec<(PathBuf, TarEntryMetadata)>,
    report: &mut TarZstdExtractReport,
) -> Result<u64, TarZstdError> {
    let TarWriteDecision {
        safety_entry,
        destination_path,
        replace_existing,
        link_target_path,
    } = decision;

    if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
        report.skipped_entries += 1;
        let warning = crate::safety::unsupported_symlink_warning(&safety_entry.archive_path);
        report.warnings.push(warning.clone());
        if let Some(context) = context.as_deref_mut() {
            context.warning(warning);
        }
        return Ok(0);
    }

    let written_bytes = materialize_tar_entry(
        entry,
        safety_entry,
        destination_path,
        replace_existing,
        link_target_path,
        context,
        deferred_directories,
    )?;
    report.written_entries += 1;
    report.written_bytes += written_bytes;
    Ok(written_bytes)
}

fn materialize_tar_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    safety_entry: &ExtractionEntry,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    context: Option<&mut JobContext<'_>>,
    deferred_directories: &mut Vec<(PathBuf, TarEntryMetadata)>,
) -> Result<u64, TarZstdError> {
    let metadata = tar_entry_metadata(entry.header());

    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    match &safety_entry.kind {
        ExtractionEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            deferred_directories.push((destination_path.to_path_buf(), metadata));
            Ok(0)
        }
        ExtractionEntryKind::File => copy_tar_file_entry(
            entry,
            &safety_entry.archive_path,
            destination_path,
            replace_existing,
            metadata,
            context,
        ),
        ExtractionEntryKind::Symlink { target } => {
            write_symlink(target, destination_path)?;
            apply_symlink_mtime(destination_path, metadata.mtime);
            Ok(0)
        }
        ExtractionEntryKind::Hardlink { .. } => {
            let source_path = link_target_path.ok_or_else(|| TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hardlink target was not resolved by extraction safety planning",
                ),
            })?;
            write_hardlink(source_path, destination_path)?;
            Ok(0)
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => Err(TarZstdError::Io {
            path: destination_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::Unsupported,
                "special tar entry reached materialization after safety planning",
            ),
        }),
    }
}

fn copy_tar_file_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    archive_path: &str,
    destination_path: &Path,
    replace_existing: bool,
    metadata: TarEntryMetadata,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<u64, TarZstdError> {
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| {
            TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut written_bytes = 0_u64;

    loop {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let read = entry.read(&mut buffer).map_err(|source| TarZstdError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        output
            .file_mut()
            .map_err(|source| TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?
            .write_all(&buffer[..read])
            .map_err(|source| TarZstdError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
        let read = read as u64;
        written_bytes += read;
        if let Some(context) = context.as_deref_mut() {
            context.bytes_processed(Some(archive_path), read);
        }
    }

    output
        .commit_with_replace(replace_existing)
        .map_err(|source| TarZstdError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    apply_metadata(destination_path, metadata)?;

    Ok(written_bytes)
}

fn tar_entry_metadata(header: &Header) -> TarEntryMetadata {
    TarEntryMetadata {
        mode: header.mode().ok(),
        mtime: header.mtime().ok(),
    }
}

fn apply_deferred_directory_metadata(
    directories: &[(PathBuf, TarEntryMetadata)],
) -> Result<(), TarZstdError> {
    for (path, metadata) in directories.iter().rev() {
        apply_metadata(path, *metadata)?;
    }

    Ok(())
}

fn apply_metadata(path: &Path, metadata: TarEntryMetadata) -> Result<(), TarZstdError> {
    #[cfg(unix)]
    if let Some(mode) = metadata.mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode & TAR_MODE_MASK)).map_err(
            |source| TarZstdError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    if let Some(mtime) = metadata.mtime {
        let mtime = i64::try_from(mtime).map_err(|source| TarZstdError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tar modification time is out of range: {source}"),
            ),
        })?;
        let mtime = filetime::FileTime::from_unix_time(mtime, 0);
        filetime::set_file_mtime(path, mtime).map_err(|source| TarZstdError::Io {
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
fn apply_symlink_mtime(path: &Path, mtime: Option<u64>) {
    if let Some(mtime) = mtime
        && let Ok(mtime) = i64::try_from(mtime) {
            let ft = filetime::FileTime::from_unix_time(mtime, 0);
            let _ = filetime::set_symlink_file_times(path, ft, ft);
        }
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), TarZstdError> {
    ensure_parent_dir(destination_path)?;
    fs::hard_link(source_path, destination_path).map_err(|source| TarZstdError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), TarZstdError> {
    use std::os::unix::fs::symlink;

    ensure_parent_dir(destination_path)?;
    symlink(target, destination_path).map_err(|source| TarZstdError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), TarZstdError> {
    Err(TarZstdError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

fn ensure_parent_dir(path: &Path) -> Result<(), TarZstdError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| TarZstdError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    Ok(())
}

fn append_manifest_entry<W: io::Write>(
    builder: &mut Builder<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut TarZstdCreateReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), TarZstdError> {
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
        context.entry_started(&entry.archive_path, Some(entry.size));
        context.check_cancelled()?;
    }

    let processed = match entry.file_type {
        ManifestFileType::Directory => {
            if preserve_metadata {
                builder
                    .append_dir(&entry.archive_path, &entry.source_path)
                    .map_err(|source| TarZstdError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
            } else {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, io::empty())
                    .map_err(|source| TarZstdError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
            }
            report.written_entries += 1;
            0
        }
        ManifestFileType::File => {
            if preserve_metadata {
                builder
                    .append_path_with_name(&entry.source_path, &entry.archive_path)
                    .map_err(|source| TarZstdError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
            } else {
                let mut source =
                    File::open(&entry.source_path).map_err(|source| TarZstdError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Regular);
                header.set_size(entry.size);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, &mut source)
                    .map_err(|source| TarZstdError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
            }
            report.written_entries += 1;
            report.written_bytes += entry.size;
            if let Some(context) = context.as_deref_mut() {
                context.bytes_processed(Some(&entry.archive_path), entry.size);
            }
            entry.size
        }
        ManifestFileType::Symlink => {
            let Some(target) = &entry.symlink_target else {
                let warning = format!("skipped symlink {}: missing target", entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.archive_path, 0);
                }
                return Ok(());
            };
            append_symlink(builder, entry, target, preserve_metadata)?;
            report.written_entries += 1;
            0
        }
        ManifestFileType::Other => {
            let warning = format!(
                "skipped special file {}: TAR.ZST backend only writes files, directories, and symlinks",
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

fn append_symlink<W: io::Write>(
    builder: &mut Builder<W>,
    entry: &ManifestEntry,
    target: &Path,
    preserve_metadata: bool,
) -> Result<(), TarZstdError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    if preserve_metadata && let Some(mode) = entry.permissions.unix_mode {
        header.set_mode(mode & 0o777);
    }
    if preserve_metadata
        && let Some(modified) = entry.modified.and_then(system_time_to_unix_seconds)
    {
        header.set_mtime(modified);
    }
    if !preserve_metadata {
        header.set_mode(0o777);
        header.set_mtime(0);
    }
    builder
        .append_link(&mut header, &entry.archive_path, target)
        .map_err(|source| TarZstdError::Io {
            path: entry.source_path.clone(),
            source,
        })
}

fn entry_path_string<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, TarZstdError> {
    let path = entry.path().map_err(|source| TarZstdError::Io {
        path: PathBuf::from("<tar-entry>"),
        source,
    })?;

    Ok(path.to_string_lossy().into_owned())
}

fn is_archive_root_directory(path: &str, kind: &ExtractionEntryKind) -> bool {
    matches!(kind, ExtractionEntryKind::Directory) && is_root_entry_path(path)
}

fn is_root_entry_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    trimmed.is_empty() || trimmed == "."
}

fn extraction_kind<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    archive_path: &str,
) -> Result<ExtractionEntryKind, TarZstdError> {
    let entry_type = entry.header().entry_type();

    if entry_type.is_file() || entry_type.is_contiguous() {
        return Ok(ExtractionEntryKind::File);
    }

    if entry_type.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }

    if entry_type.is_symlink() {
        let Some(target) = entry.link_name().map_err(|source| TarZstdError::Io {
            path: PathBuf::from(archive_path),
            source,
        })?
        else {
            return Err(TarZstdError::MissingLinkTarget {
                archive_path: archive_path.to_owned(),
            });
        };
        return Ok(ExtractionEntryKind::Symlink {
            target: target.into_owned(),
        });
    }

    if entry_type.is_hard_link() {
        let Some(target) = entry.link_name().map_err(|source| TarZstdError::Io {
            path: PathBuf::from(archive_path),
            source,
        })?
        else {
            return Err(TarZstdError::MissingLinkTarget {
                archive_path: archive_path.to_owned(),
            });
        };
        return Ok(ExtractionEntryKind::Hardlink {
            target: target.into_owned(),
        });
    }

    if entry_type.is_block_special() || entry_type.is_character_special() {
        return Ok(ExtractionEntryKind::Device);
    }

    Ok(ExtractionEntryKind::Special)
}

fn default_zstd_threads() -> Option<u32> {
    let threads = std::thread::available_parallelism().ok()?.get();

    u32::try_from(threads).ok().filter(|threads| *threads > 1)
}

fn system_time_to_unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|time| time.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{
        TarZstdCreateOptions, TarZstdError, create_tar_zst_from_path, extract_tar_zst,
        extract_tar_zst_with_context, system_time_to_unix_seconds,
    };
    use crate::jobs::{CancellationToken, JobContext, JobEvent};
    use crate::safety::{ExtractionPolicy, ExtractionSafetyError};
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn creates_and_extracts_tar_zst() {
        let temp = TestDir::new("creates_and_extracts_tar_zst");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        temp.write_file("project/hello cafe.txt", b"unicode");
        let archive = temp.path("archive.tar.zst");

        let create_report = create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions::default(),
        )
        .unwrap();
        let extract_report =
            extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(create_report.level, 3);
        assert_eq!(create_report.written_entries, 5);
        assert_eq!(extract_report.written_entries, 5);
        assert_eq!(
            fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path("out/project/hello cafe.txt")).unwrap(),
            "unicode"
        );
        assert!(temp.path("out/project/empty").is_dir());
    }

    #[test]

    fn preserves_metadata_during_creation_and_extraction() {
        let temp = TestDir::new("preserves_metadata_tar_zst");

        temp.write_file("project/script.sh", b"echo hello");

        #[allow(unused_variables)]
        let path = temp.path("project/script.sh");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            
            // Add a symlink to test symlink metadata
            std::os::unix::fs::symlink("script.sh", temp.path("project/link.sh")).unwrap();
            // Set a specific mtime on the symlink
            let time = filetime::FileTime::from_unix_time(1500000000, 0);
            filetime::set_symlink_file_times(temp.path("project/link.sh"), time, time).unwrap();
        }

        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions {
                preserve_metadata: true,
                ..TarZstdCreateOptions::default()
            },
        )
        .unwrap();

        extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let out_path = temp.path("out/project/script.sh");
        
        #[allow(unused_variables)]
        let metadata = fs::metadata(&out_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
            
            // Verify symlink metadata
            let link_metadata = fs::symlink_metadata(temp.path("out/project/link.sh")).unwrap();
            let link_mtime = filetime::FileTime::from_last_modification_time(&link_metadata);
            assert!(link_metadata.is_symlink());
            assert_eq!(link_mtime.unix_seconds(), 1500000000);
        }
    }

    #[test]

    fn accepts_custom_compression_level_and_thread_count() {
        let temp = TestDir::new("accepts_custom_compression_level_and_thread_count");
        temp.write_file("project/file.txt", b"content");
        let archive = temp.path("archive.tar.zst");
        let options = TarZstdCreateOptions {
            level: 1,
            threads: Some(1),
            preserve_metadata: true,
            replace_existing: false,
        };

        let report = create_tar_zst_from_path(temp.path("project"), archive, &options).unwrap();

        assert_eq!(report.level, 1);
        assert_eq!(report.threads, Some(1));
    }

    #[test]
    fn handles_larger_files() {
        let temp = TestDir::new("handles_larger_files_tar_zst");
        let contents = vec![b'x'; 1024 * 1024];
        temp.write_file("project/large.bin", &contents);
        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions::default(),
        )
        .unwrap();
        extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(
            fs::read(temp.path("out/project/large.bin")).unwrap(),
            contents
        );
    }

    #[test]
    fn cancelled_extraction_removes_partial_file_output() {
        let temp = TestDir::new("cancelled_extraction_removes_partial_file_output_tar_zst");
        let contents = vec![b'x'; crate::DEFAULT_IO_BUFFER_BYTES * 4];
        temp.write_file("project/large.bin", &contents);
        let archive = temp.path("archive.tar.zst");
        create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions::default(),
        )
        .unwrap();
        let token = CancellationToken::new();
        let cancel_token = token.clone();
        let mut events = Vec::new();
        let mut sink = |event: JobEvent| {
            if matches!(event, JobEvent::BytesProcessed { .. }) {
                cancel_token.cancel();
            }
            events.push(event);
        };
        let mut context = JobContext::new(&token, &mut sink);

        let error = extract_tar_zst_with_context(
            &archive,
            temp.path("out"),
            ExtractionPolicy::default(),
            &mut context,
        )
        .unwrap_err();

        assert!(matches!(error, TarZstdError::Cancelled));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, JobEvent::BytesProcessed { .. }))
        );
        assert!(!temp.path("out/project/large.bin").exists());
        assert!(!contains_temporary_output(&temp.path("out/project")));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("preserves_symlinks");
        temp.write_file("project/target.txt", b"target");
        symlink("target.txt", temp.path("project/link.txt")).unwrap();
        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions::default(),
        )
        .unwrap();
        extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_eq!(
            fs::read_link(temp.path("out/project/link.txt")).unwrap(),
            PathBuf::from("target.txt")
        );
    }

    #[cfg(unix)]
    #[test]
    fn extracts_hardlinks_inside_destination() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("extracts_hardlinks_inside_destination_tar_zst");
        let archive = temp.path("archive.tar.zst");
        write_tar_zst_with_hardlink(
            &archive,
            "project/target.txt",
            "project/link.txt",
            b"target",
        );

        let report =
            extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let target = temp.path("out/project/target.txt");
        let link = temp.path("out/project/link.txt");
        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::read(&link).unwrap(), b"target");
        assert_eq!(
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&link).unwrap().ino()
        );
    }

    #[test]
    fn extraction_skips_archive_root_directory_entries() {
        let temp = TestDir::new("extracts_tar_zst_with_root_directory");
        let archive = temp.path("archive.tar.zst");
        write_tar_zst_with_root_directory(&archive, "payload/file.txt", b"payload");

        let report =
            extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(report.written_entries, 1);
        assert_eq!(report.skipped_entries, 1);
        assert_eq!(
            fs::read(temp.path("out/payload/file.txt")).unwrap(),
            b"payload"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning == "skipped archive root directory entry")
        );
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal_tar_zst");
        let archive = temp.path("archive.tar.zst");
        write_raw_tar_zst(&archive, "../escape.txt", b"escape");

        let error =
            extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(
            error,
            TarZstdError::Safety(ExtractionSafetyError::ParentTraversal { .. })
        ));
    }

    #[test]
    fn converts_system_time_to_unix_seconds() {
        assert_eq!(system_time_to_unix_seconds(UNIX_EPOCH), Some(0));
    }

    fn write_raw_tar_zst(path: &Path, entry_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let header = raw_tar_header(entry_path, contents.len().try_into().unwrap());

        encoder.write_all(&header).unwrap();
        encoder.write_all(contents).unwrap();

        let padding_len = (512 - (contents.len() % 512)) % 512;
        encoder.write_all(&vec![0; padding_len]).unwrap();
        encoder.write_all(&[0; 1024]).unwrap();
        encoder.finish().unwrap();
    }

    #[cfg(unix)]
    fn write_tar_zst_with_hardlink(
        path: &Path,
        target_path: &str,
        link_path: &str,
        contents: &[u8],
    ) {
        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, target_path, contents)
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_mtime(0);
        link_header.set_cksum();
        builder
            .append_link(&mut link_header, link_path, Path::new(target_path))
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn write_tar_zst_with_root_directory(path: &Path, entry_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut root_header = tar::Header::new_gnu();
        root_header.set_entry_type(tar::EntryType::Directory);
        root_header.set_size(0);
        root_header.set_mode(0o755);
        root_header.set_mtime(0);
        root_header.set_cksum();
        builder
            .append_data(&mut root_header, ".", io::empty())
            .unwrap();

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, entry_path, contents)
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn contains_temporary_output(path: &Path) -> bool {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        entries.filter_map(Result::ok).any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".zmanager-")
        })
    }

    fn raw_tar_header(path: &str, size: u64) -> [u8; 512] {
        let mut header = [0_u8; 512];

        write_bytes(&mut header[0..100], path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        write_bytes(&mut header[257..263], b"ustar\0");
        write_bytes(&mut header[263..265], b"00");

        let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
        write_checksum(&mut header[148..156], checksum);

        header
    }

    fn write_bytes(destination: &mut [u8], source: &[u8]) {
        let len = destination.len().min(source.len());
        destination[..len].copy_from_slice(&source[..len]);
    }

    fn write_octal(destination: &mut [u8], value: u64) {
        let encoded = format!("{value:0width$o}\0", width = destination.len() - 1);
        write_bytes(destination, encoded.as_bytes());
    }

    fn write_checksum(destination: &mut [u8], value: u32) {
        let encoded = format!("{value:06o}\0 ");
        write_bytes(destination, encoded.as_bytes());
    }

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("zmanager-{name}-{}-{now}", std::process::id()));
            fs::create_dir_all(&root).unwrap();

            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }

        fn create_dir(&self, relative: impl AsRef<Path>) {
            fs::create_dir_all(self.path(relative)).unwrap();
        }

        fn write_file(&self, relative: impl AsRef<Path>, contents: &[u8]) {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
