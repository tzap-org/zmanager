use crate::atomic_file::AtomicOutputFile;
use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{ArchiveManifest, ManifestFileType, PlanError};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use rand::RngCore as _;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::format::{
    CRYPTO_HEADER_FIXED_LEN, FormatError, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST, VOLUME_HEADER_LEN,
};
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry, ExtractedArchiveMember};
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    ArchiveWriteError, ArchiveWriteSink, ExtractError, KdfParams, MasterKey, OpenedArchive,
    RegularFileSource, SafeExtractionOptions, TarEntryKind, WriterOptions, open_seekable_archive,
    open_seekable_archive_volumes, write_archive_sources_to_sink,
};

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;
const TZAP_EXTENSION: &str = "tzap";
const TZAP_VOLUME_EXTENSION_WIDTH: usize = 3;
const TZAP_TEMP_EXTRACT_PREFIX: &str = ".zmanager-tzap-extract";
const TZAP_TEMP_EXTRACT_ATTEMPTS: u32 = 100;

/// Returns whether a path names a TZAP archive or one of its numbered volumes.
#[must_use]
pub fn is_tzap_archive_path(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(TZAP_EXTENSION))
    {
        return true;
    }

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_tzap_volume_archive_file_name)
}

fn is_tzap_volume_archive_file_name(name: &str) -> bool {
    let Some((base_name, volume_index)) = name.rsplit_once('.') else {
        return false;
    };

    volume_index.len() >= TZAP_VOLUME_EXTENSION_WIDTH
        && volume_index
            .chars()
            .all(|character| character.is_ascii_digit())
        && base_name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case(TZAP_EXTENSION))
}

/// Options for `.tzap` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCreateOptions {
    /// Passphrase used to derive the archive master key.
    pub passphrase: SecretString,
    /// Zstd compression level.
    pub level: i32,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
    /// Split output into TZAP volumes of this size when present.
    pub volume_size: Option<u64>,
    /// Percent of archive data reserved for bit-rot recovery structures.
    pub recovery_percentage: u8,
    /// Number of missing output volumes the archive should tolerate.
    pub volume_loss_tolerance: u8,
}

/// `.tzap` creation report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCreateReport {
    /// Number of regular file entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into regular file entries.
    pub written_bytes: u64,
    /// Compression level used.
    pub level: i32,
    /// Requested split volume size, when the archive was split.
    pub volume_size: Option<u64>,
    /// Number of output volumes written.
    pub volume_count: usize,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tzap` archive listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapListing {
    /// Listed entries.
    pub entries: Vec<TzapEntry>,
}

/// One `.tzap` archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEntry {
    /// Archive path.
    pub path: String,
    /// Entry kind.
    pub kind: TzapEntryKind,
    /// Uncompressed file bytes.
    pub size: u64,
    /// Portable mode bits.
    pub mode: u32,
    /// Modification time as Unix seconds.
    pub mtime: u64,
}

/// Public entry kind for `.tzap` listings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TzapEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
}

/// `.tzap` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tzap` test report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapTestReport {
    /// Number of entries in the archive.
    pub entries: usize,
    /// Number of entries selected by the filter.
    pub tested_entries: usize,
    /// Number of entries skipped by the filter.
    pub skipped_entries: usize,
    /// Total selected regular-file bytes.
    pub tested_bytes: u64,
}

/// `.tzap` backend error.
#[derive(Debug)]
pub enum TzapError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Archive format, cryptographic, or metadata validation failed.
    Format(FormatError),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Only passphrase-protected `.tzap` archives are currently supported by this backend.
    PasswordRequired,
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TzapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "{source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Format(source) => write!(f, "{source}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::PasswordRequired => write!(f, "tzap password required"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TzapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Format(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::PasswordRequired | Self::Cancelled => None,
        }
    }
}

impl From<FormatError> for TzapError {
    fn from(source: FormatError) -> Self {
        Self::Format(source)
    }
}

impl From<PlanError> for TzapError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<ExtractionSafetyError> for TzapError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TzapError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Creates a `.tzap` archive from a manifest.
///
/// # Errors
///
/// Returns [`TzapError`] when source files cannot be read, key derivation fails,
/// tzap encoding fails, filesystem writes fail, or cancellation is requested.
pub fn create_tzap_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TzapCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TzapCreateReport, TzapError> {
    context.check_cancelled()?;
    let (file_sources, mut warnings) =
        collect_regular_file_sources(manifest, options, Some(context))?;
    context.check_cancelled()?;

    let mut writer_options = WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.recovery_percentage,
        target_volume_size: options.volume_size,
        zstd_level: options.level,
        ..WriterOptions::default()
    };
    if !options.preserve_metadata {
        writer_options.closed_at_ns = 0;
    }

    let kdf_params = create_kdf_params();
    let master_key =
        MasterKey::derive_from_passphrase(&kdf_params, options.passphrase.expose_secret())?;
    let destination = destination.as_ref();
    let mut sink = TzapArchiveFileSink::new(destination, options.replace_existing)?;
    let summary = write_archive_sources_to_sink(
        &file_sources,
        &master_key,
        writer_options,
        None,
        &kdf_params,
        None,
        None,
        &mut sink,
    )
    .map_err(|source| tzap_write_error(destination, source))?;

    let volume_count = sink.commit()?;
    if summary.volume_count != volume_count {
        return Err(TzapError::Format(FormatError::WriterInvariant(
            "TZAP writer summary did not match committed volume count",
        )));
    }
    for file in &file_sources {
        context.bytes_processed(Some(&file.archive_path), file.size);
        context.entry_finished(&file.archive_path, file.size);
    }

    warnings.extend(
        manifest
            .warnings
            .iter()
            .map(|warning| warning.message.clone()),
    );

    Ok(TzapCreateReport {
        written_entries: file_sources.len(),
        written_bytes: file_sources.iter().map(|file| file.size).sum(),
        level: options.level,
        volume_size: options.volume_size,
        volume_count,
        warnings,
    })
}

fn tzap_output_volume_paths(destination: &Path, count: usize) -> Vec<PathBuf> {
    if count == 1 {
        return vec![destination.to_path_buf()];
    }

    (0..count)
        .map(|index| tzap_output_volume_path(destination, index))
        .collect()
}

fn tzap_output_volume_path(destination: &Path, zero_based_index: usize) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(format!(".{zero_based_index:0TZAP_VOLUME_EXTENSION_WIDTH$}"));
    PathBuf::from(path)
}

fn ensure_tzap_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), TzapError> {
    ensure_file_destination_available(destination, replace_existing)?;
    for path in unique_paths(volume_paths, existing_volume_paths) {
        ensure_file_destination_available(path, replace_existing)?;
    }
    Ok(())
}

fn unique_paths<'a>(left: &'a [PathBuf], right: &'a [PathBuf]) -> Vec<&'a Path> {
    let mut seen = BTreeSet::new();
    left.iter()
        .chain(right.iter())
        .filter_map(|path| {
            if seen.insert(path.clone()) {
                Some(path.as_path())
            } else {
                None
            }
        })
        .collect()
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), TzapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) if !replace_existing => Err(io_error(
            path,
            io::ErrorKind::AlreadyExists,
            format!("destination already exists: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_tzap_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), TzapError> {
    if !replace_existing {
        return Ok(());
    }

    for path in existing_volume_paths {
        remove_file_destination_for_replace(path)?;
    }
    remove_file_destination_for_replace(destination)
}

fn remove_file_destination_for_replace(path: &Path) -> Result<(), TzapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn existing_tzap_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, TzapError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let Some(destination_file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };

    let mut paths = Vec::new();
    for entry in fs::read_dir(parent).map_err(|source| TzapError::Io {
        path: parent.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if is_tzap_volume_file_name(file_name, destination_file_name) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_tzap_volume_file_name(file_name: &str, destination_file_name: &str) -> bool {
    let Some(suffix) = file_name.strip_prefix(destination_file_name) else {
        return false;
    };
    let Some(number) = suffix.strip_prefix('.') else {
        return false;
    };

    number.len() >= TZAP_VOLUME_EXTENSION_WIDTH
        && number.chars().all(|character| character.is_ascii_digit())
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> TzapError {
    TzapError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(kind, message.into()),
    }
}

/// Lists `.tzap` archive entries with a passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_password(
    archive: impl AsRef<Path>,
    password: &str,
) -> Result<TzapListing, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    let entries = opened
        .list_index_entries()?
        .into_iter()
        .map(tzap_entry_from_index_entry)
        .collect();
    Ok(TzapListing { entries })
}

/// Extracts `.tzap` entries with a passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: &str,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(archive, destination, policy, password, None)
}

/// Extracts `.tzap` entries with a passphrase and overwrite resolver.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_overwrite_resolver_and_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: &str,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(
        archive,
        destination,
        policy,
        password,
        Some(overwrite_resolver),
    )
}

/// Tests `.tzap` archive readability and integrity with a filter.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or verified.
pub fn test_tzap_with_password_filter(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    opened.verify()?;
    let entries = opened.list_files()?;
    let mut tested_entries = 0usize;
    let mut tested_bytes = 0u64;
    for entry in &entries {
        if selector(&entry.path) {
            tested_entries += 1;
            if entry.kind == TarEntryKind::Regular {
                tested_bytes = tested_bytes.saturating_add(entry.file_data_size);
            }
        }
    }
    Ok(TzapTestReport {
        entries: entries.len(),
        tested_entries,
        skipped_entries: entries.len().saturating_sub(tested_entries),
        tested_bytes,
    })
}

/// Copies selected regular `.tzap` members to a writer.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or selected members
/// cannot be extracted.
pub fn copy_tzap_files_to_writer(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    let entries = opened.list_index_entries()?;
    let mut report = TzapExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    for entry in entries {
        if !selector(&entry.path) {
            report.skipped_entries += 1;
            continue;
        }
        let mut writer_ref = &mut *writer;
        let Some(_diagnostics) = opened
            .extract_file_to_writer(&entry.path, &mut writer_ref)
            .map_err(|source| tzap_extract_error(&entry.path, source))?
        else {
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped missing entry {}", entry.path));
            continue;
        };
        report.written_entries += 1;
        report.written_bytes += entry.file_data_size;
    }
    Ok(report)
}

fn tzap_extract_error(path: &str, source: ExtractError) -> TzapError {
    match source {
        ExtractError::Format(source) => TzapError::Format(source),
        ExtractError::Output(source) => TzapError::Io {
            path: PathBuf::from(path),
            source,
        },
    }
}

/// Extracts one regular `.tzap` file member to an exact destination path.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the member cannot be
/// extracted by tzap-core, or the destination cannot be committed.
pub fn extract_tzap_file_to_destination(
    archive: impl AsRef<Path>,
    password: &str,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<Option<u64>, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    let Some(index_entry) = opened.lookup_index_entry(entry_path)? else {
        return Ok(None);
    };
    let temp_root = TemporaryTzapExtractionRoot::new(destination_path)?;
    let Some(_diagnostics) = opened.extract_file_to(
        entry_path,
        temp_root.path(),
        SafeExtractionOptions {
            overwrite_existing: false,
        },
    )?
    else {
        return Ok(None);
    };
    let extracted_path = archive_member_path_under_root(temp_root.path(), entry_path)?;
    commit_extracted_file(&extracted_path, destination_path, replace_existing)?;
    Ok(Some(index_entry.file_data_size))
}

fn collect_regular_file_sources(
    manifest: &ArchiveManifest,
    options: &TzapCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(Vec<TzapRegularFileSource>, Vec<String>), TzapError> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    for entry in &manifest.entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
            context.entry_started(&entry.archive_path, Some(entry.size));
        }

        match entry.file_type {
            ManifestFileType::File => {
                files.push(TzapRegularFileSource {
                    archive_path: entry.archive_path.clone(),
                    source_path: entry.source_path.clone(),
                    size: entry.size,
                    mode: if options.preserve_metadata {
                        entry.permissions.unix_mode.unwrap_or(0o644) & 0o7777
                    } else {
                        0o644
                    },
                    mtime: if options.preserve_metadata {
                        entry
                            .modified
                            .and_then(system_time_to_unix_seconds)
                            .unwrap_or(0)
                    } else {
                        0
                    },
                });
            }
            ManifestFileType::Directory => {
                if let Some(context) = context.as_deref_mut() {
                    context.entry_finished(&entry.archive_path, 0);
                }
            }
            ManifestFileType::Symlink | ManifestFileType::Other => {
                let warning = format!(
                    "skipped {}: tzap backend currently writes regular files only",
                    entry.archive_path
                );
                warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.archive_path, 0);
                }
            }
        }
    }

    Ok((files, warnings))
}

fn extract_tzap_inner(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: &str,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<TzapExtractReport, TzapError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    let opened = open_tzap_archive(archive, password)?;
    let entries = opened.list_files()?;
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = TzapExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in entries {
        let preloaded_member =
            if matches!(entry.kind, TarEntryKind::Symlink | TarEntryKind::Hardlink) {
                opened.extract_member(&entry.path)?
            } else {
                None
            };
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: extraction_kind_from_tzap_entry(&entry, preloaded_member.as_ref()),
            uncompressed_size: Some(entry.file_data_size),
            compressed_size: None,
        };
        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => {
                let member = match preloaded_member {
                    Some(member) => Some(member),
                    None => opened.extract_member(&entry.path)?,
                };
                let Some(member) = member else {
                    report.skipped_entries += 1;
                    report
                        .warnings
                        .push(format!("skipped missing entry {}", entry.path));
                    continue;
                };
                materialize_member(
                    &member,
                    &destination_path,
                    replace_existing,
                    link_target_path.as_deref(),
                    &mut report,
                )?;
            }
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped {}: {reason}", entry.path));
            }
        }
    }

    Ok(report)
}

fn materialize_member(
    member: &ExtractedArchiveMember,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut TzapExtractReport,
) -> Result<(), TzapError> {
    if replace_existing && member.kind != TarEntryKind::Regular {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    match member.kind {
        TarEntryKind::Regular => {
            let mut output =
                AtomicOutputFile::create(destination_path).map_err(|source| TzapError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            output
                .file_mut()
                .map_err(|source| TzapError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?
                .write_all(&member.data)
                .map_err(|source| TzapError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            output
                .commit_with_replace(replace_existing)
                .map_err(|source| TzapError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            report.written_entries += 1;
            report.written_bytes += member.data.len() as u64;
        }
        TarEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            report.written_entries += 1;
        }
        TarEntryKind::Symlink => {
            if crate::safety::should_skip_symlink_materialization(&ExtractionEntryKind::Symlink {
                target: member
                    .link_target
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_default(),
            }) {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(crate::safety::unsupported_symlink_warning(&member.path));
            } else if let Some(target) = &member.link_target {
                write_symlink(Path::new(target), destination_path)?;
                report.written_entries += 1;
            } else {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped symlink {}: missing target", member.path));
            }
        }
        TarEntryKind::Hardlink => {
            let source_path = link_target_path.ok_or_else(|| TzapError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hardlink target was not resolved by extraction safety planning",
                ),
            })?;
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
        }
    }
    Ok(())
}

fn open_tzap_archive(
    archive: impl AsRef<Path>,
    password: &str,
) -> Result<OpenedArchive, TzapError> {
    let archive_path = archive.as_ref();
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume = volume_paths.first().ok_or_else(|| {
        io_error(
            archive_path,
            io::ErrorKind::NotFound,
            "no TZAP input volumes found",
        )
    })?;
    let kdf_params = read_kdf_params_from_path(first_volume)?;
    let KdfParams::Argon2id { .. } = kdf_params else {
        return Err(TzapError::PasswordRequired);
    };
    let master_key = MasterKey::derive_from_passphrase(&kdf_params, password)?;
    let volume_files = volume_paths
        .iter()
        .map(|path| {
            File::open(path).map_err(|source| TzapError::Io {
                path: path.clone(),
                source,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if volume_files.len() == 1 {
        let volume_file = volume_files
            .into_iter()
            .next()
            .ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        return open_seekable_archive(volume_file, &master_key).map_err(Into::into);
    }

    open_seekable_archive_volumes(volume_files, &master_key).map_err(Into::into)
}

pub(crate) fn discover_tzap_input_volume_paths(archive_path: &Path) -> Vec<PathBuf> {
    if let Some(base_path) = tzap_base_path_from_volume_path(archive_path) {
        let volume_paths = contiguous_tzap_volume_paths(&base_path);
        if !volume_paths.is_empty() {
            return volume_paths;
        }
    }

    if archive_path.exists() {
        return vec![archive_path.to_path_buf()];
    }

    let volume_paths = contiguous_tzap_volume_paths(archive_path);
    if !volume_paths.is_empty() {
        return volume_paths;
    }

    vec![archive_path.to_path_buf()]
}

fn tzap_base_path_from_volume_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    let (base_name, volume_index) = file_name.rsplit_once('.')?;
    if volume_index.len() < TZAP_VOLUME_EXTENSION_WIDTH
        || !volume_index
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return None;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Some(parent.join(base_name))
}

fn contiguous_tzap_volume_paths(base_path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for index in 0usize.. {
        let path = tzap_output_volume_path(base_path, index);
        if !path.exists() {
            break;
        }
        paths.push(path);
    }
    paths
}

fn read_kdf_params_from_path(path: &Path) -> Result<KdfParams, TzapError> {
    let mut file = File::open(path).map_err(|source| TzapError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut header_bytes = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes)
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = u64::from(volume_header.crypto_header_offset);
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes)
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let fixed_bytes =
        crypto_header_bytes
            .get(..CRYPTO_HEADER_FIXED_LEN)
            .ok_or(FormatError::InvalidLength {
                structure: "CryptoHeaderFixed",
                expected: CRYPTO_HEADER_FIXED_LEN,
                actual: crypto_header_bytes.len(),
            })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        )));
    }
    let crypto_header =
        CryptoHeader::parse(&crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(crypto_header.kdf_params)
}

fn commit_extracted_file(
    source_path: &Path,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<(), TzapError> {
    if let Some(parent) = destination_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if replace_existing {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
        fs::rename(source_path, destination_path).map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    } else {
        fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn archive_member_path_under_root(root: &Path, entry_path: &str) -> Result<PathBuf, TzapError> {
    let mut path = root.to_path_buf();
    for component in entry_path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(TzapError::Format(FormatError::UnsafeArchivePath));
        }
        path.push(component);
    }
    Ok(path)
}

struct TemporaryTzapExtractionRoot {
    path: PathBuf,
}

impl TemporaryTzapExtractionRoot {
    fn new(destination_path: &Path) -> Result<Self, TzapError> {
        let parent = destination_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let destination_name = destination_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("entry");

        for attempt in 0..TZAP_TEMP_EXTRACT_ATTEMPTS {
            let path = parent.join(format!(
                "{TZAP_TEMP_EXTRACT_PREFIX}-{destination_name}-{}-{now}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(TzapError::Io { path, source });
                }
            }
        }

        Err(io_error(
            parent,
            io::ErrorKind::AlreadyExists,
            "could not allocate temporary TZAP extraction root",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryTzapExtractionRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_kdf_params() -> KdfParams {
    let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    KdfParams::Argon2id {
        t_cost: DEFAULT_ARGON2_T_COST.min(READER_MAX_ARGON2ID_T_COST),
        m_cost_kib: DEFAULT_ARGON2_M_COST_KIB.min(READER_MAX_ARGON2ID_M_COST_KIB),
        parallelism: DEFAULT_ARGON2_PARALLELISM.min(READER_MAX_ARGON2ID_PARALLELISM),
        salt,
    }
}

fn extraction_kind_from_tzap_entry(
    entry: &ArchiveEntry,
    member: Option<&ExtractedArchiveMember>,
) -> ExtractionEntryKind {
    match entry.kind {
        TarEntryKind::Regular => ExtractionEntryKind::File,
        TarEntryKind::Directory => ExtractionEntryKind::Directory,
        TarEntryKind::Symlink => ExtractionEntryKind::Symlink {
            target: member
                .and_then(|member| member.link_target.as_deref())
                .map(PathBuf::from)
                .unwrap_or_default(),
        },
        TarEntryKind::Hardlink => ExtractionEntryKind::Hardlink {
            target: member
                .and_then(|member| member.link_target.as_deref())
                .map(PathBuf::from)
                .unwrap_or_default(),
        },
    }
}

fn tzap_entry_from_index_entry(entry: ArchiveIndexEntry) -> TzapEntry {
    TzapEntry {
        path: entry.path,
        kind: TzapEntryKind::File,
        size: entry.file_data_size,
        mode: 0,
        mtime: 0,
    }
}

#[derive(Debug)]
struct TzapRegularFileSource {
    archive_path: String,
    source_path: PathBuf,
    size: u64,
    mode: u32,
    mtime: u64,
}

impl RegularFileSource for TzapRegularFileSource {
    fn archive_path(&self) -> &str {
        &self.archive_path
    }

    fn file_data_size(&self) -> u64 {
        self.size
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> u64 {
        self.mtime
    }

    fn open(&self) -> Result<Box<dyn io::Read + '_>, ArchiveWriteError> {
        let file = File::open(&self.source_path).map_err(|source| {
            ArchiveWriteError::Io(io::Error::new(
                source.kind(),
                format!(
                    "failed to open TZAP source file {}: {source}",
                    self.source_path.display()
                ),
            ))
        })?;
        Ok(Box::new(file))
    }
}

struct TzapArchiveFileSink {
    destination: PathBuf,
    replace_existing: bool,
    existing_volume_paths: Vec<PathBuf>,
    volume_paths: Vec<PathBuf>,
    outputs: Vec<AtomicOutputFile>,
}

impl TzapArchiveFileSink {
    fn new(destination: &Path, replace_existing: bool) -> Result<Self, TzapError> {
        Ok(Self {
            destination: destination.to_path_buf(),
            replace_existing,
            existing_volume_paths: existing_tzap_volume_paths(destination)?,
            volume_paths: Vec::new(),
            outputs: Vec::new(),
        })
    }

    fn commit(self) -> Result<usize, TzapError> {
        let volume_count = self.volume_paths.len();
        if volume_count == 0 {
            return Err(TzapError::Format(FormatError::WriterInvariant(
                "no TZAP volumes emitted",
            )));
        }
        if self.outputs.len() != volume_count {
            return Err(TzapError::Format(FormatError::WriterInvariant(
                "TZAP output sink did not open every planned volume",
            )));
        }

        remove_tzap_destinations_for_replace(
            &self.destination,
            &self.existing_volume_paths,
            self.replace_existing,
        )?;

        for (output, volume_path) in self.outputs.into_iter().zip(self.volume_paths) {
            output
                .commit_with_file_replace(self.replace_existing)
                .map_err(|source| TzapError::Io {
                    path: volume_path,
                    source,
                })?;
        }

        Ok(volume_count)
    }
}

impl ArchiveWriteSink for TzapArchiveFileSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        if volume_count == 0 {
            return Err(ArchiveWriteError::Format(FormatError::WriterInvariant(
                "no TZAP volumes emitted",
            )));
        }

        let volume_paths = tzap_output_volume_paths(&self.destination, volume_count);
        ensure_tzap_destinations_available(
            &self.destination,
            &volume_paths,
            &self.existing_volume_paths,
            self.replace_existing,
        )
        .map_err(tzap_archive_write_error)?;

        let mut outputs = Vec::with_capacity(volume_paths.len());
        for volume_path in &volume_paths {
            outputs.push(AtomicOutputFile::create(volume_path).map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to create TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })?);
        }

        self.volume_paths = volume_paths;
        self.outputs = outputs;
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        let volume_path = self
            .volume_paths
            .get(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "TZAP volume path index is out of bounds",
            ))?
            .clone();
        let output = self
            .outputs
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "TZAP volume sink index is out of bounds",
            ))?;
        output
            .file_mut()
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to access TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })?
            .write_all(bytes)
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to write TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })
    }

    fn write_bootstrap_sidecar(&mut self, _bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        Ok(())
    }
}

fn tzap_archive_write_error(error: TzapError) -> ArchiveWriteError {
    match error {
        TzapError::Format(source) => ArchiveWriteError::Format(source),
        TzapError::Io { source, .. } => ArchiveWriteError::Io(source),
        TzapError::Cancelled => ArchiveWriteError::Io(io::Error::other(JobCancelled)),
        TzapError::Plan(_) | TzapError::Safety(_) | TzapError::PasswordRequired => {
            ArchiveWriteError::Io(io::Error::other(error))
        }
    }
}

fn tzap_write_error(path: &Path, error: ArchiveWriteError) -> TzapError {
    match error {
        ArchiveWriteError::Format(source) => TzapError::Format(source),
        ArchiveWriteError::Io(source) => {
            if source
                .get_ref()
                .is_some_and(|source| source.downcast_ref::<JobCancelled>().is_some())
            {
                TzapError::Cancelled
            } else {
                TzapError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            }
        }
    }
}

fn system_time_to_unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    std::os::unix::fs::symlink(target, destination_path).map_err(|source| TzapError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    Err(TzapError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), TzapError> {
    fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_tzap_file_to_destination, is_tzap_archive_path, list_tzap_with_password};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tzap_core::{KdfParams, MasterKey, RegularFile, WriterOptions, write_archive_with_kdf};

    #[test]
    fn recognizes_tzap_base_and_numbered_volumes() {
        assert!(is_tzap_archive_path(Path::new("project.tzap")));
        assert!(is_tzap_archive_path(Path::new("project.tzap.000")));
        assert!(is_tzap_archive_path(Path::new("project.tzap.001")));
        assert!(is_tzap_archive_path(Path::new("PROJECT.TZAP.000")));

        assert!(!is_tzap_archive_path(Path::new("project.tzap.tmp")));
        assert!(!is_tzap_archive_path(Path::new("project.tzap.00a")));
        assert!(!is_tzap_archive_path(Path::new("project.zip.000")));
    }

    #[test]
    fn selected_extract_uses_seekable_core_for_numbered_volumes() {
        let temp = TestDir::new("tzap_seekable_selected");
        let base_path = temp.path("sample.tzap");
        let large = vec![7u8; 1024 * 1024];
        let archive = create_test_tzap_archive(&[
            RegularFile::new("large.bin", &large),
            RegularFile::new("nested/small.txt", b"small target"),
        ]);
        for (index, volume) in archive.volumes.iter().enumerate() {
            fs::write(temp.path(format!("sample.tzap.{index:03}")), volume).unwrap();
        }

        let listing = list_tzap_with_password(&base_path, "secret").unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "nested/small.txt")
        );

        let destination = temp.path("out/selected.txt");
        let written = extract_tzap_file_to_destination(
            &base_path,
            "secret",
            "nested/small.txt",
            &destination,
            false,
        )
        .unwrap();

        assert_eq!(written, Some(12));
        assert_eq!(fs::read(&destination).unwrap(), b"small target");
    }

    fn create_test_tzap_archive(files: &[RegularFile<'_>]) -> tzap_core::writer::WrittenArchive {
        let kdf = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        };
        let key = MasterKey::derive_from_passphrase(&kdf, "secret").unwrap();
        let options = WriterOptions {
            stripe_width: 4,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            zstd_level: 1,
            ..WriterOptions::default()
        };
        write_archive_with_kdf(files, &key, options, &kdf).unwrap()
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
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
