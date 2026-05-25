use crate::atomic_file::AtomicOutputFile;
use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{ArchiveManifest, ManifestFileType, PlanError};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use rand::RngCore as _;
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::format::{
    CRYPTO_HEADER_FIXED_LEN, FormatError, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST, VOLUME_HEADER_LEN,
};
use tzap_core::reader::{ArchiveEntry, ExtractedArchiveMember};
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    KdfParams, MasterKey, OpenedArchive, RegularFile, TarEntryKind, WriterOptions, open_archive,
    write_archive_with_kdf,
};

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;

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

/// Creates a single-volume `.tzap` archive from a manifest.
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
    let (owned_files, mut warnings) = collect_regular_files(manifest, options, Some(context))?;
    context.check_cancelled()?;

    let files = owned_files
        .iter()
        .map(|file| RegularFile {
            path: file.archive_path.as_str(),
            contents: &file.contents,
            mode: file.mode,
            mtime: file.mtime,
        })
        .collect::<Vec<_>>();
    let mut writer_options = WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        zstd_level: options.level,
        ..WriterOptions::default()
    };
    if !options.preserve_metadata {
        writer_options.closed_at_ns = 0;
    }

    let kdf_params = create_kdf_params();
    let master_key =
        MasterKey::derive_from_passphrase(&kdf_params, options.passphrase.expose_secret())?;
    let archive = write_archive_with_kdf(&files, &master_key, writer_options, &kdf_params)?;
    if archive.volumes.len() != 1 {
        return Err(TzapError::Format(FormatError::WriterUnsupported(
            "ZManager tzap backend currently writes one volume",
        )));
    }

    let destination = destination.as_ref();
    let mut output = AtomicOutputFile::create(destination).map_err(|source| TzapError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    output
        .file_mut()
        .map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?
        .write_all(&archive.volumes[0])
        .map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    output
        .commit_with_replace(options.replace_existing)
        .map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

    warnings.extend(
        manifest
            .warnings
            .iter()
            .map(|warning| warning.message.clone()),
    );

    Ok(TzapCreateReport {
        written_entries: files.len(),
        written_bytes: owned_files
            .iter()
            .map(|file| file.contents.len() as u64)
            .sum(),
        level: options.level,
        volume_count: archive.volumes.len(),
        warnings,
    })
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
        .list_files()?
        .into_iter()
        .map(tzap_entry_from_archive_entry)
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
    let entries = opened.list_files()?;
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
        if entry.kind != TarEntryKind::Regular {
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped non-file entry {}", entry.path));
            continue;
        }
        let Some(member) = opened.extract_member(&entry.path)? else {
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped missing entry {}", entry.path));
            continue;
        };
        writer
            .write_all(&member.data)
            .map_err(|source| TzapError::Io {
                path: PathBuf::from(&entry.path),
                source,
            })?;
        report.written_entries += 1;
        report.written_bytes += member.data.len() as u64;
    }
    Ok(report)
}

fn collect_regular_files(
    manifest: &ArchiveManifest,
    options: &TzapCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(Vec<OwnedRegularFile>, Vec<String>), TzapError> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    for entry in &manifest.entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
            context.entry_started(&entry.archive_path, Some(entry.size));
        }

        match entry.file_type {
            ManifestFileType::File => {
                let contents = fs::read(&entry.source_path).map_err(|source| TzapError::Io {
                    path: entry.source_path.clone(),
                    source,
                })?;
                if let Some(context) = context.as_deref_mut() {
                    context.bytes_processed(Some(&entry.archive_path), contents.len() as u64);
                    context.entry_finished(&entry.archive_path, contents.len() as u64);
                }
                files.push(OwnedRegularFile {
                    archive_path: entry.archive_path.clone(),
                    contents,
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
    let bytes = fs::read(archive_path).map_err(|source| TzapError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let kdf_params = read_kdf_params_from_volume(&bytes)?;
    let KdfParams::Argon2id { .. } = kdf_params else {
        return Err(TzapError::PasswordRequired);
    };
    let master_key = MasterKey::derive_from_passphrase(&kdf_params, password)?;
    open_archive(&bytes, &master_key).map_err(Into::into)
}

fn read_kdf_params_from_volume(bytes: &[u8]) -> Result<KdfParams, TzapError> {
    let header_bytes = bytes
        .get(..VOLUME_HEADER_LEN)
        .ok_or(FormatError::InvalidArchive(
            "volume is too short for VolumeHeader",
        ))?;
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let offset = volume_header.crypto_header_offset as usize;
    let length = volume_header.crypto_header_length as usize;
    let end = offset
        .checked_add(length)
        .ok_or(FormatError::InvalidArchive("CryptoHeader range overflow"))?;
    let crypto_header_bytes = bytes.get(offset..end).ok_or(FormatError::InvalidArchive(
        "volume is too short for CryptoHeader",
    ))?;
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
        CryptoHeader::parse(crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(crypto_header.kdf_params)
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

fn tzap_entry_from_archive_entry(entry: ArchiveEntry) -> TzapEntry {
    TzapEntry {
        path: entry.path,
        kind: match entry.kind {
            TarEntryKind::Regular => TzapEntryKind::File,
            TarEntryKind::Directory => TzapEntryKind::Directory,
            TarEntryKind::Symlink => TzapEntryKind::Symlink,
            TarEntryKind::Hardlink => TzapEntryKind::Hardlink,
        },
        size: entry.file_data_size,
        mode: entry.mode,
        mtime: entry.mtime,
    }
}

#[derive(Debug)]
struct OwnedRegularFile {
    archive_path: String,
    contents: Vec<u8>,
    mode: u32,
    mtime: u64,
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
