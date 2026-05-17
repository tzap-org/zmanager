use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{
    ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive,
};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::{FileOptions, SimpleFileOptions};
use zip::{AesMode, CompressionMethod, ZipArchive, ZipReadOptions, ZipWriter};

/// ZIP compression methods exposed in v1.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ZipCompression {
    /// No compression.
    Store,
    /// Standard ZIP Deflate compression.
    #[default]
    Deflate,
}

/// Options for seekable ZIP creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipCreateOptions {
    /// Compression method for regular file entries.
    pub compression: ZipCompression,
    /// Compression level for methods that support levels.
    pub level: Option<i64>,
    /// Preserve portable metadata such as Unix mode bits.
    pub preserve_metadata: bool,
    /// Optional password. When present, ZIP entries are written with AES-256.
    pub password: Option<SecretString>,
}

impl Default for ZipCreateOptions {
    fn default() -> Self {
        Self {
            compression: ZipCompression::default(),
            level: None,
            preserve_metadata: true,
            password: None,
        }
    }
}

/// Summary of a created ZIP archive.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipCreateReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into file entries.
    pub written_bytes: u64,
    /// Whether AES encryption was enabled.
    pub encrypted: bool,
    /// Non-fatal creation warnings.
    pub warnings: Vec<String>,
}

/// One ZIP listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipListEntry {
    /// Raw ZIP entry name.
    pub name: String,
    /// Entry kind.
    pub kind: ZipEntryKind,
    /// Uncompressed size.
    pub size: u64,
    /// Compressed size.
    pub compressed_size: u64,
    /// Whether the entry is encrypted.
    pub encrypted: bool,
    /// Unix mode bits when available.
    pub unix_mode: Option<u32>,
}

/// ZIP entry type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ZipEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// ZIP archive listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipListing {
    /// Entries in archive order.
    pub entries: Vec<ZipListEntry>,
}

/// ZIP integrity test report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipTestReport {
    /// Number of entries read successfully.
    pub tested_entries: usize,
    /// Number of entries skipped by the supplied test filter.
    pub skipped_entries: usize,
    /// Number of uncompressed bytes read successfully.
    pub tested_bytes: u64,
}

/// ZIP extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipExtractReport {
    /// Number of entries written to disk.
    pub written_entries: usize,
    /// Number of entries skipped by safety policy.
    pub skipped_entries: usize,
    /// Number of uncompressed bytes copied from file entries.
    pub written_bytes: u64,
    /// Non-fatal extraction warnings.
    pub warnings: Vec<String>,
}

/// ZIP backend error.
#[derive(Debug)]
pub enum ZipBackendError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// ZIP crate returned an error.
    Zip(zip::result::ZipError),
    /// A password is required to read encrypted ZIP entry data.
    PasswordRequired,
    /// The supplied password did not decrypt ZIP entry data.
    InvalidPassword,
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Symlink target was not valid UTF-8 for this v1 backend.
    InvalidSymlinkTarget { archive_path: String },
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for ZipBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Zip(source) => write!(f, "zip operation failed: {source}"),
            Self::PasswordRequired => write!(f, "password required to decrypt ZIP entry data"),
            Self::InvalidPassword => write!(f, "provided ZIP password is incorrect"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::InvalidSymlinkTarget { archive_path } => {
                write!(f, "symlink target is not valid UTF-8 for {archive_path}")
            }
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for ZipBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Zip(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::PasswordRequired
            | Self::InvalidPassword
            | Self::InvalidSymlinkTarget { .. }
            | Self::Cancelled => None,
        }
    }
}

impl From<PlanError> for ZipBackendError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<zip::result::ZipError> for ZipBackendError {
    fn from(source: zip::result::ZipError) -> Self {
        map_zip_error(source)
    }
}

impl From<ExtractionSafetyError> for ZipBackendError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for ZipBackendError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Creates a ZIP archive from a source path.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, filesystem reads, or ZIP writing
/// fails.
pub fn create_zip_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
) -> Result<ZipCreateReport, ZipBackendError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_zip_from_manifest(&manifest, destination, options)
}

/// Creates a seekable ZIP archive from a manifest.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when source files cannot be read or ZIP writing
/// fails.
pub fn create_zip_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
) -> Result<ZipCreateReport, ZipBackendError> {
    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            ZipBackendError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let file = output.file_mut().map_err(|source| ZipBackendError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut writer = ZipWriter::new(file);
    let report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    writer.finish()?;
    output.commit().map_err(|source| ZipBackendError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    Ok(report)
}

/// Creates a seekable ZIP archive from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when source files cannot be read, ZIP writing
/// fails, or cancellation is requested.
pub fn create_zip_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<ZipCreateReport, ZipBackendError> {
    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            ZipBackendError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let file = output.file_mut().map_err(|source| ZipBackendError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut writer = ZipWriter::new(file);
    let report = write_manifest_to_zip(&mut writer, manifest, options, Some(context))?;
    writer.finish()?;
    output.commit().map_err(|source| ZipBackendError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    Ok(report)
}

/// Creates a stream-mode ZIP archive from a source path.
///
/// The output writer only needs [`Write`], not [`Seek`].
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, source reads, stream writes, or
/// ZIP finalization fail.
pub fn create_zip_stream_from_path<W: Write>(
    source: impl AsRef<Path>,
    output: W,
    options: &ZipCreateOptions,
) -> Result<(W, ZipCreateReport), ZipBackendError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_zip_stream_from_manifest(&manifest, output, options)
}

/// Creates a stream-mode ZIP archive from a manifest.
///
/// The output writer only needs [`Write`], not [`Seek`].
///
/// # Errors
///
/// Returns [`ZipBackendError`] when source reads, stream writes, or ZIP
/// finalization fail.
pub fn create_zip_stream_from_manifest<W: Write>(
    manifest: &ArchiveManifest,
    output: W,
    options: &ZipCreateOptions,
) -> Result<(W, ZipCreateReport), ZipBackendError> {
    let mut writer = ZipWriter::new_stream(output);
    let report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    let output = writer.finish()?.into_inner();

    Ok((output, report))
}

/// Lists ZIP archive entries.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be opened or parsed.
pub fn list_zip(path: impl AsRef<Path>) -> Result<ZipListing, ZipBackendError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| ZipBackendError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    let mut entries = Vec::with_capacity(archive.len());

    for index in 0..archive.len() {
        let file = archive.by_index_raw(index).map_err(map_zip_error)?;
        entries.push(ZipListEntry {
            name: file.name().to_owned(),
            kind: zip_entry_kind(&file),
            size: file.size(),
            compressed_size: file.compressed_size(),
            encrypted: file.encrypted(),
            unix_mode: file.unix_mode(),
        });
    }

    Ok(ZipListing { entries })
}

/// Reads all ZIP entries to validate archive integrity.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read.
pub fn test_zip(path: impl AsRef<Path>) -> Result<ZipTestReport, ZipBackendError> {
    test_zip_with_password(path, None)
}

/// Reads all ZIP entries to validate archive integrity with an optional
/// password.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read or a password is
/// required/incorrect.
pub fn test_zip_with_password(
    path: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<ZipTestReport, ZipBackendError> {
    test_zip_with_password_filter(path, password, |_| true)
}

/// Reads selected ZIP entries to validate archive integrity with an optional
/// password.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read or a selected
/// entry requires a missing/incorrect password.
pub fn test_zip_with_password_filter(
    path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<ZipTestReport, ZipBackendError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| ZipBackendError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    let mut tested_entries = 0;
    let mut skipped_entries = 0;
    let mut tested_bytes = 0;
    let password = password_bytes(password);

    for index in 0..archive.len() {
        let name = {
            let file = archive.by_index_raw(index).map_err(map_zip_error)?;
            file.name().to_owned()
        };
        if !selected(&name) {
            skipped_entries += 1;
            continue;
        }
        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new().password(password))
            .map_err(map_zip_error)?;
        if file.is_dir() {
            tested_entries += 1;
            continue;
        }
        let copied =
            io::copy(&mut file, &mut io::sink()).map_err(|source| ZipBackendError::Io {
                path: PathBuf::from(file.name()),
                source,
            })?;
        tested_entries += 1;
        tested_bytes += copied;
    }

    Ok(ZipTestReport {
        tested_entries,
        skipped_entries,
        tested_bytes,
    })
}

/// Extracts a ZIP archive through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, an entry is
/// unsafe, or filesystem writes fail.
pub fn extract_zip(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<ZipExtractReport, ZipBackendError> {
    extract_zip_with_password(archive_path, destination, policy, None)
}

/// Extracts a ZIP archive through the shared extraction safety policy with an
/// optional password.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, a password is
/// required/incorrect, an entry is unsafe, or filesystem writes fail.
pub fn extract_zip_with_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<ZipExtractReport, ZipBackendError> {
    extract_zip_inner(archive_path, destination, policy, password, None, None)
}

/// Copies selected regular ZIP file entries to a writer in archive order.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, a selected entry
/// requires a missing/incorrect password, or the output writer fails.
pub fn copy_zip_files_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<ZipExtractReport, ZipBackendError> {
    let archive_path = archive_path.as_ref();
    let file = File::open(archive_path).map_err(|source| ZipBackendError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    let password = password_bytes(password);
    let mut report = ZipExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for index in 0..archive.len() {
        let name = {
            let file = archive.by_index_raw(index).map_err(map_zip_error)?;
            file.name().to_owned()
        };
        if !selected(&name) {
            report.skipped_entries += 1;
            continue;
        }

        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new().password(password))
            .map_err(map_zip_error)?;
        if zip_entry_kind(&file) != ZipEntryKind::File {
            report.skipped_entries += 1;
            continue;
        }

        let copied = io::copy(&mut file, output).map_err(|source| ZipBackendError::Io {
            path: PathBuf::from(file.name()),
            source,
        })?;
        report.written_entries += 1;
        report.written_bytes += copied;
    }

    Ok(report)
}

/// Extracts a ZIP archive through the shared extraction safety policy while
/// emitting job events.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, an entry is
/// unsafe, filesystem writes fail, or cancellation is requested.
pub fn extract_zip_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<ZipExtractReport, ZipBackendError> {
    extract_zip_with_context_and_password(archive_path, destination, policy, None, context)
}

/// Extracts a ZIP archive with an optional password while emitting job events.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, a password is
/// required/incorrect, an entry is unsafe, filesystem writes fail, or
/// cancellation is requested.
pub fn extract_zip_with_context_and_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<ZipExtractReport, ZipBackendError> {
    extract_zip_inner(
        archive_path,
        destination,
        policy,
        password,
        Some(context),
        None,
    )
}

/// Extracts a ZIP archive with an overwrite resolver and optional password.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be read, a password is
/// required/incorrect, an entry is unsafe, filesystem writes fail, or the
/// resolver aborts extraction.
pub fn extract_zip_with_overwrite_resolver_and_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<ZipExtractReport, ZipBackendError> {
    extract_zip_inner(
        archive_path,
        destination,
        policy,
        password,
        None,
        Some(overwrite_resolver),
    )
}

fn extract_zip_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<ZipExtractReport, ZipBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            ZipBackendError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;

    let file = File::open(archive_path).map_err(|source| ZipBackendError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    let password = password_bytes(password);
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = ZipExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for index in 0..archive.len() {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new().password(password))
            .map_err(map_zip_error)?;
        let entry_size = file.size();
        let kind = extraction_entry_kind(&mut file)?;
        let entry = ExtractionEntry {
            archive_path: file.name().to_owned(),
            kind,
            uncompressed_size: Some(entry_size),
            compressed_size: Some(file.compressed_size()),
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&entry.archive_path, Some(entry_size));
            context.check_cancelled()?;
        }

        let processed = match planner.validate_entry(&entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => write_zip_entry(
                &mut file,
                &entry,
                &destination_path,
                replace_existing,
                link_target_path.as_deref(),
                &mut report,
                context.as_deref_mut(),
            )?,
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries += 1;
                let warning = format!("skipped {}: {reason}", entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                }
                0
            }
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_finished(&entry.archive_path, processed);
        }
    }

    Ok(report)
}

fn write_manifest_to_zip<W: Write + Seek>(
    writer: &mut ZipWriter<W>,
    manifest: &ArchiveManifest,
    options: &ZipCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<ZipCreateReport, ZipBackendError> {
    let mut report = ZipCreateReport {
        written_entries: 0,
        written_bytes: 0,
        encrypted: zip_password(options).is_some(),
        warnings: Vec::new(),
    };

    for entry in &manifest.entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
            context.entry_started(&entry.archive_path, Some(entry.size));
            context.check_cancelled()?;
        }

        let processed = match entry.file_type {
            ManifestFileType::Directory => {
                writer.add_directory(&entry.archive_path, zip_options(entry, options))?;
                report.written_entries += 1;
                0
            }
            ManifestFileType::File => {
                writer.start_file(&entry.archive_path, zip_options(entry, options))?;
                let mut source =
                    File::open(&entry.source_path).map_err(|source| ZipBackendError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?;
                let copied = if let Some(context) = context.as_deref_mut() {
                    copy_with_progress(
                        &mut source,
                        writer,
                        &entry.archive_path,
                        &entry.source_path,
                        context,
                    )?
                } else {
                    io::copy(&mut source, writer).map_err(|source| ZipBackendError::Io {
                        path: entry.source_path.clone(),
                        source,
                    })?
                };
                report.written_entries += 1;
                report.written_bytes += copied;
                copied
            }
            ManifestFileType::Symlink => {
                if let Some(target) = entry.symlink_target.as_ref() {
                    writer.add_symlink_from_path(
                        &entry.archive_path,
                        target,
                        zip_options(entry, options).compression_level(None),
                    )?;
                    report.written_entries += 1;
                } else {
                    let warning = format!("skipped symlink {}: missing target", entry.archive_path);
                    report.warnings.push(warning.clone());
                    if let Some(context) = context.as_deref_mut() {
                        context.warning(warning);
                    }
                }
                0
            }
            ManifestFileType::Other => {
                let warning = format!(
                    "skipped special file {}: ZIP backend only writes files and directories",
                    entry.archive_path
                );
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                }
                0
            }
        };

        if let Some(context) = context.as_deref_mut() {
            context.entry_finished(&entry.archive_path, processed);
        }
    }

    Ok(report)
}

fn zip_options<'a>(
    entry: &ManifestEntry,
    create_options: &'a ZipCreateOptions,
) -> FileOptions<'a, ()> {
    let compression_method = match create_options.compression {
        ZipCompression::Store => CompressionMethod::Stored,
        ZipCompression::Deflate => CompressionMethod::Deflated,
    };
    let mut options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(zip_compression_level(create_options))
        .large_file(needs_zip64(entry.size));

    if create_options.preserve_metadata
        && let Some(mode) = entry.permissions.unix_mode
    {
        options = options.unix_permissions(mode);
    }

    if let Some(password) = zip_password(create_options) {
        options = options.with_aes_encryption(AesMode::Aes256, password);
    }

    options
}

fn zip_password(options: &ZipCreateOptions) -> Option<&str> {
    options
        .password
        .as_ref()
        .map(SecretString::expose_secret)
        .filter(|password| !password.is_empty())
}

fn zip_compression_level(options: &ZipCreateOptions) -> Option<i64> {
    match options.compression {
        ZipCompression::Store => None,
        ZipCompression::Deflate => options.level,
    }
}

fn password_bytes(password: Option<&str>) -> Option<&[u8]> {
    password
        .filter(|password| !password.is_empty())
        .map(str::as_bytes)
}

fn map_zip_error(source: zip::result::ZipError) -> ZipBackendError {
    match &source {
        zip::result::ZipError::UnsupportedArchive(message)
            if *message == zip::result::ZipError::PASSWORD_REQUIRED =>
        {
            ZipBackendError::PasswordRequired
        }
        zip::result::ZipError::InvalidPassword => ZipBackendError::InvalidPassword,
        _ => ZipBackendError::Zip(source),
    }
}

fn needs_zip64(size: u64) -> bool {
    size > u64::from(u32::MAX)
}

fn zip_entry_kind<R: Read>(file: &zip::read::ZipFile<'_, R>) -> ZipEntryKind {
    if file.is_dir() {
        ZipEntryKind::Directory
    } else if file.is_symlink() {
        ZipEntryKind::Symlink
    } else {
        ZipEntryKind::File
    }
}

fn extraction_entry_kind<R: Read>(
    file: &mut zip::read::ZipFile<'_, R>,
) -> Result<ExtractionEntryKind, ZipBackendError> {
    if file.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }

    if file.is_symlink() {
        let mut target = String::new();
        file.read_to_string(&mut target)
            .map_err(|_| ZipBackendError::InvalidSymlinkTarget {
                archive_path: file.name().to_owned(),
            })?;
        return Ok(ExtractionEntryKind::Symlink {
            target: PathBuf::from(target),
        });
    }

    Ok(ExtractionEntryKind::File)
}

fn write_zip_entry<R: Read>(
    file: &mut zip::read::ZipFile<'_, R>,
    entry: &ExtractionEntry,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut ZipExtractReport,
    context: Option<&mut JobContext<'_>>,
) -> Result<u64, ZipBackendError> {
    if replace_existing && !matches!(entry.kind, ExtractionEntryKind::File) {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            ZipBackendError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    match entry.kind {
        ExtractionEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| ZipBackendError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            report.written_entries += 1;
            Ok(0)
        }
        ExtractionEntryKind::File => {
            let mut destination = crate::atomic_file::AtomicOutputFile::create(destination_path)
                .map_err(|source| ZipBackendError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            let output = destination
                .file_mut()
                .map_err(|source| ZipBackendError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            let copied = if let Some(context) = context {
                copy_with_progress(file, output, &entry.archive_path, destination_path, context)?
            } else {
                io::copy(file, output).map_err(|source| ZipBackendError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?
            };
            destination
                .commit_with_replace(replace_existing)
                .map_err(|source| ZipBackendError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            report.written_entries += 1;
            report.written_bytes += copied;
            Ok(copied)
        }
        ExtractionEntryKind::Symlink { ref target } => {
            if crate::safety::should_skip_symlink_materialization(&entry.kind) {
                report.skipped_entries += 1;
                let warning = crate::safety::unsupported_symlink_warning(&entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context {
                    context.warning(warning);
                }
            } else {
                write_symlink(target, destination_path)?;
                report.written_entries += 1;
            }
            Ok(0)
        }
        ExtractionEntryKind::Hardlink { .. } => {
            let source_path = link_target_path.ok_or_else(|| ZipBackendError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hardlink target was not resolved by extraction safety planning",
                ),
            })?;
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
            Ok(0)
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
            report.skipped_entries += 1;
            report.warnings.push(format!(
                "skipped unsupported ZIP entry kind for {}",
                entry.archive_path
            ));
            Ok(0)
        }
    }
}

fn copy_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    archive_path: &str,
    io_path: &Path,
    context: &mut JobContext<'_>,
) -> Result<u64, ZipBackendError> {
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut copied = 0_u64;

    loop {
        context.check_cancelled()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ZipBackendError::Io {
                path: io_path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| ZipBackendError::Io {
                path: io_path.to_path_buf(),
                source,
            })?;
        let read = read as u64;
        copied += read;
        context.bytes_processed(Some(archive_path), read);
    }

    Ok(copied)
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), ZipBackendError> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| ZipBackendError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::hard_link(source_path, destination_path).map_err(|source| ZipBackendError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), ZipBackendError> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| ZipBackendError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    symlink(target, destination_path).map_err(|source| ZipBackendError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), ZipBackendError> {
    Err(ZipBackendError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ZipBackendError, ZipCompression, ZipCreateOptions, ZipEntryKind, create_zip_from_path,
        extract_zip, extract_zip_with_password, list_zip, needs_zip64, test_zip,
        test_zip_with_password,
    };
    use crate::safety::{ExtractionPolicy, ExtractionSafetyError};
    use crate::secrets::SecretString;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    #[test]
    fn creates_lists_tests_and_extracts_zip() {
        let temp = TestDir::new("creates_lists_tests_and_extracts_zip");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        let archive = temp.path("archive.zip");

        let create_report =
            create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default())
                .unwrap();
        let listing = list_zip(&archive).unwrap();
        let test_report = test_zip(&archive).unwrap();
        let extract_report =
            extract_zip(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(create_report.written_entries, 4);
        assert_eq!(
            listing
                .entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "project/",
                "project/empty/",
                "project/src/",
                "project/src/main.rs"
            ]
        );
        assert_eq!(test_report.tested_entries, 4);
        assert_eq!(extract_report.written_entries, 4);
        assert_eq!(
            fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert!(temp.path("out/project/empty").is_dir());
    }

    #[test]
    fn creates_store_zip() {
        let temp = TestDir::new("creates_store_zip");
        temp.write_file("project/file.txt", b"stored");
        let archive = temp.path("archive.zip");

        create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                level: None,
                preserve_metadata: true,
                password: None,
            },
        )
        .unwrap();

        let file_entry = list_zip(&archive)
            .unwrap()
            .entries
            .into_iter()
            .find(|entry| entry.name == "project/file.txt")
            .unwrap();
        assert_eq!(file_entry.kind, ZipEntryKind::File);
    }

    #[test]
    fn creates_streaming_zip_to_non_seekable_writer() {
        let temp = TestDir::new("creates_streaming_zip_to_non_seekable_writer");
        temp.write_file("project/file.txt", b"streamed");
        let mut output = WriteOnlyBuffer::default();

        let (_output, report) = super::create_zip_stream_from_path(
            temp.path("project"),
            &mut output,
            &ZipCreateOptions::default(),
        )
        .unwrap();

        assert_eq!(report.written_entries, 2);

        let cursor = std::io::Cursor::new(output.bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let mut file = archive.by_name("project/file.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, "streamed");
    }

    #[test]
    fn handles_unicode_names() {
        let temp = TestDir::new("handles_unicode_names");
        temp.write_file("project/hello cafe.txt", b"unicode");
        let archive = temp.path("archive.zip");

        create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();
        extract_zip(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(
            fs::read_to_string(temp.path("out/project/hello cafe.txt")).unwrap(),
            "unicode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_symlinks_during_creation() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("preserves_symlinks_during_creation");
        temp.write_file("project/target.txt", b"target");
        symlink("target.txt", temp.path("project/link.txt")).unwrap();
        let archive = temp.path("archive.zip");

        let report =
            create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default())
                .unwrap();

        assert_eq!(report.warnings.len(), 0);
        assert!(
            list_zip(&archive)
                .unwrap()
                .entries
                .iter()
                .any(
                    |entry| entry.name == "project/link.txt" && entry.kind == ZipEntryKind::Symlink
                )
        );
    }

    #[test]
    fn aes_zip_requires_correct_password() {
        let temp = TestDir::new("aes_zip_requires_correct_password");
        temp.write_file("project/file.txt", b"secret");
        let archive = temp.path("archive.zip");

        let report = create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Deflate,
                level: None,
                preserve_metadata: true,
                password: Some(SecretString::from("correct horse")),
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(
            list_zip(&archive)
                .unwrap()
                .entries
                .iter()
                .any(|entry| { entry.name == "project/file.txt" && entry.encrypted })
        );

        assert!(matches!(
            test_zip(&archive),
            Err(ZipBackendError::PasswordRequired)
        ));
        assert!(matches!(
            test_zip_with_password(&archive, Some("wrong password")),
            Err(ZipBackendError::InvalidPassword)
        ));

        let test_report = test_zip_with_password(&archive, Some("correct horse")).unwrap();
        assert_eq!(test_report.tested_bytes, 6);

        extract_zip_with_password(
            &archive,
            temp.path("out"),
            ExtractionPolicy::default(),
            Some("correct horse"),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(temp.path("out/project/file.txt")).unwrap(),
            "secret"
        );
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal");
        let archive = temp.path("archive.zip");
        write_raw_zip(
            &archive,
            &[(
                "../escape.txt",
                b"escape".as_slice(),
                CompressionMethod::Stored,
            )],
        );

        let error =
            extract_zip(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(
            error,
            ZipBackendError::Safety(ExtractionSafetyError::ParentTraversal { .. })
        ));
    }

    #[test]
    fn extraction_rejects_case_collisions() {
        let temp = TestDir::new("extraction_rejects_case_collisions");
        let archive = temp.path("archive.zip");
        write_raw_zip(
            &archive,
            &[
                ("README.md", b"one".as_slice(), CompressionMethod::Stored),
                ("readme.md", b"two".as_slice(), CompressionMethod::Stored),
            ],
        );

        let error =
            extract_zip(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(
            error,
            ZipBackendError::Safety(ExtractionSafetyError::NameCollision { .. })
        ));
    }

    #[test]
    fn large_entries_enable_zip64() {
        assert!(!needs_zip64(u64::from(u32::MAX)));
        assert!(needs_zip64(u64::from(u32::MAX) + 1));
    }

    fn write_raw_zip(path: &Path, entries: &[(&str, &[u8], CompressionMethod)]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);

        for (name, contents, method) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(*method),
                )
                .unwrap();
            writer.write_all(contents).unwrap();
        }

        writer.finish().unwrap();
    }

    struct TestDir {
        root: PathBuf,
    }

    #[derive(Default)]
    struct WriteOnlyBuffer {
        bytes: Vec<u8>,
    }

    impl Write for WriteOnlyBuffer {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
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
