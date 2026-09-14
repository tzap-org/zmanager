//! ZIP archive creation, listing, integrity testing, and extraction.
//!
//! Format API asymmetries vs the 7z backend, deliberately kept:
//! - Integrity testing (`test_zip_with_password_filter`) exists only on the
//!   ZIP side; 7z has no test API.
//! - [`crate::sevenz_backend::list_7z`] takes a password because 7z can
//!   encrypt its file names, while `list_zip` does not (ZIP names are always
//!   readable from the central directory).
//! - 7z never materializes symlinks — entries that a hostile archive declares
//!   as link-like are extracted as regular files; see
//!   `crate::sevenz_backend::extraction_kind` for the rationale.

use crate::backend_impl::backend_report::open_member_source;
use crate::jobs::{CancellationToken, JobContext};
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use crate::secrets::SecretString;
use crate::zip_split::{MIN_ZIP_VOLUME_SIZE_BYTES, open_zip_reader, split_zip_temp_archive};
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
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
    /// Optional password. When present, ZIP entries are written with AES-256.
    pub password: Option<SecretString>,
    /// Split ZIP output into standard `.z01`, `.z02`, ..., `.zip` volumes.
    pub volume_size: Option<u64>,
}

impl Default for ZipCreateOptions {
    fn default() -> Self {
        Self { compression: ZipCompression::default(), level: None, preserve_metadata: true, replace_existing: false, password: None, volume_size: None }
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
    /// Requested split volume size, when the archive was split.
    pub volume_size: Option<u64>,
    /// Number of output archive files created.
    pub volume_count: usize,
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
    /// Compression method name.
    pub method: String,
    /// Entry CRC-32 from the ZIP central directory.
    pub crc: u32,
    /// Entry comment, when present.
    pub comment: Option<String>,
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
    /// Requested split volume size is too small for the ZIP backend.
    VolumeSizeTooSmall { size: u64, minimum: u64 },
    /// Split ZIP creation needs unsupported ZIP metadata.
    UnsupportedSplitZip { reason: String },
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
            Self::VolumeSizeTooSmall { size, minimum } => {
                write!(f, "ZIP volume size {size} bytes is smaller than the minimum {minimum} bytes")
            }
            Self::UnsupportedSplitZip { reason } => {
                write!(f, "split ZIP creation is not supported for this archive: {reason}")
            }
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
            | Self::VolumeSizeTooSmall { .. }
            | Self::UnsupportedSplitZip { .. }
            | Self::InvalidSymlinkTarget { .. }
            | Self::Cancelled => None,
        }
    }
}

crate::backend_error_from_impls!(ZipBackendError);

impl From<zip::result::ZipError> for ZipBackendError {
    fn from(source: zip::result::ZipError) -> Self {
        map_zip_error(source)
    }
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
    validate_zip_volume_size(options.volume_size)?;

    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    let file = output.file_mut().map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    let mut writer = ZipWriter::new(file);
    let mut report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    writer.finish()?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_zip_temp_archive(output.temp_path(), destination, volume_size, options.replace_existing)?;
    } else {
        output.commit_with_file_replace(options.replace_existing).map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    }

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
    validate_zip_volume_size(options.volume_size)?;

    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    let file = output.file_mut().map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    let mut writer = ZipWriter::new(file);
    let mut report = write_manifest_to_zip(&mut writer, manifest, options, Some(context))?;
    writer.finish()?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_zip_temp_archive(output.temp_path(), destination, volume_size, options.replace_existing)?;
    } else {
        output.commit_with_file_replace(options.replace_existing).map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;
    }

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
pub fn create_zip_stream_from_path<W: Write>(source: impl AsRef<Path>, output: W, options: &ZipCreateOptions) -> Result<(W, ZipCreateReport), ZipBackendError> {
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
    validate_zip_stream_options(options)?;

    let mut writer = ZipWriter::new_stream(output);
    let report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    let output = writer.finish()?.into_inner();

    Ok((output, report))
}

fn validate_zip_stream_options(options: &ZipCreateOptions) -> Result<(), ZipBackendError> {
    if options.volume_size.is_some() {
        return Err(ZipBackendError::UnsupportedSplitZip { reason: "streaming ZIP output cannot be split".to_owned() });
    }
    Ok(())
}

fn validate_zip_volume_size(volume_size: Option<u64>) -> Result<(), ZipBackendError> {
    match volume_size {
        Some(size) if size < MIN_ZIP_VOLUME_SIZE_BYTES => Err(ZipBackendError::VolumeSizeTooSmall { size, minimum: MIN_ZIP_VOLUME_SIZE_BYTES }),
        Some(size) if size > u64::from(u32::MAX) => {
            Err(ZipBackendError::UnsupportedSplitZip { reason: "volume sizes above 4294967295 bytes need ZIP64 multi-disk metadata".to_owned() })
        }
        _ => Ok(()),
    }
}

/// Lists ZIP archive entries.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when the archive cannot be opened or parsed.
pub fn list_zip(path: impl AsRef<Path>) -> Result<ZipListing, ZipBackendError> {
    let path = path.as_ref();
    let reader = open_zip_reader(path)?;
    let mut archive = ZipArchive::new(reader)?;
    list_zip_archive(&mut archive)
}

/// Lists entries from an already opened ZIP reader.
pub(crate) fn list_zip_archive<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<ZipListing, ZipBackendError> {
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
            method: format!("{:?}", file.compression()),
            crc: file.crc32(),
            comment: (!file.comment().is_empty()).then(|| file.comment().to_owned()),
        });
    }

    Ok(ZipListing { entries })
}

/// Reads selected ZIP entries to validate archive integrity with an optional
/// password.
///
/// # Errors
/// Tests a ZIP archive from disk.
///
/// Returns [`ZipBackendError`] when the archive cannot be read or a selected
/// entry requires a missing/incorrect password.
pub fn test_zip_with_password_filter(
    path: impl AsRef<Path>,
    password: Option<&str>,
    selected: impl FnMut(&str) -> bool,
) -> Result<ZipTestReport, ZipBackendError> {
    let path = path.as_ref();
    let reader = open_zip_reader(path)?;
    let mut archive = ZipArchive::new(reader)?;
    test_zip_archive(&mut archive, path, password, || false, selected)
}

/// Tests selected entries in an already opened ZIP reader.
pub(crate) fn test_zip_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    archive_path: &Path,
    password: Option<&str>,
    is_cancelled: impl Fn() -> bool + Sync,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<ZipTestReport, ZipBackendError> {
    let mut tested_entries = 0;
    let mut skipped_entries = 0;
    let mut tested_bytes = 0;
    let password = password_bytes(password);

    let mut to_test = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        if is_cancelled() {
            return Err(ZipBackendError::Cancelled);
        }
        // Read the name straight from the parsed central directory. Opening an
        // entry reader here would decode each selected entry twice, once for its
        // name and again for its data (CR-194).
        let name = archive.name_for_index(index).ok_or_else(|| map_zip_error(zip::result::ZipError::FileNotFound))?;
        if !selected(name) {
            skipped_entries += 1;
            continue;
        }
        to_test.push(index);
    }

    if to_test.len() >= 4 && crate::tar_metadata::available_parallelism_at_least_two().is_some() && archive_path.is_file() {
        use rayon::prelude::*;
        let is_cancelled = &is_cancelled;
        let results: Result<Vec<(usize, u64)>, ZipBackendError> = to_test
            .par_chunks(32)
            .map(|chunk| {
                let file = File::open(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
                let mut local_archive = ZipArchive::new(file)?;
                let mut local_tested = 0_usize;
                let mut local_bytes = 0_u64;
                let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
                for &index in chunk {
                    if is_cancelled() {
                        return Err(ZipBackendError::Cancelled);
                    }
                    let mut file = local_archive.by_index_with_options(index, ZipReadOptions::new().password(password)).map_err(map_zip_error)?;
                    if file.is_dir() {
                        local_tested += 1;
                        continue;
                    }
                    loop {
                        if is_cancelled() {
                            return Err(ZipBackendError::Cancelled);
                        }
                        let read = file.read(&mut buffer).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
                        if read == 0 {
                            break;
                        }
                        local_bytes += read as u64;
                    }
                    local_tested += 1;
                }
                Ok((local_tested, local_bytes))
            })
            .collect();

        for (entries, bytes) in results? {
            tested_entries += entries;
            tested_bytes += bytes;
        }
        return Ok(ZipTestReport { tested_entries, skipped_entries, tested_bytes });
    }

    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    for index in to_test {
        if is_cancelled() {
            return Err(ZipBackendError::Cancelled);
        }
        let mut file = archive.by_index_with_options(index, ZipReadOptions::new().password(password)).map_err(map_zip_error)?;
        if file.is_dir() {
            tested_entries += 1;
            continue;
        }
        loop {
            if is_cancelled() {
                return Err(ZipBackendError::Cancelled);
            }
            let read = file.read(&mut buffer).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
            if read == 0 {
                break;
            }
            tested_bytes += read as u64;
        }
        tested_entries += 1;
    }

    Ok(ZipTestReport { tested_entries, skipped_entries, tested_bytes })
}

/// Copies one entry from an already opened ZIP reader.
pub(crate) fn copy_zip_entry_from_archive<R: Read + Seek, W: Write + ?Sized>(
    archive: &mut ZipArchive<R>,
    archive_path: &Path,
    password: Option<&str>,
    entry_index: usize,
    output: &mut W,
) -> Result<u64, ZipBackendError> {
    let mut file = archive.by_index_with_options(entry_index, ZipReadOptions::new().password(password_bytes(password))).map_err(map_zip_error)?;
    if zip_entry_kind(&file) != ZipEntryKind::File {
        return Err(ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "retained ZIP entry is not a regular file"),
        });
    }
    io::copy(&mut file, output).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })
}

/// Extracts a ZIP archive with an optional password while emitting job events.
pub fn extract_zip_with_context_and_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<ZipExtractReport, ZipBackendError> {
    let archive_path = archive_path.as_ref();
    let reader = open_zip_reader(archive_path)?;
    let mut archive = ZipArchive::new(reader)?;
    let token = context.cancellation_token();
    extract_zip_archive(&mut archive, archive_path, destination, policy, password, Some(&token), Some(context), None, None)
}

/// Extracts from an already opened ZIP reader without reopening its source.
#[allow(clippy::too_many_arguments)]
pub(crate) fn extract_zip_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    archive_path: &Path,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    cancellation: Option<&CancellationToken>,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    selected_indices: Option<&[usize]>,
) -> Result<ZipExtractReport, ZipBackendError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })?;

    let password = password_bytes(password);
    if let Some(indices) = selected_indices
        && indices.iter().any(|&selected| selected >= archive.len())
    {
        return Err(ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "retained ZIP entry ID is not present in this archive"),
        });
    }
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = ZipExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
    let mut deferred_directories: Vec<(PathBuf, Option<u32>, Option<zip::DateTime>)> = Vec::new();
    let mut io_buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];

    let all_indices: Vec<usize>;
    let target_indices: &[usize] = if let Some(indices) = selected_indices {
        indices
    } else {
        all_indices = (0..archive.len()).collect();
        &all_indices
    };

    for &index in target_indices {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(ZipBackendError::Cancelled);
        }
        let mut file = archive.by_index_with_options(index, ZipReadOptions::new().password(password)).map_err(map_zip_error)?;
        let entry_size = file.size();
        let unix_mode = file.unix_mode();
        let modified_time = file.last_modified();
        let kind = extraction_entry_kind(&mut file)?;
        let entry =
            ExtractionEntry { archive_path: file.name().to_owned(), kind, uncompressed_size: Some(entry_size), compressed_size: Some(file.compressed_size()) };

        crate::extract_loop::process_extraction_entry(
            &mut report,
            context.as_deref_mut(),
            &mut planner,
            &entry,
            &mut |action, report, context| match action {
                crate::extract_loop::EntryAction::Skip => Ok(0),
                crate::extract_loop::EntryAction::Write(decision) => write_zip_entry(
                    &mut file,
                    &entry,
                    ZipEntryWriteContext {
                        destination_path: decision.destination_path,
                        replace_existing: decision.replace_existing,
                        link_target_path: decision.link_target_path,
                        report,
                        job_context: context,
                        unix_mode,
                        modified_time,
                        deferred_directories: &mut deferred_directories,
                        io_buffer: &mut io_buffer,
                    },
                    cancellation,
                ),
            },
        )?;
    }

    apply_deferred_zip_directory_metadata(&deferred_directories)?;

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
        volume_size: options.volume_size,
        volume_count: 1,
        warnings: Vec::new(),
    };
    let mut io_buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];

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
            // Open before starting the member: an entry that cannot be filled
            // must not be started at all, or the archive would carry an empty
            // member claiming the file is present.
            ManifestFileType::File => match open_member_source(&entry.source_path, &mut report.warnings) {
                None => 0,
                Some(mut source) => {
                    writer.start_file(&entry.archive_path, zip_options(entry, options))?;
                    let copied = if let Some(context) = context.as_deref_mut() {
                        copy_with_progress(&mut source, writer, &entry.archive_path, &entry.source_path, context, &mut io_buffer)?
                    } else {
                        io::copy(&mut source, writer).map_err(|source| ZipBackendError::Io { path: entry.source_path.clone(), source })?
                    };
                    report.written_entries += 1;
                    report.written_bytes += copied;
                    copied
                }
            },
            ManifestFileType::Symlink => {
                if let Some(target) = entry.symlink_target.as_ref() {
                    let target_str = target.to_str().ok_or_else(|| ZipBackendError::InvalidSymlinkTarget { archive_path: entry.archive_path.clone() })?;
                    let target_normalized = if target_str.contains('\\') { target_str.replace('\\', "/") } else { target_str.to_owned() };
                    writer.add_symlink(&entry.archive_path, target_normalized, zip_options(entry, options))?;
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
                let warning = format!("skipped special file {}: ZIP backend only writes files and directories", entry.archive_path);
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

fn zip_options<'a>(entry: &ManifestEntry, create_options: &'a ZipCreateOptions) -> FileOptions<'a, ()> {
    let compression_method = match create_options.compression {
        ZipCompression::Store => CompressionMethod::Stored,
        ZipCompression::Deflate => CompressionMethod::Deflated,
    };
    let mut options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(zip_compression_level(create_options))
        .large_file(needs_zip64(entry.size));

    if create_options.preserve_metadata {
        if let Some(mode) = entry.permissions.unix_mode {
            options = options.unix_permissions(mode);
        }
        if let Some(modified) = entry.modified
            && let offset = time::OffsetDateTime::from(modified)
            && let Ok(dt) = zip::DateTime::from_date_and_time(
                u16::try_from(offset.year()).unwrap_or(1980),
                u8::from(offset.month()),
                offset.day(),
                offset.hour(),
                offset.minute(),
                offset.second(),
            )
        {
            options = options.last_modified_time(dt);
        }
    }

    if let Some(password) = zip_password(create_options) {
        options = options.with_aes_encryption(AesMode::Aes256, password);
    }

    options
}

fn zip_password(options: &ZipCreateOptions) -> Option<&str> {
    options.password.as_ref().map(SecretString::expose_secret).filter(|password| !password.is_empty())
}

fn zip_compression_level(options: &ZipCreateOptions) -> Option<i64> {
    match options.compression {
        ZipCompression::Store => None,
        ZipCompression::Deflate => options.level,
    }
}

fn password_bytes(password: Option<&str>) -> Option<&[u8]> {
    crate::secrets::normalized_password(password).map(str::as_bytes)
}

fn map_zip_error(source: zip::result::ZipError) -> ZipBackendError {
    // The zip crate has no structured "password required" error variant: it
    // reports the condition as a `ZipError::UnsupportedArchive` carrying the
    // PASSWORD_REQUIRED message string, which is why this match is stringly
    // typed. Re-check for a structured variant when the zip crate is upgraded.
    match &source {
        zip::result::ZipError::UnsupportedArchive(message) if *message == zip::result::ZipError::PASSWORD_REQUIRED => ZipBackendError::PasswordRequired,
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

fn extraction_entry_kind<R: Read>(file: &mut zip::read::ZipFile<'_, R>) -> Result<ExtractionEntryKind, ZipBackendError> {
    if file.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }

    if file.is_symlink() {
        let mut target = String::new();
        file.read_to_string(&mut target).map_err(|_| ZipBackendError::InvalidSymlinkTarget { archive_path: file.name().to_owned() })?;
        return Ok(ExtractionEntryKind::Symlink { target: PathBuf::from(target) });
    }

    Ok(ExtractionEntryKind::File)
}

struct ZipEntryWriteContext<'a, 'context> {
    destination_path: &'a Path,
    replace_existing: bool,
    link_target_path: Option<&'a Path>,
    report: &'a mut ZipExtractReport,
    job_context: Option<&'a mut JobContext<'context>>,
    unix_mode: Option<u32>,
    modified_time: Option<zip::DateTime>,
    deferred_directories: &'a mut Vec<(PathBuf, Option<u32>, Option<zip::DateTime>)>,
    io_buffer: &'a mut [u8],
}

fn prepare_zip_destination(entry: &ExtractionEntry, destination_path: &Path, replace_existing: bool) -> Result<(), ZipBackendError> {
    if replace_existing && !matches!(entry.kind, ExtractionEntryKind::File) {
        crate::safety::remove_destination_for_replace(destination_path)
            .map_err(|source| ZipBackendError::Io { path: destination_path.to_path_buf(), source })?;
    }
    Ok(())
}

fn write_zip_entry<R: Read>(
    file: &mut zip::read::ZipFile<'_, R>,
    entry: &ExtractionEntry,
    context: ZipEntryWriteContext<'_, '_>,
    cancellation: Option<&CancellationToken>,
) -> Result<u64, ZipBackendError> {
    let ZipEntryWriteContext {
        destination_path,
        replace_existing,
        link_target_path,
        report,
        job_context,
        unix_mode,
        modified_time,
        deferred_directories,
        io_buffer,
    } = context;
    prepare_zip_destination(entry, destination_path, replace_existing)?;

    match entry.kind {
        ExtractionEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| ZipBackendError::Io { path: destination_path.to_path_buf(), source })?;
            deferred_directories.push((destination_path.to_path_buf(), unix_mode, modified_time));
            report.written_entries += 1;
            Ok(0)
        }
        ExtractionEntryKind::File => {
            let copied = crate::extract_loop::copy_file_entry(
                destination_path,
                replace_existing,
                Some(&entry.archive_path),
                job_context,
                io_buffer,
                |buf| {
                    if cancellation.is_some_and(CancellationToken::is_cancelled) {
                        return Err(ZipBackendError::Cancelled);
                    }
                    file.read(buf).map_err(|source| ZipBackendError::Io { path: destination_path.to_path_buf(), source })
                },
                |source, path| ZipBackendError::Io { path: path.to_path_buf(), source },
            )?;
            apply_zip_metadata(destination_path, unix_mode, modified_time)?;
            report.written_entries += 1;
            report.written_bytes += copied;
            Ok(copied)
        }
        ExtractionEntryKind::Symlink { ref target } => {
            if crate::safety::should_skip_symlink_materialization(&entry.kind) {
                crate::extract_loop::skip_entry(report, job_context, crate::safety::unsupported_symlink_warning(&entry.archive_path));
            } else {
                crate::extract_materialize::write_symlink(target, destination_path)
                    .map_err(|source| ZipBackendError::Io { path: destination_path.to_path_buf(), source })?;
                apply_symlink_mtime(destination_path, modified_time)?;
                report.written_entries += 1;
            }
            Ok(0)
        }
        ExtractionEntryKind::Hardlink { .. } => {
            let source_path = link_target_path
                .ok_or_else(|| ZipBackendError::Io { path: destination_path.to_path_buf(), source: crate::extract_loop::unresolved_hardlink_target() })?;
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
            Ok(0)
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
            crate::extract_loop::skip_entry(report, job_context, format!("skipped unsupported ZIP entry kind for {}", entry.archive_path));
            Ok(0)
        }
    }
}

fn apply_zip_metadata(path: &Path, unix_mode: Option<u32>, modified_time: Option<zip::DateTime>) -> Result<(), ZipBackendError> {
    let file_time = modified_time.and_then(|dt| {
        let date =
            time::Date::from_calendar_date(i32::from(dt.year()), time::Month::try_from(dt.month()).unwrap_or(time::Month::January), dt.day().max(1)).ok()?;
        let time_cmp = time::Time::from_hms(dt.hour(), dt.minute(), dt.second()).ok()?;
        let primitive = time::PrimitiveDateTime::new(date, time_cmp);
        Some(filetime::FileTime::from_system_time(std::time::SystemTime::from(primitive.assume_utc())))
    });
    crate::extract_materialize::apply_metadata(path, unix_mode, file_time).map_err(|source| ZipBackendError::Io { path: path.to_path_buf(), source })
}

/// Uses `set_symlink_file_times` to avoid following the link. Errors are
/// reported so extraction cannot claim metadata was restored when it was not.
fn apply_symlink_mtime(path: &Path, modified_time: Option<zip::DateTime>) -> Result<(), ZipBackendError> {
    if let Some(dt) = modified_time
        && let Ok(date) =
            time::Date::from_calendar_date(i32::from(dt.year()), time::Month::try_from(dt.month()).unwrap_or(time::Month::January), dt.day().max(1))
        && let Ok(time_cmp) = time::Time::from_hms(dt.hour(), dt.minute(), dt.second())
    {
        let primitive = time::PrimitiveDateTime::new(date, time_cmp);
        let sys_time = std::time::SystemTime::from(primitive.assume_utc());
        let ft = filetime::FileTime::from_system_time(sys_time);
        filetime::set_symlink_file_times(path, ft, ft).map_err(|source| ZipBackendError::Io { path: path.to_path_buf(), source })?;
    }
    Ok(())
}

fn apply_deferred_zip_directory_metadata(directories: &[(PathBuf, Option<u32>, Option<zip::DateTime>)]) -> Result<(), ZipBackendError> {
    crate::extract_loop::apply_deferred_directory_metadata(directories, |(path, unix_mode, modified_time): &(PathBuf, Option<u32>, Option<zip::DateTime>)| {
        apply_zip_metadata(path, *unix_mode, *modified_time)
    })
}

/// Streams an entry from the source file into the archive writer with
/// cancellation and progress reporting (create path; the extraction path uses
/// the shared [`crate::extract_loop::copy_file_entry`]).
fn copy_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    archive_path: &str,
    io_path: &Path,
    context: &mut JobContext<'_>,
    io_buffer: &mut [u8],
) -> Result<u64, ZipBackendError> {
    let mut copied = 0_u64;

    loop {
        context.check_cancelled()?;
        let read = reader.read(io_buffer).map_err(|source| ZipBackendError::Io { path: io_path.to_path_buf(), source })?;
        if read == 0 {
            break;
        }
        writer.write_all(&io_buffer[..read]).map_err(|source| ZipBackendError::Io { path: io_path.to_path_buf(), source })?;
        let read = read as u64;
        copied += read;
        context.bytes_processed(Some(archive_path), read);
    }

    Ok(copied)
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), ZipBackendError> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| ZipBackendError::Io { path: parent.to_path_buf(), source })?;
    }
    fs::hard_link(source_path, destination_path).map_err(|source| ZipBackendError::Io { path: destination_path.to_path_buf(), source })
}

#[cfg(test)]
mod tests {
    use super::{
        ZipBackendError, ZipCompression, ZipCreateOptions, ZipEntryKind, ZipExtractReport, ZipTestReport, extract_zip_with_context_and_password, list_zip,
        needs_zip64, test_zip_with_password_filter,
    };
    use crate::jobs::{CancellationToken, JobContext, JobEvent};
    use crate::safety::{ExtractionPolicy, ExtractionSafetyError};
    use crate::secrets::SecretString;
    use crate::test_support::TestDir;
    use crate::test_support::create_zip_fixture;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::Path;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn extract_zip_fixture(
        archive_path: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        policy: ExtractionPolicy,
    ) -> Result<ZipExtractReport, ZipBackendError> {
        extract_zip_fixture_with_password(archive_path, destination, policy, None)
    }

    fn extract_zip_fixture_with_password(
        archive_path: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        policy: ExtractionPolicy,
        password: Option<&str>,
    ) -> Result<ZipExtractReport, ZipBackendError> {
        let token = CancellationToken::new();
        let mut sink = |_event: JobEvent| {};
        let mut context = JobContext::new(&token, &mut sink);
        extract_zip_with_context_and_password(archive_path, destination, policy, password, &mut context)
    }

    fn test_zip_fixture(path: impl AsRef<Path>) -> Result<ZipTestReport, ZipBackendError> {
        test_zip_fixture_with_password(path, None)
    }

    fn test_zip_fixture_with_password(path: impl AsRef<Path>, password: Option<&str>) -> Result<ZipTestReport, ZipBackendError> {
        test_zip_with_password_filter(path, password, |_| true)
    }

    #[test]
    fn creates_lists_tests_and_extracts_zip() {
        let temp = TestDir::new("creates_lists_tests_and_extracts_zip");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        let archive = temp.path("archive.zip");

        let create_report = create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();
        let listing = list_zip(&archive).unwrap();
        let test_report = test_zip_fixture(&archive).unwrap();
        let extract_report = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(create_report.written_entries, 4);
        assert_eq!(
            listing.entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(),
            vec!["project/", "project/empty/", "project/src/", "project/src/main.rs"]
        );
        assert_eq!(test_report.tested_entries, 4);
        assert_eq!(extract_report.written_entries, 4);
        assert_eq!(fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(), "fn main() {}\n");
        assert!(temp.path("out/project/empty").is_dir());
    }

    #[test]

    fn preserves_metadata_during_creation_and_extraction() {
        let temp = TestDir::new("preserves_metadata_zip");
        let (_path, mtime) = crate::test_support::script_fixture_with_metadata(&temp);

        let archive = temp.path("archive.zip");

        create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions { preserve_metadata: true, ..ZipCreateOptions::default() }).unwrap();

        extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let out_path = temp.path("out/project/script.sh");

        let metadata = fs::metadata(&out_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        }

        // ZIP only has 2-second resolution (MS-DOS time), so we check with a delta
        let mtime_extracted = filetime::FileTime::from_last_modification_time(&metadata);
        let diff = (mtime_extracted.unix_seconds() - mtime.unix_seconds()).abs();
        assert!(diff <= 2, "extracted mtime diff {diff} is greater than 2 seconds");
    }

    #[test]

    fn creates_store_zip() {
        let temp = TestDir::new("creates_store_zip");
        temp.write_file("project/file.txt", b"stored");
        let archive = temp.path("archive.zip");

        create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions { compression: ZipCompression::Store, level: None, ..ZipCreateOptions::default() },
        )
        .unwrap();

        let file_entry = list_zip(&archive).unwrap().entries.into_iter().find(|entry| entry.name == "project/file.txt").unwrap();
        assert_eq!(file_entry.kind, ZipEntryKind::File);
    }

    #[test]
    fn creates_streaming_zip_to_non_seekable_writer() {
        let temp = TestDir::new("creates_streaming_zip_to_non_seekable_writer");
        temp.write_file("project/file.txt", b"streamed");
        let mut output = WriteOnlyBuffer::default();

        let (_output, report) = super::create_zip_stream_from_path(temp.path("project"), &mut output, &ZipCreateOptions::default()).unwrap();

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

        create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();
        extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(fs::read_to_string(temp.path("out/project/hello cafe.txt")).unwrap(), "unicode");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_symlinks_during_creation() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("preserves_symlinks_during_creation");
        temp.write_file("project/target.txt", b"target");
        symlink("target.txt", temp.path("project/link.txt")).unwrap();
        let archive = temp.path("archive.zip");

        let report = create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();

        let listing = list_zip(&archive).unwrap();
        assert_eq!(report.warnings.len(), 0);
        assert!(listing.entries.iter().any(|entry| entry.name == "project/link.txt" && entry.kind == ZipEntryKind::Symlink));

        let extract_report = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        assert_eq!(extract_report.written_entries, 3);
        let extracted_link = temp.path("out/project/link.txt");
        assert_eq!(fs::read_link(&extracted_link).unwrap(), Path::new("target.txt"));
        assert_eq!(fs::read_to_string(&extracted_link).unwrap(), "target");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_relative_symlink_targets_with_parent_traversal() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("preserves_relative_symlink_targets");
        temp.write_file("project/README.txt", b"readme content");
        temp.write_file("project/root_target.txt", b"root target content");
        temp.create_dir("project/nested");
        temp.create_dir("project/deep/nested");

        symlink("../README.txt", temp.path("project/nested/readme-link.txt")).unwrap();
        symlink("../../root_target.txt", temp.path("project/deep/nested/deep-link.txt")).unwrap();
        let archive = temp.path("archive.zip");

        let report = create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();
        assert_eq!(report.warnings.len(), 0);

        let listing = list_zip(&archive).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "project/nested/readme-link.txt" && entry.kind == ZipEntryKind::Symlink));
        assert!(listing.entries.iter().any(|entry| entry.name == "project/deep/nested/deep-link.txt" && entry.kind == ZipEntryKind::Symlink));

        let extract_report = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        assert_eq!(extract_report.written_entries, 8);

        let extracted_readme_link = temp.path("out/project/nested/readme-link.txt");
        assert_eq!(fs::read_link(&extracted_readme_link).unwrap(), Path::new("../README.txt"));
        assert_eq!(fs::read_to_string(&extracted_readme_link).unwrap(), "readme content");

        let extracted_deep_link = temp.path("out/project/deep/nested/deep-link.txt");
        assert_eq!(fs::read_link(&extracted_deep_link).unwrap(), Path::new("../../root_target.txt"));
        assert_eq!(fs::read_to_string(&extracted_deep_link).unwrap(), "root target content");
    }

    #[test]
    fn aes_zip_requires_correct_password() {
        let temp = TestDir::new("aes_zip_requires_correct_password");
        temp.write_file("project/file.txt", b"secret");
        let archive = temp.path("archive.zip");

        let report = create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Deflate,
                level: None,
                password: Some(SecretString::from("correct horse")),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(list_zip(&archive).unwrap().entries.iter().any(|entry| { entry.name == "project/file.txt" && entry.encrypted }));

        assert!(matches!(test_zip_fixture(&archive), Err(ZipBackendError::PasswordRequired)));
        assert!(matches!(test_zip_fixture_with_password(&archive, Some("wrong password")), Err(ZipBackendError::InvalidPassword)));

        let test_report = test_zip_fixture_with_password(&archive, Some("correct horse")).unwrap();
        assert_eq!(test_report.tested_bytes, 6);

        extract_zip_fixture_with_password(&archive, temp.path("out"), ExtractionPolicy::default(), Some("correct horse")).unwrap();
        assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "secret");
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal");
        let archive = temp.path("archive.zip");
        write_raw_zip(&archive, &[("../escape.txt", b"escape".as_slice(), CompressionMethod::Stored)]);

        let error = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(error, ZipBackendError::Safety(ExtractionSafetyError::ParentTraversal { .. })));
    }

    #[test]
    fn extraction_skips_archive_root_directory_entries() {
        // The root-directory skip was unified across backends (CR-118): the
        // zip backend used to materialize "." as the destination root and
        // apply the archive root's metadata to it.
        let temp = TestDir::new("extracts_zip_with_root_directory");
        let archive = temp.path("archive.zip");
        let file = File::create(&archive).unwrap();
        let mut writer = ZipWriter::new(file);
        writer.add_directory(".", SimpleFileOptions::default()).unwrap();
        writer.start_file("payload/file.txt", SimpleFileOptions::default()).unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();

        let report = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert_eq!(report.written_entries, 1);
        assert_eq!(report.skipped_entries, 1);
        assert_eq!(fs::read(temp.path("out/payload/file.txt")).unwrap(), b"payload");
        assert!(report.warnings.iter().any(|warning| warning == "skipped archive root directory entry"));
    }

    #[test]
    fn extraction_rejects_case_collisions() {
        let temp = TestDir::new("extraction_rejects_case_collisions");
        let archive = temp.path("archive.zip");
        write_raw_zip(&archive, &[("README.md", b"one".as_slice(), CompressionMethod::Stored), ("readme.md", b"two".as_slice(), CompressionMethod::Stored)]);

        let error = extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(error, ZipBackendError::Safety(ExtractionSafetyError::NameCollision { .. })));
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
            writer.start_file(*name, SimpleFileOptions::default().compression_method(*method)).unwrap();
            writer.write_all(contents).unwrap();
        }

        writer.finish().unwrap();
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
}
