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
use filetime::FileTime;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use zip::extra_fields::ExtraField;
use zip::read::ZipFile;
use zip::write::FullFileOptions;
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
    /// Modification time as Unix seconds, resolved as described on `zip_entry_mtime`.
    pub modified: Option<String>,
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
    if options.preserve_metadata {
        output.close();
        patch_zip_metadata_attributes(output.temp_path(), manifest).map_err(|source| ZipBackendError::Io { path: output.temp_path().to_path_buf(), source })?;
    }
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
    if options.preserve_metadata {
        output.close();
        patch_zip_metadata_attributes(output.temp_path(), manifest).map_err(|source| ZipBackendError::Io { path: output.temp_path().to_path_buf(), source })?;
    }
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
            modified: zip_entry_mtime(&file).map(|mtime| mtime.unix_seconds().to_string()),
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

    if to_test.len() >= 4 && crate::parallelism::available_parallelism_at_least_two().is_some() && archive_path.is_file() {
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
    let mut deferred_directories: Vec<(PathBuf, Option<u32>, Option<FileTime>)> = Vec::new();
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
        let modified_time = zip_entry_mtime(&file);
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

fn zip_options<'a>(entry: &ManifestEntry, create_options: &'a ZipCreateOptions) -> FullFileOptions<'a> {
    let compression_method = match create_options.compression {
        ZipCompression::Store => CompressionMethod::Stored,
        ZipCompression::Deflate => CompressionMethod::Deflated,
    };
    let mut options = FullFileOptions::default()
        .compression_method(compression_method)
        .compression_level(zip_compression_level(create_options))
        .large_file(needs_zip64(entry.size));

    if create_options.preserve_metadata
        && let Some(mode) = entry.permissions.unix_mode
    {
        options = options.unix_permissions(mode);
    }
    // Without preserved metadata, or when the source time could not be read,
    // the entry is stamped with the creation time. It is always encoded here so
    // `zip` never falls back to its own default, which writes UTC into the
    // local-time DOS field.
    let modified = create_options.preserve_metadata.then_some(entry.modified).flatten().unwrap_or_else(std::time::SystemTime::now);
    options = with_zip_mtime(options, modified);

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

const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP_CENTRAL_DIRECTORY_HEADER_SIZE: u64 = 46;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIZE: u64 = 22;
const ZIP_MAX_COMMENT_SIZE: u64 = u16::MAX as u64;

#[derive(Clone, Copy)]
struct ZipMetadataAttributes {
    special_mode: u32,
    readonly: bool,
}

/// The zip crate's public permissions API intentionally keeps only `0o777`.
/// Restore Unix special bits and the Windows/DOS read-only attribute in the
/// central directory after it has written the archive.
fn patch_zip_metadata_attributes(path: &Path, manifest: &ArchiveManifest) -> io::Result<()> {
    let metadata_attributes: HashMap<&str, ZipMetadataAttributes> = manifest
        .entries
        .iter()
        .filter_map(|entry| {
            let special_mode = entry.permissions.unix_mode.map_or(0, |mode| mode & 0o7000);
            let readonly = entry.file_type == ManifestFileType::File && entry.permissions.unix_mode.is_none() && entry.permissions.readonly;
            (special_mode != 0 || readonly).then_some((entry.archive_path.trim_end_matches('/'), ZipMetadataAttributes { special_mode, readonly }))
        })
        .collect();
    if metadata_attributes.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let archive_length = file.metadata()?.len();
    let tail_length = archive_length.min(ZIP_END_OF_CENTRAL_DIRECTORY_SIZE + ZIP_MAX_COMMENT_SIZE);
    let tail_start = archive_length - tail_length;
    file.seek(io::SeekFrom::Start(tail_start))?;
    let mut tail = vec![0_u8; usize::try_from(tail_length).map_err(|_| invalid_zip_metadata("ZIP footer is too large"))?];
    file.read_exact(&mut tail)?;

    let eocd_offset = tail
        .windows(4)
        .rposition(|window| u32::from_le_bytes(window.try_into().expect("ZIP signature window has four bytes")) == ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
        .ok_or_else(|| invalid_zip_metadata("ZIP end-of-central-directory record is missing"))?;
    let eocd_position = tail_start + u64::try_from(eocd_offset).map_err(|_| invalid_zip_metadata("ZIP footer offset does not fit"))?;
    let eocd = &tail[eocd_offset..];
    if eocd.len() < usize::try_from(ZIP_END_OF_CENTRAL_DIRECTORY_SIZE).unwrap() {
        return Err(invalid_zip_metadata("ZIP end-of-central-directory record is truncated"));
    }

    let entries = u64::from(u16::from_le_bytes([eocd[10], eocd[11]]));
    let central_size = u64::from(u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]));
    let central_offset = u64::from(u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]));
    let (entries, central_size, central_offset) =
        if entries == u64::from(u16::MAX) || central_size == u64::from(u32::MAX) || central_offset == u64::from(u32::MAX) {
            let locator_position = eocd_position.checked_sub(20).ok_or_else(|| invalid_zip_metadata("ZIP64 locator is missing"))?;
            file.seek(io::SeekFrom::Start(locator_position))?;
            let mut locator = [0_u8; 20];
            file.read_exact(&mut locator)?;
            if u32::from_le_bytes(locator[0..4].try_into().unwrap()) != ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE {
                return Err(invalid_zip_metadata("ZIP64 end-of-central-directory locator is missing"));
            }
            let zip64_position = u64::from_le_bytes(locator[8..16].try_into().unwrap());
            file.seek(io::SeekFrom::Start(zip64_position))?;
            let mut zip64 = [0_u8; 56];
            file.read_exact(&mut zip64)?;
            if u32::from_le_bytes(zip64[0..4].try_into().unwrap()) != ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
                return Err(invalid_zip_metadata("ZIP64 end-of-central-directory record is missing"));
            }
            (
                u64::from_le_bytes(zip64[32..40].try_into().unwrap()),
                u64::from_le_bytes(zip64[40..48].try_into().unwrap()),
                u64::from_le_bytes(zip64[48..56].try_into().unwrap()),
            )
        } else {
            (entries, central_size, central_offset)
        };

    let central_end = central_offset.checked_add(central_size).ok_or_else(|| invalid_zip_metadata("ZIP central directory range overflows"))?;
    if central_end > archive_length {
        return Err(invalid_zip_metadata("ZIP central directory extends past the archive"));
    }

    let mut position = central_offset;
    for _ in 0..entries {
        if position.checked_add(ZIP_CENTRAL_DIRECTORY_HEADER_SIZE).is_none_or(|end| end > central_end) {
            return Err(invalid_zip_metadata("ZIP central directory entry is truncated"));
        }

        file.seek(io::SeekFrom::Start(position))?;
        let mut header = [0_u8; 46];
        file.read_exact(&mut header)?;
        if u32::from_le_bytes(header[0..4].try_into().unwrap()) != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Err(invalid_zip_metadata("ZIP central directory signature is invalid"));
        }

        let name_length = u64::from(u16::from_le_bytes([header[28], header[29]]));
        let extra_length = u64::from(u16::from_le_bytes([header[30], header[31]]));
        let comment_length = u64::from(u16::from_le_bytes([header[32], header[33]]));
        let record_length = ZIP_CENTRAL_DIRECTORY_HEADER_SIZE
            .checked_add(name_length)
            .and_then(|length| length.checked_add(extra_length))
            .and_then(|length| length.checked_add(comment_length))
            .ok_or_else(|| invalid_zip_metadata("ZIP central directory entry length overflows"))?;
        let record_end = position.checked_add(record_length).ok_or_else(|| invalid_zip_metadata("ZIP central directory entry range overflows"))?;
        if record_end > central_end {
            return Err(invalid_zip_metadata("ZIP central directory entry extends past the directory"));
        }

        let mut name = vec![0_u8; usize::try_from(name_length).map_err(|_| invalid_zip_metadata("ZIP entry name is too large"))?];
        file.read_exact(&mut name)?;
        let name = String::from_utf8_lossy(&name);
        if let Some(metadata) = metadata_attributes.get(name.trim_end_matches('/')) {
            let external_attributes = u32::from_le_bytes(header[38..42].try_into().unwrap());
            let patched_attributes =
                if metadata.readonly { (external_attributes & 0xffff) | 0x01 } else { external_attributes | (metadata.special_mode << 16) };
            if patched_attributes != external_attributes {
                file.seek(io::SeekFrom::Start(position + 38))?;
                file.write_all(&patched_attributes.to_le_bytes())?;
            }
        }

        position = record_end;
    }

    Ok(())
}

fn invalid_zip_metadata(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
    modified_time: Option<FileTime>,
    deferred_directories: &'a mut Vec<(PathBuf, Option<u32>, Option<FileTime>)>,
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

/// Header ID of the Info-ZIP extended timestamp extra field.
const EXTENDED_TIMESTAMP_FIELD_ID: u16 = 0x5455;
/// Extended timestamp flag bit marking the modification time as present.
const EXTENDED_TIMESTAMP_MODIFIED: u8 = 0b0000_0001;
/// Seconds from the NTFS epoch (1601-01-01) to the Unix epoch.
const NTFS_TO_UNIX_EPOCH_SECONDS: i64 = 11_644_473_600;
/// NTFS file times count 100 ns ticks.
const NTFS_TICKS_PER_SECOND: u64 = 10_000_000;

/// Resolves an entry's modification time. The NTFS and Info-ZIP extended
/// timestamp extra fields hold UTC and win when present; the DOS timestamp is
/// the creator's local wall-clock time, so it is read in the local zone.
/// Listing and extraction both use this so they cannot disagree.
fn zip_entry_mtime<R: Read>(file: &ZipFile<'_, R>) -> Option<FileTime> {
    let mut ntfs = None;
    let mut extended = None;
    for field in file.extra_data_fields() {
        match field {
            ExtraField::Ntfs(ntfs_field) if ntfs_field.mtime() != 0 => ntfs = Some(ntfs_field.mtime()),
            // `zip` exposes the field as unsigned, but Info-ZIP defines it as a
            // signed 32-bit Unix time, so pre-1970 values are negative.
            ExtraField::ExtendedTimestamp(timestamp) => extended = extended.or(timestamp.mod_time().map(|raw| i32::from_le_bytes(raw.to_le_bytes()))),
            ExtraField::Ntfs(_) => {}
        }
    }
    // NTFS keeps sub-second precision, so it is preferred over the extended timestamp.
    ntfs.and_then(ntfs_file_time)
        .or_else(|| extended.map(|seconds| FileTime::from_unix_time(i64::from(seconds), 0)))
        .or_else(|| file.last_modified().and_then(dos_local_file_time))
}

fn ntfs_file_time(ticks: u64) -> Option<FileTime> {
    let seconds = i64::try_from(ticks / NTFS_TICKS_PER_SECOND).ok()? - NTFS_TO_UNIX_EPOCH_SECONDS;
    let nanoseconds = u32::try_from(ticks % NTFS_TICKS_PER_SECOND * 100).ok()?;
    Some(FileTime::from_unix_time(seconds, nanoseconds))
}

/// Reads a DOS timestamp as local wall-clock time, using the zone offset in
/// effect on that date so daylight saving is honoured.
fn dos_local_file_time(dt: zip::DateTime) -> Option<FileTime> {
    dos_file_time_in(dt, &chrono::Local)
}

/// Reads a DOS timestamp as wall-clock time in `zone`. Split from
/// [`dos_local_file_time`] so tests can pin the zone instead of depending on the host's.
fn dos_file_time_in<Tz: chrono::TimeZone>(dt: zip::DateTime, zone: &Tz) -> Option<FileTime> {
    use chrono::Offset;

    let month = if (1..=12).contains(&dt.month()) { dt.month() } else { 1 };
    let naive = chrono::NaiveDate::from_ymd_opt(i32::from(dt.year()), u32::from(month), u32::from(dt.day().max(1)))?.and_hms_opt(
        u32::from(dt.hour()),
        u32::from(dt.minute()),
        u32::from(dt.second()),
    )?;
    let seconds = match zone.from_local_datetime(&naive) {
        chrono::LocalResult::Single(local) | chrono::LocalResult::Ambiguous(local, _) => local.timestamp(),
        // A wall-clock time skipped by a daylight-saving jump: apply the offset
        // in effect at that instant rather than dropping the timestamp.
        chrono::LocalResult::None => naive.and_utc().timestamp() - i64::from(zone.offset_from_utc_datetime(&naive).fix().local_minus_utc()),
    };
    Some(FileTime::from_unix_time(seconds, 0))
}

/// Stamps `modified` as the DOS local wall-clock time other ZIP tools expect,
/// plus an extended timestamp extra field carrying the exact UTC seconds.
/// The field is a signed 32-bit Unix time, so it is omitted outside
/// 1901-12-13..=2038-01-19 rather than written as a value readers would
/// interpret as a different date; the DOS field still covers 1980..=2107.
fn with_zip_mtime(mut options: FullFileOptions<'_>, modified: std::time::SystemTime) -> FullFileOptions<'_> {
    if let Some(dt) = dos_date_time_in(modified, &chrono::Local) {
        options = options.last_modified_time(dt);
    }
    // `FileTime` floors pre-epoch times to whole seconds, matching Unix time.
    if let Ok(seconds) = i32::try_from(FileTime::from_system_time(modified).unix_seconds()) {
        let mut field = [0_u8; 5];
        field[0] = EXTENDED_TIMESTAMP_MODIFIED;
        field[1..].copy_from_slice(&seconds.to_le_bytes());
        // This is the only extra data on the options, so the one failure mode
        // (exceeding the 64 KiB extra-data limit) cannot occur.
        let _ = options.add_extra_data(EXTENDED_TIMESTAMP_FIELD_ID, field, false);
    }
    options
}

/// Renders `modified` as a DOS timestamp in `zone`'s wall-clock time, or `None`
/// outside the 1980..=2107 range the DOS field can hold.
fn dos_date_time_in<Tz: chrono::TimeZone>(modified: std::time::SystemTime, zone: &Tz) -> Option<zip::DateTime> {
    use chrono::{Datelike, Timelike};

    let local = chrono::DateTime::<chrono::Utc>::from(modified).with_timezone(zone);
    zip::DateTime::from_date_and_time(
        u16::try_from(local.year()).ok()?,
        u8::try_from(local.month()).ok()?,
        u8::try_from(local.day()).ok()?,
        u8::try_from(local.hour()).ok()?,
        u8::try_from(local.minute()).ok()?,
        u8::try_from(local.second()).ok()?,
    )
    .ok()
}

fn apply_zip_metadata(path: &Path, unix_mode: Option<u32>, modified_time: Option<FileTime>) -> Result<(), ZipBackendError> {
    crate::extract_materialize::apply_metadata(path, unix_mode, modified_time).map_err(|source| ZipBackendError::Io { path: path.to_path_buf(), source })
}

/// Uses `set_symlink_file_times` to avoid following the link. Errors are
/// reported so extraction cannot claim metadata was restored when it was not.
fn apply_symlink_mtime(path: &Path, modified_time: Option<FileTime>) -> Result<(), ZipBackendError> {
    if let Some(ft) = modified_time {
        filetime::set_symlink_file_times(path, ft, ft).map_err(|source| ZipBackendError::Io { path: path.to_path_buf(), source })?;
    }
    Ok(())
}

fn apply_deferred_zip_directory_metadata(directories: &[(PathBuf, Option<u32>, Option<FileTime>)]) -> Result<(), ZipBackendError> {
    crate::extract_loop::apply_deferred_directory_metadata(directories, |(path, unix_mode, modified_time): &(PathBuf, Option<u32>, Option<FileTime>)| {
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
    use chrono::{Datelike, Timelike};
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::Path;
    use zip::write::{FullFileOptions, SimpleFileOptions};
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

        // The extended timestamp field carries whole seconds, so the round trip is exact.
        let mtime_extracted = filetime::FileTime::from_last_modification_time(&metadata);
        assert_eq!(mtime_extracted.unix_seconds(), mtime.unix_seconds());

        let listed = list_zip(&archive).unwrap().entries.into_iter().find(|entry| entry.name == "project/script.sh").unwrap();
        assert_eq!(listed.modified, Some(mtime.unix_seconds().to_string()));

        // The DOS field holds local wall-clock time (2-second resolution) for other tools.
        let mut zip = zip::ZipArchive::new(File::open(&archive).unwrap()).unwrap();
        let dos = zip.by_name("project/script.sh").unwrap().last_modified().unwrap();
        let local =
            chrono::DateTime::<chrono::Local>::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(mtime.unix_seconds()).unwrap()));
        assert_eq!(
            (u32::from(dos.year()), u32::from(dos.month()), u32::from(dos.day()), u32::from(dos.hour()), u32::from(dos.minute()), u32::from(dos.second())),
            (u32::try_from(local.year()).unwrap(), local.month(), local.day(), local.hour(), local.minute(), local.second() & !1)
        );
    }

    /// DOS stamp 2023-11-14 22:13:20 wall-clock, used where no UTC extra field exists.
    fn dos_stamp() -> zip::DateTime {
        zip::DateTime::from_date_and_time(2023, 11, 14, 22, 13, 20).unwrap()
    }

    fn write_single_entry_zip(path: &Path, options: FullFileOptions<'_>) {
        let mut writer = ZipWriter::new(File::create(path).unwrap());
        writer.start_file("hello.txt", options.compression_method(CompressionMethod::Stored).last_modified_time(dos_stamp())).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();
    }

    /// Asserts the listing and the extracted file both report `expected`.
    fn assert_listed_and_extracted_mtime(temp: &TestDir, archive: &Path, expected: filetime::FileTime) {
        let listing = list_zip(archive).unwrap();
        assert_eq!(listing.entries[0].modified, Some(expected.unix_seconds().to_string()));

        extract_zip_fixture(archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        let extracted = filetime::FileTime::from_last_modification_time(&fs::metadata(temp.path("out/hello.txt")).unwrap());
        assert_eq!(extracted.unix_seconds(), expected.unix_seconds());
        // Windows and most Unix filesystems keep sub-second precision; compare to 100 ns.
        assert_eq!(extracted.nanoseconds() / 100, expected.nanoseconds() / 100);
    }

    #[test]
    fn dos_only_timestamp_is_read_as_local_wall_clock() {
        use chrono::TimeZone;

        let temp = TestDir::new("zip_mtime_dos_local");
        let archive = temp.path("archive.zip");
        write_single_entry_zip(&archive, FullFileOptions::default());

        let expected = chrono::Local.with_ymd_and_hms(2023, 11, 14, 22, 13, 20).single().unwrap().timestamp();
        assert_listed_and_extracted_mtime(&temp, &archive, filetime::FileTime::from_unix_time(expected, 0));
    }

    // The tests above go through the host zone, which proves nothing on a UTC
    // runner. These pin the zone so the local-time conversion is checked everywhere.

    /// US Eastern time with 2023's daylight-saving rules: EDT (UTC-4) from
    /// 2023-03-12T07:00Z until 2023-11-05T06:00Z, EST (UTC-5) otherwise.
    #[derive(Clone, Copy, Debug)]
    struct Eastern2023;

    impl Eastern2023 {
        fn edt() -> chrono::FixedOffset {
            chrono::FixedOffset::west_opt(4 * 3600).unwrap()
        }

        fn est() -> chrono::FixedOffset {
            chrono::FixedOffset::west_opt(5 * 3600).unwrap()
        }
    }

    impl chrono::TimeZone for Eastern2023 {
        type Offset = chrono::FixedOffset;

        fn from_offset(_offset: &chrono::FixedOffset) -> Self {
            Self
        }

        fn offset_from_local_date(&self, local: &chrono::NaiveDate) -> chrono::LocalResult<chrono::FixedOffset> {
            self.offset_from_local_datetime(&local.and_hms_opt(0, 0, 0).unwrap())
        }

        fn offset_from_local_datetime(&self, local: &chrono::NaiveDateTime) -> chrono::LocalResult<chrono::FixedOffset> {
            let fits = |offset: chrono::FixedOffset| self.offset_from_utc_datetime(&(*local - offset)) == offset;
            match (fits(Self::edt()), fits(Self::est())) {
                // Fall-back hour: the EDT reading is the earlier instant.
                (true, true) => chrono::LocalResult::Ambiguous(Self::edt(), Self::est()),
                (true, false) => chrono::LocalResult::Single(Self::edt()),
                (false, true) => chrono::LocalResult::Single(Self::est()),
                (false, false) => chrono::LocalResult::None,
            }
        }

        fn offset_from_utc_date(&self, utc: &chrono::NaiveDate) -> chrono::FixedOffset {
            self.offset_from_utc_datetime(&utc.and_hms_opt(0, 0, 0).unwrap())
        }

        fn offset_from_utc_datetime(&self, utc: &chrono::NaiveDateTime) -> chrono::FixedOffset {
            let start = chrono::NaiveDate::from_ymd_opt(2023, 3, 12).unwrap().and_hms_opt(7, 0, 0).unwrap();
            let end = chrono::NaiveDate::from_ymd_opt(2023, 11, 5).unwrap().and_hms_opt(6, 0, 0).unwrap();
            if (start..end).contains(utc) { Self::edt() } else { Self::est() }
        }
    }

    fn utc_seconds(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second).unwrap().timestamp()
    }

    fn dos(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> zip::DateTime {
        zip::DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap()
    }

    fn read_dos_in<Tz: chrono::TimeZone>(dt: zip::DateTime, zone: &Tz) -> i64 {
        super::dos_file_time_in(dt, zone).unwrap().unix_seconds()
    }

    fn dos_fields(dt: zip::DateTime) -> (u16, u8, u8, u8, u8, u8) {
        (dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second())
    }

    #[test]
    fn dos_timestamp_is_read_in_the_given_fixed_zone() {
        let tokyo = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
        let bogota = chrono::FixedOffset::west_opt(5 * 3600).unwrap();
        // 22:13:20 on the wall clock is 13:13:20Z in Tokyo and 03:13:20Z next day in Bogota.
        assert_eq!(read_dos_in(dos_stamp(), &tokyo), utc_seconds(2023, 11, 14, 13, 13, 20));
        assert_eq!(read_dos_in(dos_stamp(), &bogota), utc_seconds(2023, 11, 15, 3, 13, 20));
    }

    #[test]
    fn dos_timestamp_honours_daylight_saving_on_its_own_date() {
        // Summer uses EDT and winter EST, whatever the offset is today.
        assert_eq!(read_dos_in(dos(2023, 7, 1, 12, 0, 0), &Eastern2023), utc_seconds(2023, 7, 1, 16, 0, 0));
        assert_eq!(read_dos_in(dos(2023, 1, 15, 12, 0, 0), &Eastern2023), utc_seconds(2023, 1, 15, 17, 0, 0));
    }

    #[test]
    fn dos_timestamp_in_spring_forward_gap_is_kept_not_dropped() {
        // 02:30 never happened on 2023-03-12; the pre-jump EST offset maps it to 07:30Z (03:30 EDT).
        assert_eq!(read_dos_in(dos(2023, 3, 12, 2, 30, 0), &Eastern2023), utc_seconds(2023, 3, 12, 7, 30, 0));
    }

    #[test]
    fn dos_timestamp_in_fall_back_overlap_takes_the_earlier_instant() {
        // 01:30 happened twice on 2023-11-05; the EDT reading (05:30Z) comes first.
        assert_eq!(read_dos_in(dos(2023, 11, 5, 1, 30, 0), &Eastern2023), utc_seconds(2023, 11, 5, 5, 30, 0));
    }

    #[test]
    fn dos_timestamp_is_written_as_wall_clock_in_the_given_zone() {
        let tokyo = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
        let written = super::dos_date_time_in(unix_time(utc_seconds(2023, 11, 14, 22, 13, 20)), &tokyo).unwrap();
        assert_eq!(dos_fields(written), (2023, 11, 15, 7, 13, 20));

        // Daylight saving follows the instant being written; odd seconds floor to the 2-second grid.
        let summer = super::dos_date_time_in(unix_time(utc_seconds(2023, 7, 1, 16, 0, 1)), &Eastern2023).unwrap();
        assert_eq!(dos_fields(summer), (2023, 7, 1, 12, 0, 0));
        let winter = super::dos_date_time_in(unix_time(utc_seconds(2023, 1, 15, 17, 0, 0)), &Eastern2023).unwrap();
        assert_eq!(dos_fields(winter), (2023, 1, 15, 12, 0, 0));
    }

    #[test]
    fn dos_timestamp_round_trips_through_the_same_zone() {
        for seconds in [utc_seconds(2023, 1, 15, 17, 0, 0), utc_seconds(2023, 7, 1, 16, 0, 0), utc_seconds(2023, 11, 5, 5, 30, 0)] {
            let written = super::dos_date_time_in(unix_time(seconds), &Eastern2023).unwrap();
            assert_eq!(read_dos_in(written, &Eastern2023), seconds, "round trip of {seconds}");
        }
    }

    #[test]
    fn dos_timestamp_is_not_written_outside_its_range() {
        let utc = chrono::FixedOffset::east_opt(0).unwrap();
        assert!(super::dos_date_time_in(unix_time(utc_seconds(1979, 12, 31, 23, 59, 58)), &utc).is_none());
        assert!(super::dos_date_time_in(unix_time(utc_seconds(2108, 1, 1, 0, 0, 0)), &utc).is_none());
        assert!(super::dos_date_time_in(unix_time(utc_seconds(1980, 1, 1, 0, 0, 0)), &utc).is_some());
    }

    #[test]
    fn extended_timestamp_field_overrides_dos_time() {
        let temp = TestDir::new("zip_mtime_extended");
        let archive = temp.path("archive.zip");
        let mut options = FullFileOptions::default();
        let mut field = vec![super::EXTENDED_TIMESTAMP_MODIFIED];
        field.extend_from_slice(&1_600_000_000_u32.to_le_bytes());
        options.add_extra_data(super::EXTENDED_TIMESTAMP_FIELD_ID, field, false).unwrap();
        write_single_entry_zip(&archive, options);

        assert_listed_and_extracted_mtime(&temp, &archive, filetime::FileTime::from_unix_time(1_600_000_000, 0));
    }

    #[test]
    fn ntfs_field_overrides_dos_time_with_subsecond_precision() {
        let temp = TestDir::new("zip_mtime_ntfs");
        let archive = temp.path("archive.zip");
        // 2020-09-13T12:26:40.1234567Z as NTFS ticks.
        let mtime_ticks: u64 = (1_600_000_000 + 11_644_473_600) * 10_000_000 + 1_234_567;
        let mut field = Vec::new();
        field.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        field.extend_from_slice(&1_u16.to_le_bytes()); // attribute tag 1: file times
        field.extend_from_slice(&24_u16.to_le_bytes());
        for ticks in [mtime_ticks, mtime_ticks, mtime_ticks] {
            field.extend_from_slice(&ticks.to_le_bytes());
        }
        let mut options = FullFileOptions::default();
        options.add_extra_data(0x000a, field, false).unwrap();
        write_single_entry_zip(&archive, options);

        assert_listed_and_extracted_mtime(&temp, &archive, filetime::FileTime::from_unix_time(1_600_000_000, 123_456_700));
    }

    #[test]
    fn created_archive_carries_extended_timestamp_field() {
        let temp = TestDir::new("zip_mtime_created_field");
        temp.write_file("project/file.txt", b"data");
        filetime::set_file_mtime(temp.path("project/file.txt"), filetime::FileTime::from_unix_time(1_700_000_001, 0)).unwrap();
        let archive = temp.path("archive.zip");
        create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions { preserve_metadata: true, ..ZipCreateOptions::default() }).unwrap();

        let mut zip = zip::ZipArchive::new(File::open(&archive).unwrap()).unwrap();
        let entry = zip.by_name("project/file.txt").unwrap();
        let extended = entry
            .extra_data_fields()
            .find_map(|field| match field {
                zip::ExtraField::ExtendedTimestamp(timestamp) => timestamp.mod_time(),
                zip::ExtraField::Ntfs(_) => None,
            })
            .expect("extended timestamp field present");
        // Odd second survives exactly, unlike the 2-second DOS field.
        assert_eq!(extended, 1_700_000_001);
    }

    #[test]
    fn archive_without_preserved_metadata_lists_creation_time() {
        let temp = TestDir::new("zip_mtime_not_preserved");
        temp.write_file("project/file.txt", b"data");
        filetime::set_file_mtime(temp.path("project/file.txt"), filetime::FileTime::from_unix_time(1_000_000_000, 0)).unwrap();
        let archive = temp.path("archive.zip");
        let before = filetime::FileTime::now().unix_seconds();
        create_zip_fixture(temp.path("project"), &archive, &ZipCreateOptions { preserve_metadata: false, ..ZipCreateOptions::default() }).unwrap();
        let after = filetime::FileTime::now().unix_seconds();

        let listed = list_zip(&archive).unwrap().entries.into_iter().find(|entry| entry.name == "project/file.txt").unwrap();
        let seconds: i64 = listed.modified.unwrap().parse().unwrap();
        assert!((before..=after).contains(&seconds), "listed {seconds} outside creation window {before}..={after}");
    }

    fn unix_time(seconds: i64) -> std::time::SystemTime {
        let magnitude = std::time::Duration::from_secs(seconds.unsigned_abs());
        if seconds < 0 { std::time::UNIX_EPOCH - magnitude } else { std::time::UNIX_EPOCH + magnitude }
    }

    /// Returns the raw extended timestamp modification field of `name`, as a signed value.
    fn extended_mod_time(archive: &Path, name: &str) -> Option<i32> {
        let mut zip = zip::ZipArchive::new(File::open(archive).unwrap()).unwrap();
        let entry = zip.by_name(name).unwrap();
        entry.extra_data_fields().find_map(|field| match field {
            zip::ExtraField::ExtendedTimestamp(timestamp) => timestamp.mod_time().map(|raw| i32::from_le_bytes(raw.to_le_bytes())),
            zip::ExtraField::Ntfs(_) => None,
        })
    }

    fn listed_modified(archive: &Path, name: &str) -> Option<String> {
        list_zip(archive).unwrap().entries.into_iter().find(|entry| entry.name == name).unwrap().modified
    }

    #[test]
    fn extended_timestamp_field_is_read_as_signed() {
        let temp = TestDir::new("zip_mtime_extended_signed");
        let archive = temp.path("archive.zip");
        let mut options = FullFileOptions::default();
        let mut field = vec![super::EXTENDED_TIMESTAMP_MODIFIED];
        field.extend_from_slice(&(-86_400_i32).to_le_bytes());
        options.add_extra_data(super::EXTENDED_TIMESTAMP_FIELD_ID, field, false).unwrap();
        write_single_entry_zip(&archive, options);

        // Read unsigned, these bytes would be 2106-02-06.
        assert_listed_and_extracted_mtime(&temp, &archive, filetime::FileTime::from_unix_time(-86_400, 0));
    }

    #[test]
    fn pre_epoch_time_is_written_as_negative_extended_timestamp() {
        let temp = TestDir::new("zip_mtime_pre_epoch_write");
        let archive = temp.path("archive.zip");
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        // Fractional pre-epoch times floor, as Unix time does: -86_400.5s is -86_401.
        let modified = unix_time(-86_400) - std::time::Duration::from_millis(500);
        writer.start_file("hello.txt", super::with_zip_mtime(FullFileOptions::default(), modified)).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();

        assert_eq!(extended_mod_time(&archive, "hello.txt"), Some(-86_401));
        assert_eq!(listed_modified(&archive, "hello.txt"), Some("-86401".to_owned()));
    }

    #[test]
    fn time_past_signed_32_bit_range_omits_extended_field_and_keeps_dos_time() {
        let temp = TestDir::new("zip_mtime_post_2038");
        let archive = temp.path("archive.zip");
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        // 2038-01-19T03:14:08Z: one past i32::MAX, an even second so the DOS field holds it exactly.
        let seconds = i64::from(i32::MAX) + 1;
        writer.start_file("hello.txt", super::with_zip_mtime(FullFileOptions::default(), unix_time(seconds))).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();

        assert_eq!(extended_mod_time(&archive, "hello.txt"), None);
        assert_eq!(listed_modified(&archive, "hello.txt"), Some(seconds.to_string()));
    }

    #[test]
    fn preserved_metadata_without_source_time_is_stamped_with_creation_time() {
        let temp = TestDir::new("zip_mtime_missing_source_time");
        let archive = temp.path("archive.zip");
        let entry = crate::manifest::ManifestEntry {
            archive_path: "hello.txt".to_owned(),
            source_path: temp.path("hello.txt"),
            file_type: crate::manifest::ManifestFileType::File,
            size: 5,
            modified: None,
            permissions: crate::manifest::PermissionSnapshot { readonly: false, unix_mode: None },
            symlink_target: None,
        };
        let create_options = ZipCreateOptions { preserve_metadata: true, ..ZipCreateOptions::default() };
        let before = filetime::FileTime::now().unix_seconds();
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        writer.start_file("hello.txt", super::zip_options(&entry, &create_options)).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.finish().unwrap();
        let after = filetime::FileTime::now().unix_seconds();

        // Only our own stamping writes the extended field; `zip`'s fallback would not.
        let stamped = i64::from(extended_mod_time(&archive, "hello.txt").expect("extended timestamp field present"));
        assert!((before..=after).contains(&stamped), "stamped {stamped} outside creation window {before}..={after}");
        assert_eq!(listed_modified(&archive, "hello.txt"), Some(stamped.to_string()));
    }

    #[test]
    fn ntfs_field_takes_precedence_over_extended_timestamp() {
        let temp = TestDir::new("zip_mtime_ntfs_over_extended");
        let archive = temp.path("archive.zip");
        let mut options = FullFileOptions::default();
        let mut extended = vec![super::EXTENDED_TIMESTAMP_MODIFIED];
        extended.extend_from_slice(&1_500_000_000_u32.to_le_bytes());
        options.add_extra_data(super::EXTENDED_TIMESTAMP_FIELD_ID, extended, false).unwrap();
        let mtime_ticks: u64 = (1_600_000_000 + 11_644_473_600) * 10_000_000 + 5_000_000;
        let mut ntfs = Vec::new();
        ntfs.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        ntfs.extend_from_slice(&1_u16.to_le_bytes()); // attribute tag 1: file times
        ntfs.extend_from_slice(&24_u16.to_le_bytes());
        for ticks in [mtime_ticks, mtime_ticks, mtime_ticks] {
            ntfs.extend_from_slice(&ticks.to_le_bytes());
        }
        options.add_extra_data(0x000a, ntfs, false).unwrap();
        write_single_entry_zip(&archive, options);

        assert_listed_and_extracted_mtime(&temp, &archive, filetime::FileTime::from_unix_time(1_600_000_000, 500_000_000));
    }

    #[test]
    fn extracted_directories_keep_their_own_mtime() {
        let temp = TestDir::new("zip_mtime_directory");
        let archive = temp.path("archive.zip");
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        writer.add_directory("dir/", super::with_zip_mtime(FullFileOptions::default(), unix_time(1_500_000_001))).unwrap();
        writer.start_file("dir/file.txt", super::with_zip_mtime(FullFileOptions::default(), unix_time(1_600_000_001))).unwrap();
        writer.write_all(b"data").unwrap();
        writer.finish().unwrap();

        assert_eq!(listed_modified(&archive, "dir/"), Some("1500000001".to_owned()));
        extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        // The directory time is applied after its child is written, so the write does not clobber it.
        let directory = filetime::FileTime::from_last_modification_time(&fs::metadata(temp.path("out/dir")).unwrap());
        assert_eq!(directory.unix_seconds(), 1_500_000_001);
        let file = filetime::FileTime::from_last_modification_time(&fs::metadata(temp.path("out/dir/file.txt")).unwrap());
        assert_eq!(file.unix_seconds(), 1_600_000_001);
    }

    #[cfg(unix)]
    #[test]
    fn extracted_symlinks_keep_their_own_mtime() {
        let temp = TestDir::new("zip_mtime_symlink");
        let archive = temp.path("archive.zip");
        let mut writer = ZipWriter::new(File::create(&archive).unwrap());
        writer.start_file("target.txt", super::with_zip_mtime(FullFileOptions::default(), unix_time(1_500_000_001))).unwrap();
        writer.write_all(b"target").unwrap();
        writer.add_symlink("link.txt", "target.txt", super::with_zip_mtime(FullFileOptions::default(), unix_time(1_600_000_001))).unwrap();
        writer.finish().unwrap();

        assert_eq!(listed_modified(&archive, "link.txt"), Some("1600000001".to_owned()));
        extract_zip_fixture(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();
        let link = filetime::FileTime::from_last_modification_time(&fs::symlink_metadata(temp.path("out/link.txt")).unwrap());
        assert_eq!(link.unix_seconds(), 1_600_000_001);
        // Stamping the link must not follow it onto the target.
        let target = filetime::FileTime::from_last_modification_time(&fs::metadata(temp.path("out/target.txt")).unwrap());
        assert_eq!(target.unix_seconds(), 1_500_000_001);
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
