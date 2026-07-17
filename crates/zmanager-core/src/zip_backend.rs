use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{
    ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive,
};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zip::write::{FileOptions, SimpleFileOptions};
use zip::{AesMode, CompressionMethod, ZipArchive, ZipReadOptions, ZipWriter};

const ZIP_SPLIT_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_EOCD_MIN_SIZE: usize = 22;
const ZIP_EOCD_MAX_COMMENT_SIZE: u64 = 65_535;
const MIN_ZIP_VOLUME_SIZE_BYTES: u64 = 65_536;
const ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH: usize = 2;
const ZIP_MODE_MASK: u32 = 0o7777;

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
        Self {
            compression: ZipCompression::default(),
            level: None,
            preserve_metadata: true,
            replace_existing: false,
            password: None,
            volume_size: None,
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
            Self::VolumeSizeTooSmall { size, minimum } => write!(
                f,
                "ZIP volume size {size} bytes is smaller than the minimum {minimum} bytes"
            ),
            Self::UnsupportedSplitZip { reason } => {
                write!(
                    f,
                    "split ZIP creation is not supported for this archive: {reason}"
                )
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
    validate_zip_volume_size(options.volume_size)?;

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
    let mut report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    writer.finish()?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_zip_temp_archive(
            output.temp_path(),
            destination,
            volume_size,
            options.replace_existing,
        )?;
    } else {
        output
            .commit_with_file_replace(options.replace_existing)
            .map_err(|source| ZipBackendError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
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
    let mut report = write_manifest_to_zip(&mut writer, manifest, options, Some(context))?;
    writer.finish()?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_zip_temp_archive(
            output.temp_path(),
            destination,
            volume_size,
            options.replace_existing,
        )?;
    } else {
        output
            .commit_with_file_replace(options.replace_existing)
            .map_err(|source| ZipBackendError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
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
    validate_zip_stream_options(options)?;

    let mut writer = ZipWriter::new_stream(output);
    let report = write_manifest_to_zip(&mut writer, manifest, options, None)?;
    let output = writer.finish()?.into_inner();

    Ok((output, report))
}

fn validate_zip_stream_options(options: &ZipCreateOptions) -> Result<(), ZipBackendError> {
    if options.volume_size.is_some() {
        return Err(ZipBackendError::UnsupportedSplitZip {
            reason: "streaming ZIP output cannot be split".to_owned(),
        });
    }
    Ok(())
}

fn validate_zip_volume_size(volume_size: Option<u64>) -> Result<(), ZipBackendError> {
    match volume_size {
        Some(size) if size < MIN_ZIP_VOLUME_SIZE_BYTES => {
            Err(ZipBackendError::VolumeSizeTooSmall {
                size,
                minimum: MIN_ZIP_VOLUME_SIZE_BYTES,
            })
        }
        Some(size) if size > u64::from(u32::MAX) => Err(ZipBackendError::UnsupportedSplitZip {
            reason: "volume sizes above 4294967295 bytes need ZIP64 multi-disk metadata".to_owned(),
        }),
        _ => Ok(()),
    }
}

fn split_zip_temp_archive(
    archive_path: &Path,
    destination: &Path,
    volume_size: u64,
    replace_existing: bool,
) -> Result<usize, ZipBackendError> {
    let archive_size = fs::metadata(archive_path)
        .map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?
        .len();
    let eocd = read_zip_eocd(archive_path, archive_size)?;

    if archive_size <= volume_size {
        let volume_paths = vec![destination.to_path_buf()];
        let existing_volume_paths = existing_split_zip_volume_paths(destination)?;
        ensure_split_destinations_available(
            destination,
            &volume_paths,
            &existing_volume_paths,
            replace_existing,
        )?;
        let mut archive = File::open(archive_path).map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
        let mut writer = ZipSplitVolumeWriter::new(&volume_paths, archive_size.max(1))?;
        writer.copy_from(&mut archive, archive_size, destination)?;
        writer.finish(destination, &existing_volume_paths, replace_existing)?;
        return Ok(1);
    }

    let logical_size = archive_size
        .checked_add(u64::try_from(ZIP_SPLIT_SIGNATURE.len()).unwrap_or(4))
        .ok_or_else(|| unsupported_split_zip("archive is too large to split"))?;
    let volume_count = split_volume_count(logical_size, volume_size)
        .ok_or_else(|| unsupported_split_zip("too many ZIP volumes"))?;
    let layout = ZipSplitLayout::new(logical_size, volume_size, &eocd)?;
    let volume_paths = split_zip_volume_paths(destination, volume_count)?;
    let existing_volume_paths = existing_split_zip_volume_paths(destination)?;
    ensure_split_destinations_available(
        destination,
        &volume_paths,
        &existing_volume_paths,
        replace_existing,
    )?;

    let mut central_directory = read_zip_central_directory(archive_path, &eocd)?;
    let entries_on_last_disk = patch_split_zip_central_directory(
        &mut central_directory,
        volume_size,
        layout.central_directory_logical_offset,
        layout.last_disk,
    )?;
    let mut eocd_bytes = eocd.bytes.clone();
    patch_split_zip_eocd(
        &mut eocd_bytes,
        &layout,
        eocd.total_entries,
        entries_on_last_disk,
    )?;

    let mut archive =
        BufReader::new(
            File::open(archive_path).map_err(|source| ZipBackendError::Io {
                path: archive_path.to_path_buf(),
                source,
            })?,
        );
    let mut writer = ZipSplitVolumeWriter::new(&volume_paths, volume_size)?;
    writer.write_all(&ZIP_SPLIT_SIGNATURE)?;
    writer.copy_from(&mut archive, eocd.central_directory_offset, archive_path)?;
    writer.write_all(&central_directory)?;
    writer.write_all(&eocd_bytes)?;
    writer.finish(destination, &existing_volume_paths, replace_existing)?;

    Ok(volume_count)
}

#[derive(Debug)]
struct ZipEndOfCentralDirectory {
    central_directory_offset: u64,
    central_directory_size: u64,
    total_entries: u16,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ZipSplitLayout {
    central_directory_logical_offset: u64,
    central_directory_disk: u16,
    central_directory_offset_on_disk: u32,
    last_disk: u16,
}

impl ZipSplitLayout {
    fn new(
        logical_size: u64,
        volume_size: u64,
        eocd: &ZipEndOfCentralDirectory,
    ) -> Result<Self, ZipBackendError> {
        let central_directory_logical_offset = eocd
            .central_directory_offset
            .checked_add(u64::try_from(ZIP_SPLIT_SIGNATURE.len()).unwrap_or(4))
            .ok_or_else(|| unsupported_split_zip("central directory offset overflow"))?;
        let (central_directory_disk, central_directory_offset_on_disk) =
            split_zip_location(central_directory_logical_offset, volume_size)?;
        let (last_disk, _) = split_zip_location(logical_size.saturating_sub(1), volume_size)?;
        Ok(Self {
            central_directory_logical_offset,
            central_directory_disk,
            central_directory_offset_on_disk,
            last_disk,
        })
    }
}

fn read_zip_eocd(
    archive_path: &Path,
    archive_size: u64,
) -> Result<ZipEndOfCentralDirectory, ZipBackendError> {
    if archive_size < ZIP_EOCD_MIN_SIZE as u64 {
        return Err(unsupported_split_zip("archive is missing ZIP end record"));
    }

    let tail_size = archive_size.min(ZIP_EOCD_MIN_SIZE as u64 + ZIP_EOCD_MAX_COMMENT_SIZE);
    let mut file = File::open(archive_path).map_err(|source| ZipBackendError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    file.seek(SeekFrom::Start(archive_size - tail_size))
        .map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
    let mut tail = vec![
        0;
        usize::try_from(tail_size).map_err(|_| {
            unsupported_split_zip("ZIP end record tail is too large for this platform")
        })?
    ];
    file.read_exact(&mut tail)
        .map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;

    for offset in (0..=tail.len() - ZIP_EOCD_MIN_SIZE).rev() {
        if read_u32(&tail[offset..offset + 4]) != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            continue;
        }
        let comment_len = usize::from(read_u16(&tail[offset + 20..offset + 22]));
        let eocd_len = ZIP_EOCD_MIN_SIZE + comment_len;
        if offset + eocd_len != tail.len() {
            continue;
        }
        let eocd_offset = archive_size - tail_size + u64::try_from(offset).unwrap_or(0);
        if eocd_offset >= 20 {
            let locator_start = eocd_offset - 20;
            if locator_start >= archive_size - tail_size {
                let relative = usize::try_from(locator_start - (archive_size - tail_size))
                    .map_err(|_| unsupported_split_zip("ZIP64 locator offset overflow"))?;
                if relative + 4 <= tail.len()
                    && read_u32(&tail[relative..relative + 4])
                        == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE
                {
                    return Err(unsupported_split_zip(
                        "ZIP64 split metadata is not implemented",
                    ));
                }
            }
        }

        let disk_number = read_u16(&tail[offset + 4..offset + 6]);
        let central_directory_disk = read_u16(&tail[offset + 6..offset + 8]);
        if disk_number != 0 || central_directory_disk != 0 {
            return Err(unsupported_split_zip("archive is already a multi-disk ZIP"));
        }
        let entries_on_disk = read_u16(&tail[offset + 8..offset + 10]);
        let total_entries = read_u16(&tail[offset + 10..offset + 12]);
        let central_directory_size = read_u32(&tail[offset + 12..offset + 16]);
        let central_directory_offset = read_u32(&tail[offset + 16..offset + 20]);
        if entries_on_disk == u16::MAX
            || total_entries == u16::MAX
            || central_directory_size == u32::MAX
            || central_directory_offset == u32::MAX
        {
            return Err(unsupported_split_zip(
                "ZIP64 central directory markers are not supported for split output",
            ));
        }
        if entries_on_disk != total_entries {
            return Err(unsupported_split_zip(
                "central directory entry counts are inconsistent",
            ));
        }
        let central_directory_offset = u64::from(central_directory_offset);
        let central_directory_size = u64::from(central_directory_size);
        let central_directory_end = central_directory_offset
            .checked_add(central_directory_size)
            .ok_or_else(|| unsupported_split_zip("central directory offset overflow"))?;
        if central_directory_end != eocd_offset {
            return Err(unsupported_split_zip(
                "unexpected data between central directory and ZIP end record",
            ));
        }

        return Ok(ZipEndOfCentralDirectory {
            central_directory_offset,
            central_directory_size,
            total_entries,
            bytes: tail[offset..offset + eocd_len].to_vec(),
        });
    }

    Err(unsupported_split_zip("archive is missing ZIP end record"))
}

fn read_zip_central_directory(
    archive_path: &Path,
    eocd: &ZipEndOfCentralDirectory,
) -> Result<Vec<u8>, ZipBackendError> {
    let mut file = File::open(archive_path).map_err(|source| ZipBackendError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    file.seek(SeekFrom::Start(eocd.central_directory_offset))
        .map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
    let mut central_directory = vec![
        0;
        usize::try_from(eocd.central_directory_size).map_err(|_| {
            unsupported_split_zip("central directory is too large for this platform")
        })?
    ];
    file.read_exact(&mut central_directory)
        .map_err(|source| ZipBackendError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
    Ok(central_directory)
}

fn patch_split_zip_central_directory(
    central_directory: &mut [u8],
    volume_size: u64,
    central_directory_logical_offset: u64,
    eocd_disk: u16,
) -> Result<u16, ZipBackendError> {
    let mut offset = 0usize;
    let mut entries_on_eocd_disk = 0u16;
    while offset < central_directory.len() {
        if offset + 46 > central_directory.len()
            || read_u32(&central_directory[offset..offset + 4]) != ZIP_CENTRAL_DIRECTORY_SIGNATURE
        {
            return Err(unsupported_split_zip("central directory is malformed"));
        }
        let file_name_len = usize::from(read_u16(&central_directory[offset + 28..offset + 30]));
        let extra_len = usize::from(read_u16(&central_directory[offset + 30..offset + 32]));
        let comment_len = usize::from(read_u16(&central_directory[offset + 32..offset + 34]));
        let disk_start = read_u16(&central_directory[offset + 34..offset + 36]);
        let local_header_offset = read_u32(&central_directory[offset + 42..offset + 46]);
        if disk_start != 0 {
            return Err(unsupported_split_zip("archive is already a multi-disk ZIP"));
        }
        if local_header_offset == u32::MAX {
            return Err(unsupported_split_zip(
                "ZIP64 local header offsets are not supported for split output",
            ));
        }
        let logical_header_offset = u64::from(local_header_offset)
            .checked_add(u64::try_from(ZIP_SPLIT_SIGNATURE.len()).unwrap_or(4))
            .ok_or_else(|| unsupported_split_zip("local header offset overflow"))?;
        let (disk, relative_offset) = split_zip_location(logical_header_offset, volume_size)?;
        central_directory[offset + 34..offset + 36].copy_from_slice(&disk.to_le_bytes());
        central_directory[offset + 42..offset + 46].copy_from_slice(&relative_offset.to_le_bytes());
        let central_directory_entry_offset = central_directory_logical_offset
            .checked_add(u64::try_from(offset).unwrap_or(0))
            .ok_or_else(|| unsupported_split_zip("central directory entry offset overflow"))?;
        let (central_directory_entry_disk, _) =
            split_zip_location(central_directory_entry_offset, volume_size)?;
        if central_directory_entry_disk == eocd_disk {
            entries_on_eocd_disk = entries_on_eocd_disk.saturating_add(1);
        }
        let next_offset = offset
            .checked_add(46)
            .and_then(|value| value.checked_add(file_name_len))
            .and_then(|value| value.checked_add(extra_len))
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| unsupported_split_zip("central directory entry overflow"))?;
        if next_offset > central_directory.len() {
            return Err(unsupported_split_zip(
                "central directory entry is truncated",
            ));
        }
        offset = next_offset;
    }
    Ok(entries_on_eocd_disk)
}

fn patch_split_zip_eocd(
    eocd: &mut [u8],
    layout: &ZipSplitLayout,
    total_entries: u16,
    entries_on_last_disk: u16,
) -> Result<(), ZipBackendError> {
    if eocd.len() < ZIP_EOCD_MIN_SIZE
        || read_u32(&eocd[0..4]) != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE
    {
        return Err(unsupported_split_zip("ZIP end record is malformed"));
    }
    eocd[4..6].copy_from_slice(&layout.last_disk.to_le_bytes());
    eocd[6..8].copy_from_slice(&layout.central_directory_disk.to_le_bytes());
    eocd[8..10].copy_from_slice(&entries_on_last_disk.to_le_bytes());
    eocd[10..12].copy_from_slice(&total_entries.to_le_bytes());
    eocd[16..20].copy_from_slice(&layout.central_directory_offset_on_disk.to_le_bytes());
    Ok(())
}

fn split_zip_location(
    logical_offset: u64,
    volume_size: u64,
) -> Result<(u16, u32), ZipBackendError> {
    let disk = logical_offset / volume_size;
    if disk >= u64::from(u16::MAX) {
        return Err(unsupported_split_zip("too many ZIP volumes"));
    }
    let offset = logical_offset % volume_size;
    let disk =
        u16::try_from(disk).map_err(|_| unsupported_split_zip("ZIP disk number overflow"))?;
    let offset = u32::try_from(offset)
        .map_err(|_| unsupported_split_zip("ZIP disk-relative offset overflow"))?;
    Ok((disk, offset))
}

fn split_volume_count(archive_size: u64, volume_size: u64) -> Option<usize> {
    let count = archive_size.max(1).div_ceil(volume_size);
    usize::try_from(count).ok()
}

fn split_zip_volume_paths(
    destination: &Path,
    count: usize,
) -> Result<Vec<PathBuf>, ZipBackendError> {
    if count <= 1 {
        return Ok(vec![destination.to_path_buf()]);
    }
    let base = split_zip_base_path(destination)?;
    let mut paths = Vec::with_capacity(count);
    for index in 1..count {
        let extension = format!("z{index:0ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH$}");
        paths.push(base.with_extension(extension));
    }
    paths.push(destination.to_path_buf());
    Ok(paths)
}

fn split_zip_base_path(destination: &Path) -> Result<PathBuf, ZipBackendError> {
    if destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        return Ok(destination.with_extension(""));
    }
    Err(unsupported_split_zip(
        "split ZIP output path must use a .zip extension",
    ))
}

fn ensure_split_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), ZipBackendError> {
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

fn ensure_file_destination_available(
    path: &Path,
    replace_existing: bool,
) -> Result<(), ZipBackendError> {
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
        Err(source) => Err(ZipBackendError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_split_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), ZipBackendError> {
    if !replace_existing {
        return Ok(());
    }
    for path in existing_volume_paths {
        remove_file_destination_for_replace(path)?;
    }
    remove_file_destination_for_replace(destination)
}

fn remove_file_destination_for_replace(path: &Path) -> Result<(), ZipBackendError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| ZipBackendError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ZipBackendError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn existing_split_zip_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, ZipBackendError> {
    let base = split_zip_base_path(destination)?;
    let Some(base_name) = base.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let directory = destination.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ZipBackendError::Io {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    let mut paths = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        if let Some((candidate_base, part)) = parse_split_zip_sidecar_name(candidate_name)
            && candidate_base.eq_ignore_ascii_case(base_name)
        {
            paths.insert(part, entry.path());
        }
    }
    Ok(paths.into_values().collect())
}

fn parse_split_zip_sidecar_name(name: &str) -> Option<(&str, u32)> {
    let (base, extension) = name.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();
    let number = extension.strip_prefix('z')?;
    if number.len() < ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH
        || !number.chars().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

struct ZipSplitVolumeWriter<'a> {
    paths: &'a [PathBuf],
    volume_size: u64,
    next_index: usize,
    current: Option<crate::atomic_file::AtomicOutputFile>,
    current_written: u64,
    completed: Vec<crate::atomic_file::AtomicOutputFile>,
}

impl<'a> ZipSplitVolumeWriter<'a> {
    fn new(paths: &'a [PathBuf], volume_size: u64) -> Result<Self, ZipBackendError> {
        let mut writer = Self {
            paths,
            volume_size,
            next_index: 0,
            current: None,
            current_written: 0,
            completed: Vec::with_capacity(paths.len()),
        };
        writer.start_next_volume()?;
        Ok(writer)
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), ZipBackendError> {
        while !bytes.is_empty() {
            if self.current_written == self.volume_size {
                self.finish_current_volume();
                self.start_next_volume()?;
            }
            let remaining =
                usize::try_from(self.volume_size - self.current_written).unwrap_or(usize::MAX);
            let to_write = remaining.min(bytes.len());
            let path = self.current_path().to_path_buf();
            let output = self
                .current
                .as_mut()
                .ok_or_else(|| unsupported_split_zip("missing ZIP volume output"))?
                .file_mut()
                .map_err(|source| ZipBackendError::Io {
                    path: path.clone(),
                    source,
                })?;
            output
                .write_all(&bytes[..to_write])
                .map_err(|source| ZipBackendError::Io { path, source })?;
            self.current_written += u64::try_from(to_write).unwrap_or(0);
            bytes = &bytes[to_write..];
        }
        Ok(())
    }

    fn copy_from<R: Read>(
        &mut self,
        reader: &mut R,
        mut bytes_to_copy: u64,
        source_path: &Path,
    ) -> Result<(), ZipBackendError> {
        let mut buffer = vec![0; 64 * 1024];
        while bytes_to_copy > 0 {
            let chunk_len =
                usize::try_from(bytes_to_copy.min(buffer.len() as u64)).unwrap_or(buffer.len());
            reader
                .read_exact(&mut buffer[..chunk_len])
                .map_err(|source| ZipBackendError::Io {
                    path: source_path.to_path_buf(),
                    source,
                })?;
            self.write_all(&buffer[..chunk_len])?;
            bytes_to_copy -= u64::try_from(chunk_len).unwrap_or(0);
        }
        Ok(())
    }

    fn finish(
        mut self,
        destination: &Path,
        existing_volume_paths: &[PathBuf],
        replace_existing: bool,
    ) -> Result<(), ZipBackendError> {
        self.finish_current_volume();
        if self.completed.len() != self.paths.len() {
            return Err(unsupported_split_zip(
                "ZIP split writer did not fill all volumes",
            ));
        }
        remove_split_destinations_for_replace(
            destination,
            existing_volume_paths,
            replace_existing,
        )?;
        for (output, path) in self.completed.into_iter().zip(self.paths) {
            output
                .commit_with_file_replace(replace_existing)
                .map_err(|source| ZipBackendError::Io {
                    path: path.clone(),
                    source,
                })?;
        }
        Ok(())
    }

    fn start_next_volume(&mut self) -> Result<(), ZipBackendError> {
        let Some(path) = self.paths.get(self.next_index) else {
            return Err(unsupported_split_zip("ZIP split produced too many volumes"));
        };
        let output = crate::atomic_file::AtomicOutputFile::create(path).map_err(|source| {
            ZipBackendError::Io {
                path: path.clone(),
                source,
            }
        })?;
        self.current = Some(output);
        self.current_written = 0;
        self.next_index += 1;
        Ok(())
    }

    fn finish_current_volume(&mut self) {
        if let Some(mut output) = self.current.take() {
            output.close();
            self.completed.push(output);
        }
    }

    fn current_path(&self) -> &Path {
        let current_index = self.next_index.saturating_sub(1);
        self.paths
            .get(current_index)
            .map_or_else(|| Path::new("archive.zip"), PathBuf::as_path)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn unsupported_split_zip(reason: impl Into<String>) -> ZipBackendError {
    ZipBackendError::UnsupportedSplitZip {
        reason: reason.into(),
    }
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> ZipBackendError {
    ZipBackendError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(kind, message.into()),
    }
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
    let mut deferred_directories: Vec<(PathBuf, Option<u32>)> = Vec::new();

    for index in 0..archive.len() {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new().password(password))
            .map_err(map_zip_error)?;
        let entry_size = file.size();
        let unix_mode = file.unix_mode();
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
                unix_mode,
                &mut deferred_directories,
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
    unix_mode: Option<u32>,
    deferred_directories: &mut Vec<(PathBuf, Option<u32>)>,
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
            deferred_directories.push((destination_path.to_path_buf(), unix_mode));
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
            apply_zip_unix_mode(destination_path, unix_mode)?;
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

#[cfg(unix)]
fn apply_zip_unix_mode(path: &Path, unix_mode: Option<u32>) -> Result<(), ZipBackendError> {
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode & ZIP_MODE_MASK)).map_err(
            |source| ZipBackendError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_zip_unix_mode(_path: &Path, _unix_mode: Option<u32>) -> Result<(), ZipBackendError> {
    Ok(())
}

fn apply_deferred_zip_directory_metadata(
    directories: &[(PathBuf, Option<u32>)],
) -> Result<(), ZipBackendError> {
    for (path, unix_mode) in directories.iter().rev() {
        apply_zip_unix_mode(path, *unix_mode)?;
    }
    Ok(())
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

    fn preserves_metadata_during_creation_and_extraction() {

        let temp = TestDir::new("preserves_metadata_zip");

        temp.write_file("project/script.sh", b"echo hello");

        let path = temp.path("project/script.sh");

        #[cfg(unix)]

        {

            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        }

        let mtime = filetime::FileTime::from_unix_time(1500000000, 0);

        filetime::set_file_mtime(&path, mtime).unwrap();

        let archive = temp.path("archive.zip");

        create_zip_from_path(

            temp.path("project"),

            &archive,

            &ZipCreateOptions {

                preserve_metadata: true,

                ..ZipCreateOptions::default()

            },

        )

        .unwrap();

        extract_zip(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let out_path = temp.path("out/project/script.sh");

        let metadata = fs::metadata(&out_path).unwrap();

        #[cfg(unix)]

        {

            use std::os::unix::fs::PermissionsExt;

            assert_eq!(metadata.permissions().mode() & 0o777, 0o755);

        }

        // ZIP only has 2-second resolution (MS-DOS time), so we can't assert exact unix time easily

        // We just ensure it doesn't panic.

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
                ..ZipCreateOptions::default()
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
                password: Some(SecretString::from("correct horse")),
                ..ZipCreateOptions::default()
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
    fn split_zip_round_trips_through_libarchive() {
        let temp = TestDir::new("split_zip_round_trips_through_libarchive");
        let payload = deterministic_bytes(200_000);
        temp.write_file("project/blob.bin", &payload);
        let archive = temp.path("archive.zip");

        let report = create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                volume_size: Some(super::MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.volume_size, Some(super::MIN_ZIP_VOLUME_SIZE_BYTES));
        assert!(report.volume_count > 1);
        assert_eq!(
            fs::metadata(temp.path("archive.z01")).unwrap().len(),
            super::MIN_ZIP_VOLUME_SIZE_BYTES
        );
        assert_eq!(
            &fs::read(temp.path("archive.z01")).unwrap()[..super::ZIP_SPLIT_SIGNATURE.len()],
            super::ZIP_SPLIT_SIGNATURE.as_slice()
        );
        assert!(archive.is_file());

        let listing =
            crate::libarchive_backend::list_archive_with_password(&archive, None).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "project/blob.bin")
        );

        let extract_report = crate::libarchive_backend::extract_archive_with_password(
            &archive,
            temp.path("out"),
            ExtractionPolicy::default(),
            None,
        )
        .unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(
            fs::read(temp.path("out/project/blob.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn passworded_split_zip_extracts_through_libarchive() {
        let temp = TestDir::new("passworded_split_zip_extracts_through_libarchive");
        let payload = deterministic_bytes(200_000);
        temp.write_file("project/blob.bin", &payload);
        let archive = temp.path("secret.zip");

        let report = create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                password: Some(SecretString::from("correct horse")),
                volume_size: Some(super::MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(report.volume_count > 1);

        crate::libarchive_backend::extract_archive_with_password(
            &archive,
            temp.path("out"),
            ExtractionPolicy::default(),
            Some("correct horse"),
        )
        .unwrap();

        assert_eq!(
            fs::read(temp.path("out/project/blob.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn split_zip_refuses_and_replaces_existing_sidecars() {
        let temp = TestDir::new("split_zip_refuses_and_replaces_existing_sidecars");
        temp.write_file("project/blob.bin", &deterministic_bytes(200_000));
        temp.write_file("archive.z01", b"stale");
        let archive = temp.path("archive.zip");

        let error = create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                volume_size: Some(super::MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(error, ZipBackendError::Io { .. }));
        assert_eq!(fs::read(temp.path("archive.z01")).unwrap(), b"stale");

        temp.write_file("archive.z09", b"stale tail");
        create_zip_from_path(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                replace_existing: true,
                volume_size: Some(super::MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert!(temp.path("archive.z01").is_file());
        assert!(!temp.path("archive.z09").exists());
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

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_9abc_def0_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
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
