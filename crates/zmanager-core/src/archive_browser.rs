use crate::libarchive_backend::{self, LibarchiveEntryKind, LibarchiveError};
use crate::raw_stream_backend::{self, RawStreamError, RawStreamFormat};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwritePolicy,
};
use crate::sevenz_backend::{SevenZEntryKind, SevenZError};
use crate::tar_zst_backend::TarZstdError;
use crate::tzap_backend::{TzapEntryKind, TzapError, is_tzap_archive_path};
use crate::zip_backend::ZipBackendError;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::EntryType;
use zip::{ZipArchive, ZipReadOptions};

const PREVIEW_TEMP_PREFIX: &str = "zmanager-preview";

/// Portable archive entry type for the browser UI.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BrowserEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// Other special entry.
    Special,
}

/// One archive browser row.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BrowserEntry {
    /// Raw archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Uncompressed size when known.
    pub size: Option<u64>,
    /// Compressed size when known.
    pub compressed_size: Option<u64>,
    /// Modification time formatted for display.
    pub modified: Option<String>,
}

/// Archive browser listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BrowserListing {
    /// Entries in archive order.
    pub entries: Vec<BrowserEntry>,
}

/// Options for browser-driven listing.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct BrowserListOptions<'a> {
    /// Optional password for archive formats that encrypt headers or metadata.
    pub password: Option<&'a str>,
}

/// Report for selected-entry extraction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntryExtractReport {
    /// Destination path written for the selected entry.
    pub destination_path: PathBuf,
    /// Number of regular file bytes written.
    pub written_bytes: u64,
}

/// Preview extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreviewExtractReport {
    /// Temporary root that owns the preview extraction.
    pub cleanup_root: PathBuf,
    /// Extracted path to open for preview.
    pub preview_path: PathBuf,
    /// Number of regular file bytes written.
    pub written_bytes: u64,
}

/// Options for browser-driven extraction.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BrowserExtractOptions<'a> {
    /// Optional password for encrypted archive entry data.
    pub password: Option<&'a str>,
    /// Existing destination behavior.
    pub overwrite: OverwritePolicy,
    /// Leading archive path components to drop before writing.
    pub strip_components: usize,
}

impl Default for BrowserExtractOptions<'_> {
    fn default() -> Self {
        Self {
            password: None,
            overwrite: OverwritePolicy::Refuse,
            strip_components: 0,
        }
    }
}

/// Archive browser error.
#[derive(Debug)]
pub enum ArchiveBrowserError {
    /// ZIP backend failed.
    Zip(ZipBackendError),
    /// TAR.ZST backend failed.
    TarZst(TarZstdError),
    /// 7z backend failed.
    SevenZ(SevenZError),
    /// TZAP backend failed.
    Tzap(TzapError),
    /// Libarchive backend failed.
    Libarchive(LibarchiveError),
    /// Raw single-file stream backend failed.
    RawStream(RawStreamError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Selected entry was not found.
    EntryNotFound { path: String },
    /// Selected entry cannot be materialized by the browser yet.
    UnsupportedEntry {
        path: String,
        kind: BrowserEntryKind,
    },
}

impl fmt::Display for ArchiveBrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zip(source) => write!(f, "ZIP browser operation failed: {source}"),
            Self::TarZst(source) => write!(f, "TAR.ZST browser operation failed: {source}"),
            Self::SevenZ(source) => write!(f, "7z browser operation failed: {source}"),
            Self::Tzap(source) => write!(f, "TZAP browser operation failed: {source}"),
            Self::Libarchive(source) => write!(f, "libarchive browser operation failed: {source}"),
            Self::RawStream(source) => write!(f, "raw stream browser operation failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::UnsupportedEntry { path, kind } => {
                write!(f, "unsupported preview/extract entry {path}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for ArchiveBrowserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Zip(source) => Some(source),
            Self::TarZst(source) => Some(source),
            Self::SevenZ(source) => Some(source),
            Self::Tzap(source) => Some(source),
            Self::Libarchive(source) => Some(source),
            Self::RawStream(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::EntryNotFound { .. } | Self::UnsupportedEntry { .. } => None,
        }
    }
}

impl From<ZipBackendError> for ArchiveBrowserError {
    fn from(source: ZipBackendError) -> Self {
        Self::Zip(source)
    }
}

impl From<TarZstdError> for ArchiveBrowserError {
    fn from(source: TarZstdError) -> Self {
        Self::TarZst(source)
    }
}

impl From<SevenZError> for ArchiveBrowserError {
    fn from(source: SevenZError) -> Self {
        Self::SevenZ(source)
    }
}

impl From<TzapError> for ArchiveBrowserError {
    fn from(source: TzapError) -> Self {
        Self::Tzap(source)
    }
}

impl From<LibarchiveError> for ArchiveBrowserError {
    fn from(source: LibarchiveError) -> Self {
        Self::Libarchive(source)
    }
}

impl From<RawStreamError> for ArchiveBrowserError {
    fn from(source: RawStreamError) -> Self {
        Self::RawStream(source)
    }
}

impl From<ExtractionSafetyError> for ArchiveBrowserError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries in a ZIP, TAR.ZST, or libarchive-backed archive.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read.
pub fn list_entries(path: impl AsRef<Path>) -> Result<BrowserListing, ArchiveBrowserError> {
    list_entries_with_options(path, BrowserListOptions::default())
}

/// Lists entries with browser listing options.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read.
pub fn list_entries_with_options(
    path: impl AsRef<Path>,
    options: BrowserListOptions<'_>,
) -> Result<BrowserListing, ArchiveBrowserError> {
    let path = path.as_ref();
    if is_zip_family_archive(path) && !libarchive_backend::is_split_zip_path(path) {
        list_zip_entries(path)
    } else if is_tar_zst_archive(path) {
        list_tar_zst_entries(path)
    } else if is_7z_archive(path) {
        list_7z_entries(path, options.password)
    } else if is_tzap_archive_path(path) {
        list_tzap_entries(path, options.password)
    } else if let Some(format) = raw_stream_backend::detect_raw_stream_format(path) {
        list_raw_stream_entry(path, format)
    } else {
        list_libarchive_entries(path)
    }
}

/// Extracts one selected entry into `destination`.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read, the entry
/// is not found, the entry is unsafe, or filesystem writes fail.
pub fn extract_entry(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    extract_entry_with_options(
        archive_path,
        entry_path,
        destination,
        BrowserExtractOptions::default(),
    )
}

/// Extracts one selected entry into `destination` with browser extraction
/// options.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read, the entry
/// is not found, the password is missing or incorrect, the entry is unsafe, or
/// filesystem writes fail.
pub fn extract_entry_with_options(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    options: BrowserExtractOptions<'_>,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            ArchiveBrowserError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let policy = extraction_policy(options.overwrite, options.strip_components);

    if is_zip_family_archive(archive_path) && !libarchive_backend::is_split_zip_path(archive_path) {
        extract_zip_entry(
            archive_path,
            entry_path,
            &destination_root,
            &policy,
            options.password,
        )
    } else if is_tar_zst_archive(archive_path) {
        extract_tar_zst_entry(archive_path, entry_path, &destination_root, &policy)
    } else if is_tzap_archive_path(archive_path) {
        extract_tzap_entry(
            archive_path,
            entry_path,
            &destination_root,
            &policy,
            options.password,
        )
    } else if let Some(format) = raw_stream_backend::detect_raw_stream_format(archive_path) {
        extract_raw_stream_entry(archive_path, format, entry_path, &destination_root, &policy)
    } else {
        let report = libarchive_backend::extract_archive_entry_with_password(
            archive_path,
            entry_path,
            &destination_root,
            policy,
            options.password,
        )?;
        Ok(EntryExtractReport {
            destination_path: destination.join(entry_path),
            written_bytes: report.written_bytes,
        })
    }
}

/// Extracts one selected entry into a controlled temporary preview root.
///
/// The caller owns the returned `cleanup_root` and should remove it when the
/// preview is replaced or the app exits.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when temporary directory creation,
/// extraction, or safety validation fails.
pub fn preview_entry(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
) -> Result<PreviewExtractReport, ArchiveBrowserError> {
    preview_entry_with_options(archive_path, entry_path, BrowserExtractOptions::default())
}

/// Extracts one selected entry into a controlled temporary preview root with
/// browser extraction options.
///
/// The caller owns the returned `cleanup_root` and should remove it when the
/// preview is replaced or the app exits.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when temporary directory creation,
/// extraction, password validation, or safety validation fails.
pub fn preview_entry_with_options(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    options: BrowserExtractOptions<'_>,
) -> Result<PreviewExtractReport, ArchiveBrowserError> {
    let cleanup_root = std::env::temp_dir().join(format!(
        "{PREVIEW_TEMP_PREFIX}-{}-{}",
        std::process::id(),
        unique_preview_id()
    ));
    fs::create_dir_all(&cleanup_root).map_err(|source| ArchiveBrowserError::Io {
        path: cleanup_root.clone(),
        source,
    })?;

    let report = match extract_entry_with_options(archive_path, entry_path, &cleanup_root, options)
    {
        Ok(report) => report,
        Err(error) => {
            let _ = fs::remove_dir_all(&cleanup_root);
            return Err(error);
        }
    };
    Ok(PreviewExtractReport {
        cleanup_root,
        preview_path: report.destination_path,
        written_bytes: report.written_bytes,
    })
}

fn list_zip_entries(path: &Path) -> Result<BrowserListing, ArchiveBrowserError> {
    let file = File::open(path).map_err(|source| ArchiveBrowserError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(ZipBackendError::from)?;
    let mut entries = Vec::with_capacity(archive.len());

    for index in 0..archive.len() {
        let file = archive.by_index_raw(index).map_err(ZipBackendError::from)?;
        entries.push(BrowserEntry {
            path: file.name().to_owned(),
            kind: zip_entry_kind(&file),
            size: Some(file.size()),
            compressed_size: Some(file.compressed_size()),
            modified: file.last_modified().map(|modified| modified.to_string()),
        });
    }

    Ok(BrowserListing { entries })
}

fn list_tar_zst_entries(path: &Path) -> Result<BrowserListing, ArchiveBrowserError> {
    let file = File::open(path).map_err(|source| ArchiveBrowserError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let decoder =
        zstd::stream::read::Decoder::new(file).map_err(|source| ArchiveBrowserError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|source| ArchiveBrowserError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .map(|entry| {
            let entry = entry.map_err(|source| ArchiveBrowserError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            let path = entry
                .path()
                .map_err(|source| ArchiveBrowserError::Io {
                    path: path.to_path_buf(),
                    source,
                })?
                .to_string_lossy()
                .into_owned();
            let header = entry.header();
            Ok(BrowserEntry {
                path,
                kind: tar_entry_kind(header.entry_type()),
                size: header.size().ok(),
                compressed_size: None,
                modified: header.mtime().ok().map(|mtime| mtime.to_string()),
            })
        })
        .collect::<Result<Vec<_>, ArchiveBrowserError>>()?;

    Ok(BrowserListing { entries })
}

fn list_libarchive_entries(path: &Path) -> Result<BrowserListing, ArchiveBrowserError> {
    let listing = libarchive_backend::list_archive(path)?;
    let entries = listing
        .entries
        .into_iter()
        .map(|entry| BrowserEntry {
            path: entry.path,
            kind: libarchive_entry_kind(entry.kind),
            size: u64::try_from(entry.size).ok(),
            compressed_size: None,
            modified: entry.modified.and_then(system_time_string),
        })
        .collect();
    Ok(BrowserListing { entries })
}

fn list_raw_stream_entry(
    path: &Path,
    format: RawStreamFormat,
) -> Result<BrowserListing, ArchiveBrowserError> {
    let entry_name =
        raw_stream_backend::output_name_for_raw_stream(path, format).ok_or_else(|| {
            RawStreamError::MissingOutputName {
                archive_path: path.to_path_buf(),
            }
        })?;
    let compressed_size = path.metadata().ok().map(|metadata| metadata.len());
    Ok(BrowserListing {
        entries: vec![BrowserEntry {
            path: entry_name,
            kind: BrowserEntryKind::File,
            size: None,
            compressed_size,
            modified: None,
        }],
    })
}

fn list_7z_entries(
    path: &Path,
    password: Option<&str>,
) -> Result<BrowserListing, ArchiveBrowserError> {
    let listing = crate::sevenz_backend::list_7z(path, password)?;
    let entries = listing
        .entries
        .into_iter()
        .map(|entry| BrowserEntry {
            path: entry.name,
            kind: sevenz_entry_kind(entry.kind),
            size: Some(entry.size),
            compressed_size: Some(entry.compressed_size),
            modified: None,
        })
        .collect();
    Ok(BrowserListing { entries })
}

fn list_tzap_entries(
    path: &Path,
    password: Option<&str>,
) -> Result<BrowserListing, ArchiveBrowserError> {
    let listing =
        crate::tzap_backend::list_tzap_index_entries_with_optional_password(path, password)?;
    let entries = listing
        .into_iter()
        .map(|entry| BrowserEntry {
            path: entry.path.clone(),
            kind: tzap_entry_kind_from_index_entry_path(&entry.path),
            size: Some(entry.file_data_size),
            compressed_size: None,
            modified: entry.mtime.map(|mtime| mtime.to_string()),
        })
        .collect();
    Ok(BrowserListing { entries })
}

fn tzap_entry_kind_from_index_entry_path(path: &str) -> BrowserEntryKind {
    if path.ends_with('/') {
        BrowserEntryKind::Directory
    } else {
        BrowserEntryKind::File
    }
}

fn extract_tzap_entry(
    archive_path: &Path,
    entry_path: &str,
    destination: &Path,
    policy: &ExtractionPolicy,
    password: Option<&str>,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let listing = crate::tzap_backend::list_tzap_with_optional_password(archive_path, password)?;
    let entry = listing
        .entries
        .into_iter()
        .find(|entry| entry.path == entry_path)
        .ok_or_else(|| ArchiveBrowserError::EntryNotFound {
            path: entry_path.to_owned(),
        })?;
    let extraction_kind = tzap_extraction_kind(entry.kind, &entry.path)?;
    let safety_entry = ExtractionEntry {
        archive_path: entry.path,
        kind: extraction_kind,
        uncompressed_size: Some(entry.size),
        compressed_size: None,
    };
    let decision =
        ExtractionSafetyPlanner::new(destination, policy.clone()).validate_entry(&safety_entry)?;
    let write_plan = decision_write_plan(decision, &safety_entry.archive_path)?;

    match &safety_entry.kind {
        ExtractionEntryKind::Directory => {
            let mut empty = io::empty();
            let written_bytes = write_selected_entry(&mut empty, &safety_entry, &write_plan)?;
            Ok(EntryExtractReport {
                destination_path: write_plan.destination_path,
                written_bytes,
            })
        }
        ExtractionEntryKind::File => {
            let Some(written_bytes) =
                crate::tzap_backend::extract_tzap_file_to_destination_with_optional_password(
                    archive_path,
                    password,
                    entry_path,
                    &write_plan.destination_path,
                    write_plan.replace_existing,
                )?
            else {
                return Err(ArchiveBrowserError::EntryNotFound {
                    path: entry_path.to_owned(),
                });
            };
            Ok(EntryExtractReport {
                destination_path: write_plan.destination_path,
                written_bytes,
            })
        }
        ExtractionEntryKind::Symlink { .. }
        | ExtractionEntryKind::Hardlink { .. }
        | ExtractionEntryKind::Device
        | ExtractionEntryKind::Special => Err(ArchiveBrowserError::UnsupportedEntry {
            path: safety_entry.archive_path,
            kind: BrowserEntryKind::Special,
        }),
    }
}

fn extract_zip_entry(
    archive_path: &Path,
    entry_path: &str,
    destination: &Path,
    policy: &ExtractionPolicy,
    password: Option<&str>,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let file = File::open(archive_path).map_err(|source| ArchiveBrowserError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(ZipBackendError::from)?;
    let password = password_bytes(password);

    for index in 0..archive.len() {
        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new().password(password))
            .map_err(ZipBackendError::from)?;
        if file.name() != entry_path {
            continue;
        }
        let entry = ExtractionEntry {
            archive_path: file.name().to_owned(),
            kind: zip_extraction_kind(&mut file)?,
            uncompressed_size: Some(file.size()),
            compressed_size: Some(file.compressed_size()),
        };
        let decision =
            ExtractionSafetyPlanner::new(destination, policy.clone()).validate_entry(&entry)?;
        let write_plan = decision_write_plan(decision, &entry.archive_path)?;
        let written_bytes = write_selected_entry(&mut file, &entry, &write_plan)?;
        return Ok(EntryExtractReport {
            destination_path: write_plan.destination_path,
            written_bytes,
        });
    }

    Err(ArchiveBrowserError::EntryNotFound {
        path: entry_path.to_owned(),
    })
}

fn extract_tar_zst_entry(
    archive_path: &Path,
    entry_path: &str,
    destination: &Path,
    policy: &ExtractionPolicy,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let file = File::open(archive_path).map_err(|source| ArchiveBrowserError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let decoder =
        zstd::stream::read::Decoder::new(file).map_err(|source| ArchiveBrowserError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|source| ArchiveBrowserError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?
    {
        let mut entry = entry.map_err(|source| ArchiveBrowserError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?;
        let path = entry
            .path()
            .map_err(|source| ArchiveBrowserError::Io {
                path: archive_path.to_path_buf(),
                source,
            })?
            .to_string_lossy()
            .into_owned();
        if path != entry_path {
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: path,
            kind: tar_extraction_kind(&entry)?,
            uncompressed_size: entry.header().size().ok(),
            compressed_size: None,
        };
        let decision = ExtractionSafetyPlanner::new(destination, policy.clone())
            .validate_entry(&safety_entry)?;
        let write_plan = decision_write_plan(decision, &safety_entry.archive_path)?;
        let written_bytes = write_selected_entry(&mut entry, &safety_entry, &write_plan)?;
        return Ok(EntryExtractReport {
            destination_path: write_plan.destination_path,
            written_bytes,
        });
    }

    Err(ArchiveBrowserError::EntryNotFound {
        path: entry_path.to_owned(),
    })
}

fn extract_raw_stream_entry(
    archive_path: &Path,
    format: RawStreamFormat,
    entry_path: &str,
    destination: &Path,
    policy: &ExtractionPolicy,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let expected_entry = raw_stream_backend::output_name_for_raw_stream(archive_path, format)
        .ok_or_else(|| RawStreamError::MissingOutputName {
            archive_path: archive_path.to_path_buf(),
        })?;
    if entry_path != expected_entry {
        return Err(ArchiveBrowserError::EntryNotFound {
            path: entry_path.to_owned(),
        });
    }

    let mut reader = raw_stream_backend::open_decoder(archive_path, format)?;
    let safety_entry = ExtractionEntry {
        archive_path: expected_entry,
        kind: ExtractionEntryKind::File,
        uncompressed_size: None,
        compressed_size: archive_path.metadata().ok().map(|metadata| metadata.len()),
    };
    let decision =
        ExtractionSafetyPlanner::new(destination, policy.clone()).validate_entry(&safety_entry)?;
    let write_plan = decision_write_plan(decision, &safety_entry.archive_path)?;
    let written_bytes = write_selected_entry(&mut reader, &safety_entry, &write_plan)?;
    Ok(EntryExtractReport {
        destination_path: write_plan.destination_path,
        written_bytes,
    })
}

fn write_selected_entry<R: Read>(
    reader: &mut R,
    entry: &ExtractionEntry,
    write_plan: &SelectedEntryWritePlan,
) -> Result<u64, ArchiveBrowserError> {
    let destination_path = &write_plan.destination_path;
    match &entry.kind {
        ExtractionEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| ArchiveBrowserError::Io {
                path: destination_path.clone(),
                source,
            })?;
            Ok(0)
        }
        ExtractionEntryKind::File => {
            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path)
                .map_err(|source| ArchiveBrowserError::Io {
                    path: destination_path.clone(),
                    source,
                })?;
            let written_bytes = io::copy(
                reader,
                output
                    .file_mut()
                    .map_err(|source| ArchiveBrowserError::Io {
                        path: destination_path.clone(),
                        source,
                    })?,
            )
            .map_err(|source| ArchiveBrowserError::Io {
                path: destination_path.clone(),
                source,
            })?;
            output
                .commit_with_replace(write_plan.replace_existing)
                .map_err(|source| ArchiveBrowserError::Io {
                    path: destination_path.clone(),
                    source,
                })?;
            Ok(written_bytes)
        }
        ExtractionEntryKind::Symlink { .. }
        | ExtractionEntryKind::Hardlink { .. }
        | ExtractionEntryKind::Device
        | ExtractionEntryKind::Special => Err(ArchiveBrowserError::UnsupportedEntry {
            path: entry.archive_path.clone(),
            kind: BrowserEntryKind::Special,
        }),
    }
}

struct SelectedEntryWritePlan {
    destination_path: PathBuf,
    replace_existing: bool,
}

fn decision_write_plan(
    decision: ExtractionDecision,
    archive_path: &str,
) -> Result<SelectedEntryWritePlan, ArchiveBrowserError> {
    match decision {
        ExtractionDecision::Write {
            destination_path,
            replace_existing,
            ..
        } => Ok(SelectedEntryWritePlan {
            destination_path,
            replace_existing,
        }),
        ExtractionDecision::Skip { reason, .. } => Err(ArchiveBrowserError::UnsupportedEntry {
            path: format!("{archive_path}: {reason}"),
            kind: BrowserEntryKind::Special,
        }),
    }
}

fn extraction_policy(overwrite: OverwritePolicy, strip_components: usize) -> ExtractionPolicy {
    ExtractionPolicy {
        overwrite,
        strip_components,
        ..ExtractionPolicy::default()
    }
}

fn password_bytes(password: Option<&str>) -> Option<&[u8]> {
    password
        .filter(|password| !password.is_empty())
        .map(str::as_bytes)
}

fn zip_entry_kind<R: Read>(file: &zip::read::ZipFile<'_, R>) -> BrowserEntryKind {
    if file.is_dir() {
        BrowserEntryKind::Directory
    } else if file.is_symlink() {
        BrowserEntryKind::Symlink
    } else {
        BrowserEntryKind::File
    }
}

fn zip_extraction_kind<R: Read>(
    file: &mut zip::read::ZipFile<'_, R>,
) -> Result<ExtractionEntryKind, ArchiveBrowserError> {
    if file.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }
    if file.is_symlink() {
        let mut target = String::new();
        file.read_to_string(&mut target)
            .map_err(|_| ArchiveBrowserError::UnsupportedEntry {
                path: file.name().to_owned(),
                kind: BrowserEntryKind::Symlink,
            })?;
        return Ok(ExtractionEntryKind::Symlink {
            target: PathBuf::from(target),
        });
    }
    Ok(ExtractionEntryKind::File)
}

fn tar_entry_kind(entry_type: EntryType) -> BrowserEntryKind {
    if entry_type.is_dir() {
        BrowserEntryKind::Directory
    } else if entry_type.is_symlink() {
        BrowserEntryKind::Symlink
    } else if entry_type.is_hard_link() {
        BrowserEntryKind::Hardlink
    } else if entry_type.is_file() {
        BrowserEntryKind::File
    } else {
        BrowserEntryKind::Special
    }
}

fn tar_extraction_kind<R: Read>(
    entry: &tar::Entry<'_, R>,
) -> Result<ExtractionEntryKind, ArchiveBrowserError> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_dir() {
        Ok(ExtractionEntryKind::Directory)
    } else if entry_type.is_file() {
        Ok(ExtractionEntryKind::File)
    } else if entry_type.is_symlink() {
        let target = entry
            .link_name()
            .map_err(|source| ArchiveBrowserError::Io {
                path: PathBuf::from(entry.path().map_or_else(
                    |_| String::new(),
                    |path| path.to_string_lossy().into_owned(),
                )),
                source,
            })?;
        Ok(ExtractionEntryKind::Symlink {
            target: target.unwrap_or_default().into_owned(),
        })
    } else if entry_type.is_hard_link() {
        let target = entry
            .link_name()
            .map_err(|source| ArchiveBrowserError::Io {
                path: PathBuf::from(entry.path().map_or_else(
                    |_| String::new(),
                    |path| path.to_string_lossy().into_owned(),
                )),
                source,
            })?;
        Ok(ExtractionEntryKind::Hardlink {
            target: target.unwrap_or_default().into_owned(),
        })
    } else {
        Ok(ExtractionEntryKind::Special)
    }
}

fn libarchive_entry_kind(kind: LibarchiveEntryKind) -> BrowserEntryKind {
    match kind {
        LibarchiveEntryKind::File => BrowserEntryKind::File,
        LibarchiveEntryKind::Directory => BrowserEntryKind::Directory,
        LibarchiveEntryKind::Symlink => BrowserEntryKind::Symlink,
        LibarchiveEntryKind::Hardlink => BrowserEntryKind::Hardlink,
        LibarchiveEntryKind::Device | LibarchiveEntryKind::Special => BrowserEntryKind::Special,
    }
}

fn sevenz_entry_kind(kind: SevenZEntryKind) -> BrowserEntryKind {
    match kind {
        SevenZEntryKind::File => BrowserEntryKind::File,
        SevenZEntryKind::Directory => BrowserEntryKind::Directory,
        SevenZEntryKind::AntiItem => BrowserEntryKind::Special,
    }
}

fn tzap_entry_kind(kind: TzapEntryKind) -> BrowserEntryKind {
    match kind {
        TzapEntryKind::File => BrowserEntryKind::File,
        TzapEntryKind::Directory => BrowserEntryKind::Directory,
        TzapEntryKind::Symlink => BrowserEntryKind::Symlink,
        TzapEntryKind::Hardlink => BrowserEntryKind::Hardlink,
    }
}

fn tzap_extraction_kind(
    kind: TzapEntryKind,
    path: &str,
) -> Result<ExtractionEntryKind, ArchiveBrowserError> {
    match kind {
        TzapEntryKind::File => Ok(ExtractionEntryKind::File),
        TzapEntryKind::Directory => Ok(ExtractionEntryKind::Directory),
        TzapEntryKind::Symlink | TzapEntryKind::Hardlink => {
            Err(ArchiveBrowserError::UnsupportedEntry {
                path: path.to_owned(),
                kind: tzap_entry_kind(kind),
            })
        }
    }
}

fn system_time_string(time: SystemTime) -> Option<String> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs().to_string())
}

fn is_zip_family_archive(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "zip" | "zipx" | "jar" | "war" | "ipa" | "apk" | "appx" | "xpi"
            )
        })
}

fn is_tar_zst_archive(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tzst"))
    {
        return true;
    }

    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zst"))
        && path
            .file_stem()
            .and_then(|stem| Path::new(stem).extension())
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tar"))
}

fn is_7z_archive(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

fn unique_preview_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserListOptions, extract_entry, list_entries, list_entries_with_options, preview_entry,
    };
    use crate::jobs::{CancellationToken, JobContext};
    use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot};
    use crate::secrets::SecretString;
    use crate::sevenz_backend::{SevenZCreateOptions, create_7z_from_path};
    use crate::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_path};
    use crate::tzap_backend::{
        TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context,
    };
    use crate::zip_backend::{ZipCreateOptions, create_zip_from_path};
    use bzip2::Compression;
    use bzip2::write::BzEncoder;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tar::{Builder, Header};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    #[test]
    fn lists_and_extracts_single_zip_entry() {
        let temp = TestDir::new("browser_zip");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/b.txt", b"b");
        let archive = temp.path("archive.zip");
        create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();

        let listing = list_entries(&archive).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "project/b.txt")
        );

        let report = extract_entry(&archive, "project/b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(
            fs::read_to_string(temp.path("out/project/b.txt")).unwrap(),
            "b"
        );
        assert!(!temp.path("out/project/a.txt").exists());
    }

    #[test]
    fn lists_tzap_entry_from_index_metadata() {
        let temp = TestDir::new("browser_tzap_index");
        let payload = temp.path("payload.txt");
        fs::write(&payload, b"hello").unwrap();
        let archive = temp.path("archive.tzap");

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: payload,
                file_type: ManifestFileType::File,
                size: 5,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 5,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let listing = list_entries(&archive).unwrap();
        let payload_entry = listing
            .entries
            .iter()
            .find(|entry| entry.path == "payload.txt")
            .expect("payload entry should be listed")
            .clone();

        assert_eq!(payload_entry.path, "payload.txt");
        assert_eq!(payload_entry.kind, super::BrowserEntryKind::File);
        assert_eq!(payload_entry.size, Some(5));
        assert_eq!(payload_entry.modified, Some("1700000000".to_owned()));
        assert_eq!(listing.entries.len(), 1);
    }

    #[test]
    fn lists_and_extracts_single_tar_zst_entry() {
        let temp = TestDir::new("browser_tar_zst");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/b.txt", b"b");
        let archive = temp.path("archive.tar.zst");
        create_tar_zst_from_path(
            temp.path("project"),
            &archive,
            &TarZstdCreateOptions {
                level: 1,
                threads: Some(1),
                preserve_metadata: true,
                replace_existing: false,
            },
        )
        .unwrap();

        let listing = list_entries(&archive).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "project/b.txt")
        );

        let report = extract_entry(&archive, "project/b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(
            fs::read_to_string(temp.path("out/project/b.txt")).unwrap(),
            "b"
        );
        assert!(!temp.path("out/project/a.txt").exists());
    }

    #[test]
    fn lists_encrypted_7z_headers_with_password() {
        let temp = TestDir::new("browser_7z_encrypted_headers");
        temp.write_file("project/a.txt", b"a");
        let archive = temp.path("archive.7z");
        create_7z_from_path(
            temp.path("project"),
            &archive,
            &SevenZCreateOptions {
                password: Some(SecretString::from("correct horse")),
                encrypt_file_names: true,
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        let error = list_entries(&archive).unwrap_err();
        assert!(error.to_string().contains("password required"));

        let listing = list_entries_with_options(
            &archive,
            BrowserListOptions {
                password: Some("correct horse"),
            },
        )
        .unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "project/a.txt")
        );
    }

    #[test]
    fn split_tzap_listing_uses_tzap_backend_route() {
        let temp = TestDir::new("browser_split_tzap_route");
        let archive = temp.path("archive.vol000.tzap");
        fs::write(&archive, b"not a real tzap volume").unwrap();

        let error = list_entries(&archive).unwrap_err().to_string();

        assert!(error.contains("TZAP browser operation failed"), "{error}");
        assert!(!error.contains("libarchive"), "{error}");
    }

    #[test]
    fn lists_and_extracts_single_libarchive_backed_tar_entry() {
        let temp = TestDir::new("browser_libarchive_tar");
        let archive = temp.path("archive.tar");
        write_tar(
            &archive,
            &[("a.txt", b"a".as_slice()), ("b.txt", b"b".as_slice())],
        );

        let listing = list_entries(&archive).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "b.txt"));

        let report = extract_entry(&archive, "b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(fs::read_to_string(temp.path("out/b.txt")).unwrap(), "b");
        assert!(!temp.path("out/a.txt").exists());
    }

    #[test]
    fn lists_and_extracts_raw_bzip2_stream() {
        let temp = TestDir::new("browser_raw_bzip2");
        let archive = temp.path("payload.txt.bz2");
        write_bz2(&archive, b"raw payload");

        let listing = list_entries(&archive).unwrap();

        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        assert_eq!(listing.entries[0].kind, super::BrowserEntryKind::File);
        assert!(listing.entries[0].compressed_size.is_some());

        let report = extract_entry(&archive, "payload.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 11);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload.txt")).unwrap(),
            "raw payload"
        );
    }

    #[test]
    fn preview_entry_uses_temporary_cleanup_root() {
        let temp = TestDir::new("browser_preview");
        temp.write_file("project/file.txt", b"preview");
        let archive = temp.path("archive.zip");
        create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default()).unwrap();

        let report = preview_entry(&archive, "project/file.txt").unwrap();

        assert!(report.cleanup_root.exists());
        assert_eq!(fs::read_to_string(&report.preview_path).unwrap(), "preview");
        fs::remove_dir_all(report.cleanup_root).unwrap();
    }

    #[test]
    fn selected_entry_extraction_uses_safety_policy() {
        let temp = TestDir::new("browser_safety");
        let archive = temp.path("archive.zip");
        write_zip(&archive, &[("../escape.txt", b"escape".as_slice())]);

        let error = extract_entry(&archive, "../escape.txt", temp.path("out")).unwrap_err();

        assert!(error.to_string().contains("extraction safety"));
        assert!(!temp.path("escape.txt").exists());
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        for (name, contents) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    fn write_tar(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut builder = Builder::new(file);
        for (name, contents) in entries {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, *name, *contents).unwrap();
        }
        builder.finish().unwrap();
    }

    fn write_bz2(path: &Path, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = BzEncoder::new(file, Compression::best());
        encoder.write_all(contents).unwrap();
        encoder.finish().unwrap();
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
