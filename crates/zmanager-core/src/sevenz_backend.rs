//! `.7z` archive creation, listing, and extraction.
//!
//! Format API asymmetries vs the ZIP backend, deliberately kept:
//! - [`list_7z`] takes a password because 7z can encrypt its file names,
//!   while `list_zip` does not (ZIP names are always readable).
//! - 7z never materializes symlinks: `sevenz_rust2` exposes no link-target
//!   metadata, so every non-directory entry — including link-like entries a
//!   hostile archive may declare — is extracted as a regular file. This is
//!   deliberately safer than materializing links that cannot be validated;
//!   see [`extraction_kind`].

use crate::backend_impl::backend_report::open_member_source;
use crate::jobs::{CancellationToken, JobContext};
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use crate::sevenz_volume::{
    MIN_VOLUME_SIZE_BYTES, MultiVolumeReader, discover_7z_read_volume_paths, has_7z_extension, parse_7z_volume_file_name, split_7z_temp_archive,
};
use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
use sevenz_rust2::{Archive, ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderMethod, Password, SourceReader};
use std::borrow::Cow;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const DEFAULT_SEVENZ_COMPRESSION_LEVEL: u32 = 6;
const DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_SEVENZ_LZMA2_THREADS: u32 = 256;
const SEVENZ_MODE_MASK: u32 = 0o7777;
/// Bit 31 in 7z `windows_attributes` signals that Unix permission bits are
/// present in the upper half-word (bits 16–27).
const SEVENZ_UNIX_ATTRIBUTES_FLAG: u32 = 0x8000_0000;

type SevenZProgressCallback<'a> = Rc<RefCell<dyn FnMut(Option<&str>, u64) + 'a>>;

/// Options for `.7z` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SevenZCreateOptions {
    /// Whether regular files should be packed into a solid block.
    pub solid: bool,
    /// Compression level for LZMA2 where supported.
    pub level: Option<u32>,
    /// LZMA2 worker count. `None` leaves the backend's single-thread default.
    pub threads: Option<u32>,
    /// LZMA2 independent chunk size for multi-threaded compression.
    pub chunk_size: Option<u64>,
    /// Preserve timestamps and attributes exposed by the 7z backend.
    pub preserve_metadata: bool,
    /// Optional AES password. Empty strings are treated as no password.
    pub password: Option<SecretString>,
    /// Encrypt archive headers so file names cannot be listed without a password.
    pub encrypt_file_names: bool,
    /// Replace an existing destination archive after caller confirmation.
    pub replace_existing: bool,
    /// Split the archive into numbered 7z volumes of this size.
    pub volume_size: Option<u64>,
}

impl Default for SevenZCreateOptions {
    fn default() -> Self {
        Self {
            solid: true,
            level: None,
            threads: crate::tar_metadata::available_parallelism_at_least_two(),
            chunk_size: Some(DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES),
            preserve_metadata: true,
            password: None,
            encrypt_file_names: true,
            replace_existing: false,
            volume_size: None,
        }
    }
}

/// Summary of a created `.7z` archive.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZCreateReport {
    /// Number of archive entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into file entries.
    pub written_bytes: u64,
    /// Whether solid compression was requested.
    pub solid: bool,
    /// LZMA2 worker count requested for archive creation.
    pub threads: Option<u32>,
    /// Whether AES encryption was enabled.
    pub encrypted: bool,
    /// Requested split volume size, when the archive was split.
    pub volume_size: Option<u64>,
    /// Number of output archive files created.
    pub volume_count: usize,
    /// Non-fatal creation warnings.
    pub warnings: Vec<String>,
}

/// One `.7z` listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZListEntry {
    /// Raw path reported by the 7z archive.
    pub name: String,
    /// Entry kind.
    pub kind: SevenZEntryKind,
    /// Uncompressed size.
    pub size: u64,
    /// Compressed size when reported by the backend.
    pub compressed_size: u64,
    /// Whether the entry has a data stream.
    pub has_stream: bool,
    /// Modification time when present.
    pub modified: Option<std::time::SystemTime>,
    /// Creation time when present.
    pub created: Option<std::time::SystemTime>,
    /// Access time when present.
    pub accessed: Option<std::time::SystemTime>,
    /// Unix permission mode when present.
    pub mode: Option<u32>,
    /// Checksum CRC32.
    pub crc: Option<u32>,
    /// Windows attributes.
    pub attributes: Option<u32>,
}

/// Portable 7z entry type exposed by the backend.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SevenZEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// 7z anti-item marker.
    AntiItem,
}

/// Archive listing returned by the 7z backend.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZListing {
    /// Entries in archive order.
    pub entries: Vec<SevenZListEntry>,
    /// Whether the archive is solid.
    pub solid: bool,
}

/// Extraction report returned by the 7z backend.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped.
    pub skipped_entries: usize,
    /// File bytes copied from the archive.
    pub written_bytes: u64,
    /// Non-fatal extraction warnings.
    pub warnings: Vec<String>,
}

/// Integrity-test report returned after reading selected 7z entries.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZTestReport {
    /// Entries whose headers or data were read.
    pub tested_entries: usize,
    /// Entries excluded by the filter or represented by an anti-item.
    pub skipped_entries: usize,
    /// Regular-file bytes read while validating the archive.
    pub tested_bytes: u64,
}

/// Error returned by the 7z backend.
#[derive(Debug)]
pub enum SevenZError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// The 7z crate returned an error.
    SevenZ(sevenz_rust2::Error),
    /// Requested split volume size is too small for the create backend.
    VolumeSizeTooSmall { size: u64, minimum: u64 },
    /// A password is required to read encrypted 7z data.
    PasswordRequired,
    /// The supplied password did not decrypt 7z data.
    InvalidPassword,
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Job was cancelled cooperatively.
    Cancelled,
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
}

impl fmt::Display for SevenZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::SevenZ(source) => write!(f, "7z operation failed: {source}"),
            Self::VolumeSizeTooSmall { size, minimum } => {
                write!(f, "7z volume size {size} bytes is smaller than the minimum {minimum} bytes")
            }
            Self::PasswordRequired => write!(f, "password required to decrypt 7z data"),
            Self::InvalidPassword => write!(f, "provided 7z password is incorrect"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Cancelled => write!(f, "job cancelled"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
        }
    }
}

impl std::error::Error for SevenZError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::SevenZ(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::VolumeSizeTooSmall { .. } | Self::PasswordRequired | Self::InvalidPassword | Self::Cancelled => None,
        }
    }
}

crate::backend_error_from_impls!(SevenZError);

impl From<sevenz_rust2::Error> for SevenZError {
    fn from(source: sevenz_rust2::Error) -> Self {
        map_7z_error(source)
    }
}

/// Creates a `.7z` archive from a source path.
///
/// # Errors
///
/// Returns [`SevenZError`] when planning, filesystem reads, or 7z writing fails.
pub fn create_7z_from_path(source: impl AsRef<Path>, destination: impl AsRef<Path>, options: &SevenZCreateOptions) -> Result<SevenZCreateReport, SevenZError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_7z_from_manifest(&manifest, destination, options)
}

/// Creates a `.7z` archive from a manifest.
///
/// # Errors
///
/// Returns [`SevenZError`] when source files cannot be read or 7z writing fails.
pub fn create_7z_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
) -> Result<SevenZCreateReport, SevenZError> {
    create_7z_from_manifest_inner(manifest, destination, options, None, None, None)
}

/// Creates a `.7z` archive from a manifest while emitting source-byte progress.
///
/// # Errors
///
/// Returns [`SevenZError`] when source files cannot be read or 7z writing fails.
pub fn create_7z_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<SevenZCreateReport, SevenZError> {
    let cancellation_token = context.cancellation_token();
    let cancellation_observed = Rc::new(Cell::new(false));
    let progress: SevenZProgressCallback<'_> = Rc::new(RefCell::new(move |path: Option<&str>, bytes: u64| {
        context.bytes_processed(path, bytes);
    }));
    create_7z_from_manifest_inner(manifest, destination, options, Some(&progress), Some(&cancellation_token), Some(&cancellation_observed))
}

fn create_7z_from_manifest_inner(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
    progress: Option<&SevenZProgressCallback<'_>>,
    cancellation_token: Option<&CancellationToken>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
) -> Result<SevenZCreateReport, SevenZError> {
    validate_volume_size(options.volume_size)?;

    let destination = destination.as_ref();
    let mut output = crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })?;
    let output_file = output.file_mut().map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })?;
    let mut writer = ArchiveWriter::new(output_file)?;
    writer.set_encrypt_header(options.encrypt_file_names);
    let encrypted = configure_content_methods(&mut writer, options);
    let mut report = SevenZCreateReport {
        written_entries: 0,
        written_bytes: 0,
        solid: options.solid,
        threads: sevenz_threads(options),
        encrypted,
        volume_size: options.volume_size,
        volume_count: 1,
        warnings: Vec::new(),
    };

    let write_result = if options.solid {
        write_solid_manifest(&mut writer, manifest, options.preserve_metadata, &mut report, progress, cancellation_token, cancellation_observed)
    } else {
        write_non_solid_manifest(&mut writer, manifest, options.preserve_metadata, &mut report, progress, cancellation_token, cancellation_observed)
    };
    map_cancelled_7z_create_result(write_result, cancellation_observed)?;

    map_cancelled_7z_create_result(writer.finish().map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source }), cancellation_observed)?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_7z_temp_archive(output.temp_path(), destination, volume_size, options.replace_existing)?;
    } else {
        output.commit_with_file_replace(options.replace_existing).map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })?;
    }

    Ok(report)
}

fn map_cancelled_7z_create_result<T>(result: Result<T, SevenZError>, cancellation_observed: Option<&Rc<Cell<bool>>>) -> Result<T, SevenZError> {
    match result {
        Err(_) if cancellation_observed.is_some_and(|observed| observed.get()) => Err(SevenZError::Cancelled),
        result => result,
    }
}

struct SevenZProgressReader<'a, R> {
    inner: R,
    archive_path: String,
    progress: Option<SevenZProgressCallback<'a>>,
    cancellation_token: Option<CancellationToken>,
    cancellation_observed: Option<Rc<Cell<bool>>>,
}

impl<'a, R> SevenZProgressReader<'a, R> {
    fn new(
        inner: R,
        archive_path: impl Into<String>,
        progress: Option<SevenZProgressCallback<'a>>,
        cancellation_token: Option<CancellationToken>,
        cancellation_observed: Option<Rc<Cell<bool>>>,
    ) -> Self {
        Self { inner, archive_path: archive_path.into(), progress, cancellation_token, cancellation_observed }
    }
}

impl<R: Read> Read for SevenZProgressReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation_token.as_ref().is_some_and(CancellationToken::is_cancelled) {
            if let Some(observed) = &self.cancellation_observed {
                observed.set(true);
            }
            return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
        }

        let read = self.inner.read(buffer)?;
        if read > 0
            && let Some(progress) = &self.progress
        {
            let read_u64 = u64::try_from(read).map_err(|_| io::Error::other("7z progress byte count overflow"))?;
            progress.borrow_mut()(Some(&self.archive_path), read_u64);
        }
        Ok(read)
    }
}

fn validate_volume_size(volume_size: Option<u64>) -> Result<(), SevenZError> {
    match volume_size {
        Some(size) if size < MIN_VOLUME_SIZE_BYTES => Err(SevenZError::VolumeSizeTooSmall { size, minimum: MIN_VOLUME_SIZE_BYTES }),
        _ => Ok(()),
    }
}

/// Returns true when `path` is a numbered `.7z.001` style volume.
#[must_use]
pub fn is_7z_volume_path(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        parse_7z_volume_file_name(&lower).is_some_and(|(base, _)| has_7z_extension(base))
    })
}

/// Returns whether a requested 7z path has an existing file or numbered input
/// volume beside it. This keeps logical base-path compatibility at the 7z
/// source seam instead of making the archive engine probe unknown formats.
#[must_use]
pub fn has_existing_7z_input(path: &Path) -> bool {
    discover_7z_read_volume_paths(path).is_ok_and(|paths| paths.iter().any(|candidate| candidate.is_file()))
}

/// Returns the complete path-backed input set used by the 7z reader.
pub(crate) fn discover_7z_input_paths(path: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    discover_7z_read_volume_paths(path)
}

fn open_7z_reader(path: &Path) -> Result<SevenZReadSource, SevenZError> {
    let volume_paths = discover_7z_read_volume_paths(path)?;
    if volume_paths.len() > 1 {
        let error_path = volume_paths.first().cloned().unwrap_or_else(|| path.to_path_buf());
        MultiVolumeReader::open(volume_paths).map(SevenZReadSource::Multi).map_err(|source| SevenZError::Io { path: error_path, source })
    } else {
        let read_path = volume_paths.first().map_or(path, PathBuf::as_path);
        File::open(read_path).map(SevenZReadSource::File).map_err(|source| SevenZError::Io { path: read_path.to_path_buf(), source })
    }
}

enum SevenZReadSource {
    File(File),
    Multi(MultiVolumeReader),
}

impl Read for SevenZReadSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            Self::Multi(reader) => reader.read(buffer),
        }
    }
}

impl Seek for SevenZReadSource {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(file) => file.seek(position),
            Self::Multi(reader) => reader.seek(position),
        }
    }
}

/// Lists `.7z` archive entries.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be opened or parsed.
pub fn list_7z(path: impl AsRef<Path>, password: Option<&str>) -> Result<SevenZListing, SevenZError> {
    let path = path.as_ref();
    let password = archive_password(password);
    let mut reader = open_7z_reader(path)?;
    let archive = Archive::read(&mut reader, &password)?;
    let entries = archive
        .files
        .iter()
        .map(|entry| SevenZListEntry {
            name: entry.name().to_owned(),
            kind: entry_kind(entry),
            size: entry.size(),
            compressed_size: entry.compressed_size,
            has_stream: entry.has_stream(),
            modified: entry.has_last_modified_date.then(|| std::time::SystemTime::from(entry.last_modified_date())),
            created: entry.has_creation_date.then(|| std::time::SystemTime::from(entry.creation_date())),
            accessed: entry.has_access_date.then(|| std::time::SystemTime::from(entry.access_date())),
            mode: sevenz_unix_mode(entry),
            crc: if entry.has_crc { u32::try_from(entry.crc).ok() } else { None },
            attributes: entry.has_windows_attributes.then_some(entry.windows_attributes()),
        })
        .collect();

    Ok(SevenZListing { entries, solid: archive.is_solid })
}

/// Reads selected `.7z` entries without writing them, validating that their
/// encrypted/compressed content can be decoded with the supplied password.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, or when its
/// encrypted data requires a missing or incorrect password.
pub fn test_7z_with_password_filter(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<SevenZTestReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let password = archive_password(password);
    let source = open_7z_reader(archive_path)?;
    let mut reader = ArchiveReader::new(source, password)?;
    let mut report = SevenZTestReport { tested_entries: 0, skipped_entries: 0, tested_bytes: 0 };
    let mut callback_error = None;

    let result = reader.for_each_entries(|entry, entry_reader| {
        let path = entry.name().to_owned();
        if entry.is_anti_item() || !selected(&path) {
            if let Err(error) = drain_reader(entry_reader, &path) {
                return Err(callback_failed_with(&mut callback_error, error));
            }
            report.skipped_entries += 1;
            return Ok(true);
        }

        let copied = if entry.is_directory() {
            0
        } else {
            match io::copy(entry_reader, &mut io::sink()) {
                Ok(copied) => copied,
                Err(source) => {
                    return Err(callback_failed_with(&mut callback_error, SevenZError::Io { path: PathBuf::from(&path), source }));
                }
            }
        };
        report.tested_entries += 1;
        report.tested_bytes += copied;
        Ok(true)
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;

    Ok(report)
}

/// Extracts a `.7z` archive through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, or filesystem writes fail.
pub fn extract_7z(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(archive_path, destination, password, policy, None, None, None)
}

/// Stable path-based identity for a 7z entry retained by the engine session.
#[derive(Debug, Clone, Copy)]
pub struct SevenZEntrySelector<'a> {
    /// Raw archive path from the retained listing.
    pub path: &'a str,
    /// Zero-based occurrence among entries with the same path.
    pub occurrence: usize,
}

/// Extracts one retained 7z entry by its stable archive path and duplicate
/// occurrence.  Unlike the legacy index wrapper, this does not list the
/// archive again before opening the extraction reader.
pub(crate) fn extract_7z_entry_by_name_occurrence(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    entry_name: &str,
    occurrence: usize,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<SevenZExtractReport, SevenZError> {
    let selectors = [SevenZEntrySelector { path: entry_name, occurrence }];
    extract_7z_entries_by_name_occurrence(archive_path, destination, password, policy, &selectors, overwrite_resolver)
}

/// Extracts every retained 7z entry matching one of `selectors` in a single
/// pass.
///
/// A 7z archive is parsed as a whole and its payload is usually stored in solid
/// blocks, so extracting a selection one entry at a time reopens the file and
/// re-decodes shared blocks per entry. One pass also means one safety planner,
/// so the aggregate expansion guard covers the whole batch.
pub(crate) fn extract_7z_entries_by_name_occurrence(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    selectors: &[SevenZEntrySelector<'_>],
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<SevenZExtractReport, SevenZError> {
    // Narrow planning to the selected names so the planner accounts only for
    // what this call will write. Duplicate names collapse: they differ by
    // occurrence, which patterns cannot express.
    let mut include_patterns = selectors.iter().map(|selector| selector.path.to_owned()).collect::<Vec<_>>();
    include_patterns.sort_unstable();
    include_patterns.dedup();

    let mut selected_policy = policy;
    selected_policy.include_patterns = include_patterns;
    extract_7z_inner(archive_path, destination, password, selected_policy, overwrite_resolver, None, Some(selectors))
}

/// Extracts a `.7z` archive with an overwrite resolver.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, filesystem writes fail, or the resolver aborts
/// extraction.
pub fn extract_7z_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(archive_path, destination, password, policy, Some(overwrite_resolver), None, None)
}

/// Extracts a `.7z` archive through the shared extraction safety policy with a
/// reporting context.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, or filesystem writes fail.
#[cfg(test)]
fn extract_7z_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(archive_path, destination, password, policy, None, Some(context), None)
}

fn extract_7z_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
    selection: Option<&[SevenZEntrySelector<'_>]>,
) -> Result<SevenZExtractReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })?;

    let password = archive_password(password);
    let source = open_7z_reader(archive_path)?;
    let mut reader = ArchiveReader::new(source, password)?;
    let (decisions, modes) = plan_extraction(reader.archive().files.as_slice(), &destination_root, policy, overwrite_resolver)?;
    let mut report = SevenZExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
    let mut callback_error = None;
    let mut deferred_directories: Vec<(PathBuf, Option<u32>, Option<std::time::SystemTime>)> = Vec::new();
    let mut io_buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];

    let mut entry_occurrences = std::collections::HashMap::<String, usize>::new();
    let result = reader.for_each_entries(|entry, entry_reader| {
        let path = entry.name().to_owned();
        let occurrence = entry_occurrences.entry(path.clone()).or_insert(0);
        let is_selected = selection.is_none_or(|selectors| selectors.iter().any(|s| s.path == path && s.occurrence == *occurrence));
        *occurrence = occurrence.saturating_add(1);
        if !is_selected {
            if let Err(error) = drain_reader(entry_reader, &path) {
                return Err(callback_failed_with(&mut callback_error, error));
            }
            report.skipped_entries += 1;
            return Ok(true);
        }
        if entry.is_anti_item() {
            if let Err(error) = drain_reader(entry_reader, &path) {
                return Err(callback_failed_with(&mut callback_error, error));
            }
            crate::extract_loop::skip_entry(&mut report, context.as_deref_mut(), format!("skipped anti-item {path}"));
            return Ok(true);
        }

        let safety_entry = ExtractionEntry {
            archive_path: path,
            kind: extraction_kind(entry),
            uncompressed_size: Some(entry.size()),
            compressed_size: (entry.compressed_size > 0).then_some(entry.compressed_size),
        };
        let decision = match decisions.get(entry.name()) {
            Some(decision) => decision.clone(),
            None => return Err(callback_failed_with(&mut callback_error, missing_extraction_decision(entry.name()))),
        };
        match crate::extract_loop::process_planned_entry(&mut report, context.as_deref_mut(), &safety_entry, decision, &mut |action, report, context| {
            match action {
                crate::extract_loop::EntryAction::Skip => {
                    drain_reader(entry_reader, entry.name())?;
                    Ok(0)
                }
                crate::extract_loop::EntryAction::Write(decision) => write_sevenz_entry(
                    entry,
                    entry_reader,
                    &decision,
                    modes.get(entry.name()).copied().flatten(),
                    &mut deferred_directories,
                    report,
                    context,
                    &mut io_buffer,
                ),
            }
        }) {
            Ok(_) => Ok(true),
            Err(error) => Err(callback_failed_with(&mut callback_error, error)),
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;
    apply_deferred_sevenz_directory_metadata(&deferred_directories)?;

    Ok(report)
}

/// Copies one retained regular 7z entry by its stable archive path and
/// duplicate occurrence without re-listing the archive.
pub(crate) fn copy_7z_entry_by_name_occurrence<W: Write + ?Sized>(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    target_name: &str,
    target_occurrence: usize,
    output: &mut W,
) -> Result<u64, SevenZError> {
    let archive_path = archive_path.as_ref();
    let password = archive_password(password);
    let source = open_7z_reader(archive_path)?;
    let mut reader = ArchiveReader::new(source, password)?;

    let mut occurrences = std::collections::HashMap::<String, usize>::new();
    let mut copied = None;
    let mut callback_error = None;
    let result = reader.for_each_entries(|entry, entry_reader| {
        let occurrence = occurrences.entry(entry.name().to_owned()).or_insert(0);
        let selected = entry.name() == target_name && *occurrence == target_occurrence;
        *occurrence = occurrence.saturating_add(1);
        if !selected {
            drain_reader(entry_reader, entry.name()).map_err(|error| callback_failed_with(&mut callback_error, error))?;
            return Ok(true);
        }
        if entry.is_directory() || entry.is_anti_item() {
            drain_reader(entry_reader, entry.name()).map_err(|error| callback_failed_with(&mut callback_error, error))?;
            return Err(callback_failed_with(
                &mut callback_error,
                SevenZError::Io {
                    path: PathBuf::from(entry.name()),
                    source: io::Error::new(io::ErrorKind::InvalidInput, "retained 7z entry is not a regular file"),
                },
            ));
        }
        copied = Some(
            io::copy(entry_reader, output)
                .map_err(|source| callback_failed_with(&mut callback_error, SevenZError::Io { path: PathBuf::from(entry.name()), source }))?,
        );
        Ok(false)
    });
    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;
    copied.ok_or_else(|| SevenZError::Io {
        path: archive_path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::NotFound, "retained 7z entry ID is not present in this archive"),
    })
}

fn configure_content_methods<W: io::Write + io::Seek>(writer: &mut ArchiveWriter<W>, options: &SevenZCreateOptions) -> bool {
    let password = options.password.as_ref().map(SecretString::expose_secret).filter(|password| !password.is_empty());
    let lzma2_options = sevenz_lzma2_options(options);

    match (password, lzma2_options) {
        (Some(password), Some(lzma2_options)) => {
            writer.set_content_methods(vec![AesEncoderOptions::new(Password::from(password)).into(), lzma2_options.into()]);
            true
        }
        (Some(password), None) => {
            writer.set_content_methods(vec![AesEncoderOptions::new(Password::from(password)).into(), EncoderMethod::LZMA2.into()]);
            true
        }
        (None, Some(lzma2_options)) => {
            writer.set_content_methods(vec![lzma2_options.into()]);
            false
        }
        (None, None) => false,
    }
}

fn sevenz_lzma2_options(options: &SevenZCreateOptions) -> Option<Lzma2Options> {
    let level = options.level.unwrap_or(DEFAULT_SEVENZ_COMPRESSION_LEVEL);
    let Some(threads) = sevenz_threads(options) else {
        return options.level.map(Lzma2Options::from_level);
    };

    if threads <= 1 {
        return Some(Lzma2Options::from_level(level));
    }

    Some(Lzma2Options::from_level_mt(level, threads, options.chunk_size.unwrap_or(DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES)))
}

fn sevenz_threads(options: &SevenZCreateOptions) -> Option<u32> {
    options.threads.map(|threads| threads.clamp(1, MAX_SEVENZ_LZMA2_THREADS))
}

fn archive_password(password: Option<&str>) -> Password {
    crate::secrets::normalized_password(password).map_or_else(Password::empty, Password::from)
}

fn map_7z_error(source: sevenz_rust2::Error) -> SevenZError {
    match source {
        sevenz_rust2::Error::PasswordRequired => SevenZError::PasswordRequired,
        sevenz_rust2::Error::MaybeBadPassword(_) => SevenZError::InvalidPassword,
        source => SevenZError::SevenZ(source),
    }
}

/// One solid-mode file pair: the archive entry plus its source reader.
type SolidFilePair<'a> = (ArchiveEntry, SourceReader<SevenZProgressReader<'a, File>>);

fn write_non_solid_manifest<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    manifest: &ArchiveManifest,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
    progress: Option<&SevenZProgressCallback<'_>>,
    cancellation_token: Option<&CancellationToken>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
) -> Result<(), SevenZError> {
    for entry in &manifest.entries {
        append_manifest_entry(writer, entry, preserve_metadata, report, progress, cancellation_token, cancellation_observed, false)?;
    }

    Ok(())
}

fn write_solid_manifest<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    manifest: &ArchiveManifest,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
    progress: Option<&SevenZProgressCallback<'_>>,
    cancellation_token: Option<&CancellationToken>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
) -> Result<(), SevenZError> {
    let mut solid_entries = Vec::new();
    let mut solid_readers = Vec::new();

    for entry in &manifest.entries {
        if let Some((archive_entry, reader)) =
            append_manifest_entry(writer, entry, preserve_metadata, report, progress, cancellation_token, cancellation_observed, true)?
        {
            solid_entries.push(archive_entry);
            solid_readers.push(reader);
        }
    }

    if !solid_entries.is_empty() {
        writer.push_archive_entries(solid_entries, solid_readers)?;
    }

    Ok(())
}

/// Appends one manifest entry to the archive, either immediately (non-solid
/// mode) or returning the file pair for a single batched push (solid mode).
///
/// The Directory/Symlink/Other arms are byte-identical between the two modes;
/// only the File arm differs in where the reader goes.
#[allow(clippy::too_many_arguments)]
fn append_manifest_entry<'a, W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
    progress: Option<&SevenZProgressCallback<'a>>,
    cancellation_token: Option<&CancellationToken>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
    solid: bool,
) -> Result<Option<SolidFilePair<'a>>, SevenZError> {
    match entry.file_type {
        ManifestFileType::Directory => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            writer.push_archive_entry::<&[u8]>(archive_entry, None)?;
            report.written_entries += 1;
        }
        ManifestFileType::File => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            let Some(file) = open_member_source(&entry.source_path, &mut report.warnings) else {
                return Ok(None);
            };
            let reader =
                SevenZProgressReader::new(file, entry.archive_path.clone(), progress.cloned(), cancellation_token.cloned(), cancellation_observed.cloned());
            let pending = if solid {
                Some((archive_entry, SourceReader::new(reader)))
            } else {
                writer.push_archive_entry(archive_entry, Some(reader))?;
                None
            };
            report.written_entries += 1;
            report.written_bytes += entry.size;
            return Ok(pending);
        }
        ManifestFileType::Symlink => {
            report.warnings.push(format!("skipped symlink {}: 7z backend does not materialize symlink entries in v1", entry.archive_path));
        }
        ManifestFileType::Other => {
            report.warnings.push(format!("skipped unsupported entry {}: 7z backend only writes files and directories in v1", entry.archive_path));
        }
    }

    Ok(None)
}

fn sevenz_archive_entry(entry: &ManifestEntry, preserve_metadata: bool) -> ArchiveEntry {
    if preserve_metadata {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut archive_entry = ArchiveEntry::from_path(&entry.source_path, entry.archive_path.clone());
        #[cfg(unix)]
        if let Some(mode) = entry.permissions.unix_mode {
            archive_entry.has_windows_attributes = true;
            archive_entry.windows_attributes |= SEVENZ_UNIX_ATTRIBUTES_FLAG | ((mode & SEVENZ_MODE_MASK) << 16);
        }
        return archive_entry;
    }

    match entry.file_type {
        ManifestFileType::Directory => ArchiveEntry::new_directory(&entry.archive_path),
        ManifestFileType::File | ManifestFileType::Symlink | ManifestFileType::Other => ArchiveEntry::new_file(&entry.archive_path),
    }
}

fn entry_kind(entry: &ArchiveEntry) -> SevenZEntryKind {
    if entry.is_anti_item() {
        SevenZEntryKind::AntiItem
    } else if entry.is_directory() {
        SevenZEntryKind::Directory
    } else {
        SevenZEntryKind::File
    }
}

/// Maps a 7z entry to an extraction safety kind.
///
/// `sevenz_rust2` exposes no link-target metadata, so every non-directory
/// entry — including hostile symlink entries a crafted archive may declare —
/// extracts as a regular file. This is deliberately safer than materializing
/// links we cannot validate: a symlink entry whose target we cannot parse
/// can never make extraction write outside the destination. Revisit only if
/// the library starts exposing link metadata.
fn extraction_kind(entry: &ArchiveEntry) -> ExtractionEntryKind {
    if entry.is_directory() { ExtractionEntryKind::Directory } else { ExtractionEntryKind::File }
}

fn sevenz_unix_mode(entry: &ArchiveEntry) -> Option<u32> {
    if entry.has_windows_attributes && (entry.windows_attributes() & SEVENZ_UNIX_ATTRIBUTES_FLAG) != 0 {
        Some((entry.windows_attributes() >> 16) & SEVENZ_MODE_MASK)
    } else {
        None
    }
}

fn apply_sevenz_metadata(path: &Path, unix_mode: Option<u32>, modified_time: Option<std::time::SystemTime>) -> Result<(), SevenZError> {
    let file_time = modified_time.map(filetime::FileTime::from_system_time);
    crate::extract_materialize::apply_metadata(path, unix_mode, file_time).map_err(|source| SevenZError::Io { path: path.to_path_buf(), source })
}

fn apply_deferred_sevenz_directory_metadata(directories: &[(PathBuf, Option<u32>, Option<std::time::SystemTime>)]) -> Result<(), SevenZError> {
    crate::extract_loop::apply_deferred_directory_metadata(directories, |(path, unix_mode, modified_time)| {
        apply_sevenz_metadata(path, *unix_mode, *modified_time)
    })
}

type SevenZExtractionDecisions = HashMap<String, ExtractionDecision>;
type SevenZUnixModes = HashMap<String, Option<u32>>;

fn plan_extraction(
    entries: &[ArchiveEntry],
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<(SevenZExtractionDecisions, SevenZUnixModes), SevenZError> {
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(destination, policy, overwrite_resolver);
    let mut decisions = HashMap::with_capacity(entries.len());
    let mut modes = HashMap::with_capacity(entries.len());

    for entry in entries {
        if entry.is_anti_item() {
            continue;
        }

        let kind = extraction_kind(entry);
        let safety_entry = ExtractionEntry {
            archive_path: entry.name().to_owned(),
            kind,
            uncompressed_size: Some(entry.size()),
            compressed_size: (entry.compressed_size > 0).then_some(entry.compressed_size),
        };
        let decision = planner.validate_entry(&safety_entry)?;
        decisions.insert(entry.name().to_owned(), decision);
        modes.insert(entry.name().to_owned(), sevenz_unix_mode(entry));
    }

    Ok((decisions, modes))
}

#[allow(clippy::too_many_arguments)]
fn write_sevenz_entry(
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
    decision: &crate::extract_loop::WriteDecision<'_>,
    unix_mode: Option<u32>,
    deferred_directories: &mut Vec<(PathBuf, Option<u32>, Option<std::time::SystemTime>)>,
    report: &mut SevenZExtractReport,
    context: Option<&mut JobContext<'_>>,
    io_buffer: &mut [u8],
) -> Result<u64, SevenZError> {
    if decision.replace_existing && entry.is_directory() {
        crate::safety::remove_destination_for_replace(decision.destination_path)
            .map_err(|source| SevenZError::Io { path: decision.destination_path.to_path_buf(), source })?;
    }
    if entry.is_directory() {
        fs::create_dir_all(decision.destination_path).map_err(|source| SevenZError::Io { path: decision.destination_path.to_path_buf(), source })?;
        deferred_directories.push((decision.destination_path.to_path_buf(), unix_mode, sevenz_modified_time(entry)));
        report.written_entries += 1;
        Ok(0)
    } else {
        let written_bytes = crate::extract_loop::copy_file_entry(
            decision.destination_path,
            decision.replace_existing,
            Some(entry.name()),
            context,
            io_buffer,
            |buf| reader.read(buf).map_err(|source| SevenZError::Io { path: decision.destination_path.to_path_buf(), source }),
            |source, path| SevenZError::Io { path: path.to_path_buf(), source },
        )?;
        apply_sevenz_metadata(decision.destination_path, unix_mode, sevenz_modified_time(entry))?;
        report.written_entries += 1;
        report.written_bytes += written_bytes;
        Ok(written_bytes)
    }
}

fn sevenz_modified_time(entry: &ArchiveEntry) -> Option<std::time::SystemTime> {
    if entry.has_last_modified_date { Some(std::time::SystemTime::from(entry.last_modified_date())) } else { None }
}

fn missing_extraction_decision(archive_path: &str) -> SevenZError {
    SevenZError::SevenZ(sevenz_rust2::Error::Other(Cow::Owned(format!("missing extraction decision for {archive_path}"))))
}

fn drain_reader(reader: &mut dyn Read, archive_path: &str) -> Result<(), SevenZError> {
    io::copy(reader, &mut io::sink()).map_err(|source| SevenZError::Io { path: PathBuf::from(archive_path), source })?;
    Ok(())
}

/// Parks a real backend error and returns the sentinel error the callback
/// must yield instead.
///
/// `sevenz_rust2`'s `for_each_entries` callback cannot return the backend's
/// own error type — it is required to return `Result<bool, sevenz_rust2::Error>`.
/// Without this dance the real error (with its path and source) would be
/// degraded into a generic library error. The parked error is returned by
/// the caller immediately after the callback loop completes.
fn callback_failed_with<E>(callback_error: &mut Option<E>, error: E) -> sevenz_rust2::Error {
    *callback_error = Some(error);
    callback_failed_error()
}

fn callback_failed_error() -> sevenz_rust2::Error {
    sevenz_rust2::Error::Other(Cow::Borrowed("zmanager extraction callback failed"))
}

#[cfg(test)]
mod tests {
    use super::{SevenZCreateOptions, SevenZEntryKind, SevenZError, create_7z_from_path, extract_7z, extraction_kind, list_7z, test_7z_with_password_filter};
    use crate::safety::{ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError};
    use crate::secrets::SecretString;
    use crate::test_support::TestDir;
    use std::fs::{self, File};
    use std::time::SystemTime;

    #[test]
    fn policy_skips_are_reported_to_job_context() {
        use crate::jobs::{CancellationToken, JobContext, JobEvent};

        // Regression for CR-121: the 7z backend's inline skip-warning block
        // used to omit the `context.warning` call the other four backends
        // make, so policy skips vanished from the job context.
        let temp = TestDir::new("sevenz_policy_skip_warning_context");
        temp.write_file("project/keep.txt", b"keep");
        temp.write_file("project/excluded.txt", b"exclude");
        let archive = temp.path("archive.7z");
        create_7z_from_path(temp.path("project"), &archive, &SevenZCreateOptions::default()).unwrap();

        let policy = ExtractionPolicy { exclude_patterns: vec!["**/excluded.txt".to_owned()], ..ExtractionPolicy::default() };
        let token = CancellationToken::new();
        let mut warnings = Vec::new();
        let mut sink = |event: JobEvent| {
            if let JobEvent::Warning { message } = event {
                warnings.push(message);
            }
        };
        let mut context = JobContext::new(&token, &mut sink);
        let report = super::extract_7z_with_context(&archive, temp.path("out"), None, policy, &mut context).unwrap();

        assert!(report.written_entries >= 1);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("excluded.txt")));
        assert!(warnings.iter().any(|warning| warning.contains("excluded.txt")));
    }

    #[test]
    fn extraction_kind_never_materializes_link_entries() {
        use sevenz_rust2::ArchiveEntry;

        // sevenz_rust2 exposes no link-target metadata, so even an entry a
        // hostile archive declares as something link-like must plan as a
        // regular file, never as a symlink or hardlink that could be
        // materialized outside the destination.
        let entry = ArchiveEntry { name: "payload.bin".to_owned(), ..ArchiveEntry::default() };
        assert_eq!(extraction_kind(&entry), ExtractionEntryKind::File);

        let directory = ArchiveEntry { is_directory: true, ..entry };
        assert_eq!(extraction_kind(&directory), ExtractionEntryKind::Directory);
    }

    #[test]
    fn application_of_metadata_propagates_io_errors() {
        let temp = TestDir::new("sevenz_metadata_error_prop");
        let nonexistent = temp.path("does_not_exist");

        let result = super::apply_sevenz_metadata(&nonexistent, Some(0o644), Some(SystemTime::now()));

        assert!(matches!(result, Err(SevenZError::Io { .. })));
    }

    // The permission-mode assertions are Unix-only and the source path and
    // extracted metadata bindings are only meaningfully exercised there, so
    // the whole test is gated instead of sprinkling `unused_variables` allows.
    #[cfg(unix)]
    #[test]

    fn preserves_metadata_during_creation_and_extraction() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TestDir::new("preserves_metadata_sevenz");
        let (path, _fixture_mtime) = crate::test_support::script_fixture_with_metadata(&temp);
        fs::set_permissions(temp.path("project"), fs::Permissions::from_mode(0o1750)).unwrap();
        let mtime = filetime::FileTime::from_unix_time(1_500_000_000, 234_567_800);
        filetime::set_file_mtime(&path, mtime).unwrap();

        let archive = temp.path("archive.7z");

        create_7z_from_path(temp.path("project"), &archive, &SevenZCreateOptions { preserve_metadata: true, ..SevenZCreateOptions::default() }).unwrap();
        extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default()).unwrap();

        let out_path = temp.path("out/project/script.sh");
        let metadata = fs::metadata(&out_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        let directory_metadata = fs::metadata(temp.path("out/project")).unwrap();
        assert_eq!(directory_metadata.permissions().mode() & 0o7777, 0o1750);
        assert_eq!(metadata.mtime(), 1_500_000_000);
        assert_eq!(metadata.mtime_nsec(), 234_567_800);

        // Check mtime. The test creates the archive with mtime=1500000000
        let mtime_extracted = filetime::FileTime::from_last_modification_time(&metadata);
        let diff = (mtime_extracted.unix_seconds() - mtime.unix_seconds()).abs();
        assert!(diff <= 2, "extracted mtime diff {diff} is greater than 2 seconds");
    }

    #[test]

    fn default_7z_create_options_request_parallel_lzma2_when_available() {
        let options = SevenZCreateOptions::default();

        assert_eq!(options.threads, crate::tar_metadata::available_parallelism_at_least_two());
        assert_eq!(options.chunk_size, Some(super::DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES));
    }

    #[test]
    fn sevenz_thread_count_is_clamped_to_backend_limits() {
        let mut options = SevenZCreateOptions { threads: Some(0), ..SevenZCreateOptions::default() };
        assert_eq!(super::sevenz_threads(&options), Some(1));

        options.threads = Some(super::MAX_SEVENZ_LZMA2_THREADS + 1);
        assert_eq!(super::sevenz_threads(&options), Some(super::MAX_SEVENZ_LZMA2_THREADS));
    }

    #[test]
    fn create_report_includes_configured_7z_thread_count() {
        let temp = TestDir::new("create_report_includes_configured_7z_thread_count");
        temp.write_file("payload/file.txt", b"hello");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                level: Some(1),
                threads: Some(2),
                chunk_size: Some(crate::sevenz_volume::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.threads, Some(2));
        extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default()).unwrap();
        assert_eq!(fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(), "hello");
    }

    #[test]
    fn creates_and_extracts_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        temp.create_dir("payload/empty");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(temp.path("payload"), &archive, &SevenZCreateOptions::default()).unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default()).unwrap();

        assert!(report.solid);
        assert_eq!(report.written_bytes, 10);
        assert!(listing.solid);
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/file.txt"));
        assert!(listing.entries.iter().any(|entry| entry.kind == SevenZEntryKind::Directory));
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(), "hello");
        assert!(temp.path("out/payload/empty").is_dir());
    }

    #[test]
    fn creates_and_extracts_non_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_non_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        let archive = temp.path("payload.7z");

        create_7z_from_path(temp.path("payload"), &archive, &SevenZCreateOptions { solid: false, ..SevenZCreateOptions::default() }).unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default()).unwrap();

        assert!(!listing.solid);
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(fs::read_to_string(temp.path("out/payload/nested/second.txt")).unwrap(), "world");
    }

    #[test]
    fn encrypted_archive_requires_correct_password() {
        let temp = TestDir::new("encrypted_archive_requires_correct_password");
        temp.write_file("payload/file.txt", b"secret");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { password: Some(SecretString::from("correct horse")), ..SevenZCreateOptions::default() },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(matches!(list_7z(&archive, None), Err(SevenZError::PasswordRequired)));
        assert!(matches!(extract_7z(&archive, temp.path("wrong"), Some("wrong password"), ExtractionPolicy::default()), Err(SevenZError::InvalidPassword)));
        assert!(matches!(test_7z_with_password_filter(&archive, None, |_| true), Err(SevenZError::PasswordRequired)));
        assert!(matches!(test_7z_with_password_filter(&archive, Some("wrong password"), |_| true), Err(SevenZError::InvalidPassword)));
        let verification = test_7z_with_password_filter(&archive, Some("correct horse"), |entry| entry == "payload/file.txt").unwrap();
        assert_eq!(verification.tested_entries, 1);
        assert_eq!(verification.tested_bytes, 6);
        assert_eq!(verification.skipped_entries, 1);

        let listing = list_7z(&archive, Some("correct horse")).unwrap();
        let extract_report = extract_7z(&archive, temp.path("out"), Some("correct horse"), ExtractionPolicy::default()).unwrap();

        assert_eq!(listing.entries.len(), 2);
        assert_eq!(extract_report.written_bytes, 6);
        assert_eq!(fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(), "secret");
    }

    #[test]
    fn encrypted_archive_can_leave_file_names_visible() {
        let temp = TestDir::new("encrypted_archive_can_leave_file_names_visible");
        temp.write_file("payload/file.txt", b"secret");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { password: Some(SecretString::from("correct horse")), encrypt_file_names: false, ..SevenZCreateOptions::default() },
        )
        .unwrap();

        assert!(report.encrypted);
        let listing = list_7z(&archive, None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/file.txt"));
        assert!(matches!(
            extract_7z(&archive, temp.path("missing-password"), None, ExtractionPolicy::default()),
            Err(SevenZError::PasswordRequired | SevenZError::InvalidPassword)
        ));
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal");
        let archive = temp.path("hostile.7z");
        let output = File::create(&archive).unwrap();
        let mut writer = sevenz_rust2::ArchiveWriter::new(output).unwrap();
        writer.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file("../evil.txt"), Some(&b"owned"[..])).unwrap();
        writer.finish().unwrap();

        let error = extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default()).unwrap_err();

        assert!(matches!(error, SevenZError::Safety(ExtractionSafetyError::ParentTraversal { .. })));
        assert!(!temp.path("evil.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn creation_skips_symlinks_with_warning() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("creation_skips_symlinks_with_warning");
        temp.write_file("payload/file.txt", b"hello");
        symlink("file.txt", temp.path("payload/link.txt")).unwrap();
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(temp.path("payload"), &archive, &SevenZCreateOptions::default()).unwrap();
        let listing = list_7z(&archive, None).unwrap();

        assert_eq!(report.warnings.len(), 1);
        assert!(!listing.entries.iter().any(|entry| entry.name == "payload/link.txt"));
    }
}
