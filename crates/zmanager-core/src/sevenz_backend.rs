use crate::jobs::{CancellationToken, JobCancelled, JobContext};
use crate::manifest::{
    ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive,
};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
use sevenz_rust2::{
    Archive, ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderMethod, Password, SourceReader,
};
use std::borrow::Cow;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MIN_VOLUME_SIZE_BYTES: u64 = 1_048_576;
const DEFAULT_SEVENZ_COMPRESSION_LEVEL: u32 = 6;
const DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_SEVENZ_LZMA2_THREADS: u32 = 256;
const SEVENZ_VOLUME_EXTENSION_WIDTH: usize = 3;
const SEVENZ_MODE_MASK: u32 = 0o0777;
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
            threads: default_sevenz_threads(),
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
            Self::VolumeSizeTooSmall { size, minimum } => write!(
                f,
                "7z volume size {size} bytes is smaller than the minimum {minimum} bytes"
            ),
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
            Self::VolumeSizeTooSmall { .. }
            | Self::PasswordRequired
            | Self::InvalidPassword
            | Self::Cancelled => None,
        }
    }
}

impl From<PlanError> for SevenZError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<sevenz_rust2::Error> for SevenZError {
    fn from(source: sevenz_rust2::Error) -> Self {
        map_7z_error(source)
    }
}

impl From<ExtractionSafetyError> for SevenZError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for SevenZError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Creates a `.7z` archive from a source path.
///
/// # Errors
///
/// Returns [`SevenZError`] when planning, filesystem reads, or 7z writing fails.
pub fn create_7z_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
) -> Result<SevenZCreateReport, SevenZError> {
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
    let progress: SevenZProgressCallback<'_> =
        Rc::new(RefCell::new(move |path: Option<&str>, bytes: u64| {
            context.bytes_processed(path, bytes);
        }));
    create_7z_from_manifest_inner(
        manifest,
        destination,
        options,
        Some(&progress),
        Some(&cancellation_token),
        Some(&cancellation_observed),
    )
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
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            SevenZError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let output_file = output.file_mut().map_err(|source| SevenZError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
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
        write_solid_manifest(
            &mut writer,
            manifest,
            options.preserve_metadata,
            &mut report,
            progress,
            cancellation_token,
            cancellation_observed,
        )
    } else {
        write_non_solid_manifest(
            &mut writer,
            manifest,
            options.preserve_metadata,
            &mut report,
            progress,
            cancellation_token,
            cancellation_observed,
        )
    };
    map_cancelled_7z_create_result(write_result, cancellation_observed)?;

    map_cancelled_7z_create_result(
        writer.finish().map_err(|source| SevenZError::Io {
            path: destination.to_path_buf(),
            source,
        }),
        cancellation_observed,
    )?;
    if let Some(volume_size) = options.volume_size {
        output.close();
        report.volume_count = split_7z_temp_archive(
            output.temp_path(),
            destination,
            volume_size,
            options.replace_existing,
        )?;
    } else {
        output
            .commit_with_file_replace(options.replace_existing)
            .map_err(|source| SevenZError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
    }

    Ok(report)
}

fn map_cancelled_7z_create_result<T>(
    result: Result<T, SevenZError>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
) -> Result<T, SevenZError> {
    match result {
        Err(_) if cancellation_observed.is_some_and(|observed| observed.get()) => {
            Err(SevenZError::Cancelled)
        }
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
        Self {
            inner,
            archive_path: archive_path.into(),
            progress,
            cancellation_token,
            cancellation_observed,
        }
    }
}

impl<R: Read> Read for SevenZProgressReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            if let Some(observed) = &self.cancellation_observed {
                observed.set(true);
            }
            return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
        }

        let read = self.inner.read(buffer)?;
        if read > 0
            && let Some(progress) = &self.progress
        {
            let read_u64 = u64::try_from(read)
                .map_err(|_| io::Error::other("7z progress byte count overflow"))?;
            progress.borrow_mut()(Some(&self.archive_path), read_u64);
        }
        Ok(read)
    }
}

fn validate_volume_size(volume_size: Option<u64>) -> Result<(), SevenZError> {
    match volume_size {
        Some(size) if size < MIN_VOLUME_SIZE_BYTES => Err(SevenZError::VolumeSizeTooSmall {
            size,
            minimum: MIN_VOLUME_SIZE_BYTES,
        }),
        _ => Ok(()),
    }
}

fn split_7z_temp_archive(
    archive_path: &Path,
    destination: &Path,
    volume_size: u64,
    replace_existing: bool,
) -> Result<usize, SevenZError> {
    let archive_size = fs::metadata(archive_path)
        .map_err(|source| SevenZError::Io {
            path: archive_path.to_path_buf(),
            source,
        })?
        .len();
    let volume_count = split_volume_count(archive_size, volume_size).ok_or_else(|| {
        io_error(
            destination,
            io::ErrorKind::InvalidInput,
            "too many 7z volumes",
        )
    })?;
    let volume_paths = sevenz_volume_paths(destination, volume_count)?;

    let existing_volume_paths = existing_7z_volume_paths(destination)?;
    ensure_split_destinations_available(
        destination,
        &volume_paths,
        &existing_volume_paths,
        replace_existing,
    )?;

    let archive_file = File::open(archive_path).map_err(|source| SevenZError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = BufReader::new(archive_file);
    let mut volume_outputs = Vec::with_capacity(volume_paths.len());

    for (index, volume_path) in volume_paths.iter().enumerate() {
        let mut output =
            crate::atomic_file::AtomicOutputFile::create(volume_path).map_err(|source| {
                SevenZError::Io {
                    path: volume_path.clone(),
                    source,
                }
            })?;
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(volume_size))
            .ok_or_else(|| {
                io_error(
                    volume_path,
                    io::ErrorKind::InvalidInput,
                    "7z volume offset overflow",
                )
            })?;
        let bytes_to_copy = archive_size.saturating_sub(offset).min(volume_size);
        let output_file = output.file_mut().map_err(|source| SevenZError::Io {
            path: volume_path.clone(),
            source,
        })?;
        copy_exact_volume_bytes(&mut archive, output_file, bytes_to_copy, volume_path)?;
        output.close();
        volume_outputs.push(output);
    }

    let created_volume_count = volume_paths.len();
    remove_split_destinations_for_replace(destination, &existing_volume_paths, replace_existing)?;
    for (output, volume_path) in volume_outputs.into_iter().zip(volume_paths) {
        output
            .commit_with_file_replace(replace_existing)
            .map_err(|source| SevenZError::Io {
                path: volume_path,
                source,
            })?;
    }

    Ok(created_volume_count)
}

fn split_volume_count(archive_size: u64, volume_size: u64) -> Option<usize> {
    let count = archive_size.max(1).div_ceil(volume_size);
    usize::try_from(count).ok()
}

fn sevenz_volume_paths(destination: &Path, count: usize) -> Result<Vec<PathBuf>, SevenZError> {
    let mut paths = Vec::with_capacity(count);
    for index in 1..=count {
        let index = u64::try_from(index).map_err(|_| {
            io_error(
                destination,
                io::ErrorKind::InvalidInput,
                "too many 7z volumes",
            )
        })?;
        paths.push(sevenz_volume_path(destination, index));
    }
    Ok(paths)
}

fn sevenz_volume_path(destination: &Path, one_based_index: u64) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(format!(
        ".{one_based_index:0SEVENZ_VOLUME_EXTENSION_WIDTH$}"
    ));
    PathBuf::from(path)
}

fn ensure_split_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), SevenZError> {
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
) -> Result<(), SevenZError> {
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
        Err(source) => Err(SevenZError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_split_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), SevenZError> {
    if !replace_existing {
        return Ok(());
    }

    for path in existing_volume_paths {
        remove_file_destination_for_replace(path)?;
    }
    remove_file_destination_for_replace(destination)
}

fn remove_file_destination_for_replace(path: &Path) -> Result<(), SevenZError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| SevenZError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SevenZError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn existing_7z_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(destination_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let directory = destination.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(SevenZError::Io {
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
        if let Some((base_name, part)) = parse_7z_volume_file_name(candidate_name)
            && base_name == destination_name
        {
            paths.insert(part, entry.path());
        }
    }

    Ok(paths.into_values().collect())
}

fn parse_7z_volume_file_name(name: &str) -> Option<(&str, u32)> {
    let (base, number) = name.rsplit_once('.')?;
    if number.len() != SEVENZ_VOLUME_EXTENSION_WIDTH
        || !number.chars().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

/// Returns true when `path` is a numbered `.7z.001` style volume.
#[must_use]
pub fn is_7z_volume_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            parse_7z_volume_file_name(&lower).is_some_and(|(base, _)| has_7z_extension(base))
        })
}

fn open_7z_reader(path: &Path) -> Result<SevenZReadSource, SevenZError> {
    let volume_paths = discover_7z_read_volume_paths(path)?;
    if volume_paths.len() > 1 {
        MultiVolumeReader::open(volume_paths).map(SevenZReadSource::Multi)
    } else {
        let read_path = volume_paths.first().map_or(path, PathBuf::as_path);
        File::open(read_path)
            .map(SevenZReadSource::File)
            .map_err(|source| SevenZError::Io {
                path: read_path.to_path_buf(),
                source,
            })
    }
}

fn discover_7z_read_volume_paths(path: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(vec![path.to_path_buf()]);
    };
    let lower_name = file_name.to_ascii_lowercase();
    let volume_base = if let Some((base, _)) = parse_7z_volume_file_name(&lower_name) {
        if !has_7z_extension(base) {
            return Ok(vec![path.to_path_buf()]);
        }
        base.to_owned()
    } else if has_7z_extension(&lower_name) {
        lower_name
    } else {
        return Ok(vec![path.to_path_buf()]);
    };
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![path.to_path_buf()]);
        }
        Err(source) => {
            return Err(SevenZError::Io {
                path: directory.to_path_buf(),
                source,
            });
        }
    };

    let mut parts = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        if let Some((candidate_base, part)) = parse_7z_volume_file_name(&candidate_lower)
            && candidate_base == volume_base
        {
            parts.insert(part, entry.path());
        }
    }

    if parts.is_empty() {
        return Ok(vec![path.to_path_buf()]);
    }
    let max_part = *parts.keys().last().unwrap_or(&0);
    for expected in 1..=max_part {
        if !parts.contains_key(&expected) {
            return Err(io_error(
                path,
                io::ErrorKind::NotFound,
                format!("missing 7z volume part {expected:03}"),
            ));
        }
    }
    Ok(parts.into_values().collect())
}

fn has_7z_extension(value: &str) -> bool {
    Path::new(value)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
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

struct MultiVolumeReader {
    parts: Vec<MultiVolumePart>,
    total_len: u64,
    position: u64,
}

struct MultiVolumePart {
    path: PathBuf,
    file: File,
    start: u64,
    len: u64,
}

impl MultiVolumeReader {
    fn open(paths: Vec<PathBuf>) -> Result<Self, SevenZError> {
        let mut parts = Vec::with_capacity(paths.len());
        let mut total_len = 0u64;
        for path in paths {
            let file = File::open(&path).map_err(|source| SevenZError::Io {
                path: path.clone(),
                source,
            })?;
            let len = file
                .metadata()
                .map_err(|source| SevenZError::Io {
                    path: path.clone(),
                    source,
                })?
                .len();
            parts.push(MultiVolumePart {
                path,
                file,
                start: total_len,
                len,
            });
            total_len = total_len.checked_add(len).ok_or_else(|| {
                io_error(
                    Path::new("archive.7z.001"),
                    io::ErrorKind::InvalidInput,
                    "7z volume set is too large",
                )
            })?;
        }
        Ok(Self {
            parts,
            total_len,
            position: 0,
        })
    }

    fn current_part_index(&self) -> Option<usize> {
        self.parts.iter().position(|part| {
            self.position >= part.start && self.position < part.start.saturating_add(part.len)
        })
    }
}

impl Read for MultiVolumeReader {
    fn read(&mut self, mut buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.total_len || buffer.is_empty() {
            return Ok(0);
        }

        let mut copied = 0usize;
        while !buffer.is_empty() && self.position < self.total_len {
            let Some(index) = self.current_part_index() else {
                break;
            };
            let part = &mut self.parts[index];
            let offset = self.position.saturating_sub(part.start);
            let remaining_in_part = usize::try_from(part.len.saturating_sub(offset))
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            part.file.seek(SeekFrom::Start(offset))?;
            let read = part.file.read(&mut buffer[..remaining_in_part])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("unexpected EOF in {}", part.path.display()),
                ));
            }
            self.position = self
                .position
                .checked_add(u64::try_from(read).unwrap_or(0))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "7z volume position overflow")
                })?;
            copied += read;
            buffer = &mut buffer[read..];
        }
        Ok(copied)
    }
}

impl Seek for MultiVolumeReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => i128::from(self.total_len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before start of 7z volume set",
            ));
        }
        self.position = u64::try_from(target).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "7z volume seek target overflow",
            )
        })?;
        Ok(self.position)
    }
}

fn copy_exact_volume_bytes<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    bytes_to_copy: u64,
    volume_path: &Path,
) -> Result<(), SevenZError> {
    let mut limited = reader.take(bytes_to_copy);
    let copied = io::copy(&mut limited, writer).map_err(|source| SevenZError::Io {
        path: volume_path.to_path_buf(),
        source,
    })?;
    if copied != bytes_to_copy {
        return Err(io_error(
            volume_path,
            io::ErrorKind::UnexpectedEof,
            "7z temp archive ended before volume was filled",
        ));
    }
    Ok(())
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> SevenZError {
    SevenZError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(kind, message.into()),
    }
}

/// Lists `.7z` archive entries.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be opened or parsed.
pub fn list_7z(
    path: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<SevenZListing, SevenZError> {
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
        })
        .collect();

    Ok(SevenZListing {
        entries,
        solid: archive.is_solid,
    })
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
    extract_7z_inner(archive_path, destination, password, policy, None, None)
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
    extract_7z_inner(
        archive_path,
        destination,
        password,
        policy,
        Some(overwrite_resolver),
        None,
    )
}

/// Extracts a `.7z` archive through the shared extraction safety policy with a
/// reporting context.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, or filesystem writes fail.
pub fn extract_7z_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    context: &mut JobContext<'_>,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(
        archive_path,
        destination,
        password,
        policy,
        None,
        Some(context),
    )
}

fn extract_7z_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<SevenZExtractReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| SevenZError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

    let password = archive_password(password);
    let source = open_7z_reader(archive_path)?;
    let mut reader = ArchiveReader::new(source, password)?;
    let (decisions, modes) = plan_extraction(
        reader.archive().files.as_slice(),
        &destination_root,
        policy,
        overwrite_resolver,
    )?;
    let mut report = SevenZExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut callback_error = None;
    let mut deferred_directories: Vec<(PathBuf, Option<u32>, Option<std::time::SystemTime>)> =
        Vec::new();

    let result = reader.for_each_entries(|entry, entry_reader| {
        match extract_entry(
            entry,
            entry_reader,
            &decisions,
            &modes,
            &mut deferred_directories,
            &mut report,
            context.as_deref_mut(),
        ) {
            Ok(()) => Ok(true),
            Err(error) => {
                callback_error = Some(error);
                Err(callback_failed_error())
            }
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;
    apply_deferred_sevenz_directory_metadata(&deferred_directories)?;

    Ok(report)
}

/// Copies selected regular `.7z` file entries to a writer in archive order.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, a password is
/// missing/incorrect, or output writing fails.
pub fn copy_7z_files_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<SevenZExtractReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let password = archive_password(password);
    let source = open_7z_reader(archive_path)?;
    let mut reader = ArchiveReader::new(source, password)?;
    let mut report = SevenZExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut callback_error = None;

    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_anti_item() || !selected(entry.name()) || entry.is_directory() {
            if let Err(error) = drain_reader(entry_reader, entry.name()) {
                callback_error = Some(error);
                return Err(callback_failed_error());
            }
            report.skipped_entries += 1;
            return Ok(true);
        }

        match io::copy(entry_reader, output) {
            Ok(copied) => {
                report.written_entries += 1;
                report.written_bytes += copied;
                Ok(true)
            }
            Err(source) => {
                callback_error = Some(SevenZError::Io {
                    path: PathBuf::from(entry.name()),
                    source,
                });
                Err(callback_failed_error())
            }
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;

    Ok(report)
}

fn configure_content_methods<W: io::Write + io::Seek>(
    writer: &mut ArchiveWriter<W>,
    options: &SevenZCreateOptions,
) -> bool {
    let password = options
        .password
        .as_ref()
        .map(SecretString::expose_secret)
        .filter(|password| !password.is_empty());
    let lzma2_options = sevenz_lzma2_options(options);

    match (password, lzma2_options) {
        (Some(password), Some(lzma2_options)) => {
            writer.set_content_methods(vec![
                AesEncoderOptions::new(Password::from(password)).into(),
                lzma2_options.into(),
            ]);
            true
        }
        (Some(password), None) => {
            writer.set_content_methods(vec![
                AesEncoderOptions::new(Password::from(password)).into(),
                EncoderMethod::LZMA2.into(),
            ]);
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

    Some(Lzma2Options::from_level_mt(
        level,
        threads,
        options
            .chunk_size
            .unwrap_or(DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES),
    ))
}

fn sevenz_threads(options: &SevenZCreateOptions) -> Option<u32> {
    options
        .threads
        .map(|threads| threads.clamp(1, MAX_SEVENZ_LZMA2_THREADS))
}

fn default_sevenz_threads() -> Option<u32> {
    let threads = std::thread::available_parallelism().ok()?.get();

    u32::try_from(threads).ok().filter(|threads| *threads > 1)
}

fn archive_password(password: Option<&str>) -> Password {
    password
        .filter(|password| !password.is_empty())
        .map_or_else(Password::empty, Password::from)
}

fn map_7z_error(source: sevenz_rust2::Error) -> SevenZError {
    match source {
        sevenz_rust2::Error::PasswordRequired => SevenZError::PasswordRequired,
        sevenz_rust2::Error::MaybeBadPassword(_) => SevenZError::InvalidPassword,
        source => SevenZError::SevenZ(source),
    }
}

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
        append_non_solid_entry(
            writer,
            entry,
            preserve_metadata,
            report,
            progress,
            cancellation_token,
            cancellation_observed,
        )?;
    }

    Ok(())
}

fn append_non_solid_entry<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
    progress: Option<&SevenZProgressCallback<'_>>,
    cancellation_token: Option<&CancellationToken>,
    cancellation_observed: Option<&Rc<Cell<bool>>>,
) -> Result<(), SevenZError> {
    match entry.file_type {
        ManifestFileType::Directory => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            writer.push_archive_entry::<&[u8]>(archive_entry, None)?;
            report.written_entries += 1;
        }
        ManifestFileType::File => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            let file = File::open(&entry.source_path).map_err(|source| SevenZError::Io {
                path: entry.source_path.clone(),
                source,
            })?;
            let reader = SevenZProgressReader::new(
                file,
                entry.archive_path.clone(),
                progress.cloned(),
                cancellation_token.cloned(),
                cancellation_observed.cloned(),
            );
            writer.push_archive_entry(archive_entry, Some(reader))?;
            report.written_entries += 1;
            report.written_bytes += entry.size;
        }
        ManifestFileType::Symlink => {
            report.warnings.push(format!(
                "skipped symlink {}: 7z backend does not materialize symlink entries in v1",
                entry.archive_path
            ));
        }
        ManifestFileType::Other => {
            report.warnings.push(format!(
                "skipped unsupported entry {}: 7z backend only writes files and directories in v1",
                entry.archive_path
            ));
        }
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
        match entry.file_type {
            ManifestFileType::Directory => {
                let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
                writer.push_archive_entry::<&[u8]>(archive_entry, None)?;
                report.written_entries += 1;
            }
            ManifestFileType::File => {
                let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
                let file = File::open(&entry.source_path).map_err(|source| SevenZError::Io {
                    path: entry.source_path.clone(),
                    source,
                })?;
                let reader = SevenZProgressReader::new(
                    file,
                    entry.archive_path.clone(),
                    progress.cloned(),
                    cancellation_token.cloned(),
                    cancellation_observed.cloned(),
                );
                solid_entries.push(archive_entry);
                solid_readers.push(SourceReader::new(reader));
                report.written_entries += 1;
                report.written_bytes += entry.size;
            }
            ManifestFileType::Symlink => {
                report.warnings.push(format!(
                    "skipped symlink {}: 7z backend does not materialize symlink entries in v1",
                    entry.archive_path
                ));
            }
            ManifestFileType::Other => {
                report.warnings.push(format!(
                    "skipped unsupported entry {}: 7z backend only writes files and directories in v1",
                    entry.archive_path
                ));
            }
        }
    }

    if !solid_entries.is_empty() {
        writer.push_archive_entries(solid_entries, solid_readers)?;
    }

    Ok(())
}

fn sevenz_archive_entry(entry: &ManifestEntry, preserve_metadata: bool) -> ArchiveEntry {
    if preserve_metadata {
        let mut archive_entry =
            ArchiveEntry::from_path(&entry.source_path, entry.archive_path.clone());
        #[cfg(unix)]
        if let Some(mode) = entry.permissions.unix_mode {
            archive_entry.has_windows_attributes = true;
            archive_entry.windows_attributes |=
                SEVENZ_UNIX_ATTRIBUTES_FLAG | ((mode & SEVENZ_MODE_MASK) << 16);
        }
        return archive_entry;
    }

    match entry.file_type {
        ManifestFileType::Directory => ArchiveEntry::new_directory(&entry.archive_path),
        ManifestFileType::File | ManifestFileType::Symlink | ManifestFileType::Other => {
            ArchiveEntry::new_file(&entry.archive_path)
        }
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

fn sevenz_unix_mode(entry: &ArchiveEntry) -> Option<u32> {
    if entry.has_windows_attributes
        && (entry.windows_attributes() & SEVENZ_UNIX_ATTRIBUTES_FLAG) != 0
    {
        Some((entry.windows_attributes() >> 16) & SEVENZ_MODE_MASK)
    } else {
        None
    }
}

fn apply_sevenz_metadata(
    path: &Path,
    unix_mode: Option<u32>,
    modified_time: Option<std::time::SystemTime>,
) -> Result<(), SevenZError> {
    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & SEVENZ_MODE_MASK)).map_err(
            |source| SevenZError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    #[cfg(not(unix))]
    if let Some(mode) = unix_mode {
        if mode & 0o222 == 0 {
            if let Ok(metadata) = fs::metadata(path) {
                let mut perms = metadata.permissions();
                perms.set_readonly(true);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }

    if let Some(sys_time) = modified_time {
        let _ = filetime::set_file_mtime(path, filetime::FileTime::from_system_time(sys_time));
    }
    Ok(())
}

fn apply_deferred_sevenz_directory_metadata(
    directories: &[(PathBuf, Option<u32>, Option<std::time::SystemTime>)],
) -> Result<(), SevenZError> {
    for (path, unix_mode, modified_time) in directories.iter().rev() {
        apply_sevenz_metadata(path, *unix_mode, *modified_time)?;
    }
    Ok(())
}

fn plan_extraction(
    entries: &[ArchiveEntry],
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<
    (
        HashMap<String, ExtractionDecision>,
        HashMap<String, Option<u32>>,
    ),
    SevenZError,
> {
    let mut planner = match overwrite_resolver {
        Some(resolver) => {
            ExtractionSafetyPlanner::new_with_overwrite_resolver(destination, policy, resolver)
        }
        None => ExtractionSafetyPlanner::new(destination, policy),
    };
    let mut decisions = HashMap::with_capacity(entries.len());
    let mut modes = HashMap::with_capacity(entries.len());

    for entry in entries {
        if entry.is_anti_item() {
            continue;
        }

        let kind = if entry.is_directory() {
            ExtractionEntryKind::Directory
        } else {
            ExtractionEntryKind::File
        };
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

fn extract_entry(
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
    decisions: &HashMap<String, ExtractionDecision>,
    modes: &HashMap<String, Option<u32>>,
    deferred_directories: &mut Vec<(PathBuf, Option<u32>, Option<std::time::SystemTime>)>,
    report: &mut SevenZExtractReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), SevenZError> {
    let path = entry.name().to_owned();
    if let Some(context) = context.as_deref_mut() {
        context.entry_started(&path, Some(entry.size()));
    }
    let mut processed_bytes = 0_u64;

    if entry.is_anti_item() {
        drain_reader(reader, entry.name())?;
        report.skipped_entries += 1;
        report
            .warnings
            .push(format!("skipped anti-item {}", entry.name()));
        if let Some(context) = context {
            context.warning(format!("skipped anti-item {path}"));
            context.entry_finished(&path, 0);
        }
        return Ok(());
    }

    let decision = decisions
        .get(entry.name())
        .ok_or_else(|| missing_extraction_decision(entry.name()))?;
    let unix_mode = modes.get(entry.name()).copied().flatten();

    let modified_time = if entry.has_last_modified_date {
        let nt = entry.last_modified_date();
        std::time::SystemTime::try_from(nt).ok()
    } else {
        None
    };

    match decision {
        ExtractionDecision::Write {
            destination_path,
            replace_existing,
            ..
        } => {
            if *replace_existing && entry.is_directory() {
                crate::safety::remove_destination_for_replace(destination_path).map_err(
                    |source| SevenZError::Io {
                        path: destination_path.clone(),
                        source,
                    },
                )?;
            }
            if entry.is_directory() {
                fs::create_dir_all(destination_path).map_err(|source| SevenZError::Io {
                    path: destination_path.clone(),
                    source,
                })?;
                deferred_directories.push((destination_path.clone(), unix_mode, modified_time));
                report.written_entries += 1;
            } else {
                let written_bytes = write_file_entry(
                    reader,
                    destination_path,
                    *replace_existing,
                    Some(&path),
                    context.as_deref_mut(),
                )?;
                apply_sevenz_metadata(destination_path, unix_mode, modified_time)?;
                report.written_entries += 1;
                report.written_bytes += written_bytes;
                processed_bytes = written_bytes;
            }
        }
        ExtractionDecision::Skip { reason, .. } => {
            drain_reader(reader, entry.name())?;
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped {}: {reason}", entry.name()));
        }
    }

    if let Some(context) = context {
        context.entry_finished(&path, processed_bytes);
    }

    Ok(())
}

fn missing_extraction_decision(archive_path: &str) -> SevenZError {
    SevenZError::SevenZ(sevenz_rust2::Error::Other(Cow::Owned(format!(
        "missing extraction decision for {archive_path}"
    ))))
}

fn write_file_entry(
    reader: &mut dyn Read,
    destination_path: &Path,
    replace_existing: bool,
    path: Option<&str>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<u64, SevenZError> {
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| {
            SevenZError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    loop {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let read = reader.read(&mut buffer).map_err(|source| SevenZError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        output
            .file_mut()
            .map_err(|source| SevenZError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?
            .write_all(&buffer[..read])
            .map_err(|source| SevenZError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
        let read = read as u64;
        copied += read;
        if let Some(context) = context.as_deref_mut() {
            context.bytes_processed(path, read);
        }
    }
    output
        .commit_with_replace(replace_existing)
        .map_err(|source| SevenZError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    Ok(copied)
}

fn drain_reader(reader: &mut dyn Read, archive_path: &str) -> Result<(), SevenZError> {
    io::copy(reader, &mut io::sink()).map_err(|source| SevenZError::Io {
        path: PathBuf::from(archive_path),
        source,
    })?;
    Ok(())
}

fn callback_failed_error() -> sevenz_rust2::Error {
    sevenz_rust2::Error::Other(Cow::Borrowed("zmanager extraction callback failed"))
}

#[cfg(test)]
mod tests {
    use super::{
        SevenZCreateOptions, SevenZEntryKind, SevenZError, create_7z_from_path, extract_7z, list_7z,
    };
    use crate::safety::{ExtractionPolicy, ExtractionSafetyError};
    use crate::secrets::SecretString;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]

    fn preserves_metadata_during_creation_and_extraction() {
        let temp = TestDir::new("preserves_metadata_sevenz");

        temp.write_file("project/script.sh", b"echo hello");

        #[allow(unused_variables)]
        let path = temp.path("project/script.sh");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mtime = filetime::FileTime::from_unix_time(1500000000, 0);
        filetime::set_file_mtime(&path, mtime).unwrap();

        let archive = temp.path("archive.7z");

        create_7z_from_path(
            temp.path("project"),
            &archive,
            &SevenZCreateOptions {
                preserve_metadata: true,
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();
        extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        let out_path = temp.path("out/project/script.sh");

        #[allow(unused_variables)]
        let metadata = fs::metadata(&out_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        }

        #[cfg(not(unix))]
        {
            // Windows fallback check
        }

        // Check mtime. The test creates the archive with mtime=1500000000
        let mtime_extracted = filetime::FileTime::from_last_modification_time(&metadata);
        let diff = (mtime_extracted.unix_seconds() - mtime.unix_seconds()).abs();
        assert!(
            diff <= 2,
            "extracted mtime diff {} is greater than 2 seconds",
            diff
        );
    }

    #[test]

    fn default_7z_create_options_request_parallel_lzma2_when_available() {
        let options = SevenZCreateOptions::default();

        assert_eq!(options.threads, super::default_sevenz_threads());
        assert_eq!(
            options.chunk_size,
            Some(super::DEFAULT_SEVENZ_LZMA2_CHUNK_SIZE_BYTES)
        );
    }

    #[test]
    fn sevenz_thread_count_is_clamped_to_backend_limits() {
        let mut options = SevenZCreateOptions {
            threads: Some(0),
            ..SevenZCreateOptions::default()
        };
        assert_eq!(super::sevenz_threads(&options), Some(1));

        options.threads = Some(super::MAX_SEVENZ_LZMA2_THREADS + 1);
        assert_eq!(
            super::sevenz_threads(&options),
            Some(super::MAX_SEVENZ_LZMA2_THREADS)
        );
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
                chunk_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.threads, Some(2));
        extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn creates_and_extracts_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        temp.create_dir("payload/empty");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions::default(),
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert!(report.solid);
        assert_eq!(report.written_bytes, 10);
        assert!(listing.solid);
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/file.txt")
        );
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.kind == SevenZEntryKind::Directory)
        );
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "hello"
        );
        assert!(temp.path("out/payload/empty").is_dir());
    }

    #[test]
    fn creates_and_extracts_non_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_non_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        let archive = temp.path("payload.7z");

        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert!(!listing.solid);
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/nested/second.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn creates_split_7z_volumes() {
        let temp = TestDir::new("creates_split_7z_volumes");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.volume_size, Some(super::MIN_VOLUME_SIZE_BYTES));
        assert!(report.volume_count >= 2);
        assert!(!archive.exists());
        assert_eq!(
            fs::metadata(temp.path("payload.7z.001")).unwrap().len(),
            super::MIN_VOLUME_SIZE_BYTES
        );

        let mut joined = Vec::new();
        for index in 1..=report.volume_count {
            let part = temp.path(format!("payload.7z.{index:03}"));
            let part_bytes = fs::read(part).unwrap();
            assert!(u64::try_from(part_bytes.len()).unwrap() <= super::MIN_VOLUME_SIZE_BYTES);
            joined.extend(part_bytes);
        }
        temp.write_file("joined.7z", &joined);

        let listing = list_7z(temp.path("joined.7z"), None).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/blob.bin")
        );
        let extract_report = extract_7z(
            temp.path("joined.7z"),
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(
            fs::read(temp.path("out/payload/blob.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn passworded_split_7z_volumes_read_from_first_part() {
        let temp = TestDir::new("passworded_split_7z_volumes_read_from_first_part");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");
        let first_volume = temp.path("payload.7z.001");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                password: Some(SecretString::from("correct horse")),
                encrypt_file_names: true,
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(report.volume_count >= 2);
        assert!(matches!(
            list_7z(&first_volume, None),
            Err(SevenZError::PasswordRequired)
        ));

        let listing = list_7z(&first_volume, Some("correct horse")).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/blob.bin")
        );
        let extract_report = extract_7z(
            &first_volume,
            temp.path("out"),
            Some("correct horse"),
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(
            fs::read(temp.path("out/payload/blob.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn single_volume_split_7z_reads_from_base_path() {
        let temp = TestDir::new("single_volume_split_7z_reads_from_base_path");
        temp.write_file("payload/file.txt", b"small payload");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.volume_count, 1);
        assert!(!archive.exists());
        assert!(temp.path("payload.7z.001").exists());

        let listing = list_7z(&archive, None).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/file.txt")
        );
    }

    #[test]
    fn split_7z_refuses_existing_volume_without_replace() {
        let temp = TestDir::new("split_7z_refuses_existing_volume_without_replace");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        temp.write_file("payload.7z.001", b"old");
        let archive = temp.path("payload.7z");

        let error = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(fs::read(temp.path("payload.7z.001")).unwrap(), b"old");
    }

    #[test]
    fn split_7z_replace_removes_stale_old_volumes() {
        let temp = TestDir::new("split_7z_replace_removes_stale_old_volumes");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        let archive = temp.path("payload.7z");

        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();
        assert!(temp.path("payload.7z.002").exists());

        temp.write_file("payload/blob.bin", b"small");
        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                replace_existing: true,
                volume_size: Some(super::MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(temp.path("payload.7z.001").exists());
        assert!(!temp.path("payload.7z.002").exists());
    }

    #[test]
    fn encrypted_archive_requires_correct_password() {
        let temp = TestDir::new("encrypted_archive_requires_correct_password");
        temp.write_file("payload/file.txt", b"secret");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                password: Some(SecretString::from("correct horse")),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(matches!(
            list_7z(&archive, None),
            Err(SevenZError::PasswordRequired)
        ));
        assert!(matches!(
            extract_7z(
                &archive,
                temp.path("wrong"),
                Some("wrong password"),
                ExtractionPolicy::default()
            ),
            Err(SevenZError::InvalidPassword)
        ));

        let listing = list_7z(&archive, Some("correct horse")).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            Some("correct horse"),
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert_eq!(listing.entries.len(), 2);
        assert_eq!(extract_report.written_bytes, 6);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "secret"
        );
    }

    #[test]
    fn encrypted_archive_can_leave_file_names_visible() {
        let temp = TestDir::new("encrypted_archive_can_leave_file_names_visible");
        temp.write_file("payload/file.txt", b"secret");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                password: Some(SecretString::from("correct horse")),
                encrypt_file_names: false,
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        let listing = list_7z(&archive, None).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/file.txt")
        );
        assert!(matches!(
            extract_7z(
                &archive,
                temp.path("missing-password"),
                None,
                ExtractionPolicy::default()
            ),
            Err(SevenZError::PasswordRequired | SevenZError::InvalidPassword)
        ));
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal");
        let archive = temp.path("hostile.7z");
        let output = File::create(&archive).unwrap();
        let mut writer = sevenz_rust2::ArchiveWriter::new(output).unwrap();
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("../evil.txt"),
                Some(&b"owned"[..]),
            )
            .unwrap();
        writer.finish().unwrap();

        let error = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            SevenZError::Safety(ExtractionSafetyError::ParentTraversal { .. })
        ));
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

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions::default(),
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();

        assert_eq!(report.warnings.len(), 1);
        assert!(
            !listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/link.txt")
        );
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
