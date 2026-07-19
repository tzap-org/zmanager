use crate::jobs::{JobCancelled, JobContext};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_libarchive::{FileType, ReadArchive};

const LIBARCHIVE_MODE_MASK: u32 = 0o7777;

const NUMBERED_VOLUME_EXTENSION_WIDTH: usize = 3;
const NUMBERED_VOLUME_ARCHIVE_SUFFIXES: &[&str] = &[".7z", ".zip"];
const TAR_BROTLI_SUFFIX: &str = ".tar.br";

/// One libarchive listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveListEntry {
    /// Raw path reported by libarchive.
    pub path: String,
    /// Entry kind.
    pub kind: LibarchiveEntryKind,
    /// Uncompressed size when known.
    pub size: i64,
    /// Unix permission bits reported by libarchive.
    pub mode: u32,
    /// Modification time when reported by libarchive.
    pub modified: Option<SystemTime>,
    /// Whether entry data is encrypted.
    pub data_encrypted: bool,
    /// Whether entry metadata is encrypted.
    pub metadata_encrypted: bool,
}

/// Portable entry type for libarchive-backed archives.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LibarchiveEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// Character or block device.
    Device,
    /// FIFO, socket, or unknown special entry.
    Special,
}

/// Archive listing returned by the libarchive adapter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveListing {
    /// Entries in archive order.
    pub entries: Vec<LibarchiveListEntry>,
}

/// Extraction report returned by the libarchive adapter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveExtractReport {
    /// Entries written to disk.
    pub written_entries: usize,
    /// Entries skipped by policy or unsupported materialization.
    pub skipped_entries: usize,
    /// Regular file bytes copied.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Data-read test report returned by the libarchive adapter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LibarchiveTestReport {
    /// Entries selected and read or skipped through successfully.
    pub tested_entries: usize,
    /// Entries skipped by the supplied filter.
    pub skipped_entries: usize,
    /// Regular file bytes read from selected entries.
    pub tested_bytes: u64,
}

/// Error returned by the libarchive adapter.
#[derive(Debug)]
pub enum LibarchiveError {
    /// libarchive returned an error.
    Archive(zmanager_libarchive::Error),
    /// A compressed tar wrapper could not be decoded before libarchive read it.
    RawStream(crate::raw_stream_backend::RawStreamError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Entry had no path.
    MissingPath,
    /// Link entry had no target.
    MissingLinkTarget { path: String },
    /// Requested archive entry was not found.
    EntryNotFound { path: String },
    /// Job was cancelled cooperatively.
    Cancelled,
    /// Stdout extraction must resolve to one regular file.
    StdoutSelectionNotSingleFile { selected_files: usize },
}

impl fmt::Display for LibarchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(source) => write!(f, "libarchive operation failed: {source}"),
            Self::RawStream(source) => write!(f, "compressed tar decode failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingPath => write!(f, "libarchive entry has no path"),
            Self::MissingLinkTarget { path } => {
                write!(f, "libarchive link entry has no target: {path}")
            }
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::Cancelled => write!(f, "job cancelled"),
            Self::StdoutSelectionNotSingleFile { selected_files } => write!(
                f,
                "extract --to-stdout requires exactly one selected regular file; selected {selected_files}"
            ),
        }
    }
}

impl std::error::Error for LibarchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Archive(source) => Some(source),
            Self::RawStream(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingPath
            | Self::MissingLinkTarget { .. }
            | Self::EntryNotFound { .. }
            | Self::Cancelled
            | Self::StdoutSelectionNotSingleFile { .. } => None,
        }
    }
}

impl From<JobCancelled> for LibarchiveError {
    fn from(_: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<zmanager_libarchive::Error> for LibarchiveError {
    fn from(source: zmanager_libarchive::Error) -> Self {
        Self::Archive(source)
    }
}

impl From<ExtractionSafetyError> for LibarchiveError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries in any archive format supported by the linked libarchive.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot open or read the archive.
pub fn list_archive(path: impl AsRef<Path>) -> Result<LibarchiveListing, LibarchiveError> {
    list_archive_with_password(path, None)
}

/// Lists entries in any archive format supported by the linked libarchive,
/// optionally using a passphrase for encrypted archive metadata.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot open or read the archive.
pub fn list_archive_with_password(
    path: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<LibarchiveListing, LibarchiveError> {
    let mut archive = open_archive(path.as_ref(), password)?;
    let mut entries = Vec::new();

    while let Some(entry) = archive.next_entry()? {
        entries.push(LibarchiveListEntry {
            path: entry.pathname().ok_or(LibarchiveError::MissingPath)?,
            kind: entry_kind(&entry),
            size: entry.size(),
            mode: entry.mode(),
            modified: entry.mtime(),
            data_encrypted: entry.is_data_encrypted(),
            metadata_encrypted: entry.is_metadata_encrypted(),
        });
        archive.skip_data()?;
    }

    Ok(LibarchiveListing { entries })
}

/// Extracts an archive through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, an entry
/// is unsafe, or filesystem writes fail.
pub fn extract_archive(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_with_password(archive_path, destination, policy, None)
}

/// Extracts an archive through the shared extraction safety policy, optionally
/// using a passphrase for encrypted archive data.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, an entry
/// is unsafe, or filesystem writes fail.
pub fn extract_archive_with_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_inner(
        archive_path,
        destination,
        policy,
        password,
        None,
        None,
        None,
    )
}

/// Extracts an archive through the shared extraction safety policy, optionally
/// with progress reporting.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, an entry
/// is unsafe, or filesystem writes fail.
pub fn extract_archive_with_password_and_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_inner(
        archive_path,
        destination,
        policy,
        password,
        None,
        None,
        Some(context),
    )
}

/// Extracts an archive with an overwrite resolver and optional password.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, an entry
/// is unsafe, filesystem writes fail, or the resolver aborts extraction.
pub fn extract_archive_with_overwrite_resolver_and_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_inner(
        archive_path,
        destination,
        policy,
        password,
        None,
        Some(overwrite_resolver),
        None,
    )
}

/// Extracts one selected archive entry through the shared extraction safety
/// policy.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, the
/// entry is unsafe, the selected entry is not found, or filesystem writes fail.
pub fn extract_archive_entry(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_entry_with_password(archive_path, entry_path, destination, policy, None)
}

/// Extracts one selected archive entry through the shared extraction safety
/// policy with an optional passphrase.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot read the archive, the
/// passphrase is missing or incorrect, the entry is unsafe, the selected entry
/// is not found, or filesystem writes fail.
pub fn extract_archive_entry_with_password(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    extract_archive_inner(
        archive_path,
        destination,
        policy,
        password,
        Some(entry_path),
        None,
        None,
    )
}

/// Copies the one selected regular file entry to a writer.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when the archive cannot be read, the selection
/// does not resolve to exactly one regular file, or output writing fails.
pub fn copy_archive_files_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    let archive_path = archive_path.as_ref();
    let mut archive = open_archive(archive_path, password)?;
    let mut report = LibarchiveExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut selected_files = 0_usize;
    let mut staged_file = None;

    while let Some(entry) = archive.next_entry()? {
        let owned_entry = OwnedEntry::from_entry(&entry)?;
        if !selected(&owned_entry.path)
            || !matches!(owned_entry.extraction_kind, ExtractionEntryKind::File)
        {
            archive.skip_data()?;
            report.skipped_entries += 1;
            continue;
        }

        selected_files += 1;
        if selected_files > 1 {
            archive.skip_data()?;
            report.skipped_entries += 1;
            continue;
        }

        let mut staged =
            crate::atomic_file::TemporaryFile::create("libarchive-stdout").map_err(|source| {
                LibarchiveError::Io {
                    path: std::env::temp_dir(),
                    source,
                }
            })?;
        let copied = copy_file_entry_to_writer(&mut archive, staged.file_mut(), &owned_entry.path)?;
        report.written_entries += 1;
        report.written_bytes += copied;
        staged_file = Some(staged);
    }

    if selected_files != 1 {
        return Err(LibarchiveError::StdoutSelectionNotSingleFile { selected_files });
    }

    let mut staged =
        staged_file.ok_or(LibarchiveError::StdoutSelectionNotSingleFile { selected_files: 0 })?;
    staged
        .file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|source| LibarchiveError::Io {
            path: staged.path().to_path_buf(),
            source,
        })?;
    io::copy(staged.file_mut(), output).map_err(|source| LibarchiveError::Io {
        path: staged.path().to_path_buf(),
        source,
    })?;

    Ok(report)
}

/// Reads selected archive entries to validate libarchive-backed data streams.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive cannot open or read the archive.
pub fn test_archive_with_password_filter(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<LibarchiveTestReport, LibarchiveError> {
    let archive_path = archive_path.as_ref();
    let mut archive = open_archive(archive_path, password)?;
    let mut report = LibarchiveTestReport {
        tested_entries: 0,
        skipped_entries: 0,
        tested_bytes: 0,
    };

    while let Some(entry) = archive.next_entry()? {
        let owned_entry = OwnedEntry::from_entry(&entry)?;
        if !selected(&owned_entry.path) {
            archive.skip_data()?;
            report.skipped_entries += 1;
            continue;
        }

        if matches!(owned_entry.extraction_kind, ExtractionEntryKind::File) {
            let mut sink = io::sink();
            report.tested_bytes +=
                copy_file_entry_to_writer(&mut archive, &mut sink, &owned_entry.path)?;
        } else {
            archive.skip_data()?;
        }
        report.tested_entries += 1;
    }

    Ok(report)
}

#[allow(clippy::too_many_lines)]
fn extract_archive_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    selected_entry: Option<&str>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<LibarchiveExtractReport, LibarchiveError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            LibarchiveError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;

    let mut archive = open_archive(archive_path.as_ref(), password)?;
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = LibarchiveExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut found_selected_entry = selected_entry.is_none();
    let mut deferred_directories = Vec::new();
    let mut deferred_hardlinks = Vec::new();
    let mut io_buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];

    while let Some(entry) = archive.next_entry()? {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let owned_entry = OwnedEntry::from_entry(&entry)?;
        if let Some(selected_entry) = selected_entry
            && owned_entry.path != selected_entry
        {
            archive.skip_data()?;
            continue;
        }
        found_selected_entry = true;
        if owned_entry.is_archive_root_directory() {
            archive.skip_data()?;
            report.skipped_entries += 1;
            report
                .warnings
                .push("skipped archive root directory entry".to_owned());
            if let Some(context) = context.as_deref_mut() {
                context.warning("skipped archive root directory entry");
                context.entry_finished(&owned_entry.path, 0);
            }
            continue;
        }
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&owned_entry.path, nonnegative_size(owned_entry.size));
        }
        let safety_entry = ExtractionEntry {
            archive_path: owned_entry.path.clone(),
            kind: owned_entry.extraction_kind.clone(),
            uncompressed_size: nonnegative_size(owned_entry.size),
            compressed_size: None,
        };

        let processed = match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => write_entry(
                &mut archive,
                &owned_entry,
                &destination_path,
                replace_existing,
                link_target_path.as_deref(),
                &mut report,
                context.as_deref_mut(),
                &mut deferred_directories,
                &mut deferred_hardlinks,
                &mut io_buffer,
            )?,
            ExtractionDecision::Skip { reason, .. } => {
                archive.skip_data()?;
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped {}: {reason}", owned_entry.path));
                if let Some(context) = context.as_deref_mut() {
                    context.warning(format!("skipped {}: {reason}", owned_entry.path));
                }
                0
            }
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_finished(&owned_entry.path, processed);
        }
    }

    if !found_selected_entry && let Some(path) = selected_entry {
        return Err(LibarchiveError::EntryNotFound {
            path: path.to_owned(),
        });
    }

    materialize_deferred_hardlinks(&deferred_hardlinks, &mut report)?;
    apply_deferred_directory_metadata(&deferred_directories)?;

    Ok(report)
}

fn open_archive(path: &Path, password: Option<&str>) -> Result<OpenedArchive, LibarchiveError> {
    let password = password.filter(|password| !password.is_empty());
    let input = ArchiveReadInput::new(path)?;
    let parts = discover_multi_volume_paths(input.path());

    match (parts.len() > 1, password) {
        (true, Some(password)) => Ok(OpenedArchive::new(
            ReadArchive::open_filenames_with_passphrase(parts.as_slice(), password)?,
            input,
        )),
        (true, None) => Ok(OpenedArchive::new(
            ReadArchive::open_filenames(parts.as_slice())?,
            input,
        )),
        (false, Some(password)) => Ok(OpenedArchive::new(
            ReadArchive::open_with_passphrase(input.path(), password)?,
            input,
        )),
        (false, None) => Ok(OpenedArchive::new(ReadArchive::open(input.path())?, input)),
    }
}

struct OpenedArchive {
    archive: ReadArchive,
    _input: ArchiveReadInput,
}

impl OpenedArchive {
    fn new(archive: ReadArchive, input: ArchiveReadInput) -> Self {
        Self {
            archive,
            _input: input,
        }
    }
}

impl Deref for OpenedArchive {
    type Target = ReadArchive;

    fn deref(&self) -> &Self::Target {
        &self.archive
    }
}

impl DerefMut for OpenedArchive {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.archive
    }
}

struct ArchiveReadInput {
    path: PathBuf,
    temporary: bool,
}

impl ArchiveReadInput {
    fn new(path: &Path) -> Result<Self, LibarchiveError> {
        if !is_tar_brotli_archive(path) {
            return Ok(Self {
                path: path.to_path_buf(),
                temporary: false,
            });
        }

        let decoded_path = temporary_decoded_tar_path();
        let mut decoded = File::create(&decoded_path).map_err(|source| LibarchiveError::Io {
            path: decoded_path.clone(),
            source,
        })?;
        crate::raw_stream_backend::copy_raw_stream_to_writer(
            path,
            crate::raw_stream_backend::RawStreamFormat::Brotli,
            &mut decoded,
        )
        .map_err(|source| {
            let _ = fs::remove_file(&decoded_path);
            LibarchiveError::RawStream(source)
        })?;
        decoded.flush().map_err(|source| {
            let _ = fs::remove_file(&decoded_path);
            LibarchiveError::Io {
                path: decoded_path.clone(),
                source,
            }
        })?;

        Ok(Self {
            path: decoded_path,
            temporary: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ArchiveReadInput {
    fn drop(&mut self) {
        if self.temporary {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn is_tar_brotli_archive(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(TAR_BROTLI_SUFFIX))
}

fn temporary_decoded_tar_path() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("zmanager-tar-br-{}-{now}.tar", std::process::id()))
}

/// Returns true when `path` belongs to a standard split ZIP set.
#[must_use]
pub fn is_split_zip_path(path: &Path) -> bool {
    discover_split_zip_paths(path).is_some_and(|paths| paths.len() > 1)
}

fn discover_multi_volume_paths(path: &Path) -> Vec<PathBuf> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return vec![path.to_path_buf()];
    };
    let lower_name = file_name.to_ascii_lowercase();
    let directory = path.parent().unwrap_or_else(|| Path::new("."));

    if let Some(parts) = discover_split_zip_paths(path) {
        return parts;
    }

    if let Some(parts) = discover_numbered_archive_volume_paths(directory, &lower_name) {
        return parts;
    }

    if let Some((base, _)) = parse_part_rar_name(&lower_name)
        && let Ok(entries) = fs::read_dir(directory)
    {
        let mut parts = BTreeMap::new();
        for entry in entries.flatten() {
            let candidate_name = entry.file_name();
            let Some(candidate_name) = candidate_name.to_str() else {
                continue;
            };
            let candidate_lower = candidate_name.to_ascii_lowercase();
            if let Some((candidate_base, part)) = parse_part_rar_name(&candidate_lower)
                && candidate_base == base
            {
                parts.insert(part, entry.path());
            }
        }
        if parts.len() > 1 {
            return parts.into_values().collect();
        }
    }

    if let Some((base, first_path)) = old_style_rar_base(path, &lower_name)
        && let Ok(entries) = fs::read_dir(directory)
    {
        let mut numbered_parts = BTreeMap::new();
        for entry in entries.flatten() {
            let candidate_name = entry.file_name();
            let Some(candidate_name) = candidate_name.to_str() else {
                continue;
            };
            let candidate_lower = candidate_name.to_ascii_lowercase();
            if let Some(part) = parse_old_rar_part_name(&candidate_lower, base) {
                numbered_parts.insert(part, entry.path());
            }
        }
        if !numbered_parts.is_empty() {
            let mut parts = Vec::with_capacity(numbered_parts.len() + 1);
            parts.push(first_path);
            parts.extend(numbered_parts.into_values());
            return parts;
        }
    }

    vec![path.to_path_buf()]
}

fn discover_split_zip_paths(path: &Path) -> Option<Vec<PathBuf>> {
    let file_name = path.file_name()?.to_str()?;
    let lower_name = file_name.to_ascii_lowercase();
    let (base, _) = parse_split_zip_volume_name(&lower_name)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = fs::read_dir(directory).ok()?;
    let mut sidecars = BTreeMap::new();
    let mut final_zip = None;

    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        let Some((candidate_base, part)) = parse_split_zip_volume_name(&candidate_lower) else {
            continue;
        };
        if candidate_base != base {
            continue;
        }
        match part {
            SplitZipPart::Sidecar(index) => {
                sidecars.insert(index, entry.path());
            }
            SplitZipPart::Final => {
                final_zip = Some(entry.path());
            }
        }
    }

    let final_zip = final_zip?;
    let max_sidecar = *sidecars.keys().last()?;
    for expected in 1..=max_sidecar {
        sidecars.get(&expected)?;
    }

    let mut parts = sidecars.into_values().collect::<Vec<_>>();
    parts.push(final_zip);
    Some(parts)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SplitZipPart {
    Sidecar(u32),
    Final,
}

fn parse_split_zip_volume_name(name: &str) -> Option<(&str, SplitZipPart)> {
    let (base, extension) = name.rsplit_once('.')?;
    if extension == "zip" {
        return Some((base, SplitZipPart::Final));
    }
    let number = extension.strip_prefix('z')?;
    if number.len() < 2 || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let index = number.parse().ok()?;
    (index > 0).then_some((base, SplitZipPart::Sidecar(index)))
}

#[cfg(test)]
fn parse_numbered_7z_volume_name(name: &str) -> Option<(&str, u32)> {
    let (base, part) = parse_numbered_archive_volume_name(name)?;
    has_7z_extension(base).then_some((base, part))
}

fn discover_numbered_archive_volume_paths(
    directory: &Path,
    lower_name: &str,
) -> Option<Vec<PathBuf>> {
    let (base, _) = parse_numbered_archive_volume_name(lower_name)?;
    let entries = fs::read_dir(directory).ok()?;
    let mut parts = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        if let Some((candidate_base, part)) = parse_numbered_archive_volume_name(&candidate_lower)
            && candidate_base == base
        {
            parts.insert(part, entry.path());
        }
    }
    (parts.len() > 1).then(|| parts.into_values().collect())
}

fn parse_numbered_archive_volume_name(name: &str) -> Option<(&str, u32)> {
    let (base, number) = name.rsplit_once('.')?;
    if !NUMBERED_VOLUME_ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| base.ends_with(suffix))
        || number.len() != NUMBERED_VOLUME_EXTENSION_WIDTH
        || !number.chars().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

#[cfg(test)]
fn has_7z_extension(value: &str) -> bool {
    Path::new(value)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

fn parse_part_rar_name(name: &str) -> Option<(&str, u32)> {
    let stem = name.strip_suffix(".rar")?;
    let marker = stem.rfind(".part")?;
    let base = &stem[..marker];
    let number = &stem[marker + ".part".len()..];
    if base.is_empty() || number.is_empty() || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    Some((base, number.parse().ok()?))
}

fn old_style_rar_base<'a>(path: &Path, lower_name: &'a str) -> Option<(&'a str, PathBuf)> {
    if let Some(base) = lower_name.strip_suffix(".rar")
        && !base.is_empty()
    {
        return Some((base, path.to_path_buf()));
    }

    None
}

fn parse_old_rar_part_name(name: &str, base: &str) -> Option<u32> {
    let suffix = name.strip_prefix(base)?.strip_prefix(".r")?;
    if suffix.len() != 2 || !suffix.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct OwnedEntry {
    path: String,
    kind: LibarchiveEntryKind,
    extraction_kind: ExtractionEntryKind,
    size: i64,
    metadata: LibarchiveEntryMetadata,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LibarchiveEntryMetadata {
    mode: Option<u32>,
    modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DeferredHardlink {
    source_path: PathBuf,
    destination_path: PathBuf,
}

impl OwnedEntry {
    fn from_entry(entry: &zmanager_libarchive::Entry) -> Result<Self, LibarchiveError> {
        let path = entry.pathname().ok_or(LibarchiveError::MissingPath)?;
        let kind = entry_kind(entry);
        let extraction_kind = extraction_kind(entry, kind, &path)?;

        Ok(Self {
            path,
            kind,
            extraction_kind,
            size: entry.size(),
            metadata: LibarchiveEntryMetadata {
                mode: archive_entry_mode(entry.mode(), kind),
                modified: entry.mtime(),
            },
        })
    }

    fn is_archive_root_directory(&self) -> bool {
        matches!(self.kind, LibarchiveEntryKind::Directory) && is_root_entry_path(&self.path)
    }
}

fn is_root_entry_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    trimmed.is_empty() || trimmed == "."
}

fn nonnegative_size(size: i64) -> Option<u64> {
    u64::try_from(size).ok()
}

fn archive_entry_mode(mode: u32, kind: LibarchiveEntryKind) -> Option<u32> {
    let permissions = mode & LIBARCHIVE_MODE_MASK;
    // Some formats without POSIX modes (notably 7z) are synthesized by
    // libarchive as 0644 for every entry. Treat an unsearchable directory mode
    // as absent rather than making the extracted tree inaccessible.
    if permissions == 0
        || (matches!(kind, LibarchiveEntryKind::Directory) && permissions & 0o111 == 0)
    {
        None
    } else {
        Some(permissions)
    }
}

fn entry_kind(entry: &zmanager_libarchive::Entry) -> LibarchiveEntryKind {
    if entry.hardlink().is_some() {
        return LibarchiveEntryKind::Hardlink;
    }

    match entry.file_type() {
        FileType::RegularFile => LibarchiveEntryKind::File,
        FileType::Directory => LibarchiveEntryKind::Directory,
        FileType::SymbolicLink => LibarchiveEntryKind::Symlink,
        FileType::BlockDevice | FileType::CharacterDevice => LibarchiveEntryKind::Device,
        FileType::Fifo | FileType::Socket | FileType::Unknown => LibarchiveEntryKind::Special,
    }
}

fn extraction_kind(
    entry: &zmanager_libarchive::Entry,
    kind: LibarchiveEntryKind,
    path: &str,
) -> Result<ExtractionEntryKind, LibarchiveError> {
    match kind {
        LibarchiveEntryKind::File => Ok(ExtractionEntryKind::File),
        LibarchiveEntryKind::Directory => Ok(ExtractionEntryKind::Directory),
        LibarchiveEntryKind::Symlink => {
            let target = entry
                .symlink()
                .ok_or_else(|| LibarchiveError::MissingLinkTarget {
                    path: path.to_owned(),
                })?;
            Ok(ExtractionEntryKind::Symlink {
                target: PathBuf::from(target),
            })
        }
        LibarchiveEntryKind::Hardlink => {
            let target = entry
                .hardlink()
                .ok_or_else(|| LibarchiveError::MissingLinkTarget {
                    path: path.to_owned(),
                })?;
            Ok(ExtractionEntryKind::Hardlink {
                target: PathBuf::from(target),
            })
        }
        LibarchiveEntryKind::Device => Ok(ExtractionEntryKind::Device),
        LibarchiveEntryKind::Special => Ok(ExtractionEntryKind::Special),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_entry(
    archive: &mut ReadArchive,
    entry: &OwnedEntry,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut LibarchiveExtractReport,
    mut context: Option<&mut JobContext<'_>>,
    deferred_directories: &mut Vec<(PathBuf, LibarchiveEntryMetadata)>,
    deferred_hardlinks: &mut Vec<DeferredHardlink>,
    io_buffer: &mut [u8],
) -> Result<u64, LibarchiveError> {
    if replace_existing && !matches!(entry.extraction_kind, ExtractionEntryKind::File) {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    match &entry.extraction_kind {
        ExtractionEntryKind::Directory => {
            archive.skip_data()?;
            fs::create_dir_all(destination_path).map_err(|source| LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            deferred_directories.push((destination_path.to_path_buf(), entry.metadata));
            report.written_entries += 1;
            Ok(0)
        }
        ExtractionEntryKind::File => {
            let written_bytes = write_file_entry(
                archive,
                &entry.path,
                destination_path,
                replace_existing,
                entry.metadata,
                context,
                io_buffer,
            )?;
            report.written_entries += 1;
            report.written_bytes += written_bytes;
            Ok(written_bytes)
        }
        ExtractionEntryKind::Symlink { target } => {
            archive.skip_data()?;
            if crate::safety::should_skip_symlink_materialization(&entry.extraction_kind) {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(crate::safety::unsupported_symlink_warning(&entry.path));
                if let Some(context) = context.as_deref_mut() {
                    context.warning(crate::safety::unsupported_symlink_warning(&entry.path));
                }
                Ok(0)
            } else {
                write_symlink(target, destination_path)?;
                apply_symlink_mtime(destination_path, entry.metadata.modified)?;
                report.written_entries += 1;
                Ok(0)
            }
        }
        ExtractionEntryKind::Hardlink { target } => {
            archive.skip_data()?;
            let source_path = link_target_path.ok_or_else(|| LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "hardlink target for {} -> {} was not resolved by extraction safety planning",
                        entry.path,
                        target.display()
                    ),
                ),
            })?;
            deferred_hardlinks.push(DeferredHardlink {
                source_path: source_path.to_path_buf(),
                destination_path: destination_path.to_path_buf(),
            });
            Ok(0)
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
            archive.skip_data()?;
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped unsupported special entry {}", entry.path));
            if let Some(context) = context {
                context.warning(format!("skipped unsupported special entry {}", entry.path));
            }
            Ok(0)
        }
    }
}

fn materialize_deferred_hardlinks(
    hardlinks: &[DeferredHardlink],
    report: &mut LibarchiveExtractReport,
) -> Result<(), LibarchiveError> {
    let paths = hardlinks
        .iter()
        .map(|hardlink| {
            (
                hardlink.source_path.clone(),
                hardlink.destination_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    let order = crate::safety::deferred_link_dependency_order(&paths).map_err(|source| {
        LibarchiveError::Io {
            path: hardlinks
                .first()
                .map_or_else(PathBuf::new, |link| link.destination_path.clone()),
            source,
        }
    })?;
    for index in order {
        let hardlink = &hardlinks[index];
        write_hardlink(&hardlink.source_path, &hardlink.destination_path)?;
        report.written_entries += 1;
    }
    Ok(())
}

fn write_file_entry(
    archive: &mut ReadArchive,
    archive_path: &str,
    destination_path: &Path,
    replace_existing: bool,
    metadata: LibarchiveEntryMetadata,
    mut context: Option<&mut JobContext<'_>>,
    buffer: &mut [u8],
) -> Result<u64, LibarchiveError> {
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| {
            LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    let mut written_bytes = 0_u64;

    loop {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let read = archive.read_data(&mut *buffer)?;
        if read == 0 {
            break;
        }
        output
            .file_mut()
            .map_err(|source| LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?
            .write_all(&buffer[..read])
            .map_err(|source| LibarchiveError::Io {
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
        .map_err(|source| LibarchiveError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    apply_metadata(destination_path, metadata)?;

    Ok(written_bytes)
}

fn apply_deferred_directory_metadata(
    directories: &[(PathBuf, LibarchiveEntryMetadata)],
) -> Result<(), LibarchiveError> {
    for (path, metadata) in directories.iter().rev() {
        apply_metadata(path, *metadata)?;
    }
    Ok(())
}

fn apply_metadata(path: &Path, metadata: LibarchiveEntryMetadata) -> Result<(), LibarchiveError> {
    #[cfg(unix)]
    if let Some(mode) = metadata.mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            path,
            fs::Permissions::from_mode(mode & LIBARCHIVE_MODE_MASK),
        )
        .map_err(|source| LibarchiveError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }

    #[cfg(not(unix))]
    if let Some(mode) = metadata.mode
        && mode & 0o222 == 0
        && let Ok(fs_metadata) = fs::metadata(path)
    {
        let mut perms = fs_metadata.permissions();
        perms.set_readonly(true);
        fs::set_permissions(path, perms).map_err(|source| LibarchiveError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }

    if let Some(modified) = metadata.modified {
        filetime::set_file_mtime(path, filetime::FileTime::from_system_time(modified)).map_err(
            |source| LibarchiveError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    Ok(())
}

/// Uses `set_symlink_file_times` to avoid following the link. Errors are
/// reported so extraction cannot claim metadata was restored when it was not.
fn apply_symlink_mtime(path: &Path, modified: Option<SystemTime>) -> Result<(), LibarchiveError> {
    if let Some(modified) = modified {
        let ft = filetime::FileTime::from_system_time(modified);
        filetime::set_symlink_file_times(path, ft, ft).map_err(|source| LibarchiveError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn copy_file_entry_to_writer<W: Write>(
    archive: &mut ReadArchive,
    output: &mut W,
    entry_path: &str,
) -> Result<u64, LibarchiveError> {
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut written_bytes = 0_u64;

    loop {
        let read = archive.read_data(&mut buffer)?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| LibarchiveError::Io {
                path: PathBuf::from(entry_path),
                source,
            })?;
        written_bytes += read as u64;
    }

    Ok(written_bytes)
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), LibarchiveError> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| LibarchiveError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::hard_link(source_path, destination_path).map_err(|source| LibarchiveError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), LibarchiveError> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| LibarchiveError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    symlink(target, destination_path).map_err(|source| LibarchiveError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), LibarchiveError> {
    Err(LibarchiveError::Io {
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
        LibarchiveEntryKind, LibarchiveError, copy_archive_files_to_writer,
        discover_multi_volume_paths, extract_archive, is_split_zip_path, list_archive,
        parse_numbered_7z_volume_name, parse_numbered_archive_volume_name,
    };
    use crate::safety::ExtractionPolicy;
    use std::fs;
    #[cfg(unix)]
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn lists_and_extracts_tar_archive() {
        if !bsdtar_available() {
            return;
        }
        let temp = TestDir::new("lists_and_extracts_tar_archive");
        temp.write_file("payload/file.txt", b"hello");
        let archive = temp.path("archive.tar");
        create_bsdtar_archive(&temp.root, "payload", &archive, "-cf");

        let listing = list_archive(&archive).unwrap();
        let report =
            extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "payload/file.txt")
        );
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.kind == LibarchiveEntryKind::File)
        );
        assert_eq!(report.written_bytes, 5);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "hello"
        );
    }

    #[cfg(unix)]
    #[test]
    fn extracts_tar_gz_permissions_and_modification_times() {
        use std::os::unix::fs::MetadataExt;

        const DIRECTORY_MTIME: u64 = 1_600_000_000;
        const FILE_MTIME: u64 = 1_700_000_000;

        let temp = TestDir::new("extracts_tar_gz_permissions_and_modification_times");
        let archive = temp.path("archive.tar.gz");
        write_tar_gz_with_metadata(
            &archive,
            "payload",
            0o1750,
            DIRECTORY_MTIME,
            "payload/run.sh",
            0o751,
            FILE_MTIME,
            b"#!/bin/sh\n",
            "payload/link.sh",
            "run.sh",
            FILE_MTIME,
        );

        extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let directory_metadata = fs::metadata(temp.path("out/payload")).unwrap();
        let file_metadata = fs::metadata(temp.path("out/payload/run.sh")).unwrap();
        let link_metadata = fs::symlink_metadata(temp.path("out/payload/link.sh")).unwrap();

        assert_eq!(directory_metadata.mode() & 0o7777, 0o1750);
        assert_eq!(file_metadata.mode() & 0o7777, 0o751);

        assert_eq!(
            directory_metadata.mtime(),
            i64::try_from(DIRECTORY_MTIME).unwrap()
        );
        assert_eq!(file_metadata.mtime(), i64::try_from(FILE_MTIME).unwrap());

        assert!(link_metadata.is_symlink());
        assert_eq!(link_metadata.mtime(), i64::try_from(FILE_MTIME).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn extracts_pax_tar_precise_modification_time() {
        use std::os::unix::fs::MetadataExt;

        const FILE_MTIME: u64 = 1_700_000_000;
        const FILE_MTIME_NANOS: i64 = 234_567_890;

        let temp = TestDir::new("extracts_pax_tar_precise_modification_time");
        let archive = temp.path("archive.tar");
        let file = File::create(&archive).unwrap();
        let mut builder = tar::Builder::new(file);
        builder
            .append_pax_extensions([("mtime", b"1700000000.234567890".as_slice())])
            .unwrap();
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(7);
        header.set_mode(0o640);
        header.set_mtime(FILE_MTIME);
        header.set_cksum();
        builder
            .append_data(&mut header, "precise.txt", b"precise".as_slice())
            .unwrap();
        builder.finish().unwrap();

        extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let metadata = fs::metadata(temp.path("out/precise.txt")).unwrap();
        assert_eq!(metadata.mtime(), i64::try_from(FILE_MTIME).unwrap());
        assert_eq!(metadata.mtime_nsec(), FILE_MTIME_NANOS);
    }

    #[test]
    fn lists_and_extracts_brotli_compressed_tar_archive() {
        let temp = TestDir::new("lists_and_extracts_brotli_compressed_tar_archive");
        let archive = temp.path("archive.tar.br");
        write_tar_brotli_with_file(&archive, "payload/file.txt", b"hello brotli tar");

        let listing = list_archive(&archive).unwrap();
        let report =
            extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "payload/file.txt")
        );
        assert_eq!(report.written_bytes, 16);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "hello brotli tar"
        );
    }

    #[test]
    fn copy_to_writer_rejects_multiple_selected_files_without_partial_output() {
        let temp = TestDir::new("copy_to_writer_rejects_multiple_selected_files");
        let archive = temp.path("archive.tar.br");
        write_tar_brotli_with_files(
            &archive,
            &[
                ("payload/a.txt", b"first".as_slice()),
                ("payload/b.txt", b"second".as_slice()),
            ],
        );
        let mut output = Vec::new();

        let error =
            copy_archive_files_to_writer(&archive, None, |_| true, &mut output).unwrap_err();

        assert!(matches!(
            error,
            LibarchiveError::StdoutSelectionNotSingleFile { selected_files: 2 }
        ));
        assert!(
            output.is_empty(),
            "stdout output must not receive partial bytes when selection is ambiguous"
        );
    }

    #[test]
    fn copy_to_writer_streams_single_selected_file_after_validation() {
        let temp = TestDir::new("copy_to_writer_streams_single_selected_file");
        let archive = temp.path("archive.tar.br");
        write_tar_brotli_with_files(
            &archive,
            &[
                ("payload/a.txt", b"first".as_slice()),
                ("payload/b.txt", b"second".as_slice()),
            ],
        );
        let mut output = Vec::new();

        let report = copy_archive_files_to_writer(
            &archive,
            None,
            |path| path == "payload/b.txt",
            &mut output,
        )
        .unwrap();

        assert_eq!(output, b"second");
        assert_eq!(report.written_entries, 1);
        assert_eq!(report.written_bytes, 6);
    }

    #[cfg(unix)]
    #[test]
    fn extracts_hardlinks_from_tar_archive() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("extracts_hardlinks_from_tar_archive");
        let archive = temp.path("archive.tar");
        write_tar_with_hardlink(
            &archive,
            "payload/target.txt",
            "payload/link.txt",
            b"target",
        );

        let report =
            extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let target = temp.path("out/payload/target.txt");
        let link = temp.path("out/payload/link.txt");
        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::read(&link).unwrap(), b"target");
        assert_eq!(
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&link).unwrap().ino()
        );
    }

    #[cfg(unix)]
    #[test]
    fn extracts_forward_hardlinks_from_tar_archive() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("extracts_forward_hardlinks_from_tar_archive");
        let archive = temp.path("archive.tar");
        write_tar_with_forward_hardlink(
            &archive,
            "payload/target.txt",
            "payload/link.txt",
            b"target",
        );

        let report =
            extract_archive(&archive, temp.path("out"), ExtractionPolicy::default()).unwrap();

        let target = temp.path("out/payload/target.txt");
        let link = temp.path("out/payload/link.txt");
        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::read(&link).unwrap(), b"target");
        assert_eq!(
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&link).unwrap().ino()
        );
    }

    #[test]
    fn lists_common_non_zip_formats() {
        if !bsdtar_available() {
            return;
        }
        let temp = TestDir::new("lists_common_non_zip_formats");
        temp.write_file("payload/file.txt", b"hello");
        let formats = [
            ("archive.tar", "-cf"),
            ("archive.tar.gz", "-czf"),
            ("archive.tar.bz2", "-cjf"),
            ("archive.tar.xz", "-cJf"),
            ("archive.cpio", "--format=cpio -cf"),
        ];

        for (archive_name, flags) in formats {
            let archive = temp.path(archive_name);
            create_bsdtar_archive(&temp.root, "payload", &archive, flags);
            let listing = list_archive(&archive).unwrap();

            assert!(
                listing
                    .entries
                    .iter()
                    .any(|entry| entry.path == "payload/file.txt"),
                "missing payload file in {archive_name}"
            );
        }
    }

    #[test]
    fn lists_and_extracts_numbered_7z_volumes() {
        let temp = TestDir::new("lists_and_extracts_numbered_7z_volumes");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");

        crate::sevenz_backend::create_7z_from_path(
            temp.path("payload"),
            &archive,
            &crate::sevenz_backend::SevenZCreateOptions {
                solid: false,
                level: Some(1),
                volume_size: Some(1_048_576),
                ..crate::sevenz_backend::SevenZCreateOptions::default()
            },
        )
        .unwrap();

        let listing = list_archive(temp.path("payload.7z.001")).unwrap();
        let report = extract_archive(
            temp.path("payload.7z.001"),
            temp.path("out"),
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "payload/blob.bin")
        );
        assert_eq!(report.written_bytes, payload.len() as u64);
        assert_eq!(
            fs::read(temp.path("out/payload/blob.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn discovers_numbered_7z_volumes_from_any_part() {
        let temp = TestDir::new("discovers_numbered_7z_volumes_from_any_part");
        temp.write_file("payload.7z.001", b"a");
        temp.write_file("payload.7z.002", b"b");
        temp.write_file("payload.7z.003", b"c");

        let from_first = discover_multi_volume_paths(&temp.path("payload.7z.001"));
        let from_middle = discover_multi_volume_paths(&temp.path("payload.7z.002"));

        assert_eq!(
            relative_names(&temp.root, &from_first),
            vec!["payload.7z.001", "payload.7z.002", "payload.7z.003"]
        );
        assert_eq!(from_middle, from_first);
    }

    #[test]
    fn discovers_numbered_zip_stream_volumes_from_any_part() {
        let temp = TestDir::new("discovers_numbered_zip_stream_volumes_from_any_part");
        temp.write_file("payload.zip.001", b"a");
        temp.write_file("payload.zip.002", b"b");
        temp.write_file("payload.zip.003", b"c");

        let from_first = discover_multi_volume_paths(&temp.path("payload.zip.001"));
        let from_middle = discover_multi_volume_paths(&temp.path("payload.zip.002"));

        assert_eq!(
            relative_names(&temp.root, &from_first),
            vec!["payload.zip.001", "payload.zip.002", "payload.zip.003"]
        );
        assert_eq!(from_middle, from_first);
    }

    #[test]
    fn discovers_standard_split_zip_volumes_from_final_or_sidecar() {
        let temp = TestDir::new("discovers_standard_split_zip_volumes_from_final_or_sidecar");
        temp.write_file("payload.z01", b"a");
        temp.write_file("payload.z02", b"b");
        temp.write_file("payload.zip", b"c");

        let from_final = discover_multi_volume_paths(&temp.path("payload.zip"));
        let from_sidecar = discover_multi_volume_paths(&temp.path("payload.z01"));

        assert_eq!(
            relative_names(&temp.root, &from_final),
            vec!["payload.z01", "payload.z02", "payload.zip"]
        );
        assert_eq!(from_sidecar, from_final);
        assert!(is_split_zip_path(&temp.path("payload.zip")));
    }

    #[test]
    fn parses_only_numbered_7z_volume_names() {
        assert_eq!(
            parse_numbered_7z_volume_name("payload.7z.001"),
            Some(("payload.7z", 1))
        );
        assert_eq!(parse_numbered_7z_volume_name("payload.7z.000"), None);
        assert_eq!(parse_numbered_7z_volume_name("payload.zip.001"), None);
        assert_eq!(parse_numbered_7z_volume_name("payload.7z.01"), None);
        assert_eq!(
            parse_numbered_archive_volume_name("payload.zip.001"),
            Some(("payload.zip", 1))
        );
    }

    fn bsdtar_available() -> bool {
        Command::new("bsdtar")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success())
    }

    fn create_bsdtar_archive(root: &Path, input_name: &str, archive: &Path, flags: &str) {
        let mut command = Command::new("bsdtar");
        for flag in flags.split_whitespace() {
            command.arg(flag);
        }
        let status = command
            .arg(archive)
            .arg("-C")
            .arg(root)
            .arg(input_name)
            .status()
            .unwrap();

        assert!(status.success());
    }

    fn relative_names(root: &Path, paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
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

    #[cfg(unix)]
    fn write_tar_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let mut builder = tar::Builder::new(file);

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

        builder.finish().unwrap();
    }

    #[cfg(unix)]
    fn write_tar_with_forward_hardlink(
        path: &Path,
        target_path: &str,
        link_path: &str,
        contents: &[u8],
    ) {
        let file = File::create(path).unwrap();
        let mut builder = tar::Builder::new(file);

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_mtime(0);
        link_header.set_cksum();
        builder
            .append_link(&mut link_header, link_path, Path::new(target_path))
            .unwrap();

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, target_path, contents)
            .unwrap();

        builder.finish().unwrap();
    }

    fn write_tar_brotli_with_file(path: &Path, entry_path: &str, contents: &[u8]) {
        write_tar_brotli_with_files(path, &[(entry_path, contents)]);
    }

    #[cfg(unix)]
    #[allow(clippy::too_many_arguments)]
    fn write_tar_gz_with_metadata(
        path: &Path,
        directory_path: &str,
        directory_mode: u32,
        directory_mtime: u64,
        file_path: &str,
        file_mode: u32,
        file_mtime: u64,
        contents: &[u8],
        symlink_path: &str,
        symlink_target: &str,
        symlink_mtime: u64,
    ) {
        let file = File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let mut directory_header = tar::Header::new_gnu();
        directory_header.set_entry_type(tar::EntryType::Directory);
        directory_header.set_size(0);
        directory_header.set_mode(directory_mode);
        directory_header.set_mtime(directory_mtime);
        directory_header.set_cksum();
        builder
            .append_data(&mut directory_header, directory_path, std::io::empty())
            .unwrap();

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(file_mode);
        file_header.set_mtime(file_mtime);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, file_path, contents)
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mtime(symlink_mtime);
        link_header.set_link_name(symlink_target).unwrap();
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, symlink_path, std::io::empty())
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn write_tar_brotli_with_files(path: &Path, entries: &[(&str, &[u8])]) {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (entry_path, contents) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(contents.len().try_into().unwrap());
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, *entry_path, *contents)
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let file = fs::File::create(path).unwrap();
        let mut encoder =
            brotli::CompressorWriter::new(file, crate::DEFAULT_IO_BUFFER_BYTES, 5, 22);
        encoder.write_all(&tar_bytes).unwrap();
        encoder.flush().unwrap();
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

    #[test]
    fn test_zstd_linkage_version_match() {
        // Query version number of zstd from Rust's zstd-sys dependency via safe wrapper
        let rust_zstd_ver = zstd::zstd_safe::version_number();
        let rust_major = rust_zstd_ver / 10000;
        let rust_minor = (rust_zstd_ver % 10000) / 100;
        let rust_patch = rust_zstd_ver % 100;
        let rust_version_str = format!("{rust_major}.{rust_minor}.{rust_patch}");

        // Query version details from libarchive
        let details = zmanager_libarchive::version_details();

        // Parse libzstd version from details (e.g. "libzstd/1.5.7")
        if let Some(pos) = details.find("libzstd/") {
            let start = pos + "libzstd/".len();
            let end = details[start..]
                .find(' ')
                .map_or(details.len(), |p| start + p);
            let libarchive_zstd_version = &details[start..end];

            println!("Rust zstd version: {rust_version_str}");
            println!("Libarchive linked zstd version: {libarchive_zstd_version}");

            // Verify they match or that the Rust version is at least as new as the one libarchive is using.
            // On macOS, they must match exactly because we link them to the same static library.
            // On other platforms, they should be compatible.
            assert_eq!(
                rust_version_str, libarchive_zstd_version,
                "Linkage mismatch: Rust zstd version ({rust_version_str}) does not match libarchive's linked zstd version ({libarchive_zstd_version})."
            );
        } else {
            // If zstd is disabled, that's allowed on musl, but let's warn/check on other platforms.
            #[cfg(not(all(target_os = "linux", target_env = "musl")))]
            panic!("libarchive was compiled without zstd support, but we expect it!");
        }
    }
}
