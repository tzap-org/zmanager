use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use zmanager_libarchive::{FileType, ReadArchive};

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

/// Error returned by the libarchive adapter.
#[derive(Debug)]
pub enum LibarchiveError {
    /// libarchive returned an error.
    Archive(zmanager_libarchive::Error),
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
    /// Stdout extraction must resolve to one regular file.
    StdoutSelectionNotSingleFile { selected_files: usize },
}

impl fmt::Display for LibarchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(source) => write!(f, "libarchive operation failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingPath => write!(f, "libarchive entry has no path"),
            Self::MissingLinkTarget { path } => {
                write!(f, "libarchive link entry has no target: {path}")
            }
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
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
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingPath
            | Self::MissingLinkTarget { .. }
            | Self::EntryNotFound { .. }
            | Self::StdoutSelectionNotSingleFile { .. } => None,
        }
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
    extract_archive_inner(archive_path, destination, policy, password, None, None)
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
    extract_archive_inner(
        archive_path,
        destination,
        policy,
        None,
        Some(entry_path),
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
    let selected_paths = selected_regular_file_paths(archive_path, password, &mut selected)?;
    if selected_paths.len() != 1 {
        return Err(LibarchiveError::StdoutSelectionNotSingleFile {
            selected_files: selected_paths.len(),
        });
    }
    let selected_path = selected_paths[0].clone();
    let mut archive = open_archive(archive_path, password)?;
    let mut report = LibarchiveExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut copied_selected = false;

    while let Some(entry) = archive.next_entry()? {
        let owned_entry = OwnedEntry::from_entry(&entry)?;
        if copied_selected || owned_entry.path != selected_path {
            archive.skip_data()?;
            report.skipped_entries += 1;
            continue;
        }
        if !matches!(owned_entry.extraction_kind, ExtractionEntryKind::File) {
            archive.skip_data()?;
            report.skipped_entries += 1;
            continue;
        }

        let copied = copy_file_entry_to_writer(&mut archive, output, &owned_entry.path)?;
        report.written_entries += 1;
        report.written_bytes += copied;
        copied_selected = true;
    }

    if copied_selected {
        Ok(report)
    } else {
        Err(LibarchiveError::EntryNotFound {
            path: selected_path,
        })
    }
}

fn extract_archive_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    selected_entry: Option<&str>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
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

    while let Some(entry) = archive.next_entry()? {
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
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: owned_entry.path.clone(),
            kind: owned_entry.extraction_kind.clone(),
            uncompressed_size: nonnegative_size(owned_entry.size),
            compressed_size: None,
        };

        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => {
                write_entry(
                    &mut archive,
                    &owned_entry,
                    &destination_path,
                    replace_existing,
                    link_target_path.as_deref(),
                    &mut report,
                )?;
            }
            ExtractionDecision::Skip { reason, .. } => {
                archive.skip_data()?;
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped {}: {reason}", owned_entry.path));
            }
        }
    }

    if !found_selected_entry && let Some(path) = selected_entry {
        return Err(LibarchiveError::EntryNotFound {
            path: path.to_owned(),
        });
    }

    Ok(report)
}

fn open_archive(path: &Path, password: Option<&str>) -> Result<ReadArchive, LibarchiveError> {
    let password = password.filter(|password| !password.is_empty());
    let parts = discover_multi_volume_paths(path);

    match (parts.len() > 1, password) {
        (true, Some(password)) => Ok(ReadArchive::open_filenames_with_passphrase(
            parts.as_slice(),
            password,
        )?),
        (true, None) => Ok(ReadArchive::open_filenames(parts.as_slice())?),
        (false, Some(password)) => Ok(ReadArchive::open_with_passphrase(path, password)?),
        (false, None) => Ok(ReadArchive::open(path)?),
    }
}

fn discover_multi_volume_paths(path: &Path) -> Vec<PathBuf> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return vec![path.to_path_buf()];
    };
    let lower_name = file_name.to_ascii_lowercase();
    let directory = path.parent().unwrap_or_else(|| Path::new("."));

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

fn selected_regular_file_paths(
    archive_path: &Path,
    password: Option<&str>,
    selected: &mut impl FnMut(&str) -> bool,
) -> Result<Vec<String>, LibarchiveError> {
    let mut archive = open_archive(archive_path, password)?;
    let mut selected_paths = Vec::new();

    while let Some(entry) = archive.next_entry()? {
        let owned_entry = OwnedEntry::from_entry(&entry)?;
        if selected(&owned_entry.path)
            && matches!(owned_entry.extraction_kind, ExtractionEntryKind::File)
        {
            selected_paths.push(owned_entry.path);
        }
        archive.skip_data()?;
    }

    Ok(selected_paths)
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

fn write_entry(
    archive: &mut ReadArchive,
    entry: &OwnedEntry,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut LibarchiveExtractReport,
) -> Result<(), LibarchiveError> {
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
            report.written_entries += 1;
        }
        ExtractionEntryKind::File => {
            let written_bytes = write_file_entry(archive, destination_path, replace_existing)?;
            report.written_entries += 1;
            report.written_bytes += written_bytes;
        }
        ExtractionEntryKind::Symlink { target } => {
            archive.skip_data()?;
            if crate::safety::should_skip_symlink_materialization(&entry.extraction_kind) {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(crate::safety::unsupported_symlink_warning(&entry.path));
            } else {
                write_symlink(target, destination_path)?;
                report.written_entries += 1;
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
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
        }
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
            archive.skip_data()?;
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped unsupported special entry {}", entry.path));
        }
    }

    Ok(())
}

fn write_file_entry(
    archive: &mut ReadArchive,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<u64, LibarchiveError> {
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| {
            LibarchiveError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut written_bytes = 0_u64;

    loop {
        let read = archive.read_data(&mut buffer)?;
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
        written_bytes += read as u64;
    }

    output
        .commit_with_replace(replace_existing)
        .map_err(|source| LibarchiveError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;

    Ok(written_bytes)
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
    use super::{LibarchiveEntryKind, extract_archive, list_archive};
    use crate::safety::ExtractionPolicy;
    use std::fs;
    #[cfg(unix)]
    use std::fs::File;
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
