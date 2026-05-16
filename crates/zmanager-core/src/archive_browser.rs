use crate::libarchive_backend::{self, LibarchiveEntryKind, LibarchiveError};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner,
};
use crate::tar_zst_backend::TarZstdError;
use crate::zip_backend::ZipBackendError;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::EntryType;
use zip::{ZipArchive, ZipReadOptions};

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

/// Archive browser error.
#[derive(Debug)]
pub enum ArchiveBrowserError {
    /// ZIP backend failed.
    Zip(ZipBackendError),
    /// TAR.ZST backend failed.
    TarZst(TarZstdError),
    /// Libarchive backend failed.
    Libarchive(LibarchiveError),
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
            Self::Libarchive(source) => write!(f, "libarchive browser operation failed: {source}"),
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
            Self::Libarchive(source) => Some(source),
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

impl From<LibarchiveError> for ArchiveBrowserError {
    fn from(source: LibarchiveError) -> Self {
        Self::Libarchive(source)
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
    let path = path.as_ref();
    if is_zip_family_archive(path) {
        list_zip_entries(path)
    } else if is_tar_zst_archive(path) {
        list_tar_zst_entries(path)
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
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    fs::create_dir_all(destination).map_err(|source| ArchiveBrowserError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    if is_zip_family_archive(archive_path) {
        extract_zip_entry(archive_path, entry_path, destination)
    } else if is_tar_zst_archive(archive_path) {
        extract_tar_zst_entry(archive_path, entry_path, destination)
    } else {
        let report = libarchive_backend::extract_archive_entry(
            archive_path,
            entry_path,
            destination,
            ExtractionPolicy::default(),
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
    let cleanup_root = std::env::temp_dir().join(format!(
        "zmanager-preview-{}-{}",
        std::process::id(),
        unique_preview_id()
    ));
    fs::create_dir_all(&cleanup_root).map_err(|source| ArchiveBrowserError::Io {
        path: cleanup_root.clone(),
        source,
    })?;

    let report = match extract_entry(archive_path, entry_path, &cleanup_root) {
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

fn extract_zip_entry(
    archive_path: &Path,
    entry_path: &str,
    destination: &Path,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let file = File::open(archive_path).map_err(|source| ArchiveBrowserError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = ZipArchive::new(file).map_err(ZipBackendError::from)?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index_with_options(index, ZipReadOptions::new())
            .map_err(ZipBackendError::from)?;
        if file.name() != entry_path {
            continue;
        }
        let entry = ExtractionEntry {
            archive_path: file.name().to_owned(),
            kind: zip_extraction_kind(&mut file)?,
        };
        let decision = ExtractionSafetyPlanner::new(destination, ExtractionPolicy::default())
            .validate_entry(&entry)?;
        let destination_path = decision_destination(decision, &entry.archive_path)?;
        let written_bytes = write_selected_entry(&mut file, &entry, &destination_path)?;
        return Ok(EntryExtractReport {
            destination_path,
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
        };
        let decision = ExtractionSafetyPlanner::new(destination, ExtractionPolicy::default())
            .validate_entry(&safety_entry)?;
        let destination_path = decision_destination(decision, &safety_entry.archive_path)?;
        let written_bytes = write_selected_entry(&mut entry, &safety_entry, &destination_path)?;
        return Ok(EntryExtractReport {
            destination_path,
            written_bytes,
        });
    }

    Err(ArchiveBrowserError::EntryNotFound {
        path: entry_path.to_owned(),
    })
}

fn write_selected_entry<R: Read>(
    reader: &mut R,
    entry: &ExtractionEntry,
    destination_path: &Path,
) -> Result<u64, ArchiveBrowserError> {
    match &entry.kind {
        ExtractionEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| ArchiveBrowserError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            Ok(0)
        }
        ExtractionEntryKind::File => {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|source| ArchiveBrowserError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            let mut output =
                File::create(destination_path).map_err(|source| ArchiveBrowserError::Io {
                    path: destination_path.to_path_buf(),
                    source,
                })?;
            io::copy(reader, &mut output).map_err(|source| ArchiveBrowserError::Io {
                path: destination_path.to_path_buf(),
                source,
            })
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

fn decision_destination(
    decision: ExtractionDecision,
    archive_path: &str,
) -> Result<PathBuf, ArchiveBrowserError> {
    match decision {
        ExtractionDecision::Write {
            destination_path, ..
        } => Ok(destination_path),
        ExtractionDecision::Skip { reason, .. } => Err(ArchiveBrowserError::UnsupportedEntry {
            path: format!("{archive_path}: {reason}"),
            kind: BrowserEntryKind::Special,
        }),
    }
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

fn unique_preview_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::{extract_entry, list_entries, preview_entry};
    use crate::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_path};
    use crate::zip_backend::{ZipCreateOptions, create_zip_from_path};
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
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
