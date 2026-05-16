use crate::libarchive_backend::{self, LibarchiveError};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, remove_destination_for_replace,
};
use crate::tar_zst_backend::{self, TarZstdError};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Nested `.deb` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DebExtractReport {
    /// Entries written to disk.
    pub written_entries: usize,
    /// Entries skipped by policy.
    pub skipped_entries: usize,
    /// Regular file bytes copied.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Error returned by the `.deb` payload extractor.
#[derive(Debug)]
pub enum DebError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Top-level or payload extraction through libarchive failed.
    Libarchive(LibarchiveError),
    /// `.tar.zst` payload extraction failed.
    TarZst(TarZstdError),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A required `.deb` member was missing.
    MissingMember { member: &'static str },
}

impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Libarchive(source) => write!(f, "libarchive extraction failed: {source}"),
            Self::TarZst(source) => write!(f, "tar.zst payload extraction failed: {source}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingMember { member } => write!(f, "deb package is missing {member}"),
        }
    }
}

impl std::error::Error for DebError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Libarchive(source) => Some(source),
            Self::TarZst(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingMember { .. } => None,
        }
    }
}

impl From<LibarchiveError> for DebError {
    fn from(source: LibarchiveError) -> Self {
        Self::Libarchive(source)
    }
}

impl From<TarZstdError> for DebError {
    fn from(source: TarZstdError) -> Self {
        Self::TarZst(source)
    }
}

impl From<ExtractionSafetyError> for DebError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Extracts a `.deb` into a package-aware layout:
///
/// - `debian-binary` at the destination root
/// - `control.tar.*` expanded under `control/`
/// - `data.tar.*` expanded under `data/`
///
/// # Errors
///
/// Returns [`DebError`] when the package is malformed, a payload archive cannot
/// be read, a safety policy rejects an entry, or filesystem writes fail.
pub fn extract_deb_nested(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<DebExtractReport, DebError> {
    let destination = destination.as_ref();
    fs::create_dir_all(destination).map_err(|source| DebError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    let temp = TempDir::new("zmanager-deb")?;
    libarchive_backend::extract_archive(archive_path, temp.path(), ExtractionPolicy::default())?;

    let debian_binary = temp.path().join("debian-binary");
    let control_member =
        find_top_level_member(temp.path(), "control.tar.").ok_or(DebError::MissingMember {
            member: "control.tar.*",
        })?;
    let data_member =
        find_top_level_member(temp.path(), "data.tar.").ok_or(DebError::MissingMember {
            member: "data.tar.*",
        })?;

    let mut report = DebExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    if debian_binary.is_file() {
        copy_synthetic_file(
            &debian_binary,
            "debian-binary",
            destination,
            policy.clone(),
            &mut report,
        )?;
    } else {
        report
            .warnings
            .push("deb package did not include debian-binary".to_owned());
    }

    let control_report = extract_payload_archive(
        &control_member,
        &destination.join("control"),
        policy.clone(),
    )?;
    absorb_archive_report("control", control_report, &mut report);
    let data_report = extract_payload_archive(&data_member, &destination.join("data"), policy)?;
    absorb_archive_report("data", data_report, &mut report);

    Ok(report)
}

fn copy_synthetic_file(
    source_path: &Path,
    archive_path: &str,
    destination: &Path,
    policy: ExtractionPolicy,
    report: &mut DebExtractReport,
) -> Result<(), DebError> {
    let entry = ExtractionEntry {
        archive_path: archive_path.to_owned(),
        kind: ExtractionEntryKind::File,
    };
    let mut planner = ExtractionSafetyPlanner::new(destination, policy);
    match planner.validate_entry(&entry)? {
        ExtractionDecision::Write {
            destination_path,
            replace_existing,
            ..
        } => {
            if replace_existing {
                remove_destination_for_replace(&destination_path).map_err(|source| {
                    DebError::Io {
                        path: destination_path.clone(),
                        source,
                    }
                })?;
            }
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|source| DebError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            let mut input = File::open(source_path).map_err(|source| DebError::Io {
                path: source_path.to_path_buf(),
                source,
            })?;
            let mut output = File::create(&destination_path).map_err(|source| DebError::Io {
                path: destination_path.clone(),
                source,
            })?;
            let written_bytes =
                io::copy(&mut input, &mut output).map_err(|source| DebError::Io {
                    path: destination_path.clone(),
                    source,
                })?;
            output.flush().map_err(|source| DebError::Io {
                path: destination_path,
                source,
            })?;
            report.written_entries += 1;
            report.written_bytes += written_bytes;
        }
        ExtractionDecision::Skip { reason, .. } => {
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped {archive_path}: {reason}"));
        }
    }
    Ok(())
}

fn extract_payload_archive(
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
) -> Result<ArchiveReport, DebError> {
    if is_tar_zst_archive(archive_path) {
        tar_zst_backend::extract_tar_zst(archive_path, destination, policy)
            .map(ArchiveReport::from)
            .map_err(DebError::from)
    } else {
        libarchive_backend::extract_archive(archive_path, destination, policy)
            .map(ArchiveReport::from)
            .map_err(DebError::from)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ArchiveReport {
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    warnings: Vec<String>,
}

impl From<libarchive_backend::LibarchiveExtractReport> for ArchiveReport {
    fn from(report: libarchive_backend::LibarchiveExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<tar_zst_backend::TarZstdExtractReport> for ArchiveReport {
    fn from(report: tar_zst_backend::TarZstdExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

fn absorb_archive_report(prefix: &str, source: ArchiveReport, destination: &mut DebExtractReport) {
    destination.written_entries += source.written_entries;
    destination.skipped_entries += source.skipped_entries;
    destination.written_bytes += source.written_bytes;
    destination.warnings.extend(
        source
            .warnings
            .into_iter()
            .map(|warning| format!("{prefix}: {warning}")),
    );
}

fn find_top_level_member(root: &Path, prefix: &str) -> Option<PathBuf> {
    fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
}

fn is_tar_zst_archive(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            ends_with_ignore_ascii_case(name, ".tar.zst")
                || ends_with_ignore_ascii_case(name, ".tzst")
        })
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    let value = value.as_bytes();
    let suffix = suffix.as_bytes();
    value.len() >= suffix.len() && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[derive(Debug)]
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Result<Self, DebError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!("{label}-{}-{now}", std::process::id()));
        fs::create_dir_all(&path).map_err(|source| DebError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
