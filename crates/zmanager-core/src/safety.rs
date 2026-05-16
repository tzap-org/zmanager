use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Reusable extraction safety policy shared by all archive backends.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractionPolicy {
    /// Behavior when a destination path already exists.
    pub overwrite: OverwritePolicy,
    /// Behavior for device files, FIFOs, sockets, and unknown special files.
    pub unsafe_file: UnsafeFilePolicy,
    /// Include only archive paths matching at least one pattern. Empty means
    /// include all.
    pub include_patterns: Vec<String>,
    /// Exclude archive paths matching any pattern.
    pub exclude_patterns: Vec<String>,
    /// Drop this many leading path components before writing.
    pub strip_components: usize,
}

impl Default for ExtractionPolicy {
    fn default() -> Self {
        Self {
            overwrite: OverwritePolicy::Refuse,
            unsafe_file: UnsafeFilePolicy::Reject,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            strip_components: 0,
        }
    }
}

/// Existing destination handling.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OverwritePolicy {
    /// Refuse to overwrite existing destination paths.
    Refuse,
    /// Allow replacing existing destination paths.
    Replace,
    /// Write conflicting entries to deterministic renamed paths.
    Rename,
}

/// Unsafe archive entry handling.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnsafeFilePolicy {
    /// Return an error for unsafe file types.
    Reject,
    /// Skip unsafe file types without writing them.
    Skip,
}

/// File type requested by an archive backend.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExtractionEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link with a filesystem target.
    Symlink { target: PathBuf },
    /// Hard link with a filesystem target.
    Hardlink { target: PathBuf },
    /// Character or block device.
    Device,
    /// FIFO or socket.
    Special,
}

/// Archive entry metadata needed before extraction writes to disk.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractionEntry {
    /// Raw path from archive metadata.
    pub archive_path: String,
    /// Requested file type.
    pub kind: ExtractionEntryKind,
}

/// Safe extraction decision for one archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExtractionDecision {
    /// Entry may be written at the destination path.
    Write {
        /// Slash-normalized archive path.
        normalized_archive_path: String,
        /// Final destination path.
        destination_path: PathBuf,
        /// Whether the writer should remove an existing destination path before
        /// materializing this entry.
        replace_existing: bool,
    },
    /// Entry should be skipped by policy.
    Skip {
        /// Slash-normalized archive path.
        normalized_archive_path: String,
        /// Human-readable reason.
        reason: String,
    },
}

/// Stateful extraction safety planner for one destination directory.
#[derive(Debug, Clone)]
pub struct ExtractionSafetyPlanner {
    destination_root: PathBuf,
    policy: ExtractionPolicy,
    seen_paths: HashMap<String, String>,
}

impl ExtractionSafetyPlanner {
    /// Creates a planner for one extraction destination.
    #[must_use]
    pub fn new(destination_root: impl Into<PathBuf>, policy: ExtractionPolicy) -> Self {
        let destination_root = lexically_normalize(&destination_root.into());

        Self {
            destination_root,
            policy,
            seen_paths: HashMap::new(),
        }
    }

    /// Validates one archive entry before extraction.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractionSafetyError`] when the archive path, link target,
    /// overwrite behavior, file type, or name collision would violate the
    /// configured safety policy.
    pub fn validate_entry(
        &mut self,
        entry: &ExtractionEntry,
    ) -> Result<ExtractionDecision, ExtractionSafetyError> {
        let mut normalized_archive_path = normalize_archive_path(&entry.archive_path)?;
        if !archive_path_selected(
            &normalized_archive_path,
            &self.policy.include_patterns,
            &self.policy.exclude_patterns,
        ) {
            return Ok(ExtractionDecision::Skip {
                normalized_archive_path,
                reason: "filtered by include/exclude policy".to_owned(),
            });
        }
        if self.policy.strip_components > 0 {
            let stripped =
                strip_archive_components(&normalized_archive_path, self.policy.strip_components);
            let Some(stripped) = stripped else {
                return Ok(ExtractionDecision::Skip {
                    normalized_archive_path,
                    reason: "path removed by strip-components policy".to_owned(),
                });
            };
            normalized_archive_path = stripped;
        }
        let destination_path = self.destination_root.join(&normalized_archive_path);
        let mut destination_path = lexically_normalize(&destination_path);
        ensure_inside_destination(
            &self.destination_root,
            &destination_path,
            &entry.archive_path,
        )?;

        match &entry.kind {
            ExtractionEntryKind::Symlink { target } | ExtractionEntryKind::Hardlink { target } => {
                self.validate_link_target(&destination_path, target)?;
            }
            ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                if self.policy.unsafe_file == UnsafeFilePolicy::Skip {
                    return Ok(ExtractionDecision::Skip {
                        normalized_archive_path,
                        reason: "unsafe file type skipped by policy".to_owned(),
                    });
                }

                return Err(ExtractionSafetyError::UnsafeFileType {
                    archive_path: entry.archive_path.clone(),
                });
            }
            ExtractionEntryKind::File | ExtractionEntryKind::Directory => {}
        }

        self.reject_collision(&normalized_archive_path)?;

        let mut replace_existing = false;
        let destination_metadata = std::fs::symlink_metadata(&destination_path);
        if let Ok(metadata) = destination_metadata {
            match self.policy.overwrite {
                OverwritePolicy::Refuse => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory)
                        && metadata.file_type().is_dir()
                    {
                        return Ok(ExtractionDecision::Write {
                            normalized_archive_path,
                            destination_path,
                            replace_existing: false,
                        });
                    }
                    return Err(ExtractionSafetyError::DestinationExists {
                        archive_path: entry.archive_path.clone(),
                        destination_path,
                    });
                }
                OverwritePolicy::Replace => {
                    replace_existing = !matches!(entry.kind, ExtractionEntryKind::Directory)
                        || !metadata.file_type().is_dir();
                }
                OverwritePolicy::Rename => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory)
                        && metadata.file_type().is_dir()
                    {
                        return Ok(ExtractionDecision::Write {
                            normalized_archive_path,
                            destination_path,
                            replace_existing: false,
                        });
                    }
                    destination_path = next_available_destination_path(&destination_path);
                }
            }
        } else if let Err(error) = destination_metadata
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(ExtractionSafetyError::DestinationProbe {
                archive_path: entry.archive_path.clone(),
                destination_path,
                message: error.to_string(),
            });
        }

        Ok(ExtractionDecision::Write {
            normalized_archive_path,
            destination_path,
            replace_existing,
        })
    }

    fn reject_collision(
        &mut self,
        normalized_archive_path: &str,
    ) -> Result<(), ExtractionSafetyError> {
        let collision_key = normalized_archive_path.to_ascii_lowercase();

        if let Some(previous_archive_path) = self
            .seen_paths
            .insert(collision_key, normalized_archive_path.to_owned())
        {
            return Err(ExtractionSafetyError::NameCollision {
                archive_path: normalized_archive_path.to_owned(),
                previous_archive_path,
            });
        }

        Ok(())
    }

    fn validate_link_target(
        &self,
        destination_path: &Path,
        target: &Path,
    ) -> Result<(), ExtractionSafetyError> {
        let target_text = target.to_string_lossy();
        reject_raw_path_hazards(&target_text)?;
        if target.is_absolute() {
            return Err(ExtractionSafetyError::LinkTargetEscapes {
                target: target.to_path_buf(),
            });
        }

        let Some(parent) = destination_path.parent() else {
            return Err(ExtractionSafetyError::LinkTargetEscapes {
                target: target.to_path_buf(),
            });
        };
        let resolved_target = lexically_normalize(&parent.join(target));

        if !resolved_target.starts_with(&self.destination_root) {
            return Err(ExtractionSafetyError::LinkTargetEscapes {
                target: target.to_path_buf(),
            });
        }

        Ok(())
    }
}

/// Extraction safety failure.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExtractionSafetyError {
    /// Archive path is empty after normalization.
    EmptyPath,
    /// Archive path contained a NUL byte.
    NulByte { path: String },
    /// Archive path is absolute.
    AbsolutePath { path: String },
    /// Archive path uses a Windows drive or UNC prefix.
    WindowsPrefix { path: String },
    /// Archive path attempts to traverse above destination.
    ParentTraversal { path: String },
    /// Normalized destination escapes the extraction root.
    DestinationEscape {
        archive_path: String,
        destination_root: PathBuf,
        destination_path: PathBuf,
    },
    /// Entry collides with a previous archive path.
    NameCollision {
        archive_path: String,
        previous_archive_path: String,
    },
    /// Entry would overwrite an existing destination path.
    DestinationExists {
        archive_path: String,
        destination_path: PathBuf,
    },
    /// Destination existence could not be checked safely.
    DestinationProbe {
        archive_path: String,
        destination_path: PathBuf,
        message: String,
    },
    /// Entry type is unsafe by default.
    UnsafeFileType { archive_path: String },
    /// Link target resolves outside the extraction root.
    LinkTargetEscapes { target: PathBuf },
}

impl fmt::Display for ExtractionSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => write!(f, "archive path is empty"),
            Self::NulByte { path } => write!(f, "archive path contains NUL byte: {path:?}"),
            Self::AbsolutePath { path } => write!(f, "archive path is absolute: {path}"),
            Self::WindowsPrefix { path } => {
                write!(f, "archive path uses a Windows prefix: {path}")
            }
            Self::ParentTraversal { path } => {
                write!(f, "archive path attempts parent traversal: {path}")
            }
            Self::DestinationEscape {
                archive_path,
                destination_root,
                destination_path,
            } => write!(
                f,
                "archive path {archive_path} resolves outside {} to {}",
                destination_root.display(),
                destination_path.display()
            ),
            Self::NameCollision {
                archive_path,
                previous_archive_path,
            } => write!(
                f,
                "archive path {archive_path} collides with previous entry {previous_archive_path}"
            ),
            Self::DestinationExists {
                archive_path,
                destination_path,
            } => write!(
                f,
                "archive path {archive_path} would overwrite {}",
                destination_path.display()
            ),
            Self::DestinationProbe {
                archive_path,
                destination_path,
                message,
            } => write!(
                f,
                "archive path {archive_path} could not check {}: {message}",
                destination_path.display()
            ),
            Self::UnsafeFileType { archive_path } => {
                write!(f, "archive path {archive_path} has an unsafe file type")
            }
            Self::LinkTargetEscapes { target } => {
                write!(
                    f,
                    "link target escapes extraction root: {}",
                    target.display()
                )
            }
        }
    }
}

impl std::error::Error for ExtractionSafetyError {}

/// Normalizes a raw archive path into a slash-separated relative path.
///
/// # Errors
///
/// Returns [`ExtractionSafetyError`] when the path is empty, absolute, contains
/// a NUL byte, uses a Windows prefix, or attempts parent traversal.
pub fn normalize_archive_path(raw_path: &str) -> Result<String, ExtractionSafetyError> {
    reject_raw_path_hazards(raw_path)?;

    let slash_path = raw_path.replace('\\', "/");
    let mut parts = Vec::new();

    for part in slash_path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(ExtractionSafetyError::ParentTraversal {
                    path: raw_path.to_owned(),
                });
            }
            safe_part => parts.push(safe_part),
        }
    }

    if parts.is_empty() {
        return Err(ExtractionSafetyError::EmptyPath);
    }

    Ok(parts.join("/"))
}

fn reject_raw_path_hazards(raw_path: &str) -> Result<(), ExtractionSafetyError> {
    if raw_path.contains('\0') {
        return Err(ExtractionSafetyError::NulByte {
            path: raw_path.to_owned(),
        });
    }

    let slash_path = raw_path.replace('\\', "/");
    if has_windows_prefix(&slash_path) {
        return Err(ExtractionSafetyError::WindowsPrefix {
            path: raw_path.to_owned(),
        });
    }

    if slash_path.starts_with('/') {
        return Err(ExtractionSafetyError::AbsolutePath {
            path: raw_path.to_owned(),
        });
    }

    Ok(())
}

fn has_windows_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }

    path.starts_with("//")
}

fn ensure_inside_destination(
    destination_root: &Path,
    destination_path: &Path,
    archive_path: &str,
) -> Result<(), ExtractionSafetyError> {
    if destination_path.starts_with(destination_root) {
        return Ok(());
    }

    Err(ExtractionSafetyError::DestinationEscape {
        archive_path: archive_path.to_owned(),
        destination_root: destination_root.to_path_buf(),
        destination_path: destination_path.to_path_buf(),
    })
}

fn archive_path_selected(path: &str, includes: &[String], excludes: &[String]) -> bool {
    let matches_include = includes.is_empty()
        || includes
            .iter()
            .any(|pattern| archive_pattern_matches(pattern, path));
    let matches_exclude = excludes
        .iter()
        .any(|pattern| archive_pattern_matches(pattern, path));

    matches_include && !matches_exclude
}

fn archive_pattern_matches(pattern: &str, path: &str) -> bool {
    pattern == path
        || (pattern.ends_with("/**") && path.starts_with(pattern.trim_end_matches("**")))
        || wildcard_matches(pattern.as_bytes(), path.as_bytes())
}

fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == b'*' {
        return wildcard_matches(&pattern[1..], value)
            || (!value.is_empty() && wildcard_matches(pattern, &value[1..]));
    }
    if !value.is_empty() && (pattern[0] == b'?' || pattern[0] == value[0]) {
        return wildcard_matches(&pattern[1..], &value[1..]);
    }
    false
}

fn strip_archive_components(path: &str, count: usize) -> Option<String> {
    let components = path.split('/').skip(count).collect::<Vec<_>>();
    if components.is_empty() {
        None
    } else {
        Some(components.join("/"))
    }
}

fn next_available_destination_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .or_else(|| path.file_name().and_then(|name| name.to_str()))
        .unwrap_or("entry");
    let extension = path.extension().and_then(|extension| extension.to_str());

    for index in 1..10_000 {
        let file_name = if let Some(extension) = extension {
            format!("{stem} ({index}).{extension}")
        } else {
            format!("{stem} ({index})")
        };
        let candidate = parent.join(file_name);
        if !candidate.exists() {
            return candidate;
        }
    }

    path.to_path_buf()
}

/// Removes an existing destination path before an explicit overwrite write.
///
/// This uses symlink metadata so replacing a symlink removes the link itself
/// instead of following it.
///
/// # Errors
///
/// Returns any filesystem error other than a missing destination.
pub fn remove_destination_for_replace(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::{
        ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
        ExtractionSafetyError, ExtractionSafetyPlanner, OverwritePolicy, UnsafeFilePolicy,
        normalize_archive_path,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn normalizes_archive_paths() {
        assert_eq!(
            normalize_archive_path("./dir\\file.txt").unwrap(),
            "dir/file.txt"
        );
        assert_eq!(
            normalize_archive_path("dir//file.txt").unwrap(),
            "dir/file.txt"
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        let error = normalize_archive_path("dir/../../escape.txt").unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::ParentTraversal { .. }
        ));
    }

    #[test]
    fn rejects_absolute_paths() {
        let error = normalize_archive_path("/tmp/file.txt").unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::AbsolutePath { .. }));
    }

    #[test]
    fn rejects_windows_prefixes() {
        let drive_error = normalize_archive_path("C:/tmp/file.txt").unwrap_err();
        let unc_error = normalize_archive_path("\\\\server\\share\\file.txt").unwrap_err();

        assert!(matches!(
            drive_error,
            ExtractionSafetyError::WindowsPrefix { .. }
        ));
        assert!(matches!(
            unc_error,
            ExtractionSafetyError::WindowsPrefix { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_entries() {
        let temp = TestDir::new("rejects_duplicate_entries");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let first = file_entry("dir/file.txt");
        let duplicate = file_entry("dir/file.txt");

        planner.validate_entry(&first).unwrap();
        let error = planner.validate_entry(&duplicate).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::NameCollision { .. }));
    }

    #[test]
    fn rejects_case_insensitive_collisions() {
        let temp = TestDir::new("rejects_case_insensitive_collisions");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        planner
            .validate_entry(&file_entry("dir/README.md"))
            .unwrap();
        let error = planner
            .validate_entry(&file_entry("dir/readme.md"))
            .unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::NameCollision { .. }));
    }

    #[test]
    fn refuses_overwrite_when_destination_exists() {
        let temp = TestDir::new("refuses_overwrite_when_destination_exists");
        temp.write_file("out/file.txt", b"existing");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        let error = planner.validate_entry(&file_entry("file.txt")).unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::DestinationExists { .. }
        ));
    }

    #[test]
    fn allows_overwrite_when_policy_replaces() {
        let temp = TestDir::new("allows_overwrite_when_policy_replaces");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy {
            overwrite: OverwritePolicy::Replace,
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        assert!(matches!(decision, ExtractionDecision::Write { .. }));
    }

    #[test]
    fn rejects_symlink_escape() {
        let temp = TestDir::new("rejects_symlink_escape");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Symlink {
                target: PathBuf::from("../../outside"),
            },
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::LinkTargetEscapes { .. }
        ));
    }

    #[test]
    fn allows_symlink_inside_destination() {
        let temp = TestDir::new("allows_symlink_inside_destination");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Symlink {
                target: PathBuf::from("../target.txt"),
            },
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Write { .. }));
    }

    #[test]
    fn rejects_hardlink_escape() {
        let temp = TestDir::new("rejects_hardlink_escape");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Hardlink {
                target: PathBuf::from("../../outside"),
            },
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::LinkTargetEscapes { .. }
        ));
    }

    #[test]
    fn rejects_unsafe_file_types_by_default() {
        let temp = TestDir::new("rejects_unsafe_file_types_by_default");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dev/null".to_owned(),
            kind: ExtractionEntryKind::Device,
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::UnsafeFileType { .. }
        ));
    }

    #[test]
    fn skips_unsafe_file_types_when_policy_allows_skip() {
        let temp = TestDir::new("skips_unsafe_file_types_when_policy_allows_skip");
        let policy = ExtractionPolicy {
            unsafe_file: UnsafeFilePolicy::Skip,
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);
        let entry = ExtractionEntry {
            archive_path: "dev/null".to_owned(),
            kind: ExtractionEntryKind::Device,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    fn file_entry(archive_path: &str) -> ExtractionEntry {
        ExtractionEntry {
            archive_path: archive_path.to_owned(),
            kind: ExtractionEntryKind::File,
        }
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
