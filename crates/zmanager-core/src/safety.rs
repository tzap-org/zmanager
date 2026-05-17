use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const DEFAULT_MAX_EXTRACTED_MIB: u64 = 64 * 1024;
/// Default maximum total uncompressed bytes planned for one extraction.
pub const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_EXTRACTED_MIB * crate::MEBIBYTE_BYTES;
/// Default maximum entry-level uncompressed-to-compressed size ratio.
pub const DEFAULT_MAX_ENTRY_EXPANSION_RATIO: u64 = 1_000;

/// Expanded-size guardrails applied while planning extraction writes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractionLimits {
    /// Maximum total uncompressed file bytes for one extraction. `None`
    /// disables the total-size guard.
    pub max_expanded_bytes: Option<u64>,
    /// Maximum per-entry uncompressed-to-compressed ratio. `None` disables the
    /// ratio guard when compressed size metadata is available.
    pub max_entry_expansion_ratio: Option<u64>,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_expanded_bytes: Some(DEFAULT_MAX_EXTRACTED_BYTES),
            max_entry_expansion_ratio: Some(DEFAULT_MAX_ENTRY_EXPANSION_RATIO),
        }
    }
}

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
    /// Expanded-size guardrails.
    pub limits: ExtractionLimits,
}

impl Default for ExtractionPolicy {
    fn default() -> Self {
        Self {
            overwrite: OverwritePolicy::Refuse,
            unsafe_file: UnsafeFilePolicy::Reject,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            strip_components: 0,
            limits: ExtractionLimits::default(),
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
    /// Ask a caller-provided resolver for each conflicting destination path.
    Ask,
}

/// Destination conflict presented to an overwrite resolver.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OverwriteConflict {
    /// Raw archive path for the conflicting entry.
    pub archive_path: String,
    /// Existing destination path.
    pub destination_path: PathBuf,
}

/// Decision returned by an overwrite resolver.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OverwriteDecision {
    /// Replace the existing destination path.
    Replace,
    /// Skip this archive entry.
    Skip,
    /// Write this archive entry to a deterministic non-conflicting path.
    Rename,
    /// Abort extraction.
    Quit,
}

/// Provides decisions for interactive overwrite conflicts.
pub trait OverwriteResolver {
    /// Returns a decision for one destination conflict.
    fn decide(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision;
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

/// Returns true when this platform/backend build can materialize archive
/// symlinks as filesystem symlinks.
#[must_use]
pub(crate) fn symlink_extraction_supported() -> bool {
    cfg!(unix)
}

/// Returns true when a symlink entry is safe but cannot be materialized here.
#[must_use]
pub(crate) fn should_skip_symlink_materialization(kind: &ExtractionEntryKind) -> bool {
    matches!(kind, ExtractionEntryKind::Symlink { .. }) && !symlink_extraction_supported()
}

/// Standard warning for safe symlinks skipped on platforms without symlink
/// materialization support.
#[must_use]
pub(crate) fn unsupported_symlink_warning(archive_path: &str) -> String {
    format!("skipped symlink {archive_path}: symlink extraction is not supported on this platform")
}

/// Archive entry metadata needed before extraction writes to disk.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtractionEntry {
    /// Raw path from archive metadata.
    pub archive_path: String,
    /// Requested file type.
    pub kind: ExtractionEntryKind,
    /// Uncompressed regular-file size when the backend knows it before writing.
    pub uncompressed_size: Option<u64>,
    /// Compressed regular-file size when the backend exposes it per entry.
    pub compressed_size: Option<u64>,
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
        /// Resolved hardlink source path for archive formats that model
        /// hardlinks as references to other archive members.
        link_target_path: Option<PathBuf>,
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
pub struct ExtractionSafetyPlanner<'a> {
    destination_root: PathBuf,
    policy: ExtractionPolicy,
    seen_paths: HashMap<String, String>,
    planned_expanded_bytes: u64,
    overwrite_resolver: Option<&'a mut dyn OverwriteResolver>,
}

struct PlannedWrite {
    normalized_archive_path: String,
    destination_path: PathBuf,
    link_target_path: Option<PathBuf>,
    replace_existing: bool,
}

impl PlannedWrite {
    fn into_decision(self) -> ExtractionDecision {
        ExtractionDecision::Write {
            normalized_archive_path: self.normalized_archive_path,
            destination_path: self.destination_path,
            link_target_path: self.link_target_path,
            replace_existing: self.replace_existing,
        }
    }
}

enum PlannedDestination {
    Write(PlannedWrite),
    Skip {
        normalized_archive_path: String,
        reason: String,
    },
}

impl From<PlannedWrite> for PlannedDestination {
    fn from(plan: PlannedWrite) -> Self {
        Self::Write(plan)
    }
}

impl<'a> ExtractionSafetyPlanner<'a> {
    /// Creates a planner for one extraction destination.
    #[must_use]
    pub fn new(destination_root: impl Into<PathBuf>, policy: ExtractionPolicy) -> Self {
        let destination_root = lexically_normalize(&destination_root.into());

        Self {
            destination_root,
            policy,
            seen_paths: HashMap::new(),
            planned_expanded_bytes: 0,
            overwrite_resolver: None,
        }
    }

    /// Creates a planner that can resolve [`OverwritePolicy::Ask`] conflicts.
    #[must_use]
    pub fn new_with_overwrite_resolver(
        destination_root: impl Into<PathBuf>,
        policy: ExtractionPolicy,
        overwrite_resolver: &'a mut dyn OverwriteResolver,
    ) -> Self {
        let destination_root = lexically_normalize(&destination_root.into());

        Self {
            destination_root,
            policy,
            seen_paths: HashMap::new(),
            planned_expanded_bytes: 0,
            overwrite_resolver: Some(overwrite_resolver),
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
        let destination_path = lexically_normalize(&destination_path);
        ensure_inside_destination(
            &self.destination_root,
            &destination_path,
            &entry.archive_path,
        )?;

        let link_target_path = match &entry.kind {
            ExtractionEntryKind::Symlink { target } => {
                self.validate_symlink_target(&destination_path, target)?;
                None
            }
            ExtractionEntryKind::Hardlink { target } => Some(self.resolve_hardlink_target(target)?),
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
            ExtractionEntryKind::File | ExtractionEntryKind::Directory => None,
        };

        self.reject_collision(&normalized_archive_path)?;

        let plan = self.plan_destination_write(
            entry,
            normalized_archive_path,
            destination_path,
            link_target_path,
        )?;

        match plan {
            PlannedDestination::Write(plan) => {
                self.reserve_expanded_size(entry)?;
                Ok(plan.into_decision())
            }
            PlannedDestination::Skip {
                normalized_archive_path,
                reason,
            } => Ok(ExtractionDecision::Skip {
                normalized_archive_path,
                reason,
            }),
        }
    }

    fn plan_destination_write(
        &mut self,
        entry: &ExtractionEntry,
        normalized_archive_path: String,
        mut destination_path: PathBuf,
        link_target_path: Option<PathBuf>,
    ) -> Result<PlannedDestination, ExtractionSafetyError> {
        let mut replace_existing = false;
        let destination_metadata = std::fs::symlink_metadata(&destination_path);
        if let Ok(metadata) = destination_metadata {
            match self.policy.overwrite {
                OverwritePolicy::Refuse => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory)
                        && metadata.file_type().is_dir()
                    {
                        return Ok(PlannedWrite {
                            normalized_archive_path,
                            destination_path,
                            link_target_path,
                            replace_existing: false,
                        }
                        .into());
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
                        return Ok(PlannedWrite {
                            normalized_archive_path,
                            destination_path,
                            link_target_path,
                            replace_existing: false,
                        }
                        .into());
                    }
                    destination_path = next_available_destination_path(&destination_path);
                }
                OverwritePolicy::Ask => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory)
                        && metadata.file_type().is_dir()
                    {
                        return Ok(PlannedWrite {
                            normalized_archive_path,
                            destination_path,
                            link_target_path,
                            replace_existing: false,
                        }
                        .into());
                    }
                    let decision = self.resolve_overwrite_conflict(entry, &destination_path)?;
                    match decision {
                        OverwriteDecision::Replace => {
                            replace_existing = true;
                        }
                        OverwriteDecision::Skip => {
                            return Ok(PlannedDestination::Skip {
                                normalized_archive_path,
                                reason: "skipped by overwrite prompt".to_owned(),
                            });
                        }
                        OverwriteDecision::Rename => {
                            destination_path = next_available_destination_path(&destination_path);
                        }
                        OverwriteDecision::Quit => {
                            return Err(ExtractionSafetyError::OverwriteAborted {
                                archive_path: entry.archive_path.clone(),
                                destination_path,
                            });
                        }
                    }
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

        Ok(PlannedWrite {
            normalized_archive_path,
            destination_path,
            link_target_path,
            replace_existing,
        }
        .into())
    }

    fn resolve_overwrite_conflict(
        &mut self,
        entry: &ExtractionEntry,
        destination_path: &Path,
    ) -> Result<OverwriteDecision, ExtractionSafetyError> {
        let Some(resolver) = self.overwrite_resolver.as_deref_mut() else {
            return Err(ExtractionSafetyError::OverwritePromptUnavailable {
                archive_path: entry.archive_path.clone(),
                destination_path: destination_path.to_path_buf(),
            });
        };
        Ok(resolver.decide(&OverwriteConflict {
            archive_path: entry.archive_path.clone(),
            destination_path: destination_path.to_path_buf(),
        }))
    }

    fn reject_collision(
        &mut self,
        normalized_archive_path: &str,
    ) -> Result<(), ExtractionSafetyError> {
        let collision_key = case_collision_key(normalized_archive_path);

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

    fn validate_symlink_target(
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

    fn resolve_hardlink_target(&self, target: &Path) -> Result<PathBuf, ExtractionSafetyError> {
        let target_text = target.to_string_lossy();
        let mut normalized_target = normalize_archive_path(&target_text).map_err(|_| {
            ExtractionSafetyError::LinkTargetEscapes {
                target: target.to_path_buf(),
            }
        })?;
        if self.policy.strip_components > 0 {
            normalized_target =
                strip_archive_components(&normalized_target, self.policy.strip_components)
                    .ok_or_else(|| ExtractionSafetyError::LinkTargetEscapes {
                        target: target.to_path_buf(),
                    })?;
        }

        let target_path = lexically_normalize(&self.destination_root.join(normalized_target));
        if target_path.starts_with(&self.destination_root) {
            return Ok(target_path);
        }

        Err(ExtractionSafetyError::LinkTargetEscapes {
            target: target.to_path_buf(),
        })
    }

    fn reserve_expanded_size(
        &mut self,
        entry: &ExtractionEntry,
    ) -> Result<(), ExtractionSafetyError> {
        if !matches!(entry.kind, ExtractionEntryKind::File) {
            return Ok(());
        }
        let Some(uncompressed_size) = entry.uncompressed_size else {
            return Ok(());
        };

        if let Some(ratio_limit) = self.policy.limits.max_entry_expansion_ratio {
            reject_expansion_ratio(
                &entry.archive_path,
                uncompressed_size,
                entry.compressed_size,
                ratio_limit,
            )?;
        }

        if let Some(total_limit) = self.policy.limits.max_expanded_bytes {
            let attempted = self
                .planned_expanded_bytes
                .saturating_add(uncompressed_size);
            if attempted > total_limit {
                return Err(ExtractionSafetyError::ExpandedSizeLimitExceeded {
                    archive_path: entry.archive_path.clone(),
                    attempted_bytes: attempted,
                    limit_bytes: total_limit,
                });
            }
            self.planned_expanded_bytes = attempted;
        }

        Ok(())
    }
}

fn case_collision_key(path: &str) -> String {
    path.chars().flat_map(char::to_lowercase).collect()
}

fn reject_expansion_ratio(
    archive_path: &str,
    uncompressed_size: u64,
    compressed_size: Option<u64>,
    ratio_limit: u64,
) -> Result<(), ExtractionSafetyError> {
    let Some(compressed_size) = compressed_size else {
        return Ok(());
    };
    let exceeds_limit = if compressed_size == 0 {
        uncompressed_size > 0
    } else {
        u128::from(uncompressed_size) > u128::from(compressed_size) * u128::from(ratio_limit)
    };

    if exceeds_limit {
        return Err(ExtractionSafetyError::ExpansionRatioLimitExceeded {
            archive_path: archive_path.to_owned(),
            uncompressed_size,
            compressed_size,
            ratio_limit,
        });
    }

    Ok(())
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
    /// Interactive overwrite was requested without a resolver.
    OverwritePromptUnavailable {
        archive_path: String,
        destination_path: PathBuf,
    },
    /// User aborted extraction from an overwrite prompt.
    OverwriteAborted {
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
    /// Planned expanded bytes exceed the configured extraction policy.
    ExpandedSizeLimitExceeded {
        /// Archive path that crossed the limit.
        archive_path: String,
        /// Total bytes that would be planned.
        attempted_bytes: u64,
        /// Configured limit.
        limit_bytes: u64,
    },
    /// Entry-level compression ratio exceeds the configured extraction policy.
    ExpansionRatioLimitExceeded {
        /// Archive path that crossed the limit.
        archive_path: String,
        /// Entry uncompressed size.
        uncompressed_size: u64,
        /// Entry compressed size.
        compressed_size: u64,
        /// Configured ratio limit.
        ratio_limit: u64,
    },
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
            Self::OverwritePromptUnavailable {
                archive_path,
                destination_path,
            } => write!(
                f,
                "archive path {archive_path} requires an overwrite decision for {}",
                destination_path.display()
            ),
            Self::OverwriteAborted {
                archive_path,
                destination_path,
            } => write!(
                f,
                "overwrite prompt aborted while handling archive path {archive_path} for {}",
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
            Self::ExpandedSizeLimitExceeded {
                archive_path,
                attempted_bytes,
                limit_bytes,
            } => write!(
                f,
                "archive path {archive_path} would expand extraction to {attempted_bytes} bytes, exceeding the {limit_bytes} byte limit"
            ),
            Self::ExpansionRatioLimitExceeded {
                archive_path,
                uncompressed_size,
                compressed_size,
                ratio_limit,
            } => write!(
                f,
                "archive path {archive_path} expands from {compressed_size} to {uncompressed_size} bytes, exceeding the {ratio_limit}:1 ratio limit"
            ),
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

/// Creates and canonicalizes an extraction root before safety planning.
///
/// Extraction planners compare candidate output paths against this root. Using
/// the canonical root keeps that comparison stable when callers pass paths with
/// `..` components or a symlinked destination directory.
///
/// # Errors
///
/// Returns any filesystem error from creating or canonicalizing the root.
pub fn prepare_destination_root(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(path)?;
    path.canonicalize()
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
        ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionLimits,
        ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteConflict,
        OverwriteDecision, OverwritePolicy, OverwriteResolver, UnsafeFilePolicy,
        normalize_archive_path, prepare_destination_root,
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
    fn rejects_unicode_case_insensitive_collisions() {
        let temp = TestDir::new("rejects_unicode_case_insensitive_collisions");
        let mut planner =
            ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        planner.validate_entry(&file_entry("Über.txt")).unwrap();
        let error = planner.validate_entry(&file_entry("über.txt")).unwrap_err();

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
    fn asks_overwrite_resolver_for_conflicts() {
        let temp = TestDir::new("asks_overwrite_resolver_for_conflicts");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy {
            overwrite: OverwritePolicy::Ask,
            ..ExtractionPolicy::default()
        };
        let mut resolver = FixedOverwriteResolver(OverwriteDecision::Skip);
        let mut planner = ExtractionSafetyPlanner::new_with_overwrite_resolver(
            temp.path("out"),
            policy,
            &mut resolver,
        );

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    #[test]
    fn ask_overwrite_renames_conflicts_safely() {
        let temp = TestDir::new("ask_overwrite_renames_conflicts_safely");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy {
            overwrite: OverwritePolicy::Ask,
            ..ExtractionPolicy::default()
        };
        let mut resolver = FixedOverwriteResolver(OverwriteDecision::Rename);
        let mut planner = ExtractionSafetyPlanner::new_with_overwrite_resolver(
            temp.path("out"),
            policy,
            &mut resolver,
        );

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        let ExtractionDecision::Write {
            destination_path, ..
        } = decision
        else {
            panic!("expected renamed write decision");
        };
        assert_eq!(destination_path, temp.path("out/file (1).txt"));
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
            uncompressed_size: None,
            compressed_size: None,
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
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Write { .. }));
    }

    #[test]
    fn resolves_hardlink_target_as_archive_member_path_after_strip() {
        let temp = TestDir::new("resolves_hardlink_target_as_archive_member_path_after_strip");
        let policy = ExtractionPolicy {
            strip_components: 1,
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);
        let entry = ExtractionEntry {
            archive_path: "project/dir/link.txt".to_owned(),
            kind: ExtractionEntryKind::Hardlink {
                target: PathBuf::from("project/dir/target.txt"),
            },
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        let ExtractionDecision::Write {
            destination_path,
            link_target_path: Some(link_target_path),
            ..
        } = decision
        else {
            panic!("expected resolved hardlink write decision");
        };
        assert_eq!(destination_path, temp.path("out/dir/link.txt"));
        assert_eq!(link_target_path, temp.path("out/dir/target.txt"));
    }

    #[test]
    fn prepare_destination_root_canonicalizes_dotdot_paths() {
        let temp = TestDir::new("prepare_destination_root_canonicalizes_dotdot_paths");
        let root = temp.path("out");
        fs::create_dir_all(&root).unwrap();

        let prepared = prepare_destination_root(&temp.path("nested/../out")).unwrap();

        assert_eq!(prepared, root.canonicalize().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_destination_root_resolves_symlinked_roots() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("prepare_destination_root_resolves_symlinked_roots");
        let target = temp.path("target");
        let link = temp.path("link");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &link).unwrap();

        let prepared = prepare_destination_root(&link).unwrap();

        assert_eq!(prepared, target.canonicalize().unwrap());
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
            uncompressed_size: None,
            compressed_size: None,
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::LinkTargetEscapes { .. }
        ));
    }

    #[test]
    fn rejects_extraction_when_total_expanded_size_exceeds_limit() {
        let temp = TestDir::new("rejects_extraction_when_total_expanded_size_exceeds_limit");
        let policy = ExtractionPolicy {
            limits: ExtractionLimits {
                max_expanded_bytes: Some(5),
                max_entry_expansion_ratio: None,
            },
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        planner
            .validate_entry(&sized_file_entry("one.bin", 3, Some(3)))
            .unwrap();
        let error = planner
            .validate_entry(&sized_file_entry("two.bin", 3, Some(3)))
            .unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }
        ));
    }

    #[test]
    fn rejects_entry_when_expansion_ratio_exceeds_limit() {
        let temp = TestDir::new("rejects_entry_when_expansion_ratio_exceeds_limit");
        let policy = ExtractionPolicy {
            limits: ExtractionLimits {
                max_expanded_bytes: None,
                max_entry_expansion_ratio: Some(10),
            },
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        let error = planner
            .validate_entry(&sized_file_entry("bomb.bin", 100, Some(1)))
            .unwrap_err();

        assert!(matches!(
            error,
            ExtractionSafetyError::ExpansionRatioLimitExceeded { .. }
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
            uncompressed_size: None,
            compressed_size: None,
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
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    fn file_entry(archive_path: &str) -> ExtractionEntry {
        sized_file_entry(archive_path, 1, Some(1))
    }

    fn sized_file_entry(
        archive_path: &str,
        uncompressed_size: u64,
        compressed_size: Option<u64>,
    ) -> ExtractionEntry {
        ExtractionEntry {
            archive_path: archive_path.to_owned(),
            kind: ExtractionEntryKind::File,
            uncompressed_size: Some(uncompressed_size),
            compressed_size,
        }
    }

    struct FixedOverwriteResolver(OverwriteDecision);

    impl OverwriteResolver for FixedOverwriteResolver {
        fn decide(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
            assert_eq!(conflict.archive_path, "file.txt");
            self.0
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
