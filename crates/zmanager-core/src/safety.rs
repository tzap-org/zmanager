use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

const DEFAULT_MAX_EXTRACTED_MIB: u64 = 64 * 1024;
/// Default maximum total uncompressed bytes planned for one extraction.
pub const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_EXTRACTED_MIB * crate::MEBIBYTE_BYTES;
/// Default maximum entry-level uncompressed-to-compressed size ratio.
pub const DEFAULT_MAX_ENTRY_EXPANSION_RATIO: u64 = 1_000;

/// Expanded-size guardrails applied while planning extraction writes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExtractionLimits {
    /// Maximum total uncompressed file bytes for one extraction. `None`
    /// disables the total-size guard.
    pub max_expanded_bytes: Option<u64>,
    /// Maximum per-entry uncompressed-to-compressed ratio. `None` disables the
    /// ratio guard when compressed size metadata is available.
    pub max_entry_expansion_ratio: Option<u64>,
    /// Maximum number of selected archive entries that may be materialized.
    pub max_entries: Option<u64>,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self { max_expanded_bytes: Some(DEFAULT_MAX_EXTRACTED_BYTES), max_entry_expansion_ratio: Some(DEFAULT_MAX_ENTRY_EXPANSION_RATIO), max_entries: None }
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
    /// Whether to ignore symbolic links during extraction.
    pub ignore_symlinks: bool,
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
            ignore_symlinks: false,
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

/// A reborrow of an overwrite resolver whose trait-object lifetime is chosen
/// fresh at the point of use.
///
/// `Option<&'long mut dyn OverwriteResolver>` cannot be narrowed to
/// `Option<&'short mut dyn OverwriteResolver>`: the pointee of a `&mut` is
/// invariant, so the `dyn ... + 'long` bound is stuck. Routing the reborrow
/// through a concrete type re-runs the unsizing coercion, letting each caller
/// pick a bound that fits its own borrow. This is what lets one caller-owned
/// resolver be handed to a sequence of per-entry operations.
pub(crate) struct ReborrowedResolver<'r, 'resolver: 'r>(&'r mut (dyn OverwriteResolver + 'resolver));

impl<'r, 'resolver: 'r> ReborrowedResolver<'r, 'resolver> {
    pub(crate) fn new(resolver: &'r mut (dyn OverwriteResolver + 'resolver)) -> Self {
        Self(resolver)
    }
}

impl OverwriteResolver for ReborrowedResolver<'_, '_> {
    fn decide(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
        self.0.decide(conflict)
    }
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

/// Returns a linear-time materialization order for deferred filesystem links.
///
/// Each pair is `(source, destination)`. A source produced by another pair is
/// ordered after that dependency; sources outside the deferred set must
/// already exist. Cycles and missing sources are rejected.
pub(crate) fn deferred_link_dependency_order(links: &[(PathBuf, PathBuf)]) -> io::Result<Vec<usize>> {
    let destinations = links.iter().enumerate().map(|(index, (_, destination))| (destination.clone(), index)).collect::<HashMap<_, _>>();
    let mut dependency_counts = vec![0_usize; links.len()];
    let mut dependents = vec![Vec::new(); links.len()];

    for (index, (source, _)) in links.iter().enumerate() {
        if let Some(&dependency) = destinations.get(source) {
            dependency_counts[index] = 1;
            dependents[dependency].push(index);
        } else if let Err(source_error) = std::fs::symlink_metadata(source) {
            return Err(io::Error::new(source_error.kind(), format!("deferred link target was not materialized: {}", source.display())));
        }
    }

    let mut ready = dependency_counts.iter().enumerate().filter_map(|(index, count)| (*count == 0).then_some(index)).collect::<VecDeque<_>>();
    let mut order = Vec::with_capacity(links.len());
    while let Some(index) = ready.pop_front() {
        order.push(index);
        for &dependent in &dependents[index] {
            dependency_counts[dependent] -= 1;
            if dependency_counts[dependent] == 0 {
                ready.push_back(dependent);
            }
        }
    }

    if order.len() != links.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "deferred link dependency cycle"));
    }
    Ok(order)
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
    compiled_includes: Vec<CompiledPattern>,
    compiled_excludes: Vec<CompiledPattern>,
    seen_paths: HashMap<String, String>,
    planned_expanded_bytes: u64,
    planned_entries: u64,
    /// Lowest rename suffix not yet known to be taken, keyed by the conflicting
    /// destination path. Without it, extracting many entries that collide on one
    /// name re-probes from " 2" every time, which is quadratic in the batch size.
    next_rename_index: HashMap<PathBuf, u64>,
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
    Skip { normalized_archive_path: String, reason: String },
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
        Self::with_overwrite_resolver(destination_root, policy, None)
    }

    /// Creates a planner that can resolve [`OverwritePolicy::Ask`] conflicts.
    #[must_use]
    pub fn new_with_overwrite_resolver(
        destination_root: impl Into<PathBuf>,
        policy: ExtractionPolicy,
        overwrite_resolver: &'a mut dyn OverwriteResolver,
    ) -> Self {
        Self::with_overwrite_resolver(destination_root, policy, Some(overwrite_resolver))
    }

    /// Shared constructor: normalizes the destination root and wires up the
    /// optional overwrite resolver, so both public constructors behave
    /// identically.
    pub fn with_overwrite_resolver(
        destination_root: impl Into<PathBuf>,
        policy: ExtractionPolicy,
        overwrite_resolver: Option<&'a mut dyn OverwriteResolver>,
    ) -> Self {
        let destination_root = lexically_normalize(&destination_root.into());
        let compiled_includes = policy.include_patterns.iter().map(|p| CompiledPattern::new(p)).collect();
        let compiled_excludes = policy.exclude_patterns.iter().map(|p| CompiledPattern::new(p)).collect();

        Self {
            destination_root,
            policy,
            compiled_includes,
            compiled_excludes,
            seen_paths: HashMap::new(),
            planned_expanded_bytes: 0,
            planned_entries: 0,
            next_rename_index: HashMap::new(),
            overwrite_resolver,
        }
    }

    fn is_path_selected(&self, path: &str) -> bool {
        let matches_include = self.compiled_includes.is_empty() || self.compiled_includes.iter().any(|p| p.matches(path));
        let matches_exclude = self.compiled_excludes.iter().any(|p| p.matches(path));
        matches_include && !matches_exclude
    }

    /// Validates one archive entry before extraction.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractionSafetyError`] when the archive path, link target,
    /// overwrite behavior, file type, or name collision would violate the
    /// configured safety policy.
    pub fn validate_entry(&mut self, entry: &ExtractionEntry) -> Result<ExtractionDecision, ExtractionSafetyError> {
        let mut normalized_archive_path = normalize_archive_path(&entry.archive_path)?;
        if !self.is_path_selected(&normalized_archive_path) {
            return Ok(ExtractionDecision::Skip { normalized_archive_path, reason: "filtered by include/exclude policy".to_owned() });
        }
        if self.policy.strip_components > 0 {
            let stripped = strip_archive_components(&normalized_archive_path, self.policy.strip_components);
            let Some(stripped) = stripped else {
                return Ok(ExtractionDecision::Skip { normalized_archive_path, reason: "path removed by strip-components policy".to_owned() });
            };
            normalized_archive_path = stripped;
        }
        self.reserve_entry(&normalized_archive_path)?;
        let destination_path = self.destination_root.join(&normalized_archive_path);
        let destination_path = lexically_normalize(&destination_path);
        ensure_inside_destination(&self.destination_root, &destination_path, &entry.archive_path)?;

        let link_target_path = match &entry.kind {
            ExtractionEntryKind::Symlink { target } => {
                if self.policy.ignore_symlinks {
                    return Ok(ExtractionDecision::Skip { normalized_archive_path, reason: "skipped symbolic link by policy".to_owned() });
                }
                self.validate_symlink_target(&destination_path, target)?;
                None
            }
            ExtractionEntryKind::Hardlink { target } => Some(self.resolve_hardlink_target(target)?),
            ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                if self.policy.unsafe_file == UnsafeFilePolicy::Skip {
                    return Ok(ExtractionDecision::Skip { normalized_archive_path, reason: "unsafe file type skipped by policy".to_owned() });
                }

                return Err(ExtractionSafetyError::UnsafeFileType { archive_path: entry.archive_path.clone() });
            }
            ExtractionEntryKind::File | ExtractionEntryKind::Directory => None,
        };

        if self.policy.overwrite != OverwritePolicy::Replace {
            self.reject_collision(&normalized_archive_path)?;
        }

        let plan = self.plan_destination_write(entry, normalized_archive_path, destination_path, link_target_path)?;

        match plan {
            PlannedDestination::Write(plan) => {
                self.reserve_expanded_size(entry)?;
                Ok(plan.into_decision())
            }
            PlannedDestination::Skip { normalized_archive_path, reason } => Ok(ExtractionDecision::Skip { normalized_archive_path, reason }),
        }
    }

    fn plan_destination_write(
        &mut self,
        entry: &ExtractionEntry,
        normalized_archive_path: String,
        mut destination_path: PathBuf,
        link_target_path: Option<PathBuf>,
    ) -> Result<PlannedDestination, ExtractionSafetyError> {
        // Replace must select the rename-based atomic commit for regular
        // files even when the destination is absent. The refuse path uses a
        // hard link to enforce no-clobber semantics; that operation is
        // unavailable on Android's app-cache filesystems, including freshly
        // created staging roots. Directories are materialized separately and
        // must not be replaced when absent: readers such as 7z may emit the
        // directory after its child files.
        let mut replace_existing = matches!(self.policy.overwrite, OverwritePolicy::Replace) && !matches!(entry.kind, ExtractionEntryKind::Directory);
        let destination_metadata = std::fs::symlink_metadata(&destination_path);
        if let Ok(metadata) = destination_metadata {
            match self.policy.overwrite {
                OverwritePolicy::Refuse => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory) && metadata.file_type().is_dir() {
                        return Ok(PlannedWrite { normalized_archive_path, destination_path, link_target_path, replace_existing: false }.into());
                    }
                    return Err(ExtractionSafetyError::DestinationExists { archive_path: entry.archive_path.clone(), destination_path });
                }
                OverwritePolicy::Replace => {
                    replace_existing = !matches!(entry.kind, ExtractionEntryKind::Directory) || !metadata.file_type().is_dir();
                }
                OverwritePolicy::Rename => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory) && metadata.file_type().is_dir() {
                        return Ok(PlannedWrite { normalized_archive_path, destination_path, link_target_path, replace_existing: false }.into());
                    }
                    destination_path = self.rename_candidate_or_error(entry, destination_path)?;
                }
                OverwritePolicy::Ask => {
                    if matches!(entry.kind, ExtractionEntryKind::Directory) && metadata.file_type().is_dir() {
                        return Ok(PlannedWrite { normalized_archive_path, destination_path, link_target_path, replace_existing: false }.into());
                    }
                    let decision = self.resolve_overwrite_conflict(entry, &destination_path)?;
                    match decision {
                        OverwriteDecision::Replace => {
                            replace_existing = true;
                        }
                        OverwriteDecision::Skip => {
                            return Ok(PlannedDestination::Skip { normalized_archive_path, reason: "skipped by overwrite prompt".to_owned() });
                        }
                        OverwriteDecision::Rename => {
                            destination_path = self.rename_candidate_or_error(entry, destination_path)?;
                        }
                        OverwriteDecision::Quit => {
                            return Err(ExtractionSafetyError::OverwriteAborted { archive_path: entry.archive_path.clone(), destination_path });
                        }
                    }
                }
            }
        } else if let Err(error) = destination_metadata
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(ExtractionSafetyError::DestinationProbe { archive_path: entry.archive_path.clone(), destination_path, message: error.to_string() });
        }

        Ok(PlannedWrite { normalized_archive_path, destination_path, link_target_path, replace_existing }.into())
    }

    fn resolve_overwrite_conflict(&mut self, entry: &ExtractionEntry, destination_path: &Path) -> Result<OverwriteDecision, ExtractionSafetyError> {
        let Some(resolver) = self.overwrite_resolver.as_deref_mut() else {
            return Err(ExtractionSafetyError::OverwritePromptUnavailable {
                archive_path: entry.archive_path.clone(),
                destination_path: destination_path.to_path_buf(),
            });
        };
        Ok(resolver.decide(&OverwriteConflict { archive_path: entry.archive_path.clone(), destination_path: destination_path.to_path_buf() }))
    }

    /// Resolves a renamed destination for a conflicting path, mapping an
    /// exhausted candidate space to an error instead of falling back to the
    /// original (existing) path, which would overwrite in place.
    ///
    /// Successive conflicts on the same name resume probing above the suffix
    /// this planner last handed out, so a batch that collides repeatedly stays
    /// linear rather than re-walking the taken suffixes for every entry.
    fn rename_candidate_or_error(&mut self, entry: &ExtractionEntry, destination_path: PathBuf) -> Result<PathBuf, ExtractionSafetyError> {
        let start_index = self.next_rename_index.get(&destination_path).copied().unwrap_or(FIRST_RENAME_INDEX);
        let Some((candidate, resume_index)) = next_available_destination_path_from(&destination_path, start_index, MAX_RENAME_CANDIDATES) else {
            return Err(ExtractionSafetyError::RenameDestinationExhausted { archive_path: entry.archive_path.clone(), destination_path });
        };

        self.next_rename_index.insert(destination_path, resume_index);
        Ok(candidate)
    }

    fn reject_collision(&mut self, normalized_archive_path: &str) -> Result<(), ExtractionSafetyError> {
        let collision_key = case_collision_key(normalized_archive_path);

        if let Some(previous_archive_path) = self.seen_paths.insert(collision_key, normalized_archive_path.to_owned()) {
            return Err(ExtractionSafetyError::NameCollision { archive_path: normalized_archive_path.to_owned(), previous_archive_path });
        }

        Ok(())
    }

    fn validate_symlink_target(&self, destination_path: &Path, target: &Path) -> Result<(), ExtractionSafetyError> {
        let target_text = target.to_string_lossy();
        reject_raw_path_hazards(&target_text)?;
        if target.is_absolute() {
            return Err(ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() });
        }

        let Some(parent) = destination_path.parent() else {
            return Err(ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() });
        };
        let resolved_target = lexically_normalize(&parent.join(target));

        if !resolved_target.starts_with(&self.destination_root) {
            return Err(ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() });
        }

        Ok(())
    }

    fn resolve_hardlink_target(&self, target: &Path) -> Result<PathBuf, ExtractionSafetyError> {
        let target_text = target.to_string_lossy();
        let mut normalized_target =
            normalize_archive_path(&target_text).map_err(|_| ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() })?;
        if self.policy.strip_components > 0 {
            normalized_target = strip_archive_components(&normalized_target, self.policy.strip_components)
                .ok_or_else(|| ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() })?;
        }

        let target_path = lexically_normalize(&self.destination_root.join(normalized_target));
        if target_path.starts_with(&self.destination_root) {
            return Ok(target_path);
        }

        Err(ExtractionSafetyError::LinkTargetEscapes { target: target.to_path_buf() })
    }

    fn reserve_expanded_size(&mut self, entry: &ExtractionEntry) -> Result<(), ExtractionSafetyError> {
        if !matches!(entry.kind, ExtractionEntryKind::File) {
            return Ok(());
        }
        let Some(uncompressed_size) = entry.uncompressed_size else {
            return Ok(());
        };

        if let Some(ratio_limit) = self.policy.limits.max_entry_expansion_ratio {
            reject_expansion_ratio(&entry.archive_path, uncompressed_size, entry.compressed_size, ratio_limit)?;
        }

        self.reserve_expanded_bytes(&entry.archive_path, uncompressed_size)
    }

    fn reserve_entry(&mut self, archive_path: &str) -> Result<(), ExtractionSafetyError> {
        if let Some(limit) = self.policy.limits.max_entries {
            let attempted = self.planned_entries.saturating_add(1);
            if attempted > limit {
                return Err(ExtractionSafetyError::EntryCountLimitExceeded {
                    archive_path: archive_path.to_owned(),
                    attempted_entries: attempted,
                    limit_entries: limit,
                });
            }
            self.planned_entries = attempted;
        }
        Ok(())
    }

    /// Reserves `bytes` against the expanded-size limit for an entry that is
    /// not planned as [`ExtractionEntryKind::File`].
    ///
    /// Backends use this for link-like entries that copy their full source
    /// bytes at materialization — notably RAR `FileCopy` entries, which the
    /// planner validates as hardlinks but must still consume expansion
    /// budget, otherwise a solid archive of copies bypasses the size guard.
    pub(crate) fn reserve_expanded_bytes(&mut self, archive_path: &str, bytes: u64) -> Result<(), ExtractionSafetyError> {
        if let Some(total_limit) = self.policy.limits.max_expanded_bytes {
            let attempted = self.planned_expanded_bytes.saturating_add(bytes);
            if attempted > total_limit {
                return Err(ExtractionSafetyError::ExpandedSizeLimitExceeded {
                    archive_path: archive_path.to_owned(),
                    attempted_bytes: attempted,
                    limit_bytes: total_limit,
                });
            }
            self.planned_expanded_bytes = attempted;
        }

        Ok(())
    }
}

/// Case-folding collision key shared by extraction planning and manifest
/// planning. The Unicode-aware lowercase mapping matches what
/// case-insensitive file systems (APFS, NTFS, FAT) compare at a level far
/// closer than ASCII-only folding, so both planning passes agree on which
/// names would collide on such systems.
pub fn case_collision_key(path: &str) -> String {
    if path.is_ascii() { path.to_ascii_lowercase() } else { path.chars().flat_map(char::to_lowercase).collect() }
}

fn reject_expansion_ratio(archive_path: &str, uncompressed_size: u64, compressed_size: Option<u64>, ratio_limit: u64) -> Result<(), ExtractionSafetyError> {
    let Some(compressed_size) = compressed_size else {
        return Ok(());
    };
    let exceeds_limit =
        if compressed_size == 0 { uncompressed_size > 0 } else { u128::from(uncompressed_size) > u128::from(compressed_size) * u128::from(ratio_limit) };

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
    /// Archive path exceeds the maximum allowed length.
    PathTooLong { path: String },
    /// Archive path contains a Windows reserved device name.
    WindowsReservedName { path: String, component: String },
    /// Normalized destination escapes the extraction root.
    DestinationEscape { archive_path: String, destination_root: PathBuf, destination_path: PathBuf },
    /// Entry collides with a previous archive path.
    NameCollision { archive_path: String, previous_archive_path: String },
    /// Entry would overwrite an existing destination path.
    DestinationExists { archive_path: String, destination_path: PathBuf },
    /// Interactive overwrite was requested without a resolver.
    OverwritePromptUnavailable { archive_path: String, destination_path: PathBuf },
    /// User aborted extraction from an overwrite prompt.
    OverwriteAborted { archive_path: String, destination_path: PathBuf },
    /// Destination existence could not be checked safely.
    DestinationProbe { archive_path: String, destination_path: PathBuf, message: String },
    /// Entry type is unsafe by default.
    UnsafeFileType { archive_path: String },
    /// Link target resolves outside the extraction root.
    LinkTargetEscapes { target: PathBuf },
    /// All deterministic renamed destinations are already taken.
    RenameDestinationExhausted { archive_path: String, destination_path: PathBuf },
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
    /// The selected entry count exceeds the configured extraction policy.
    EntryCountLimitExceeded {
        /// Archive path that crossed the limit.
        archive_path: String,
        /// Number of selected entries that would be materialized.
        attempted_entries: u64,
        /// Configured entry limit.
        limit_entries: u64,
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
            Self::PathTooLong { path } => {
                write!(f, "archive path is too long: {path}")
            }
            Self::WindowsReservedName { path, component } => {
                write!(f, "archive path contains a Windows reserved device name ({component}): {path}")
            }
            Self::DestinationEscape { archive_path, destination_root, destination_path } => {
                write!(f, "archive path {archive_path} resolves outside {} to {}", destination_root.display(), destination_path.display())
            }
            Self::NameCollision { archive_path, previous_archive_path } => {
                write!(f, "archive path {archive_path} collides with previous entry {previous_archive_path}")
            }
            Self::DestinationExists { archive_path, destination_path } => {
                write!(f, "archive path {archive_path} would overwrite {}", destination_path.display())
            }
            Self::OverwritePromptUnavailable { archive_path, destination_path } => {
                write!(f, "archive path {archive_path} requires an overwrite decision for {}", destination_path.display())
            }
            Self::OverwriteAborted { archive_path, destination_path } => {
                write!(f, "overwrite prompt aborted while handling archive path {archive_path} for {}", destination_path.display())
            }
            Self::DestinationProbe { archive_path, destination_path, message } => {
                write!(f, "archive path {archive_path} could not check {}: {message}", destination_path.display())
            }
            Self::UnsafeFileType { archive_path } => {
                write!(f, "archive path {archive_path} has an unsafe file type")
            }
            Self::LinkTargetEscapes { target } => {
                write!(f, "link target escapes extraction root: {}", target.display())
            }
            Self::RenameDestinationExhausted { archive_path, destination_path } => {
                write!(f, "archive path {archive_path} has no available renamed destination for {}", destination_path.display())
            }
            Self::ExpandedSizeLimitExceeded { archive_path, attempted_bytes, limit_bytes } => {
                write!(f, "archive path {archive_path} would expand extraction to {attempted_bytes} bytes, exceeding the {limit_bytes} byte limit")
            }
            Self::ExpansionRatioLimitExceeded { archive_path, uncompressed_size, compressed_size, ratio_limit } => {
                write!(f, "archive path {archive_path} expands from {compressed_size} to {uncompressed_size} bytes, exceeding the {ratio_limit}:1 ratio limit")
            }
            Self::EntryCountLimitExceeded { archive_path, attempted_entries, limit_entries } => {
                write!(f, "archive path {archive_path} would bring extraction to {attempted_entries} entries, exceeding the {limit_entries} entry limit")
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
        if part.len() > 255 {
            return Err(ExtractionSafetyError::PathTooLong { path: raw_path.to_owned() });
        }
        let upper = part.to_ascii_uppercase();
        let stem = upper.split('.').next().unwrap_or(&upper);
        if matches!(
            stem,
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(ExtractionSafetyError::WindowsReservedName { path: raw_path.to_owned(), component: part.to_owned() });
        }
        match part {
            "" | "." => {}
            ".." => {
                return Err(ExtractionSafetyError::ParentTraversal { path: raw_path.to_owned() });
            }
            safe_part => parts.push(safe_part),
        }
    }

    if parts.is_empty() {
        return Err(ExtractionSafetyError::EmptyPath);
    }

    Ok(parts.join("/"))
}

/// Normalizes a path selector for matching against archive entry paths.
#[must_use]
pub fn normalize_selector(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').split('/').filter(|segment| !segment.is_empty() && *segment != ".").collect::<Vec<_>>().join("/")
}

/// Returns true when `norm_entry` matches `norm_selected` or is a descendant of `norm_selected`.
#[must_use]
pub fn normalized_entry_matches_normalized_selector(norm_entry: &str, norm_selected: &str) -> bool {
    if norm_selected.is_empty() {
        return true;
    }
    if norm_entry == norm_selected {
        return true;
    }
    if norm_entry.len() > norm_selected.len() && norm_entry.starts_with(norm_selected) && norm_entry.as_bytes()[norm_selected.len()] == b'/' {
        return true;
    }
    false
}

/// Returns true when `entry_path` matches `selected_path` or is a descendant of `selected_path`.
///
/// Both paths are normalized using slash separators and stripped of leading/trailing dots and slashes.
#[must_use]
pub fn archive_entry_matches_selected(entry_path: &str, selected_path: &str) -> bool {
    let norm_entry = normalize_selector(entry_path);
    let norm_selected = normalize_selector(selected_path);
    normalized_entry_matches_normalized_selector(&norm_entry, &norm_selected)
}

fn reject_raw_path_hazards(raw_path: &str) -> Result<(), ExtractionSafetyError> {
    if raw_path.contains('\0') {
        return Err(ExtractionSafetyError::NulByte { path: raw_path.to_owned() });
    }

    let slash_path = raw_path.replace('\\', "/");
    if has_windows_prefix(&slash_path) {
        return Err(ExtractionSafetyError::WindowsPrefix { path: raw_path.to_owned() });
    }

    if slash_path.starts_with('/') {
        return Err(ExtractionSafetyError::AbsolutePath { path: raw_path.to_owned() });
    }

    Ok(())
}

fn has_windows_prefix(path: &str) -> bool {
    // The drive-letter check is deliberately conservative: it rejects any
    // leading `X:` path component, including ones like `a:b` that are not
    // real Windows prefixes. Rejecting a few harmless archive paths is fine;
    // accepting a real Windows prefix is not.
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }

    path.starts_with("//")
}

fn ensure_inside_destination(destination_root: &Path, destination_path: &Path, archive_path: &str) -> Result<(), ExtractionSafetyError> {
    if destination_path.starts_with(destination_root) {
        return Ok(());
    }

    Err(ExtractionSafetyError::DestinationEscape {
        archive_path: archive_path.to_owned(),
        destination_root: destination_root.to_path_buf(),
        destination_path: destination_path.to_path_buf(),
    })
}

/// Pre-compiled include/exclude pattern for efficient repeated matching.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledPattern {
    norm_pattern: String,
    clean_prefix: Option<String>,
    ends_with_doublestar: Option<String>,
    is_wildcard: bool,
}

impl CompiledPattern {
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let norm_pattern = pattern.replace('\\', "/");
        let ends_with_doublestar = if norm_pattern.ends_with("/**") { Some(norm_pattern.trim_end_matches("**").to_owned()) } else { None };
        let clean = norm_pattern.trim_end_matches('/');
        let (clean_prefix, is_wildcard) = if !clean.is_empty() && !clean.contains('*') && !clean.contains('?') {
            (Some(format!("{clean}/")), false)
        } else {
            (None, norm_pattern.contains('*') || norm_pattern.contains('?'))
        };
        Self { norm_pattern, clean_prefix, ends_with_doublestar, is_wildcard }
    }

    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let norm_path = if path.contains('\\') { std::borrow::Cow::Owned(path.replace('\\', "/")) } else { std::borrow::Cow::Borrowed(path) };

        if self.norm_pattern == *norm_path {
            return true;
        }

        if let Some(prefix) = &self.ends_with_doublestar
            && norm_path.starts_with(prefix)
        {
            return true;
        }

        if let Some(prefix) = &self.clean_prefix {
            let clean = prefix.trim_end_matches('/');
            if norm_path.as_ref() == clean || norm_path.starts_with(prefix) {
                return true;
            }
        }

        if self.is_wildcard { crate::wildcard::wildcard_matches(self.norm_pattern.as_bytes(), norm_path.as_bytes()) } else { false }
    }
}

/// Returns whether an archive path is included and not excluded by the
/// caller's pattern lists.
#[must_use]
pub fn archive_pattern_matches_any(path: &str, includes: &[String], excludes: &[String]) -> bool {
    let matches_include = includes.is_empty() || includes.iter().any(|pattern| archive_pattern_matches(pattern, path));
    let matches_exclude = excludes.iter().any(|pattern| archive_pattern_matches(pattern, path));

    matches_include && !matches_exclude
}

#[must_use]
pub fn archive_pattern_matches(pattern: &str, path: &str) -> bool {
    CompiledPattern::new(pattern).matches(path)
}

fn strip_archive_components(path: &str, count: usize) -> Option<String> {
    let components = path.split('/').skip(count).collect::<Vec<_>>();
    if components.is_empty() { None } else { Some(components.join("/")) }
}

/// Maximum deterministic renamed destinations tried for one conflicting path.
const MAX_RENAME_CANDIDATES: u64 = 10_000;

/// First rename suffix to try: the base name conceptually occupies index 1.
const FIRST_RENAME_INDEX: u64 = 2;

/// Returns a deterministic non-conflicting sibling path for an existing
/// destination, searching `"{stem} {index}"` candidates at or after
/// `start_index`, or `None` when every candidate in the budget is taken.
/// Returning the original path would silently degrade a rename policy into
/// an in-place overwrite, so callers must surface `None` as an error.
///
/// The chosen path comes back with the index a subsequent search for the same
/// name should resume from. The `candidate_budget` ceiling is absolute, so
/// resuming from a higher `start_index` narrows the search without moving the
/// point at which the candidate space is considered exhausted.
fn next_available_destination_path_from(path: &Path, start_index: u64, candidate_budget: u64) -> Option<(PathBuf, u64)> {
    if !path.exists() {
        // The base name was free, so the numbered space is untouched.
        return Some((path.to_path_buf(), start_index));
    }

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem().and_then(|stem| stem.to_str()).or_else(|| path.file_name().and_then(|name| name.to_str())).unwrap_or("entry");
    let extension = path.extension().and_then(|extension| extension.to_str());

    // A budget of N yields the N candidates numbered 2..=N+1.
    for index in start_index..=candidate_budget.saturating_add(1) {
        let file_name = if let Some(extension) = extension { format!("{stem} {index}.{extension}") } else { format!("{stem} {index}") };
        let candidate = parent.join(file_name);
        if !candidate.exists() {
            return Some((candidate, index.saturating_add(1)));
        }
    }

    None
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

    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) }
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
        ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionLimits, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner,
        FIRST_RENAME_INDEX, OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver, UnsafeFilePolicy, archive_entry_matches_selected,
        archive_pattern_matches, deferred_link_dependency_order, next_available_destination_path_from, normalize_archive_path, prepare_destination_root,
    };
    use crate::test_support::TestDir;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn deferred_link_order_is_linearized_and_cycles_are_rejected() {
        let temp = TestDir::new("deferred_link_dependency_order");
        let target = temp.path("target");
        fs::write(&target, b"target").unwrap();
        let first = temp.path("first");
        let middle = temp.path("middle");
        let last = temp.path("last");
        let chain = vec![(middle.clone(), first.clone()), (last.clone(), middle.clone()), (target, last.clone())];

        assert_eq!(deferred_link_dependency_order(&chain).unwrap(), vec![2, 1, 0]);
        let cycle = vec![(middle.clone(), first.clone()), (first, middle)];
        assert_eq!(deferred_link_dependency_order(&cycle).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn normalizes_archive_paths() {
        assert_eq!(normalize_archive_path("./dir\\file.txt").unwrap(), "dir/file.txt");
        assert_eq!(normalize_archive_path("dir//file.txt").unwrap(), "dir/file.txt");
    }

    #[test]
    fn wildcard_patterns_match_without_backtracking_explosion() {
        assert!(archive_pattern_matches("src/*.rs", "src/main.rs"));
        assert!(archive_pattern_matches("src/???.rs", "src/lib.rs"));
        assert!(!archive_pattern_matches("src/*.rs", "src/main.txt"));

        let pattern = format!("{}b", "*a".repeat(64));
        let path = format!("{}c", "a".repeat(256));
        assert!(!archive_pattern_matches(&pattern, &path));
    }

    #[test]
    fn rejects_parent_traversal() {
        let error = normalize_archive_path("dir/../../escape.txt").unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::ParentTraversal { .. }));
    }

    #[test]
    fn rejects_absolute_paths() {
        let error = normalize_archive_path("/tmp/file.txt").unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::AbsolutePath { .. }));
    }

    #[test]
    fn renamed_destination_reports_exhaustion_instead_of_overwriting() {
        let temp = TestDir::new("rename-exhaustion");
        fs::write(temp.path("file.txt"), b"original").unwrap();
        for index in 2..=4 {
            fs::write(temp.path(format!("file {index}.txt")), b"taken").unwrap();
        }

        let candidate = |path: PathBuf, budget| next_available_destination_path_from(&path, FIRST_RENAME_INDEX, budget).map(|(path, _)| path);

        // A non-conflicting path does not need renaming.
        assert_eq!(candidate(temp.path("free.txt"), 3), Some(temp.path("free.txt")));

        // A free candidate inside the budget is selected deterministically.
        assert_eq!(candidate(temp.path("file.txt"), 5), Some(temp.path("file 5.txt")));

        // An exhausted budget reports `None` instead of falling back to the
        // original existing path, which would silently overwrite it.
        assert_eq!(candidate(temp.path("file.txt"), 3), None);
    }

    #[test]
    fn resuming_rename_search_skips_suffixes_already_handed_out() {
        let temp = TestDir::new("rename-resume");
        fs::write(temp.path("file.txt"), b"original").unwrap();

        // Nothing numbered exists yet, so a fresh search takes " 2" and reports
        // 3 as the resume point.
        let (first, resume) = next_available_destination_path_from(&temp.path("file.txt"), FIRST_RENAME_INDEX, 10).unwrap();
        assert_eq!(first, temp.path("file 2.txt"));
        assert_eq!(resume, 3);

        // Resuming skips " 2" even though it is still free on disk, which is
        // what keeps a colliding batch from re-probing the same suffixes.
        let (second, resume) = next_available_destination_path_from(&temp.path("file.txt"), resume, 10).unwrap();
        assert_eq!(second, temp.path("file 3.txt"));
        assert_eq!(resume, 4);

        // The budget ceiling stays absolute rather than shifting with the
        // resume point.
        assert!(next_available_destination_path_from(&temp.path("file.txt"), 12, 10).is_none());
    }

    #[test]
    fn rejects_windows_prefixes() {
        let drive_error = normalize_archive_path("C:/tmp/file.txt").unwrap_err();
        let unc_error = normalize_archive_path("\\\\server\\share\\file.txt").unwrap_err();

        assert!(matches!(drive_error, ExtractionSafetyError::WindowsPrefix { .. }));
        assert!(matches!(unc_error, ExtractionSafetyError::WindowsPrefix { .. }));
    }

    #[test]
    fn rejects_windows_reserved_device_names() {
        let error = normalize_archive_path("dir/CON").unwrap_err();
        assert!(matches!(error, ExtractionSafetyError::WindowsReservedName { .. }));

        let error_ext = normalize_archive_path("dir/prn.txt").unwrap_err();
        assert!(matches!(error_ext, ExtractionSafetyError::WindowsReservedName { .. }));
    }

    #[test]
    fn rejects_excessively_long_paths() {
        let long_name = "a".repeat(256);
        let path = format!("dir/{long_name}");
        let error = normalize_archive_path(&path).unwrap_err();
        assert!(matches!(error, ExtractionSafetyError::PathTooLong { .. }));
    }

    #[test]
    fn rejects_duplicate_entries() {
        let temp = TestDir::new("rejects_duplicate_entries");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let first = file_entry("dir/file.txt");
        let duplicate = file_entry("dir/file.txt");

        planner.validate_entry(&first).unwrap();
        let error = planner.validate_entry(&duplicate).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::NameCollision { .. }));
    }

    #[test]
    fn rejects_case_insensitive_collisions() {
        let temp = TestDir::new("rejects_case_insensitive_collisions");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        planner.validate_entry(&file_entry("dir/README.md")).unwrap();
        let error = planner.validate_entry(&file_entry("dir/readme.md")).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::NameCollision { .. }));
    }

    #[test]
    fn rejects_unicode_case_insensitive_collisions() {
        let temp = TestDir::new("rejects_unicode_case_insensitive_collisions");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        planner.validate_entry(&file_entry("Über.txt")).unwrap();
        let error = planner.validate_entry(&file_entry("über.txt")).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::NameCollision { .. }));
    }

    #[test]
    fn refuses_overwrite_when_destination_exists() {
        let temp = TestDir::new("refuses_overwrite_when_destination_exists");
        temp.write_file("out/file.txt", b"existing");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());

        let error = planner.validate_entry(&file_entry("file.txt")).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::DestinationExists { .. }));
    }

    #[test]
    fn allows_overwrite_when_policy_replaces() {
        let temp = TestDir::new("allows_overwrite_when_policy_replaces");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        assert!(matches!(decision, ExtractionDecision::Write { .. }));
    }

    #[test]
    fn asks_overwrite_resolver_for_conflicts() {
        let temp = TestDir::new("asks_overwrite_resolver_for_conflicts");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Ask, ..ExtractionPolicy::default() };
        let mut resolver = FixedOverwriteResolver(OverwriteDecision::Skip);
        let mut planner = ExtractionSafetyPlanner::new_with_overwrite_resolver(temp.path("out"), policy, &mut resolver);

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    #[test]
    fn ask_overwrite_renames_conflicts_safely() {
        let temp = TestDir::new("ask_overwrite_renames_conflicts_safely");
        temp.write_file("out/file.txt", b"existing");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Ask, ..ExtractionPolicy::default() };
        let mut resolver = FixedOverwriteResolver(OverwriteDecision::Rename);
        let mut planner = ExtractionSafetyPlanner::new_with_overwrite_resolver(temp.path("out"), policy, &mut resolver);

        let decision = planner.validate_entry(&file_entry("file.txt")).unwrap();

        let ExtractionDecision::Write { destination_path, .. } = decision else {
            panic!("expected renamed write decision");
        };
        assert_eq!(destination_path, temp.path("out/file 2.txt"));
    }

    #[test]
    fn rejects_symlink_escape() {
        let temp = TestDir::new("rejects_symlink_escape");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Symlink { target: PathBuf::from("../../outside") },
            uncompressed_size: None,
            compressed_size: None,
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::LinkTargetEscapes { .. }));
    }

    #[test]
    fn allows_symlink_inside_destination() {
        let temp = TestDir::new("allows_symlink_inside_destination");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Symlink { target: PathBuf::from("../target.txt") },
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Write { .. }));
    }

    #[test]
    fn skips_symlink_when_ignore_symlinks_enabled() {
        let temp = TestDir::new("skips_symlink_when_ignore_symlinks_enabled");
        let policy = ExtractionPolicy { ignore_symlinks: true, ..ExtractionPolicy::default() };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Symlink { target: PathBuf::from("../target.txt") },
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    #[test]
    fn resolves_hardlink_target_as_archive_member_path_after_strip() {
        let temp = TestDir::new("resolves_hardlink_target_as_archive_member_path_after_strip");
        let policy = ExtractionPolicy { strip_components: 1, ..ExtractionPolicy::default() };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);
        let entry = ExtractionEntry {
            archive_path: "project/dir/link.txt".to_owned(),
            kind: ExtractionEntryKind::Hardlink { target: PathBuf::from("project/dir/target.txt") },
            uncompressed_size: None,
            compressed_size: None,
        };

        let decision = planner.validate_entry(&entry).unwrap();

        let ExtractionDecision::Write { destination_path, link_target_path: Some(link_target_path), .. } = decision else {
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
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry {
            archive_path: "dir/link".to_owned(),
            kind: ExtractionEntryKind::Hardlink { target: PathBuf::from("../../outside") },
            uncompressed_size: None,
            compressed_size: None,
        };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::LinkTargetEscapes { .. }));
    }

    #[test]
    fn rejects_extraction_when_total_expanded_size_exceeds_limit() {
        let temp = TestDir::new("rejects_extraction_when_total_expanded_size_exceeds_limit");
        let policy = ExtractionPolicy {
            limits: ExtractionLimits { max_expanded_bytes: Some(5), max_entry_expansion_ratio: None, max_entries: None },
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        planner.validate_entry(&sized_file_entry("one.bin", 3, Some(3))).unwrap();
        let error = planner.validate_entry(&sized_file_entry("two.bin", 3, Some(3))).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }));
    }

    #[test]
    fn rejects_entry_when_expansion_ratio_exceeds_limit() {
        let temp = TestDir::new("rejects_entry_when_expansion_ratio_exceeds_limit");
        let policy = ExtractionPolicy {
            limits: ExtractionLimits { max_expanded_bytes: None, max_entry_expansion_ratio: Some(10), max_entries: None },
            ..ExtractionPolicy::default()
        };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);

        let error = planner.validate_entry(&sized_file_entry("bomb.bin", 100, Some(1))).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::ExpansionRatioLimitExceeded { .. }));
    }

    #[test]
    fn rejects_unsafe_file_types_by_default() {
        let temp = TestDir::new("rejects_unsafe_file_types_by_default");
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), ExtractionPolicy::default());
        let entry = ExtractionEntry { archive_path: "dev/null".to_owned(), kind: ExtractionEntryKind::Device, uncompressed_size: None, compressed_size: None };

        let error = planner.validate_entry(&entry).unwrap_err();

        assert!(matches!(error, ExtractionSafetyError::UnsafeFileType { .. }));
    }

    #[test]
    fn skips_unsafe_file_types_when_policy_allows_skip() {
        let temp = TestDir::new("skips_unsafe_file_types_when_policy_allows_skip");
        let policy = ExtractionPolicy { unsafe_file: UnsafeFilePolicy::Skip, ..ExtractionPolicy::default() };
        let mut planner = ExtractionSafetyPlanner::new(temp.path("out"), policy);
        let entry = ExtractionEntry { archive_path: "dev/null".to_owned(), kind: ExtractionEntryKind::Device, uncompressed_size: None, compressed_size: None };

        let decision = planner.validate_entry(&entry).unwrap();

        assert!(matches!(decision, ExtractionDecision::Skip { .. }));
    }

    fn file_entry(archive_path: &str) -> ExtractionEntry {
        sized_file_entry(archive_path, 1, Some(1))
    }

    fn sized_file_entry(archive_path: &str, uncompressed_size: u64, compressed_size: Option<u64>) -> ExtractionEntry {
        ExtractionEntry { archive_path: archive_path.to_owned(), kind: ExtractionEntryKind::File, uncompressed_size: Some(uncompressed_size), compressed_size }
    }

    struct FixedOverwriteResolver(OverwriteDecision);

    impl OverwriteResolver for FixedOverwriteResolver {
        fn decide(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
            assert_eq!(conflict.archive_path, "file.txt");
            self.0
        }
    }

    #[test]
    fn test_archive_entry_matches_selected() {
        assert!(archive_entry_matches_selected("Antigravity-arm64/Antigravity", "Antigravity-arm64"));
        assert!(archive_entry_matches_selected("./Antigravity-arm64/lib/foo.so", "Antigravity-arm64"));
        assert!(archive_entry_matches_selected("Antigravity-arm64/", "Antigravity-arm64"));
        assert!(archive_entry_matches_selected("Antigravity-arm64", "Antigravity-arm64/"));
        assert!(archive_entry_matches_selected("./Antigravity-arm64", "./Antigravity-arm64/"));
        assert!(archive_entry_matches_selected("folder\\sub\\file.txt", "folder"));
        assert!(archive_entry_matches_selected("folder\\sub\\file.txt", "folder/"));
        assert!(archive_entry_matches_selected("folder/sub/file.txt", "folder\\"));
        assert!(archive_entry_matches_selected("folder\\sub\\file.txt", "folder\\sub"));
        assert!(archive_entry_matches_selected("folder\\sub\\file.txt", "folder\\sub\\"));
        assert!(!archive_entry_matches_selected("Antigravity-arm64-v2/lib.so", "Antigravity-arm64"));
        assert!(archive_entry_matches_selected("file.txt", "file.txt"));
        assert!(!archive_entry_matches_selected("other.txt", "file.txt"));
    }

    #[test]
    fn test_archive_pattern_matches_directory_and_backslashes() {
        assert!(archive_pattern_matches("folder", "folder/file.txt"));
        assert!(archive_pattern_matches("folder/", "folder/file.txt"));
        assert!(archive_pattern_matches("folder\\", "folder/file.txt"));
        assert!(archive_pattern_matches("folder\\sub", "folder/sub/file.txt"));
        assert!(archive_pattern_matches("folder\\sub\\", "folder/sub/file.txt"));
        assert!(archive_pattern_matches("folder/sub", "folder\\sub\\file.txt"));
        assert!(!archive_pattern_matches("folder-v2", "folder/file.txt"));
        assert!(archive_pattern_matches("folder\\*.txt", "folder/file.txt"));
    }
}
