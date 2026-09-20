use crate::gitignore::{GitignoreRule, gitignore_decision, gitignore_has_later_negated_descendant, read_gitignore_rules};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The planned archive contents before any archive bytes are written.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArchiveManifest {
    /// Original source root passed to the planner.
    pub root: PathBuf,
    /// Entries that should be written to the archive.
    pub entries: Vec<ManifestEntry>,
    /// Total size of included regular files.
    pub total_bytes: u64,
    /// Entries skipped by planner rules.
    pub excluded_entries: Vec<ExcludedEntry>,
    /// Estimated regular-file bytes skipped by planner rules.
    pub excluded_bytes: u64,
    /// Non-fatal issues encountered while planning.
    pub warnings: Vec<ManifestWarning>,
}

impl ArchiveManifest {
    /// Returns the number of planned archive entries.
    #[must_use]
    pub fn included_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of skipped archive entries.
    #[must_use]
    pub fn excluded_count(&self) -> usize {
        self.excluded_entries.len()
    }

    /// Formats a compact summary suitable for CLI output.
    #[must_use]
    pub fn summary(&self) -> String {
        format!("planned {} entries, {} bytes, {} excluded, {} warnings", self.included_count(), self.total_bytes, self.excluded_count(), self.warnings.len())
    }
}

/// One file-system item that will become an archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManifestEntry {
    /// Stable slash-separated path inside the archive.
    pub archive_path: String,
    /// Source path on disk.
    pub source_path: PathBuf,
    /// File-system type.
    pub file_type: ManifestFileType,
    /// Uncompressed size for regular files. Other entry types use zero.
    pub size: u64,
    /// Last modification time when available.
    pub modified: Option<SystemTime>,
    /// Portable permission snapshot.
    pub permissions: PermissionSnapshot,
    /// Link target for symlink entries.
    pub symlink_target: Option<PathBuf>,
}

/// File type captured by the manifest planner.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ManifestFileType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Other file-system type, such as a FIFO or socket.
    Other,
}

/// Portable permission details for a manifest entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PermissionSnapshot {
    /// Whether the source permissions are read-only.
    pub readonly: bool,
    /// Unix mode bits when available.
    pub unix_mode: Option<u32>,
}

/// One file-system item skipped by planner rules.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExcludedEntry {
    /// Stable slash-separated path that would have been used inside the archive.
    pub archive_path: String,
    /// Source path on disk.
    pub source_path: PathBuf,
    /// Human-readable exclusion reason.
    pub reason: String,
    /// Estimated regular-file bytes skipped for this entry.
    pub size: u64,
}

/// Non-fatal manifest planning issue.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManifestWarning {
    /// Path related to the warning.
    pub source_path: PathBuf,
    /// Human-readable warning message.
    pub message: String,
}

/// Default exclusion profile applied while planning archive entries.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExclusionProfile {
    /// Excludes common generated or platform clutter (for example `.DS_Store`).
    Minimal,
    /// Excludes common source checkout noise such as VCS data, dependency
    /// folders, build outputs, caches, and editor metadata, and applies
    /// `.gitignore` rules found while walking the source tree.
    CleanSource,
    /// Excludes nothing by default. Used when the caller explicitly opts out
    /// of all default exclusion rules (for example a `--no-ignore` flag).
    Unrestricted,
}

/// User-configurable manifest planner options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlanOptions {
    /// Default exclusion profile.
    pub exclusion_profile: ExclusionProfile,
    /// Applies `.gitignore` rules found while walking the source tree.
    ///
    /// Kept as an independent flag because callers (for example the desktop
    /// app) combine either profile with an explicit gitignore preference.
    pub respect_gitignore: bool,
    /// Exclude any entry whose final path component matches one of these names.
    pub exclude_names: Vec<String>,
    /// Exclude exact slash-separated archive paths.
    pub exclude_archive_paths: Vec<String>,
    /// Include exact slash-separated archive paths even when they match an
    /// exclusion rule. Directory includes also include descendants.
    pub include_archive_paths: Vec<String>,
    /// Follow symlink targets while planning instead of recording symlink
    /// entries.
    pub follow_symlinks: bool,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            exclusion_profile: ExclusionProfile::Minimal,
            respect_gitignore: false,
            exclude_names: Vec::new(),
            exclude_archive_paths: Vec::new(),
            include_archive_paths: Vec::new(),
            follow_symlinks: false,
        }
    }
}

impl PlanOptions {
    /// Returns the product-facing clean source archive profile.
    #[must_use]
    pub fn clean_source() -> Self {
        Self { exclusion_profile: ExclusionProfile::CleanSource, respect_gitignore: true, ..Self::default() }
    }
}

/// Error returned by manifest planning.
#[derive(Debug)]
pub enum PlanError {
    /// The source path does not have a usable top-level file name.
    MissingFileName { path: PathBuf },
    /// File-system metadata could not be read.
    Metadata { path: PathBuf, source: io::Error },
    /// Directory contents could not be read.
    ReadDir { path: PathBuf, source: io::Error },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFileName { path } => {
                write!(f, "source path has no archive name: {}", path.display())
            }
            Self::Metadata { path, source } => {
                write!(f, "failed to read metadata for {}: {source}", path.display())
            }
            Self::ReadDir { path, source } => {
                write!(f, "failed to read directory {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingFileName { .. } => None,
            Self::Metadata { source, .. } | Self::ReadDir { source, .. } => Some(source),
        }
    }
}

/// Plans archive entries for one source path.
///
/// The top-level source file or directory is included in the archive path. For
/// example, planning `/tmp/project` produces entries under `project/`.
///
/// # Errors
///
/// Returns [`PlanError`] if the source has no usable archive name, if metadata
/// cannot be read, or if directory traversal fails.
pub fn plan_archive(source: impl AsRef<Path>, options: &PlanOptions) -> Result<ArchiveManifest, PlanError> {
    let root = source.as_ref().to_path_buf();
    plan_archive_roots([root.clone()], root, options)
}

/// Plans archive entries for multiple source paths.
///
/// Each top-level source file or directory is included using its own file name
/// as the archive path, matching repeated single-source planning.
///
/// # Errors
///
/// Returns [`PlanError`] if no sources are supplied, if any source has no
/// usable archive name, if metadata cannot be read, or if directory traversal
/// fails.
pub fn plan_archives<I, P>(sources: I, options: &PlanOptions) -> Result<ArchiveManifest, PlanError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let roots = sources.into_iter().map(|source| source.as_ref().to_path_buf()).collect::<Vec<_>>();
    let Some(first_root) = roots.first() else {
        return Err(PlanError::MissingFileName { path: PathBuf::new() });
    };
    let manifest_root = common_parent(&roots).unwrap_or_else(|| first_root.clone());

    plan_archive_roots(roots, manifest_root, options)
}

fn plan_archive_roots(roots: impl IntoIterator<Item = PathBuf>, manifest_root: PathBuf, options: &PlanOptions) -> Result<ArchiveManifest, PlanError> {
    let mut planner = ManifestPlanner { options, entries: Vec::new(), excluded_entries: Vec::new(), warnings: Vec::new(), total_bytes: 0, excluded_bytes: 0 };

    for root in roots {
        let root_name = archive_file_name(&root)?;
        planner.walk(&root, root_name, 0, &mut Vec::new(), &mut Vec::new())?;
    }

    planner.entries.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    record_archive_path_collisions(&planner.entries, &mut planner.warnings);
    planner.excluded_entries.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    planner.warnings.sort_by(|left, right| left.source_path.cmp(&right.source_path));

    Ok(ArchiveManifest {
        root: manifest_root,
        entries: planner.entries,
        total_bytes: planner.total_bytes,
        excluded_entries: planner.excluded_entries,
        excluded_bytes: planner.excluded_bytes,
        warnings: planner.warnings,
    })
}

fn common_parent(paths: &[PathBuf]) -> Option<PathBuf> {
    let first_parent = paths.first()?.parent()?.to_path_buf();
    if paths.iter().all(|path| path.parent().is_some_and(|parent| parent == first_parent)) { Some(first_parent) } else { None }
}

struct ManifestPlanner<'a> {
    options: &'a PlanOptions,
    entries: Vec<ManifestEntry>,
    excluded_entries: Vec<ExcludedEntry>,
    warnings: Vec<ManifestWarning>,
    total_bytes: u64,
    excluded_bytes: u64,
}

impl ManifestPlanner<'_> {
    fn walk(
        &mut self,
        source_path: &Path,
        archive_path: String,
        depth: usize,
        gitignore_rules: &mut Vec<GitignoreRule>,
        active_dirs: &mut Vec<PathBuf>,
    ) -> Result<(), PlanError> {
        let metadata = if self.options.follow_symlinks {
            fs::metadata(source_path).map_err(|source| PlanError::Metadata { path: source_path.to_path_buf(), source })?
        } else {
            fs::symlink_metadata(source_path).map_err(|source| PlanError::Metadata { path: source_path.to_path_buf(), source })?
        };
        let file_type = manifest_file_type(&metadata);

        if depth > 1024 {
            return Err(PlanError::Metadata {
                path: source_path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "maximum manifest walk depth exceeded"),
            });
        }

        if depth > 0
            && let Some(reason) = self.exclusion_reason(source_path, &archive_path, file_type, gitignore_rules)
        {
            let size = estimate_regular_file_bytes(&metadata, file_type);
            self.excluded_bytes = self.excluded_bytes.saturating_add(size);
            self.excluded_entries.push(ExcludedEntry { archive_path, source_path: source_path.to_path_buf(), reason, size });
            return Ok(());
        }

        let entry = build_entry(source_path, archive_path.clone(), &metadata, &mut self.warnings);
        if entry.file_type == ManifestFileType::File {
            self.total_bytes = self.total_bytes.saturating_add(entry.size);
        }

        let should_recurse = entry.file_type == ManifestFileType::Directory;
        self.entries.push(entry);

        if should_recurse {
            let active_dir_marker = if self.options.follow_symlinks {
                match fs::canonicalize(source_path) {
                    Ok(canonical) if active_dirs.contains(&canonical) => {
                        self.warnings.push(ManifestWarning { source_path: source_path.to_path_buf(), message: "skipped symlink directory loop".to_owned() });
                        return Ok(());
                    }
                    Ok(canonical) => {
                        active_dirs.push(canonical);
                        true
                    }
                    Err(source) => {
                        return Err(PlanError::Metadata { path: source_path.to_path_buf(), source });
                    }
                }
            } else {
                false
            };
            let gitignore_len = gitignore_rules.len();
            if self.options.respect_gitignore {
                gitignore_rules.extend(read_gitignore_rules(source_path, &archive_path, &mut self.warnings));
            }
            let children = fs::read_dir(source_path)
                .map_err(|source| PlanError::ReadDir { path: source_path.to_path_buf(), source })?
                .collect::<Result<Vec<_>, io::Error>>()
                .map_err(|source| PlanError::ReadDir { path: source_path.to_path_buf(), source })?;

            for child in children {
                let child_name = child.file_name();
                let child_name = child_name.to_string_lossy();
                let child_archive_path = format!("{archive_path}/{child_name}");
                self.walk(&child.path(), child_archive_path, depth + 1, gitignore_rules, active_dirs)?;
            }
            gitignore_rules.truncate(gitignore_len);
            if active_dir_marker {
                active_dirs.pop();
            }
        }

        Ok(())
    }

    fn exclusion_reason(&self, source_path: &Path, archive_path: &str, file_type: ManifestFileType, gitignore_rules: &[GitignoreRule]) -> Option<String> {
        let file_name = source_path.file_name()?.to_string_lossy();

        if self.is_explicitly_included(archive_path) {
            return None;
        }

        if self.options.exclusion_profile != ExclusionProfile::Unrestricted && file_name == ".DS_Store" {
            return Some("default macOS metadata exclusion".to_owned());
        }

        if self.options.exclusion_profile == ExclusionProfile::CleanSource
            && let Some(reason) = self.clean_source_exclusion_reason(archive_path, file_type)
        {
            return Some(reason);
        }

        if self.options.exclude_names.iter().any(|excluded| excluded == file_name.as_ref()) {
            if file_type == ManifestFileType::Directory && self.has_explicit_include_descendant(archive_path) {
                return None;
            }
            return Some(format!("excluded name: {file_name}"));
        }

        if self.options.exclude_archive_paths.iter().any(|excluded| excluded == archive_path) {
            if file_type == ManifestFileType::Directory && self.has_explicit_include_descendant(archive_path) {
                return None;
            }
            return Some(format!("excluded archive path: {archive_path}"));
        }

        if self.options.respect_gitignore
            && let Some((ignored, rule_index)) = gitignore_decision(archive_path, file_type, gitignore_rules)
            && ignored
        {
            if file_type == ManifestFileType::Directory && gitignore_has_later_negated_descendant(archive_path, gitignore_rules, rule_index) {
                return None;
            }
            return Some("ignored by .gitignore".to_owned());
        }

        None
    }

    fn clean_source_exclusion_reason(&self, archive_path: &str, file_type: ManifestFileType) -> Option<String> {
        let mut components = archive_path.split('/').skip(1);
        let matched_name = components.find(|component| clean_source_exclude_name(component))?;

        if file_type == ManifestFileType::Directory && self.has_explicit_include_descendant(archive_path) {
            return None;
        }

        Some(format!("clean source exclusion: {matched_name}"))
    }

    fn is_explicitly_included(&self, archive_path: &str) -> bool {
        self.options.include_archive_paths.iter().any(|included| path_matches_or_is_descendant(archive_path, included))
    }

    fn has_explicit_include_descendant(&self, archive_path: &str) -> bool {
        self.options.include_archive_paths.iter().any(|included| is_strict_descendant_path(included, archive_path))
    }
}

/// True when `path` lies strictly below `ancestor`.
///
/// This is a byte comparison rather than a `starts_with(format!("{ancestor}/"))`
/// so it allocates nothing; it runs once per excluded directory during a walk.
fn is_strict_descendant_path(path: &str, ancestor: &str) -> bool {
    path.strip_prefix(ancestor).is_some_and(|rest| rest.starts_with('/'))
}

fn path_matches_or_is_descendant(path: &str, include_path: &str) -> bool {
    path == include_path || is_strict_descendant_path(path, include_path)
}

fn clean_source_exclude_name(name: &str) -> bool {
    matches!(
        name,
        ".DS_Store"
            | ".cache"
            | ".git"
            | ".gradle"
            | ".hg"
            | ".idea"
            | ".mypy_cache"
            | ".next"
            | ".nuxt"
            | ".pytest_cache"
            | ".ruff_cache"
            | ".svn"
            | ".turbo"
            | ".vscode"
            | "DerivedData"
            | "Thumbs.db"
            | "__pycache__"
            | "build"
            | "dist"
            | "node_modules"
            | "target"
    )
}

fn estimate_regular_file_bytes(metadata: &Metadata, file_type: ManifestFileType) -> u64 {
    match file_type {
        ManifestFileType::File => metadata.len(),
        ManifestFileType::Directory | ManifestFileType::Symlink | ManifestFileType::Other => 0,
    }
}

fn archive_file_name(path: &Path) -> Result<String, PlanError> {
    let file_name = path.file_name().ok_or_else(|| PlanError::MissingFileName { path: path.to_path_buf() })?;

    Ok(file_name.to_string_lossy().into_owned())
}

fn build_entry(source_path: &Path, archive_path: String, metadata: &Metadata, warnings: &mut Vec<ManifestWarning>) -> ManifestEntry {
    let file_type = manifest_file_type(metadata);
    let size = if file_type == ManifestFileType::File { metadata.len() } else { 0 };
    let symlink_target = if file_type == ManifestFileType::Symlink {
        match fs::read_link(source_path) {
            Ok(target) => Some(target),
            Err(error) => {
                warnings.push(ManifestWarning { source_path: source_path.to_path_buf(), message: format!("failed to read symlink target: {error}") });
                None
            }
        }
    } else {
        None
    };

    ManifestEntry {
        archive_path,
        source_path: source_path.to_path_buf(),
        file_type,
        size,
        modified: metadata.modified().ok(),
        permissions: permission_snapshot(metadata),
        symlink_target,
    }
}

fn manifest_file_type(metadata: &Metadata) -> ManifestFileType {
    let file_type = metadata.file_type();

    if file_type.is_file() {
        ManifestFileType::File
    } else if file_type.is_dir() {
        ManifestFileType::Directory
    } else if file_type.is_symlink() {
        ManifestFileType::Symlink
    } else {
        ManifestFileType::Other
    }
}

#[cfg(unix)]
fn permission_snapshot(metadata: &Metadata) -> PermissionSnapshot {
    use std::os::unix::fs::PermissionsExt;

    PermissionSnapshot { readonly: metadata.permissions().readonly(), unix_mode: Some(metadata.permissions().mode()) }
}

#[cfg(not(unix))]
fn permission_snapshot(metadata: &Metadata) -> PermissionSnapshot {
    PermissionSnapshot { readonly: metadata.permissions().readonly(), unix_mode: None }
}

fn record_archive_path_collisions(entries: &[ManifestEntry], warnings: &mut Vec<ManifestWarning>) {
    let mut seen_paths: HashMap<String, &str> = HashMap::new();

    for entry in entries {
        // Uses the same Unicode-aware collision key as extraction planning so
        // the manifest warns about the same collisions extraction rejects.
        let collision_key = crate::safety::case_collision_key(&entry.archive_path);
        if let Some(previous_path) = seen_paths.insert(collision_key, &entry.archive_path) {
            warnings.push(ManifestWarning {
                source_path: entry.source_path.clone(),
                message: format!("archive path may collide with {previous_path} on case-insensitive file systems"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ManifestEntry, ManifestFileType, PermissionSnapshot, PlanOptions, plan_archive, plan_archives, record_archive_path_collisions};
    use crate::test_support::TestDir;
    use std::path::PathBuf;

    #[test]
    fn plans_files_directories_and_empty_directories() {
        let temp = TestDir::new("plans_files_directories_and_empty_directories");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).unwrap();
        let archive_paths = manifest_paths(&manifest);

        assert_eq!(archive_paths, vec!["project", "project/empty", "project/src", "project/src/main.rs"]);
        assert_eq!(manifest.total_bytes, 13);
        assert_eq!(manifest.excluded_entries, Vec::new());
    }

    #[test]
    fn excludes_default_macos_metadata() {
        let temp = TestDir::new("excludes_default_macos_metadata");
        temp.write_file("project/.DS_Store", b"noise");
        temp.write_file("project/file.txt", b"content");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/file.txt"]);
        assert_eq!(manifest.excluded_count(), 1);
        assert_eq!(manifest.excluded_entries[0].archive_path, "project/.DS_Store");
    }

    #[test]
    fn supports_explicit_name_and_archive_path_exclusions() {
        let temp = TestDir::new("supports_explicit_name_and_archive_path_exclusions");
        temp.write_file("project/a.log", b"a");
        temp.write_file("project/cache/b.txt", b"b");
        temp.write_file("project/keep.txt", b"k");

        let options =
            PlanOptions { exclude_names: vec!["a.log".to_owned()], exclude_archive_paths: vec!["project/cache".to_owned()], ..PlanOptions::default() };
        let manifest = plan_archive(temp.path("project"), &options).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/keep.txt"]);
        assert_eq!(manifest.excluded_count(), 2);
    }

    #[test]
    fn clean_source_applies_default_developer_exclusions() {
        let temp = TestDir::new("clean_source_applies_default_developer_exclusions");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.write_file("project/.git/config", b"config");
        temp.write_file("project/node_modules/pkg/index.js", b"module");
        temp.write_file("project/dist/app.js", b"bundle");
        temp.write_file("project/.vscode/settings.json", b"{}");
        temp.write_file("project/.DS_Store", b"noise");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::clean_source()).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/src", "project/src/main.rs"]);
        assert_eq!(manifest.excluded_count(), 5);
        assert_eq!(manifest.excluded_bytes, 5);
        assert!(
            manifest
                .excluded_entries
                .iter()
                .any(|entry| { entry.archive_path == "project/node_modules" && entry.reason.contains("clean source") && entry.size == 0 })
        );
        assert!(
            manifest
                .excluded_entries
                .iter()
                .any(|entry| { entry.archive_path == "project/.DS_Store" && entry.reason.contains("default macOS") && entry.size == 5 })
        );
    }

    #[test]
    fn clean_source_respects_nested_gitignore_files() {
        let temp = TestDir::new("clean_source_respects_nested_gitignore_files");
        temp.write_file("project/.gitignore", b"target/\n*.log\n!keep.log\n");
        temp.write_file("project/target/debug/app", b"binary");
        temp.write_file("project/debug.log", b"drop");
        temp.write_file("project/keep.log", b"keep");
        temp.write_file("project/src/.gitignore", b"generated/\n");
        temp.write_file("project/src/generated/code.rs", b"generated");
        temp.write_file("project/src/lib.rs", b"lib");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::clean_source()).unwrap();

        assert_eq!(
            manifest_paths(&manifest),
            vec!["project", "project/.gitignore", "project/keep.log", "project/src", "project/src/.gitignore", "project/src/lib.rs"]
        );
        assert!(manifest.excluded_entries.iter().any(|entry| { entry.archive_path == "project/debug.log" && entry.reason == "ignored by .gitignore" }));
        assert!(manifest.excluded_entries.iter().any(|entry| { entry.archive_path == "project/src/generated" && entry.reason == "ignored by .gitignore" }));
    }

    #[test]
    fn clean_source_gitignore_negation_reincludes_previous_match() {
        let temp = TestDir::new("clean_source_gitignore_negation_reincludes_previous_match");
        temp.write_file("project/.gitignore", b"*.log\n!keep.log\n");
        temp.write_file("project/drop.log", b"drop");
        temp.write_file("project/keep.log", b"keep");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::clean_source()).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/.gitignore", "project/keep.log"]);
        assert_eq!(manifest.excluded_count(), 1);
        assert_eq!(manifest.excluded_entries[0].archive_path, "project/drop.log");
    }

    #[test]
    fn clean_source_explicit_include_overrides_default_exclusion() {
        let temp = TestDir::new("clean_source_explicit_include_overrides_default_exclusion");
        temp.write_file("project/node_modules/drop/index.js", b"drop");
        temp.write_file("project/node_modules/kept/index.js", b"keep");
        let options = PlanOptions { include_archive_paths: vec!["project/node_modules/kept/index.js".to_owned()], ..PlanOptions::clean_source() };

        let manifest = plan_archive(temp.path("project"), &options).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/node_modules", "project/node_modules/kept", "project/node_modules/kept/index.js"]);
        assert!(manifest.excluded_entries.iter().any(|entry| { entry.archive_path == "project/node_modules/drop" && entry.reason.contains("clean source") }));
    }

    #[test]
    fn records_file_metadata() {
        let temp = TestDir::new("records_file_metadata");
        temp.write_file("project/file.txt", b"content");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).unwrap();
        let file = manifest.entries.iter().find(|entry| entry.archive_path == "project/file.txt").unwrap();

        assert_eq!(file.file_type, ManifestFileType::File);
        assert_eq!(file.size, 7);
        assert!(file.modified.is_some());
        assert!(!file.permissions.readonly);
        #[cfg(unix)]
        assert!(file.permissions.unix_mode.is_some());
        #[cfg(not(unix))]
        assert!(file.permissions.unix_mode.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn records_symlink_entries_without_recursing() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("records_symlink_entries_without_recursing");
        temp.write_file("project/target.txt", b"target");
        symlink("target.txt", temp.path("project/link.txt")).unwrap();

        let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).unwrap();
        let link = manifest.entries.iter().find(|entry| entry.archive_path == "project/link.txt").unwrap();

        assert_eq!(link.file_type, ManifestFileType::Symlink);
        assert_eq!(link.size, 0);
        assert_eq!(link.symlink_target, Some(PathBuf::from("target.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn records_unix_socket_as_other_without_opening_it() {
        use std::fs;
        use std::os::unix::net::UnixListener;

        // Unix-domain socket paths are limited to roughly 104 bytes on macOS.
        // `/tmp` is the short, stable alias for the much longer per-user temp
        // directory returned by `std::env::temp_dir()` there.
        let source = PathBuf::from("/tmp").join(crate::temp_names::unique_temp_name("socket"));
        fs::create_dir_all(&source).unwrap();
        let socket_path = source.join("service.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let manifest = plan_archive(&source, &PlanOptions::default()).unwrap();
        let socket = manifest.entries.iter().find(|entry| entry.source_path == socket_path).unwrap();

        assert_eq!(socket.file_type, ManifestFileType::Other);
        assert_eq!(socket.size, 0);
        assert_eq!(socket.symlink_target, None);

        drop(listener);
        fs::remove_dir_all(source).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn follow_symlinks_skips_directory_loops() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("follow_symlinks_skips_directory_loops");
        temp.write_file("project/dir/file.txt", b"payload");
        symlink("..", temp.path("project/dir/back")).unwrap();
        let options = PlanOptions { follow_symlinks: true, ..PlanOptions::default() };

        let manifest = plan_archive(temp.path("project"), &options).unwrap();
        let paths = manifest_paths(&manifest);

        assert!(paths.contains(&"project/dir/back"), "{paths:?}");
        assert!(!paths.iter().any(|path| path.contains("back/dir/back")), "symlink directory loop should not recurse indefinitely: {paths:?}");
        assert!(
            manifest
                .warnings
                .iter()
                .any(|warning| { warning.source_path == temp.path("project/dir/back") && warning.message == "skipped symlink directory loop" })
        );
    }

    #[cfg(unix)]
    #[test]
    fn follow_symlinks_keeps_outside_file_targets_at_link_archive_path() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("follow_symlinks_outside_file");
        temp.write_file("outside.txt", b"outside");
        temp.create_dir("project");
        symlink("../outside.txt", temp.path("project/outside-link.txt")).unwrap();
        let options = PlanOptions { follow_symlinks: true, ..PlanOptions::default() };

        let manifest = plan_archive(temp.path("project"), &options).unwrap();
        let link = manifest.entries.iter().find(|entry| entry.archive_path == "project/outside-link.txt").unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/outside-link.txt"]);
        assert_eq!(link.file_type, ManifestFileType::File);
        assert_eq!(link.size, 7);
        assert_eq!(link.symlink_target, None);
    }

    #[test]
    fn output_is_deterministic() {
        let temp = TestDir::new("output_is_deterministic");
        temp.write_file("project/z.txt", b"z");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/nested/b.txt", b"b");

        let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["project", "project/a.txt", "project/nested", "project/nested/b.txt", "project/z.txt"]);
    }

    #[test]
    fn plans_multiple_source_roots() {
        let temp = TestDir::new("plans_multiple_source_roots");
        temp.write_file("a.txt", b"a");
        temp.write_file("folder/b.txt", b"bb");

        let manifest = plan_archives([temp.path("a.txt"), temp.path("folder")], &PlanOptions::default()).unwrap();

        assert_eq!(manifest_paths(&manifest), vec!["a.txt", "folder", "folder/b.txt"]);
        assert_eq!(manifest.total_bytes, 3);
        assert_eq!(manifest.root, temp.root().to_path_buf());
    }

    #[test]
    fn warns_about_duplicate_names_on_case_insensitive_file_systems() {
        let entries = vec![test_entry("project/README.md"), test_entry("project/between.txt"), test_entry("project/readme.md")];
        let mut warnings = Vec::new();

        record_archive_path_collisions(&entries, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("case-insensitive"));
    }

    #[test]
    fn warns_about_unicode_case_collisions_like_extraction_rejects() {
        let entries = vec![test_entry("project/Über.txt"), test_entry("project/über.txt")];
        let mut warnings = Vec::new();

        record_archive_path_collisions(&entries, &mut warnings);

        assert_eq!(warnings.len(), 1);
        // The warning names the earlier entry whose path the later one may
        // collide with, and points at the colliding entry's source path.
        assert!(warnings[0].message.contains("Über.txt"));
        assert_eq!(warnings[0].source_path, PathBuf::from("project/über.txt"));
    }

    fn manifest_paths(manifest: &super::ArchiveManifest) -> Vec<&str> {
        manifest.entries.iter().map(|entry| entry.archive_path.as_str()).collect()
    }

    fn test_entry(archive_path: &str) -> ManifestEntry {
        ManifestEntry {
            archive_path: archive_path.to_owned(),
            source_path: PathBuf::from(archive_path),
            file_type: ManifestFileType::File,
            size: 0,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: None },
            symlink_target: None,
        }
    }
}
