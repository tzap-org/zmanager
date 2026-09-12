use crate::jobs::JobContext;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
    normalize_archive_path, remove_destination_for_replace,
};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zmanager_unrar::{MAX_LARGE_DICTIONARY_BYTES, RarEntryKind, UnrarError};

const LARGE_DICTIONARY_LIMIT_MIB: u64 = MAX_LARGE_DICTIONARY_BYTES / crate::MEBIBYTE_BYTES;
const RAR_UNIX_MODE_MASK: u32 = 0o7777;
const RAR_FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
const RAR_FILETIME_NANOS_PER_TICK: u64 = 100;
const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;

/// One RAR listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarListEntry {
    /// Archive path.
    pub path: String,
    /// Entry kind.
    pub kind: RarListEntryKind,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// RAR dictionary size in bytes.
    pub dictionary_size: u64,
    /// Link or file-copy target for RAR redirection entries.
    pub link_target: Option<String>,
    /// Whether entry data is encrypted.
    pub encrypted: bool,
    /// Whether the entry is part of a solid archive.
    pub solid: bool,
    /// Original file attributes (Unix or Windows).
    pub file_attr: u32,
    /// Modification time (Windows FILETIME).
    pub mtime: u64,
}

/// Portable RAR listing entry type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RarListEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link or junction.
    Symlink,
    /// Hard link or file-copy redirection.
    Hardlink,
    /// File-copy redirection.
    FileCopy,
    /// Unsupported special entry.
    Special,
}

/// RAR listing report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarListing {
    /// Entries in archive order.
    pub entries: Vec<RarListEntry>,
}

/// RAR extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarExtractReport {
    /// Entries written to disk.
    pub written_entries: usize,
    /// Entries skipped by policy or unsupported materialization.
    pub skipped_entries: usize,
    /// Regular file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// RAR data-verification report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarTestReport {
    /// Number of selected entries whose data or structural metadata was verified.
    pub tested_entries: usize,
    /// Number of entries excluded or not meaningfully testable.
    pub skipped_entries: usize,
    /// Uncompressed bytes requested from regular-file entries.
    pub tested_bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

/// Error returned by the RAR backend.
#[derive(Debug)]
pub enum RarBackendError {
    /// Bundled `UnRAR` failed.
    Unrar(UnrarError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Link-like entry did not include a target.
    MissingLinkTarget { path: String },
    /// Link-like entry target cannot be mapped safely.
    InvalidLinkTarget { path: String, target: String, reason: String },
    /// Entry requests a dictionary larger than ZM permits.
    DictionaryTooLarge { path: String, size: u64 },
}

impl fmt::Display for RarBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrar(source) => write!(f, "UnRAR operation failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { path } => {
                write!(f, "RAR link entry has no target: {path}")
            }
            Self::InvalidLinkTarget { path, target, reason } => {
                write!(f, "RAR link entry {path} has invalid target {target}: {reason}")
            }
            Self::DictionaryTooLarge { path, size } => {
                write!(f, "RAR dictionary exceeds {LARGE_DICTIONARY_LIMIT_MIB} MiB limit for {path}: {} MiB", size.div_ceil(crate::MEBIBYTE_BYTES))
            }
        }
    }
}

impl std::error::Error for RarBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unrar(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingLinkTarget { .. } | Self::InvalidLinkTarget { .. } | Self::DictionaryTooLarge { .. } => None,
        }
    }
}

impl From<UnrarError> for RarBackendError {
    fn from(source: UnrarError) -> Self {
        Self::Unrar(source)
    }
}

impl From<ExtractionSafetyError> for RarBackendError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists a RAR archive through bundled `UnRAR`.
///
/// # Errors
///
/// Returns [`RarBackendError`] when `UnRAR` cannot open or read the archive.
pub fn list_rar_with_password(archive: impl AsRef<Path>, password: Option<&str>) -> Result<RarListing, RarBackendError> {
    let entries = zmanager_unrar::list_archive(archive.as_ref(), password)?
        .into_iter()
        .map(|entry| RarListEntry {
            path: entry.path,
            kind: list_entry_kind(entry.kind),
            size: entry.unpacked_size,
            dictionary_size: entry.dictionary_size,
            link_target: entry.link_target,
            encrypted: entry.encrypted,
            solid: entry.solid,
            file_attr: entry.file_attr,
            mtime: entry.mtime,
        })
        .collect();

    Ok(RarListing { entries })
}

/// Reads selected RAR entries through bundled `UnRAR` without exposing a
/// secondary reader path. Regular files are extracted into a private,
/// automatically removed directory so the same native decoder path validates
/// payloads and detects truncation or password failures.
pub fn test_rar_with_password_filter(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
) -> Result<RarTestReport, RarBackendError> {
    let archive = archive.as_ref();
    let entries = zmanager_unrar::list_archive(archive, password)?;
    let temporary = crate::temp_names::TemporaryDirectory::new("rar-test").map_err(|error| RarBackendError::Io { path: error.path, source: error.source })?;
    let mut selections = BTreeMap::new();
    let mut report = RarTestReport { tested_entries: 0, skipped_entries: 0, tested_bytes: 0, warnings: Vec::new() };

    for (index, entry) in entries.into_iter().enumerate() {
        reject_large_dictionary(&entry)?;
        if !selected(&entry.path) {
            report.skipped_entries += 1;
            continue;
        }
        match entry.kind {
            zmanager_unrar::RarEntryKind::File => {
                let destination = temporary.path().join(format!("entry-{index}"));
                selections.insert(entry.path, destination);
                report.tested_entries += 1;
                report.tested_bytes = report.tested_bytes.saturating_add(entry.unpacked_size);
            }
            zmanager_unrar::RarEntryKind::Directory => report.tested_entries += 1,
            zmanager_unrar::RarEntryKind::Symlink | zmanager_unrar::RarEntryKind::Hardlink | zmanager_unrar::RarEntryKind::FileCopy => {
                report.skipped_entries += 1;
                report.warnings.push(format!("skipped non-payload RAR entry {}", entry.path));
            }
            zmanager_unrar::RarEntryKind::Special => {
                report.skipped_entries += 1;
                report.warnings.push(format!("skipped unsupported RAR special entry {}", entry.path));
            }
        }
    }

    zmanager_unrar::extract_selected(archive, password, &selections)?;
    Ok(report)
}

/// Options for the single core RAR extraction implementation.
///
/// Every public extract entry point is a thin wrapper that builds this struct
/// (listing the archive when the caller did not already do so) and delegates
/// here, so the extraction pipeline has exactly one implementation.
pub(crate) struct RarExtractOptions<'password, 'resolver, 'context> {
    pub(crate) password: Option<&'password str>,
    pub(crate) overwrite_resolver: Option<&'resolver mut dyn OverwriteResolver>,
    pub(crate) context: Option<&'resolver mut JobContext<'context>>,
    pub(crate) entries: Vec<zmanager_unrar::RarEntry>,
}

/// Extracts a RAR archive through bundled `UnRAR` and the shared safety planner.
///
/// # Errors
///
/// Returns [`RarBackendError`] when `UnRAR` cannot read the archive, an entry is
/// unsafe, or filesystem writes fail.
pub fn extract_rar_with_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<RarExtractReport, RarBackendError> {
    let entries = zmanager_unrar::list_archive(archive.as_ref(), password)?;
    extract_rar_with_options(archive.as_ref(), destination.as_ref(), policy, RarExtractOptions { password, overwrite_resolver: None, context: None, entries })
}

/// Extracts a RAR archive with an overwrite resolver.
///
/// # Errors
///
/// Returns [`RarBackendError`] when `UnRAR` cannot read the archive, an entry is
/// unsafe, filesystem writes fail, or the resolver aborts extraction.
pub fn extract_rar_with_overwrite_resolver_and_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<RarExtractReport, RarBackendError> {
    let entries = zmanager_unrar::list_archive(archive.as_ref(), password)?;
    extract_rar_with_options(
        archive.as_ref(),
        destination.as_ref(),
        policy,
        RarExtractOptions { password, overwrite_resolver: Some(overwrite_resolver), context: None, entries },
    )
}

/// Extracts exactly one RAR entry by its retained path and duplicate
/// occurrence.  The occurrence is resolved against the native listing rather
/// than treating an engine entry ID as an unchecked index.
pub(crate) fn extract_rar_entry_by_path_occurrence(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    entry_path: &str,
    occurrence: usize,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<RarExtractReport, RarBackendError> {
    let archive = archive.as_ref();
    let entry = zmanager_unrar::list_archive(archive, password)?.into_iter().filter(|entry| entry.path == entry_path).nth(occurrence).ok_or_else(|| {
        RarBackendError::Io {
            path: archive.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "retained RAR entry is not present in this archive"),
        }
    })?;
    reject_large_dictionary(&entry)?;
    extract_rar_with_options(archive, destination.as_ref(), policy, RarExtractOptions { password, overwrite_resolver, context: None, entries: vec![entry] })
}

/// Selects one retained RAR entry by path and duplicate occurrence.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RarEntrySelector<'a> {
    pub(crate) path: &'a str,
    pub(crate) occurrence: usize,
}

/// Extracts several retained RAR entries in a single pass.
///
/// RAR archives may be solid, in which case decoding one member requires
/// decoding every member before it. Extracting a selection one entry at a time
/// therefore repeats that work per entry; `UnRAR` can take the whole selection
/// at once, so the archive is walked once regardless of how many entries are
/// selected.
///
/// # Errors
///
/// Returns [`RarBackendError`] when `UnRAR` cannot read the archive, a selector
/// names an entry the archive does not contain, an entry is unsafe, or
/// filesystem writes fail.
pub(crate) fn extract_rar_entries_by_path_occurrence(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    selectors: &[RarEntrySelector<'_>],
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<RarExtractReport, RarBackendError> {
    let archive = archive.as_ref();
    let listing = zmanager_unrar::list_archive(archive, password)?;

    // Group by path once rather than rescanning the listing per selector, so
    // resolving a large selection stays linear in the archive size.
    let mut by_path: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, entry) in listing.iter().enumerate() {
        by_path.entry(entry.path.as_str()).or_default().push(index);
    }

    let mut indices = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let index = by_path.get(selector.path).and_then(|matches| matches.get(selector.occurrence).copied()).ok_or_else(|| RarBackendError::Io {
            path: archive.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "retained RAR entry is not present in this archive"),
        })?;
        indices.push(index);
    }
    // Extract in archive order so a solid stream is consumed front to back.
    indices.sort_unstable();
    indices.dedup();

    let mut entries = Vec::with_capacity(indices.len());
    for index in indices {
        let entry = listing[index].clone();
        reject_large_dictionary(&entry)?;
        entries.push(entry);
    }

    extract_rar_with_options(archive, destination.as_ref(), policy, RarExtractOptions { password, overwrite_resolver, context: None, entries })
}

/// Copies exactly one regular RAR entry by its retained path and duplicate
/// occurrence.
pub(crate) fn copy_rar_entry_by_path_occurrence(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    entry_path: &str,
    occurrence: usize,
    output: &mut dyn io::Write,
) -> Result<u64, RarBackendError> {
    let archive = archive.as_ref();
    let entry = zmanager_unrar::list_archive(archive, password)?.into_iter().filter(|entry| entry.path == entry_path).nth(occurrence).ok_or_else(|| {
        RarBackendError::Io {
            path: archive.to_path_buf(),
            source: io::Error::new(io::ErrorKind::NotFound, "retained RAR entry is not present in this archive"),
        }
    })?;
    reject_large_dictionary(&entry)?;
    if !matches!(entry.kind, RarEntryKind::File) {
        return Err(RarBackendError::Io {
            path: PathBuf::from(&entry.path),
            source: io::Error::new(io::ErrorKind::InvalidInput, "retained RAR entry is not a regular file"),
        });
    }

    let temporary = crate::temp_names::TemporaryDirectory::new("rar-copy").map_err(|error| RarBackendError::Io { path: error.path, source: error.source })?;
    let temporary_path = temporary.path().join("payload");
    let mut selections = BTreeMap::new();
    selections.insert(entry.path.clone(), temporary_path.clone());
    zmanager_unrar::extract_selected(archive, password, &selections)?;
    let mut decoded = fs::File::open(&temporary_path).map_err(|source| RarBackendError::Io { path: temporary_path.clone(), source })?;
    io::copy(&mut decoded, output).map_err(|source| RarBackendError::Io { path: temporary_path, source })
}

/// The single core RAR extraction implementation used by every public entry
/// point.
///
/// The explicit lifetimes are required: eliding them makes the trait-object
/// reborrow of the overwrite resolver unify with the struct's field lifetime
/// and fail to compile.
#[allow(clippy::elidable_lifetime_names)]
fn extract_rar_with_options<'password, 'resolver, 'context>(
    archive: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    options: RarExtractOptions<'password, 'resolver, 'context>,
) -> Result<RarExtractReport, RarBackendError> {
    let RarExtractOptions { password, overwrite_resolver, mut context, entries } = options;
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| RarBackendError::Io { path: destination.to_path_buf(), source })?;

    let PlannedRarExtraction { selections, metadata_map, deferred_links, deferred_dirs, entry_progress, mut report } =
        plan_rar_entries(entries, &destination_root, policy, overwrite_resolver)?;

    if let Some(context) = context.as_deref_mut() {
        for (path, bytes) in &entry_progress {
            context.entry_started(path, Some(*bytes));
        }
    }

    match context {
        Some(context) => {
            let mut progress = |path: String, bytes: u64| {
                context.bytes_processed(Some(path.as_str()), bytes);
                context.entry_finished(path, bytes);
            };
            zmanager_unrar::extract_selected_with_progress(archive, password, &selections, Some(&mut progress))?;
        }
        None => {
            zmanager_unrar::extract_selected_with_progress(archive, password, &selections, None)?;
        }
    }

    for (archive_path, dest_path) in &selections {
        if let Some(&(file_attr, mtime)) = metadata_map.get(archive_path) {
            apply_rar_metadata(dest_path, file_attr, mtime).map_err(|source| RarBackendError::Io { path: dest_path.clone(), source })?;
        }
    }

    report.written_entries += selections.len();
    materialize_deferred_links(&deferred_links, &mut report)?;

    for (dir_path, file_attr, mtime) in deferred_dirs.into_iter().rev() {
        apply_rar_metadata(&dir_path, file_attr, mtime).map_err(|source| RarBackendError::Io { path: dir_path, source })?;
    }

    Ok(report)
}

struct PlannedRarExtraction {
    selections: BTreeMap<String, PathBuf>,
    metadata_map: BTreeMap<String, (u32, u64)>,
    deferred_links: Vec<DeferredLink>,
    deferred_dirs: Vec<(PathBuf, u32, u64)>,
    entry_progress: Vec<(String, u64)>,
    report: RarExtractReport,
}

/// One planned writable entry, produced without touching the filesystem.
///
/// Planning is split into a pure per-entry plan phase and a commit phase so
/// a failing entry cannot leave partially created directories behind.
enum PlannedEntry {
    Directory { destination_path: PathBuf, replace_existing: bool, file_attr: u32, mtime: u64 },
    File { archive_path: String, destination_path: PathBuf, replace_existing: bool, file_attr: u32, mtime: u64, size: u64 },
    Symlink { destination_path: PathBuf, replace_existing: bool, target: PathBuf, file_attr: u32, mtime: u64 },
    Hardlink { destination_path: PathBuf, replace_existing: bool, source_path: PathBuf, file_attr: u32, mtime: u64 },
    FileCopy { destination_path: PathBuf, replace_existing: bool, source_path: PathBuf, file_attr: u32, mtime: u64 },
}

// The by-value policy is the contract that keeps the public wrappers free of
// `needless_pass_by_value` warnings: they hand ownership down, and the planner
// clones the policy exactly once here.
#[allow(clippy::needless_pass_by_value)]
fn plan_rar_entries(
    entries: Vec<zmanager_unrar::RarEntry>,
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<PlannedRarExtraction, RarBackendError> {
    // The planner owns the policy; clone it exactly once instead of holding a
    // reference through the whole planning loop.
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(destination, policy.clone(), resolver),
        None => ExtractionSafetyPlanner::new(destination, policy.clone()),
    };
    let mut plans = Vec::new();
    let mut extraction = PlannedRarExtraction {
        selections: BTreeMap::new(),
        metadata_map: BTreeMap::new(),
        deferred_links: Vec::new(),
        deferred_dirs: Vec::new(),
        entry_progress: Vec::new(),
        report: RarExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() },
    };

    for entry in entries {
        reject_large_dictionary(&entry)?;
        let Some(extraction_kind) = extraction_entry_kind(&entry, &policy)? else {
            extraction.report.skipped_entries += 1;
            extraction.report.warnings.push(format!("skipped {}: unsupported RAR special entry", entry.path));
            continue;
        };
        let safety_entry =
            ExtractionEntry { archive_path: entry.path.clone(), kind: extraction_kind, uncompressed_size: Some(entry.unpacked_size), compressed_size: None };

        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write { destination_path, replace_existing, .. } => {
                // FileCopy entries are planned as hardlink-like entries, so
                // the planner does not account for them by itself, but
                // materialization copies the full source file. Charge the
                // copy against the expanded-size limit up front so the guard
                // trips at planning time, not after the bytes exist.
                if matches!(entry.kind, RarEntryKind::FileCopy) {
                    planner.reserve_expanded_bytes(&entry.path, entry.unpacked_size)?;
                }
                extraction.entry_progress.push((entry.path.clone(), entry.unpacked_size));
                plans.push(plan_entry(entry, destination_path, replace_existing, destination, &policy)?);
            }
            ExtractionDecision::Skip { reason, .. } => {
                extraction.report.skipped_entries += 1;
                extraction.report.warnings.push(format!("skipped {}: {reason}", entry.path));
            }
        }
    }

    for plan in plans {
        commit_planned_entry(plan, &mut extraction)?;
    }

    Ok(extraction)
}

fn plan_entry(
    entry: zmanager_unrar::RarEntry,
    destination_path: PathBuf,
    replace_existing: bool,
    destination: &Path,
    policy: &ExtractionPolicy,
) -> Result<PlannedEntry, RarBackendError> {
    match entry.kind {
        RarEntryKind::Directory => Ok(PlannedEntry::Directory { destination_path, replace_existing, file_attr: entry.file_attr, mtime: entry.mtime }),
        RarEntryKind::File => Ok(PlannedEntry::File {
            archive_path: entry.path,
            destination_path,
            replace_existing,
            file_attr: entry.file_attr,
            mtime: entry.mtime,
            size: entry.unpacked_size,
        }),
        RarEntryKind::Symlink => {
            let target = link_target(&entry)?;
            Ok(PlannedEntry::Symlink { destination_path, replace_existing, target: PathBuf::from(target), file_attr: entry.file_attr, mtime: entry.mtime })
        }
        RarEntryKind::Hardlink | RarEntryKind::FileCopy => {
            let target = link_target(&entry)?;
            let source_path = archive_target_destination(destination, target, policy)?;
            if entry.kind == RarEntryKind::Hardlink {
                Ok(PlannedEntry::Hardlink { destination_path, replace_existing, source_path, file_attr: entry.file_attr, mtime: entry.mtime })
            } else {
                Ok(PlannedEntry::FileCopy { destination_path, replace_existing, source_path, file_attr: entry.file_attr, mtime: entry.mtime })
            }
        }
        RarEntryKind::Special => {
            // Planning skips special entries; if a future planner change lets
            // one through, fail the entry instead of panicking the process.
            Err(RarBackendError::Io {
                path: destination_path.clone(),
                source: io::Error::new(io::ErrorKind::InvalidData, format!("unsupported RAR special entry: {}", entry.path)),
            })
        }
    }
}

fn commit_planned_entry(plan: PlannedEntry, extraction: &mut PlannedRarExtraction) -> Result<(), RarBackendError> {
    match plan {
        PlannedEntry::Directory { destination_path, replace_existing, file_attr, mtime } => {
            if replace_existing {
                remove_destination(&destination_path)?;
            }
            fs::create_dir_all(&destination_path).map_err(|source| RarBackendError::Io { path: destination_path.clone(), source })?;
            extraction.deferred_dirs.push((destination_path, file_attr, mtime));
            extraction.report.written_entries += 1;
        }
        PlannedEntry::File { archive_path, destination_path, replace_existing, file_attr, mtime, size } => {
            if replace_existing {
                remove_destination(&destination_path)?;
            }
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|source| RarBackendError::Io { path: parent.to_path_buf(), source })?;
            }
            extraction.report.written_bytes += size;
            extraction.metadata_map.insert(archive_path.clone(), (file_attr, mtime));
            extraction.selections.insert(archive_path, destination_path);
        }
        PlannedEntry::Symlink { destination_path, replace_existing, target, file_attr, mtime } => {
            extraction.deferred_links.push(DeferredLink { destination_path, replace_existing, kind: DeferredLinkKind::Symlink { target }, file_attr, mtime });
        }
        PlannedEntry::Hardlink { destination_path, replace_existing, source_path, file_attr, mtime } => {
            extraction.deferred_links.push(DeferredLink {
                destination_path,
                replace_existing,
                kind: DeferredLinkKind::Hardlink { source_path },
                file_attr,
                mtime,
            });
        }
        PlannedEntry::FileCopy { destination_path, replace_existing, source_path, file_attr, mtime } => {
            extraction.deferred_links.push(DeferredLink {
                destination_path,
                replace_existing,
                kind: DeferredLinkKind::FileCopy { source_path },
                file_attr,
                mtime,
            });
        }
    }
    Ok(())
}

fn reject_large_dictionary(entry: &zmanager_unrar::RarEntry) -> Result<(), RarBackendError> {
    if entry.dictionary_size > MAX_LARGE_DICTIONARY_BYTES {
        return Err(RarBackendError::DictionaryTooLarge { path: entry.path.clone(), size: entry.dictionary_size });
    }
    Ok(())
}

fn list_entry_kind(kind: RarEntryKind) -> RarListEntryKind {
    match kind {
        RarEntryKind::File => RarListEntryKind::File,
        RarEntryKind::Directory => RarListEntryKind::Directory,
        RarEntryKind::Symlink => RarListEntryKind::Symlink,
        RarEntryKind::Hardlink => RarListEntryKind::Hardlink,
        RarEntryKind::FileCopy => RarListEntryKind::FileCopy,
        RarEntryKind::Special => RarListEntryKind::Special,
    }
}

fn extraction_entry_kind(entry: &zmanager_unrar::RarEntry, policy: &ExtractionPolicy) -> Result<Option<ExtractionEntryKind>, RarBackendError> {
    match entry.kind {
        RarEntryKind::File => Ok(Some(ExtractionEntryKind::File)),
        RarEntryKind::Directory => Ok(Some(ExtractionEntryKind::Directory)),
        RarEntryKind::Symlink => Ok(Some(ExtractionEntryKind::Symlink { target: PathBuf::from(link_target(entry)?) })),
        RarEntryKind::Hardlink | RarEntryKind::FileCopy => {
            let target = link_target(entry)?;
            let relative_target = relative_archive_target_for_link(&entry.path, target, policy.strip_components)?;
            Ok(Some(ExtractionEntryKind::Hardlink { target: relative_target }))
        }
        RarEntryKind::Special => Ok(None),
    }
}

fn remove_destination(path: &Path) -> Result<(), RarBackendError> {
    remove_destination_for_replace(path).map_err(|source| RarBackendError::Io { path: path.to_path_buf(), source })
}

struct DeferredLink {
    destination_path: PathBuf,
    replace_existing: bool,
    kind: DeferredLinkKind,
    file_attr: u32,
    mtime: u64,
}

enum DeferredLinkKind {
    Symlink { target: PathBuf },
    Hardlink { source_path: PathBuf },
    FileCopy { source_path: PathBuf },
}

fn materialize_deferred_links(links: &[DeferredLink], report: &mut RarExtractReport) -> Result<(), RarBackendError> {
    let mut pending = Vec::new();
    for link in links {
        if matches!(&link.kind, DeferredLinkKind::Symlink { .. }) {
            materialize_deferred_link(link, report)?;
        } else {
            pending.push(link);
        }
    }

    let paths = pending
        .iter()
        .map(|link| {
            let source_path = match &link.kind {
                DeferredLinkKind::Hardlink { source_path } | DeferredLinkKind::FileCopy { source_path } => source_path,
                // Symlinks are materialized eagerly above; a deferred symlink
                // would be a planner bug, so fail loudly rather than panic.
                DeferredLinkKind::Symlink { .. } => {
                    return Err(RarBackendError::Io {
                        path: link.destination_path.clone(),
                        source: io::Error::new(io::ErrorKind::InvalidData, "deferred symlink was not materialized"),
                    });
                }
            };
            Ok((source_path.clone(), link.destination_path.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let order = crate::safety::deferred_link_dependency_order(&paths)
        .map_err(|source| RarBackendError::Io { path: pending.first().map_or_else(PathBuf::new, |link| link.destination_path.clone()), source })?;
    for index in order {
        materialize_deferred_link(pending[index], report)?;
    }
    Ok(())
}

fn materialize_deferred_link(link: &DeferredLink, report: &mut RarExtractReport) -> Result<(), RarBackendError> {
    if link.replace_existing {
        remove_destination(&link.destination_path)?;
    }
    if let Some(parent) = link.destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| RarBackendError::Io { path: parent.to_path_buf(), source })?;
    }

    match &link.kind {
        DeferredLinkKind::Symlink { target } => {
            crate::extract_materialize::write_symlink(target, &link.destination_path)
                .map_err(|source| RarBackendError::Io { path: link.destination_path.clone(), source })?;
        }
        DeferredLinkKind::Hardlink { source_path } => {
            fs::hard_link(source_path, &link.destination_path).map_err(|source| RarBackendError::Io { path: link.destination_path.clone(), source })?;
        }
        DeferredLinkKind::FileCopy { source_path } => {
            let bytes = fs::copy(source_path, &link.destination_path).map_err(|source| RarBackendError::Io { path: link.destination_path.clone(), source })?;
            report.written_bytes += bytes;
        }
    }

    apply_rar_metadata(&link.destination_path, link.file_attr, link.mtime)
        .map_err(|source| RarBackendError::Io { path: link.destination_path.clone(), source })?;

    report.written_entries += 1;
    Ok(())
}

fn apply_rar_metadata(path: &Path, file_attr: u32, mtime: u64) -> io::Result<()> {
    let is_symlink = fs::symlink_metadata(path)?.file_type().is_symlink();

    #[cfg(unix)]
    {
        if !is_symlink && (file_attr & 0xFFFF_0000) != 0 {
            use std::os::unix::fs::PermissionsExt;
            let permissions = (file_attr >> 16) & RAR_UNIX_MODE_MASK;
            fs::set_permissions(path, fs::Permissions::from_mode(permissions))?;
        }
    }

    #[cfg(not(unix))]
    {
        if !is_symlink && (file_attr & 0xFFFF_0000) != 0 {
            let permissions = (file_attr >> 16) & RAR_UNIX_MODE_MASK;
            if permissions & 0o222 == 0
                && let Ok(fs_metadata) = fs::metadata(path)
            {
                let mut perms = fs_metadata.permissions();
                perms.set_readonly(true);
                fs::set_permissions(path, perms)?;
            }
        }
    }

    if mtime != 0 {
        let filetime_seconds = mtime / RAR_FILETIME_TICKS_PER_SECOND;
        let unix_seconds = i128::from(filetime_seconds) - i128::from(WINDOWS_TO_UNIX_EPOCH_SECONDS);
        let unix_secs = i64::try_from(unix_seconds)
            .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, format!("RAR modification time is out of range: {source}")))?;
        let nanos = u32::try_from((mtime % RAR_FILETIME_TICKS_PER_SECOND) * RAR_FILETIME_NANOS_PER_TICK)
            .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, format!("RAR modification time fraction is out of range: {source}")))?;
        let file_time = filetime::FileTime::from_unix_time(unix_secs, nanos);

        if is_symlink {
            filetime::set_symlink_file_times(path, file_time, file_time)?;
        } else {
            filetime::set_file_mtime(path, file_time)?;
        }
    }
    Ok(())
}

fn link_target(entry: &zmanager_unrar::RarEntry) -> Result<&str, RarBackendError> {
    entry.link_target.as_deref().ok_or_else(|| RarBackendError::MissingLinkTarget { path: entry.path.clone() })
}

fn archive_target_destination(destination: &Path, target: &str, policy: &ExtractionPolicy) -> Result<PathBuf, RarBackendError> {
    let target = stripped_archive_path(target, policy.strip_components)?;
    Ok(destination.join(target))
}

fn relative_archive_target_for_link(link_path: &str, target: &str, strip_components: usize) -> Result<PathBuf, RarBackendError> {
    let stripped_link = stripped_archive_path(link_path, strip_components)?;
    let stripped_target = stripped_archive_path(target, strip_components)?;
    let link_parent = stripped_link.rsplit_once('/').map_or("", |(parent, _)| parent);
    Ok(relative_path(link_parent, &stripped_target))
}

fn stripped_archive_path(path: &str, strip_components: usize) -> Result<String, RarBackendError> {
    let normalized = normalize_archive_path(path).map_err(|source| RarBackendError::InvalidLinkTarget {
        path: path.to_owned(),
        target: path.to_owned(),
        reason: source.to_string(),
    })?;
    if strip_components == 0 {
        return Ok(normalized);
    }

    let components = normalized.split('/').skip(strip_components).collect::<Vec<_>>();
    if components.is_empty() {
        return Err(RarBackendError::InvalidLinkTarget {
            path: path.to_owned(),
            target: path.to_owned(),
            reason: "target is removed by strip-components policy".to_owned(),
        });
    }
    Ok(components.join("/"))
}

fn relative_path(from_parent: &str, to: &str) -> PathBuf {
    let from_parts = if from_parent.is_empty() { Vec::new() } else { from_parent.split('/').collect::<Vec<_>>() };
    let to_parts = to.split('/').collect::<Vec<_>>();
    let common = from_parts.iter().zip(&to_parts).take_while(|(left, right)| left == right).count();

    let mut path = PathBuf::new();
    for _ in common..from_parts.len() {
        path.push("..");
    }
    for part in &to_parts[common..] {
        path.push(part);
    }
    path
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{
        DeferredLink, DeferredLinkKind, RAR_FILETIME_TICKS_PER_SECOND, RarExtractReport, WINDOWS_TO_UNIX_EPOCH_SECONDS, apply_rar_metadata,
        materialize_deferred_links,
    };
    use super::{extract_rar_with_password, list_rar_with_password};
    use crate::safety::{ExtractionPolicy, OverwritePolicy};
    use crate::test_support::TestDir;
    use std::collections::HashSet;
    #[cfg(unix)]
    use std::fs;
    use std::path::PathBuf;

    fn rar_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn assert_complete_multipart_rar_round_trip(archive: &std::path::Path, password: Option<&str>, label: &str) {
        let listing = list_rar_with_password(archive, password).unwrap_or_else(|error| panic!("{label} listing failed: {error}"));
        // RAR listings use the host separator; normalize so the fixture
        // assertions are platform-independent (matches the CLI fixture test).
        let paths = listing.entries.iter().map(|entry| entry.path.replace('\\', "/")).collect::<Vec<_>>();
        let unique_paths = paths.iter().cloned().collect::<HashSet<_>>();
        assert_eq!(paths.len(), unique_paths.len(), "{label} must not list volume continuations as duplicate entries");
        assert_eq!(paths.iter().filter(|path| path.as_str() == "rar-fixture/data/stream.bin").count(), 1);
        assert!(paths.contains(&"rar-fixture/docs/readme.txt".to_string()));
        assert!(paths.contains(&"rar-fixture/data/manifest.json".to_string()));

        let temp = TestDir::new("checked_in_rar_fixture_extract");
        let report = extract_rar_with_password(
            archive,
            temp.path("out"),
            ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            password,
        )
        .unwrap_or_else(|error| panic!("{label} extraction failed: {error}"));

        assert_eq!(report.written_bytes, 196_608 + 22 + 23);
        assert_eq!(std::fs::read(temp.path("out/rar-fixture/data/stream.bin")).unwrap(), vec![0; 196_608]);
        assert_eq!(std::fs::read_to_string(temp.path("out/rar-fixture/docs/readme.txt")).unwrap(), "RAR multipart fixture\n");
        assert_eq!(std::fs::read_to_string(temp.path("out/rar-fixture/data/manifest.json")).unwrap(), "{\"fixture\":\"zmanager\"}\n");
    }

    #[test]
    fn checked_in_rar5_multipart_fixture_lists_once_and_extracts_every_file() {
        assert_complete_multipart_rar_round_trip(&rar_fixture("rar5-multipart.part1.rar"), None, "rar5-multipart");
    }

    #[test]
    fn checked_in_passworded_rar5_multipart_fixture_requires_the_exact_password() {
        let archive = rar_fixture("rar5-passworded-multipart.part1.rar");
        assert!(list_rar_with_password(&archive, None).is_err(), "passworded RAR must not list without a password");
        assert!(list_rar_with_password(&archive, Some("wrong password")).is_err(), "passworded RAR must reject a wrong password");
        assert_complete_multipart_rar_round_trip(&archive, Some("zmanager-rar-fixture-password"), "rar5-passworded-multipart");
    }

    #[cfg(unix)]
    #[test]
    fn rar_metadata_preserves_special_mode_bits_without_following_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TestDir::new("rar_metadata_modes");
        let directory = temp.path("sticky");
        fs::create_dir(&directory).unwrap();
        apply_rar_metadata(&directory, 0o1750 << 16, 0).unwrap();
        assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o7777, 0o1750);

        let target = temp.path("target.txt");
        fs::write(&target, b"target").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let link = temp.path("link.txt");
        symlink("target.txt", &link).unwrap();

        apply_rar_metadata(&link, 0o777 << 16, 0).unwrap();

        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o7777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn rar_metadata_restores_pre_epoch_subsecond_time() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("rar_metadata_pre_epoch_time");
        let path = temp.path("old.txt");
        fs::write(&path, b"old").unwrap();
        let filetime_ticks = (WINDOWS_TO_UNIX_EPOCH_SECONDS - 1) * RAR_FILETIME_TICKS_PER_SECOND + 2_500_000;

        apply_rar_metadata(&path, 0, filetime_ticks).unwrap();

        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.mtime(), -1);
        assert_eq!(metadata.mtime_nsec(), 250_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn rar_deferred_hardlink_chains_do_not_depend_on_archive_order() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("rar_forward_hardlink_chain");
        let target = temp.path("target.txt");
        let middle = temp.path("middle.txt");
        let first = temp.path("first.txt");
        fs::write(&target, b"target").unwrap();
        let links = [
            DeferredLink {
                destination_path: first.clone(),
                replace_existing: false,
                kind: DeferredLinkKind::Hardlink { source_path: middle.clone() },
                file_attr: 0,
                mtime: 0,
            },
            DeferredLink {
                destination_path: middle.clone(),
                replace_existing: false,
                kind: DeferredLinkKind::Hardlink { source_path: target.clone() },
                file_attr: 0,
                mtime: 0,
            },
        ];
        let mut report = RarExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

        materialize_deferred_links(&links, &mut report).unwrap();

        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::metadata(&target).unwrap().ino(), fs::metadata(&first).unwrap().ino());
        assert_eq!(fs::metadata(&target).unwrap().ino(), fs::metadata(&middle).unwrap().ino());
    }

    #[test]
    fn file_copy_entries_are_charged_against_expanded_size_limit() {
        use super::*;

        let destination = std::env::temp_dir().join(format!("zmanager-rar-filecopy-limit-{}", std::process::id()));
        let mut policy = ExtractionPolicy::default();
        policy.limits.max_expanded_bytes = Some(100);

        let regular_file = |path: &str, size: u64| zmanager_unrar::RarEntry {
            path: path.to_owned(),
            unpacked_size: size,
            dictionary_size: 0,
            kind: RarEntryKind::File,
            link_target: None,
            encrypted: false,
            solid: true,
            file_attr: 0,
            mtime: 0,
        };
        let file_copy = |path: &str, size: u64| zmanager_unrar::RarEntry {
            path: path.to_owned(),
            unpacked_size: size,
            dictionary_size: 0,
            kind: RarEntryKind::FileCopy,
            link_target: Some("source.txt".to_owned()),
            encrypted: false,
            solid: true,
            file_attr: 0,
            mtime: 0,
        };

        // A copy within the limit plans cleanly.
        plan_rar_entries(vec![regular_file("source.txt", 60), file_copy("copy.txt", 40)], &destination, policy.clone(), None)
            .expect("a file copy within the limit should plan");

        // The copy must be charged against the limit like a regular file:
        // source (60) plus copy (60) exceeds the 100-byte limit.
        let Err(error) = plan_rar_entries(vec![regular_file("source.txt", 60), file_copy("copy.txt", 60)], &destination, policy, None) else {
            panic!("file copies over the limit should be rejected at planning time");
        };
        assert!(matches!(error, RarBackendError::Safety(ExtractionSafetyError::ExpandedSizeLimitExceeded { .. })));
    }
}
