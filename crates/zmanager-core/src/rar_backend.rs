use crate::jobs::JobContext;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver, normalize_archive_path,
    remove_destination_for_replace,
};
use std::collections::BTreeMap;
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

impl RarListEntry {
    pub(crate) fn into_unrar_entry(self) -> zmanager_unrar::RarEntry {
        zmanager_unrar::RarEntry {
            path: self.path,
            unpacked_size: self.size,
            dictionary_size: self.dictionary_size,
            kind: self.kind.into_unrar_kind(),
            link_target: self.link_target,
            encrypted: self.encrypted,
            solid: self.solid,
            file_attr: self.file_attr,
            mtime: self.mtime,
        }
    }
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

impl RarListEntryKind {
    fn into_unrar_kind(self) -> RarEntryKind {
        match self {
            Self::File => RarEntryKind::File,
            Self::Directory => RarEntryKind::Directory,
            Self::Symlink => RarEntryKind::Symlink,
            Self::Hardlink => RarEntryKind::Hardlink,
            Self::FileCopy => RarEntryKind::FileCopy,
            Self::Special => RarEntryKind::Special,
        }
    }
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
    InvalidLinkTarget {
        path: String,
        target: String,
        reason: String,
    },
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
            Self::InvalidLinkTarget {
                path,
                target,
                reason,
            } => write!(
                f,
                "RAR link entry {path} has invalid target {target}: {reason}"
            ),
            Self::DictionaryTooLarge { path, size } => write!(
                f,
                "RAR dictionary exceeds {LARGE_DICTIONARY_LIMIT_MIB} MiB limit for {path}: {} MiB",
                size.div_ceil(crate::MEBIBYTE_BYTES)
            ),
        }
    }
}

impl std::error::Error for RarBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unrar(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingLinkTarget { .. }
            | Self::InvalidLinkTarget { .. }
            | Self::DictionaryTooLarge { .. } => None,
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
pub fn list_rar_with_password(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<RarListing, RarBackendError> {
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
    extract_rar_inner(archive, destination, policy, password, None, None)
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
    extract_rar_inner(
        archive,
        destination,
        policy,
        password,
        Some(overwrite_resolver),
        None,
    )
}

/// Extracts a RAR archive through bundled `UnRAR` and the shared safety
/// planner, with progress reporting.
///
/// # Errors
///
/// Returns [`RarBackendError`] when `UnRAR` cannot read the archive, an entry
/// is unsafe, or filesystem writes fail.
pub fn extract_rar_with_password_and_context(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<RarExtractReport, RarBackendError> {
    extract_rar_inner(archive, destination, policy, password, None, Some(context))
}

pub(crate) fn extract_rar_entries_with_password_and_context(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    entries: Vec<zmanager_unrar::RarEntry>,
    context: &mut JobContext<'_>,
) -> Result<RarExtractReport, RarBackendError> {
    extract_rar_inner_with_entries(
        archive,
        destination,
        policy,
        password,
        entries,
        None,
        Some(context),
    )
}

fn extract_rar_inner(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<RarExtractReport, RarBackendError> {
    let entries = zmanager_unrar::list_archive(archive.as_ref(), password)?;
    extract_rar_inner_with_entries(
        archive,
        destination,
        policy,
        password,
        entries,
        overwrite_resolver,
        context,
    )
}

fn extract_rar_inner_with_entries(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    entries: Vec<zmanager_unrar::RarEntry>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<RarExtractReport, RarBackendError> {
    let archive = archive.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            RarBackendError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;

    let PlannedRarExtraction {
        selections,
        metadata_map,
        deferred_links,
        deferred_dirs,
        entry_progress,
        mut report,
    } = plan_rar_entries(entries, &destination_root, policy, overwrite_resolver)?;

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
            zmanager_unrar::extract_selected_with_progress(
                archive,
                password,
                &selections,
                Some(&mut progress),
            )?;
        }
        None => {
            zmanager_unrar::extract_selected_with_progress(archive, password, &selections, None)?;
        }
    }

    for (archive_path, dest_path) in &selections {
        if let Some(&(file_attr, mtime)) = metadata_map.get(archive_path) {
            apply_rar_metadata(dest_path, file_attr, mtime).map_err(|source| {
                RarBackendError::Io {
                    path: dest_path.clone(),
                    source,
                }
            })?;
        }
    }

    report.written_entries += selections.len();
    materialize_deferred_links(&deferred_links, &mut report)?;

    for (dir_path, file_attr, mtime) in deferred_dirs.into_iter().rev() {
        apply_rar_metadata(&dir_path, file_attr, mtime).map_err(|source| RarBackendError::Io {
            path: dir_path,
            source,
        })?;
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

fn plan_rar_entries(
    entries: Vec<zmanager_unrar::RarEntry>,
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<PlannedRarExtraction, RarBackendError> {
    let target_policy = policy.clone();
    let mut planner = match overwrite_resolver {
        Some(resolver) => {
            ExtractionSafetyPlanner::new_with_overwrite_resolver(destination, policy, resolver)
        }
        None => ExtractionSafetyPlanner::new(destination, policy),
    };
    let mut selections = BTreeMap::new();
    let mut metadata_map = BTreeMap::new();
    let mut deferred_links = Vec::new();
    let mut deferred_dirs = Vec::new();
    let mut entry_progress = Vec::new();
    let mut report = RarExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in entries {
        reject_large_dictionary(&entry)?;
        let Some(extraction_kind) = extraction_entry_kind(&entry, &target_policy)? else {
            report.skipped_entries += 1;
            report.warnings.push(format!(
                "skipped {}: unsupported RAR special entry",
                entry.path
            ));
            continue;
        };
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: extraction_kind,
            uncompressed_size: Some(entry.unpacked_size),
            compressed_size: None,
        };

        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                ..
            } => plan_writable_entry(
                entry,
                destination,
                &target_policy,
                WritableEntryPlan {
                    destination_path,
                    replace_existing,
                    selections: &mut selections,
                    metadata_map: &mut metadata_map,
                    deferred_links: &mut deferred_links,
                    deferred_dirs: &mut deferred_dirs,
                    entry_progress: &mut entry_progress,
                    report: &mut report,
                },
            )?,
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped {}: {reason}", entry.path));
            }
        }
    }

    Ok(PlannedRarExtraction {
        selections,
        metadata_map,
        deferred_links,
        deferred_dirs,
        entry_progress,
        report,
    })
}

fn reject_large_dictionary(entry: &zmanager_unrar::RarEntry) -> Result<(), RarBackendError> {
    if entry.dictionary_size > MAX_LARGE_DICTIONARY_BYTES {
        return Err(RarBackendError::DictionaryTooLarge {
            path: entry.path.clone(),
            size: entry.dictionary_size,
        });
    }
    Ok(())
}

struct WritableEntryPlan<'a> {
    destination_path: PathBuf,
    replace_existing: bool,
    selections: &'a mut BTreeMap<String, PathBuf>,
    metadata_map: &'a mut BTreeMap<String, (u32, u64)>,
    deferred_links: &'a mut Vec<DeferredLink>,
    deferred_dirs: &'a mut Vec<(PathBuf, u32, u64)>,
    entry_progress: &'a mut Vec<(String, u64)>,
    report: &'a mut RarExtractReport,
}

fn plan_writable_entry(
    entry: zmanager_unrar::RarEntry,
    destination: &Path,
    target_policy: &ExtractionPolicy,
    mut plan: WritableEntryPlan<'_>,
) -> Result<(), RarBackendError> {
    plan.entry_progress
        .push((entry.path.clone(), entry.unpacked_size));

    match entry.kind {
        RarEntryKind::Directory => plan_directory_entry(&entry, &mut plan)?,
        RarEntryKind::File => plan_file_entry(entry, plan)?,
        RarEntryKind::Symlink => plan_symlink_entry(&entry, plan)?,
        RarEntryKind::Hardlink | RarEntryKind::FileCopy => {
            plan_hardlink_like_entry(&entry, destination, target_policy, plan)?;
        }
        RarEntryKind::Special => {
            unreachable!("unsupported RAR special entries are skipped before planning")
        }
    }
    Ok(())
}

fn plan_directory_entry(
    entry: &zmanager_unrar::RarEntry,
    plan: &mut WritableEntryPlan<'_>,
) -> Result<(), RarBackendError> {
    if plan.replace_existing {
        remove_destination(&plan.destination_path)?;
    }
    fs::create_dir_all(&plan.destination_path).map_err(|source| RarBackendError::Io {
        path: plan.destination_path.clone(),
        source,
    })?;
    plan.deferred_dirs
        .push((plan.destination_path.clone(), entry.file_attr, entry.mtime));
    plan.report.written_entries += 1;
    Ok(())
}

fn plan_file_entry(
    entry: zmanager_unrar::RarEntry,
    plan: WritableEntryPlan<'_>,
) -> Result<(), RarBackendError> {
    if plan.replace_existing {
        remove_destination(&plan.destination_path)?;
    }
    if let Some(parent) = plan.destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| RarBackendError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    plan.report.written_bytes += entry.unpacked_size;
    plan.metadata_map
        .insert(entry.path.clone(), (entry.file_attr, entry.mtime));
    plan.selections.insert(entry.path, plan.destination_path);
    Ok(())
}

fn plan_symlink_entry(
    entry: &zmanager_unrar::RarEntry,
    plan: WritableEntryPlan<'_>,
) -> Result<(), RarBackendError> {
    let target = link_target(entry)?;
    plan.deferred_links.push(DeferredLink {
        destination_path: plan.destination_path,
        replace_existing: plan.replace_existing,
        kind: DeferredLinkKind::Symlink {
            target: PathBuf::from(target),
        },
        file_attr: entry.file_attr,
        mtime: entry.mtime,
    });
    Ok(())
}

fn plan_hardlink_like_entry(
    entry: &zmanager_unrar::RarEntry,
    destination: &Path,
    target_policy: &ExtractionPolicy,
    plan: WritableEntryPlan<'_>,
) -> Result<(), RarBackendError> {
    let target = link_target(entry)?;
    let source_path = archive_target_destination(destination, target, target_policy)?;
    plan.deferred_links.push(DeferredLink {
        destination_path: plan.destination_path,
        replace_existing: plan.replace_existing,
        kind: if entry.kind == RarEntryKind::Hardlink {
            DeferredLinkKind::Hardlink { source_path }
        } else {
            DeferredLinkKind::FileCopy { source_path }
        },
        file_attr: entry.file_attr,
        mtime: entry.mtime,
    });
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

fn extraction_entry_kind(
    entry: &zmanager_unrar::RarEntry,
    policy: &ExtractionPolicy,
) -> Result<Option<ExtractionEntryKind>, RarBackendError> {
    match entry.kind {
        RarEntryKind::File => Ok(Some(ExtractionEntryKind::File)),
        RarEntryKind::Directory => Ok(Some(ExtractionEntryKind::Directory)),
        RarEntryKind::Symlink => Ok(Some(ExtractionEntryKind::Symlink {
            target: PathBuf::from(link_target(entry)?),
        })),
        RarEntryKind::Hardlink | RarEntryKind::FileCopy => {
            let target = link_target(entry)?;
            let relative_target =
                relative_archive_target_for_link(&entry.path, target, policy.strip_components)?;
            Ok(Some(ExtractionEntryKind::Hardlink {
                target: relative_target,
            }))
        }
        RarEntryKind::Special => Ok(None),
    }
}

fn remove_destination(path: &Path) -> Result<(), RarBackendError> {
    remove_destination_for_replace(path).map_err(|source| RarBackendError::Io {
        path: path.to_path_buf(),
        source,
    })
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

fn materialize_deferred_links(
    links: &[DeferredLink],
    report: &mut RarExtractReport,
) -> Result<(), RarBackendError> {
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
                DeferredLinkKind::Hardlink { source_path }
                | DeferredLinkKind::FileCopy { source_path } => source_path,
                DeferredLinkKind::Symlink { .. } => unreachable!(),
            };
            (source_path.clone(), link.destination_path.clone())
        })
        .collect::<Vec<_>>();
    let order = crate::safety::deferred_link_dependency_order(&paths).map_err(|source| {
        RarBackendError::Io {
            path: pending
                .first()
                .map_or_else(PathBuf::new, |link| link.destination_path.clone()),
            source,
        }
    })?;
    for index in order {
        materialize_deferred_link(pending[index], report)?;
    }
    Ok(())
}

fn materialize_deferred_link(
    link: &DeferredLink,
    report: &mut RarExtractReport,
) -> Result<(), RarBackendError> {
    if link.replace_existing {
        remove_destination(&link.destination_path)?;
    }
    if let Some(parent) = link.destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| RarBackendError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    match &link.kind {
        DeferredLinkKind::Symlink { target } => {
            write_symlink(target, &link.destination_path)?;
        }
        DeferredLinkKind::Hardlink { source_path } => {
            fs::hard_link(source_path, &link.destination_path).map_err(|source| {
                RarBackendError::Io {
                    path: link.destination_path.clone(),
                    source,
                }
            })?;
        }
        DeferredLinkKind::FileCopy { source_path } => {
            let bytes = fs::copy(source_path, &link.destination_path).map_err(|source| {
                RarBackendError::Io {
                    path: link.destination_path.clone(),
                    source,
                }
            })?;
            report.written_bytes += bytes;
        }
    }

    apply_rar_metadata(&link.destination_path, link.file_attr, link.mtime).map_err(|source| {
        RarBackendError::Io {
            path: link.destination_path.clone(),
            source,
        }
    })?;

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
            if permissions & 0o222 == 0 {
                if let Ok(fs_metadata) = fs::metadata(path) {
                    let mut perms = fs_metadata.permissions();
                    perms.set_readonly(true);
                    fs::set_permissions(path, perms)?;
                }
            }
        }
    }

    if mtime != 0 {
        let filetime_seconds = mtime / RAR_FILETIME_TICKS_PER_SECOND;
        let unix_seconds = i128::from(filetime_seconds) - i128::from(WINDOWS_TO_UNIX_EPOCH_SECONDS);
        let unix_secs = i64::try_from(unix_seconds).map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("RAR modification time is out of range: {source}"),
            )
        })?;
        let nanos =
            u32::try_from((mtime % RAR_FILETIME_TICKS_PER_SECOND) * RAR_FILETIME_NANOS_PER_TICK)
                .map_err(|source| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("RAR modification time fraction is out of range: {source}"),
                    )
                })?;
        let file_time = filetime::FileTime::from_unix_time(unix_secs, nanos);

        if is_symlink {
            filetime::set_symlink_file_times(path, file_time, file_time)?;
        } else {
            filetime::set_file_mtime(path, file_time)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), RarBackendError> {
    use std::os::unix::fs::symlink;

    symlink(target, destination_path).map_err(|source| RarBackendError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), RarBackendError> {
    Err(RarBackendError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

fn link_target(entry: &zmanager_unrar::RarEntry) -> Result<&str, RarBackendError> {
    entry
        .link_target
        .as_deref()
        .ok_or_else(|| RarBackendError::MissingLinkTarget {
            path: entry.path.clone(),
        })
}

fn archive_target_destination(
    destination: &Path,
    target: &str,
    policy: &ExtractionPolicy,
) -> Result<PathBuf, RarBackendError> {
    let target = stripped_archive_path(target, policy.strip_components)?;
    Ok(destination.join(target))
}

fn relative_archive_target_for_link(
    link_path: &str,
    target: &str,
    strip_components: usize,
) -> Result<PathBuf, RarBackendError> {
    let stripped_link = stripped_archive_path(link_path, strip_components)?;
    let stripped_target = stripped_archive_path(target, strip_components)?;
    let link_parent = stripped_link
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    Ok(relative_path(link_parent, &stripped_target))
}

fn stripped_archive_path(path: &str, strip_components: usize) -> Result<String, RarBackendError> {
    let normalized =
        normalize_archive_path(path).map_err(|source| RarBackendError::InvalidLinkTarget {
            path: path.to_owned(),
            target: path.to_owned(),
            reason: source.to_string(),
        })?;
    if strip_components == 0 {
        return Ok(normalized);
    }

    let components = normalized
        .split('/')
        .skip(strip_components)
        .collect::<Vec<_>>();
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
    let from_parts = if from_parent.is_empty() {
        Vec::new()
    } else {
        from_parent.split('/').collect::<Vec<_>>()
    };
    let to_parts = to.split('/').collect::<Vec<_>>();
    let common = from_parts
        .iter()
        .zip(&to_parts)
        .take_while(|(left, right)| left == right)
        .count();

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
        DeferredLink, DeferredLinkKind, RAR_FILETIME_TICKS_PER_SECOND, RarExtractReport,
        WINDOWS_TO_UNIX_EPOCH_SECONDS, apply_rar_metadata, materialize_deferred_links,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn rar_metadata_preserves_special_mode_bits_without_following_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TestDir::new("rar_metadata_modes");
        let directory = temp.path("sticky");
        fs::create_dir(&directory).unwrap();
        apply_rar_metadata(&directory, 0o1750 << 16, 0).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o1750
        );

        let target = temp.path("target.txt");
        fs::write(&target, b"target").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let link = temp.path("link.txt");
        symlink("target.txt", &link).unwrap();

        apply_rar_metadata(&link, 0o777 << 16, 0).unwrap();

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn rar_metadata_restores_pre_epoch_subsecond_time() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("rar_metadata_pre_epoch_time");
        let path = temp.path("old.txt");
        fs::write(&path, b"old").unwrap();
        let filetime_ticks =
            (WINDOWS_TO_UNIX_EPOCH_SECONDS - 1) * RAR_FILETIME_TICKS_PER_SECOND + 2_500_000;

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
                kind: DeferredLinkKind::Hardlink {
                    source_path: middle.clone(),
                },
                file_attr: 0,
                mtime: 0,
            },
            DeferredLink {
                destination_path: middle.clone(),
                replace_existing: false,
                kind: DeferredLinkKind::Hardlink {
                    source_path: target.clone(),
                },
                file_attr: 0,
                mtime: 0,
            },
        ];
        let mut report = RarExtractReport {
            written_entries: 0,
            skipped_entries: 0,
            written_bytes: 0,
            warnings: Vec::new(),
        };

        materialize_deferred_links(&links, &mut report).unwrap();

        assert_eq!(report.written_entries, 2);
        assert_eq!(
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&first).unwrap().ino()
        );
        assert_eq!(
            fs::metadata(&target).unwrap().ino(),
            fs::metadata(&middle).unwrap().ino()
        );
    }

    #[cfg(unix)]
    struct TestDir {
        root: PathBuf,
    }

    #[cfg(unix)]
    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("zmanager-{label}-{}-{unique}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }
    }

    #[cfg(unix)]
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
