//! TZAP extraction: the public extraction surface, the single
//! [`TzapExtractionState`] state machine shared by the fast and restore-based
//! paths, and the streaming and deferred-metadata helpers they use.

use super::{TzapError, io_error};
use crate::atomic_file::AtomicOutputFile;
use crate::jobs::JobContext;
use crate::safety::{ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyPlanner, OverwritePolicy, OverwriteResolver};
use crate::tzap::metadata::{metadata_diagnostic_labels, write_hardlink, write_symlink};
const TZAP_TEMP_EXTRACT_PREFIX: &str = ".zmanager-tzap-extract";
const TZAP_TEMP_EXTRACT_ATTEMPTS: u32 = 100;
// Batch restore runs single-threaded; the jobs parameter is the plugin's
// parallelism (minimum 1).
const EXTRACT_SELECTED_JOBS: usize = 1;
use crate::tzap::open::open_tzap_archive_with_key_options_multi;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::reader::{ArchiveEntry, ExtractedArchiveMember};
use tzap_core::{
    ArchiveTimestamp, ExtractError, FormatError, MetadataDiagnostic, OpenedArchive, RestorePolicy as CoreRestorePolicy, SafeExtractionOptions, TarEntryKind,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TzapFileExtractReport {
    /// Number of payload bytes written.
    pub written_bytes: u64,
    /// Structured metadata restoration diagnostics rendered for application clients.
    pub metadata_diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum TzapRestorePolicy {
    /// Restore payload bytes only.
    Content,
    /// Restore portable metadata such as ordinary mode bits and modification time.
    #[default]
    Portable,
    /// Request authenticated metadata for the current operating system.
    SameOs,
    /// Explicitly authorize system-class metadata restoration.
    System,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct TzapRestoreOptions {
    /// Requested restoration level.
    pub policy: TzapRestorePolicy,
    /// Permit unsupported requested metadata to be skipped with diagnostics.
    pub allow_degraded: bool,
    /// Allow absolute symlinks.
    pub allow_absolute_symlinks: bool,
}

impl TzapRestoreOptions {
    fn core_options(self, overwrite_existing: bool) -> SafeExtractionOptions {
        SafeExtractionOptions {
            overwrite_existing,
            restore_policy: match self.policy {
                TzapRestorePolicy::Content => CoreRestorePolicy::Content,
                TzapRestorePolicy::Portable => CoreRestorePolicy::Portable,
                TzapRestorePolicy::SameOs => CoreRestorePolicy::SameOs,
                TzapRestorePolicy::System => CoreRestorePolicy::System,
            },
            allow_degraded: self.allow_degraded,
            system_authorized: self.policy == TzapRestorePolicy::System && process_is_elevated(),
            allow_absolute_symlinks: self.allow_absolute_symlinks,
            sync_published_files: false,
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn process_is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn process_is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let Ok(elevation_size) = u32::try_from(size_of::<TOKEN_ELEVATION>()) else {
        unsafe {
            CloseHandle(token);
        }
        return false;
    };
    let elevated = unsafe {
        GetTokenInformation(token, TokenElevation, (&raw mut elevation).cast(), elevation_size, &raw mut returned) != 0
            && returned == elevation_size
            && elevation.TokenIsElevated != 0
    };
    unsafe {
        CloseHandle(token);
    }
    elevated
}

#[cfg(not(any(unix, windows)))]
fn process_is_elevated() -> bool {
    false
}

/// Key material for opening a `.tzap` archive.
///
/// A key source is exclusive: password-protected archives take a passphrase,
/// recipient-wrapped archives take a private key, and unprotected archives
/// take none (legacy no-secret raw-key archives open with tzap's all-zero
/// key). Previously this matrix was exposed as ~20 `extract_tzap_with_*`
/// wrappers (CR-142).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TzapExtractKeySource<'a> {
    /// No key material: opens unencrypted archives (and legacy no-secret
    /// raw-key archives with tzap's all-zero key).
    None,
    /// Passphrase-protected archives.
    Password(&'a str),
    /// Recipient-wrapped archives, keyed from a private-key file path.
    RecipientKeyPath(&'a Path),
    /// Recipient-wrapped archives, keyed from in-memory private-key bytes
    /// (for example a loaded secret-store value).
    RecipientKeyBytes(&'a [u8]),
    /// Recipient-wrapped archives, keyed from several in-memory candidate
    /// private-key blobs (a device's active key plus any retired ones,
    /// design §9.4). The first candidate whose SPKI matches the record wins.
    RecipientKeyBytesList(&'a [Vec<u8>]),
}

/// One `.tzap` extraction request (CR-142).
///
/// Replaces the previous `extract_tzap_with_*` wrapper matrix: key source,
/// safety policy, metadata restoration, overwrite resolution, and progress
/// context are explicit fields.
pub struct TzapExtractRequest<'a, 'context> {
    /// Key material used to open the archive.
    pub key: TzapExtractKeySource<'a>,
    /// Extraction safety policy.
    pub policy: ExtractionPolicy,
    /// Metadata restoration options.
    pub restore_options: TzapRestoreOptions,
    /// Overwrite resolver for `OverwritePolicy::Ask` conflicts. The fast
    /// extraction path does not support a resolver; passing one with
    /// `fast: true` is a programming error (asserted in debug builds).
    pub overwrite_resolver: Option<&'a mut dyn OverwriteResolver>,
    /// Job context for cancellation and progress reporting.
    pub context: Option<&'a mut JobContext<'context>>,
    /// Forces the fast single-pass state-machine extraction path instead of
    /// the restore-based path with automatic path selection.
    pub fast: bool,
}

/// Extracts a `.tzap` archive to a destination directory.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// requested metadata cannot be restored, or filesystem writes fail.
pub fn extract_tzap(request: TzapExtractRequest<'_, '_>, archive: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<TzapExtractReport, TzapError> {
    let TzapExtractRequest { key, policy, restore_options, overwrite_resolver, context, fast } = request;
    if fast {
        debug_assert!(overwrite_resolver.is_none(), "fast extraction does not support an overwrite resolver");
        return extract_tzap_fast_inner(archive, destination, policy, key, restore_options, context);
    }
    let (password, recipient_private_key, key_bytes_list) = key_components(key);
    extract_tzap_inner(
        archive,
        destination,
        ExtractTzapOptions { policy, password, recipient_private_key, recipient_private_key_bytes_list: key_bytes_list, restore_options },
        overwrite_resolver,
        context,
    )
}

/// Fast extraction with authenticated v45 metadata: regular-file payloads
/// remain streamed, while portable mode and modification time metadata are
/// restored after the payload is authenticated; unsupported special entries
/// are skipped with warnings.
fn extract_tzap_fast_inner(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    key: TzapExtractKeySource<'_>,
    restore_options: TzapRestoreOptions,
    context: Option<&mut JobContext<'_>>,
) -> Result<TzapExtractReport, TzapError> {
    let destination = destination.as_ref();
    let (password, recipient_private_key, key_bytes_list) = key_components(key);
    let opened = open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, key_bytes_list.as_deref())?;
    let entries = opened.list_files()?;
    opened.plan_metadata_restore(restore_options.core_options(false))?;
    if matches!(restore_options.policy, TzapRestorePolicy::SameOs | TzapRestorePolicy::System)
        && !restore_options.allow_degraded
        && entries.iter().any(|entry| entry.kind != TarEntryKind::Regular)
    {
        return Err(TzapError::Format(FormatError::ReaderUnsupported(
            "strict native metadata restore for non-regular entries is not supported by zmanager fast extraction; explicitly allow degraded restore",
        )));
    }
    let destination_root = crate::safety::prepare_destination_root(destination).map_err(|source| TzapError::Io { path: destination.to_path_buf(), source })?;
    let planner = ExtractionSafetyPlanner::new(&destination_root, policy);
    // The fast path shares the single `TzapExtractionState` machine with the
    // restore-based path; `Some(context)` drives job event emission.
    let mut state = TzapExtractionState::new(&opened, planner, restore_options);
    state.extract_entries(&entries, context)?;
    state.finish()
}

/// Archive-opening primitives resolved from a [`TzapExtractKeySource`]:
/// passphrase, recipient private-key path, and recipient key candidates.
type KeyComponents<'a> = (Option<&'a str>, Option<&'a Path>, Option<Vec<Vec<u8>>>);

/// Resolves a key source into the archive-opening primitives. Recipient key
/// bytes are normalized to a candidate list either way, so every downstream
/// caller goes through the same multi-key open path (design §9.4).
fn key_components(key: TzapExtractKeySource<'_>) -> KeyComponents<'_> {
    match key {
        TzapExtractKeySource::None => (None, None, None),
        TzapExtractKeySource::Password(password) => (Some(password), None, None),
        TzapExtractKeySource::RecipientKeyPath(path) => (None, Some(path), None),
        TzapExtractKeySource::RecipientKeyBytes(bytes) => (None, None, Some(vec![bytes.to_vec()])),
        TzapExtractKeySource::RecipientKeyBytesList(bytes_list) => (None, None, Some(bytes_list.to_vec())),
    }
}

/// Copies selected regular `.tzap` members to a writer.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or selected members
/// cannot be extracted.
pub fn copy_tzap_files_to_writer(
    archive: impl AsRef<Path>,
    key: TzapExtractKeySource<'_>,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let (password, recipient_private_key, key_bytes_list) = key_components(key);
    let opened = open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, key_bytes_list.as_deref())?;
    copy_opened_tzap_files_to_writer(&opened, selector, writer)
}

/// Copies one exact regular `.tzap` member to a writer with a key source,
/// without first enumerating every index entry.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or the selected
/// member cannot be extracted.
pub fn copy_tzap_file_to_writer(
    archive: impl AsRef<Path>,
    key: TzapExtractKeySource<'_>,
    entry_path: &str,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let (password, recipient_private_key, key_bytes_list) = key_components(key);
    let opened = open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, key_bytes_list.as_deref())?;
    let Some(entry) = opened.lookup_index_entry(entry_path)? else {
        return Ok(skipped_missing_entry_report(entry_path));
    };
    let mut writer_ref = &mut *writer;
    let Some(_diagnostics) = opened.extract_file_to_writer(entry_path, &mut writer_ref).map_err(|source| tzap_extract_error(entry_path, source))? else {
        return Ok(skipped_missing_entry_report(entry_path));
    };
    Ok(TzapExtractReport { written_entries: 1, skipped_entries: 0, written_bytes: entry.file_data_size, warnings: Vec::new() })
}

fn skipped_missing_entry_report(entry_path: &str) -> TzapExtractReport {
    TzapExtractReport { written_entries: 0, skipped_entries: 1, written_bytes: 0, warnings: vec![format!("skipped missing entry {entry_path}")] }
}

fn copy_opened_tzap_files_to_writer(
    opened: &OpenedArchive,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let entries = opened.list_index_entries()?;
    let mut report = TzapExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };
    for entry in entries {
        if !selector(&entry.path) {
            report.skipped_entries += 1;
            continue;
        }
        let mut writer_ref = &mut *writer;
        let Some(_diagnostics) = opened.extract_file_to_writer(&entry.path, &mut writer_ref).map_err(|source| tzap_extract_error(&entry.path, source))? else {
            report.skipped_entries += 1;
            report.warnings.push(format!("skipped missing entry {}", entry.path));
            continue;
        };
        report.written_entries += 1;
        report.written_bytes += entry.file_data_size;
    }
    Ok(report)
}

fn tzap_extract_error(path: &str, source: ExtractError) -> TzapError {
    match source {
        ExtractError::Format(source) => TzapError::Format(source),
        ExtractError::Output(source) => TzapError::Io { path: PathBuf::from(path), source },
    }
}

/// Extracts one regular `.tzap` file member to an exact destination path with
/// explicit metadata restoration options.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the requested
/// restoration policy cannot be satisfied, or the destination cannot be committed.
pub(crate) fn extract_tzap_file_to_destination(
    archive: impl AsRef<Path>,
    key: TzapExtractKeySource<'_>,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
    restore_options: TzapRestoreOptions,
) -> Result<Option<TzapFileExtractReport>, TzapError> {
    let (password, recipient_private_key, key_bytes_list) = key_components(key);
    let opened = open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, key_bytes_list.as_deref())?;
    extract_tzap_file_from_opened_archive(&opened, entry_path, destination_path, replace_existing, restore_options)
}

fn extract_tzap_file_from_opened_archive(
    opened: &OpenedArchive,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
    restore_options: TzapRestoreOptions,
) -> Result<Option<TzapFileExtractReport>, TzapError> {
    let Some(index_entry) = opened.lookup_index_entry(entry_path)? else {
        return Ok(None);
    };
    let temp_root = TemporaryTzapExtractionRoot::new(destination_path)?;
    let Some(diagnostics) = opened.extract_file_to(entry_path, temp_root.path(), restore_options.core_options(false))? else {
        return Ok(None);
    };
    let extracted_path = archive_member_path_under_root(temp_root.path(), entry_path)?;
    commit_extracted_file(&extracted_path, destination_path, replace_existing)?;
    Ok(Some(TzapFileExtractReport { written_bytes: index_entry.file_data_size, metadata_diagnostics: metadata_diagnostic_labels(&diagnostics) }))
}

struct ExtractTzapOptions<'a> {
    policy: ExtractionPolicy,
    password: Option<&'a str>,
    recipient_private_key: Option<&'a Path>,
    recipient_private_key_bytes_list: Option<Vec<Vec<u8>>>,
    restore_options: TzapRestoreOptions,
}

struct TzapExtractionState<'archive, 'resolver> {
    opened: &'archive OpenedArchive,
    planner: ExtractionSafetyPlanner<'resolver>,
    restore_options: TzapRestoreOptions,
    report: TzapExtractReport,
    deferred_directory_metadata: Vec<(PathBuf, TzapPortableEntryMetadata)>,
    deferred_hardlinks: Vec<DeferredTzapHardlink>,
}

struct TzapEntryWriteDecision {
    destination_path: PathBuf,
    replace_existing: bool,
    link_target_path: Option<PathBuf>,
}

impl<'archive, 'resolver> TzapExtractionState<'archive, 'resolver> {
    fn new(opened: &'archive OpenedArchive, planner: ExtractionSafetyPlanner<'resolver>, restore_options: TzapRestoreOptions) -> Self {
        Self {
            opened,
            planner,
            restore_options,
            report: TzapExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() },
            deferred_directory_metadata: Vec::new(),
            deferred_hardlinks: Vec::new(),
        }
    }

    fn extract_entries(&mut self, entries: &[ArchiveEntry], mut context: Option<&mut JobContext<'_>>) -> Result<(), TzapError> {
        for entry in entries {
            self.extract_entry(entry, context.as_deref_mut())?;
        }
        Ok(())
    }

    fn extract_entry(&mut self, entry: &ArchiveEntry, mut context: Option<&mut JobContext<'_>>) -> Result<(), TzapError> {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        append_metadata_diagnostics(&entry.path, &entry.diagnostics, &mut self.report.warnings, context.as_deref_mut());
        let preloaded_member =
            if matches!(entry.kind, TarEntryKind::Symlink | TarEntryKind::Hardlink) { self.opened.extract_member(&entry.path)? } else { None };
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: extraction_kind_from_tzap_entry(entry, preloaded_member.as_ref()),
            uncompressed_size: Some(entry.file_data_size),
            compressed_size: None,
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&entry.path, Some(entry.file_data_size));
        }
        match self.planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write { destination_path, replace_existing, link_target_path, .. } => self.write_entry(
                entry,
                &safety_entry,
                preloaded_member,
                &TzapEntryWriteDecision { destination_path, replace_existing, link_target_path },
                context,
            ),
            ExtractionDecision::Skip { reason, .. } => {
                self.record_skip(&entry.path, format!("skipped {}: {reason}", entry.path), context);
                Ok(())
            }
        }
    }

    fn write_entry(
        &mut self,
        entry: &ArchiveEntry,
        safety_entry: &ExtractionEntry,
        preloaded_member: Option<ExtractedArchiveMember>,
        decision: &TzapEntryWriteDecision,
        mut context: Option<&mut JobContext<'_>>,
    ) -> Result<(), TzapError> {
        if matches!(safety_entry.kind, ExtractionEntryKind::File) {
            let Some(processed) = stream_regular_member_to_destination(
                self.opened,
                &entry.path,
                entry.file_data_size,
                self.restore_options,
                &decision.destination_path,
                decision.replace_existing,
                context.as_deref_mut(),
            )?
            else {
                self.record_missing_entry(&entry.path, context);
                return Ok(());
            };
            self.report.written_entries += 1;
            self.report.written_bytes += processed.written_bytes;
            for diagnostic in processed.metadata_diagnostics {
                let warning = format!("metadata {}: {diagnostic}", entry.path);
                self.report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                }
            }
            if let Some(context) = context {
                context.entry_finished(&entry.path, processed.written_bytes);
            }
            return Ok(());
        }

        let member = match preloaded_member {
            Some(member) => Some(member),
            None => self.opened.extract_member(&entry.path)?,
        };
        let Some(member) = member else {
            self.record_missing_entry(&entry.path, context);
            return Ok(());
        };
        if member.kind == TarEntryKind::Hardlink {
            let source_path = decision.link_target_path.clone().ok_or_else(|| TzapError::Io {
                path: decision.destination_path.clone(),
                source: io::Error::new(io::ErrorKind::InvalidData, "hardlink target was not resolved by extraction safety planning"),
            })?;
            self.deferred_hardlinks.push(DeferredTzapHardlink {
                source_path,
                destination_path: decision.destination_path.clone(),
                replace_existing: decision.replace_existing,
            });
            if let Some(context) = context {
                context.entry_finished(&entry.path, 0);
            }
            return Ok(());
        }
        let processed = materialize_non_regular_member(
            &member,
            &decision.destination_path,
            decision.replace_existing,
            decision.link_target_path.as_deref(),
            &mut self.report,
        )?;
        if member.kind == TarEntryKind::Directory {
            self.deferred_directory_metadata.push((decision.destination_path.clone(), TzapPortableEntryMetadata::from_archive_entry(entry)));
        } else if member.kind == TarEntryKind::Symlink && should_restore_tzap_metadata(self.restore_options) {
            apply_tzap_symlink_mtime(&decision.destination_path, entry.mtime)?;
        }
        if let Some(context) = context {
            context.bytes_processed(Some(&entry.path), processed);
            context.entry_finished(&entry.path, processed);
        }
        Ok(())
    }

    fn record_missing_entry(&mut self, entry_path: &str, context: Option<&mut JobContext<'_>>) {
        self.record_skip(entry_path, format!("skipped missing entry {entry_path}"), context);
    }

    fn record_skip(&mut self, entry_path: &str, warning: String, context: Option<&mut JobContext<'_>>) {
        self.report.skipped_entries += 1;
        self.report.warnings.push(warning.clone());
        if let Some(context) = context {
            context.warning(warning);
            context.entry_finished(entry_path, 0);
        }
    }

    fn finish(mut self) -> Result<TzapExtractReport, TzapError> {
        materialize_deferred_tzap_hardlinks(&self.deferred_hardlinks, &mut self.report)?;
        apply_deferred_tzap_directory_metadata(&self.deferred_directory_metadata, self.restore_options)?;
        Ok(self.report)
    }
}

fn extract_tzap_inner(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: ExtractTzapOptions<'_>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<TzapExtractReport, TzapError> {
    let ExtractTzapOptions { policy, password, recipient_private_key, recipient_private_key_bytes_list, restore_options } = options;
    let destination = destination.as_ref();
    let destination_root = crate::safety::prepare_destination_root(destination).map_err(|source| TzapError::Io { path: destination.to_path_buf(), source })?;
    let opened = open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, recipient_private_key_bytes_list.as_deref())?;
    let entries = opened.list_files()?;
    if overwrite_resolver.is_none() && policy.strip_components == 0 && matches!(policy.overwrite, OverwritePolicy::Refuse | OverwritePolicy::Replace) {
        return extract_opened_tzap_with_core_restore(&opened, &destination_root, policy, &entries, restore_options, context);
    }
    opened.plan_metadata_restore(restore_options.core_options(false))?;
    let planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(&destination_root, policy, resolver),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut state = TzapExtractionState::new(&opened, planner, restore_options);
    state.extract_entries(&entries, context)?;
    state.finish()
}

fn extract_opened_tzap_with_core_restore(
    opened: &OpenedArchive,
    destination_root: &Path,
    policy: ExtractionPolicy,
    entries: &[ArchiveEntry],
    restore_options: TzapRestoreOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TzapExtractReport, TzapError> {
    let replace_existing = policy.overwrite == OverwritePolicy::Replace;
    let mut planner = ExtractionSafetyPlanner::new(destination_root, policy);
    let mut selected = Vec::new();
    let mut report = TzapExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

    for entry in entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
            context.entry_started(&entry.path, Some(entry.file_data_size));
        }
        let preloaded_member = if matches!(entry.kind, TarEntryKind::Symlink | TarEntryKind::Hardlink) { opened.extract_member(&entry.path)? } else { None };
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: extraction_kind_from_tzap_entry(entry, preloaded_member.as_ref()),
            uncompressed_size: Some(entry.file_data_size),
            compressed_size: None,
        };
        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write { .. } => selected.push(entry.path.clone()),
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                let warning = format!("skipped {}: {reason}", entry.path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.path, 0);
                }
            }
        }
    }

    if selected.is_empty() {
        return Ok(report);
    }

    let restored = opened.extract_selected_files_to(&selected, destination_root, restore_options.core_options(replace_existing), EXTRACT_SELECTED_JOBS)?;
    let sizes = entries.iter().map(|entry| (entry.path.as_str(), entry.file_data_size)).collect::<BTreeMap<_, _>>();
    for (path, diagnostics) in restored {
        let written_bytes = sizes.get(path.as_str()).copied().unwrap_or(0);
        report.written_entries = report.written_entries.saturating_add(1);
        report.written_bytes = report.written_bytes.saturating_add(written_bytes);
        append_metadata_diagnostics(&path, &diagnostics, &mut report.warnings, context.as_deref_mut());
        if let Some(context) = context.as_deref_mut() {
            context.bytes_processed(Some(&path), written_bytes);
            context.entry_finished(&path, written_bytes);
        }
    }

    Ok(report)
}

#[derive(Debug, Clone, Copy)]
struct TzapPortableEntryMetadata {
    mode: u32,
    mtime: ArchiveTimestamp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DeferredTzapHardlink {
    source_path: PathBuf,
    destination_path: PathBuf,
    replace_existing: bool,
}

fn materialize_deferred_tzap_hardlinks(hardlinks: &[DeferredTzapHardlink], report: &mut TzapExtractReport) -> Result<(), TzapError> {
    let paths = hardlinks.iter().map(|hardlink| (hardlink.source_path.clone(), hardlink.destination_path.clone())).collect::<Vec<_>>();
    let order = crate::safety::deferred_link_dependency_order(&paths)
        .map_err(|source| TzapError::Io { path: hardlinks.first().map_or_else(PathBuf::new, |link| link.destination_path.clone()), source })?;
    for index in order {
        let hardlink = &hardlinks[index];
        if hardlink.replace_existing {
            crate::safety::remove_destination_for_replace(&hardlink.destination_path)
                .map_err(|source| TzapError::Io { path: hardlink.destination_path.clone(), source })?;
        }
        write_hardlink(&hardlink.source_path, &hardlink.destination_path)?;
        report.written_entries += 1;
    }
    Ok(())
}

impl TzapPortableEntryMetadata {
    fn from_archive_entry(entry: &ArchiveEntry) -> Self {
        Self { mode: entry.mode, mtime: entry.mtime }
    }
}

#[derive(Debug)]
struct StreamedTzapMember {
    written_bytes: u64,
    metadata_diagnostics: Vec<String>,
}

fn stream_regular_member_to_destination(
    opened: &OpenedArchive,
    entry_path: &str,
    entry_size: u64,
    restore_options: TzapRestoreOptions,
    destination_path: &Path,
    replace_existing: bool,
    context: Option<&mut JobContext<'_>>,
) -> Result<Option<StreamedTzapMember>, TzapError> {
    let mut output = AtomicOutputFile::create(destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    let output_file = output.file_mut().map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    let extracted = match context {
        Some(context) => {
            let mut progress = |archive_path: &str, bytes: u64| {
                context.bytes_processed(Some(archive_path), bytes);
            };
            opened.extract_file_to_writer_with_progress(entry_path, output_file, &mut progress)
        }
        None => opened.extract_file_to_writer(entry_path, output_file),
    }
    .map_err(|source| tzap_extract_error(entry_path, source))?;

    let Some(_diagnostics) = extracted else {
        return Ok(None);
    };

    let metadata_diagnostics = opened
        .restore_file_metadata_to_open_file(entry_path, output_file, restore_options.core_options(false))?
        .ok_or(TzapError::Format(FormatError::InvalidArchive("streamed archive entry disappeared before metadata restore")))?;

    output.commit_with_replace(replace_existing).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    Ok(Some(StreamedTzapMember { written_bytes: entry_size, metadata_diagnostics: metadata_diagnostic_labels(&metadata_diagnostics) }))
}

fn apply_deferred_tzap_directory_metadata(directories: &[(PathBuf, TzapPortableEntryMetadata)], restore_options: TzapRestoreOptions) -> Result<(), TzapError> {
    if !should_restore_tzap_metadata(restore_options) {
        return Ok(());
    }

    for (path, metadata) in directories.iter().rev() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = if restore_options.policy == TzapRestorePolicy::System { metadata.mode & 0o7777 } else { metadata.mode & 0o1777 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| TzapError::Io { path: path.clone(), source })?;
        }

        #[cfg(not(unix))]
        {
            let mut permissions = fs::metadata(path).map_err(|source| TzapError::Io { path: path.clone(), source })?.permissions();
            permissions.set_readonly(metadata.mode & 0o222 == 0);
            fs::set_permissions(path, permissions).map_err(|source| TzapError::Io { path: path.clone(), source })?;
        }

        let mtime = archive_timestamp_file_time(metadata.mtime)
            .map_err(|message| TzapError::Io { path: path.clone(), source: io::Error::new(io::ErrorKind::InvalidData, message) })?;
        filetime::set_file_mtime(path, mtime).map_err(|source| TzapError::Io { path: path.clone(), source })?;
    }
    Ok(())
}

fn should_restore_tzap_metadata(restore_options: TzapRestoreOptions) -> bool {
    restore_options.policy != TzapRestorePolicy::Content
}

fn archive_timestamp_file_time(timestamp: ArchiveTimestamp) -> Result<filetime::FileTime, &'static str> {
    if timestamp.nanoseconds >= 1_000_000_000 {
        return Err("timestamp nanoseconds must be less than one billion");
    }
    if timestamp.seconds < 0 && timestamp.nanoseconds != 0 {
        let seconds = timestamp.seconds.checked_sub(1).ok_or("timestamp is outside the filesystem time range")?;
        return Ok(filetime::FileTime::from_unix_time(seconds, 1_000_000_000 - timestamp.nanoseconds));
    }
    Ok(filetime::FileTime::from_unix_time(timestamp.seconds, timestamp.nanoseconds))
}

fn apply_tzap_symlink_mtime(path: &Path, timestamp: ArchiveTimestamp) -> Result<(), TzapError> {
    let file_time = archive_timestamp_file_time(timestamp)
        .map_err(|message| TzapError::Io { path: path.to_path_buf(), source: io::Error::new(io::ErrorKind::InvalidData, message) })?;
    filetime::set_symlink_file_times(path, file_time, file_time).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })
}

fn append_metadata_diagnostics(entry_path: &str, diagnostics: &[MetadataDiagnostic], warnings: &mut Vec<String>, mut context: Option<&mut JobContext<'_>>) {
    for diagnostic in metadata_diagnostic_labels(diagnostics) {
        let warning = format!("metadata {entry_path}: {diagnostic}");
        warnings.push(warning.clone());
        if let Some(context) = context.as_deref_mut() {
            context.warning(warning);
        }
    }
}

fn materialize_non_regular_member(
    member: &ExtractedArchiveMember,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut TzapExtractReport,
) -> Result<u64, TzapError> {
    if replace_existing && member.kind != TarEntryKind::Regular {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    }

    match member.kind {
        TarEntryKind::Regular => {
            return Err(TzapError::Format(FormatError::InvalidArchive("regular TZAP member reached non-regular materializer")));
        }
        TarEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
            report.written_entries += 1;
            return Ok(0);
        }
        TarEntryKind::Symlink => {
            if crate::safety::should_skip_symlink_materialization(&ExtractionEntryKind::Symlink {
                target: member.link_target.as_deref().map(PathBuf::from).unwrap_or_default(),
            }) {
                report.skipped_entries += 1;
                report.warnings.push(crate::safety::unsupported_symlink_warning(&member.path));
            } else if let Some(target) = &member.link_target {
                write_symlink(Path::new(target), destination_path)?;
                report.written_entries += 1;
            } else {
                report.skipped_entries += 1;
                report.warnings.push(format!("skipped symlink {}: missing target", member.path));
            }
        }
        TarEntryKind::Hardlink => {
            let source_path = link_target_path.ok_or_else(|| TzapError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidData, "hardlink target was not resolved by extraction safety planning"),
            })?;
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
            return Ok(0);
        }
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
            report.skipped_entries += 1;
            report.warnings.push(format!("skipped special entry {}: portable extraction does not materialize device nodes or FIFOs", member.path));
        }
    }
    Ok(0)
}

fn extraction_kind_from_tzap_entry(entry: &ArchiveEntry, member: Option<&ExtractedArchiveMember>) -> ExtractionEntryKind {
    match entry.kind {
        TarEntryKind::Regular => ExtractionEntryKind::File,
        TarEntryKind::Directory => ExtractionEntryKind::Directory,
        TarEntryKind::Symlink => {
            ExtractionEntryKind::Symlink { target: member.and_then(|member| member.link_target.as_deref()).map(PathBuf::from).unwrap_or_default() }
        }
        TarEntryKind::Hardlink => {
            ExtractionEntryKind::Hardlink { target: member.and_then(|member| member.link_target.as_deref()).map(PathBuf::from).unwrap_or_default() }
        }
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => ExtractionEntryKind::Special,
    }
}

pub(crate) fn commit_extracted_file(source_path: &Path, destination_path: &Path, replace_existing: bool) -> Result<(), TzapError> {
    if let Some(parent) = destination_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| TzapError::Io { path: parent.to_path_buf(), source })?;
    }

    if replace_existing {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
        fs::rename(source_path, destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    } else {
        fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })?;
    }
    Ok(())
}

pub(crate) fn archive_member_path_under_root(root: &Path, entry_path: &str) -> Result<PathBuf, TzapError> {
    let mut path = root.to_path_buf();
    for component in entry_path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(TzapError::Format(FormatError::UnsafeArchivePath));
        }
        path.push(component);
    }
    Ok(path)
}

pub(crate) struct TemporaryTzapExtractionRoot {
    path: PathBuf,
}

impl TemporaryTzapExtractionRoot {
    pub(crate) fn new(destination_path: &Path) -> Result<Self, TzapError> {
        let parent = destination_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| TzapError::Io { path: parent.to_path_buf(), source })?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        let destination_name = destination_path.file_name().and_then(|name| name.to_str()).unwrap_or("entry");

        for attempt in 0..TZAP_TEMP_EXTRACT_ATTEMPTS {
            let path = parent.join(format!("{TZAP_TEMP_EXTRACT_PREFIX}-{destination_name}-{}-{now}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(TzapError::Io { path, source });
                }
            }
        }

        Err(io_error(parent, io::ErrorKind::AlreadyExists, "could not allocate temporary TZAP extraction root"))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryTzapExtractionRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{TzapRestoreOptions, TzapRestorePolicy, archive_timestamp_file_time, process_is_elevated, should_restore_tzap_metadata};
    use tzap_core::ArchiveTimestamp;

    #[test]
    fn content_restore_policy_excludes_non_payload_metadata() {
        assert!(!should_restore_tzap_metadata(TzapRestoreOptions { policy: TzapRestorePolicy::Content, allow_degraded: false, ..Default::default() }));
        assert!(should_restore_tzap_metadata(TzapRestoreOptions::default()));
    }

    #[test]
    fn system_restore_authorization_matches_process_elevation() {
        let options = TzapRestoreOptions { policy: TzapRestorePolicy::System, ..Default::default() }.core_options(false);
        assert_eq!(options.system_authorized, process_is_elevated());
    }

    #[test]
    fn converts_negative_archive_timestamp_to_filesystem_time() {
        let time = archive_timestamp_file_time(ArchiveTimestamp::new(-1, 500_000_000)).unwrap();

        assert_eq!(time, filetime::FileTime::from_unix_time(-2, 500_000_000));
    }
}
