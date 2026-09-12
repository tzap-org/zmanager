use crate::engine::types::ArchiveError;
use crate::engine::{TzapRestoreOptions, TzapRestorePolicy};
use crate::safety::{ExtractionPolicy, ExtractionSafetyError, OverwritePolicy};
use crate::tzap::is_tzap_archive_path;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const PREVIEW_TEMP_PREFIX: &str = "zmanager-preview";

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
    /// RAR file-copy redirection.
    FileCopy,
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
    /// Portable Unix mode bits when the archive exposes them.
    pub mode: Option<u32>,
    /// Authenticated metadata diagnostics reported by the backend.
    pub metadata_diagnostics: Vec<String>,
    /// Whether entry data or metadata is encrypted.
    pub encrypted: Option<bool>,
    /// Compression algorithm or method name.
    pub method: Option<String>,
    /// Pre-computed checksum (e.g. CRC-32).
    pub crc: Option<u32>,
    /// Zip comment or entry-level comment.
    pub comment: Option<String>,
    /// Creation time formatted for display.
    pub created: Option<String>,
    /// Access time formatted for display.
    pub accessed: Option<String>,
    /// Solid archive member indicator (7z).
    pub solid: Option<bool>,
    /// Target path for symlinks or hardlinks.
    pub link_target: Option<String>,
    /// OS-specific or format-specific attribute flags.
    pub attributes: Option<String>,
    /// User identifier.
    pub uid: Option<u32>,
    /// Group identifier.
    pub gid: Option<u32>,
    /// Owner username.
    pub owner: Option<String>,
    /// Group name.
    pub group: Option<String>,
}

/// Archive browser listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BrowserListing {
    /// Entries in archive order.
    pub entries: Vec<BrowserEntry>,
}

/// Options for browser-driven listing.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct BrowserListOptions<'a> {
    /// Optional password for archive formats that encrypt headers or metadata.
    pub password: Option<&'a str>,
    /// Optional private key for recipient-encrypted TZAP metadata.
    pub recipient_key: Option<&'a Path>,
    /// Optional in-memory private key candidates for recipient-encrypted TZAP
    /// metadata (see [`crate::engine::OpenOptions::recipient_key_bytes`]).
    pub recipient_key_bytes: Option<&'a [Vec<u8>]>,
    /// Optional app-controlled root for decoder intermediates.
    pub temp_root: Option<&'a Path>,
}

/// Report for selected-entry extraction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntryExtractReport {
    /// Destination path written for the selected entry.
    pub destination_path: PathBuf,
    /// Number of regular file bytes written.
    pub written_bytes: u64,
    /// Metadata restoration diagnostics for this entry.
    pub metadata_diagnostics: Vec<String>,
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

/// Report for copying the regular files selected by CLI-style include and
/// exclude patterns through one retained engine handle.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SelectedCopyReport {
    /// Number of regular-file entries copied to the writer.
    pub copied_entries: usize,
    /// Number of listed entries skipped by the selection or entry kind.
    pub skipped_entries: usize,
    /// Decoded bytes written to the writer.
    pub written_bytes: u64,
    /// Non-fatal diagnostics returned by the adapters.
    pub warnings: Vec<String>,
}

/// Options for browser-driven extraction.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BrowserExtractOptions<'a> {
    /// Optional password for encrypted archive entry data.
    pub password: Option<&'a str>,
    /// Existing destination behavior.
    pub overwrite: OverwritePolicy,
    /// Leading archive path components to drop before writing.
    pub strip_components: usize,
    /// TZAP metadata restoration level. Other formats ignore this option.
    pub tzap_restore_policy: TzapRestorePolicy,
    /// Permit unsupported requested TZAP metadata to be skipped with diagnostics.
    pub tzap_allow_degraded: bool,
    /// Permit absolute symlinks in extracted content.
    pub tzap_allow_absolute_symlinks: bool,
    /// Whether to ignore symbolic links during extraction.
    pub ignore_symlinks: bool,
    /// Optional extraction limits overriding the default safety caps.
    pub limits: Option<crate::safety::ExtractionLimits>,
}

impl Default for BrowserExtractOptions<'_> {
    fn default() -> Self {
        Self {
            password: None,
            overwrite: OverwritePolicy::Refuse,
            strip_components: 0,
            tzap_restore_policy: TzapRestorePolicy::Portable,
            tzap_allow_degraded: false,
            tzap_allow_absolute_symlinks: false,
            ignore_symlinks: false,
            limits: None,
        }
    }
}

/// Archive browser error.
#[derive(Debug)]
pub enum ArchiveBrowserError {
    /// Enumeration was cancelled by the caller between entries.
    Cancelled,
    /// The stateful archive engine rejected a listing request.
    Engine { format: Option<crate::engine::FormatId>, source: ArchiveError },
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Selected entry was not found.
    EntryNotFound { path: String },
    /// Selected entry cannot be materialized by the browser yet.
    UnsupportedEntry { path: String, kind: BrowserEntryKind },
    /// Selected operation is not supported by the format.
    UnsupportedOperation(String),
}

impl fmt::Display for ArchiveBrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "archive enumeration cancelled"),
            Self::Engine { format: Some(crate::engine::FormatId::TZAP), source } => write!(f, "TZAP browser operation failed: {source}"),
            Self::Engine { source, .. } => write!(f, "archive engine listing failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::EntryNotFound { path } => write!(f, "archive entry not found: {path}"),
            Self::UnsupportedEntry { path, kind } => {
                write!(f, "unsupported preview/extract entry {path}: {kind:?}")
            }
            Self::UnsupportedOperation(msg) => {
                write!(f, "unsupported operation: {msg}")
            }
        }
    }
}

impl std::error::Error for ArchiveBrowserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Each variant carries a distinct error type, so the `Some(source)`
        // arms cannot merge even though their bodies are identical.
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Cancelled => None,
            Self::Engine { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::EntryNotFound { .. } => None,
            Self::UnsupportedEntry { .. } => None,
            Self::UnsupportedOperation(_) => None,
        }
    }
}

impl From<ExtractionSafetyError> for ArchiveBrowserError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries through the stateful archive engine.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read.
pub fn list_entries(path: impl AsRef<Path>) -> Result<BrowserListing, ArchiveBrowserError> {
    list_entries_with_options(path, BrowserListOptions::default())
}

/// Lists entries with browser listing options.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read.
pub fn list_entries_with_options(path: impl AsRef<Path>, options: BrowserListOptions<'_>) -> Result<BrowserListing, ArchiveBrowserError> {
    let path = path.as_ref();
    list_entries_via_engine(path, options)
}

/// Returns true if the archive format supports on-demand directory listing.
pub fn supports_on_demand_directories(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    is_tzap_archive_path(path)
}

/// Lists only the immediate children of a given directory path.
///
/// If `dir_path` is empty, lists the root directory. The engine has no
/// progressive directory API, so this helper lists the complete archive once
/// and filters client-side to the requested prefix.
pub fn list_directory_with_options(path: impl AsRef<Path>, dir_path: &str, options: BrowserListOptions<'_>) -> Result<BrowserListing, ArchiveBrowserError> {
    let path = path.as_ref();
    if !is_tzap_archive_path(path) {
        return Err(ArchiveBrowserError::UnsupportedOperation("Archive format does not support on-demand directory listing.".to_string()));
    }

    let engine = crate::engine::create_default_engine().map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let source = crate::engine::ArchiveSource::from_path_autodetect(path);
    let open_options = crate::engine::OpenOptions {
        password: options.password.map(ToOwned::to_owned),
        recipient_key: options.recipient_key.map(Path::to_path_buf),
        recipient_key_bytes: options.recipient_key_bytes.map(ToOwned::to_owned),
        temp_root: options.temp_root.map(Path::to_path_buf),
        ..Default::default()
    };
    let mut handle = engine.open(source, open_options).map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    list_directory_from_engine_handle(&mut handle, dir_path)
}

/// Lists immediate children from a retained engine handle.
fn list_directory_from_engine_handle(handle: &mut crate::engine::ArchiveHandle, dir_path: &str) -> Result<BrowserListing, ArchiveBrowserError> {
    let listing = list_entries_from_engine_handle(handle)?;
    let parent = dir_path.replace('\\', "/").trim_matches('/').to_owned();
    let prefix = if parent.is_empty() { String::new() } else { format!("{parent}/") };
    let entries = listing
        .entries
        .into_iter()
        .filter(|entry| {
            let normalized = entry.path.replace('\\', "/");
            let Some(relative) = normalized.strip_prefix(&prefix) else {
                return false;
            };
            !relative.is_empty() && !relative.contains('/')
        })
        .collect();
    Ok(BrowserListing { entries })
}

/// Visits archive entries through one engine handle.
///
/// The engine exposes no progressive iterator, so this helper lists the
/// complete archive first and then visits each entry from the retained
/// listing. Returning `false` from `visitor` cancels at the next entry
/// boundary.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read or the visitor
/// cancels enumeration.
pub fn visit_entries_with_options(
    path: impl AsRef<Path>,
    options: BrowserListOptions<'_>,
    mut visitor: impl FnMut(BrowserEntry) -> bool,
) -> Result<usize, ArchiveBrowserError> {
    let listing = list_entries_with_options(path, options)?;
    let mut visited = 0;
    for entry in listing.entries {
        if !visitor(entry) {
            return Err(ArchiveBrowserError::Cancelled);
        }
        visited += 1;
    }
    Ok(visited)
}

/// Extracts one selected entry into `destination`.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read, the entry
/// is not found, the entry is unsafe, or filesystem writes fail.
pub fn extract_entry(archive_path: impl AsRef<Path>, entry_path: &str, destination: impl AsRef<Path>) -> Result<EntryExtractReport, ArchiveBrowserError> {
    extract_entry_with_options(archive_path, entry_path, destination, BrowserExtractOptions::default())
}

/// Extracts one selected entry into `destination` with browser extraction
/// options.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when the archive cannot be read, the entry
/// is not found, the password is missing or incorrect, the entry is unsafe, or
/// filesystem writes fail.
pub fn extract_entry_with_options(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    destination: impl AsRef<Path>,
    options: BrowserExtractOptions<'_>,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| ArchiveBrowserError::Io { path: destination.to_path_buf(), source })?;
    let policy = extraction_policy(options.overwrite, options.strip_components, options.ignore_symlinks, options.limits);

    extract_entry_via_engine(
        archive_path,
        entry_path,
        &destination_root,
        &policy,
        options.password,
        None,
        TzapRestoreOptions {
            policy: options.tzap_restore_policy,
            allow_degraded: options.tzap_allow_degraded,
            allow_absolute_symlinks: options.tzap_allow_absolute_symlinks,
        },
    )
}

/// Extracts selected paths through a caller-owned retained engine handle.
///
/// Path selectors are resolved to `EntryId` values exactly once from the
/// handle's cached listing. Reusing this function for a batch keeps duplicate
/// physical entries distinct and prevents per-entry reopen/re-detect loops in
/// product job runners.
pub fn extract_selected_entries_from_engine_handle(
    handle: &mut crate::engine::ArchiveHandle,
    entry_paths: &[String],
    destination: impl AsRef<Path>,
    options: BrowserExtractOptions<'_>,
) -> Result<Vec<(String, EntryExtractReport)>, ArchiveBrowserError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| ArchiveBrowserError::Io { path: destination.to_path_buf(), source })?;
    let format = handle.detected().format;
    let listing = handle.list().map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;
    let policy = extraction_policy(options.overwrite, options.strip_components, options.ignore_symlinks, options.limits);
    if entry_paths.is_empty() {
        return Ok(Vec::new());
    }
    let norm_selectors: Vec<String> = entry_paths.iter().map(|p| crate::safety::normalize_selector(p)).collect();
    let mut matched_selector_indices = vec![false; norm_selectors.len()];
    let mut selected_entries = Vec::new();

    for entry in &listing.entries {
        let norm_entry = crate::safety::normalize_selector(&entry.path);
        let mut matched = false;
        for (i, selector) in norm_selectors.iter().enumerate() {
            if crate::safety::normalized_entry_matches_normalized_selector(&norm_entry, selector) {
                matched_selector_indices[i] = true;
                matched = true;
            }
        }
        if matched {
            selected_entries.push(entry);
        }
    }

    for (i, &matched) in matched_selector_indices.iter().enumerate() {
        if !matched {
            return Err(ArchiveBrowserError::EntryNotFound { path: entry_paths[i].clone() });
        }
    }
    if selected_entries.is_empty() {
        return Err(ArchiveBrowserError::EntryNotFound { path: entry_paths[0].clone() });
    }

    // Resolve selectors against the retained listing once, in archive order.
    // Matching each selector independently would extract duplicate physical
    // entries repeatedly when the archive contains duplicate names or the
    // caller supplies the same selector more than once.
    let mut reports = Vec::with_capacity(selected_entries.len());
    let mut planned_expanded_bytes = 0_u64;
    let mut seen_paths = std::collections::HashMap::new();

    let entry_ids: Vec<crate::engine::EntryId> = selected_entries.iter().map(|entry| entry.id).collect();
    for entry in &selected_entries {
        if options.overwrite != OverwritePolicy::Replace {
            let collision_key = crate::safety::case_collision_key(&entry.path);
            if let Some(previous) = seen_paths.insert(collision_key, entry.path.clone()) {
                return Err(ArchiveBrowserError::Safety(crate::safety::ExtractionSafetyError::NameCollision {
                    archive_path: entry.path.clone(),
                    previous_archive_path: previous,
                }));
            }
        }

        if let Some(entry_size) = entry.size {
            planned_expanded_bytes = planned_expanded_bytes.saturating_add(entry_size);
            if let Some(max_bytes) = policy.limits.max_expanded_bytes
                && planned_expanded_bytes > max_bytes
            {
                return Err(ArchiveBrowserError::Safety(crate::safety::ExtractionSafetyError::ExpandedSizeLimitExceeded {
                    archive_path: entry.path.clone(),
                    attempted_bytes: planned_expanded_bytes,
                    limit_bytes: max_bytes,
                }));
            }
        }
    }

    let mut selected_options = crate::engine::SelectedExtractOptions {
        destination: destination_root.clone(),
        policy: policy.clone(),
        tzap_restore_options: Some(TzapRestoreOptions {
            policy: options.tzap_restore_policy,
            allow_degraded: options.tzap_allow_degraded,
            allow_absolute_symlinks: options.tzap_allow_absolute_symlinks,
        }),
        ..Default::default()
    };
    let batch_report =
        handle.extract_selected_many(&entry_ids, &mut selected_options).map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;

    for entry in selected_entries {
        reports.push((
            entry.path.clone(),
            EntryExtractReport {
                destination_path: destination_root.join(&entry.path),
                written_bytes: entry.size.unwrap_or(0),
                metadata_diagnostics: batch_report.warnings.clone(),
            },
        ));
    }
    Ok(reports)
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
pub fn preview_entry(archive_path: impl AsRef<Path>, entry_path: &str) -> Result<PreviewExtractReport, ArchiveBrowserError> {
    preview_entry_with_options(archive_path, entry_path, BrowserExtractOptions::default())
}

/// Extracts one selected entry into a controlled temporary preview root with
/// browser extraction options.
///
/// The caller owns the returned `cleanup_root` and should remove it when the
/// preview is replaced or the app exits.
///
/// # Errors
///
/// Returns [`ArchiveBrowserError`] when temporary directory creation,
/// extraction, password validation, or safety validation fails.
pub fn preview_entry_with_options(
    archive_path: impl AsRef<Path>,
    entry_path: &str,
    options: BrowserExtractOptions<'_>,
) -> Result<PreviewExtractReport, ArchiveBrowserError> {
    let cleanup_root = std::env::temp_dir().join(crate::temp_names::unique_temp_name(PREVIEW_TEMP_PREFIX));
    fs::create_dir_all(&cleanup_root).map_err(|source| ArchiveBrowserError::Io { path: cleanup_root.clone(), source })?;

    // The freshly-created, app-controlled preview root cannot contain a user
    // destination. Replacing therefore keeps the normal safety planner while
    // allowing the atomic writer to rename its temporary file. Android app
    // cache filesystems can reject the hard-link commit used for a refuse
    // policy, which would otherwise make safe preview materialization fail.
    let preview_options = BrowserExtractOptions { overwrite: OverwritePolicy::Replace, ..options };
    let report = match extract_entry_with_options(archive_path, entry_path, &cleanup_root, preview_options) {
        Ok(report) => report,
        Err(error) => {
            let _ = fs::remove_dir_all(&cleanup_root);
            return Err(error);
        }
    };
    Ok(PreviewExtractReport { cleanup_root, preview_path: report.destination_path, written_bytes: report.written_bytes })
}

fn list_entries_via_engine(path: &Path, options: BrowserListOptions<'_>) -> Result<BrowserListing, ArchiveBrowserError> {
    let engine = crate::engine::create_default_engine().map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let source = crate::engine::ArchiveSource::from_path_autodetect(path);
    let open_options = crate::engine::OpenOptions {
        password: options.password.map(ToOwned::to_owned),
        recipient_key: options.recipient_key.map(Path::to_path_buf),
        recipient_key_bytes: options.recipient_key_bytes.map(ToOwned::to_owned),
        temp_root: options.temp_root.map(Path::to_path_buf),
        ..Default::default()
    };
    let mut handle = engine.open(source, open_options).map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    list_entries_from_engine_handle(&mut handle)
}

fn extract_entry_via_engine(
    archive_path: &Path,
    entry_path: &str,
    destination: &Path,
    policy: &ExtractionPolicy,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    tzap_restore_options: TzapRestoreOptions,
) -> Result<EntryExtractReport, ArchiveBrowserError> {
    let engine = crate::engine::create_default_engine().map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let source = crate::engine::ArchiveSource::from_path_autodetect(archive_path);
    let open_options =
        crate::engine::OpenOptions { password: password.map(ToOwned::to_owned), recipient_key: recipient_key.map(Path::to_path_buf), ..Default::default() };
    let mut handle = engine.open(source, open_options).map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let format = handle.detected().format;
    let listing = handle.list().map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;
    let mut matching_entries: Vec<_> =
        listing.entries.into_iter().filter(|entry| crate::safety::archive_entry_matches_selected(&entry.path, entry_path)).collect();
    if matching_entries.is_empty() {
        return Err(ArchiveBrowserError::EntryNotFound { path: entry_path.to_owned() });
    }
    // The native Apple Archive operation preserves the historical behavior of
    // extracting a selected directory and its descendants in one call.
    if format == crate::engine::FormatId::APPLE_ARCHIVE {
        matching_entries.truncate(1);
    }

    // Browser selection preserves the historical folder semantics: a selected
    // directory extracts its retained directory entry and every retained
    // descendant. Each operation still uses the session-scoped ID, so duplicate
    // names and central-directory order remain unambiguous to the engine.
    // One batched call, not one call per descendant: formats whose reader can
    // select many members from a single traversal (tar, tar.gz, tar.zst, 7z,
    // zip) implement that in `selected_extract_many`. Extracting a folder entry
    // by entry re-walks - and for a compressed stream re-decompresses - the
    // whole archive once per file, which is quadratic in the folder size.
    let entry_ids: Vec<_> = matching_entries.iter().map(|entry| entry.id).collect();
    let mut selected_options = crate::engine::SelectedExtractOptions {
        destination: destination.to_path_buf(),
        policy: policy.clone(),
        tzap_restore_options: Some(tzap_restore_options),
        ..Default::default()
    };
    let report =
        handle.extract_selected_many(&entry_ids, &mut selected_options).map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;
    let written_bytes = report.written_bytes;
    let metadata_diagnostics = report.warnings;

    let destination_path = destination.join(entry_path.replace('\\', "/").trim_matches('/'));
    Ok(EntryExtractReport { destination_path, written_bytes, metadata_diagnostics })
}

/// Copies selected regular-file entries through one retained engine handle.
///
/// Selection remains a caller-facing batch concern, while physical entries
/// are addressed by the IDs returned from the same retained listing. This
/// keeps duplicate archive paths independently addressable and prevents a
/// second backend-specific path scan from reselecting the payload.
pub fn copy_selected_entries_to_writer(
    archive_path: impl AsRef<Path>,
    include_patterns: &[String],
    exclude_patterns: &[String],
    password: Option<&str>,
    recipient_key: Option<&Path>,
    writer: &mut dyn Write,
) -> Result<SelectedCopyReport, ArchiveBrowserError> {
    let archive_path = archive_path.as_ref();
    let engine = crate::engine::create_default_engine().map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let source = crate::engine::ArchiveSource::from_path_autodetect(archive_path);
    let open_options =
        crate::engine::OpenOptions { password: password.map(ToOwned::to_owned), recipient_key: recipient_key.map(Path::to_path_buf), ..Default::default() };
    let mut handle = engine.open(source, open_options).map_err(|source| ArchiveBrowserError::Engine { format: None, source })?;
    let format = handle.detected().format;
    let listing = handle.list().map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;
    let mut report = SelectedCopyReport::default();
    let compiled_includes = crate::safety::compile_patterns(include_patterns);
    let compiled_excludes = crate::safety::compile_patterns(exclude_patterns);
    let selected_entries: Vec<_> = listing
        .entries
        .iter()
        .filter(|entry| {
            matches!(entry.kind, BrowserEntryKind::File | BrowserEntryKind::FileCopy)
                && crate::safety::compiled_pattern_matches_any(&entry.path, &compiled_includes, &compiled_excludes)
        })
        .collect();
    report.skipped_entries = listing.entries.len().saturating_sub(selected_entries.len());
    if selected_entries.len() > 1 {
        return Err(ArchiveBrowserError::UnsupportedOperation(format!(
            "writer-copy requires exactly one selected regular file; selected {}",
            selected_entries.len()
        )));
    }
    for entry in selected_entries {
        let copied = handle.copy_entry(entry.id, writer).map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;
        report.copied_entries = report.copied_entries.saturating_add(1);
        report.written_bytes = report.written_bytes.saturating_add(copied.written_bytes);
    }

    Ok(report)
}

/// Maps a retained engine handle listing into the browser-facing entry model.
pub fn list_entries_from_engine_handle(handle: &mut crate::engine::ArchiveHandle) -> Result<BrowserListing, ArchiveBrowserError> {
    let format = handle.detected().format;
    let listing = handle.list().map_err(|source| ArchiveBrowserError::Engine { format: Some(format), source })?;

    let entries = listing
        .entries
        .into_iter()
        .map(|entry| BrowserEntry {
            path: entry.path,
            kind: entry.kind,
            size: entry.size,
            compressed_size: entry.compressed_size,
            modified: entry.modified,
            mode: entry.mode,
            metadata_diagnostics: Vec::new(),
            encrypted: entry.encrypted,
            method: entry.method,
            crc: entry.crc,
            comment: entry.comment,
            created: entry.created,
            accessed: entry.accessed,
            solid: entry.solid,
            link_target: entry.link_target,
            attributes: entry.attributes,
            uid: entry.uid,
            gid: entry.gid,
            owner: entry.owner,
            group: entry.group,
        })
        .collect();

    Ok(BrowserListing { entries })
}

fn extraction_policy(
    overwrite: OverwritePolicy,
    strip_components: usize,
    ignore_symlinks: bool,
    limits: Option<crate::safety::ExtractionLimits>,
) -> ExtractionPolicy {
    ExtractionPolicy { overwrite, strip_components, ignore_symlinks, limits: limits.unwrap_or_default(), ..ExtractionPolicy::default() }
}

#[cfg(test)]
mod tests {
    use super::{ArchiveBrowserError, BrowserListOptions, extract_entry, list_entries, list_entries_with_options, preview_entry, visit_entries_with_options};
    use crate::jobs::{CancellationToken, JobContext};
    use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot, PlanOptions, plan_archive};
    use crate::safety::OverwritePolicy;
    use crate::secrets::SecretString;
    use crate::sevenz_backend::{SevenZCreateOptions, create_7z_from_path};
    use crate::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_path};
    use crate::test_support::TestDir;
    use crate::tzap::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};
    use crate::zip_backend::{ZipCreateOptions, create_zip_from_manifest};
    use bzip2::Compression;
    use bzip2::write::BzEncoder;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};
    use tar::{Builder, Header};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn create_zip_fixture(source: impl AsRef<Path>, destination: impl AsRef<Path>) {
        let manifest = plan_archive(source, &PlanOptions::default()).unwrap();
        create_zip_from_manifest(&manifest, destination, &ZipCreateOptions::default()).unwrap();
    }

    #[test]
    fn lists_and_extracts_single_zip_entry() {
        let temp = TestDir::new("browser_zip");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/b.txt", b"b");
        let archive = temp.path("archive.zip");
        create_zip_fixture(temp.path("project"), &archive);

        let listing = list_entries(&archive).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/b.txt"));

        let report = extract_entry(&archive, "project/b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(fs::read_to_string(temp.path("out/project/b.txt")).unwrap(), "b");
        assert!(!temp.path("out/project/a.txt").exists());
    }

    #[test]
    fn progressive_zip_visit_matches_the_existing_listing() {
        let temp = TestDir::new("browser_zip_progressive_equivalence");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/b.txt", b"b");
        let archive = temp.path("archive.zip");
        create_zip_fixture(temp.path("project"), &archive);

        let expected = list_entries(&archive).unwrap();
        let mut visited = Vec::new();
        let count = visit_entries_with_options(&archive, BrowserListOptions::default(), |entry| {
            visited.push(entry);
            true
        })
        .unwrap();

        assert_eq!(count, expected.entries.len());
        assert_eq!(visited, expected.entries);
    }

    #[test]
    fn progressive_zip_visit_observes_cancellation_at_an_entry_boundary() {
        let temp = TestDir::new("browser_zip_progressive_cancel");
        temp.write_file("project/a.txt", b"a");
        temp.write_file("project/b.txt", b"b");
        let archive = temp.path("archive.zip");
        create_zip_fixture(temp.path("project"), &archive);
        let mut callbacks = 0;

        let error = visit_entries_with_options(&archive, BrowserListOptions::default(), |_| {
            callbacks += 1;
            false
        })
        .unwrap_err();

        assert!(matches!(error, ArchiveBrowserError::Cancelled));
        assert_eq!(callbacks, 1);
    }

    #[test]
    fn lists_tzap_entry_with_portable_metadata() {
        let temp = TestDir::new("browser_tzap_metadata");
        let payload = temp.path("payload.txt");
        fs::write(&payload, b"hello").unwrap();
        let archive = temp.path("archive.tzap");

        let manifest = ArchiveManifest {
            root: temp.root().to_path_buf(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: payload,
                file_type: ManifestFileType::File,
                size: 5,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
                symlink_target: None,
            }],
            total_bytes: 5,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            volume_count: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
            emit_bootstrap_sidecar: false,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

        let listing = list_entries(&archive).unwrap();
        let payload_entry = listing.entries.iter().find(|entry| entry.path == "payload.txt").expect("payload entry should be listed").clone();

        assert_eq!(payload_entry.path, "payload.txt");
        assert_eq!(payload_entry.kind, super::BrowserEntryKind::File);
        assert_eq!(payload_entry.size, Some(5));
        assert_eq!(payload_entry.modified, Some("1700000000".to_owned()));
        assert_eq!(payload_entry.mode, Some(0o644));
        assert!(payload_entry.metadata_diagnostics.is_empty());
        assert_eq!(listing.entries.len(), 1);
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
            &TarZstdCreateOptions { level: 1, threads: Some(1), preserve_metadata: true, replace_existing: false },
        )
        .unwrap();

        let listing = list_entries(&archive).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/b.txt"));

        let report = extract_entry(&archive, "project/b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(fs::read_to_string(temp.path("out/project/b.txt")).unwrap(), "b");
        assert!(!temp.path("out/project/a.txt").exists());
    }

    #[test]
    fn lists_encrypted_7z_headers_with_password() {
        let temp = TestDir::new("browser_7z_encrypted_headers");
        temp.write_file("project/a.txt", b"a");
        let archive = temp.path("archive.7z");
        create_7z_from_path(
            temp.path("project"),
            &archive,
            &SevenZCreateOptions { password: Some(SecretString::from("correct horse")), encrypt_file_names: true, ..SevenZCreateOptions::default() },
        )
        .unwrap();

        let error = list_entries(&archive).unwrap_err();
        assert!(error.to_string().contains("password required"));

        let listing = list_entries_with_options(
            &archive,
            BrowserListOptions { password: Some("correct horse"), recipient_key: None, recipient_key_bytes: None, temp_root: None },
        )
        .unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/a.txt"));
    }

    #[test]
    fn passworded_multipart_rar_listing_uses_the_rar_backend() {
        let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/rar5-passworded-multipart.part1.rar");

        let missing_password = list_entries(&archive).unwrap_err().to_string();
        assert!(missing_password.contains("password"), "{missing_password}");

        let listing = list_entries_with_options(
            &archive,
            BrowserListOptions { password: Some("zmanager-rar-fixture-password"), recipient_key: None, recipient_key_bytes: None, temp_root: None },
        )
        .unwrap();
        assert_eq!(listing.entries.iter().filter(|entry| entry.path.replace('\\', "/") == "rar-fixture/data/stream.bin").count(), 1);
        assert!(listing.entries.iter().any(|entry| entry.path.replace('\\', "/") == "rar-fixture/docs/readme.txt"));
    }

    #[test]
    fn split_tzap_listing_uses_tzap_route() {
        let temp = TestDir::new("browser_split_tzap_route");
        let archive = temp.path("archive.vol000.tzap");
        fs::write(&archive, b"not a real tzap volume").unwrap();

        let error = list_entries(&archive).unwrap_err().to_string();

        assert!(error.contains("TZAP browser operation failed"), "{error}");
    }

    #[test]
    fn lists_and_extracts_single_native_tar_entry() {
        let temp = TestDir::new("browser_native_tar");
        let archive = temp.path("archive.tar");
        write_tar(&archive, &[("a.txt", b"a".as_slice()), ("b.txt", b"b".as_slice())]);

        let listing = list_entries(&archive).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "b.txt"));
        assert!(
            listing.entries.iter().all(|entry| entry.compressed_size.is_none()),
            "per-entry packed size must remain unknown when the backend does not report it"
        );

        let report = extract_entry(&archive, "b.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 1);
        assert_eq!(fs::read_to_string(temp.path("out/b.txt")).unwrap(), "b");
        assert!(!temp.path("out/a.txt").exists());
    }

    #[test]
    fn native_tar_listing_exposes_tar_link_targets() {
        let temp = TestDir::new("browser_native_tar_link");
        let archive = temp.path("archive.tar");
        let file = File::create(&archive).unwrap();
        let mut builder = Builder::new(file);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_link_name("target.txt").unwrap();
        header.set_cksum();
        builder.append_data(&mut header, "link.txt", io::empty()).unwrap();
        builder.finish().unwrap();

        let listing = list_entries(&archive).unwrap();
        let link = listing.entries.iter().find(|entry| entry.path == "link.txt").unwrap();
        assert_eq!(link.link_target.as_deref(), Some("target.txt"));
    }

    #[test]
    fn lists_and_extracts_raw_bzip2_stream() {
        let temp = TestDir::new("browser_raw_bzip2");
        let archive = temp.path("payload.txt.bz2");
        write_bz2(&archive, b"raw payload");

        let listing = list_entries(&archive).unwrap();

        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        assert_eq!(listing.entries[0].kind, super::BrowserEntryKind::File);
        assert!(listing.entries[0].compressed_size.is_some());

        let report = extract_entry(&archive, "payload.txt", temp.path("out")).unwrap();
        assert_eq!(report.written_bytes, 11);
        assert_eq!(fs::read_to_string(temp.path("out/payload.txt")).unwrap(), "raw payload");
    }

    #[test]
    fn preview_entry_uses_temporary_cleanup_root() {
        let temp = TestDir::new("browser_preview");
        temp.write_file("project/file.txt", b"preview");
        let archive = temp.path("archive.zip");
        create_zip_fixture(temp.path("project"), &archive);

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

    #[test]
    fn selected_entry_extraction_deduplicates_path_selectors_but_keeps_physical_duplicates() {
        let temp = TestDir::new("browser_duplicate_selection");
        let archive = temp.path("archive.zip");
        write_zip(&archive, &[("duplicate/./file.txt", b"first".as_slice()), ("duplicate/file.txt", b"second".as_slice())]);

        let engine = crate::engine::create_default_engine().unwrap();
        let mut handle = engine.open(crate::engine::ArchiveSource::from_path_autodetect(&archive), crate::engine::OpenOptions::default()).unwrap();
        let reports = super::extract_selected_entries_from_engine_handle(
            &mut handle,
            &["duplicate/file.txt".to_owned(), "duplicate/file.txt".to_owned()],
            temp.path("out"),
            super::BrowserExtractOptions { overwrite: OverwritePolicy::Replace, ..Default::default() },
        )
        .unwrap();

        assert_eq!(reports.len(), 2, "each physical duplicate should be extracted once");
        assert_eq!(fs::read_to_string(temp.path("out/duplicate/file.txt")).unwrap(), "second");
    }

    #[test]
    fn zip_listing_populates_mode_encrypted_method_crc_and_comment() {
        let temp = TestDir::new("browser_zip_metadata");
        let archive = temp.path("archive.zip");
        write_zip(&archive, &[("hello.txt", b"hello world".as_slice())]);

        let listing = list_entries(&archive).unwrap();
        assert_eq!(listing.entries.len(), 1);
        let entry = &listing.entries[0];
        assert_eq!(entry.path, "hello.txt");
        assert_eq!(entry.encrypted, Some(false));
        assert_eq!(entry.method.as_deref(), Some("Stored"));
        assert!(entry.crc.is_some());
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        for (name, contents) in entries {
            writer.start_file(*name, SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
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

    fn write_bz2(path: &Path, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = BzEncoder::new(file, Compression::best());
        encoder.write_all(contents).unwrap();
        encoder.finish().unwrap();
    }
    #[test]
    fn list_tzap_directory_pages_virtual_subdirectories() {
        let temp = TestDir::new("list-tzap-directory");
        let payload = temp.path("payload.txt");
        fs::write(&payload, b"hello").unwrap();
        let archive = temp.path("test.tzap");

        let manifest = ArchiveManifest {
            root: temp.root().to_path_buf(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: payload,
                file_type: ManifestFileType::File,
                size: 5,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
                symlink_target: None,
            }],
            total_bytes: 5,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            volume_count: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
            emit_bootstrap_sidecar: false,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

        let root_listing = list_entries(&archive).unwrap();
        assert!(!root_listing.entries.is_empty());
    }
}
