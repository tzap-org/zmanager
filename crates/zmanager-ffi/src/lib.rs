uniffi::include_scaffolding!("zmanager_ffi");

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zmanager_core::apple_archive_backend::{self, AppleArchiveError};
use zmanager_core::archive_browser::{
    self, ArchiveBrowserError, BrowserEntryKind, BrowserExtractOptions, BrowserListOptions,
};
use zmanager_core::jobs::{self, CancellationToken, JobEvent as CoreJobEvent, JobKind as CoreJobKind};
use zmanager_core::libarchive_backend::{self, LibarchiveError, LibarchiveTestReport};
use zmanager_core::manifest::{self, ManifestFileType, PlanError, PlanOptions};
use zmanager_core::rar_backend::RarBackendError;
use zmanager_core::raw_stream_backend::{self, RawStreamError};
use zmanager_core::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError,
    ExtractionSafetyPlanner, OverwritePolicy,
};
use zmanager_core::secrets::SecretString;
use zmanager_core::sevenz_backend::{SevenZCreateOptions, SevenZError};
use zmanager_core::tar_zst_backend::{TarZstdCreateOptions, TarZstdError};
use zmanager_core::tzap_backend::{
    self, TzapCreateOptions, TzapError, TzapKeySource, TzapTestReport, TzapX509SigningOptions,
};
use zmanager_core::zip_backend::{self, ZipBackendError, ZipCreateOptions, ZipTestReport};

const ERROR_INVALID_REQUEST: &str = "invalid_request";
const ERROR_NOT_FOUND: &str = "not_found";
const ERROR_PASSWORD_REQUIRED: &str = "password_required";
const ERROR_INVALID_PASSWORD: &str = "invalid_password";
const ERROR_UNSAFE_ARCHIVE: &str = "unsafe_archive";
const ERROR_IO_ERROR: &str = "io_error";
const ERROR_UNSUPPORTED_FORMAT: &str = "unsupported_format";
const ERROR_DAMAGED_ARCHIVE: &str = "damaged_archive";
const ERROR_CANCELLED: &str = "cancelled";
const ERROR_OPERATION_FAILED: &str = "operation_failed";
const WARNING_GENERIC: &str = "warning";
const WARNING_LAUNCH_GATED_FORMAT: &str = "launch_gated_format";
const MAX_EVENTS_PER_JOB: usize = 512;

static JOB_REGISTRY: OnceLock<Arc<MobileJobRegistry>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BridgeSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub recovery_hint: Option<String>,
    pub severity: BridgeSeverity,
    pub retryable: bool,
}

#[derive(Debug, Error)]
pub enum ZmanagerGuiError {
    #[error("{user_message}")]
    Bridge {
        code: String,
        user_message: String,
        recovery_hint: Option<String>,
        severity: BridgeSeverity,
        retryable: bool,
    },
}

impl From<BridgeError> for ZmanagerGuiError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge {
            code: error.code,
            user_message: error.message,
            recovery_hint: error.recovery_hint,
            severity: error.severity,
            retryable: error.retryable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckResult {
    pub status: String,
    pub engine: String,
    pub version: String,
    pub ready: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Zip,
    SplitZip,
    Rar,
    MultipartRar,
    SevenZ,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Tzap,
    AppleArchive,
    Xip,
    RawStream,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveRequest {
    pub archive_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub exists: bool,
    pub is_file: bool,
    pub can_list: bool,
    pub can_extract: bool,
    pub can_create: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: ArchiveEntryKind,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub entries: Vec<ArchiveEntry>,
    pub entry_count: u64,
    pub total_size: Option<u64>,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub verified: bool,
    pub tested_entries: u64,
    pub skipped_entries: u64,
    pub total_entries: u64,
    pub tested_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewRequest {
    pub archive_path: String,
    pub entry_path: String,
    pub password: Option<String>,
    pub strip_components: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewResult {
    pub archive_path: String,
    pub entry_path: String,
    pub cleanup_root: String,
    pub preview_path: String,
    pub written_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExtractionCollisionPolicy {
    Refuse,
    Replace,
    Rename,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExtractionPlanEntryStatus {
    Write,
    Skip,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanExtractRequest {
    pub archive_path: String,
    pub destination_root: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
    pub strip_components: u64,
    pub collision_policy: ExtractionCollisionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionPlanEntry {
    pub archive_path: String,
    pub normalized_path: Option<String>,
    pub destination_path: Option<String>,
    pub kind: ArchiveEntryKind,
    pub status: ExtractionPlanEntryStatus,
    pub reason: Option<String>,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub replace_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanExtractResult {
    pub plan_id: String,
    pub archive_path: String,
    pub destination_root: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub entries: Vec<ExtractionPlanEntry>,
    pub total_entries: u64,
    pub writable_entries: u64,
    pub skipped_entries: u64,
    pub blocked_entries: u64,
    pub estimated_bytes: Option<u64>,
    pub can_start: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateArchiveFormat {
    Zip,
    SevenZ,
    TarZst,
    Tzap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCreateRequest {
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub password: Option<String>,
    pub preserve_metadata: bool,
    pub replace_existing: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePlanEntry {
    pub archive_path: String,
    pub source_path: String,
    pub kind: ArchiveEntryKind,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCreateResult {
    pub plan_id: String,
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub format_label: String,
    pub entries: Vec<CreatePlanEntry>,
    pub total_entries: u64,
    pub total_bytes: u64,
    pub excluded_entries: u64,
    pub excluded_bytes: u64,
    pub output_exists: bool,
    pub replace_existing: bool,
    pub encrypted: bool,
    pub preserve_metadata: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
    pub verify_supported: bool,
    pub can_start: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartCreateRequest {
    pub source_paths: Vec<String>,
    pub destination_archive_path: String,
    pub format: CreateArchiveFormat,
    pub password: Option<String>,
    pub preserve_metadata: bool,
    pub replace_existing: bool,
    pub clean_source: bool,
    pub verify_after_create: bool,
    pub excluded_paths: Vec<String>,
    pub level: u32,
    pub encrypt_file_names: bool,
    pub volume_size: Option<u64>,
    pub recovery_percentage: u8,
    pub volume_loss_tolerance: u8,
    pub tzap_signing_certificate: Option<String>,
    pub tzap_signing_private_key: Option<String>,
    pub tzap_signing_chain: Vec<String>,
    pub tzap_identity: Option<String>,
    pub tzap_identity_password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl MobileJobStatus {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobKind {
    ZipCreate,
    ZipExtract,
    SevenZCreate,
    SevenZExtract,
    RarExtract,
    TarZstdCreate,
    TarZstdExtract,
    TzapCreate,
    TzapExtract,
    AppleArchiveCreate,
    AppleArchiveExtract,
    ArchiveExtract,
    RawStreamExtract,
    TestArchive,
    TarGzCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileJobEventKind {
    Started,
    EntryStarted,
    BytesProcessed,
    EntryFinished,
    Paused,
    Resumed,
    Warning,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileJobEvent {
    pub sequence: u64,
    pub event_type: MobileJobEventKind,
    pub job_kind: Option<MobileJobKind>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub total_bytes_processed: Option<u64>,
    pub entries: Option<u64>,
    pub total_entries: Option<u64>,
    pub message: Option<String>,
    pub error: Option<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobTerminalSummary {
    pub written_entries: u64,
    pub skipped_entries: Option<u64>,
    pub written_bytes: u64,
    pub encrypted: Option<bool>,
    pub volume_size: Option<u64>,
    pub volume_count: Option<u64>,
    pub output_paths: Vec<String>,
    pub verified: Option<bool>,
    pub verified_entries: Option<u64>,
    pub verified_bytes: Option<u64>,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartExtractRequest {
    pub archive_path: String,
    pub destination_root: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
    pub strip_components: u64,
    pub collision_policy: ExtractionCollisionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartJobResult {
    pub job_id: String,
    pub kind: MobileJobKind,
    pub status: MobileJobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollJobEventsRequest {
    pub job_id: String,
    pub cursor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollJobEventsResult {
    pub job_id: String,
    pub kind: MobileJobKind,
    pub status: MobileJobStatus,
    pub events: Vec<MobileJobEvent>,
    pub next_cursor: u64,
    pub min_retained_sequence: u64,
    pub is_terminal: bool,
    pub terminal_summary: Option<JobTerminalSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelJobRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelJobResult {
    pub job_id: String,
    pub status: MobileJobStatus,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearSensitiveStateResult {
    pub cleared_terminal_jobs: u64,
    pub cancel_requested_jobs: u64,
    pub retained_active_jobs: u64,
}

pub fn healthcheck() -> HealthcheckResult {
    let report = zmanager_core::healthcheck();
    HealthcheckResult {
        status: if report.ready { "ready" } else { "not-ready" }.to_string(),
        engine: report.engine.to_string(),
        version: report.version.to_string(),
        ready: report.ready,
        summary: report.summary(),
    }
}

pub fn detect_archive(request: DetectArchiveRequest) -> Result<DetectArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let path = Path::new(&archive_path);
    let (format, mut warnings) = classify_archive_path(path);
    let (can_list, can_extract, can_create) = format_capabilities(format);

    if matches!(format, ArchiveFormat::Xip) {
        warnings.push(bridge_warning_with_code(
            WARNING_LAUNCH_GATED_FORMAT,
            "This launch-scope format must be handled by zmanager-core before mobile exposes it.",
        ));
    }

    Ok(DetectArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        exists: true,
        is_file: true,
        can_list,
        can_extract,
        can_create,
        warnings,
    })
}

#[allow(non_snake_case)]
pub fn detectArchive(request: DetectArchiveRequest) -> Result<DetectArchiveResult, ZmanagerGuiError> {
    detect_archive(request)
}

pub fn list_archive(request: ListArchiveRequest) -> Result<ListArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let password = password_ref(&request.password);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);

    let listing = archive_browser::list_entries_with_options(path, BrowserListOptions { password })
        .map_err(map_archive_browser_error)?;

    let mut total_size = 0u64;
    let mut has_size = false;
    let mut entries = Vec::with_capacity(listing.entries.len());

    for entry in listing.entries {
        if let Some(size) = entry.size {
            total_size = total_size.saturating_add(size);
            has_size = true;
        }

        let kind = map_browser_entry_kind(entry.kind);
        entries.push(ArchiveEntry {
            path: entry.path,
            kind,
            is_dir: matches!(kind, ArchiveEntryKind::Directory),
            size: entry.size,
            compressed_size: entry.compressed_size,
            modified_at: entry.modified,
        });
    }

    Ok(ListArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        entry_count: entries.len() as u64,
        total_size: has_size.then_some(total_size),
        entries,
        warnings: Vec::new(),
    })
}

#[allow(non_snake_case)]
pub fn listArchive(request: ListArchiveRequest) -> Result<ListArchiveResult, ZmanagerGuiError> {
    list_archive(request)
}

pub fn test_archive(request: TestArchiveRequest) -> Result<TestArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let password = password_ref(&request.password);
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);

    let report = if matches!(format, ArchiveFormat::Zip) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_zip(
            zip_backend::test_zip_with_password_filter(path, password, |entry_path| {
                selected_path_matches(selected_paths, entry_path)
            })
            .map_err(map_zip_error)?,
        )
    } else if matches!(format, ArchiveFormat::Tzap) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_tzap(
            tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
                path,
                password,
                |entry_path| selected_path_matches(selected_paths, entry_path),
                None,
            )
            .map_err(map_tzap_error)?,
        )
    } else if matches!(format, ArchiveFormat::AppleArchive) {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_apple_archive(
            apple_archive_backend::test_apple_archive_filter(
                path,
                |entry_path| selected_path_matches(selected_paths, entry_path),
                None,
            )
            .map_err(map_apple_archive_error)?,
        )
    } else if let Some(raw_format) = raw_stream_backend::detect_raw_stream_format(path) {
        test_raw_stream(path, raw_format, &selected_paths)?
    } else {
        let selected_paths = selected_paths.as_slice();
        TestArchiveReport::from_libarchive(
            libarchive_backend::test_archive_with_password_filter(path, password, |entry_path| {
                selected_path_matches(selected_paths, entry_path)
            })
            .map_err(map_libarchive_error)?,
        )
    };

    Ok(TestArchiveResult {
        archive_path,
        format,
        format_label: format_label(format).to_string(),
        verified: true,
        tested_entries: report.tested_entries,
        skipped_entries: report.skipped_entries,
        total_entries: report.total_entries(),
        tested_bytes: report.tested_bytes,
        warnings: report.warnings,
    })
}

#[allow(non_snake_case)]
pub fn testArchive(request: TestArchiveRequest) -> Result<TestArchiveResult, ZmanagerGuiError> {
    test_archive(request)
}

pub fn materialize_preview(request: MaterializePreviewRequest) -> Result<MaterializePreviewResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let entry_path = ensure_non_empty_entry_path(request.entry_path)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let password = password_ref(&request.password);

    let options = BrowserExtractOptions { password, strip_components, ..BrowserExtractOptions::default() };

    let report = archive_browser::preview_entry_with_options(Path::new(&archive_path), &entry_path, options)
        .map_err(map_archive_browser_error)?;

    Ok(MaterializePreviewResult {
        archive_path,
        entry_path,
        cleanup_root: report.cleanup_root.to_string_lossy().to_string(),
        preview_path: report.preview_path.to_string_lossy().to_string(),
        written_bytes: report.written_bytes,
        warnings: Vec::new(),
    })
}

#[allow(non_snake_case)]
pub fn materializePreview(request: MaterializePreviewRequest) -> Result<MaterializePreviewResult, ZmanagerGuiError> {
    materialize_preview(request)
}

pub fn plan_extract(request: PlanExtractRequest) -> Result<PlanExtractResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let destination_root = ensure_destination_root_path(request.destination_root)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let password = password_ref(&request.password);
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);
    let listing = archive_browser::list_entries_with_options(path, BrowserListOptions { password })
        .map_err(map_archive_browser_error)?;

    let policy = ExtractionPolicy {
        overwrite: map_collision_policy(request.collision_policy),
        strip_components,
        ..ExtractionPolicy::default()
    };
    let mut planner = ExtractionSafetyPlanner::new(PathBuf::from(&destination_root), policy);
    let mut entries = Vec::new();
    let mut estimated_bytes = 0u64;
    let mut has_estimated_bytes = false;
    let mut warnings = Vec::new();

    for entry in listing.entries {
        if !selected_path_matches(&selected_paths, &entry.path) {
            continue;
        }

        match plan_browser_entry(&mut planner, entry) {
            PlanEntryOutcome::Entry(plan_entry) => {
                if matches!(plan_entry.status, ExtractionPlanEntryStatus::Write)
                    && matches!(plan_entry.kind, ArchiveEntryKind::File)
                    && let Some(size) = plan_entry.size
                {
                    estimated_bytes = estimated_bytes.saturating_add(size);
                    has_estimated_bytes = true;
                }
                entries.push(plan_entry);
            }
            PlanEntryOutcome::EntryWithWarning { plan_entry, warning } => {
                warnings.push(warning);
                entries.push(plan_entry);
            }
        }
    }

    let total_entries = usize_to_u64(entries.len());
    let writable_entries =
        usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Write)).count());
    let skipped_entries =
        usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Skip)).count());
    let blocked_entries =
        usize_to_u64(entries.iter().filter(|entry| matches!(entry.status, ExtractionPlanEntryStatus::Block)).count());

    Ok(PlanExtractResult {
        plan_id: new_plan_id("extract"),
        archive_path,
        destination_root,
        format,
        format_label: format_label(format).to_string(),
        entries,
        total_entries,
        writable_entries,
        skipped_entries,
        blocked_entries,
        estimated_bytes: has_estimated_bytes.then_some(estimated_bytes),
        can_start: writable_entries > 0,
        warnings,
    })
}

#[allow(non_snake_case)]
pub fn planExtract(request: PlanExtractRequest) -> Result<PlanExtractResult, ZmanagerGuiError> {
    plan_extract(request)
}

pub fn plan_create(request: PlanCreateRequest) -> Result<PlanCreateResult, ZmanagerGuiError> {
    let source_paths = ensure_existing_source_paths(request.source_paths)?;
    let destination_archive_path = ensure_destination_archive_path(request.destination_archive_path)?;
    let destination_path = Path::new(&destination_archive_path);
    let output_exists = destination_path.exists();
    let plan_options = create_plan_options(request.clean_source, &[]);
    let source_path_bufs = source_paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    let manifest = manifest::plan_archives(&source_path_bufs, &plan_options).map_err(map_plan_error)?;
    let mut warnings = manifest
        .warnings
        .iter()
        .map(|warning| bridge_warning(format!("{}: {}", warning.source_path.display(), warning.message)))
        .collect::<Vec<_>>();

    if output_exists && !request.replace_existing {
        warnings.push(bridge_warning("Destination archive already exists and replaceExisting is false."));
    }

    let entries = manifest
        .entries
        .iter()
        .map(|entry| CreatePlanEntry {
            archive_path: entry.archive_path.clone(),
            source_path: entry.source_path.to_string_lossy().to_string(),
            kind: map_manifest_file_type(entry.file_type),
            size: entry.size,
        })
        .collect::<Vec<_>>();
    let total_entries = usize_to_u64(entries.len());
    let encrypted = password_ref(&request.password).is_some();

    Ok(PlanCreateResult {
        plan_id: new_plan_id("create"),
        source_paths,
        destination_archive_path,
        format: request.format,
        format_label: create_format_label(request.format).to_string(),
        entries,
        total_entries,
        total_bytes: manifest.total_bytes,
        excluded_entries: usize_to_u64(manifest.excluded_count()),
        excluded_bytes: manifest.excluded_bytes,
        output_exists,
        replace_existing: request.replace_existing,
        encrypted,
        preserve_metadata: request.preserve_metadata,
        clean_source: request.clean_source,
        verify_after_create: request.verify_after_create,
        verify_supported: create_verify_supported(request.format),
        can_start: total_entries > 0 && (!output_exists || request.replace_existing),
        warnings,
    })
}

#[allow(non_snake_case)]
pub fn planCreate(request: PlanCreateRequest) -> Result<PlanCreateResult, ZmanagerGuiError> {
    plan_create(request)
}

pub fn start_create(request: StartCreateRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    let source_paths = ensure_existing_source_paths(request.source_paths)?;
    let destination_archive_path = ensure_destination_archive_path(request.destination_archive_path)?;
    if Path::new(&destination_archive_path).exists() && !request.replace_existing {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "Destination archive already exists.",
            hint("Choose a different output name or enable replaceExisting."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let password = sanitize_password(request.password);
    let contains_sensitive_input = password.is_some();
    let token = CancellationToken::new();
    let kind = mobile_create_job_kind(request.format);
    let registry = job_registry();
    let result = registry.create_job(kind, token.clone(), contains_sensitive_input);
    let job_id = result.job_id.clone();
    let input = CreateJobInput {
        source_paths: source_paths.iter().map(PathBuf::from).collect(),
        destination_archive_path,
        format: request.format,
        password,
        preserve_metadata: request.preserve_metadata,
        replace_existing: request.replace_existing,
        clean_source: request.clean_source,
        verify_after_create: request.verify_after_create,
        excluded_paths: request.excluded_paths,
        level: request.level,
        encrypt_file_names: request.encrypt_file_names,
        volume_size: request.volume_size,
        recovery_percentage: request.recovery_percentage,
        volume_loss_tolerance: request.volume_loss_tolerance,
        tzap_signing_certificate: request.tzap_signing_certificate,
        tzap_signing_private_key: request.tzap_signing_private_key,
        tzap_signing_chain: request.tzap_signing_chain,
        tzap_identity: request.tzap_identity,
        tzap_identity_password: request.tzap_identity_password,
    };
    let worker_registry = Arc::clone(&registry);

    thread::spawn(move || {
        let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = RegistryJobEventSink { registry: Arc::clone(&worker_registry), job_id: job_id.clone() };
            run_create_job(input, &token, &mut sink)
        }));

        match worker_result {
            Ok(Ok(summary)) => worker_registry.set_terminal_summary(&job_id, summary),
            Ok(Err(error)) => {
                worker_registry.finish_with_error(&job_id, bridge_error_from_mobile(error));
            }
            Err(_) => {
                worker_registry.finish_with_error(
                    &job_id,
                    BridgeError {
                        code: ERROR_OPERATION_FAILED.to_string(),
                        message: "Create worker failed unexpectedly.".to_string(),
                        recovery_hint: hint("Retry the operation and report this if it repeats."),
                        severity: BridgeSeverity::Error,
                        retryable: true,
                    },
                );
            }
        }
    });

    Ok(result)
}

#[allow(non_snake_case)]
pub fn startCreate(request: StartCreateRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    start_create(request)
}

pub fn start_extract(request: StartExtractRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let destination_root = ensure_destination_root_path(request.destination_root)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let password = sanitize_password(request.password);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);
    let (_, can_extract, _) = format_capabilities(format);

    if !can_extract {
        return Err(bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            format!("{} extraction is not exposed by zmanager-core for mobile yet.", format_label(format)),
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    let token = CancellationToken::new();
    let kind = mobile_extract_job_kind(path, format);
    let registry = job_registry();
    let result = registry.create_job(kind, token.clone(), password.is_some());
    let job_id = result.job_id.clone();
    let input = ExtractJobInput {
        archive_path,
        destination_root,
        password,
        selected_paths,
        strip_components,
        collision_policy: request.collision_policy,
        format,
    };
    let worker_registry = Arc::clone(&registry);

    thread::spawn(move || {
        let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = RegistryJobEventSink { registry: Arc::clone(&worker_registry), job_id: job_id.clone() };
            run_extract_job(input, &token, &mut sink)
        }));

        match worker_result {
            Ok(Ok(summary)) => worker_registry.set_terminal_summary(&job_id, summary),
            Ok(Err(error)) => {
                worker_registry.finish_with_error(&job_id, bridge_error_from_mobile(error));
            }
            Err(_) => {
                worker_registry.finish_with_error(
                    &job_id,
                    BridgeError {
                        code: ERROR_OPERATION_FAILED.to_string(),
                        message: "Extraction worker failed unexpectedly.".to_string(),
                        recovery_hint: hint("Retry the operation and report this if it repeats."),
                        severity: BridgeSeverity::Error,
                        retryable: true,
                    },
                );
            }
        }
    });

    Ok(result)
}

#[allow(non_snake_case)]
pub fn startExtract(request: StartExtractRequest) -> Result<StartJobResult, ZmanagerGuiError> {
    start_extract(request)
}

pub fn poll_job_events(request: PollJobEventsRequest) -> Result<PollJobEventsResult, ZmanagerGuiError> {
    job_registry().poll_events(request)
}

#[allow(non_snake_case)]
pub fn pollJobEvents(request: PollJobEventsRequest) -> Result<PollJobEventsResult, ZmanagerGuiError> {
    poll_job_events(request)
}

pub fn cancel_job(request: CancelJobRequest) -> Result<CancelJobResult, ZmanagerGuiError> {
    job_registry().cancel_job(request)
}

#[allow(non_snake_case)]
pub fn cancelJob(request: CancelJobRequest) -> Result<CancelJobResult, ZmanagerGuiError> {
    cancel_job(request)
}

pub fn clear_sensitive_state() -> ClearSensitiveStateResult {
    job_registry().clear_sensitive_state()
}

#[allow(non_snake_case)]
pub fn clearSensitiveState() -> ClearSensitiveStateResult {
    clear_sensitive_state()
}

pub fn tzap_public_metadata_summary(archive_path: String) -> String {
    let archive_path =
        ensure_existing_file_path(archive_path, "archivePath").unwrap_or_else(|error| return_tzap_error(error));
    zmanager_core::tzap_service::tzap_public_metadata_summary(&archive_path)
}

#[allow(non_snake_case)]
pub fn tzapPublicMetadataSummary(archive_path: String) -> String {
    tzap_public_metadata_summary(archive_path)
}

pub fn verify_tzap_x509(
    archive_path: String,
    password: Option<String>,
    trusted_ca_certs: Vec<String>,
    trusted_system_roots: bool,
) -> String {
    let archive_path =
        ensure_existing_file_path(archive_path, "archivePath").unwrap_or_else(|error| return_tzap_error(error));
    zmanager_core::tzap_service::verify_tzap_x509(
        &archive_path,
        password_ref(&password),
        &trusted_ca_certs,
        trusted_system_roots,
    )
}

#[allow(non_snake_case)]
pub fn verifyTzapX509(
    archive_path: String,
    password: Option<String>,
    trusted_ca_certs: Vec<String>,
    trusted_system_roots: bool,
) -> String {
    verify_tzap_x509(archive_path, password, trusted_ca_certs, trusted_system_roots)
}

pub fn verify_tzap_x509_public_no_key(
    archive_path: String,
    trusted_ca_certs: Vec<String>,
    trusted_system_roots: bool,
) -> String {
    let archive_path =
        ensure_existing_file_path(archive_path, "archivePath").unwrap_or_else(|error| return_tzap_error(error));
    zmanager_core::tzap_service::verify_tzap_x509_public_no_key(&archive_path, &trusted_ca_certs, trusted_system_roots)
}

#[allow(non_snake_case)]
pub fn verifyTzapX509PublicNoKey(
    archive_path: String,
    trusted_ca_certs: Vec<String>,
    trusted_system_roots: bool,
) -> String {
    verify_tzap_x509_public_no_key(archive_path, trusted_ca_certs, trusted_system_roots)
}

pub fn inspect_tzap_x509_signer(archive_path: String, password: Option<String>) -> String {
    let archive_path =
        ensure_existing_file_path(archive_path, "archivePath").unwrap_or_else(|error| return_tzap_error(error));
    zmanager_core::tzap_service::inspect_tzap_x509_signer(&archive_path, password_ref(&password))
}

#[allow(non_snake_case)]
pub fn inspectTzapX509Signer(archive_path: String, password: Option<String>) -> String {
    inspect_tzap_x509_signer(archive_path, password)
}

pub fn inspect_tzap_x509_public_no_key_signer(archive_path: String) -> String {
    let archive_path =
        ensure_existing_file_path(archive_path, "archivePath").unwrap_or_else(|error| return_tzap_error(error));
    zmanager_core::tzap_service::inspect_tzap_x509_public_no_key_signer(&archive_path)
}

#[allow(non_snake_case)]
pub fn inspectTzapX509PublicNoKeySigner(archive_path: String) -> String {
    inspect_tzap_x509_public_no_key_signer(archive_path)
}

pub fn create_tzap_self_signed_identity(
    identity_path: String,
    public_certificate_path: String,
    common_name: String,
    password: String,
) -> String {
    zmanager_core::tzap_service::create_tzap_self_signed_identity(
        &identity_path,
        Some(&public_certificate_path),
        &common_name,
        &password,
    )
}

#[allow(non_snake_case)]
pub fn createTzapSelfSignedIdentity(
    identity_path: String,
    public_certificate_path: String,
    common_name: String,
    password: String,
) -> String {
    create_tzap_self_signed_identity(identity_path, public_certificate_path, common_name, password)
}

pub fn tzap_auth_login_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_auth_login_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapAuthLoginJson(request_json: String) -> String {
    tzap_auth_login_json(request_json)
}

pub fn tzap_auth_callback_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_auth_callback_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapAuthCallbackJson(request_json: String) -> String {
    tzap_auth_callback_json(request_json)
}

pub fn tzap_auth_status_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_auth_status_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapAuthStatusJson(request_json: String) -> String {
    tzap_auth_status_json(request_json)
}

pub fn tzap_auth_forget_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_auth_forget_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapAuthForgetJson(request_json: String) -> String {
    tzap_auth_forget_json(request_json)
}

pub fn tzap_auth_account_url_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_auth_account_url_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapAuthAccountUrlJson(request_json: String) -> String {
    tzap_auth_account_url_json(request_json)
}

pub fn tzap_certificate_inventory_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_certificate_inventory_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapCertificateInventoryJson(request_json: String) -> String {
    tzap_certificate_inventory_json(request_json)
}

pub fn tzap_cert_enroll_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_cert_enroll_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapCertEnrollJson(request_json: String) -> String {
    tzap_cert_enroll_json(request_json)
}

pub fn tzap_cert_renew_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_cert_renew_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapCertRenewJson(request_json: String) -> String {
    tzap_cert_renew_json(request_json)
}

pub fn tzap_cert_revoke_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_cert_revoke_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapCertRevokeJson(request_json: String) -> String {
    tzap_cert_revoke_json(request_json)
}

pub fn tzap_device_retire_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_device_retire_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapDeviceRetireJson(request_json: String) -> String {
    tzap_device_retire_json(request_json)
}

pub fn tzap_document_sign_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_document_sign_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapDocumentSignJson(request_json: String) -> String {
    tzap_document_sign_json(request_json)
}

pub fn tzap_document_verify_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_document_verify_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapDocumentVerifyJson(request_json: String) -> String {
    tzap_document_verify_json(request_json)
}

pub fn tzap_recipient_key_generate_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_recipient_key_generate_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapRecipientKeyGenerateJson(request_json: String) -> String {
    tzap_recipient_key_generate_json(request_json)
}

pub fn tzap_recipient_key_remove_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_recipient_key_remove_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapRecipientKeyRemoveJson(request_json: String) -> String {
    tzap_recipient_key_remove_json(request_json)
}

pub fn tzap_contact_export_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_contact_export_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapContactExportJson(request_json: String) -> String {
    tzap_contact_export_json(request_json)
}

pub fn tzap_contact_import_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_contact_import_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapContactImportJson(request_json: String) -> String {
    tzap_contact_import_json(request_json)
}

pub fn tzap_contact_list_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_contact_list_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapContactListJson(request_json: String) -> String {
    tzap_contact_list_json(request_json)
}

pub fn tzap_contact_remove_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_contact_remove_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapContactRemoveJson(request_json: String) -> String {
    tzap_contact_remove_json(request_json)
}

pub fn tzap_share_create_json(request_json: String) -> String {
    zmanager_core::tzap_service::tzap_share_create_json(&request_json)
}

#[allow(non_snake_case)]
pub fn tzapShareCreateJson(request_json: String) -> String {
    tzap_share_create_json(request_json)
}

/// Turns a path-validation error into the JSON error envelope the tzap
/// service endpoints use, since they are declared without `[Throws]`.
fn return_tzap_error(error: ZmanagerGuiError) -> String {
    let message = match error {
        ZmanagerGuiError::Bridge { user_message, .. } => user_message,
    };
    format!("{{\"ok\":false,\"message\":{}}}", serde_json::to_string(&message).unwrap_or_default())
}

#[derive(Default)]
struct MobileJobRegistry {
    inner: Mutex<MobileJobRegistryInner>,
}

#[derive(Default)]
struct MobileJobRegistryInner {
    next_job_index: u64,
    jobs: HashMap<String, MobileJobRecord>,
}

struct MobileJobRecord {
    kind: MobileJobKind,
    status: MobileJobStatus,
    events: VecDeque<MobileJobEvent>,
    next_sequence: u64,
    token: CancellationToken,
    terminal_summary: Option<JobTerminalSummary>,
    contains_sensitive_input: bool,
}

struct RegistryJobEventSink {
    registry: Arc<MobileJobRegistry>,
    job_id: String,
}

impl jobs::JobEventSink for RegistryJobEventSink {
    fn emit(&mut self, event: CoreJobEvent) {
        self.registry.emit_core_event(&self.job_id, event);
    }
}

impl MobileJobRegistry {
    fn create_job(
        &self,
        kind: MobileJobKind,
        token: CancellationToken,
        contains_sensitive_input: bool,
    ) -> StartJobResult {
        let mut inner = self.inner.lock().expect("job registry mutex poisoned");
        inner.next_job_index = inner.next_job_index.saturating_add(1);
        let job_id = format!("job-{}-{}", std::process::id(), inner.next_job_index);
        inner.jobs.insert(
            job_id.clone(),
            MobileJobRecord {
                kind,
                status: MobileJobStatus::Queued,
                events: VecDeque::new(),
                next_sequence: 1,
                token,
                terminal_summary: None,
                contains_sensitive_input,
            },
        );

        StartJobResult { job_id, kind, status: MobileJobStatus::Queued }
    }

    fn poll_events(&self, request: PollJobEventsRequest) -> Result<PollJobEventsResult, ZmanagerGuiError> {
        let inner = self.inner.lock().expect("job registry mutex poisoned");
        let record = inner.jobs.get(&request.job_id).ok_or_else(|| {
            bridge_error(
                ERROR_NOT_FOUND,
                "Job not found.",
                hint("The job may have been created in a previous app process."),
                BridgeSeverity::Warning,
                false,
            )
        })?;

        let events: Vec<MobileJobEvent> =
            record.events.iter().filter(|event| event.sequence > request.cursor).cloned().collect();
        let next_cursor = events.last().map(|event| event.sequence).unwrap_or(request.cursor);
        let min_retained_sequence = record.events.front().map(|event| event.sequence).unwrap_or(record.next_sequence);

        Ok(PollJobEventsResult {
            job_id: request.job_id,
            kind: record.kind,
            status: record.status,
            events,
            next_cursor,
            min_retained_sequence,
            is_terminal: record.status.is_terminal(),
            terminal_summary: record.terminal_summary.clone(),
        })
    }

    fn cancel_job(&self, request: CancelJobRequest) -> Result<CancelJobResult, ZmanagerGuiError> {
        let inner = self.inner.lock().expect("job registry mutex poisoned");
        let record = inner.jobs.get(&request.job_id).ok_or_else(|| {
            bridge_error(
                ERROR_NOT_FOUND,
                "Job not found.",
                hint("The job may have been created in a previous app process."),
                BridgeSeverity::Warning,
                false,
            )
        })?;

        let cancel_requested = !record.status.is_terminal();
        if cancel_requested {
            record.token.cancel();
        }

        Ok(CancelJobResult { job_id: request.job_id, status: record.status, cancel_requested })
    }

    fn clear_sensitive_state(&self) -> ClearSensitiveStateResult {
        let mut inner = self.inner.lock().expect("job registry mutex poisoned");
        let mut cleared_terminal_jobs = 0u64;
        let mut cancel_requested_jobs = 0u64;
        let mut retained_active_jobs = 0u64;

        inner.jobs.retain(|_, record| {
            if record.status.is_terminal() {
                cleared_terminal_jobs = cleared_terminal_jobs.saturating_add(1);
                return false;
            }

            if record.contains_sensitive_input {
                record.token.cancel();
                cancel_requested_jobs = cancel_requested_jobs.saturating_add(1);
                return false;
            } else {
                retained_active_jobs = retained_active_jobs.saturating_add(1);
            }

            true
        });

        ClearSensitiveStateResult { cleared_terminal_jobs, cancel_requested_jobs, retained_active_jobs }
    }

    fn emit_core_event(&self, job_id: &str, event: CoreJobEvent) {
        let mut inner = self.inner.lock().expect("job registry mutex poisoned");
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };
        let event = mobile_event_from_core_event(event);
        Self::append_event(record, event);
    }

    fn set_terminal_summary(&self, job_id: &str, summary: JobTerminalSummary) {
        let mut inner = self.inner.lock().expect("job registry mutex poisoned");
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };
        record.terminal_summary = Some(summary.clone());
        if !record.status.is_terminal() {
            Self::append_event(record, completed_event_from_summary(&summary));
        }
    }

    fn finish_with_error(&self, job_id: &str, error: BridgeError) {
        let mut inner = self.inner.lock().expect("job registry mutex poisoned");
        let Some(record) = inner.jobs.get_mut(job_id) else {
            return;
        };

        if matches!(record.status, MobileJobStatus::Cancelled) {
            return;
        }

        if matches!(record.events.back().map(|event| event.event_type), Some(MobileJobEventKind::Failed)) {
            if let Some(event) = record.events.back_mut() {
                event.message = Some(error.message.clone());
                event.error = Some(error);
            }
            return;
        }

        if error.code == ERROR_CANCELLED {
            if !record.status.is_terminal() {
                Self::append_event(record, cancelled_event(error.message));
            }
        } else if !record.status.is_terminal() {
            Self::append_event(record, failed_event(error));
        }
    }

    fn append_event(record: &mut MobileJobRecord, mut event: MobileJobEvent) {
        if record.status.is_terminal()
            && matches!(
                event.event_type,
                MobileJobEventKind::Completed | MobileJobEventKind::Failed | MobileJobEventKind::Cancelled
            )
        {
            return;
        }

        match event.event_type {
            MobileJobEventKind::Started => {
                if !record.status.is_terminal() {
                    record.status = MobileJobStatus::Running;
                }
            }
            MobileJobEventKind::Completed => {
                record.status = MobileJobStatus::Completed;
                if record.terminal_summary.is_none() {
                    record.terminal_summary = Some(JobTerminalSummary {
                        written_entries: event.entries.unwrap_or(0),
                        skipped_entries: None,
                        written_bytes: event.bytes.unwrap_or(0),
                        encrypted: None,
                        volume_size: None,
                        volume_count: None,
                        output_paths: Vec::new(),
                        verified: None,
                        verified_entries: None,
                        verified_bytes: None,
                        warnings: Vec::new(),
                    });
                }
            }
            MobileJobEventKind::Failed => record.status = MobileJobStatus::Failed,
            MobileJobEventKind::Cancelled => record.status = MobileJobStatus::Cancelled,
            MobileJobEventKind::Paused => record.status = MobileJobStatus::Paused,
            MobileJobEventKind::Resumed
            | MobileJobEventKind::EntryStarted
            | MobileJobEventKind::BytesProcessed
            | MobileJobEventKind::EntryFinished
            | MobileJobEventKind::Warning => {}
        }

        event.sequence = record.next_sequence;
        record.next_sequence = record.next_sequence.saturating_add(1);
        record.events.push_back(event);
        while record.events.len() > MAX_EVENTS_PER_JOB {
            record.events.pop_front();
        }
    }
}

struct ExtractJobInput {
    archive_path: String,
    destination_root: String,
    password: Option<String>,
    selected_paths: Vec<String>,
    strip_components: usize,
    collision_policy: ExtractionCollisionPolicy,
    format: ArchiveFormat,
}

struct CreateJobInput {
    source_paths: Vec<PathBuf>,
    destination_archive_path: String,
    format: CreateArchiveFormat,
    password: Option<String>,
    preserve_metadata: bool,
    replace_existing: bool,
    clean_source: bool,
    verify_after_create: bool,
    excluded_paths: Vec<String>,
    level: u32,
    encrypt_file_names: bool,
    volume_size: Option<u64>,
    recovery_percentage: u8,
    volume_loss_tolerance: u8,
    tzap_signing_certificate: Option<String>,
    tzap_signing_private_key: Option<String>,
    tzap_signing_chain: Vec<String>,
    tzap_identity: Option<String>,
    tzap_identity_password: Option<String>,
}

fn job_registry() -> Arc<MobileJobRegistry> {
    JOB_REGISTRY.get_or_init(|| Arc::new(MobileJobRegistry::default())).clone()
}

fn run_create_job(
    input: CreateJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let destination = Path::new(&input.destination_archive_path);
    let plan_options = create_plan_options(input.clean_source, &input.excluded_paths);
    let verify_after_create = input.verify_after_create;
    let verify_password = verify_after_create.then(|| input.password.clone()).flatten();
    let level = input.level;
    let volume_size = input.volume_size;
    let encrypt_file_names = input.encrypt_file_names;
    let recovery_percentage = input.recovery_percentage;
    let volume_loss_tolerance = input.volume_loss_tolerance;
    let x509_signing = tzap_signing_options(&input);
    let mut summary = match input.format {
        CreateArchiveFormat::Zip => {
            let options = ZipCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                password: input.password.map(SecretString::from),
                level: (level > 0).then_some(i64::from(level)),
                volume_size,
                ..ZipCreateOptions::default()
            };
            let report = jobs::run_zip_create_job_from_sources_with_plan_options(
                &input.source_paths,
                destination,
                &options,
                &plan_options,
                token,
                sink,
            )
            .map_err(map_zip_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::SevenZ => {
            let options = SevenZCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                password: input.password.map(SecretString::from),
                level: (level > 0).then_some(level),
                encrypt_file_names,
                volume_size,
                ..SevenZCreateOptions::default()
            };
            let report = jobs::run_7z_create_job_from_sources_with_plan_options(
                &input.source_paths,
                destination,
                &options,
                &plan_options,
                token,
                sink,
            )
            .map_err(map_7z_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::TarZst => {
            let options = TarZstdCreateOptions {
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                level: i32::try_from(level).unwrap_or(0),
                ..TarZstdCreateOptions::default()
            };
            let report = jobs::run_tar_zst_create_job_from_sources_with_plan_options(
                &input.source_paths,
                destination,
                &options,
                &plan_options,
                token,
                sink,
            )
            .map_err(map_tar_zst_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
        CreateArchiveFormat::Tzap => {
            let options = TzapCreateOptions {
                key_source: input
                    .password
                    .map(|password| TzapKeySource::Passphrase(SecretString::from(password)))
                    .unwrap_or(TzapKeySource::NoPassword),
                level: i32::try_from(level).unwrap_or(0),
                preserve_metadata: input.preserve_metadata,
                replace_existing: input.replace_existing,
                volume_size,
                recovery_percentage,
                volume_loss_tolerance,
                x509_signing,
            };
            let report = jobs::run_tzap_create_job_from_sources_with_plan_options(
                &input.source_paths,
                destination,
                &options,
                &plan_options,
                token,
                sink,
            )
            .map_err(map_tzap_error)?;
            JobTerminalSummary::from(ArchiveJobReport::from(report).with_output_path(destination))
        }
    };

    if verify_after_create {
        apply_create_verification(&mut summary, destination, verify_password, sink);
    }

    Ok(summary)
}

fn run_extract_job(
    input: ExtractJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    if input.selected_paths.is_empty() {
        run_full_extract_job(input, token, sink)
    } else {
        run_selected_extract_job(input, token, sink)
    }
}

fn run_full_extract_job(
    input: ExtractJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let archive_path = Path::new(&input.archive_path);
    let destination_root = Path::new(&input.destination_root);
    let password = input.password.as_deref();
    let policy = extraction_policy_for_request(input.collision_policy, input.strip_components);

    if matches!(input.format, ArchiveFormat::Zip) {
        jobs::run_zip_extract_job_with_password_and_policy(
            archive_path,
            destination_root,
            password,
            policy,
            token,
            sink,
        )
        .map(ArchiveJobReport::from)
        .map_err(map_zip_error)
        .map(JobTerminalSummary::from)
    } else if matches!(input.format, ArchiveFormat::TarZst) {
        jobs::run_tar_zst_extract_job_with_policy(archive_path, destination_root, policy, token, sink)
            .map(ArchiveJobReport::from)
            .map_err(map_tar_zst_error)
            .map(JobTerminalSummary::from)
    } else if matches!(input.format, ArchiveFormat::SevenZ) {
        jobs::run_7z_extract_job_with_password_and_policy(archive_path, destination_root, password, policy, token, sink)
            .map(ArchiveJobReport::from)
            .map_err(map_7z_error)
            .map(JobTerminalSummary::from)
    } else if matches!(input.format, ArchiveFormat::Rar | ArchiveFormat::MultipartRar) {
        jobs::run_rar_extract_job_with_password_and_policy(
            archive_path,
            destination_root,
            password,
            policy,
            token,
            sink,
        )
        .map(ArchiveJobReport::from)
        .map_err(map_rar_error)
        .map(JobTerminalSummary::from)
    } else if matches!(input.format, ArchiveFormat::Tzap) {
        jobs::run_tzap_extract_job_with_password_and_policy(
            archive_path,
            destination_root,
            password,
            policy,
            token,
            sink,
        )
        .map(ArchiveJobReport::from)
        .map_err(map_tzap_error)
        .map(JobTerminalSummary::from)
    } else if matches!(input.format, ArchiveFormat::AppleArchive) {
        jobs::run_apple_archive_extract_job_with_policy(archive_path, destination_root, policy, token, sink)
            .map(ArchiveJobReport::from)
            .map_err(map_apple_archive_error)
            .map(JobTerminalSummary::from)
    } else if let Some(raw_format) = raw_stream_backend::detect_raw_stream_format(archive_path) {
        jobs::run_raw_stream_extract_job_with_policy(archive_path, raw_format, destination_root, policy, token, sink)
            .map(ArchiveJobReport::from)
            .map_err(map_raw_stream_error)
            .map(JobTerminalSummary::from)
    } else {
        jobs::run_libarchive_extract_job_with_password_and_policy(
            archive_path,
            destination_root,
            password,
            policy,
            token,
            sink,
        )
        .map(ArchiveJobReport::from)
        .map_err(map_libarchive_error)
        .map(JobTerminalSummary::from)
    }
}

fn run_selected_extract_job(
    input: ExtractJobInput,
    token: &CancellationToken,
    sink: &mut dyn jobs::JobEventSink,
) -> Result<JobTerminalSummary, ZmanagerGuiError> {
    let archive_path = Path::new(&input.archive_path);
    let destination_root = Path::new(&input.destination_root);
    let password = input.password.as_deref();
    let listing = archive_browser::list_entries_with_options(archive_path, BrowserListOptions { password })
        .map_err(map_archive_browser_error)?;
    let entries: Vec<_> =
        listing.entries.into_iter().filter(|entry| selected_path_matches(&input.selected_paths, &entry.path)).collect();

    if entries.is_empty() {
        return Err(bridge_error(
            ERROR_NOT_FOUND,
            "No selected archive entries were found.",
            hint("Refresh the archive listing and select entries that still exist."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let total_bytes = entries.iter().fold((false, 0_u64), |(has_size, total), entry| match entry.size {
        Some(size) => (true, total.saturating_add(size)),
        None => (has_size, total),
    });
    sink.emit(CoreJobEvent::Started {
        kind: core_extract_job_kind(archive_path, input.format),
        total_bytes: total_bytes.0.then_some(total_bytes.1),
    });

    let mut written_entries = 0usize;
    let mut written_bytes = 0u64;
    let options = BrowserExtractOptions {
        password,
        overwrite: map_collision_policy(input.collision_policy),
        strip_components: input.strip_components,
        ..Default::default()
    };

    for entry in entries {
        if token.is_cancelled() {
            sink.emit(CoreJobEvent::Cancelled { message: "job cancelled".to_string() });
            return Err(cancelled_bridge_error("Extraction job was cancelled."));
        }

        let entry_path = entry.path;
        sink.emit(CoreJobEvent::EntryStarted { path: entry_path.clone(), bytes: entry.size });
        let report = archive_browser::extract_entry_with_options(archive_path, &entry_path, destination_root, options)
            .map_err(map_archive_browser_error)?;
        written_entries = written_entries.saturating_add(1);
        written_bytes = written_bytes.saturating_add(report.written_bytes);
        sink.emit(CoreJobEvent::EntryFinished { path: entry_path, bytes: report.written_bytes });
    }

    sink.emit(CoreJobEvent::Completed { entries: written_entries, bytes: written_bytes });

    Ok(JobTerminalSummary {
        written_entries: usize_to_u64(written_entries),
        skipped_entries: Some(0),
        written_bytes,
        encrypted: None,
        volume_size: None,
        volume_count: None,
        output_paths: Vec::new(),
        verified: None,
        verified_entries: None,
        verified_bytes: None,
        warnings: Vec::new(),
    })
}

struct ArchiveJobReport {
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    encrypted: Option<bool>,
    volume_size: Option<u64>,
    volume_count: Option<usize>,
    output_paths: Vec<String>,
    warnings: Vec<String>,
}

impl ArchiveJobReport {
    fn with_output_path(mut self, path: &Path) -> Self {
        self.output_paths.push(path.to_string_lossy().to_string());
        self
    }
}

impl From<zip_backend::ZipExtractReport> for ArchiveJobReport {
    fn from(report: zip_backend::ZipExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::tar_zst_backend::TarZstdExtractReport> for ArchiveJobReport {
    fn from(report: zmanager_core::tar_zst_backend::TarZstdExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::sevenz_backend::SevenZExtractReport> for ArchiveJobReport {
    fn from(report: zmanager_core::sevenz_backend::SevenZExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::rar_backend::RarExtractReport> for ArchiveJobReport {
    fn from(report: zmanager_core::rar_backend::RarExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<tzap_backend::TzapExtractReport> for ArchiveJobReport {
    fn from(report: tzap_backend::TzapExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<apple_archive_backend::AppleArchiveExtractReport> for ArchiveJobReport {
    fn from(report: apple_archive_backend::AppleArchiveExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<raw_stream_backend::RawStreamExtractReport> for ArchiveJobReport {
    fn from(report: raw_stream_backend::RawStreamExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<libarchive_backend::LibarchiveExtractReport> for ArchiveJobReport {
    fn from(report: libarchive_backend::LibarchiveExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: None,
            volume_count: None,
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zip_backend::ZipCreateReport> for ArchiveJobReport {
    fn from(report: zip_backend::ZipCreateReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: 0,
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            volume_size: report.volume_size,
            volume_count: Some(report.volume_count),
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::sevenz_backend::SevenZCreateReport> for ArchiveJobReport {
    fn from(report: zmanager_core::sevenz_backend::SevenZCreateReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: 0,
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            volume_size: report.volume_size,
            volume_count: Some(report.volume_count),
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::tar_zst_backend::TarZstdCreateReport> for ArchiveJobReport {
    fn from(report: zmanager_core::tar_zst_backend::TarZstdCreateReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: 0,
            written_bytes: report.written_bytes,
            encrypted: Some(false),
            volume_size: None,
            volume_count: Some(1),
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<tzap_backend::TzapCreateReport> for ArchiveJobReport {
    fn from(report: tzap_backend::TzapCreateReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: 0,
            written_bytes: report.written_bytes,
            encrypted: None,
            volume_size: report.volume_size,
            volume_count: Some(report.volume_count),
            output_paths: Vec::new(),
            warnings: report.warnings,
        }
    }
}

impl From<ArchiveJobReport> for JobTerminalSummary {
    fn from(report: ArchiveJobReport) -> Self {
        Self {
            written_entries: usize_to_u64(report.written_entries),
            skipped_entries: Some(usize_to_u64(report.skipped_entries)),
            written_bytes: report.written_bytes,
            encrypted: report.encrypted,
            volume_size: report.volume_size,
            volume_count: report.volume_count.map(usize_to_u64),
            output_paths: report.output_paths,
            verified: None,
            verified_entries: None,
            verified_bytes: None,
            warnings: report.warnings.into_iter().map(bridge_warning).collect(),
        }
    }
}

struct TestArchiveReport {
    tested_entries: u64,
    skipped_entries: u64,
    tested_bytes: u64,
    warnings: Vec<BridgeError>,
}

impl TestArchiveReport {
    fn from_zip(report: ZipTestReport) -> Self {
        Self {
            tested_entries: usize_to_u64(report.tested_entries),
            skipped_entries: usize_to_u64(report.skipped_entries),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        }
    }

    fn from_libarchive(report: LibarchiveTestReport) -> Self {
        Self {
            tested_entries: usize_to_u64(report.tested_entries),
            skipped_entries: usize_to_u64(report.skipped_entries),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        }
    }

    fn from_tzap(report: TzapTestReport) -> Self {
        let warnings = report
            .x509_root_auth
            .map(|verification| {
                let mut warnings = Vec::with_capacity(1 + verification.diagnostics.len());
                warnings.push(bridge_warning(format!("TZAP root-auth verified for {}", verification.subject)));
                warnings.extend(verification.diagnostics.into_iter().map(bridge_warning));
                warnings
            })
            .unwrap_or_default();

        Self {
            tested_entries: usize_to_u64(report.tested_entries),
            skipped_entries: usize_to_u64(report.skipped_entries),
            tested_bytes: report.tested_bytes,
            warnings,
        }
    }

    fn from_apple_archive(report: apple_archive_backend::AppleArchiveTestReport) -> Self {
        Self {
            tested_entries: usize_to_u64(report.tested_entries),
            skipped_entries: usize_to_u64(report.skipped_entries),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        }
    }

    fn total_entries(&self) -> u64 {
        self.tested_entries.saturating_add(self.skipped_entries)
    }
}

enum PlanEntryOutcome {
    Entry(ExtractionPlanEntry),
    EntryWithWarning { plan_entry: ExtractionPlanEntry, warning: BridgeError },
}

fn plan_browser_entry(
    planner: &mut ExtractionSafetyPlanner<'_>,
    entry: zmanager_core::archive_browser::BrowserEntry,
) -> PlanEntryOutcome {
    let kind = map_browser_entry_kind(entry.kind);

    let extraction_kind = match entry.kind {
        BrowserEntryKind::File => ExtractionEntryKind::File,
        BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
        BrowserEntryKind::Symlink | BrowserEntryKind::Hardlink => {
            let reason = "Link target metadata is required before mobile can safely plan this entry.";
            let archive_path = entry.path.clone();
            return PlanEntryOutcome::EntryWithWarning {
                plan_entry: blocked_plan_entry(entry, kind, reason),
                warning: bridge_warning(format!(
                    "Blocked {} until zmanager-core exposes link target metadata for mobile planning.",
                    archive_path
                )),
            };
        }
        BrowserEntryKind::Special => {
            return PlanEntryOutcome::Entry(blocked_plan_entry(
                entry,
                kind,
                "Special files are blocked by the mobile extraction policy.",
            ));
        }
    };

    let safety_entry = ExtractionEntry {
        archive_path: entry.path.clone(),
        kind: extraction_kind,
        uncompressed_size: entry.size,
        compressed_size: entry.compressed_size,
    };

    match planner.validate_entry(&safety_entry) {
        Ok(ExtractionDecision::Write { normalized_archive_path, destination_path, replace_existing, .. }) => {
            PlanEntryOutcome::Entry(ExtractionPlanEntry {
                archive_path: entry.path,
                normalized_path: Some(normalized_archive_path),
                destination_path: Some(destination_path.to_string_lossy().to_string()),
                kind,
                status: ExtractionPlanEntryStatus::Write,
                reason: None,
                size: entry.size,
                compressed_size: entry.compressed_size,
                replace_existing,
            })
        }
        Ok(ExtractionDecision::Skip { normalized_archive_path, reason }) => {
            PlanEntryOutcome::Entry(ExtractionPlanEntry {
                archive_path: entry.path,
                normalized_path: Some(normalized_archive_path),
                destination_path: None,
                kind,
                status: ExtractionPlanEntryStatus::Skip,
                reason: Some(reason),
                size: entry.size,
                compressed_size: entry.compressed_size,
                replace_existing: false,
            })
        }
        Err(error) => PlanEntryOutcome::Entry(blocked_plan_entry_from_safety_error(entry, kind, error)),
    }
}

fn blocked_plan_entry(
    entry: zmanager_core::archive_browser::BrowserEntry,
    kind: ArchiveEntryKind,
    reason: impl Into<String>,
) -> ExtractionPlanEntry {
    ExtractionPlanEntry {
        archive_path: entry.path,
        normalized_path: None,
        destination_path: None,
        kind,
        status: ExtractionPlanEntryStatus::Block,
        reason: Some(reason.into()),
        size: entry.size,
        compressed_size: entry.compressed_size,
        replace_existing: false,
    }
}

fn blocked_plan_entry_from_safety_error(
    entry: zmanager_core::archive_browser::BrowserEntry,
    kind: ArchiveEntryKind,
    error: ExtractionSafetyError,
) -> ExtractionPlanEntry {
    let destination_path = safety_error_destination_path(&error);
    ExtractionPlanEntry {
        archive_path: entry.path,
        normalized_path: None,
        destination_path: destination_path.map(|path| path.to_string_lossy().to_string()),
        kind,
        status: ExtractionPlanEntryStatus::Block,
        reason: Some(error.to_string()),
        size: entry.size,
        compressed_size: entry.compressed_size,
        replace_existing: false,
    }
}

fn safety_error_destination_path(error: &ExtractionSafetyError) -> Option<PathBuf> {
    match error {
        ExtractionSafetyError::DestinationEscape { destination_path, .. }
        | ExtractionSafetyError::DestinationExists { destination_path, .. }
        | ExtractionSafetyError::OverwritePromptUnavailable { destination_path, .. }
        | ExtractionSafetyError::OverwriteAborted { destination_path, .. }
        | ExtractionSafetyError::DestinationProbe { destination_path, .. } => Some(destination_path.clone()),
        ExtractionSafetyError::EmptyPath
        | ExtractionSafetyError::NulByte { .. }
        | ExtractionSafetyError::AbsolutePath { .. }
        | ExtractionSafetyError::WindowsPrefix { .. }
        | ExtractionSafetyError::ParentTraversal { .. }
        | ExtractionSafetyError::NameCollision { .. }
        | ExtractionSafetyError::UnsafeFileType { .. }
        | ExtractionSafetyError::LinkTargetEscapes { .. }
        | ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }
        | ExtractionSafetyError::ExpansionRatioLimitExceeded { .. } => None,
    }
}

fn map_collision_policy(policy: ExtractionCollisionPolicy) -> OverwritePolicy {
    match policy {
        ExtractionCollisionPolicy::Refuse => OverwritePolicy::Refuse,
        ExtractionCollisionPolicy::Replace => OverwritePolicy::Replace,
        ExtractionCollisionPolicy::Rename => OverwritePolicy::Rename,
    }
}

fn extraction_policy_for_request(
    collision_policy: ExtractionCollisionPolicy,
    strip_components: usize,
) -> ExtractionPolicy {
    ExtractionPolicy {
        overwrite: map_collision_policy(collision_policy),
        strip_components,
        ..ExtractionPolicy::default()
    }
}

fn create_plan_options(clean_source: bool, excluded_paths: &[String]) -> PlanOptions {
    let mut options = if clean_source { PlanOptions::clean_source() } else { PlanOptions::default() };
    let excluded: Vec<String> = excluded_paths.iter().filter(|path| !path.trim().is_empty()).cloned().collect();
    if !excluded.is_empty() {
        options.exclude_archive_paths = excluded;
    }
    options
}

fn tzap_signing_options(input: &CreateJobInput) -> Option<TzapX509SigningOptions> {
    if let Some(identity) = input.tzap_identity.as_deref().filter(|path| !path.is_empty()) {
        return Some(TzapX509SigningOptions::Pkcs12 {
            identity: PathBuf::from(identity),
            password: SecretString::from(input.tzap_identity_password.clone().unwrap_or_default()),
        });
    }

    match (
        input.tzap_signing_certificate.as_deref().filter(|path| !path.is_empty()),
        input.tzap_signing_private_key.as_deref().filter(|path| !path.is_empty()),
    ) {
        (Some(certificate), Some(private_key)) => Some(TzapX509SigningOptions::CertificateAndKey {
            signing_certificate: PathBuf::from(certificate),
            signing_private_key: PathBuf::from(private_key),
            signing_chain: input.tzap_signing_chain.iter().filter(|path| !path.is_empty()).map(PathBuf::from).collect(),
        }),
        _ => None,
    }
}

fn create_verify_supported(_format: CreateArchiveFormat) -> bool {
    true
}

fn apply_create_verification(
    summary: &mut JobTerminalSummary,
    destination: &Path,
    password: Option<String>,
    sink: &mut dyn jobs::JobEventSink,
) {
    match test_archive(TestArchiveRequest {
        archive_path: destination.to_string_lossy().to_string(),
        password,
        selected_paths: Vec::new(),
    }) {
        Ok(report) => {
            summary.verified = Some(true);
            summary.verified_entries = Some(report.tested_entries);
            summary.verified_bytes = Some(report.tested_bytes);
            summary.warnings.extend(report.warnings);
        }
        Err(error) => {
            let error = bridge_error_from_mobile(error);
            summary.verified = Some(false);
            summary.warnings.push(error.clone());
            sink.emit(CoreJobEvent::Warning {
                message: format!("Created archive verification failed: {}", error.message),
            });
        }
    }
}

fn mobile_create_job_kind(format: CreateArchiveFormat) -> MobileJobKind {
    match format {
        CreateArchiveFormat::Zip => MobileJobKind::ZipCreate,
        CreateArchiveFormat::SevenZ => MobileJobKind::SevenZCreate,
        CreateArchiveFormat::TarZst => MobileJobKind::TarZstdCreate,
        CreateArchiveFormat::Tzap => MobileJobKind::TzapCreate,
    }
}

fn create_format_label(format: CreateArchiveFormat) -> &'static str {
    match format {
        CreateArchiveFormat::Zip => "ZIP",
        CreateArchiveFormat::SevenZ => "7z",
        CreateArchiveFormat::TarZst => "TAR.ZST",
        CreateArchiveFormat::Tzap => "TZAP",
    }
}

fn map_manifest_file_type(file_type: ManifestFileType) -> ArchiveEntryKind {
    match file_type {
        ManifestFileType::File => ArchiveEntryKind::File,
        ManifestFileType::Directory => ArchiveEntryKind::Directory,
        ManifestFileType::Symlink => ArchiveEntryKind::Symlink,
        ManifestFileType::Other => ArchiveEntryKind::Special,
    }
}

fn sanitize_password(password: Option<String>) -> Option<String> {
    password.filter(|value| !value.is_empty())
}

fn password_ref(password: &Option<String>) -> Option<&str> {
    password.as_deref().filter(|value| !value.is_empty())
}

fn mobile_extract_job_kind(path: &Path, format: ArchiveFormat) -> MobileJobKind {
    match core_extract_job_kind(path, format) {
        CoreJobKind::ZipCreate => MobileJobKind::ZipCreate,
        CoreJobKind::ZipExtract => MobileJobKind::ZipExtract,
        CoreJobKind::SevenZCreate => MobileJobKind::SevenZCreate,
        CoreJobKind::SevenZExtract => MobileJobKind::SevenZExtract,
        CoreJobKind::RarExtract => MobileJobKind::RarExtract,
        CoreJobKind::TarZstdCreate => MobileJobKind::TarZstdCreate,
        CoreJobKind::TarZstdExtract => MobileJobKind::TarZstdExtract,
        CoreJobKind::TzapCreate => MobileJobKind::TzapCreate,
        CoreJobKind::TzapExtract => MobileJobKind::TzapExtract,
        CoreJobKind::AppleArchiveCreate => MobileJobKind::AppleArchiveCreate,
        CoreJobKind::AppleArchiveExtract => MobileJobKind::AppleArchiveExtract,
        CoreJobKind::ArchiveExtract => MobileJobKind::ArchiveExtract,
        CoreJobKind::RawStreamExtract => MobileJobKind::RawStreamExtract,
        CoreJobKind::TarGzCreate => MobileJobKind::TarGzCreate,
    }
}

fn core_extract_job_kind(path: &Path, format: ArchiveFormat) -> CoreJobKind {
    if matches!(format, ArchiveFormat::Zip) {
        CoreJobKind::ZipExtract
    } else if matches!(format, ArchiveFormat::SevenZ) {
        CoreJobKind::SevenZExtract
    } else if matches!(format, ArchiveFormat::Rar | ArchiveFormat::MultipartRar) {
        CoreJobKind::RarExtract
    } else if matches!(format, ArchiveFormat::TarZst) {
        CoreJobKind::TarZstdExtract
    } else if matches!(format, ArchiveFormat::Tzap) {
        CoreJobKind::TzapExtract
    } else if matches!(format, ArchiveFormat::AppleArchive) {
        CoreJobKind::AppleArchiveExtract
    } else if raw_stream_backend::detect_raw_stream_format(path).is_some() {
        CoreJobKind::RawStreamExtract
    } else {
        CoreJobKind::ArchiveExtract
    }
}

fn mobile_job_kind_from_core(kind: CoreJobKind) -> MobileJobKind {
    match kind {
        CoreJobKind::ZipCreate => MobileJobKind::ZipCreate,
        CoreJobKind::ZipExtract => MobileJobKind::ZipExtract,
        CoreJobKind::SevenZCreate => MobileJobKind::SevenZCreate,
        CoreJobKind::SevenZExtract => MobileJobKind::SevenZExtract,
        CoreJobKind::RarExtract => MobileJobKind::RarExtract,
        CoreJobKind::TarZstdCreate => MobileJobKind::TarZstdCreate,
        CoreJobKind::TarZstdExtract => MobileJobKind::TarZstdExtract,
        CoreJobKind::TzapCreate => MobileJobKind::TzapCreate,
        CoreJobKind::TzapExtract => MobileJobKind::TzapExtract,
        CoreJobKind::AppleArchiveCreate => MobileJobKind::AppleArchiveCreate,
        CoreJobKind::AppleArchiveExtract => MobileJobKind::AppleArchiveExtract,
        CoreJobKind::ArchiveExtract => MobileJobKind::ArchiveExtract,
        CoreJobKind::RawStreamExtract => MobileJobKind::RawStreamExtract,
        CoreJobKind::TarGzCreate => MobileJobKind::TarGzCreate,
    }
}

fn mobile_event_from_core_event(event: CoreJobEvent) -> MobileJobEvent {
    match event {
        CoreJobEvent::Started { kind, total_bytes } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::Started,
            job_kind: Some(mobile_job_kind_from_core(kind)),
            path: None,
            bytes: None,
            total_bytes,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        },
        CoreJobEvent::EntryStarted { path, bytes } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::EntryStarted,
            job_kind: None,
            path: Some(path),
            bytes,
            total_bytes: None,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        },
        CoreJobEvent::BytesProcessed { path, bytes, total_bytes_processed, .. } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::BytesProcessed,
            job_kind: None,
            path,
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: Some(total_bytes_processed),
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        },
        CoreJobEvent::EntryFinished { path, bytes } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::EntryFinished,
            job_kind: None,
            path: Some(path),
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        },
        CoreJobEvent::Warning { message } => {
            let error = bridge_warning(message.clone());
            MobileJobEvent {
                sequence: 0,
                event_type: MobileJobEventKind::Warning,
                job_kind: None,
                path: None,
                bytes: None,
                total_bytes: None,
                total_bytes_processed: None,
                entries: None,
                total_entries: None,
                message: Some(message),
                error: Some(error),
            }
        }
        CoreJobEvent::Completed { entries, bytes } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::Completed,
            job_kind: None,
            path: None,
            bytes: Some(bytes),
            total_bytes: None,
            total_bytes_processed: None,
            entries: Some(usize_to_u64(entries)),
            total_entries: None,
            message: None,
            error: None,
        },
        CoreJobEvent::Failed { message } => {
            let error = BridgeError {
                code: ERROR_OPERATION_FAILED.to_string(),
                message: message.clone(),
                recovery_hint: None,
                severity: BridgeSeverity::Error,
                retryable: false,
            };
            MobileJobEvent {
                sequence: 0,
                event_type: MobileJobEventKind::Failed,
                job_kind: None,
                path: None,
                bytes: None,
                total_bytes: None,
                total_bytes_processed: None,
                entries: None,
                total_entries: None,
                message: Some(message),
                error: Some(error),
            }
        }
        CoreJobEvent::Cancelled { message } => cancelled_event(message),
        CoreJobEvent::PhaseStarted { .. } | CoreJobEvent::PhaseBytesProcessed { .. } => MobileJobEvent {
            sequence: 0,
            event_type: MobileJobEventKind::Started,
            job_kind: None,
            path: None,
            bytes: None,
            total_bytes: None,
            total_bytes_processed: None,
            entries: None,
            total_entries: None,
            message: None,
            error: None,
        },
    }
}

fn completed_event_from_summary(summary: &JobTerminalSummary) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Completed,
        job_kind: None,
        path: None,
        bytes: Some(summary.written_bytes),
        total_bytes: None,
        total_bytes_processed: None,
        entries: Some(summary.written_entries),
        total_entries: None,
        message: None,
        error: None,
    }
}

fn failed_event(error: BridgeError) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Failed,
        job_kind: None,
        path: None,
        bytes: None,
        total_bytes: None,
        total_bytes_processed: None,
        entries: None,
        total_entries: None,
        message: Some(error.message.clone()),
        error: Some(error),
    }
}

fn cancelled_event(message: String) -> MobileJobEvent {
    MobileJobEvent {
        sequence: 0,
        event_type: MobileJobEventKind::Cancelled,
        job_kind: None,
        path: None,
        bytes: None,
        total_bytes: None,
        total_bytes_processed: None,
        entries: None,
        total_entries: None,
        message: Some(message),
        error: Some(BridgeError {
            code: ERROR_CANCELLED.to_string(),
            message: "Job was cancelled.".to_string(),
            recovery_hint: None,
            severity: BridgeSeverity::Info,
            retryable: true,
        }),
    }
}

fn test_raw_stream(
    path: &Path,
    format: raw_stream_backend::RawStreamFormat,
    selected_paths: &[String],
) -> Result<TestArchiveReport, ZmanagerGuiError> {
    let synthetic_entry = raw_stream_backend::output_name_for_raw_stream(path, format)
        .unwrap_or_else(|| format_label(classify_archive_path(path).0).to_string());

    if !selected_path_matches(selected_paths, &synthetic_entry) {
        return Ok(TestArchiveReport { tested_entries: 0, skipped_entries: 1, tested_bytes: 0, warnings: Vec::new() });
    }

    let tested_bytes = raw_stream_backend::test_raw_stream(path, format).map_err(map_raw_stream_error)?;

    Ok(TestArchiveReport { tested_entries: 1, skipped_entries: 0, tested_bytes, warnings: Vec::new() })
}

fn sanitize_selected_paths(selected_paths: Vec<String>) -> Vec<String> {
    selected_paths.into_iter().map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).collect()
}

fn selected_path_matches(selected_paths: &[String], entry_path: &str) -> bool {
    selected_paths.is_empty() || selected_paths.iter().any(|value| value == entry_path)
}

fn ensure_non_empty_entry_path(value: String) -> Result<String, ZmanagerGuiError> {
    if value.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "entryPath cannot be empty",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    Ok(value)
}

fn ensure_destination_root_path(value: String) -> Result<String, ZmanagerGuiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationRoot cannot be empty",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    if value.contains("://") {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationRoot must be an app-controlled filesystem path",
            hint("Resolve provider destinations to app-controlled staging before calling the Rust bridge."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let path = Path::new(&value);
    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationRoot must point to a directory when it already exists",
            None,
            BridgeSeverity::Warning,
            false,
        )),
        Ok(_) => Ok(value),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(value),
        Err(source) => Err(map_io_error(path.to_path_buf(), source)),
    }
}

fn ensure_existing_source_paths(values: Vec<String>) -> Result<Vec<String>, ZmanagerGuiError> {
    if values.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "sourcePaths cannot be empty",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| ensure_existing_source_path(value, &format!("sourcePaths[{index}]")))
        .collect()
}

fn ensure_existing_source_path(value: String, field: &str) -> Result<String, ZmanagerGuiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} cannot be empty"),
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    if value.contains("://") {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} must be an app-controlled filesystem path"),
            hint("Copy provider-backed files into app cache before calling the Rust bridge."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let path = Path::new(&value);
    fs::metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            bridge_error(
                ERROR_NOT_FOUND,
                format!("{field} does not exist"),
                hint("Choose sources that have already been copied into app-controlled storage."),
                BridgeSeverity::Warning,
                false,
            )
        } else {
            map_io_error(path.to_path_buf(), source)
        }
    })?;

    Ok(value)
}

fn ensure_destination_archive_path(value: String) -> Result<String, ZmanagerGuiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationArchivePath cannot be empty",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    if value.contains("://") {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationArchivePath must be an app-controlled filesystem path",
            hint("Use an app-controlled staging path for archive creation, then let the native shell commit it."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let path = Path::new(&value);
    if path.parent().is_none_or(|parent| parent.as_os_str().is_empty()) {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationArchivePath must include a parent directory",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    if let Some(parent) = path.parent() {
        match fs::metadata(parent) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(bridge_error(
                    ERROR_INVALID_REQUEST,
                    "destinationArchivePath parent must be a directory",
                    None,
                    BridgeSeverity::Warning,
                    false,
                ));
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(bridge_error(
                    ERROR_NOT_FOUND,
                    "destinationArchivePath parent does not exist",
                    hint("Create the app-controlled staging directory before calling the bridge."),
                    BridgeSeverity::Warning,
                    false,
                ));
            }
            Err(source) => return Err(map_io_error(parent.to_path_buf(), source)),
        }
    }

    if let Ok(metadata) = fs::metadata(path)
        && metadata.is_dir()
    {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            "destinationArchivePath must point to an archive file, not a directory",
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    Ok(value)
}

fn usize_from_u64(value: u64, field: &str) -> Result<usize, ZmanagerGuiError> {
    usize::try_from(value).map_err(|_| {
        bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} is too large for this device"),
            None,
            BridgeSeverity::Warning,
            false,
        )
    })
}

fn ensure_existing_file_path(value: String, field: &str) -> Result<String, ZmanagerGuiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} cannot be empty"),
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    if value.contains("://") {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} must be an app-controlled filesystem path"),
            hint("Copy provider-backed files into app cache before calling the Rust bridge."),
            BridgeSeverity::Warning,
            false,
        ));
    }

    let path = Path::new(&value);
    let metadata = fs::metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            bridge_error(
                ERROR_NOT_FOUND,
                format!("{field} does not exist"),
                hint("Choose an archive that has already been copied into app-controlled storage."),
                BridgeSeverity::Warning,
                false,
            )
        } else {
            map_io_error(path.to_path_buf(), source)
        }
    })?;

    if !metadata.is_file() {
        return Err(bridge_error(
            ERROR_INVALID_REQUEST,
            format!("{field} must point to a file"),
            None,
            BridgeSeverity::Warning,
            false,
        ));
    }

    Ok(value)
}

fn classify_archive_path(path: &Path) -> (ArchiveFormat, Vec<BridgeError>) {
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();

    let format = if matches!(extension.as_str(), "zip" | "zipx" | "jar" | "war" | "ipa" | "apk" | "appx" | "xpi") {
        ArchiveFormat::Zip
    } else if is_split_zip_extension(&extension) {
        ArchiveFormat::SplitZip
    } else if extension == "rar" {
        if file_name.contains(".part") { ArchiveFormat::MultipartRar } else { ArchiveFormat::Rar }
    } else if is_rar_sidecar_extension(&extension) {
        ArchiveFormat::MultipartRar
    } else if extension == "7z" {
        ArchiveFormat::SevenZ
    } else if extension == "tar" {
        ArchiveFormat::Tar
    } else if matches!(extension.as_str(), "tgz") || file_name.ends_with(".tar.gz") {
        ArchiveFormat::TarGz
    } else if matches!(extension.as_str(), "tbz" | "tbz2") || file_name.ends_with(".tar.bz2") {
        ArchiveFormat::TarBz2
    } else if matches!(extension.as_str(), "txz") || file_name.ends_with(".tar.xz") {
        ArchiveFormat::TarXz
    } else if extension == "tzst" || file_name.ends_with(".tar.zst") {
        ArchiveFormat::TarZst
    } else if extension == "gz" {
        ArchiveFormat::Gzip
    } else if extension == "bz2" {
        ArchiveFormat::Bzip2
    } else if extension == "xz" {
        ArchiveFormat::Xz
    } else if extension == "zst" {
        ArchiveFormat::Zstd
    } else if extension == "tzap" {
        ArchiveFormat::Tzap
    } else if extension == "aar" {
        ArchiveFormat::AppleArchive
    } else if extension == "xip" {
        ArchiveFormat::Xip
    } else if matches!(extension.as_str(), "lzma" | "lz" | "br" | "lz4" | "lzo" | "z" | "lrz") {
        ArchiveFormat::RawStream
    } else {
        ArchiveFormat::Other
    };

    (format, Vec::new())
}

fn format_capabilities(format: ArchiveFormat) -> (bool, bool, bool) {
    match format {
        ArchiveFormat::Xip => (false, false, false),
        ArchiveFormat::AppleArchive => (true, true, false),
        ArchiveFormat::Rar | ArchiveFormat::MultipartRar | ArchiveFormat::SplitZip => (true, true, false),
        ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::TarZst | ArchiveFormat::Tzap => (true, true, true),
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarBz2
        | ArchiveFormat::TarXz
        | ArchiveFormat::Gzip
        | ArchiveFormat::Bzip2
        | ArchiveFormat::Xz
        | ArchiveFormat::Zstd
        | ArchiveFormat::RawStream
        | ArchiveFormat::Other => (true, true, false),
    }
}

fn format_label(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Zip => "ZIP",
        ArchiveFormat::SplitZip => "Split ZIP",
        ArchiveFormat::Rar => "RAR",
        ArchiveFormat::MultipartRar => "Multipart RAR",
        ArchiveFormat::SevenZ => "7z",
        ArchiveFormat::Tar => "TAR",
        ArchiveFormat::TarGz => "TAR.GZ",
        ArchiveFormat::TarBz2 => "TAR.BZ2",
        ArchiveFormat::TarXz => "TAR.XZ",
        ArchiveFormat::TarZst => "TAR.ZST",
        ArchiveFormat::Gzip => "GZIP",
        ArchiveFormat::Bzip2 => "BZIP2",
        ArchiveFormat::Xz => "XZ",
        ArchiveFormat::Zstd => "Zstd",
        ArchiveFormat::Tzap => "TZAP",
        ArchiveFormat::AppleArchive => "AppleArchive / AAR",
        ArchiveFormat::Xip => "XIP",
        ArchiveFormat::RawStream => "Raw stream",
        ArchiveFormat::Other => "Archive",
    }
}

fn is_split_zip_extension(extension: &str) -> bool {
    let Some(number) = extension.strip_prefix('z') else {
        return false;
    };
    number.len() == 2 && number.chars().all(|value| value.is_ascii_digit())
}

fn is_rar_sidecar_extension(extension: &str) -> bool {
    let Some(number) = extension.strip_prefix('r') else {
        return false;
    };
    number.len() == 2 && number.chars().all(|value| value.is_ascii_digit())
}

fn map_browser_entry_kind(entry: BrowserEntryKind) -> ArchiveEntryKind {
    match entry {
        BrowserEntryKind::File => ArchiveEntryKind::File,
        BrowserEntryKind::Directory => ArchiveEntryKind::Directory,
        BrowserEntryKind::Symlink => ArchiveEntryKind::Symlink,
        BrowserEntryKind::Hardlink => ArchiveEntryKind::Hardlink,
        BrowserEntryKind::Special => ArchiveEntryKind::Special,
    }
}

fn map_archive_browser_error(error: ArchiveBrowserError) -> ZmanagerGuiError {
    match error {
        ArchiveBrowserError::Zip(source) => map_zip_error(source),
        ArchiveBrowserError::TarZst(source) => map_tar_zst_error(source),
        ArchiveBrowserError::SevenZ(source) => map_7z_error(source),
        ArchiveBrowserError::Tzap(source) => map_tzap_error(source),
        ArchiveBrowserError::AppleArchive(source) => map_apple_archive_error(source),
        ArchiveBrowserError::Libarchive(source) => map_libarchive_error(source),
        ArchiveBrowserError::RawStream(source) => map_raw_stream_error(source),
        ArchiveBrowserError::Io { path, source } => map_io_error(path, source),
        ArchiveBrowserError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::UnsupportedEntry { path, .. } => bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            format!("Entry cannot be extracted or previewed here: {path}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::Cancelled | ArchiveBrowserError::UnsupportedOperation(_) => bridge_error(
            ERROR_OPERATION_FAILED,
            "Operation cancelled or unsupported.".to_string(),
            None,
            BridgeSeverity::Warning,
            false,
        ),
    }
}

fn map_plan_error(error: PlanError) -> ZmanagerGuiError {
    match error {
        PlanError::MissingFileName { path } => bridge_error(
            ERROR_INVALID_REQUEST,
            format!("Source path has no archive name: {}", path.display()),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        PlanError::Metadata { path, source } | PlanError::ReadDir { path, source } => map_io_error(path, source),
    }
}

fn map_zip_error(error: ZipBackendError) -> ZmanagerGuiError {
    match error {
        ZipBackendError::PasswordRequired => bridge_error(
            ERROR_PASSWORD_REQUIRED,
            "This ZIP archive is encrypted and requires a password.",
            hint("Enter the archive password."),
            BridgeSeverity::Warning,
            true,
        ),
        ZipBackendError::InvalidPassword => {
            bridge_error(ERROR_INVALID_PASSWORD, "The ZIP password was incorrect.", None, BridgeSeverity::Warning, true)
        }
        ZipBackendError::Io { path, source } => map_io_error(path, source),
        ZipBackendError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        ZipBackendError::UnsupportedSplitZip { .. } => bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            "ZIP split archives are unsupported for this operation in this path.",
            None,
            BridgeSeverity::Warning,
            false,
        ),
        ZipBackendError::Zip(source) => damaged_archive(format!("ZIP archive could not be read: {source}")),
        ZipBackendError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "ZIP job was cancelled.", None, BridgeSeverity::Info, true)
        }
        source => operation_failed(format!("ZIP operation failed: {source}")),
    }
}

fn map_tar_zst_error(error: TarZstdError) -> ZmanagerGuiError {
    match error {
        TarZstdError::Io { path, source } => map_io_error(path, source),
        TarZstdError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        TarZstdError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "TAR/ZST job was cancelled.", None, BridgeSeverity::Info, true)
        }
        source => operation_failed(format!("TAR/ZST operation failed: {source}")),
    }
}

fn map_7z_error(error: SevenZError) -> ZmanagerGuiError {
    match error {
        SevenZError::PasswordRequired => bridge_error(
            ERROR_PASSWORD_REQUIRED,
            "This 7z archive is encrypted and requires a password.",
            hint("Enter the archive password."),
            BridgeSeverity::Warning,
            true,
        ),
        SevenZError::InvalidPassword => {
            bridge_error(ERROR_INVALID_PASSWORD, "The 7z password was incorrect.", None, BridgeSeverity::Warning, true)
        }
        SevenZError::Io { path, source } => map_io_error(path, source),
        SevenZError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        SevenZError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "7z job was cancelled.", None, BridgeSeverity::Info, true)
        }
        source => operation_failed(format!("7z operation failed: {source}")),
    }
}

fn map_tzap_error(error: TzapError) -> ZmanagerGuiError {
    match error {
        TzapError::PasswordRequired => bridge_error(
            ERROR_PASSWORD_REQUIRED,
            "This TZAP archive requires a password.",
            hint("Enter the archive password."),
            BridgeSeverity::Warning,
            true,
        ),
        TzapError::RecipientKeyRequired => bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            "This TZAP archive requires a recipient key that mobile has not been given.",
            None,
            BridgeSeverity::Warning,
            false,
        ),
        TzapError::Format(source) => damaged_archive(format!("TZAP archive could not be verified: {source}")),
        TzapError::X509RootAuth(_) => damaged_archive("TZAP root-auth verification failed."),
        TzapError::KeyWrap(_) => damaged_archive("TZAP recipient key wrapping failed."),
        TzapError::Io { path, source } => map_io_error(path, source),
        TzapError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        TzapError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "TZAP job was cancelled.", None, BridgeSeverity::Info, true)
        }
        source => operation_failed(format!("TZAP operation failed: {source}")),
    }
}

fn map_apple_archive_error(error: AppleArchiveError) -> ZmanagerGuiError {
    match error {
        AppleArchiveError::Plan(source) => map_plan_error(source),
        AppleArchiveError::Native(source) => operation_failed(format!("AppleArchive operation failed: {source}")),
        AppleArchiveError::Io { path, source } => map_io_error(path, source),
        AppleArchiveError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        AppleArchiveError::MissingLinkTarget { path } => {
            damaged_archive(format!("AppleArchive symlink entry has no target: {path}"))
        }
        AppleArchiveError::MissingFileData { path } => {
            damaged_archive(format!("AppleArchive file entry has no data blob: {path}"))
        }
        AppleArchiveError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        AppleArchiveError::StdoutSelectionNotSingleFile { selected_files } => bridge_error(
            ERROR_INVALID_REQUEST,
            format!("AppleArchive stdout extraction needs exactly one file, found {selected_files}."),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        AppleArchiveError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "AppleArchive job was cancelled.", None, BridgeSeverity::Info, true)
        }
    }
}

fn map_rar_error(error: RarBackendError) -> ZmanagerGuiError {
    match error {
        RarBackendError::Io { path, source } => map_io_error(path, source),
        RarBackendError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        RarBackendError::Unrar(source) => {
            let message = source.to_string();
            let lower_message = message.to_ascii_lowercase();
            if lower_message.contains("password") {
                bridge_error(
                    ERROR_INVALID_PASSWORD,
                    "The RAR password was missing or incorrect.",
                    hint("Enter the archive password and try again."),
                    BridgeSeverity::Warning,
                    true,
                )
            } else {
                damaged_archive(format!("RAR archive could not be read: {message}"))
            }
        }
        source => operation_failed(format!("RAR operation failed: {source}")),
    }
}

fn map_libarchive_error(error: LibarchiveError) -> ZmanagerGuiError {
    match error {
        LibarchiveError::Archive(source) => damaged_archive(format!("Archive could not be read: {source}")),
        LibarchiveError::RawStream(source) => map_raw_stream_error(source),
        LibarchiveError::Io { path, source } => map_io_error(path, source),
        LibarchiveError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        LibarchiveError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        LibarchiveError::Cancelled => {
            bridge_error(ERROR_CANCELLED, "Archive job was cancelled.", None, BridgeSeverity::Info, true)
        }
        source => operation_failed(format!("Archive operation failed: {source}")),
    }
}

fn map_raw_stream_error(error: RawStreamError) -> ZmanagerGuiError {
    match error {
        RawStreamError::Io { path, source } => map_io_error(path, source),
        RawStreamError::Safety(source) => bridge_error(
            ERROR_UNSAFE_ARCHIVE,
            format!("Entry blocked by safety policy: {source}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        RawStreamError::ExternalToolUnavailable { tool, .. } => bridge_error(
            ERROR_UNSUPPORTED_FORMAT,
            format!("Required decoder tool is unavailable: {tool}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        RawStreamError::ExternalToolFailed { tool, .. } => {
            damaged_archive(format!("{tool} could not decode this stream."))
        }
        source => operation_failed(format!("Raw stream operation failed: {source}")),
    }
}

fn map_io_error(path: PathBuf, source: io::Error) -> ZmanagerGuiError {
    if source.kind() == io::ErrorKind::NotFound {
        bridge_error(
            ERROR_NOT_FOUND,
            format!("Path not found: {}", path.display()),
            hint("Choose an archive that has already been copied into app-controlled storage."),
            BridgeSeverity::Warning,
            false,
        )
    } else {
        bridge_error(
            ERROR_IO_ERROR,
            format!("I/O failed for {}: {source}", path.display()),
            None,
            BridgeSeverity::Error,
            is_retryable_io_error(source.kind()),
        )
    }
}

fn operation_failed(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_OPERATION_FAILED, message, None, BridgeSeverity::Error, false)
}

fn damaged_archive(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(
        ERROR_DAMAGED_ARCHIVE,
        message,
        hint("Choose a different archive or verify the source file."),
        BridgeSeverity::Warning,
        false,
    )
}

fn cancelled_bridge_error(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_CANCELLED, message, None, BridgeSeverity::Info, true)
}

fn bridge_error_from_mobile(error: ZmanagerGuiError) -> BridgeError {
    match error {
        ZmanagerGuiError::Bridge { code, user_message, recovery_hint, severity, retryable } => {
            BridgeError { code, message: user_message, recovery_hint, severity, retryable }
        }
    }
}

fn bridge_warning(message: impl Into<String>) -> BridgeError {
    bridge_warning_with_code(WARNING_GENERIC, message)
}

fn bridge_warning_with_code(code: impl Into<String>, message: impl Into<String>) -> BridgeError {
    BridgeError {
        code: code.into(),
        message: message.into(),
        recovery_hint: None,
        severity: BridgeSeverity::Warning,
        retryable: false,
    }
}

fn bridge_error(
    code: impl Into<String>,
    message: impl Into<String>,
    recovery_hint: Option<String>,
    severity: BridgeSeverity,
    retryable: bool,
) -> ZmanagerGuiError {
    BridgeError { code: code.into(), message: message.into(), recovery_hint, severity, retryable }.into()
}

fn hint(value: impl Into<String>) -> Option<String> {
    Some(value.into())
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn new_plan_id(prefix: &str) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{prefix}-{}-{now}", std::process::id())
}

fn is_retryable_io_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use zmanager_core::zip_backend::{ZipCreateOptions, create_zip_from_path};

    static JOB_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn healthcheck_reports_real_core() {
        let result = healthcheck();

        assert_eq!(result.engine, "zmanager-core");
        assert!(result.ready);
        assert_eq!(result.status, "ready");
        assert!(result.summary.contains("zmanager-core"));
    }

    #[test]
    fn classify_archive_path_supports_launch_extensions() {
        let cases = [
            ("ARCHIVE.ZIP", ArchiveFormat::Zip),
            ("archive.z01", ArchiveFormat::SplitZip),
            ("archive.part01.rar", ArchiveFormat::MultipartRar),
            ("archive.r02", ArchiveFormat::MultipartRar),
            ("archive.7z", ArchiveFormat::SevenZ),
            ("archive.tar", ArchiveFormat::Tar),
            ("archive.tar.gz", ArchiveFormat::TarGz),
            ("archive.tbz2", ArchiveFormat::TarBz2),
            ("archive.txz", ArchiveFormat::TarXz),
            ("archive.tar.zst", ArchiveFormat::TarZst),
            ("archive.gz", ArchiveFormat::Gzip),
            ("archive.bz2", ArchiveFormat::Bzip2),
            ("archive.xz", ArchiveFormat::Xz),
            ("archive.zst", ArchiveFormat::Zstd),
            ("archive.tzap", ArchiveFormat::Tzap),
            ("archive.aar", ArchiveFormat::AppleArchive),
            ("archive.xip", ArchiveFormat::Xip),
        ];

        for (path, expected) in cases {
            assert_eq!(classify_archive_path(Path::new(path)).0, expected, "{path}");
        }
    }

    #[test]
    fn detect_archive_rejects_platform_uri_objects() {
        let error =
            detect_archive(DetectArchiveRequest { archive_path: "content://downloads/archive.zip".to_string() })
                .unwrap_err();

        assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn detect_archive_classifies_existing_app_controlled_file() {
        let temp = TestDir::new("detect-existing-file");
        temp.write_file("ARCHIVE.ZIP", b"not parsed during detection");

        let result = detect_archive(DetectArchiveRequest {
            archive_path: temp.path("ARCHIVE.ZIP").to_string_lossy().to_string(),
        })
        .expect("detection should classify an existing app-controlled path");

        assert_eq!(result.format, ArchiveFormat::Zip);
        assert_eq!(result.format_label, "ZIP");
        assert!(result.exists);
        assert!(result.is_file);
        assert!(result.can_list);
        assert!(result.can_extract);
        assert!(result.can_create);
    }

    #[test]
    fn detect_archive_returns_normalized_launch_gated_warning() {
        let temp = TestDir::new("detect-launch-gated-warning");
        temp.write_file("archive.aar", b"not parsed during detection");

        let result = detect_archive(DetectArchiveRequest {
            archive_path: temp.path("archive.aar").to_string_lossy().to_string(),
        })
        .expect("detection should classify launch-gated app-controlled path");

        assert_eq!(result.format, ArchiveFormat::AppleArchive);
        assert_eq!(result.warnings.len(), 1);
        let warning = &result.warnings[0];
        assert_eq!(warning.code, WARNING_LAUNCH_GATED_FORMAT);
        assert!(matches!(warning.severity, BridgeSeverity::Warning));
        assert!(!warning.retryable);
    }

    #[test]
    fn list_archive_rejects_missing_path() {
        let error = list_archive(ListArchiveRequest {
            archive_path: "/definitely/missing/archive.zip".to_string(),
            password: None,
        })
        .unwrap_err();

        assert_bridge_error_code(error, ERROR_NOT_FOUND);
    }

    #[test]
    fn list_archive_reads_real_zip_through_core() {
        let temp = TestDir::new("list-archive-real-zip");
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let archive = temp.path("archive.zip");
        create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default())
            .expect("fixture zip should be created through zmanager-core");

        let result =
            list_archive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None })
                .expect("core-backed listing should succeed");

        assert_eq!(result.format, ArchiveFormat::Zip);
        assert!(result.entry_count >= 1);
        assert!(result.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
        assert!(result.total_size.is_some());
    }

    #[test]
    fn test_archive_reads_real_zip_through_core() {
        let fixture = create_test_zip("test-archive-real-zip");

        let result = test_archive(TestArchiveRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            password: None,
            selected_paths: Vec::new(),
        })
        .expect("core-backed archive test should succeed");

        assert_eq!(result.format, ArchiveFormat::Zip);
        assert!(result.verified);
        assert!(result.tested_entries >= 1);
        assert_eq!(result.total_entries, result.tested_entries + result.skipped_entries);
        assert!(result.tested_bytes > 0);
    }

    #[test]
    fn test_archive_honors_selected_entry_filter() {
        let fixture = create_test_zip("test-archive-selected-filter");

        let result = test_archive(TestArchiveRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            password: None,
            selected_paths: vec!["missing.txt".to_string()],
        })
        .expect("skipping all entries is still a successful filtered test");

        assert_eq!(result.tested_entries, 0);
        assert!(result.skipped_entries >= 1);
        assert_eq!(result.total_entries, result.skipped_entries);
        assert_eq!(result.tested_bytes, 0);
    }

    #[test]
    fn test_archive_reports_corrupt_zip_as_damaged_archive() {
        let temp = TestDir::new("test-archive-corrupt-zip");
        temp.write_file("broken.zip", b"this is not a zip archive");

        let error = test_archive(TestArchiveRequest {
            archive_path: temp.path("broken.zip").to_string_lossy().to_string(),
            password: None,
            selected_paths: Vec::new(),
        })
        .unwrap_err();

        assert_bridge_error_code(error, ERROR_DAMAGED_ARCHIVE);
    }

    #[test]
    fn password_helpers_preserve_boundary_whitespace() {
        let password = Some(" secret ".to_string());

        assert_eq!(password_ref(&password), Some(" secret "));
        assert_eq!(sanitize_password(password), Some(" secret ".to_string()));
    }

    #[test]
    fn materialize_preview_extracts_one_entry_to_cleanup_root() {
        let fixture = create_test_zip("materialize-preview-real-zip");
        let entry_path = readme_entry_path(&fixture.archive);

        let result = materialize_preview(MaterializePreviewRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            entry_path: entry_path.clone(),
            password: None,
            strip_components: 0,
        })
        .expect("preview should materialize through zmanager-core");

        let cleanup_root = PathBuf::from(&result.cleanup_root);
        let preview_path = PathBuf::from(&result.preview_path);
        let canonical_cleanup_root = fs::canonicalize(&cleanup_root).expect("cleanup root should exist");
        let canonical_preview_path = fs::canonicalize(&preview_path).expect("preview path should exist");
        assert_eq!(result.entry_path, entry_path);
        assert!(canonical_preview_path.starts_with(&canonical_cleanup_root));
        assert_eq!(
            fs::read_to_string(&preview_path).expect("preview file should be readable"),
            "hello mobile bridge\n"
        );
        assert!(result.written_bytes > 0);

        fs::remove_dir_all(cleanup_root).expect("preview cleanup root should be removable");
    }

    #[test]
    fn materialize_preview_rejects_empty_entry_path() {
        let fixture = create_test_zip("materialize-preview-empty-entry");

        let error = materialize_preview(MaterializePreviewRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            entry_path: String::new(),
            password: None,
            strip_components: 0,
        })
        .unwrap_err();

        assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
    }

    #[test]
    fn plan_extract_returns_write_plan_without_creating_destination() {
        let fixture = create_test_zip("plan-extract-real-zip");
        let destination = fixture.temp.path("out");

        let result = plan_extract(PlanExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: None,
            selected_paths: Vec::new(),
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("planning should succeed without extracting");

        assert!(!destination.exists());
        assert!(result.can_start);
        assert!(result.writable_entries >= 1);
        assert_eq!(result.blocked_entries, 0);
        assert!(result.estimated_bytes.is_some());
        assert!(result.entries.iter().any(|entry| {
            matches!(entry.status, ExtractionPlanEntryStatus::Write)
                && entry.destination_path.as_deref().is_some_and(|path| Path::new(path).starts_with(&destination))
        }));
    }

    #[test]
    fn plan_extract_surfaces_destination_collision_as_blocked_entry() {
        let fixture = create_test_zip("plan-extract-collision");
        let entry_path = readme_entry_path(&fixture.archive);
        let destination = fixture.temp.path("out");
        let colliding_path = destination.join(&entry_path);
        fs::create_dir_all(colliding_path.parent().expect("colliding path should have a parent"))
            .expect("collision parent should be created");
        fs::write(&colliding_path, b"existing").expect("collision file should be written");

        let result = plan_extract(PlanExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: None,
            selected_paths: vec![entry_path.clone()],
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("planning should return a blocked collision row");

        assert_eq!(result.total_entries, 1);
        assert_eq!(result.writable_entries, 0);
        assert_eq!(result.blocked_entries, 1);
        assert!(!result.can_start);
        let blocked = result.entries.first().expect("blocked entry should exist");
        assert_eq!(blocked.archive_path, entry_path);
        assert!(matches!(blocked.status, ExtractionPlanEntryStatus::Block));
        assert!(blocked.reason.as_deref().is_some_and(|reason| reason.contains("would overwrite")));
    }

    #[test]
    fn plan_create_returns_manifest_without_writing_archive() {
        let temp = TestDir::new("plan-create-zip");
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let destination = temp.path("archive.zip");

        let result = plan_create(PlanCreateRequest {
            source_paths: vec![temp.path("project").to_string_lossy().to_string()],
            destination_archive_path: destination.to_string_lossy().to_string(),
            format: CreateArchiveFormat::Zip,
            password: None,
            preserve_metadata: true,
            replace_existing: false,
            clean_source: false,
            verify_after_create: false,
        })
        .expect("create planning should succeed");

        assert!(!destination.exists());
        assert_eq!(result.format, CreateArchiveFormat::Zip);
        assert_eq!(result.format_label, "ZIP");
        assert!(result.can_start);
        assert!(!result.encrypted);
        assert!(result.verify_supported);
        assert!(result.total_entries >= 1);
        assert!(result.total_bytes > 0);
        assert!(result.entries.iter().any(|entry| {
            entry.archive_path.ends_with("readme.txt") && matches!(entry.kind, ArchiveEntryKind::File)
        }));
    }

    #[test]
    fn plan_create_blocks_existing_output_without_replace() {
        let temp = TestDir::new("plan-create-collision");
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let destination = temp.path("archive.zip");
        fs::write(&destination, b"existing").expect("existing destination should be written");

        let result = plan_create(PlanCreateRequest {
            source_paths: vec![temp.path("project").to_string_lossy().to_string()],
            destination_archive_path: destination.to_string_lossy().to_string(),
            format: CreateArchiveFormat::Zip,
            password: None,
            preserve_metadata: true,
            replace_existing: false,
            clean_source: false,
            verify_after_create: false,
        })
        .expect("create planning should surface output collision");

        assert!(result.output_exists);
        assert!(!result.can_start);
        assert!(result.warnings.iter().any(|warning| warning.message.contains("already exists")));
    }

    #[test]
    fn start_extract_job_extracts_zip_and_reports_terminal_summary() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let fixture = create_test_zip("start-extract-real-zip");
        let entry_path = readme_entry_path(&fixture.archive);
        let destination = fixture.temp.path("out");

        let started = start_extract(StartExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: None,
            selected_paths: Vec::new(),
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("extract job should start");

        assert_eq!(started.kind, MobileJobKind::ZipExtract);
        assert_eq!(started.status, MobileJobStatus::Queued);

        let terminal = wait_for_terminal_job(&started.job_id);
        assert_eq!(terminal.status, MobileJobStatus::Completed);
        assert!(terminal.is_terminal);
        assert!(terminal.events.iter().any(|event| {
            matches!(event.event_type, MobileJobEventKind::Started) && event.job_kind == Some(MobileJobKind::ZipExtract)
        }));
        assert!(terminal.events.iter().any(|event| matches!(event.event_type, MobileJobEventKind::Completed)));
        let summary = terminal.terminal_summary.expect("completed job should include a terminal summary");
        assert!(summary.written_entries >= 1);
        assert!(summary.written_bytes > 0);
        assert_eq!(
            fs::read_to_string(destination.join(entry_path)).expect("extracted file should be readable"),
            "hello mobile bridge\n"
        );
    }

    #[test]
    fn start_create_job_creates_zip_and_reports_terminal_summary() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let temp = TestDir::new("start-create-zip");
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let destination = temp.path("archive.zip");

        let started = start_create(StartCreateRequest {
            source_paths: vec![temp.path("project").to_string_lossy().to_string()],
            destination_archive_path: destination.to_string_lossy().to_string(),
            format: CreateArchiveFormat::Zip,
            password: None,
            preserve_metadata: true,
            replace_existing: false,
            clean_source: false,
            verify_after_create: false,
        })
        .expect("create job should start");

        assert_eq!(started.kind, MobileJobKind::ZipCreate);
        let terminal = wait_for_terminal_summary(&started.job_id, |summary| summary.encrypted == Some(false));
        assert_eq!(terminal.status, MobileJobStatus::Completed);
        assert!(destination.exists());
        let summary = terminal.terminal_summary.expect("create job should include a terminal summary");
        assert!(summary.written_entries >= 1);
        assert!(summary.written_bytes > 0);
        assert_eq!(summary.encrypted, Some(false));
        assert_eq!(summary.verified, None);
        assert_eq!(summary.output_paths, vec![destination.to_string_lossy().to_string()]);

        let listing = list_archive(ListArchiveRequest {
            archive_path: destination.to_string_lossy().to_string(),
            password: None,
        })
        .expect("created zip should list through the bridge");
        assert!(listing.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
    }

    #[test]
    fn start_create_job_honors_clean_source_for_zip() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let temp = TestDir::new("start-create-clean-source-zip");
        temp.create_dir("project/src");
        temp.create_dir("project/target");
        temp.write_file("project/src/main.txt", b"keep me\n");
        temp.write_file("project/target/build.bin", b"exclude me\n");
        let destination = temp.path("archive.zip");

        let started = start_create(StartCreateRequest {
            source_paths: vec![temp.path("project").to_string_lossy().to_string()],
            destination_archive_path: destination.to_string_lossy().to_string(),
            format: CreateArchiveFormat::Zip,
            password: None,
            preserve_metadata: true,
            replace_existing: false,
            clean_source: true,
            verify_after_create: false,
        })
        .expect("clean source create job should start");

        let terminal = wait_for_terminal_job(&started.job_id);
        assert_eq!(terminal.status, MobileJobStatus::Completed);

        let listing = list_archive(ListArchiveRequest {
            archive_path: destination.to_string_lossy().to_string(),
            password: None,
        })
        .expect("created clean-source zip should list");
        assert!(listing.entries.iter().any(|entry| entry.path.ends_with("src/main.txt")));
        assert!(!listing.entries.iter().any(|entry| entry.path.contains("/target/")));
    }

    #[test]
    fn start_create_job_preserves_encrypted_zip_password_whitespace() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let temp = TestDir::new("start-create-encrypted-zip");
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let destination = temp.path("archive.zip");
        let password = " secret ";

        let started = start_create(StartCreateRequest {
            source_paths: vec![temp.path("project").to_string_lossy().to_string()],
            destination_archive_path: destination.to_string_lossy().to_string(),
            format: CreateArchiveFormat::Zip,
            password: Some(password.to_string()),
            preserve_metadata: true,
            replace_existing: false,
            clean_source: false,
            verify_after_create: true,
        })
        .expect("encrypted create job should start");

        let terminal = wait_for_terminal_summary(&started.job_id, |summary| summary.verified == Some(true));
        assert_eq!(terminal.status, MobileJobStatus::Completed);
        assert!(!format!("{terminal:?}").contains(password), "job events and summaries must not expose passwords");
        assert_eq!(terminal.terminal_summary.as_ref().and_then(|summary| summary.encrypted), Some(true));
        assert_eq!(terminal.terminal_summary.as_ref().and_then(|summary| summary.verified), Some(true));

        let verified = test_archive(TestArchiveRequest {
            archive_path: destination.to_string_lossy().to_string(),
            password: Some(password.to_string()),
            selected_paths: Vec::new(),
        })
        .expect("created encrypted zip should verify with the exact password");
        assert!(verified.verified);
        assert!(verified.tested_entries >= 1);
    }

    #[test]
    fn start_extract_job_honors_selected_paths() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let fixture = create_test_zip("start-extract-selected-zip");
        let entry_path = readme_entry_path(&fixture.archive);
        let destination = fixture.temp.path("out");

        let started = start_extract(StartExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: None,
            selected_paths: vec![entry_path.clone()],
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("selected extract job should start");

        let terminal = wait_for_terminal_job(&started.job_id);
        assert_eq!(terminal.status, MobileJobStatus::Completed);
        assert!(terminal.events.iter().any(|event| {
            matches!(event.event_type, MobileJobEventKind::EntryStarted)
                && event.path.as_deref() == Some(entry_path.as_str())
        }));
        assert_eq!(
            fs::read_to_string(destination.join(entry_path)).expect("selected file should be extracted"),
            "hello mobile bridge\n"
        );
    }

    #[test]
    fn clear_sensitive_state_removes_retained_terminal_jobs() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let fixture = create_test_zip("clear-sensitive-terminal-job");
        let destination = fixture.temp.path("out");

        let started = start_extract(StartExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: Some(" secret ".to_string()),
            selected_paths: Vec::new(),
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("sensitive extract job should start");
        let terminal = wait_for_terminal_job(&started.job_id);
        assert!(terminal.is_terminal);

        let result = clear_sensitive_state();
        assert!(result.cleared_terminal_jobs >= 1);
        assert_eq!(result.cancel_requested_jobs, 0);

        let error = poll_job_events(PollJobEventsRequest { job_id: started.job_id, cursor: 0 }).unwrap_err();
        assert_bridge_error_code(error, ERROR_NOT_FOUND);
    }

    #[test]
    fn clear_sensitive_state_cancels_and_removes_active_sensitive_jobs() {
        let registry = MobileJobRegistry::default();
        let sensitive_token = CancellationToken::new();
        let regular_token = CancellationToken::new();
        let sensitive_job = registry.create_job(MobileJobKind::ZipExtract, sensitive_token.clone(), true);
        let regular_job = registry.create_job(MobileJobKind::ZipCreate, regular_token.clone(), false);

        let result = registry.clear_sensitive_state();

        assert_eq!(result.cleared_terminal_jobs, 0);
        assert_eq!(result.cancel_requested_jobs, 1);
        assert_eq!(result.retained_active_jobs, 1);
        assert!(sensitive_token.is_cancelled());
        assert!(!regular_token.is_cancelled());

        let sensitive_error =
            registry.poll_events(PollJobEventsRequest { job_id: sensitive_job.job_id, cursor: 0 }).unwrap_err();
        assert_bridge_error_code(sensitive_error, ERROR_NOT_FOUND);

        let regular_result = registry
            .poll_events(PollJobEventsRequest { job_id: regular_job.job_id, cursor: 0 })
            .expect("non-sensitive active job should stay pollable");
        assert_eq!(regular_result.status, MobileJobStatus::Queued);
    }

    #[test]
    fn poll_job_events_uses_sequence_cursor() {
        let _guard = JOB_TEST_LOCK.lock().expect("job test lock poisoned");
        let fixture = create_test_zip("poll-job-cursor");
        let destination = fixture.temp.path("out");

        let started = start_extract(StartExtractRequest {
            archive_path: fixture.archive.to_string_lossy().to_string(),
            destination_root: destination.to_string_lossy().to_string(),
            password: None,
            selected_paths: Vec::new(),
            strip_components: 0,
            collision_policy: ExtractionCollisionPolicy::Refuse,
        })
        .expect("extract job should start");

        let terminal = wait_for_terminal_job(&started.job_id);
        assert!(!terminal.events.is_empty());
        let repeated = poll_job_events(PollJobEventsRequest { job_id: started.job_id, cursor: terminal.next_cursor })
            .expect("polling from the latest cursor should succeed");

        assert!(repeated.events.is_empty());
        assert_eq!(repeated.next_cursor, terminal.next_cursor);
        assert!(repeated.is_terminal);
    }

    #[test]
    fn cancel_job_rejects_unknown_job_id() {
        let error = cancel_job(CancelJobRequest { job_id: "missing-job".to_string() }).unwrap_err();

        assert_bridge_error_code(error, ERROR_NOT_FOUND);
    }

    fn assert_bridge_error_code(error: ZmanagerGuiError, expected: &str) {
        match error {
            ZmanagerGuiError::Bridge { code, .. } => assert_eq!(code, expected),
        }
    }

    fn wait_for_terminal_job(job_id: &str) -> PollJobEventsResult {
        for _ in 0..100 {
            let poll = poll_job_events(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 })
                .expect("job should remain pollable");

            if poll.is_terminal {
                return poll;
            }

            std::thread::sleep(Duration::from_millis(20));
        }

        panic!("job did not finish within the test timeout");
    }

    fn wait_for_terminal_summary(job_id: &str, predicate: impl Fn(&JobTerminalSummary) -> bool) -> PollJobEventsResult {
        for _ in 0..100 {
            let poll = poll_job_events(PollJobEventsRequest { job_id: job_id.to_string(), cursor: 0 })
                .expect("job should remain pollable");

            if poll.is_terminal && poll.terminal_summary.as_ref().is_some_and(&predicate) {
                return poll;
            }

            std::thread::sleep(Duration::from_millis(20));
        }

        panic!("job terminal summary did not settle within the test timeout");
    }

    fn readme_entry_path(archive: &Path) -> String {
        list_archive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None })
            .expect("fixture archive should list")
            .entries
            .into_iter()
            .find(|entry| entry.path.ends_with("readme.txt"))
            .expect("fixture archive should contain readme.txt")
            .path
    }

    fn create_test_zip(name: &str) -> TestArchiveFixture {
        let temp = TestDir::new(name);
        temp.create_dir("project");
        temp.write_file("project/readme.txt", b"hello mobile bridge\n");
        let archive = temp.path("archive.zip");
        create_zip_from_path(temp.path("project"), &archive, &ZipCreateOptions::default())
            .expect("fixture zip should be created through zmanager-core");
        TestArchiveFixture { temp, archive }
    }

    struct TestArchiveFixture {
        temp: TestDir,
        archive: PathBuf,
    }

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let root = std::env::temp_dir().join(format!("zmanager-mobile-{name}-{}-{now}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("test temp root should be created");
            Self { root }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        fn create_dir(&self, relative: &str) {
            fs::create_dir_all(self.path(relative)).expect("test directory should be created");
        }

        fn write_file(&self, relative: &str, contents: &[u8]) {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test parent should be created");
            }
            fs::write(path, contents).expect("test file should be written");
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
