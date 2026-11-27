//! Archive healthcheck/detect/list/test/materialize ops shared by every FFI
//! consumer. Job orchestration, archive sessions, and extraction/creation
//! planning moved to zmanager-mobile's private `zmanager-mobile-core` /
//! `zmanager-mobile-ffi` crates (Track 12d of zmanager-mobile's
//! docs/mobile-code-health-remediation-plan.md) — they were mobile-only in
//! practice, since desktop never depended on this crate.

use std::path::Path;

use zmanager_core::archive_browser::{self, BrowserExtractOptions};
use zmanager_core::engine::{ArchiveOperation, ArchiveSource, OpenOptions, TestOptions, create_default_engine};

use crate::ffi::error::{WARNING_LAUNCH_GATED_FORMAT, bridge_warning, bridge_warning_with_code, map_archive_browser_error};
use crate::ffi::types::{
    ArchiveEntry, ArchiveEntryKind, ArchiveFormat, BridgeError, DetectArchiveRequest, DetectArchiveResult, FormatDescriptor, HealthcheckResult,
    ListArchiveRequest, ListArchiveResult, ListFormatsResult, MaterializePreviewRequest, MaterializePreviewResult, TestArchiveRequest, TestArchiveResult,
    ZmanagerGuiError,
};
use crate::ffi::util::{
    classify_archive_path, ensure_existing_file_path, ensure_non_empty_entry_path, format_capabilities, format_label, kind_label, map_browser_entry_kind,
    password_ref, usize_from_u64,
};

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

/// Enumerates the full compile-time format capability registry so consumers
/// can present or verify format support without duplicating extension lists
/// or platform predicates.
#[allow(non_snake_case)]
pub fn listFormats() -> ListFormatsResult {
    let engine_snapshot = create_default_engine().ok().map(|engine| engine.capability_snapshot()).unwrap_or_default();
    let mut formats = zmanager_core::archive_format::FORMAT_CAPABILITIES
        .iter()
        .map(|capability| {
            let engine_capability = zmanager_core::engine::FormatId::from_archive_format_kind(capability.kind)
                .and_then(|format| engine_snapshot.iter().find(|snapshot| snapshot.format == format));
            let recognized = !matches!(capability.kind, zmanager_core::archive_format::ArchiveFormatKind::Unknown);
            let platform_available = engine_capability.is_some_and(|snapshot| snapshot.platform_available);
            let unavailable_reason = engine_capability.and_then(|snapshot| snapshot.unavailable_reason.clone());
            let source_access = engine_capability.and_then(|snapshot| snapshot.source_access.map(source_access_label));
            let encryption_supported = engine_capability.is_some_and(|snapshot| snapshot.encryption_supported);
            FormatDescriptor {
                kind: format!("{:?}", capability.kind),
                label: kind_label(capability.kind).to_string(),
                extensions: capability.extensions.iter().map(|suffix| suffix.to_string()).collect(),
                can_list: engine_capability.is_some_and(|snapshot| snapshot.operations.contains(&ArchiveOperation::List)),
                can_extract: engine_capability.is_some_and(|snapshot| snapshot.operations.contains(&ArchiveOperation::Extract)),
                can_create: engine_capability.is_some_and(|snapshot| snapshot.operations.contains(&ArchiveOperation::Create)),
                recognized,
                platform_available,
                unavailable_reason,
                source_access,
                encryption_supported,
            }
        })
        .collect::<Vec<_>>();
    // Unknown is a product-facing detection result, not an engine registry
    // row. Keep it here only for clients that display an explicit
    // unrecognized-format state; it cannot resolve to an engine format or
    // operation.
    formats.push(FormatDescriptor {
        kind: "Unknown".to_owned(),
        label: kind_label(zmanager_core::archive_format::ArchiveFormatKind::Unknown).to_string(),
        extensions: Vec::new(),
        can_list: false,
        can_extract: false,
        can_create: false,
        recognized: false,
        platform_available: false,
        unavailable_reason: Some("unrecognized format".to_owned()),
        source_access: None,
        encryption_supported: false,
    });
    ListFormatsResult { formats }
}

fn source_access_label(source_access: zmanager_core::engine::SourceAccess) -> String {
    match source_access {
        zmanager_core::engine::SourceAccess::Seekable => "seekable",
        zmanager_core::engine::SourceAccess::SequentialOnly => "sequential_only",
        zmanager_core::engine::SourceAccess::MultiVolumeSet => "multi_volume_set",
    }
    .to_owned()
}

#[allow(non_snake_case)]
pub fn detectArchive(request: DetectArchiveRequest) -> Result<DetectArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let path = Path::new(&archive_path);
    let (format, mut warnings) = classify_archive_path(path);
    let (can_list, can_extract, can_create) = format_capabilities(format);

    if matches!(format, ArchiveFormat::Xip) {
        warnings
            .push(bridge_warning_with_code(WARNING_LAUNCH_GATED_FORMAT, "This launch-scope format must be handled by zmanager-core before mobile exposes it."));
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
pub fn listArchive(request: ListArchiveRequest) -> Result<ListArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let password = password_ref(&request.password);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);

    let listing = {
        let engine = create_default_engine().map_err(crate::ffi::error::map_archive_engine_error)?;
        let mut handle = engine
            .open(
                ArchiveSource::from_path_autodetect(path),
                OpenOptions { password: password.map(ToOwned::to_owned), recipient_key: None, ..Default::default() },
            )
            .map_err(crate::ffi::error::map_archive_engine_error)?;
        let listing = handle.list().map_err(crate::ffi::error::map_archive_engine_error)?;
        handle.close().map_err(crate::ffi::error::map_archive_engine_error)?;
        listing
    };

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
            link_target: entry.link_target,
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
pub fn testArchive(request: TestArchiveRequest) -> Result<TestArchiveResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let selected_paths = sanitize_selected_paths(request.selected_paths);
    let path = Path::new(&archive_path);
    let (format, _warnings) = classify_archive_path(path);
    let password = password_ref(&request.password);
    let engine = create_default_engine().map_err(crate::ffi::error::map_archive_engine_error)?;
    let mut handle = engine
        .open(ArchiveSource::from_path_autodetect(path), OpenOptions { password: password.map(str::to_owned), recipient_key: None, ..Default::default() })
        .map_err(crate::ffi::error::map_archive_engine_error)?;
    let report = TestArchiveReport::from_engine(
        handle.test(&TestOptions { selected_paths, ..TestOptions::default() }).map_err(crate::ffi::error::map_archive_engine_error)?,
    );
    handle.close().map_err(crate::ffi::error::map_archive_engine_error)?;

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
pub fn materializePreview(request: MaterializePreviewRequest) -> Result<MaterializePreviewResult, ZmanagerGuiError> {
    let archive_path = ensure_existing_file_path(request.archive_path, "archivePath")?;
    let entry_path = ensure_non_empty_entry_path(request.entry_path)?;
    let strip_components = usize_from_u64(request.strip_components, "stripComponents")?;
    let password = password_ref(&request.password);

    let options = BrowserExtractOptions { password, strip_components, ..BrowserExtractOptions::default() };

    let report = archive_browser::preview_entry_with_options(Path::new(&archive_path), &entry_path, options).map_err(map_archive_browser_error)?;

    Ok(MaterializePreviewResult {
        archive_path,
        entry_path,
        cleanup_root: report.cleanup_root.to_string_lossy().to_string(),
        preview_path: report.preview_path.to_string_lossy().to_string(),
        written_bytes: report.written_bytes,
        warnings: Vec::new(),
    })
}

pub(crate) fn sanitize_selected_paths(selected_paths: Vec<String>) -> Vec<String> {
    selected_paths.into_iter().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty()).collect()
}

pub(crate) struct TestArchiveReport {
    pub(crate) tested_entries: u64,
    pub(crate) skipped_entries: u64,
    pub(crate) tested_bytes: u64,
    pub(crate) warnings: Vec<BridgeError>,
}

impl TestArchiveReport {
    pub(crate) fn from_engine(report: zmanager_core::engine::TestReport) -> Self {
        Self {
            tested_entries: report.tested_entries,
            skipped_entries: report.skipped_entries,
            tested_bytes: report.tested_bytes,
            warnings: report.warnings.into_iter().map(bridge_warning).collect(),
        }
    }

    pub(crate) fn total_entries(&self) -> u64 {
        self.tested_entries.saturating_add(self.skipped_entries)
    }
}
