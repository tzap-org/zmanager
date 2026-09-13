//! TZAP portable metadata capture: owner/group resolution, mode and time
//! capture, metadata diagnostic rendering, and symlink/hardlink writing.

use super::TzapError;
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use tzap_core::{ArchiveTimestamp, MetadataDiagnostic, MetadataDiagnosticStatus, MetadataOperation, PortableFileMetadata};

pub(crate) fn system_time_to_archive_timestamp(time: SystemTime) -> Option<ArchiveTimestamp> {
    // tzap-core now owns the §16.7.2 sign-magnitude conversion this host already
    // had right, so `tzap-cli` -- which used a timespec-style borrow and wrote
    // times a second early -- shares it. `None` still means "no encodable
    // timestamp"; the typed reason is available from the core call directly.
    tzap_core::entry_metadata::archive_timestamp_from_system_time(time)
}

#[derive(Default)]
pub(crate) struct CapturedPortableFileMetadata {
    pub(crate) metadata: PortableFileMetadata,
    #[cfg(target_os = "macos")]
    pub(crate) macos_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
}

pub(crate) fn portable_file_metadata(path: &Path) -> Result<CapturedPortableFileMetadata, TzapError> {
    // tzap-core owns portable capture now, so this host and `tzap-cli` assemble
    // the same struct from the same rules instead of each writing their own. It
    // also owns the mid-capture race retry this module used to carry, which had
    // to string-match an upstream error message it did not control.
    let captured = tzap_core::portable_capture::capture_portable_file_metadata(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    Ok(CapturedPortableFileMetadata {
        metadata: captured.metadata,
        #[cfg(target_os = "macos")]
        macos_identity: captured.macos_identity,
    })
}

pub(crate) fn metadata_diagnostic_labels(diagnostics: &[MetadataDiagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "profile={} class={} operation={} status={}: {}",
                diagnostic.profile,
                diagnostic.metadata_class,
                metadata_operation_label(&diagnostic.operation),
                metadata_diagnostic_status_label(&diagnostic.status),
                diagnostic.message
            )
        })
        .collect()
}

fn metadata_operation_label(operation: &MetadataOperation) -> &'static str {
    match operation {
        MetadataOperation::Capture => "capture",
        MetadataOperation::Parse => "parse",
        MetadataOperation::Verify => "verify",
        MetadataOperation::Plan => "plan",
        MetadataOperation::Restore => "restore",
    }
}

fn metadata_diagnostic_status_label(status: &MetadataDiagnosticStatus) -> &'static str {
    match status {
        MetadataDiagnosticStatus::Partial => "partial",
        MetadataDiagnosticStatus::Unsupported => "unsupported",
        MetadataDiagnosticStatus::Skipped => "skipped",
        MetadataDiagnosticStatus::Materialized => "materialized",
        MetadataDiagnosticStatus::Failed => "failed",
    }
}

#[cfg(unix)]
pub(crate) fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    std::os::unix::fs::symlink(target, destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })
}

#[cfg(not(unix))]
pub(crate) fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    Err(TzapError::Io {
        path: destination_path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::Unsupported, "symlink extraction is not supported on this platform"),
    })
}

pub(crate) fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), TzapError> {
    fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io { path: destination_path.to_path_buf(), source })
}
