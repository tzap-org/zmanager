//! TZAP portable metadata capture: owner/group resolution, mode and time
//! capture, metadata diagnostic rendering, and symlink/hardlink writing.

use super::TzapError;
use std::fs;
use std::path::Path;
use tzap_core::{MetadataDiagnostic, PortableFileMetadata};

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
        macos_identity: Some(captured.macos_identity),
    })
}

/// Renders diagnostics for display.
///
/// The spelling of each operation and status comes from `tzap-core`, so this
/// host and `tzap-cli` cannot drift apart on what a diagnostic is called.
pub(crate) fn metadata_diagnostic_labels(diagnostics: &[MetadataDiagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "profile={} class={} operation={} status={}: {}",
                diagnostic.profile,
                diagnostic.metadata_class,
                diagnostic.operation.label(),
                diagnostic.status.label(),
                diagnostic.message
            )
        })
        .collect()
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
