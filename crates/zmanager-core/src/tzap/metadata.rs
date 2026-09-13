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
    tzap_core::entry_metadata::archive_timestamp_from_system_time(time).ok()
}

#[derive(Default)]
pub(crate) struct CapturedPortableFileMetadata {
    pub(crate) metadata: PortableFileMetadata,
    #[cfg(target_os = "macos")]
    pub(crate) macos_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
}

const METADATA_CAPTURE_ATTEMPTS: usize = 3;

/// Marker text `tzap-core` uses when a file changed underneath it mid-capture.
///
/// This is a coupling to an upstream error *message*, because `tzap-core`
/// reports the race as `io::Error::other(..)` with no distinguishing kind or
/// typed variant (`macos_metadata.rs` / `linux_metadata.rs`). Nothing here can
/// detect a reword at compile time, and the race is not reproducible on demand,
/// so it cannot be pinned by a test either — `transient_metadata_capture_error`
/// below builds the error rather than provoking it. Treat a `tzap-core` upgrade
/// as a prompt to re-check this string; the durable fix is a typed error
/// upstream.
const METADATA_CAPTURE_RACE_MARKER: &str = "input changed during metadata capture";

/// Returns whether an error is the transient mid-capture race worth retrying.
///
/// Matches on a substring rather than the whole message: `tzap-cli` already
/// reports the same condition as `"<marker>: <path>"`, so an equivalent
/// enrichment reaching `tzap-core` would silently disable this retry under an
/// equality check.
fn is_transient_metadata_capture_race(error: &TzapError) -> bool {
    matches!(error, TzapError::Io { source, .. } if source.to_string().contains(METADATA_CAPTURE_RACE_MARKER))
}

fn with_metadata_capture_retry<T>(mut capture: impl FnMut() -> Result<T, TzapError>) -> Result<T, TzapError> {
    for attempt in 0..METADATA_CAPTURE_ATTEMPTS {
        match capture() {
            Ok(value) => return Ok(value),
            Err(error) if is_transient_metadata_capture_race(&error) && attempt + 1 < METADATA_CAPTURE_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("metadata capture retry loop must return from every attempt")
}

pub(crate) fn portable_file_metadata(path: &Path) -> Result<CapturedPortableFileMetadata, TzapError> {
    with_metadata_capture_retry(|| portable_file_metadata_once(path))
}

fn portable_file_metadata_once(path: &Path) -> Result<CapturedPortableFileMetadata, TzapError> {
    // tzap-core owns portable capture now, so this host and `tzap-cli` assemble
    // the same struct from the same rules instead of each writing their own.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transient_metadata_capture_error() -> TzapError {
        TzapError::Io { path: Path::new("input.txt").to_path_buf(), source: std::io::Error::other(METADATA_CAPTURE_RACE_MARKER) }
    }

    #[test]
    fn transient_metadata_capture_race_is_retried() {
        let mut attempts = 0;
        let result = with_metadata_capture_retry(|| {
            attempts += 1;
            if attempts == 1 { Err(transient_metadata_capture_error()) } else { Ok("captured") }
        });

        assert_eq!(result.unwrap(), "captured");
        assert_eq!(attempts, 2);
    }

    /// `tzap-cli` already reports this condition as `"<marker>: <path>"`. If
    /// that enrichment ever reaches `tzap-core`, the retry must survive it.
    #[test]
    fn enriched_metadata_capture_race_message_is_still_retried() {
        let enriched =
            TzapError::Io { path: Path::new("input.txt").to_path_buf(), source: std::io::Error::other(format!("{METADATA_CAPTURE_RACE_MARKER}: input.txt")) };
        assert!(is_transient_metadata_capture_race(&enriched));
    }

    /// An unrelated I/O failure must not be retried.
    #[test]
    fn unrelated_io_error_is_not_retried() {
        let unrelated = TzapError::Io { path: Path::new("input.txt").to_path_buf(), source: std::io::Error::other("permission denied") };
        assert!(!is_transient_metadata_capture_race(&unrelated));

        let mut attempts = 0;
        let result = with_metadata_capture_retry(|| {
            attempts += 1;
            Err::<(), _>(TzapError::Io { path: Path::new("input.txt").to_path_buf(), source: std::io::Error::other("permission denied") })
        });
        assert!(result.is_err());
        assert_eq!(attempts, 1, "a non-transient error must fail on the first attempt");
    }

    #[test]
    fn persistent_metadata_capture_race_still_fails_after_retry_budget() {
        let mut attempts = 0;
        let result = with_metadata_capture_retry(|| {
            attempts += 1;
            Err::<(), _>(transient_metadata_capture_error())
        });

        assert!(result.is_err());
        assert_eq!(attempts, 3);
    }
}
