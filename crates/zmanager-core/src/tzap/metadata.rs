//! TZAP portable metadata capture: owner/group resolution, mode and time
//! capture, metadata diagnostic rendering, and symlink/hardlink writing.

use super::TzapError;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::{
    ArchiveTimestamp, MetadataDiagnostic, MetadataDiagnosticStatus, MetadataOperation, PortableFileMetadata, PortableModeOrigin, PortablePosixOwner,
};

pub(crate) fn system_time_to_archive_timestamp(time: SystemTime) -> Option<ArchiveTimestamp> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Some(ArchiveTimestamp::new(i64::try_from(duration.as_secs()).ok()?, duration.subsec_nanos())),
        Err(error) => {
            let duration = error.duration();
            if duration.as_secs() == 0 && duration.subsec_nanos() != 0 {
                return None;
            }
            Some(ArchiveTimestamp::new(i64::try_from(-i128::from(duration.as_secs())).ok()?, duration.subsec_nanos()))
        }
    }
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
    let metadata = fs::symlink_metadata(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    let source_os = source_os_label().to_owned();
    let created = metadata.created().ok().and_then(system_time_to_archive_timestamp).or({
        // std cannot expose the birth time on musl targets (statx/STATX_BTIME
        // is unsupported there), so fall back to ctime from the standard stat
        // fields as an approximation of creation time.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            Some(ArchiveTimestamp::new(metadata.ctime(), u32::try_from(metadata.ctime_nsec()).unwrap_or(0)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    });
    let accessed = metadata.accessed().ok().and_then(system_time_to_archive_timestamp);

    #[cfg(target_os = "macos")]
    let captured_macos = tzap_core::macos_metadata::capture_macos_metadata(path, metadata.file_type().is_symlink())
        .map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;

    #[cfg(target_os = "macos")]
    let native = captured_macos.native;
    #[cfg(target_os = "linux")]
    let native = tzap_core::linux_metadata::capture_linux_metadata(path, metadata.file_type().is_symlink())
        .map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    #[cfg(windows)]
    let native = tzap_core::windows_metadata::capture_windows_metadata(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    #[cfg(all(not(target_os = "macos"), not(target_os = "linux"), not(windows)))]
    let native = tzap_core::NativeFileMetadata::default();

    #[cfg(unix)]
    let posix_owner = Some(portable_posix_owner(&metadata));
    #[cfg(not(unix))]
    let posix_owner = portable_posix_owner(&metadata);

    #[cfg(windows)]
    let attributes = Some(portable_file_attributes(&metadata));
    #[cfg(not(windows))]
    let attributes = None;

    Ok(CapturedPortableFileMetadata {
        metadata: PortableFileMetadata {
            source_os,
            source_filesystem: "unknown".to_owned(),
            mode_origin: if cfg!(unix) { PortableModeOrigin::Native } else { PortableModeOrigin::Projected },
            posix_owner,
            attributes,
            created,
            accessed,
            native,
        },
        #[cfg(target_os = "macos")]
        macos_identity: Some(captured_macos.identity),
    })
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn resolve_posix_name<Structure>(
    mut call: impl FnMut(*mut Structure, *mut libc::c_char, usize, *mut *mut Structure) -> libc::c_int,
    name_field: impl Fn(*const Structure) -> *const libc::c_char,
) -> Option<String> {
    use std::ffi::CStr;

    let mut buffer = vec![0u8; 1024];
    let mut structure = std::mem::MaybeUninit::uninit();
    let mut result = std::ptr::null_mut();
    let res = call(structure.as_mut_ptr(), buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len(), &raw mut result);
    if res == 0 && !result.is_null() {
        let structure = unsafe { structure.assume_init() };
        let name = name_field(&raw const structure);
        if !name.is_null() {
            let cstr = unsafe { CStr::from_ptr(name) };
            let bytes = cstr.to_bytes();
            if !bytes.is_empty() {
                return Some(String::from_utf8_lossy(bytes).into_owned());
            }
        }
    }
    None
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn resolve_uname(uid: u32) -> Option<String> {
    resolve_posix_name(
        |structure, buffer, capacity, result| unsafe { libc::getpwuid_r(uid as libc::uid_t, structure, buffer, capacity, result) },
        |structure| unsafe { (*structure).pw_name },
    )
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn resolve_gname(gid: u32) -> Option<String> {
    resolve_posix_name(
        |structure, buffer, capacity, result| unsafe { libc::getgrgid_r(gid as libc::gid_t, structure, buffer, capacity, result) },
        |structure| unsafe { (*structure).gr_name },
    )
}

#[cfg(unix)]
fn portable_posix_owner(metadata: &fs::Metadata) -> PortablePosixOwner {
    use std::os::unix::fs::MetadataExt;

    let uid = metadata.uid();
    let gid = metadata.gid();

    PortablePosixOwner { uid: u64::from(uid), gid: u64::from(gid), uname: resolve_uname(uid), gname: resolve_gname(gid) }
}

#[cfg(not(unix))]
fn portable_posix_owner(_metadata: &fs::Metadata) -> Option<PortablePosixOwner> {
    None
}

#[cfg(windows)]
fn portable_file_attributes(metadata: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    let attributes = metadata.file_attributes();
    let mut projection = 0u32;
    // Bit 0: READONLY  (FILE_ATTRIBUTE_READONLY = 0x1)
    // Bit 1: HIDDEN    (FILE_ATTRIBUTE_HIDDEN   = 0x2)
    // Bit 2: SYSTEM    (FILE_ATTRIBUTE_SYSTEM   = 0x4)
    // Bit 3: ARCHIVE   (FILE_ATTRIBUTE_ARCHIVE  = 0x20)
    projection |= u32::from(attributes & 0x0000_0001 != 0);
    projection |= u32::from(attributes & 0x0000_0002 != 0) << 1;
    projection |= u32::from(attributes & 0x0000_0004 != 0) << 2;
    projection |= u32::from(attributes & 0x0000_0020 != 0) << 3;
    projection
}

fn source_os_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "solaris") {
        "solaris"
    } else if cfg!(target_family = "unix") {
        "other-unix"
    } else {
        "other"
    }
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
