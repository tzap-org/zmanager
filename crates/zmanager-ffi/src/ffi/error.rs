//! Error-code constants and the backend-error → `ZmanagerGuiError` mapping.

use std::io;
use std::path::PathBuf;

use zmanager_core::archive_browser::ArchiveBrowserError;
use zmanager_core::engine::{ArchiveError, ErrorKind};

use crate::ffi::types::{BridgeError, BridgeSeverity, ZmanagerGuiError};
#[cfg(feature = "tzap-online")]
use crate::ffi::util::ensure_existing_tzap_archive_path;
#[cfg(feature = "localsend")]
use zmanager_localsend::LocalSendBridgeError;

pub(crate) const ERROR_INVALID_REQUEST: &str = "invalid_request";
pub(crate) const ERROR_NOT_FOUND: &str = "not_found";
pub(crate) const ERROR_PASSWORD_REQUIRED: &str = "password_required";
pub(crate) const ERROR_INVALID_PASSWORD: &str = "invalid_password";
pub(crate) const ERROR_UNSAFE_ARCHIVE: &str = "unsafe_archive";
pub(crate) const ERROR_IO_ERROR: &str = "io_error";
pub(crate) const ERROR_UNSUPPORTED_FORMAT: &str = "unsupported_format";
pub(crate) const ERROR_DAMAGED_ARCHIVE: &str = "damaged_archive";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_CANCELLED: &str = "cancelled";
pub(crate) const ERROR_OPERATION_FAILED: &str = "operation_failed";
pub(crate) const WARNING_GENERIC: &str = "warning";
pub(crate) const WARNING_LAUNCH_GATED_FORMAT: &str = "launch_gated_format";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_LOCALSEND_PROTOCOL: &str = "localsend_protocol_error";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_LOCALSEND_NO_RECEIVER: &str = "localsend_no_receiver";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_LOCALSEND_RECEIVER_RUNNING: &str = "localsend_receiver_running";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_LOCALSEND_UNKNOWN_REQUEST: &str = "localsend_unknown_request";
#[cfg(feature = "localsend")]
pub(crate) const ERROR_LOCALSEND_UNKNOWN_SEND: &str = "localsend_unknown_send";
#[cfg(feature = "tzap-online")]
pub(crate) const ERROR_TZAP_OPERATION_FAILED: &str = "tzap_operation_failed";

/// Turns a path-validation error into the JSON error envelope the tzap
/// service endpoints use, since they are declared without `[Throws]`.
#[cfg(feature = "tzap-online")]
pub(crate) fn return_tzap_error(error: ZmanagerGuiError) -> String {
    let message = match error {
        ZmanagerGuiError::Bridge { user_message, .. } => user_message,
    };
    format!("{{\"ok\":false,\"message\":{}}}", serde_json::to_string(&message).unwrap_or_default())
}

/// Validates an existing archive path for the tzap service endpoints and
/// returns it, or the JSON error envelope as `Err` on validation failure.
/// The service endpoints are declared without `[Throws]`, so callers must
/// return the envelope as the function value instead of continuing with it.
#[cfg(feature = "tzap-online")]
pub(crate) fn existing_archive_path_or_tzap_error(value: String) -> Result<String, String> {
    ensure_existing_tzap_archive_path(value, "archivePath").map_err(return_tzap_error)
}

pub(crate) fn map_archive_browser_error(error: ArchiveBrowserError) -> ZmanagerGuiError {
    match error {
        ArchiveBrowserError::Engine { source, .. } => map_archive_engine_error(source),
        ArchiveBrowserError::Io { path, source } => map_io_error(path, source),
        ArchiveBrowserError::Safety(source) => {
            bridge_error(ERROR_UNSAFE_ARCHIVE, format!("Entry blocked by safety policy: {source}"), None, BridgeSeverity::Warning, false)
        }
        ArchiveBrowserError::EntryNotFound { path } => bridge_error(
            ERROR_NOT_FOUND,
            format!("Archive entry not found: {path}"),
            hint("Open a different archive or choose a different entry."),
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::EntrySkipped { path } => bridge_error(
            ERROR_OPERATION_FAILED,
            format!("Archive entry was skipped by the strip-components policy: {path}"),
            None,
            BridgeSeverity::Warning,
            false,
        ),
        ArchiveBrowserError::UnsupportedEntry { path, .. } => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, format!("Entry cannot be extracted or previewed here: {path}"), None, BridgeSeverity::Warning, false)
        }
        ArchiveBrowserError::Cancelled => bridge_error(ERROR_OPERATION_FAILED, "Operation cancelled.".to_string(), None, BridgeSeverity::Warning, true),
        ArchiveBrowserError::UnsupportedOperation(message) => bridge_error(ERROR_UNSUPPORTED_FORMAT, message, None, BridgeSeverity::Warning, false),
    }
}

pub(crate) fn map_archive_engine_error(error: ArchiveError) -> ZmanagerGuiError {
    let message = error.message;
    match error.kind {
        ErrorKind::PasswordRequired => bridge_error(ERROR_PASSWORD_REQUIRED, message, hint("Enter the archive password."), BridgeSeverity::Warning, true),
        ErrorKind::WrongPassword => bridge_error(ERROR_INVALID_PASSWORD, message, None, BridgeSeverity::Warning, true),
        ErrorKind::SafetyViolation => bridge_error(ERROR_UNSAFE_ARCHIVE, message, None, BridgeSeverity::Warning, false),
        ErrorKind::Io => map_io_error(error.path.unwrap_or_default(), io::Error::other(message)),
        ErrorKind::CorruptData => damaged_archive(message),
        ErrorKind::InvalidFormat | ErrorKind::UnsupportedOperation | ErrorKind::ResourceLimitExceeded | ErrorKind::SourceChanged => {
            bridge_error(ERROR_UNSUPPORTED_FORMAT, message, None, BridgeSeverity::Warning, false)
        }
        ErrorKind::Cancelled => bridge_error(ERROR_OPERATION_FAILED, message, None, BridgeSeverity::Warning, true),
    }
}

#[cfg(feature = "localsend")]
pub(crate) fn map_localsend_error(error: LocalSendBridgeError) -> ZmanagerGuiError {
    match error {
        LocalSendBridgeError::LocalSend(source) => bridge_error(ERROR_LOCALSEND_PROTOCOL, source.to_string(), None, BridgeSeverity::Error, false),
        LocalSendBridgeError::InvalidRequest(message) => bridge_error(ERROR_INVALID_REQUEST, message, None, BridgeSeverity::Warning, false),
        LocalSendBridgeError::NoReceiverRunning => bridge_error(
            ERROR_LOCALSEND_NO_RECEIVER,
            "No LocalSend receiver is running.".to_string(),
            hint("Start the LocalSend receiver before using this action."),
            BridgeSeverity::Warning,
            false,
        ),
        LocalSendBridgeError::ReceiverAlreadyRunning => bridge_error(
            ERROR_LOCALSEND_RECEIVER_RUNNING,
            "A LocalSend receiver is already running.".to_string(),
            hint("Stop the current receiver before starting a new one."),
            BridgeSeverity::Warning,
            false,
        ),
        LocalSendBridgeError::UnknownRequestId(request_id) => {
            bridge_error(ERROR_LOCALSEND_UNKNOWN_REQUEST, format!("Unknown LocalSend transfer request: {request_id}"), None, BridgeSeverity::Warning, false)
        }
        LocalSendBridgeError::Io(source) => bridge_error(ERROR_IO_ERROR, source.to_string(), None, BridgeSeverity::Error, is_retryable_io_error(source.kind())),
        LocalSendBridgeError::SendCancelled => bridge_error(ERROR_CANCELLED, "The send was cancelled.".to_string(), None, BridgeSeverity::Info, true),
        LocalSendBridgeError::UnknownSendId(send_id) => {
            bridge_error(ERROR_LOCALSEND_UNKNOWN_SEND, format!("Unknown LocalSend send: {send_id}"), None, BridgeSeverity::Warning, false)
        }
    }
}

pub(crate) fn map_io_error(path: PathBuf, source: io::Error) -> ZmanagerGuiError {
    if source.kind() == io::ErrorKind::NotFound {
        bridge_error(
            ERROR_NOT_FOUND,
            format!("Path not found: {}", path.display()),
            hint("Choose an archive that has already been copied into app-controlled storage."),
            BridgeSeverity::Warning,
            false,
        )
    } else {
        bridge_error(ERROR_IO_ERROR, format!("I/O failed for {}: {source}", path.display()), None, BridgeSeverity::Error, is_retryable_io_error(source.kind()))
    }
}

pub(crate) fn damaged_archive(message: impl Into<String>) -> ZmanagerGuiError {
    bridge_error(ERROR_DAMAGED_ARCHIVE, message, hint("Choose a different archive or verify the source file."), BridgeSeverity::Warning, false)
}

#[cfg(feature = "tzap-online")]
pub(crate) fn map_tzap_error(message: String) -> ZmanagerGuiError {
    bridge_error(ERROR_TZAP_OPERATION_FAILED, message, None, BridgeSeverity::Warning, false)
}

pub(crate) fn bridge_warning(message: impl Into<String>) -> BridgeError {
    bridge_warning_with_code(WARNING_GENERIC, message)
}

pub(crate) fn bridge_warning_with_code(code: impl Into<String>, message: impl Into<String>) -> BridgeError {
    BridgeError { code: code.into(), message: message.into(), recovery_hint: None, severity: BridgeSeverity::Warning, retryable: false }
}

pub(crate) fn bridge_error(
    code: impl Into<String>,
    message: impl Into<String>,
    recovery_hint: Option<String>,
    severity: BridgeSeverity,
    retryable: bool,
) -> ZmanagerGuiError {
    BridgeError { code: code.into(), message: message.into(), recovery_hint, severity, retryable }.into()
}

pub(crate) fn hint(value: impl Into<String>) -> Option<String> {
    Some(value.into())
}

pub(crate) fn is_retryable_io_error(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_mapping_and_hints() {
        assert!(hint("a hint").is_some());
        assert!(is_retryable_io_error(io::ErrorKind::TimedOut));
        assert!(!is_retryable_io_error(io::ErrorKind::NotFound));

        let warning = bridge_warning("test warning");
        assert!(matches!(warning.severity, BridgeSeverity::Warning));

        let damaged = damaged_archive("corrupt archive");
        match damaged {
            ZmanagerGuiError::Bridge { code, recovery_hint, .. } => {
                assert_eq!(code, ERROR_DAMAGED_ARCHIVE);
                assert!(recovery_hint.is_some());
            }
        }

        let io_not_found = map_io_error(PathBuf::from("missing.zip"), io::Error::new(io::ErrorKind::NotFound, "file not found"));
        match io_not_found {
            ZmanagerGuiError::Bridge { code, recovery_hint, .. } => {
                assert_eq!(code, ERROR_NOT_FOUND);
                assert!(recovery_hint.is_some());
            }
        }

        let io_other = map_io_error(PathBuf::from("other.zip"), io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        match io_other {
            ZmanagerGuiError::Bridge { code, retryable, .. } => {
                assert_eq!(code, ERROR_IO_ERROR);
                assert!(!retryable);
            }
        }
    }
}
