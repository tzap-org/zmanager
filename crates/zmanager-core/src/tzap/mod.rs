//! TZAP backend implementation.
//!
//! This module tree owns the protocol implementation. Historical backend
//! facade paths are private implementation aliases; consumers use the
//! engine-owned protocol seam.

mod display;
mod extract;
mod listing;
mod metadata;
mod open;
mod verification;
mod write;
mod x509;

#[cfg(test)]
mod tests;

pub use display::{TzapPublicDisplaySummary, TzapPublicSignatureStatus, inspect_tzap_public_footer_signature, summarize_tzap_public_display};
pub use extract::{
    TzapExtractKeySource, TzapExtractReport, TzapExtractRequest, TzapRestoreOptions, TzapRestorePolicy, copy_tzap_file_to_writer, copy_tzap_files_to_writer,
    extract_tzap,
};
pub(crate) use extract::{TzapSelectedEntry, TzapSelectedExtractRequest, extract_tzap_selected, extract_tzap_with_context};
pub use listing::{
    TzapEntryKind, TzapListing, list_tzap_with_optional_password, list_tzap_with_password, list_tzap_with_recipient_key, list_tzap_with_recipient_key_bytes,
};
pub(crate) use listing::{list_tzap_index_with_optional_password, list_tzap_index_with_recipient_key, list_tzap_index_with_recipient_key_bytes_list};
pub(crate) use open::discover_tzap_input_volume_paths;
pub use open::is_tzap_archive_path;
pub use open::{TzapPublicMetadataSummary, TzapPublicVolumeSummary, has_existing_tzap_input_volume, summarize_tzap_public_metadata};
pub use verification::{
    TzapArchiveSignatureCheck, TzapArchiveSignerDetails, TzapArchiveStatusCheck, TzapArchiveTimeCheck, TzapArchiveTrustCheck, TzapArchiveVerification,
    TzapArchiveVerificationOutcome, verify_tzap_archive_public_no_key, verify_tzap_archive_public_no_key_with_signer_predicate,
};
pub use write::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context, tzap_bootstrap_sidecar_path};
pub(crate) use x509::test_tzap_with_recipient_key_bytes_list_filter_and_x509_trust;
pub use x509::{
    TzapTestReport, TzapX509SignerInspection, TzapX509SigningOptions, TzapX509TrustAnchor, TzapX509TrustOptions, TzapX509VerificationReport,
    inspect_tzap_x509_public_no_key_signer, inspect_tzap_x509_signer, test_tzap_with_optional_password_filter_and_x509_trust, test_tzap_with_password_filter,
    test_tzap_with_password_filter_and_x509_trust, test_tzap_with_recipient_key_bytes_filter_and_x509_trust,
    test_tzap_with_recipient_key_filter_and_x509_trust, verify_tzap_x509_public_no_key,
};
pub use x509::{resolve_default_signing_certificate_id, tzap_x509_signing_options_from_inventory};

/// `.tzap` backend error.
#[derive(Debug)]
pub enum TzapError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Archive format, cryptographic, or metadata validation failed.
    Format(FormatError),
    /// X.509 `RootAuth` signing or verification failed.
    X509RootAuth(String),
    /// X.509 recipient key wrapping failed.
    KeyWrap(String),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A passphrase-protected `.tzap` archive was opened without a password.
    PasswordRequired,
    /// A recipient-wrapped `.tzap` archive was opened without a recipient private key.
    RecipientKeyRequired,
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TzapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "{source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Format(source) => write!(f, "{source}"),
            Self::X509RootAuth(message) | Self::KeyWrap(message) => write!(f, "{message}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::PasswordRequired => write!(f, "tzap password required"),
            Self::RecipientKeyRequired => write!(f, "tzap recipient private key required"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TzapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Format(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::X509RootAuth(_) | Self::KeyWrap(_) | Self::PasswordRequired | Self::RecipientKeyRequired | Self::Cancelled => None,
        }
    }
}

impl From<FormatError> for TzapError {
    fn from(source: FormatError) -> Self {
        Self::Format(source)
    }
}

impl From<PlanError> for TzapError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<ExtractionSafetyError> for TzapError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TzapError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

pub(crate) fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> TzapError {
    TzapError::Io { path: path.to_path_buf(), source: io::Error::new(kind, message.into()) }
}

use crate::jobs::JobCancelled;
use crate::manifest::PlanError;
use crate::safety::ExtractionSafetyError;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use tzap_core::format::FormatError;
