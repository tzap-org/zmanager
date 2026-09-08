//! Public TZAP trust distribution, status, bulk-status, and CRL client helpers.

use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpResponse, TzapAuthHttpTransport};
pub use crate::crl::validate_crl_der_against_manifest;
use crate::crl::{crl_download_to_der, optional_unix_or_rfc3339, parse_crl_manifest};
use crate::document_verification::{
    TzapDocumentVerificationResult, TzapOfflineVerificationOptions, authority_key_identifier, verify_tzap_document_envelope_offline,
};
use crate::http_client::{require_success, send_json_request};
use crate::json_util::{json_object, required_string};
use crate::trust::{self, TzapCertificateStatus, TzapTrustAnchorType, TzapVerificationState};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fmt;
use x509_parser::prelude::{FromDer as _, X509Certificate};

pub const STATUS_FRESHNESS_SKEW_SECONDS: i64 = 5 * 60;
pub const MAX_POSITIVE_STATUS_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub const MIN_BULK_LOOKUPS: usize = 1;
pub const MAX_BULK_LOOKUPS: usize = 100;

#[derive(Debug)]
pub enum TzapStatusClientError {
    Auth(TzapAuthError),
    InvalidJson(serde_json::Error),
    InvalidField { field: &'static str },
    InvalidBulkLookup { reason: &'static str },
    HttpStatus { status_code: u16 },
    CrlValidation { reason: String },
}

impl fmt::Display for TzapStatusClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "status client auth failed: {error}"),
            Self::InvalidJson(error) => write!(f, "status JSON is invalid: {error}"),
            Self::InvalidField { field } => write!(f, "status field is invalid: {field}"),
            Self::InvalidBulkLookup { reason } => {
                write!(f, "bulk status lookup is invalid: {reason}")
            }
            Self::HttpStatus { status_code } => {
                write!(f, "status HTTP request failed with status {status_code}")
            }
            Self::CrlValidation { reason } => write!(f, "CRL validation failed: {reason}"),
        }
    }
}

impl std::error::Error for TzapStatusClientError {}

impl From<TzapAuthError> for TzapStatusClientError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<serde_json::Error> for TzapStatusClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

pub struct TzapStatusClient<'a, T> {
    sign_base_url: String,
    transport: &'a T,
}

impl<'a, T: TzapAuthHttpTransport> TzapStatusClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self { sign_base_url: sign_base_url.into(), transport }
    }

    pub fn status_by_fingerprint(&self, certificate_sha256: &str) -> Result<TzapStatusResponse, TzapStatusClientError> {
        let path = trust::status_certificate_by_fingerprint_path(certificate_sha256)
            .map_err(|_| TzapStatusClientError::InvalidField { field: "certificate_sha256" })?;
        let bytes = self.get_bytes(&path)?;
        TzapStatusResponse::from_json_bytes(&bytes)
    }

    pub fn bulk_status(&self, lookups: &[TzapBulkStatusLookup]) -> Result<Vec<TzapBulkStatusItem>, TzapStatusClientError> {
        validate_bulk_lookups(lookups)?;
        let body = json!({
            "lookups": lookups.iter().map(TzapBulkStatusLookup::to_json).collect::<Vec<_>>(),
        });
        let response = self.send_json(TzapAuthHttpMethod::Post, trust::STATUS_BULK_PATH, Some(body))?;
        parse_bulk_status_response(&response.body, lookups)
    }

    pub fn crl_manifest(&self) -> Result<Vec<TzapCrlManifestEntry>, TzapStatusClientError> {
        let bytes = self.get_bytes(trust::STATUS_CRL_MANIFEST_PATH)?;
        parse_crl_manifest(&bytes)
    }

    pub fn crl_der(&self, issuer_sha256: &str) -> Result<Vec<u8>, TzapStatusClientError> {
        let path = trust::status_crl_pem_path(issuer_sha256).map_err(|_| TzapStatusClientError::InvalidField { field: "issuer_sha256" })?;
        crl_download_to_der(&self.get_bytes(&path)?)
    }

    fn get_bytes(&self, path: &str) -> Result<Vec<u8>, TzapStatusClientError> {
        Ok(self.send_json(TzapAuthHttpMethod::Get, path, None)?.body)
    }

    fn send_json(&self, method: TzapAuthHttpMethod, path: &str, body: Option<Value>) -> Result<TzapAuthHttpResponse, TzapStatusClientError> {
        let response = send_json_request(self.transport, method, &self.sign_base_url, path, None, body)?;
        require_success(response, |status_code, _| TzapStatusClientError::HttpStatus { status_code })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapBulkStatusLookupForm {
    CertificateFingerprint { certificate_sha256: String },
    IssuerSerial { issuer_certificate_sha256: String, serial_number: String },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapBulkStatusLookup {
    pub lookup_id: String,
    pub form: TzapBulkStatusLookupForm,
}

impl TzapBulkStatusLookup {
    #[must_use]
    pub fn by_fingerprint(lookup_id: impl Into<String>, certificate_sha256: impl Into<String>) -> Self {
        Self { lookup_id: lookup_id.into(), form: TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256: certificate_sha256.into() } }
    }

    #[must_use]
    pub fn by_issuer_serial(lookup_id: impl Into<String>, issuer_certificate_sha256: impl Into<String>, serial_number: impl Into<String>) -> Self {
        Self {
            lookup_id: lookup_id.into(),
            form: TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256: issuer_certificate_sha256.into(), serial_number: serial_number.into() },
        }
    }

    fn to_json(&self) -> Value {
        match &self.form {
            TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256 } => json!({
                "lookup_id": self.lookup_id,
                "certificate_sha256": certificate_sha256,
            }),
            TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256, serial_number } => json!({
                "lookup_id": self.lookup_id,
                "issuer_certificate_sha256": issuer_certificate_sha256,
                "serial_number": serial_number,
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapStatusResponse {
    pub status: TzapCertificateStatus,
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub issuer_key_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub not_before_unix_seconds: Option<i64>,
    pub not_after_unix_seconds: Option<i64>,
    pub this_update_unix_seconds: Option<i64>,
    pub next_update_unix_seconds: Option<i64>,
    pub revoked_at_unix_seconds: Option<i64>,
    pub revocation_reason: Option<String>,
    /// Server-derived (S2, mobile-tzap-archive-signing-tracker.md): `Some("supersession")`
    /// only when the server's own renewal path revoked this certificate,
    /// `Some("compromise")` for every other revocation path, `None` from a
    /// server that predates this field or a certificate that was never
    /// revoked. See [`classify_archive_revocation`] for how it is used.
    pub revocation_category: Option<String>,
    pub query: TzapStatusQueryEcho,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TzapContactStatusDisposition {
    VerifiedNow,
    VerifiedOffline,
    Blocked,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TzapContactStatusDecision {
    pub disposition: TzapContactStatusDisposition,
    pub verification_state: &'static str,
    pub missing_status_caveat: bool,
}

/// Applies the shared contact-status policy to an already cryptographically
/// verified contact card. Platform adapters persist only the returned public
/// state; they must not duplicate freshness or terminal-status rules.
#[must_use]
pub fn classify_contact_status(
    offline_verification_state: &str,
    certificate_not_after_unix_seconds: Option<u64>,
    expected_certificate_sha256: &str,
    status: Option<&TzapStatusResponse>,
    verifier_time_unix_seconds: i64,
) -> TzapContactStatusDecision {
    if certificate_not_after_unix_seconds.is_some_and(|not_after| not_after <= verifier_time_unix_seconds.max(0).cast_unsigned()) {
        return TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::Blocked,
            verification_state: "status_expired",
            missing_status_caveat: false,
        };
    }
    if !matches!(offline_verification_state, "valid_now" | "valid_at_trusted_time" | "cryptographically_intact_offline") {
        return TzapContactStatusDecision { disposition: TzapContactStatusDisposition::Blocked, verification_state: "invalid", missing_status_caveat: false };
    }
    let Some(status) = status else {
        return TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::VerifiedOffline,
            verification_state: "cryptographically_intact_offline",
            missing_status_caveat: true,
        };
    };
    if status.certificate_sha256.as_deref() != Some(expected_certificate_sha256) {
        return TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::Blocked,
            verification_state: "status_mismatch",
            missing_status_caveat: false,
        };
    }
    match status.status {
        TzapCertificateStatus::Valid if status.is_fresh_valid_for_valid_now(verifier_time_unix_seconds) => {
            TzapContactStatusDecision { disposition: TzapContactStatusDisposition::VerifiedNow, verification_state: "valid_now", missing_status_caveat: false }
        }
        TzapCertificateStatus::Valid => TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::VerifiedOffline,
            verification_state: "cryptographically_intact_offline",
            missing_status_caveat: true,
        },
        TzapCertificateStatus::Revoked | TzapCertificateStatus::IssuerRevoked => {
            TzapContactStatusDecision { disposition: TzapContactStatusDisposition::Blocked, verification_state: "status_revoked", missing_status_caveat: false }
        }
        TzapCertificateStatus::Suspended | TzapCertificateStatus::IssuerSuspended => TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::Blocked,
            verification_state: "status_suspended",
            missing_status_caveat: false,
        },
        TzapCertificateStatus::Expired | TzapCertificateStatus::NotYetValid => {
            TzapContactStatusDecision { disposition: TzapContactStatusDisposition::Blocked, verification_state: "status_expired", missing_status_caveat: false }
        }
        TzapCertificateStatus::UnknownCertificate
        | TzapCertificateStatus::UnknownIssuer
        | TzapCertificateStatus::MalformedLookup
        | TzapCertificateStatus::UnsupportedLookupForm => TzapContactStatusDecision {
            disposition: TzapContactStatusDisposition::Blocked,
            verification_state: "status_unavailable",
            missing_status_caveat: false,
        },
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDocumentStatusTarget {
    pub certificate_sha256: String,
    pub issuer_certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub serial_number: String,
}

impl TzapDocumentStatusTarget {
    #[must_use]
    pub fn from_envelope(envelope: &crate::document_envelope::TzapDocumentEnvelope) -> Self {
        Self {
            certificate_sha256: envelope.signed_payload.leaf_certificate_sha256.clone(),
            issuer_certificate_sha256: envelope.signed_payload.issuer_certificate_sha256.clone(),
            issuer_key_identifier: envelope.signed_payload.issuer_key_identifier.clone(),
            serial_number: envelope.signed_payload.certificate_serial_number.clone(),
        }
    }
}

#[derive(Debug)]
pub enum TzapArchiveStatusTargetError {
    CertificateParse(String),
    MissingAuthorityKeyIdentifier,
    InvalidSerial,
}

impl fmt::Display for TzapArchiveStatusTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateParse(detail) => write!(f, "archive status target: certificate parse failed: {detail}"),
            Self::MissingAuthorityKeyIdentifier => write!(f, "archive status target: leaf certificate has no Authority Key Identifier extension"),
            Self::InvalidSerial => write!(f, "archive status target: leaf certificate serial number is invalid"),
        }
    }
}

impl std::error::Error for TzapArchiveStatusTargetError {}

/// Status-matching target for a TZAP *archive*'s embedded leaf certificate.
///
/// This is the archive equivalent of [`TzapDocumentStatusTarget`], but with
/// three required fields instead of four (mobile TZAP archive signing plan,
/// D1/Z1): archives are always queried by leaf fingerprint
/// (`status_by_fingerprint`), and a SHA-256 of the DER already uniquely
/// determines the certificate, including its issuer and serial — so
/// `issuer_certificate_sha256` is compared only when the caller supplies it,
/// rather than being required the way [`TzapDocumentStatusTarget`] requires
/// it. That is known for archives this device signed (the local identity
/// catalog stores it) but not for a received archive, which must still be
/// verifiable.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapArchiveStatusTarget {
    pub certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub serial_number: String,
    pub issuer_certificate_sha256: Option<String>,
}

impl TzapArchiveStatusTarget {
    /// Derives the target from a verified leaf certificate's raw DER — the
    /// same bytes carried in `RootAuthFooterV1.signer_identity_bytes` once
    /// the chain has verified. `issuer_certificate_sha256` is `None` unless
    /// the caller already has it from elsewhere (e.g. the local identity
    /// catalog, for an archive this device signed).
    pub fn from_leaf_certificate_der(leaf_certificate_der: &[u8], issuer_certificate_sha256: Option<String>) -> Result<Self, TzapArchiveStatusTargetError> {
        let (remaining, certificate) =
            X509Certificate::from_der(leaf_certificate_der).map_err(|error| TzapArchiveStatusTargetError::CertificateParse(error.to_string()))?;
        if !remaining.is_empty() {
            return Err(TzapArchiveStatusTargetError::CertificateParse("trailing DER bytes".to_owned()));
        }
        let issuer_key_identifier = authority_key_identifier(&certificate).ok_or(TzapArchiveStatusTargetError::MissingAuthorityKeyIdentifier)?;
        let serial_number = trust::canonical_serial_hex(certificate.raw_serial()).map_err(|_| TzapArchiveStatusTargetError::InvalidSerial)?;
        Ok(Self {
            certificate_sha256: trust::sha256_identifier(leaf_certificate_der),
            issuer_key_identifier: URL_SAFE_NO_PAD.encode(issuer_key_identifier),
            serial_number,
            issuer_certificate_sha256,
        })
    }
}

/// The one revocation reason the server itself emits on the renewal path
/// (`CertificateEnrollmentService.revokePredecessor`). Compared by exact
/// string equality — see [`classify_archive_revocation`]. Superseded as the
/// primary signal by [`RENEWAL_REVOCATION_CATEGORY`] (S2) wherever a status
/// response carries the structured field; this remains the fallback for a
/// response or stored record that predates it.
pub const RENEWAL_REVOCATION_REASON: &str = "renewed";

/// The structured `revocation_category` value (S2) the server emits only on
/// its own renewal path — never settable through a revoke request body, so
/// it is trustworthy in a way `revocation_reason` free text is not. See
/// [`classify_archive_revocation`].
pub const RENEWAL_REVOCATION_CATEGORY: &str = "supersession";

/// Outcome of applying revocation-as-early-expiry (Z3/D12) to an archive
/// signature claimed at a given time, against a `status: revoked` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TzapArchiveRevocationOutcome {
    /// The signature was claimed strictly before `revoked_at_unix_seconds`
    /// and the reason is the one the server emits for renewal: treated as an
    /// early expiry dated at the revocation, not a terminal failure.
    BeforeRevocation,
    /// Terminal: either the reason is anything other than exactly `"renewed"`
    /// (including missing, empty, or an unrecognised value), or the claimed
    /// signing time is at or after `revoked_at_unix_seconds`.
    Revoked,
}

/// Classifies a revoked certificate's effect on an archive signature claimed
/// at `signed_at_unix_seconds` (Z3/D12): the lost-card model — signatures
/// before the report stand, signatures after do not — but only when the
/// revocation reason is trustworthy enough to grant that.
///
/// This is a one-entry **allowlist**, not a denylist of compromise reasons,
/// by deliberate design: `revocation_reason` is free-form text supplied by
/// whoever calls the revoke endpoint (`CertificateManagementService.normalizeReason`
/// performs no validation), so it cannot be trusted to *widen* validity.
/// Someone revoking a compromised certificate could pass `"renewed"` to keep
/// their prior signatures verifying. Only `"renewed"` is emitted by the
/// server itself, on the renewal path, so only `"renewed"` is allowlisted —
/// a denylist of known-bad reasons (`"key_compromise"`, etc.) would fail
/// open on any reason nobody anticipated; this fails closed instead.
///
/// Comparison is exact-string and case-sensitive against
/// [`RENEWAL_REVOCATION_REASON`]; `None`, `Some("")`, and every other value
/// — including a value that merely contains "renew" — are all terminal.
///
/// When `revocation_category` is present (S2), it is authoritative and
/// `revocation_reason` is not consulted at all: the category is server-derived
/// and cannot be set through a revoke request, so it does not carry the
/// spoofing risk the reason string does. `revocation_category` is `None` for
/// a status response from a server that predates S2, or a stored record
/// migrated from before it; only then does this fall back to the
/// `revocation_reason` allowlist. Either way this stays an allowlist, not a
/// denylist: an unrecognised category is exactly as terminal as an
/// unrecognised reason.
#[must_use]
pub fn classify_archive_revocation(
    revocation_reason: Option<&str>,
    revocation_category: Option<&str>,
    revoked_at_unix_seconds: i64,
    signed_at_unix_seconds: i64,
) -> TzapArchiveRevocationOutcome {
    let is_supersession = match revocation_category {
        Some(category) => category == RENEWAL_REVOCATION_CATEGORY,
        None => revocation_reason == Some(RENEWAL_REVOCATION_REASON),
    };
    if is_supersession && signed_at_unix_seconds < revoked_at_unix_seconds {
        TzapArchiveRevocationOutcome::BeforeRevocation
    } else {
        TzapArchiveRevocationOutcome::Revoked
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapStatusQueryEcho {
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub serial_number: Option<String>,
}

impl TzapStatusResponse {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TzapStatusClientError> {
        let value: Value = serde_json::from_slice(bytes)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &Value) -> Result<Self, TzapStatusClientError> {
        let object = json_object::<TzapStatusClientError>(value, "object")?;
        let status = required_string::<TzapStatusClientError>(object, "status")?
            .parse::<TzapCertificateStatus>()
            .map_err(|()| TzapStatusClientError::InvalidField { field: "status" })?;
        let query = parse_query_echo(object)?;
        let response = Self {
            status,
            certificate_sha256: optional_string(object, "certificate_sha256")?,
            issuer_certificate_sha256: optional_string(object, "issuer_certificate_sha256")?,
            issuer_key_identifier: optional_string(object, "issuer_key_identifier")?,
            serial_number: optional_string(object, "serial_number")?,
            not_before_unix_seconds: optional_unix_or_rfc3339(object, "not_before_unix_seconds", "not_before", "not_before_unix_seconds")?,
            not_after_unix_seconds: optional_unix_or_rfc3339(object, "not_after_unix_seconds", "not_after", "not_after_unix_seconds")?,
            this_update_unix_seconds: optional_unix_or_rfc3339(object, "this_update_unix_seconds", "this_update", "this_update_unix_seconds")?,
            next_update_unix_seconds: optional_unix_or_rfc3339(object, "next_update_unix_seconds", "next_update", "next_update_unix_seconds")?,
            revoked_at_unix_seconds: optional_unix_or_rfc3339(object, "revoked_at_unix_seconds", "revoked_at", "revoked_at_unix_seconds")?,
            revocation_reason: optional_string(object, "revocation_reason")?,
            revocation_category: optional_string(object, "revocation_category")?,
            query,
        };
        response.validate_shape()?;
        Ok(response)
    }

    #[must_use]
    pub fn is_fresh_valid_for_valid_now(&self, verifier_time_unix_seconds: i64) -> bool {
        if self.status != TzapCertificateStatus::Valid {
            return false;
        }
        let Some(this_update) = self.this_update_unix_seconds else {
            return false;
        };
        let Some(next_update) = self.next_update_unix_seconds else {
            return false;
        };
        this_update <= verifier_time_unix_seconds + STATUS_FRESHNESS_SKEW_SECONDS
            && next_update > verifier_time_unix_seconds - STATUS_FRESHNESS_SKEW_SECONDS
            && next_update > this_update
            && next_update - this_update <= MAX_POSITIVE_STATUS_WINDOW_SECONDS
    }

    fn validate_shape(&self) -> Result<(), TzapStatusClientError> {
        match self.status {
            TzapCertificateStatus::Valid
            | TzapCertificateStatus::Revoked
            | TzapCertificateStatus::Expired
            | TzapCertificateStatus::NotYetValid
            | TzapCertificateStatus::Suspended
            | TzapCertificateStatus::IssuerSuspended
            | TzapCertificateStatus::IssuerRevoked => {
                require_some(self.certificate_sha256.as_ref(), "certificate_sha256")?;
                require_some(self.issuer_certificate_sha256.as_ref(), "issuer_certificate_sha256")?;
                require_some(self.issuer_key_identifier.as_ref(), "issuer_key_identifier")?;
                require_some(self.serial_number.as_ref(), "serial_number")?;
                require_some(self.not_before_unix_seconds.as_ref(), "not_before_unix_seconds")?;
                require_some(self.not_after_unix_seconds.as_ref(), "not_after_unix_seconds")?;
                require_some(self.this_update_unix_seconds.as_ref(), "this_update_unix_seconds")?;
                require_some(self.next_update_unix_seconds.as_ref(), "next_update_unix_seconds")?;
                if self.status == TzapCertificateStatus::Revoked {
                    require_some(self.revoked_at_unix_seconds.as_ref(), "revoked_at_unix_seconds")?;
                    require_some(self.revocation_reason.as_ref(), "revocation_reason")?;
                }
            }
            TzapCertificateStatus::UnknownCertificate
            | TzapCertificateStatus::UnknownIssuer
            | TzapCertificateStatus::MalformedLookup
            | TzapCertificateStatus::UnsupportedLookupForm => {
                require_some(self.this_update_unix_seconds.as_ref(), "this_update_unix_seconds")?;
                require_some(self.next_update_unix_seconds.as_ref(), "next_update_unix_seconds")?;
                if self.certificate_sha256.is_some()
                    || self.issuer_certificate_sha256.is_some()
                    || self.issuer_key_identifier.is_some()
                    || self.serial_number.is_some()
                {
                    return Err(TzapStatusClientError::InvalidField { field: "unknown_leaf_fields" });
                }
                if self.query.certificate_sha256.is_none() && self.query.issuer_certificate_sha256.is_none() {
                    return Err(TzapStatusClientError::InvalidField { field: "query" });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapBulkStatusItem {
    pub lookup_id: String,
    pub response: TzapStatusResponse,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCrlManifestEntry {
    pub crl_scope: String,
    pub crl_url: String,
    pub issuer_certificate_sha256: String,
    pub crl_sha256: String,
    pub crl_number: String,
    pub this_update_unix_seconds: i64,
    pub next_update_unix_seconds: i64,
}

#[must_use]
pub fn online_verification_result_from_status(
    offline: TzapDocumentVerificationResult,
    expected: &TzapDocumentStatusTarget,
    status: &TzapStatusResponse,
    verifier_time_unix_seconds: i64,
) -> TzapDocumentVerificationResult {
    // Report the actual failing stage instead of always blaming the online
    // status: the offline state may itself have failed, the status may be
    // for a different document, or the status may be stale or non-valid.
    if offline.state != TzapVerificationState::CryptographicallyIntactOffline || offline.trust_anchor_type == TzapTrustAnchorType::Untrusted {
        return TzapDocumentVerificationResult {
            state: TzapVerificationState::Invalid,
            reason: Some(offline.reason.clone().unwrap_or_else(|| "offline verification did not establish a valid state".to_owned())),
            ..offline
        };
    }
    if !status_matches_document(expected, status) {
        return TzapDocumentVerificationResult {
            state: TzapVerificationState::Invalid,
            reason: Some("online status does not match the document".to_owned()),
            ..offline
        };
    }
    if !status.is_fresh_valid_for_valid_now(verifier_time_unix_seconds) {
        return TzapDocumentVerificationResult {
            state: TzapVerificationState::Invalid,
            reason: Some(format!("online status is {}", status.status.as_str())),
            ..offline
        };
    }
    TzapDocumentVerificationResult { state: TzapVerificationState::ValidNow, reason: None, ..offline }
}

/// Archive equivalent of `status_matches_document`. See
/// [`TzapArchiveStatusTarget`] for why this compares three required fields
/// plus an optional fourth rather than reusing [`TzapDocumentStatusTarget`].
#[must_use]
pub fn archive_status_matches(expected: &TzapArchiveStatusTarget, status: &TzapStatusResponse) -> bool {
    let leaf_fields_match = status.certificate_sha256.as_deref() == Some(expected.certificate_sha256.as_str())
        && status.issuer_key_identifier.as_deref() == Some(expected.issuer_key_identifier.as_str())
        && status.serial_number.as_deref() == Some(expected.serial_number.as_str())
        && match &expected.issuer_certificate_sha256 {
            Some(expected_issuer) => status.issuer_certificate_sha256.as_deref() == Some(expected_issuer.as_str()),
            None => true,
        };
    // Archives are always queried by leaf fingerprint, so the echo — when
    // present at all — must agree on that fingerprint; an echo carrying
    // other fields instead is a mismatch, not something to ignore.
    let query_matches = match &status.query.certificate_sha256 {
        Some(echoed) => echoed == &expected.certificate_sha256,
        None => status.query.issuer_certificate_sha256.is_none() && status.query.serial_number.is_none(),
    };
    leaf_fields_match && query_matches
}

fn status_matches_document(expected: &TzapDocumentStatusTarget, status: &TzapStatusResponse) -> bool {
    let leaf_fields_match = status.certificate_sha256.as_deref() == Some(expected.certificate_sha256.as_str())
        && status.issuer_certificate_sha256.as_deref() == Some(expected.issuer_certificate_sha256.as_str())
        && status.issuer_key_identifier.as_deref() == Some(expected.issuer_key_identifier.as_str())
        && status.serial_number.as_deref() == Some(expected.serial_number.as_str());
    let query_matches = if status.query.certificate_sha256.is_none() && status.query.issuer_certificate_sha256.is_none() && status.query.serial_number.is_none()
    {
        true
    } else {
        status.query.certificate_sha256.as_deref() == Some(expected.certificate_sha256.as_str())
            || (status.query.issuer_certificate_sha256.as_deref() == Some(expected.issuer_certificate_sha256.as_str())
                && status.query.serial_number.as_deref() == Some(expected.serial_number.as_str()))
    };
    leaf_fields_match && query_matches
}

#[must_use]
pub fn verify_tzap_document_envelope_valid_now(
    envelope: &crate::document_envelope::TzapDocumentEnvelope,
    offline_options: &TzapOfflineVerificationOptions<'_>,
    status: &TzapStatusResponse,
) -> TzapDocumentVerificationResult {
    let offline = verify_tzap_document_envelope_offline(envelope, offline_options);
    let expected = TzapDocumentStatusTarget::from_envelope(envelope);
    online_verification_result_from_status(offline, &expected, status, offline_options.verifier_time_unix_seconds)
}

/// Composes an archive's offline verification result with an online status response (Z6).
///
/// If the offline signature check was not ok, returns the offline result unchanged.
/// If the status response does not match the archive status target, sets `status` to
/// [`crate::engine::tzap::TzapArchiveStatusCheck::Unavailable`].
/// Otherwise, evaluates the status response (fresh valid, revoked as early expiry,
/// or suspended) and updates the status axis, re-deriving the outcome.
///
/// By virtue of [`crate::engine::tzap::TzapArchiveVerificationOutcome::derive`], a staging-anchored archive
/// will never reach `Verified` even with a fresh valid status (capping at `VerifiedWithCaveat`).
#[must_use]
pub fn compose_tzap_archive_verification_with_status(
    mut offline: crate::engine::tzap::TzapArchiveVerification,
    expected: &TzapArchiveStatusTarget,
    status: &TzapStatusResponse,
    verifier_time_unix_seconds: i64,
) -> crate::engine::tzap::TzapArchiveVerification {
    if offline.signature != crate::engine::tzap::TzapArchiveSignatureCheck::Ok {
        return offline;
    }

    if !archive_status_matches(expected, status) {
        offline.status =
            crate::engine::tzap::TzapArchiveStatusCheck::Unavailable { reason: Some("online status does not match archive leaf certificate".to_owned()) };
        offline.outcome =
            crate::engine::tzap::TzapArchiveVerificationOutcome::derive(offline.signature, offline.trust, offline.certificate_time, &offline.status);
        return offline;
    }

    match status.status {
        TzapCertificateStatus::Valid if status.is_fresh_valid_for_valid_now(verifier_time_unix_seconds) => {
            offline.status = crate::engine::tzap::TzapArchiveStatusCheck::FreshValid;
        }
        TzapCertificateStatus::Revoked => {
            let signed_at = offline.signer.as_ref().map_or(0, |s| s.signed_at_unix_seconds);
            let revoked_at = status.revoked_at_unix_seconds.unwrap_or(0);
            match classify_archive_revocation(status.revocation_reason.as_deref(), status.revocation_category.as_deref(), revoked_at, signed_at) {
                TzapArchiveRevocationOutcome::BeforeRevocation => {
                    offline.status = crate::engine::tzap::TzapArchiveStatusCheck::BeforeRevocation {
                        revoked_at_unix_seconds: revoked_at,
                        reason: status.revocation_reason.clone(),
                    };
                }
                TzapArchiveRevocationOutcome::Revoked => {
                    offline.status =
                        crate::engine::tzap::TzapArchiveStatusCheck::Revoked { revoked_at_unix_seconds: revoked_at, reason: status.revocation_reason.clone() };
                }
            }
        }
        TzapCertificateStatus::Suspended => {
            offline.status = crate::engine::tzap::TzapArchiveStatusCheck::Suspended;
        }
        _ => {
            offline.status = crate::engine::tzap::TzapArchiveStatusCheck::Unavailable { reason: Some(format!("online status is {}", status.status.as_str())) };
        }
    }

    offline.outcome = crate::engine::tzap::TzapArchiveVerificationOutcome::derive(offline.signature, offline.trust, offline.certificate_time, &offline.status);
    offline
}

/// Archive equivalent of [`verify_tzap_document_envelope_valid_now`] (Z6).
///
/// Runs offline public-no-key archive verification, extracts the [`TzapArchiveStatusTarget`],
/// and composes the result with the online status response.
///
/// # Errors
///
/// Returns [`crate::engine::tzap::TzapError`] if the archive file cannot be opened.
pub fn verify_tzap_archive_valid_now(
    archive: impl AsRef<std::path::Path>,
    trust: &crate::engine::tzap::TzapX509TrustOptions,
    issuer_certificate_sha256: Option<String>,
    status: &TzapStatusResponse,
    verifier_time_unix_seconds: i64,
) -> Result<crate::engine::tzap::TzapArchiveVerification, crate::engine::tzap::TzapError> {
    let offline = crate::engine::tzap::verify_tzap_archive_public_no_key(archive, trust, verifier_time_unix_seconds)?;
    let Some(signer) = &offline.signer else {
        return Ok(offline);
    };
    let Ok(expected) = TzapArchiveStatusTarget::from_leaf_certificate_der(&signer.leaf_certificate_der, issuer_certificate_sha256) else {
        return Ok(offline);
    };
    Ok(compose_tzap_archive_verification_with_status(offline, &expected, status, verifier_time_unix_seconds))
}

fn validate_bulk_lookups(lookups: &[TzapBulkStatusLookup]) -> Result<(), TzapStatusClientError> {
    if !(MIN_BULK_LOOKUPS..=MAX_BULK_LOOKUPS).contains(&lookups.len()) {
        return Err(TzapStatusClientError::InvalidBulkLookup { reason: "lookup count must be 1-100" });
    }
    let mut ids = HashSet::new();
    for lookup in lookups {
        if !is_printable_ascii(&lookup.lookup_id) || !ids.insert(lookup.lookup_id.as_str()) {
            return Err(TzapStatusClientError::InvalidBulkLookup { reason: "lookup_id must be unique printable ASCII" });
        }
        match &lookup.form {
            TzapBulkStatusLookupForm::CertificateFingerprint { certificate_sha256 } => {
                trust::parse_certificate_sha256(certificate_sha256)
                    .map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "certificate_sha256 is invalid" })?;
            }
            TzapBulkStatusLookupForm::IssuerSerial { issuer_certificate_sha256, serial_number } => {
                trust::parse_issuer_sha256(issuer_certificate_sha256)
                    .map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "issuer_certificate_sha256 is invalid" })?;
                trust::parse_serial_hex(serial_number).map_err(|_| TzapStatusClientError::InvalidBulkLookup { reason: "serial_number is invalid" })?;
            }
        }
    }
    Ok(())
}

fn parse_bulk_status_response(bytes: &[u8], lookups: &[TzapBulkStatusLookup]) -> Result<Vec<TzapBulkStatusItem>, TzapStatusClientError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let root_object = json_object::<TzapStatusClientError>(&value, "object")?;
    let results = root_object.get("results").and_then(Value::as_array).ok_or(TzapStatusClientError::InvalidField { field: "results" })?;
    if results.len() != lookups.len() {
        return Err(TzapStatusClientError::InvalidField { field: "results" });
    }
    results
        .iter()
        .zip(lookups)
        .map(|(item, lookup)| {
            let item_object = json_object::<TzapStatusClientError>(item, "object")?;
            let lookup_id = required_string::<TzapStatusClientError>(item_object, "lookup_id")?;
            if lookup_id != lookup.lookup_id {
                return Err(TzapStatusClientError::InvalidField { field: "lookup_id" });
            }
            let response_value = item_object.get("status_response").ok_or(TzapStatusClientError::InvalidField { field: "status_response" })?;
            Ok(TzapBulkStatusItem { lookup_id: lookup_id.clone(), response: TzapStatusResponse::from_json_value(response_value)? })
        })
        .collect()
}

fn parse_query_echo(response_object: &Map<String, Value>) -> Result<TzapStatusQueryEcho, TzapStatusClientError> {
    let Some(value) = response_object.get("query") else {
        return Ok(TzapStatusQueryEcho::default());
    };
    let query = json_object::<TzapStatusClientError>(value, "object")?;
    Ok(TzapStatusQueryEcho {
        certificate_sha256: optional_string(query, "certificate_sha256")?,
        issuer_certificate_sha256: optional_string(query, "issuer_certificate_sha256")?,
        serial_number: optional_string(query, "serial_number")?,
    })
}

fn optional_string(object: &Map<String, Value>, field: &'static str) -> Result<Option<String>, TzapStatusClientError> {
    object
        .get(field)
        .map(|value| value.as_str().filter(|value| !value.is_empty()).map(str::to_owned).ok_or(TzapStatusClientError::InvalidField { field }))
        .transpose()
}

pub(crate) fn optional_i64(object: &Map<String, Value>, field: &'static str) -> Result<Option<i64>, TzapStatusClientError> {
    object.get(field).map(|value| value.as_i64().ok_or(TzapStatusClientError::InvalidField { field })).transpose()
}

fn require_some<T>(value: Option<&T>, field: &'static str) -> Result<(), TzapStatusClientError> {
    if value.is_some() { Ok(()) } else { Err(TzapStatusClientError::InvalidField { field }) }
}

fn is_printable_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

// See `crate::trust::sha256_identifier` (CR-124).
#[cfg(test)]
mod tests {
    use super::{
        TzapArchiveRevocationOutcome, TzapArchiveStatusTarget, TzapBulkStatusLookup, TzapDocumentStatusTarget, TzapStatusClient, TzapStatusResponse,
        archive_status_matches, classify_archive_revocation, classify_contact_status, compose_tzap_archive_verification_with_status,
        online_verification_result_from_status, validate_bulk_lookups,
    };
    use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport};
    use crate::document_verification::TzapDocumentVerificationResult;
    use crate::trust::{self, TzapCertificateStatus, TzapTrustAnchorType, TzapVerificationState};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};
    use openssl::x509::{X509, X509NameBuilder};
    use serde_json::json;
    use std::cell::RefCell;

    #[test]
    fn status_client_uses_percent_encoded_paths_and_parses_fresh_valid_status() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let transport = FakeStatusTransport::new(vec![json_response(&valid_status(&certificate_sha256))]);
        let client = TzapStatusClient::new("https://sign.example/", &transport);

        let status = client.status_by_fingerprint(&certificate_sha256).unwrap();

        assert_eq!(status.status, TzapCertificateStatus::Valid);
        assert!(status.is_fresh_valid_for_valid_now(1_000));
        assert!(transport.requests()[0].url.contains("sha256%3A"));
    }

    #[test]
    fn contact_status_classifier_preserves_offline_cards_for_missing_or_stale_status() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let status = TzapStatusResponse::from_json_value(&valid_status(&certificate_sha256)).unwrap();
        let fresh = classify_contact_status("valid_now", None, &certificate_sha256, Some(&status), 1_000);
        assert_eq!(fresh.disposition, super::TzapContactStatusDisposition::VerifiedNow);
        let stale = classify_contact_status("valid_now", None, &certificate_sha256, Some(&status), 2_000);
        assert_eq!(stale.disposition, super::TzapContactStatusDisposition::VerifiedOffline);
        assert!(stale.missing_status_caveat);
        let missing = classify_contact_status("valid_now", None, &certificate_sha256, None, 1_000);
        assert_eq!(missing.disposition, super::TzapContactStatusDisposition::VerifiedOffline);
    }

    #[test]
    fn contact_status_classifier_blocks_terminal_or_mismatched_status() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let mut revoked = valid_status(&certificate_sha256);
        revoked["status"] = json!("revoked");
        revoked["revoked_at_unix_seconds"] = json!(950);
        revoked["revocation_reason"] = json!("compromise");
        let revoked = TzapStatusResponse::from_json_value(&revoked).unwrap();
        assert_eq!(
            classify_contact_status("valid_now", None, &certificate_sha256, Some(&revoked), 1_000).disposition,
            super::TzapContactStatusDisposition::Blocked
        );
        let other = trust::format_certificate_sha256(&[0x0b; 32]);
        let mismatched = TzapStatusResponse::from_json_value(&valid_status(&other)).unwrap();
        assert_eq!(classify_contact_status("valid_now", None, &certificate_sha256, Some(&mismatched), 1_000).verification_state, "status_mismatch");
    }

    #[test]
    fn status_response_accepts_server_iso_timestamps() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0a; 32]);
        let mut value = valid_status(&certificate_sha256);
        value.as_object_mut().unwrap().remove("not_before_unix_seconds");
        value.as_object_mut().unwrap().remove("not_after_unix_seconds");
        value.as_object_mut().unwrap().remove("this_update_unix_seconds");
        value.as_object_mut().unwrap().remove("next_update_unix_seconds");
        value["not_before"] = json!("1970-01-01T00:01:40Z");
        value["not_after"] = json!("1970-01-01T00:33:20Z");
        value["this_update"] = json!("1970-01-01T00:15:00Z");
        value["next_update"] = json!("1970-01-01T00:25:00Z");

        let status = TzapStatusResponse::from_json_value(&value).unwrap();

        assert_eq!(status.not_before_unix_seconds, Some(100));
        assert_eq!(status.not_after_unix_seconds, Some(2_000));
        assert_eq!(status.this_update_unix_seconds, Some(900));
        assert_eq!(status.next_update_unix_seconds, Some(1_500));
        assert!(status.is_fresh_valid_for_valid_now(1_000));
    }

    #[test]
    fn status_shapes_reject_stale_unknown_suspended_and_malformed_for_valid_now() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0b; 32]);
        let mut stale = valid_status(&certificate_sha256);
        stale["next_update_unix_seconds"] = json!(600);
        assert!(!TzapStatusResponse::from_json_value(&stale).unwrap().is_fresh_valid_for_valid_now(1_000));

        for status in ["suspended", "issuer_revoked", "revoked", "expired", "not_yet_valid"] {
            let mut value = valid_status(&certificate_sha256);
            value["status"] = json!(status);
            if status == "revoked" {
                value["revoked_at_unix_seconds"] = json!(900);
                value["revocation_reason"] = json!("key_compromise");
            }
            assert!(!TzapStatusResponse::from_json_value(&value).unwrap().is_fresh_valid_for_valid_now(1_000));
        }

        let unknown = json!({
            "status": "unknown_certificate",
            "query": {"certificate_sha256": certificate_sha256},
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_800
        });
        assert_eq!(TzapStatusResponse::from_json_value(&unknown).unwrap().status, TzapCertificateStatus::UnknownCertificate);
        let mut underspecified_unknown = unknown.clone();
        underspecified_unknown.as_object_mut().unwrap().remove("next_update_unix_seconds");
        assert!(TzapStatusResponse::from_json_value(&underspecified_unknown).is_err());

        let malformed = json!({
            "status": "malformed_lookup",
            "query": {"issuer_certificate_sha256": trust::format_issuer_sha256(&[0x0c; 32]), "serial_number": "01"},
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_800
        });
        assert_eq!(TzapStatusResponse::from_json_value(&malformed).unwrap().status, TzapCertificateStatus::MalformedLookup);

        for status in ["unknown_issuer", "unsupported_lookup_form"] {
            let value = json!({
                "status": status,
                "query": {
                    "issuer_certificate_sha256": trust::format_issuer_sha256(&[0x0c; 32]),
                    "serial_number": "01",
                },
                "this_update_unix_seconds": 900,
                "next_update_unix_seconds": 1_800
            });
            assert!(!TzapStatusResponse::from_json_value(&value).unwrap().is_fresh_valid_for_valid_now(1_000));
        }
    }

    #[test]
    fn archive_status_target_extracts_fingerprint_aki_and_serial_from_leaf_der() {
        let (_root_der, leaf_der) = test_root_and_leaf_certificate_der();

        let target = TzapArchiveStatusTarget::from_leaf_certificate_der(&leaf_der, None).unwrap();

        assert_eq!(target.certificate_sha256, trust::sha256_identifier(&leaf_der));
        assert_eq!(target.serial_number, "2A");
        assert!(!target.issuer_key_identifier.is_empty());
        assert!(target.issuer_certificate_sha256.is_none());

        let with_issuer = TzapArchiveStatusTarget::from_leaf_certificate_der(&leaf_der, Some("sha256:known-issuer".to_owned())).unwrap();
        assert_eq!(with_issuer.issuer_certificate_sha256.as_deref(), Some("sha256:known-issuer"));
    }

    #[test]
    fn archive_status_matches_requires_fingerprint_aki_and_serial_agreement() {
        let expected = archive_target_fixture();
        let status = archive_status_response(&expected, None);
        assert!(archive_status_matches(&expected, &status));

        let mut wrong_serial = status.clone();
        wrong_serial.serial_number = Some("FF".to_owned());
        assert!(!archive_status_matches(&expected, &wrong_serial));

        let mut wrong_aki = status.clone();
        wrong_aki.issuer_key_identifier = Some(URL_SAFE_NO_PAD.encode([0xFF; 4]));
        assert!(!archive_status_matches(&expected, &wrong_aki));

        let mut wrong_fingerprint = status;
        wrong_fingerprint.certificate_sha256 = Some(trust::format_certificate_sha256(&[0xEE; 32]));
        assert!(!archive_status_matches(&expected, &wrong_fingerprint));
    }

    #[test]
    fn archive_status_matches_rejects_disagreeing_query_echo() {
        let expected = archive_target_fixture();
        let mut status = archive_status_response(&expected, None);
        status.query.certificate_sha256 = Some(trust::format_certificate_sha256(&[0xAA; 32]));
        assert!(!archive_status_matches(&expected, &status));
    }

    #[test]
    fn archive_status_matches_ignores_missing_local_issuer_fingerprint_for_a_received_archive() {
        // D1/Z1: a received archive has no local-catalog issuer_certificate_sha256.
        // Absence on the *target* must not block matching, even though the
        // server's response includes one.
        let mut expected = archive_target_fixture();
        expected.issuer_certificate_sha256 = None;
        let status = archive_status_response(&expected, Some(trust::format_issuer_sha256(&[0x33; 32])));

        assert!(archive_status_matches(&expected, &status));
    }

    #[test]
    fn archive_status_matches_rejects_disagreeing_local_issuer_fingerprint() {
        // When the target *does* carry a locally-known issuer fingerprint
        // (an archive this device signed), it must agree with the server.
        let mut expected = archive_target_fixture();
        expected.issuer_certificate_sha256 = Some(trust::format_issuer_sha256(&[0x33; 32]));
        let status = archive_status_response(&expected, Some(trust::format_issuer_sha256(&[0x44; 32])));

        assert!(!archive_status_matches(&expected, &status));
    }

    #[test]
    fn revocation_by_renewal_is_early_expiry_only_before_the_revocation_time() {
        // "renewal revokes the predecessor with reason `renewed` and
        // archives signed before it still verify." No revocation_category
        // present here — a server that predates S2 — so this falls back to
        // the revocation_reason allowlist.
        assert_eq!(classify_archive_revocation(Some("renewed"), None, 1_000, 500), TzapArchiveRevocationOutcome::BeforeRevocation);
        // "a signature claimed at or after revoked_at_unix_seconds is
        // revoked for every reason including `renewed`."
        assert_eq!(classify_archive_revocation(Some("renewed"), None, 1_000, 1_000), TzapArchiveRevocationOutcome::Revoked);
        assert_eq!(classify_archive_revocation(Some("renewed"), None, 1_000, 1_500), TzapArchiveRevocationOutcome::Revoked);
    }

    #[test]
    fn revocation_for_any_other_reason_is_terminal_at_any_claimed_signing_time() {
        // "key_compromise invalidates at any claimed signing time."
        assert_eq!(classify_archive_revocation(Some("key_compromise"), None, 1_000, 1), TzapArchiveRevocationOutcome::Revoked);
        assert_eq!(classify_archive_revocation(Some("key_compromise"), None, 1_000, 999), TzapArchiveRevocationOutcome::Revoked);
        // "an unrecognised reason is terminal" — including values that look
        // adjacent to "renewed" but are not an exact match, and the missing
        // or empty cases the server's own free-text field allows.
        for reason in [None, Some(""), Some("user_requested"), Some("Renewed"), Some("renewed "), Some(" renewed"), Some("re-renewed")] {
            assert_eq!(classify_archive_revocation(reason, None, 1_000, 1), TzapArchiveRevocationOutcome::Revoked, "reason {reason:?} must be terminal");
        }
    }

    #[test]
    fn revocation_category_is_authoritative_over_a_mismatched_reason_string() {
        // S2: the structured category, when present, is trusted on its own —
        // it cannot be set through a revoke request the way the reason string
        // can, so a mismatched or absent reason does not override it.
        assert_eq!(classify_archive_revocation(Some("user_requested"), Some("supersession"), 1_000, 500), TzapArchiveRevocationOutcome::BeforeRevocation);
        assert_eq!(classify_archive_revocation(None, Some("supersession"), 1_000, 500), TzapArchiveRevocationOutcome::BeforeRevocation);
        // A present category still respects the revocation-time boundary.
        assert_eq!(classify_archive_revocation(Some("renewed"), Some("supersession"), 1_000, 1_000), TzapArchiveRevocationOutcome::Revoked);
        // A present category of "compromise" is terminal even when the reason
        // string happens to say "renewed" — the category wins, not the text.
        assert_eq!(classify_archive_revocation(Some("renewed"), Some("compromise"), 1_000, 500), TzapArchiveRevocationOutcome::Revoked);
        // An unrecognised category is exactly as terminal as an unrecognised
        // reason — this stays an allowlist, not a denylist.
        assert_eq!(classify_archive_revocation(Some("renewed"), Some("unexpected_future_value"), 1_000, 500), TzapArchiveRevocationOutcome::Revoked);
    }

    fn archive_target_fixture() -> TzapArchiveStatusTarget {
        TzapArchiveStatusTarget {
            certificate_sha256: trust::format_certificate_sha256(&[0x01; 32]),
            issuer_key_identifier: URL_SAFE_NO_PAD.encode([0x02; 20]),
            serial_number: "2A".to_owned(),
            issuer_certificate_sha256: None,
        }
    }

    fn archive_status_response(expected: &TzapArchiveStatusTarget, issuer_certificate_sha256: Option<String>) -> TzapStatusResponse {
        let value = json!({
            "status": "valid",
            "certificate_sha256": expected.certificate_sha256,
            "issuer_certificate_sha256": issuer_certificate_sha256.unwrap_or_else(|| trust::format_issuer_sha256(&[0x02; 32])),
            "issuer_key_identifier": expected.issuer_key_identifier,
            "serial_number": expected.serial_number,
            "not_before_unix_seconds": 100,
            "not_after_unix_seconds": 2_000,
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_500,
            "query": {"certificate_sha256": expected.certificate_sha256},
        });
        TzapStatusResponse::from_json_value(&value).unwrap()
    }

    fn test_root_and_leaf_certificate_der() -> (Vec<u8>, Vec<u8>) {
        let root_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut root_name = X509NameBuilder::new().unwrap();
        root_name.append_entry_by_text("CN", "Archive Status Test Root").unwrap();
        let root_name = root_name.build();
        let mut root_builder = X509::builder().unwrap();
        root_builder.set_version(2).unwrap();
        root_builder.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap()).unwrap();
        root_builder.set_subject_name(&root_name).unwrap();
        root_builder.set_issuer_name(&root_name).unwrap();
        root_builder.set_pubkey(&root_key).unwrap();
        root_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        root_builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        root_builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        let ski = {
            let context = root_builder.x509v3_context(None, None);
            SubjectKeyIdentifier::new().build(&context).unwrap()
        };
        root_builder.append_extension(ski).unwrap();
        root_builder.sign(&root_key, MessageDigest::sha256()).unwrap();
        let root_cert = root_builder.build();

        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut leaf_name = X509NameBuilder::new().unwrap();
        leaf_name.append_entry_by_text("CN", "Archive Status Test Leaf").unwrap();
        let leaf_name = leaf_name.build();
        let mut leaf_builder = X509::builder().unwrap();
        leaf_builder.set_version(2).unwrap();
        leaf_builder.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(0x2A).unwrap()).unwrap()).unwrap();
        leaf_builder.set_subject_name(&leaf_name).unwrap();
        leaf_builder.set_issuer_name(root_cert.subject_name()).unwrap();
        leaf_builder.set_pubkey(&leaf_key).unwrap();
        leaf_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        leaf_builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        let aki = {
            let context = leaf_builder.x509v3_context(Some(root_cert.as_ref()), None);
            AuthorityKeyIdentifier::new().keyid(true).build(&context).unwrap()
        };
        leaf_builder.append_extension(aki).unwrap();
        leaf_builder.sign(&root_key, MessageDigest::sha256()).unwrap();
        let leaf_cert = leaf_builder.build();

        (root_cert.to_der().unwrap(), leaf_cert.to_der().unwrap())
    }

    #[test]
    fn bulk_status_validates_lookup_ids_forms_and_preserves_response_order() {
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0d; 32]);
        let duplicate_target = TzapBulkStatusLookup::by_fingerprint("a", &certificate_sha256);
        let second = TzapBulkStatusLookup::by_fingerprint("b", &certificate_sha256);
        validate_bulk_lookups(&[duplicate_target.clone(), second.clone()]).unwrap();
        assert!(validate_bulk_lookups(&[duplicate_target.clone(), duplicate_target]).is_err());
        assert!(validate_bulk_lookups(&[TzapBulkStatusLookup::by_fingerprint("\n", certificate_sha256.clone())]).is_err());

        let response = json!({
            "results": [
                {"lookup_id": "a", "status_response": valid_status(&certificate_sha256)},
                {"lookup_id": "b", "status_response": valid_status(&certificate_sha256)}
            ]
        });
        let transport = FakeStatusTransport::new(vec![json_response(&response)]);
        let client = TzapStatusClient::new("https://sign.example", &transport);
        let results = client.bulk_status(&[second_lookup("a", &certificate_sha256), second_lookup("b", &certificate_sha256)]).unwrap();

        assert_eq!(results[0].lookup_id, "a");
        assert_eq!(results[1].lookup_id, "b");
        assert_eq!(transport.requests()[0].method, TzapAuthHttpMethod::Post);
    }

    #[test]
    fn online_status_mapping_returns_valid_now_only_for_fresh_valid_status() {
        let offline = TzapDocumentVerificationResult {
            state: TzapVerificationState::CryptographicallyIntactOffline,
            trust_anchor_type: TzapTrustAnchorType::OfficialTzap,
            reason: Some("offline verification has no fresh status proof".to_owned()),
            root_certificate_sha256: None,
            public_metadata: None,
        };
        let certificate_sha256 = trust::format_certificate_sha256(&[0x0e; 32]);
        let expected = TzapDocumentStatusTarget {
            certificate_sha256: certificate_sha256.clone(),
            issuer_certificate_sha256: trust::format_issuer_sha256(&[0x02; 32]),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "01".to_owned(),
        };
        let valid = TzapStatusResponse::from_json_value(&valid_status(&certificate_sha256)).unwrap();
        let valid_now = online_verification_result_from_status(offline.clone(), &expected, &valid, 1_000);
        assert_eq!(valid_now.state, TzapVerificationState::ValidNow);
        assert_eq!(valid_now.reason, None);
        let mismatched = TzapStatusResponse::from_json_value(&valid_status(&trust::format_certificate_sha256(&[0x55; 32]))).unwrap();
        assert_eq!(online_verification_result_from_status(offline.clone(), &expected, &mismatched, 1_000).state, TzapVerificationState::Invalid);

        let mut suspended = valid_status(&certificate_sha256);
        suspended["status"] = json!("suspended");
        let suspended = TzapStatusResponse::from_json_value(&suspended).unwrap();
        assert_eq!(online_verification_result_from_status(offline, &expected, &suspended, 1_000).state, TzapVerificationState::Invalid);
    }

    #[test]
    fn crl_manifest_parses_and_rejects_bad_fields() {
        let issuer_sha256 = trust::format_issuer_sha256(&[0x0f; 32]);
        let manifest = json!({
            "crls": [{
                "crl_scope": trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA,
                "crl_url": trust::status_crl_pem_path(&issuer_sha256).unwrap(),
                "issuer_certificate_sha256": issuer_sha256,
                "crl_number": "01",
                "crl_sha256": trust::format_certificate_sha256(&[0x10; 32]),
                "this_update_unix_seconds": 900,
                "next_update_unix_seconds": 1_200
            }]
        });
        let entries = super::parse_crl_manifest(serde_json::to_string(&manifest).unwrap().as_bytes()).unwrap();
        assert_eq!(entries[0].crl_scope, trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA);

        let iso_manifest = json!({
            "crls": [{
                "crl_scope": trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA,
                "crl_url": trust::status_crl_pem_path(&issuer_sha256).unwrap(),
                "issuer_certificate_sha256": issuer_sha256,
                "crl_number": "01",
                "crl_sha256": trust::format_certificate_sha256(&[0x10; 32]),
                "this_update": "1970-01-01T00:15:00Z",
                "next_update": "1970-01-01T00:20:00Z"
            }]
        });
        let iso_entries = super::parse_crl_manifest(serde_json::to_string(&iso_manifest).unwrap().as_bytes()).unwrap();
        assert_eq!(iso_entries[0].this_update_unix_seconds, 900);
        assert_eq!(iso_entries[0].next_update_unix_seconds, 1_200);

        let mut bad = manifest;
        bad["crls"][0]["next_update_unix_seconds"] = json!(800);
        assert!(super::parse_crl_manifest(serde_json::to_string(&bad).unwrap().as_bytes()).is_err());

        let mut bad_scope = bad.clone();
        bad_scope["crls"][0]["next_update_unix_seconds"] = json!(1_200);
        bad_scope["crls"][0]["crl_scope"] = json!("issuer");
        assert!(super::parse_crl_manifest(serde_json::to_string(&bad_scope).unwrap().as_bytes()).is_err());
    }

    #[test]
    fn crl_download_decodes_pem_endpoint_to_der() {
        let issuer_sha256 = trust::format_issuer_sha256(&[0x11; 32]);
        let transport = FakeStatusTransport::new(vec![TzapAuthHttpResponse { status_code: 200, body: TEST_CRL_PEM.as_bytes().to_vec(), headers: Vec::new() }]);
        let client = TzapStatusClient::new("https://sign.example/", &transport);

        let crl_der = client.crl_der(&issuer_sha256).unwrap();

        assert!(openssl::x509::X509Crl::from_der(&crl_der).is_ok());
        assert!(transport.requests()[0].url.ends_with(&format!("/v1/status/crls/{}/pem", trust::percent_encode_path_param(&issuer_sha256))));
    }

    fn valid_status(certificate_sha256: &str) -> serde_json::Value {
        json!({
            "status": "valid",
            "certificate_sha256": certificate_sha256,
            "issuer_certificate_sha256": trust::format_issuer_sha256(&[0x02; 32]),
            "issuer_key_identifier": "AQIDBA",
            "serial_number": "01",
            "not_before_unix_seconds": 100,
            "not_after_unix_seconds": 2_000,
            "this_update_unix_seconds": 900,
            "next_update_unix_seconds": 1_500,
        })
    }

    fn second_lookup(id: &str, certificate_sha256: &str) -> TzapBulkStatusLookup {
        TzapBulkStatusLookup::by_fingerprint(id, certificate_sha256)
    }

    fn json_response(body: &serde_json::Value) -> TzapAuthHttpResponse {
        TzapAuthHttpResponse { status_code: 200, body: serde_json::to_vec(body).unwrap(), headers: Vec::new() }
    }

    const TEST_CRL_PEM: &str = "-----BEGIN X509 CRL-----\nMIIBajBUAgEBMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRlc3RDQRcNMjYw\nNjI2MDQwOTQ1WhcNMjYwNjI3MDQwOTQ1WqAPMA0wCwYDVR0UBAQCAhAAMA0GCSqG\nSIb3DQEBCwUAA4IBAQBvjtd1d23B5m454FBHAuBiy7Q+BnXBDEK5txSMSe30g9Zt\nm+1/WhHsqMp1biNSyQhVQYwLsJoWimzqcgR4CygJyFaVM3gT1QpN4yFxxs6tmEyi\nAgDD+ngO6GtY+ouzRpsnsrd5g9PTPbchGjjDjbwjCwcqcWY6n7cxMwJc0OBxj6BU\nYaz++TmBFD9a7p3HOL2SJWfSaT4JACRofsmGfiSQa6xBum91/NbVYDtDly8sp8si\n1d4lPYtpBr3r+PKMKEilx+vHOo0kUIOcKQkJx85revQeZhQXRJfPphMn+iJkp8QQ\n6lNu5AzDf/eH7pjDm8htQOlZil25T3BXhEMzc/ts\n-----END X509 CRL-----\n";

    struct FakeStatusTransport {
        responses: RefCell<Vec<TzapAuthHttpResponse>>,
        requests: RefCell<Vec<TzapAuthHttpRequest>>,
    }

    impl FakeStatusTransport {
        fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
            Self { responses: RefCell::new(responses.into_iter().rev().collect()), requests: RefCell::new(Vec::new()) }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeStatusTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses.borrow_mut().pop().ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }

    #[test]
    fn archive_status_composition_caps_staging_below_verified_and_promotes_production() {
        use crate::engine::tzap::{
            TzapArchiveSignatureCheck, TzapArchiveSignerDetails, TzapArchiveStatusCheck, TzapArchiveTimeCheck, TzapArchiveTrustCheck, TzapArchiveVerification,
            TzapArchiveVerificationOutcome,
        };

        let target = archive_target_fixture();
        let status = archive_status_response(&target, None);

        let signer = TzapArchiveSignerDetails {
            subject: "CN=Test".to_owned(),
            display_name: Some("Test".to_owned()),
            organization: None,
            certificate_sha256: [0x01; 32],
            certificate_sha256_hex: target.certificate_sha256.clone(),
            issuer: "CN=Issuer".to_owned(),
            serial_number_hex: target.serial_number.clone(),
            signed_at_unix_seconds: 500,
            leaf_certificate_der: Vec::new(),
        };

        // Production anchor + valid-at-signing + fresh valid -> Verified
        let prod_offline = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            Some(signer.clone()),
            false,
        );
        let prod_verified = compose_tzap_archive_verification_with_status(prod_offline, &target, &status, 1_000);
        assert_eq!(prod_verified.outcome, TzapArchiveVerificationOutcome::Verified);
        assert_eq!(prod_verified.status, TzapArchiveStatusCheck::FreshValid);
        assert_eq!(prod_verified.headline_label(), "Verified Now");

        // Staging anchor + valid-at-signing + fresh valid -> VerifiedWithCaveat (never Verified!)
        let staging_offline = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::StagingRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            Some(signer.clone()),
            false,
        );
        let staging_verified = compose_tzap_archive_verification_with_status(staging_offline, &target, &status, 1_000);
        assert_eq!(staging_verified.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(staging_verified.status, TzapArchiveStatusCheck::FreshValid);
        assert_eq!(staging_verified.headline_label(), "Verified — Test Certificate");

        // Revocation with 'renewed' and signed before revoked_at -> BeforeRevocation -> VerifiedWithCaveat
        let mut revoked_status = archive_status_response(&target, None);
        revoked_status.status = TzapCertificateStatus::Revoked;
        revoked_status.revocation_reason = Some("renewed".to_owned());
        revoked_status.revoked_at_unix_seconds = Some(800);

        let prod_offline2 = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            Some(signer.clone()),
            false,
        );
        let renewed_verified = compose_tzap_archive_verification_with_status(prod_offline2, &target, &revoked_status, 1_000);
        assert_eq!(renewed_verified.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(renewed_verified.status, TzapArchiveStatusCheck::BeforeRevocation { revoked_at_unix_seconds: 800, reason: Some("renewed".to_owned()) });
        assert_eq!(renewed_verified.headline_label(), "Signed Before Revocation");

        // Revocation with 'key_compromise' -> Revoked -> Failed
        let mut compromise_status = archive_status_response(&target, None);
        compromise_status.status = TzapCertificateStatus::Revoked;
        compromise_status.revocation_reason = Some("key_compromise".to_owned());
        compromise_status.revoked_at_unix_seconds = Some(800);

        let prod_offline3 = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            Some(signer.clone()),
            false,
        );
        let compromise_verified = compose_tzap_archive_verification_with_status(prod_offline3, &target, &compromise_status, 1_000);
        assert_eq!(compromise_verified.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(compromise_verified.status, TzapArchiveStatusCheck::Revoked { revoked_at_unix_seconds: 800, reason: Some("key_compromise".to_owned()) });
        assert_eq!(compromise_verified.headline_label(), "Certificate Revoked");

        // Target mismatch leaves status as Unavailable
        let mut mismatched_target = target.clone();
        mismatched_target.serial_number = "999".to_owned();
        let prod_offline4 = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            Some(signer),
            false,
        );
        let mismatched_verified = compose_tzap_archive_verification_with_status(prod_offline4, &mismatched_target, &status, 1_000);
        assert_eq!(mismatched_verified.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert!(matches!(mismatched_verified.status, TzapArchiveStatusCheck::Unavailable { .. }));
        assert_eq!(mismatched_verified.headline_label(), "Signature Valid — Status Not Checked");
    }
}
