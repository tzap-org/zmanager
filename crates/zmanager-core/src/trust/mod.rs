//! Shared TZAP trust constants, status values, endpoint paths, and root pins.
//!
//! The certificate-profile validation lives in
//! [`certificate_profile`](crate::trust::certificate_profile) and the
//! identifier/encoding helpers in [`identifiers`](crate::trust::identifiers);
//! this module re-exports their public items so the crate's API surface is
//! unchanged (CR-137).

use openssl::x509::X509;
use sha2::{Digest as _, Sha256};

mod certificate_profile;
mod identifiers;
pub mod intermediate_cache;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use certificate_profile::{ORG_INTERMEDIATE_PATH_LEN, PLATFORM_LEAF_ONLY_PATH_LEN, PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE, REQUIRED_ROOT_PATH_LEN};
pub use certificate_profile::{
    TzapCertificateProfileError, TzapCertificateProfileOptions, TzapCertificateProfileValidation, TzapCertificatePublicMetadata, TzapOfficialRootPinKind,
    public_intermediate_chain_der, validate_custom_tzap_certificate_chain_der, validate_official_tzap_certificate_chain_der,
};
pub(crate) use identifiers::candidate_chains;
pub use identifiers::{
    TrustIdentifierError, canonical_serial_hex, decode_base64url_no_padding, format_certificate_sha256, format_csr_sha256, format_issuer_sha256,
    format_sha256_identifier, is_valid_base64url_no_padding, is_valid_issuer_key_identifier, is_valid_public_device_id, is_valid_public_org_id,
    is_valid_public_signer_id, is_valid_serial_hex, is_valid_sha256_identifier, parse_certificate_sha256, parse_crl_sha256, parse_csr_sha256,
    parse_issuer_sha256, parse_serial_hex, parse_sha256_identifier, parse_spki_sha256, percent_encode_path_param, sha256_identifier,
    status_certificate_by_fingerprint_path, status_crl_pem_path, validate_base64url_no_padding,
};
pub use intermediate_cache::{
    TzapIntermediateCache, TzapIntermediateCacheError, TzapIntermediateResolveError, TzapIntermediateResolver, extract_authority_key_identifier,
    extract_subject_key_identifier,
};

/// Domain separator used by TZAP document envelopes.
pub const TZAP_DOCUMENT_DOMAIN_SEPARATOR: &str = "TZAP-DOC-SIGNING-v1";

/// Envelope and payload versions.
pub const TZAP_PAYLOAD_VERSION: u16 = 1;
pub const TZAP_ENVELOPE_VERSION: u16 = 1;

/// Canonical digest and algorithm identifiers.
pub const TZAP_PAYLOAD_DIGEST_ALGORITHM: &str = "SHA-256";
pub const TZAP_DOCUMENT_SIGNATURE_ALGORITHM: &str = "ECDSA-P256-SHA256";
pub const TZAP_LEAF_KEY_ALGORITHM: &str = "ECDSA-P256";
pub const TZAP_LEAF_CERTIFICATE_SIGNATURE_ALGORITHM: &str = "ECDSA-P256-SHA256";

/// MVP algorithm allowlists.
pub const TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA: &str = "all_certificates_issued_by_ca";

/// MVP OIDs (numeric UUID-derived arcs).
pub const TZAP_OID_DOCUMENT_SIGNING_EKU: &str = "2.25.201653505380392472132808080578384925035";
pub const TZAP_OID_CA_POLICY: &str = "2.25.216801977638581014157980575261877559132";
pub const TZAP_OID_ORGANIZATION_POLICY: &str = "2.25.317365475553219749193645940235128210";
pub const TZAP_OID_LEAF_POLICY: &str = "2.25.194500518885741369143906285659225836299";
pub const TZAP_OID_METADATA_EXTENSION: &str = "2.25.25754549376475580214508793807157112225";

/// Canonical identifier prefixes and helper values.
pub const SHA256_IDENTIFIER_PREFIX: &str = "sha256:";
pub const SHA256_IDENTIFIER_HEX_LENGTH: usize = 64;

/// Public identifier prefixes.
pub const PUBLIC_SIGNER_ID_PREFIX: &str = "psign_";
pub const PUBLIC_ORG_ID_PREFIX: &str = "porg_";
pub const PUBLIC_DEVICE_ID_PREFIX: &str = "pdev_";

/// Public identifier suffix length bounds (excluding prefix).
pub const PUBLIC_IDENTIFIER_SUFFIX_MIN_LENGTH: usize = 16;
pub const PUBLIC_IDENTIFIER_SUFFIX_MAX_LENGTH: usize = 64;

/// Canonical status values.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapCertificateStatus {
    Valid,
    Revoked,
    Expired,
    NotYetValid,
    Suspended,
    IssuerSuspended,
    IssuerRevoked,
    UnknownCertificate,
    UnknownIssuer,
    MalformedLookup,
    UnsupportedLookupForm,
}

impl TzapCertificateStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Suspended => "suspended",
            Self::IssuerSuspended => "issuer_suspended",
            Self::IssuerRevoked => "issuer_revoked",
            Self::UnknownCertificate => "unknown_certificate",
            Self::UnknownIssuer => "unknown_issuer",
            Self::MalformedLookup => "malformed_lookup",
            Self::UnsupportedLookupForm => "unsupported_lookup_form",
        }
    }
}

impl std::str::FromStr for TzapCertificateStatus {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "valid" => Ok(Self::Valid),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            "not_yet_valid" => Ok(Self::NotYetValid),
            "suspended" => Ok(Self::Suspended),
            "issuer_suspended" => Ok(Self::IssuerSuspended),
            "issuer_revoked" => Ok(Self::IssuerRevoked),
            "unknown_certificate" => Ok(Self::UnknownCertificate),
            "unknown_issuer" => Ok(Self::UnknownIssuer),
            "malformed_lookup" => Ok(Self::MalformedLookup),
            "unsupported_lookup_form" => Ok(Self::UnsupportedLookupForm),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapVerificationState {
    ValidNow,
    ValidAtTrustedTime,
    CryptographicallyIntactOffline,
    /// No verification result is recorded for this certificate.
    ///
    /// Records written before verification-state tracking existed have no
    /// state on disk; they must not be treated as cryptographically
    /// verified (or as failed verification) — only as unknown.
    NotRecorded,
    Invalid,
}

impl TzapVerificationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidNow => "valid_now",
            Self::ValidAtTrustedTime => "valid_at_trusted_time",
            Self::CryptographicallyIntactOffline => "cryptographically_intact_offline",
            Self::NotRecorded => "not_recorded",
            Self::Invalid => "invalid",
        }
    }
}

impl std::str::FromStr for TzapVerificationState {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "valid_now" => Ok(Self::ValidNow),
            "valid_at_trusted_time" => Ok(Self::ValidAtTrustedTime),
            "cryptographically_intact_offline" => Ok(Self::CryptographicallyIntactOffline),
            "not_recorded" => Ok(Self::NotRecorded),
            "invalid" => Ok(Self::Invalid),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapTrustAnchorType {
    OfficialTzap,
    Custom,
    Untrusted,
}

impl TzapTrustAnchorType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OfficialTzap => "official_tzap",
            Self::Custom => "custom",
            Self::Untrusted => "untrusted",
        }
    }
}

impl std::str::FromStr for TzapTrustAnchorType {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "official_tzap" => Ok(Self::OfficialTzap),
            "custom" => Ok(Self::Custom),
            "untrusted" => Ok(Self::Untrusted),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapIdentityAssurance {
    OauthVerifiedEmail,
    OauthVerifiedProviderAccount,
    OrgAdminApprovedDevice,
    EnterpriseSsoVerified,
    ContractVerified,
}

impl TzapIdentityAssurance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OauthVerifiedEmail => "oauth_verified_email",
            Self::OauthVerifiedProviderAccount => "oauth_verified_provider_account",
            Self::OrgAdminApprovedDevice => "org_admin_approved_device",
            Self::EnterpriseSsoVerified => "enterprise_sso_verified",
            Self::ContractVerified => "contract_verified",
        }
    }

    /// Parses the stable wire value.
    ///
    /// Kept as a thin wrapper around [`std::str::FromStr`] because the
    /// zmanager-desktop app calls this inherent method; it must stay in sync
    /// with the trait implementation.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        value.parse().ok()
    }
}

impl std::str::FromStr for TzapIdentityAssurance {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "oauth_verified_email" => Ok(Self::OauthVerifiedEmail),
            "oauth_verified_provider_account" => Ok(Self::OauthVerifiedProviderAccount),
            "org_admin_approved_device" => Ok(Self::OrgAdminApprovedDevice),
            "enterprise_sso_verified" => Ok(Self::EnterpriseSsoVerified),
            "contract_verified" => Ok(Self::ContractVerified),
            _ => Err(()),
        }
    }
}

/// Canonical endpoint paths.
pub const STATUS_BY_FINGERPRINT_PATH: &str = "/v1/status/certificates/by-fingerprint/{certificate_sha256}";
pub const STATUS_CRL_MANIFEST_PATH: &str = "/v1/status/crls";
pub const STATUS_CRL_PEM_PATH: &str = "/v1/status/crls/{issuer_certificate_sha256}/pem";
pub const STATUS_BULK_PATH: &str = "/v1/status/bulk";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRootPinSet {
    /// Current official TZAP roots.
    pub current: &'static [&'static str],
    /// Planned successor official roots for rollover.
    pub planned_successors: &'static [&'static str],
}

impl TzapRootPinSet {
    #[must_use]
    pub fn is_current_root(&self, fingerprint: &str) -> bool {
        is_valid_sha256_identifier(fingerprint) && self.current.iter().any(|value| *value == fingerprint && is_valid_sha256_identifier(value))
    }

    #[must_use]
    pub fn is_planned_successor(&self, fingerprint: &str) -> bool {
        is_valid_sha256_identifier(fingerprint) && self.planned_successors.iter().any(|value| *value == fingerprint && is_valid_sha256_identifier(value))
    }

    #[must_use]
    pub fn is_official_root(&self, fingerprint: &str) -> bool {
        self.is_current_root(fingerprint) || self.is_planned_successor(fingerprint)
    }
}

/// SHA-256 identifiers of the TZAP roots trusted by default in chain
/// verification. Both are official: production serves live traffic and
/// staging serves the staging environment; chains rooted at either verify.
/// These re-export `tzap_plugin_signing::trust`, which is the one place in
/// the `tzap`/`zmanager` workspaces these fingerprints and their matching
/// PEMs are pinned, so this crate cannot carry its own copy that drifts from
/// tzap's.
pub const TZAP_PRODUCTION_ROOT_SHA256: &str = tzap_plugin_signing::trust::OFFICIAL_TZAP_ROOT_CERT_SHA256;
pub const TZAP_STAGING_ROOT_SHA256: &str = tzap_plugin_signing::trust::OFFICIAL_TZAP_STAGING_ROOT_SHA256;

pub const OFFICIAL_TZAP_ROOT_PINS: TzapRootPinSet =
    TzapRootPinSet { current: &[TZAP_PRODUCTION_ROOT_SHA256, TZAP_STAGING_ROOT_SHA256], planned_successors: &[] };

/// PEM bytes for the official TZAP roots, matching [`TZAP_PRODUCTION_ROOT_SHA256`]
/// and [`TZAP_STAGING_ROOT_SHA256`]. Sourced from `tzap_plugin_signing::trust`
/// rather than embedded here; other code that needs the certificate bytes
/// themselves (not just the fingerprint) uses these constants or
/// [`official_tzap_root_certificates_der`] instead of embedding its own copy,
/// fetching one at runtime, or reading a caller-supplied path.
pub const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = tzap_plugin_signing::trust::OFFICIAL_TZAP_ROOT_CERT_PEM;
pub const OFFICIAL_TZAP_STAGING_ROOT_PEM: &[u8] = tzap_plugin_signing::trust::OFFICIAL_TZAP_STAGING_ROOT_PEM;

/// DER bytes for both official TZAP roots (production, then staging).
///
/// # Panics
/// Never in practice: the embedded PEMs are checked into this crate and
/// covered by `official_tzap_root_certificates_der_matches_pinned_fingerprints`.
#[must_use]
pub fn official_tzap_root_certificates_der() -> Vec<Vec<u8>> {
    [OFFICIAL_TZAP_ROOT_CERT_PEM, OFFICIAL_TZAP_STAGING_ROOT_PEM]
        .into_iter()
        .map(|pem| certificate_pem_or_der_to_der(pem).expect("embedded TZAP root certificate PEM must parse"))
        .collect()
}

pub fn certificate_pem_or_der_to_der(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(certificate) = X509::from_pem(bytes) {
        certificate.to_der().map_err(|error| error.to_string())
    } else {
        X509::from_der(bytes).map_err(|error| error.to_string())?;
        Ok(bytes.to_vec())
    }
}

#[must_use]
pub fn certificate_sha256_identifier_for_der(der: &[u8]) -> String {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(der));
    format_certificate_sha256(&digest)
}

/// Reads trusted-root certificate files (PEM or DER) and collects their
/// SHA-256 identifiers (CR-113: shared by the CLI and the tzap JSON service;
/// the service adopted the CLI's file-loading behavior).
pub fn load_custom_root_certificate_files(paths: &[std::path::PathBuf], custom_roots: &mut Vec<String>) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let der = certificate_pem_or_der_to_der(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
            let fingerprint = certificate_sha256_identifier_for_der(&der);
            if !custom_roots.iter().any(|root| root == &fingerprint) {
                custom_roots.push(fingerprint);
            }
            Ok(der)
        })
        .collect()
}
