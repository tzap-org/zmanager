//! Shared TZAP trust constants, certificate profiles, and identifier helpers.

use openssl::asn1::Asn1Object;
use openssl::nid::Nid;
use openssl::x509::X509;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::fmt;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer as _, X509Certificate};

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
pub const TZAP_MVP_DOCUMENT_SIGNATURE_ALGORITHMS: &[&str] = &[TZAP_DOCUMENT_SIGNATURE_ALGORITHM];
pub const TZAP_MVP_LEAF_KEY_ALGORITHMS: &[&str] = &[TZAP_LEAF_KEY_ALGORITHM];
pub const TZAP_MVP_CERTIFICATE_SIGNATURE_ALGORITHMS: &[&str] =
    &[TZAP_LEAF_CERTIFICATE_SIGNATURE_ALGORITHM];
pub const TZAP_MVP_PAYLOAD_DIGEST_ALGORITHMS: &[&str] = &[TZAP_PAYLOAD_DIGEST_ALGORITHM];

/// MVP OIDs (numeric UUID-derived arcs).
pub const TZAP_OID_DOCUMENT_SIGNING_EKU: &str = "2.25.201653505380392472132808080578384925035";
pub const TZAP_OID_CA_POLICY: &str = "2.25.216801977638581014157980575261877559132";
pub const TZAP_OID_LEAF_POLICY: &str = "2.25.194500518885741369143906285659225836299";
pub const TZAP_OID_METADATA_EXTENSION: &str = "2.25.25754549376475580214508793807157112225";
pub const TZAP_OID_STATUS_PROOF_EXTENSION: &str = "2.25.25951712805955241282365074948746758705";

const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";
const OID_EXTENDED_KEY_USAGE_EXTENSION: &str = "2.5.29.37";
const OID_SERVER_AUTH_EKU: &str = "1.3.6.1.5.5.7.3.1";
const OID_CLIENT_AUTH_EKU: &str = "1.3.6.1.5.5.7.3.2";
const OID_CODE_SIGNING_EKU: &str = "1.3.6.1.5.5.7.3.3";
const REQUIRED_ROOT_PATH_LEN: u32 = 2;
const PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE: u32 = 1;
const PLATFORM_LEAF_ONLY_PATH_LEN: u32 = 0;
const ORG_INTERMEDIATE_PATH_LEN: u32 = 0;
const MIN_TZAP_CHAIN_LEN: usize = 3;
const MAX_TZAP_CHAIN_LEN: usize = 4;
const MAX_TZAP_LEAF_VALIDITY_DAYS: i64 = 180;

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

/// Regex source strings for documentation and downstream validation reuse.
pub const PUBLIC_SIGNER_ID_REGEX: &str = r"^psign_[A-Za-z0-9_-]{16,64}$";
pub const PUBLIC_ORG_ID_REGEX: &str = r"^porg_[A-Za-z0-9_-]{16,64}$";
pub const PUBLIC_DEVICE_ID_REGEX: &str = r"^pdev_[A-Za-z0-9_-]{16,64}$";

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

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "valid" => Some(Self::Valid),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "not_yet_valid" => Some(Self::NotYetValid),
            "suspended" => Some(Self::Suspended),
            "issuer_suspended" => Some(Self::IssuerSuspended),
            "issuer_revoked" => Some(Self::IssuerRevoked),
            "unknown_certificate" => Some(Self::UnknownCertificate),
            "unknown_issuer" => Some(Self::UnknownIssuer),
            "malformed_lookup" => Some(Self::MalformedLookup),
            "unsupported_lookup_form" => Some(Self::UnsupportedLookupForm),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapVerificationState {
    ValidNow,
    ValidAtTrustedTime,
    CryptographicallyIntactOffline,
    Invalid,
}

impl TzapVerificationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidNow => "valid_now",
            Self::ValidAtTrustedTime => "valid_at_trusted_time",
            Self::CryptographicallyIntactOffline => "cryptographically_intact_offline",
            Self::Invalid => "invalid",
        }
    }

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "valid_now" => Some(Self::ValidNow),
            "valid_at_trusted_time" => Some(Self::ValidAtTrustedTime),
            "cryptographically_intact_offline" => Some(Self::CryptographicallyIntactOffline),
            "invalid" => Some(Self::Invalid),
            _ => None,
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

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "official_tzap" => Some(Self::OfficialTzap),
            "custom" => Some(Self::Custom),
            "untrusted" => Some(Self::Untrusted),
            _ => None,
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

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "oauth_verified_email" => Some(Self::OauthVerifiedEmail),
            "oauth_verified_provider_account" => Some(Self::OauthVerifiedProviderAccount),
            "org_admin_approved_device" => Some(Self::OrgAdminApprovedDevice),
            "enterprise_sso_verified" => Some(Self::EnterpriseSsoVerified),
            "contract_verified" => Some(Self::ContractVerified),
            _ => None,
        }
    }
}

/// Canonical endpoint paths.
pub const TRUST_ROOTS_PATH: &str = "/v1/trust/roots";
pub const TRUST_ROOT_PEM_PATH: &str = "/v1/trust/roots/{root_certificate_sha256}/pem";
pub const TRUST_INTERMEDIATES_PATH: &str = "/v1/trust/intermediates";
pub const TRUST_INTERMEDIATE_PEM_PATH: &str =
    "/v1/trust/intermediates/{issuer_certificate_sha256}/pem";

pub const STATUS_BY_FINGERPRINT_PATH: &str =
    "/v1/status/certificates/by-fingerprint/{certificate_sha256}";
pub const STATUS_BY_ISSUER_SERIAL_PATH: &str =
    "/v1/status/certificates/by-issuer/{issuer_certificate_sha256}/{serial_number}";
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
        is_valid_sha256_identifier(fingerprint)
            && self
                .current
                .iter()
                .any(|value| *value == fingerprint && is_valid_sha256_identifier(value))
    }

    #[must_use]
    pub fn is_planned_successor(&self, fingerprint: &str) -> bool {
        is_valid_sha256_identifier(fingerprint)
            && self
                .planned_successors
                .iter()
                .any(|value| *value == fingerprint && is_valid_sha256_identifier(value))
    }

    #[must_use]
    pub fn is_official_root(&self, fingerprint: &str) -> bool {
        self.is_current_root(fingerprint) || self.is_planned_successor(fingerprint)
    }
}

/// Placeholder for rollout configuration; later steps populate this with release-root pins.
pub const OFFICIAL_TZAP_ROOT_PINS: TzapRootPinSet = TzapRootPinSet {
    current: &[],
    planned_successors: &[],
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapOfficialRootPinKind {
    Current,
    PlannedSuccessor,
}

impl TzapOfficialRootPinKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::PlannedSuccessor => "planned_successor",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificateProfileOptions {
    /// Approved organization-intermediate policy OIDs for managed issuers.
    pub approved_org_intermediate_policy_oids: Vec<String>,
    /// Approved leaf policy OIDs beyond the default TZAP leaf policy.
    pub approved_leaf_policy_oids: Vec<String>,
}

impl Default for TzapCertificateProfileOptions {
    fn default() -> Self {
        Self {
            approved_org_intermediate_policy_oids: Vec::new(),
            approved_leaf_policy_oids: vec![TZAP_OID_LEAF_POLICY.to_owned()],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificatePublicMetadata {
    pub version: u64,
    pub public_signer_id: String,
    pub public_org_id: Option<String>,
    pub public_device_id: String,
    pub assurance_level: TzapIdentityAssurance,
    pub policy_oid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificateProfileValidation {
    pub trust_anchor_type: TzapTrustAnchorType,
    pub official_root_pin_kind: Option<TzapOfficialRootPinKind>,
    pub root_certificate_sha256: String,
    pub public_metadata: TzapCertificatePublicMetadata,
}

#[derive(Debug)]
pub enum TzapCertificateProfileError {
    InvalidChainLength {
        actual: usize,
    },
    CertificateParse {
        index: usize,
        detail: String,
    },
    ChainOrder {
        child_index: usize,
    },
    SignatureValidation {
        subject_index: usize,
        detail: String,
    },
    UnsupportedAlgorithm {
        index: usize,
        reason: &'static str,
    },
    RootNotSelfSigned,
    RootNotPinned {
        fingerprint: String,
    },
    RootProfile {
        reason: &'static str,
    },
    IntermediateProfile {
        index: usize,
        reason: &'static str,
    },
    LeafProfile {
        reason: &'static str,
    },
    MissingMetadata,
    DuplicateMetadata,
    CriticalMetadata,
    NestedAsn1Metadata,
    MalformedMetadata {
        reason: &'static str,
    },
    UnknownMetadataField {
        field: String,
    },
    MetadataPolicyMismatch {
        policy_oid: String,
    },
}

impl fmt::Display for TzapCertificateProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainLength { actual } => {
                write!(f, "TZAP certificate chain has invalid length {actual}")
            }
            Self::CertificateParse { index, detail } => {
                write!(
                    f,
                    "failed to parse certificate at chain index {index}: {detail}"
                )
            }
            Self::ChainOrder { child_index } => {
                write!(
                    f,
                    "certificate chain is not ordered leaf issuer rootward at index {child_index}"
                )
            }
            Self::SignatureValidation {
                subject_index,
                detail,
            } => write!(
                f,
                "certificate signature validation failed at chain index {subject_index}: {detail}"
            ),
            Self::UnsupportedAlgorithm { index, reason } => {
                write!(
                    f,
                    "certificate at chain index {index} uses unsupported algorithm: {reason}"
                )
            }
            Self::RootNotSelfSigned => write!(f, "TZAP root certificate is not self-signed"),
            Self::RootNotPinned { fingerprint } => {
                write!(f, "TZAP root fingerprint is not pinned: {fingerprint}")
            }
            Self::RootProfile { reason } => write!(f, "TZAP root profile rejected: {reason}"),
            Self::IntermediateProfile { index, reason } => {
                write!(
                    f,
                    "TZAP intermediate profile rejected at index {index}: {reason}"
                )
            }
            Self::LeafProfile { reason } => write!(f, "TZAP leaf profile rejected: {reason}"),
            Self::MissingMetadata => write!(f, "TZAP metadata extension is missing"),
            Self::DuplicateMetadata => write!(f, "TZAP metadata extension appears more than once"),
            Self::CriticalMetadata => write!(f, "TZAP metadata extension must be non-critical"),
            Self::NestedAsn1Metadata => {
                write!(f, "TZAP metadata extension contains a nested ASN.1 wrapper")
            }
            Self::MalformedMetadata { reason } => {
                write!(f, "TZAP metadata extension is malformed: {reason}")
            }
            Self::UnknownMetadataField { field } => {
                write!(f, "TZAP metadata extension has unknown v1 field {field}")
            }
            Self::MetadataPolicyMismatch { policy_oid } => {
                write!(
                    f,
                    "TZAP metadata policy OID is not in leaf policies: {policy_oid}"
                )
            }
        }
    }
}

impl std::error::Error for TzapCertificateProfileError {}

/// Validates an official TZAP document-signing chain against pinned root
/// fingerprints and the MVP certificate profiles.
pub fn validate_official_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    root_pins: &TzapRootPinSet,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    validate_tzap_certificate_chain_der(
        chain_der,
        Some(root_pins),
        TzapTrustAnchorType::OfficialTzap,
        options,
    )
}

/// Validates a custom trust chain against TZAP document-signing profiles without
/// upgrading it to official TZAP trust.
pub fn validate_custom_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    validate_tzap_certificate_chain_der(chain_der, None, TzapTrustAnchorType::Custom, options)
}

/// Returns the certificate chain entries that belong in public TZAP envelopes.
///
/// Local inventory keeps the full issuer chain rootward so enrollment, renewal,
/// and profile validation can operate without another root lookup. MVP document
/// envelopes and contact cards omit the pinned root certificate; verifiers are
/// expected to use their configured root store to reconstruct the full chain.
#[must_use]
pub fn public_intermediate_chain_der(chain_der: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let Some((last, rest)) = chain_der.split_last() else {
        return Vec::new();
    };
    if is_self_issued_certificate_der(last) {
        rest.to_vec()
    } else {
        chain_der.to_vec()
    }
}

fn is_self_issued_certificate_der(der: &[u8]) -> bool {
    X509Certificate::from_der(der).is_ok_and(|(remaining, certificate)| {
        remaining.is_empty() && certificate.issuer() == certificate.subject()
    })
}

fn validate_tzap_certificate_chain_der(
    chain_der: &[Vec<u8>],
    official_root_pins: Option<&TzapRootPinSet>,
    trust_anchor_type: TzapTrustAnchorType,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificateProfileValidation, TzapCertificateProfileError> {
    if !(MIN_TZAP_CHAIN_LEN..=MAX_TZAP_CHAIN_LEN).contains(&chain_der.len()) {
        return Err(TzapCertificateProfileError::InvalidChainLength {
            actual: chain_der.len(),
        });
    }

    let parsed = parse_x509_chain(chain_der)?;
    let openssl = parse_openssl_chain(chain_der)?;
    validate_chain_order_and_signatures(&parsed, &openssl)?;
    validate_chain_algorithms(&parsed, &openssl)?;

    let root_index = parsed.len() - 1;
    let mut root_digest = [0_u8; 32];
    root_digest.copy_from_slice(&Sha256::digest(&chain_der[root_index]));
    let root_fingerprint = format_certificate_sha256(&root_digest);
    let official_root_pin_kind = match official_root_pins {
        Some(pins) => official_root_pin_kind(pins, &root_fingerprint)?,
        None => None,
    };

    validate_root_certificate(&parsed[root_index])?;
    validate_intermediates(&parsed, options)?;
    require_leaf_aki_matches_issuer(&parsed)?;
    let public_metadata = validate_leaf_certificate(&parsed[0], options)?;

    Ok(TzapCertificateProfileValidation {
        trust_anchor_type,
        official_root_pin_kind,
        root_certificate_sha256: root_fingerprint,
        public_metadata,
    })
}

fn parse_x509_chain<'a>(
    chain_der: &'a [Vec<u8>],
) -> Result<Vec<X509Certificate<'a>>, TzapCertificateProfileError> {
    chain_der
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509Certificate::from_der(der)
                .map_err(|error| TzapCertificateProfileError::CertificateParse {
                    index,
                    detail: error.to_string(),
                })
                .and_then(|(remaining, certificate)| {
                    if remaining.is_empty() {
                        Ok(certificate)
                    } else {
                        Err(TzapCertificateProfileError::CertificateParse {
                            index,
                            detail: "trailing DER bytes".to_owned(),
                        })
                    }
                })
        })
        .collect()
}

fn parse_openssl_chain(chain_der: &[Vec<u8>]) -> Result<Vec<X509>, TzapCertificateProfileError> {
    chain_der
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509::from_der(der).map_err(|source| TzapCertificateProfileError::CertificateParse {
                index,
                detail: source.to_string(),
            })
        })
        .collect()
}

fn validate_chain_order_and_signatures(
    parsed: &[X509Certificate<'_>],
    openssl: &[X509],
) -> Result<(), TzapCertificateProfileError> {
    for (index, pair) in parsed.windows(2).enumerate() {
        if pair[0].issuer() != pair[1].subject() {
            return Err(TzapCertificateProfileError::ChainOrder { child_index: index });
        }
    }

    let root = parsed.last().expect("chain length checked");
    if root.issuer() != root.subject() {
        return Err(TzapCertificateProfileError::RootNotSelfSigned);
    }

    for (index, pair) in openssl.windows(2).enumerate() {
        let issuer_key = pair[1].public_key().map_err(|source| {
            TzapCertificateProfileError::SignatureValidation {
                subject_index: index,
                detail: source.to_string(),
            }
        })?;
        let verified = pair[0].verify(&issuer_key).map_err(|source| {
            TzapCertificateProfileError::SignatureValidation {
                subject_index: index,
                detail: source.to_string(),
            }
        })?;
        if !verified {
            return Err(TzapCertificateProfileError::SignatureValidation {
                subject_index: index,
                detail: "issuer public key did not verify certificate signature".to_owned(),
            });
        }
    }

    let root_index = openssl.len() - 1;
    let root_key = openssl[root_index].public_key().map_err(|source| {
        TzapCertificateProfileError::SignatureValidation {
            subject_index: root_index,
            detail: source.to_string(),
        }
    })?;
    if !openssl[root_index].verify(&root_key).map_err(|source| {
        TzapCertificateProfileError::SignatureValidation {
            subject_index: root_index,
            detail: source.to_string(),
        }
    })? {
        return Err(TzapCertificateProfileError::RootNotSelfSigned);
    }

    Ok(())
}

fn validate_chain_algorithms(
    parsed: &[X509Certificate<'_>],
    openssl: &[X509],
) -> Result<(), TzapCertificateProfileError> {
    for (index, certificate) in parsed.iter().enumerate() {
        if certificate.signature_algorithm.oid().to_id_string() != OID_ECDSA_WITH_SHA256
            || certificate.tbs_certificate.signature.oid().to_id_string() != OID_ECDSA_WITH_SHA256
        {
            return Err(TzapCertificateProfileError::UnsupportedAlgorithm {
                index,
                reason: "certificate signature must be ECDSA P-256 with SHA-256",
            });
        }

        let key = openssl[index].public_key().map_err(|source| {
            TzapCertificateProfileError::UnsupportedAlgorithm {
                index,
                reason: if source.errors().is_empty() {
                    "certificate public key is unreadable"
                } else {
                    "certificate public key is unsupported"
                },
            }
        })?;
        let ec_key =
            key.ec_key()
                .map_err(|_| TzapCertificateProfileError::UnsupportedAlgorithm {
                    index,
                    reason: "certificate public key must be ECDSA P-256",
                })?;
        if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(TzapCertificateProfileError::UnsupportedAlgorithm {
                index,
                reason: "certificate public key must use prime256v1",
            });
        }
    }

    Ok(())
}

fn official_root_pin_kind(
    pins: &TzapRootPinSet,
    fingerprint: &str,
) -> Result<Option<TzapOfficialRootPinKind>, TzapCertificateProfileError> {
    if pins.is_current_root(fingerprint) {
        Ok(Some(TzapOfficialRootPinKind::Current))
    } else if pins.is_planned_successor(fingerprint) {
        Ok(Some(TzapOfficialRootPinKind::PlannedSuccessor))
    } else {
        Err(TzapCertificateProfileError::RootNotPinned {
            fingerprint: fingerprint.to_owned(),
        })
    }
}

fn validate_root_certificate(
    certificate: &X509Certificate<'_>,
) -> Result<(), TzapCertificateProfileError> {
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| TzapCertificateProfileError::RootProfile {
            reason: "basic constraints are invalid or duplicated",
        })?
        .ok_or(TzapCertificateProfileError::RootProfile {
            reason: "missing critical basic constraints",
        })?;
    if !basic_constraints.critical
        || !basic_constraints.value.ca
        || basic_constraints.value.path_len_constraint != Some(REQUIRED_ROOT_PATH_LEN)
    {
        return Err(TzapCertificateProfileError::RootProfile {
            reason: "root must be a critical CA with pathLenConstraint 2",
        });
    }

    require_ca_key_usage(certificate, CertificateRole::Root, None)?;
    if subject_key_identifier(certificate).is_none() {
        return Err(TzapCertificateProfileError::RootProfile {
            reason: "missing subject key identifier",
        });
    }
    reject_forbidden_extended_key_usage(certificate, CertificateRole::Root)?;

    Ok(())
}

fn validate_intermediates(
    parsed: &[X509Certificate<'_>],
    options: &TzapCertificateProfileOptions,
) -> Result<(), TzapCertificateProfileError> {
    let has_org_intermediate = parsed.len() == MAX_TZAP_CHAIN_LEN;
    for index in 1..parsed.len() - 1 {
        let certificate = &parsed[index];
        let role = if has_org_intermediate && index == 1 {
            CertificateRole::OrganizationIntermediate
        } else {
            CertificateRole::PlatformIntermediate
        };
        let expected_path_len = match role {
            CertificateRole::PlatformIntermediate if has_org_intermediate => {
                PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE
            }
            CertificateRole::PlatformIntermediate => PLATFORM_LEAF_ONLY_PATH_LEN,
            CertificateRole::OrganizationIntermediate => ORG_INTERMEDIATE_PATH_LEN,
            CertificateRole::Root => unreachable!(),
        };

        let basic_constraints = certificate
            .basic_constraints()
            .map_err(|_| TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "basic constraints are invalid or duplicated",
            })?
            .ok_or(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "missing critical basic constraints",
            })?;
        if !basic_constraints.critical
            || !basic_constraints.value.ca
            || basic_constraints.value.path_len_constraint != Some(expected_path_len)
        {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "intermediate must be a critical CA with the expected path length",
            });
        }

        require_ca_key_usage(certificate, role, Some(index))?;
        reject_forbidden_extended_key_usage(certificate, role)?;
        require_aki_ski_pair(parsed, index)?;
        if !certificate_has_policy(certificate, TZAP_OID_CA_POLICY) {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "missing TZAP CA policy OID",
            });
        }
        if matches!(role, CertificateRole::OrganizationIntermediate)
            && !has_any_policy(certificate, &options.approved_org_intermediate_policy_oids)
        {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "organization intermediate lacks an approved organization policy OID",
            });
        }
        if certificate
            .iter_extensions()
            .all(|extension| extension.oid.to_id_string() != "2.5.29.31")
        {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "missing CRL distribution point or TZAP status distribution extension",
            });
        }
    }

    Ok(())
}

fn validate_leaf_certificate(
    certificate: &X509Certificate<'_>,
    options: &TzapCertificateProfileOptions,
) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| TzapCertificateProfileError::LeafProfile {
            reason: "basic constraints are invalid or duplicated",
        })?
        .ok_or(TzapCertificateProfileError::LeafProfile {
            reason: "missing critical basic constraints",
        })?;
    if !basic_constraints.critical || basic_constraints.value.ca {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "leaf must have critical CA:FALSE basic constraints",
        });
    }
    let validity = certificate.validity();
    let Some(validity_duration) = validity.not_after - validity.not_before else {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "leaf validity interval is invalid",
        });
    };
    if validity_duration.whole_days() > MAX_TZAP_LEAF_VALIDITY_DAYS {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "leaf validity exceeds the TZAP MVP maximum",
        });
    }

    let key_usage = certificate
        .key_usage()
        .map_err(|_| TzapCertificateProfileError::LeafProfile {
            reason: "key usage is invalid or duplicated",
        })?
        .ok_or(TzapCertificateProfileError::LeafProfile {
            reason: "missing critical key usage",
        })?;
    if !key_usage.critical || key_usage.value.flags != 1 {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "leaf key usage must be exactly digitalSignature",
        });
    }

    let eku_oids =
        extended_key_usage_oids(certificate).ok_or(TzapCertificateProfileError::LeafProfile {
            reason: "missing document-signing extended key usage",
        })?;
    let document_signing_oid = oid_value_bytes(TZAP_OID_DOCUMENT_SIGNING_EKU).ok_or(
        TzapCertificateProfileError::LeafProfile {
            reason: "document-signing OID is not numeric",
        },
    )?;
    if eku_oids.as_slice() != [document_signing_oid.as_slice()] {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "extended key usage must be exactly TZAP document signing",
        });
    }

    if let Some(san) = certificate.subject_alternative_name().map_err(|_| {
        TzapCertificateProfileError::LeafProfile {
            reason: "subject alternative name is invalid or duplicated",
        }
    })? {
        if san
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(_) | GeneralName::IPAddress(_)))
        {
            return Err(TzapCertificateProfileError::LeafProfile {
                reason: "MVP leaves must not contain DNS or IP subject alternative names",
            });
        }
    }

    if !has_any_policy(certificate, &options.approved_leaf_policy_oids) {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "missing approved TZAP leaf policy OID",
        });
    }

    if authority_key_identifier(certificate).is_none() {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "missing authority key identifier",
        });
    }

    let metadata = parse_public_metadata_extension(certificate)?;
    if !certificate_has_policy(certificate, &metadata.policy_oid) {
        return Err(TzapCertificateProfileError::MetadataPolicyMismatch {
            policy_oid: metadata.policy_oid,
        });
    }

    Ok(metadata)
}

fn require_ca_key_usage(
    certificate: &X509Certificate<'_>,
    role: CertificateRole,
    index: Option<usize>,
) -> Result<(), TzapCertificateProfileError> {
    let key_usage = certificate
        .key_usage()
        .map_err(|_| role.profile_error("key usage is invalid or duplicated", index))?
        .ok_or_else(|| role.profile_error("missing critical key usage", index))?;
    if !key_usage.critical
        || !key_usage.value.key_cert_sign()
        || !key_usage.value.crl_sign()
        || key_usage.value.flags != ((1 << 5) | (1 << 6))
    {
        return Err(role.profile_error(
            "CA key usage must be exactly keyCertSign and cRLSign",
            index,
        ));
    }
    Ok(())
}

fn reject_forbidden_extended_key_usage(
    certificate: &X509Certificate<'_>,
    role: CertificateRole,
) -> Result<(), TzapCertificateProfileError> {
    if let Some(eku) = certificate
        .extended_key_usage()
        .map_err(|_| role.profile_error("extended key usage is invalid or duplicated", None))?
    {
        if eku.value.any || eku.value.server_auth || eku.value.client_auth || eku.value.code_signing
        {
            return Err(
                role.profile_error("certificate authorizes forbidden extended key usage", None)
            );
        }
        let other_oids = eku
            .value
            .other
            .iter()
            .map(|oid| oid.to_id_string())
            .collect::<Vec<_>>();
        if other_oids
            .iter()
            .any(|oid| oid == OID_ANY_EXTENDED_KEY_USAGE)
        {
            return Err(role.profile_error("certificate authorizes anyExtendedKeyUsage", None));
        }
    }
    if let Some(oids) = extended_key_usage_oids(certificate) {
        let forbidden = [
            OID_ANY_EXTENDED_KEY_USAGE,
            OID_SERVER_AUTH_EKU,
            OID_CLIENT_AUTH_EKU,
            OID_CODE_SIGNING_EKU,
        ]
        .into_iter()
        .filter_map(oid_value_bytes)
        .collect::<Vec<_>>();
        if oids
            .iter()
            .any(|oid| forbidden.iter().any(|forbidden| forbidden == oid))
        {
            return Err(
                role.profile_error("certificate authorizes forbidden extended key usage", None)
            );
        }
    }
    Ok(())
}

fn require_aki_ski_pair(
    parsed: &[X509Certificate<'_>],
    index: usize,
) -> Result<(), TzapCertificateProfileError> {
    let child_aki = authority_key_identifier(&parsed[index]).ok_or(
        TzapCertificateProfileError::IntermediateProfile {
            index,
            reason: "missing authority key identifier",
        },
    )?;
    let issuer_ski = subject_key_identifier(&parsed[index + 1]).ok_or(
        TzapCertificateProfileError::IntermediateProfile {
            index,
            reason: "issuer is missing subject key identifier",
        },
    )?;
    let own_ski = subject_key_identifier(&parsed[index]).ok_or(
        TzapCertificateProfileError::IntermediateProfile {
            index,
            reason: "missing subject key identifier",
        },
    )?;
    if child_aki != issuer_ski {
        return Err(TzapCertificateProfileError::IntermediateProfile {
            index,
            reason: "authority key identifier does not match issuer subject key identifier",
        });
    }
    if index > 1 {
        let issued_child_aki = authority_key_identifier(&parsed[index - 1]).ok_or(
            TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "issued child is missing authority key identifier",
            },
        )?;
        if own_ski != issued_child_aki {
            return Err(TzapCertificateProfileError::IntermediateProfile {
                index,
                reason: "subject key identifier does not match child authority key identifier",
            });
        }
    }
    Ok(())
}

fn require_leaf_aki_matches_issuer(
    parsed: &[X509Certificate<'_>],
) -> Result<(), TzapCertificateProfileError> {
    let leaf_aki =
        authority_key_identifier(&parsed[0]).ok_or(TzapCertificateProfileError::LeafProfile {
            reason: "missing authority key identifier",
        })?;
    let issuer_ski =
        subject_key_identifier(&parsed[1]).ok_or(TzapCertificateProfileError::LeafProfile {
            reason: "issuer is missing subject key identifier",
        })?;
    if leaf_aki != issuer_ski {
        return Err(TzapCertificateProfileError::LeafProfile {
            reason: "authority key identifier does not match issuer subject key identifier",
        });
    }
    Ok(())
}

fn parse_public_metadata_extension(
    certificate: &X509Certificate<'_>,
) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    let mut matches = certificate
        .iter_extensions()
        .filter(|extension| extension_oid_matches(extension, TZAP_OID_METADATA_EXTENSION));
    let extension = matches
        .next()
        .ok_or(TzapCertificateProfileError::MissingMetadata)?;
    if matches.next().is_some() {
        return Err(TzapCertificateProfileError::DuplicateMetadata);
    }
    if extension.critical {
        return Err(TzapCertificateProfileError::CriticalMetadata);
    }
    if looks_like_nested_asn1(extension.value) {
        return Err(TzapCertificateProfileError::NestedAsn1Metadata);
    }

    let raw = std::str::from_utf8(extension.value).map_err(|_| {
        TzapCertificateProfileError::MalformedMetadata {
            reason: "metadata is not UTF-8",
        }
    })?;
    let value: Value =
        serde_json::from_str(raw).map_err(|_| TzapCertificateProfileError::MalformedMetadata {
            reason: "metadata is not JSON",
        })?;
    let canonical = serde_json_canonicalizer::to_string(&value).map_err(|_| {
        TzapCertificateProfileError::MalformedMetadata {
            reason: "metadata is not JCS canonicalizable",
        }
    })?;
    if canonical.as_bytes() != extension.value {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "metadata is not JCS canonical JSON",
        });
    }

    parse_public_metadata_value(value)
}

fn parse_public_metadata_value(
    value: Value,
) -> Result<TzapCertificatePublicMetadata, TzapCertificateProfileError> {
    let object = value
        .as_object()
        .ok_or(TzapCertificateProfileError::MalformedMetadata {
            reason: "metadata is not a JSON object",
        })?;
    validate_metadata_fields(object)?;

    let version = required_u64(object, "version")?;
    if version != 1 {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "unsupported metadata version",
        });
    }
    let public_signer_id = required_string(object, "public_signer_id")?;
    if !is_valid_public_signer_id(public_signer_id) {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "invalid public_signer_id",
        });
    }
    let public_org_id = optional_string(object, "public_org_id")?;
    if let Some(value) = public_org_id
        && !is_valid_public_org_id(value)
    {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "invalid public_org_id",
        });
    }
    let public_device_id = required_string(object, "public_device_id")?;
    if !is_valid_public_device_id(public_device_id) {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "invalid public_device_id",
        });
    }
    let assurance_level = required_string(object, "assurance_level")?;
    let assurance_level = TzapIdentityAssurance::from_str(assurance_level).ok_or(
        TzapCertificateProfileError::MalformedMetadata {
            reason: "invalid assurance_level",
        },
    )?;
    let policy_oid = required_string(object, "policy_oid")?;
    if !is_numeric_dotted_oid(policy_oid) {
        return Err(TzapCertificateProfileError::MalformedMetadata {
            reason: "invalid policy_oid",
        });
    }

    Ok(TzapCertificatePublicMetadata {
        version,
        public_signer_id: public_signer_id.to_owned(),
        public_org_id: public_org_id.map(ToOwned::to_owned),
        public_device_id: public_device_id.to_owned(),
        assurance_level,
        policy_oid: policy_oid.to_owned(),
    })
}

fn validate_metadata_fields(
    object: &Map<String, Value>,
) -> Result<(), TzapCertificateProfileError> {
    const ALLOWED_FIELDS: &[&str] = &[
        "assurance_level",
        "policy_oid",
        "public_device_id",
        "public_org_id",
        "public_signer_id",
        "version",
    ];
    for field in object.keys() {
        if !ALLOWED_FIELDS.contains(&field.as_str()) {
            return Err(TzapCertificateProfileError::UnknownMetadataField {
                field: field.clone(),
            });
        }
    }
    Ok(())
}

fn required_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<u64, TzapCertificateProfileError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(TzapCertificateProfileError::MalformedMetadata { reason: field })
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, TzapCertificateProfileError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(TzapCertificateProfileError::MalformedMetadata { reason: field })
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, TzapCertificateProfileError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(TzapCertificateProfileError::MalformedMetadata { reason: field }),
    }
}

fn looks_like_nested_asn1(value: &[u8]) -> bool {
    matches!(value.first(), Some(0x04 | 0x0c | 0x13 | 0x16 | 0x30))
}

fn is_numeric_dotted_oid(value: &str) -> bool {
    if value.is_empty() || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return false;
    }
    value
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn certificate_has_policy(certificate: &X509Certificate<'_>, oid: &str) -> bool {
    let Ok(target_oid) = Asn1Object::from_str(oid) else {
        return false;
    };
    let target_oid = target_oid.as_slice();
    certificate
        .iter_extensions()
        .filter(|extension| extension.oid.to_id_string() == "2.5.29.32")
        .any(|extension| {
            certificate_policies_contains_oid(extension.value, target_oid)
                || matches!(
                    extension.parsed_extension(),
                    ParsedExtension::CertificatePolicies(policies)
                        if policies.iter().any(|policy| policy.policy_id.to_id_string() == oid)
                )
        })
}

fn certificate_policies_contains_oid(mut input: &[u8], target_oid: &[u8]) -> bool {
    let Some(policies_content) = der_take_constructed(&mut input, 0x30) else {
        return false;
    };
    if !input.is_empty() {
        return false;
    }

    let mut policies = policies_content;
    while !policies.is_empty() {
        let Some(mut policy_info) = der_take_constructed(&mut policies, 0x30) else {
            return false;
        };
        let Some(policy_oid) = der_take_primitive(&mut policy_info, 0x06) else {
            return false;
        };
        if policy_oid == target_oid {
            return true;
        }
    }
    false
}

fn der_take_constructed<'a>(input: &mut &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    der_take_primitive(input, expected_tag)
}

fn der_take_primitive<'a>(input: &mut &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    let tag = *input.first()?;
    if tag != expected_tag {
        return None;
    }
    *input = &input[1..];
    let length = der_take_length(input)?;
    if input.len() < length {
        return None;
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Some(value)
}

fn der_take_length(input: &mut &[u8]) -> Option<usize> {
    let first = *input.first()?;
    *input = &input[1..];
    if first & 0x80 == 0 {
        return Some(usize::from(first));
    }
    let byte_count = usize::from(first & 0x7f);
    if byte_count == 0 || byte_count > 4 || input.len() < byte_count {
        return None;
    }
    let mut length = 0usize;
    for byte in &input[..byte_count] {
        length = (length << 8) | usize::from(*byte);
    }
    *input = &input[byte_count..];
    Some(length)
}

fn has_any_policy(certificate: &X509Certificate<'_>, oids: &[String]) -> bool {
    oids.iter()
        .any(|oid| certificate_has_policy(certificate, oid))
}

fn extended_key_usage_oids(certificate: &X509Certificate<'_>) -> Option<Vec<Vec<u8>>> {
    let mut matching = certificate
        .iter_extensions()
        .filter(|extension| extension.oid.to_id_string() == OID_EXTENDED_KEY_USAGE_EXTENSION);
    let extension = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    der_sequence_of_oids(extension.value)
}

fn der_sequence_of_oids(mut input: &[u8]) -> Option<Vec<Vec<u8>>> {
    let sequence = der_take_constructed(&mut input, 0x30)?;
    if !input.is_empty() {
        return None;
    }
    let mut values = Vec::new();
    let mut sequence_input = sequence;
    while !sequence_input.is_empty() {
        values.push(der_take_primitive(&mut sequence_input, 0x06)?.to_vec());
    }
    Some(values)
}

fn oid_value_bytes(oid: &str) -> Option<Vec<u8>> {
    Asn1Object::from_str(oid)
        .ok()
        .map(|oid| oid.as_slice().to_vec())
}

fn extension_oid_matches(
    extension: &x509_parser::extensions::X509Extension<'_>,
    oid: &str,
) -> bool {
    oid_value_bytes(oid).is_some_and(|target| extension.oid.as_bytes() == target.as_slice())
        || extension.oid.to_id_string() == oid
}

fn authority_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = extension.parsed_extension() {
            aki.key_identifier
                .as_ref()
                .map(|identifier| identifier.0.to_vec())
        } else {
            None
        }
    })
}

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            Some(identifier.0.to_vec())
        } else {
            None
        }
    })
}

#[derive(Copy, Clone)]
enum CertificateRole {
    Root,
    PlatformIntermediate,
    OrganizationIntermediate,
}

impl CertificateRole {
    fn profile_error(
        self,
        reason: &'static str,
        index: Option<usize>,
    ) -> TzapCertificateProfileError {
        match self {
            Self::Root => TzapCertificateProfileError::RootProfile { reason },
            Self::PlatformIntermediate | Self::OrganizationIntermediate => {
                TzapCertificateProfileError::IntermediateProfile {
                    index: index.unwrap_or(0),
                    reason,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TrustIdentifierError {
    EmptyInput,
    InvalidPrefix,
    InvalidLength,
    InvalidCharacter,
    MixedCase,
    PercentEncoding,
    NotPositive,
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn is_upper_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'F')
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + (byte - b'a')),
        b'A'..=b'F' => Some(10 + (byte - b'A')),
        _ => None,
    }
}

fn is_base64url_char(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn is_path_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
    )
}

/// Formats a lower-case `sha256:` identifier from a 32-byte digest.
#[must_use]
pub fn format_sha256_identifier(digest: &[u8; 32]) -> String {
    let mut value =
        String::with_capacity(SHA256_IDENTIFIER_PREFIX.len() + SHA256_IDENTIFIER_HEX_LENGTH);
    value.push_str(SHA256_IDENTIFIER_PREFIX);
    for byte in digest {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        value.push(char::from(HEX_LOWER[hi]));
        value.push(char::from(HEX_LOWER[lo]));
    }
    value
}

#[must_use]
pub fn format_certificate_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_root_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_issuer_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_crl_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_csr_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_spki_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

/// Validates a canonical lower-case `sha256:` identifier.
#[must_use]
pub fn is_valid_sha256_identifier(value: &str) -> bool {
    parse_sha256_identifier(value).is_ok()
}

/// Parses and validates a canonical lower-case `sha256:` identifier.
pub fn parse_sha256_identifier(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    if value.is_empty() {
        return Err(TrustIdentifierError::EmptyInput);
    }
    if !value.starts_with(SHA256_IDENTIFIER_PREFIX) {
        return Err(TrustIdentifierError::InvalidPrefix);
    }

    let hex = &value[SHA256_IDENTIFIER_PREFIX.len()..];
    if hex.len() != SHA256_IDENTIFIER_HEX_LENGTH {
        return Err(TrustIdentifierError::InvalidLength);
    }

    for byte in hex.bytes() {
        if !is_lower_hex(byte) {
            if is_upper_hex(byte) {
                return Err(TrustIdentifierError::MixedCase);
            }
            return Err(TrustIdentifierError::InvalidCharacter);
        }
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or(TrustIdentifierError::InvalidCharacter)?;
        let lo = hex_value(chunk[1]).ok_or(TrustIdentifierError::InvalidCharacter)?;
        bytes[index] = (hi << 4) | lo;
    }
    Ok(bytes)
}

pub fn parse_certificate_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

pub fn parse_root_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

pub fn parse_issuer_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

pub fn parse_crl_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

pub fn parse_csr_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

pub fn parse_spki_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
    parse_sha256_identifier(value)
}

/// Canonicalizes a positive integer from bytes to uppercase hex.
pub fn canonical_serial_hex(serial_bytes: &[u8]) -> Result<String, TrustIdentifierError> {
    if serial_bytes.is_empty() {
        return Err(TrustIdentifierError::EmptyInput);
    }

    let start = serial_bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(TrustIdentifierError::NotPositive)?;
    let trimmed = &serial_bytes[start..];
    let mut out = String::with_capacity(trimmed.len().saturating_mul(2));
    for byte in trimmed {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        out.push(char::from(HEX_UPPER[hi]));
        out.push(char::from(HEX_UPPER[lo]));
    }
    Ok(out)
}

#[must_use]
pub fn is_valid_serial_hex(serial: &str) -> bool {
    parse_serial_hex(serial).is_ok()
}

/// Parses and validates a canonical uppercase even-length positive serial string.
pub fn parse_serial_hex(serial: &str) -> Result<String, TrustIdentifierError> {
    if serial.is_empty() {
        return Err(TrustIdentifierError::EmptyInput);
    }
    if !serial.len().is_multiple_of(2) {
        return Err(TrustIdentifierError::InvalidLength);
    }
    if !serial.bytes().all(is_upper_hex) {
        if serial
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'F' | b'0'..=b'9'))
        {
            return Err(TrustIdentifierError::MixedCase);
        }
        return Err(TrustIdentifierError::InvalidCharacter);
    }
    if serial.bytes().all(|byte| byte == b'0') {
        return Err(TrustIdentifierError::NotPositive);
    }
    if serial.len() > 2 && serial.starts_with("00") {
        return Err(TrustIdentifierError::InvalidLength);
    }
    Ok(serial.to_string())
}

#[must_use]
pub fn is_valid_base64url_no_padding(value: &str) -> bool {
    validate_base64url_no_padding(value).is_ok()
}

pub fn validate_base64url_no_padding(value: &str) -> Result<(), TrustIdentifierError> {
    if value.is_empty() {
        return Err(TrustIdentifierError::EmptyInput);
    }
    if value.len() % 4 == 1 {
        return Err(TrustIdentifierError::InvalidLength);
    }
    if value.bytes().all(is_base64url_char) {
        return Ok(());
    }
    Err(TrustIdentifierError::InvalidCharacter)
}

#[must_use]
pub fn is_valid_issuer_key_identifier(value: &str) -> bool {
    is_valid_base64url_no_padding(value)
}

#[must_use]
pub fn percent_encode_path_param(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if is_path_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(HEX_UPPER[usize::from(byte >> 4)] as char);
            encoded.push(HEX_UPPER[usize::from(byte & 0x0f)] as char);
        }
    }
    encoded
}

pub fn percent_decode_path_param(value: &str) -> Result<String, TrustIdentifierError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(TrustIdentifierError::PercentEncoding);
        }
        let hi = hex_value(bytes[index + 1]).ok_or(TrustIdentifierError::PercentEncoding)?;
        let lo = hex_value(bytes[index + 2]).ok_or(TrustIdentifierError::PercentEncoding)?;
        out.push((hi << 4) | lo);
        index += 3;
    }

    String::from_utf8(out).map_err(|_| TrustIdentifierError::InvalidCharacter)
}

fn validate_and_percent_encode(identifier: &str) -> Result<String, TrustIdentifierError> {
    parse_sha256_identifier(identifier)?;
    Ok(percent_encode_path_param(identifier))
}

pub fn trust_root_pem_path(root_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(root_sha256)
        .map(|encoded| TRUST_ROOT_PEM_PATH.replace("{root_certificate_sha256}", &encoded))
}

pub fn trust_intermediate_pem_path(issuer_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(issuer_sha256)
        .map(|encoded| TRUST_INTERMEDIATE_PEM_PATH.replace("{issuer_certificate_sha256}", &encoded))
}

pub fn status_certificate_by_fingerprint_path(
    certificate_sha256: &str,
) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(certificate_sha256)
        .map(|encoded| STATUS_BY_FINGERPRINT_PATH.replace("{certificate_sha256}", &encoded))
}

pub fn status_certificate_by_issuer_path(
    issuer_sha256: &str,
    serial: &str,
) -> Result<String, TrustIdentifierError> {
    parse_serial_hex(serial)?;
    validate_and_percent_encode(issuer_sha256).map(|encoded| {
        STATUS_BY_ISSUER_SERIAL_PATH
            .replace("{issuer_certificate_sha256}", &encoded)
            .replace("{serial_number}", serial)
    })
}

pub fn status_crl_pem_path(issuer_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(issuer_sha256)
        .map(|encoded| STATUS_CRL_PEM_PATH.replace("{issuer_certificate_sha256}", &encoded))
}

#[must_use]
pub fn is_valid_public_signer_id(value: &str) -> bool {
    is_valid_public_identifier(value, PUBLIC_SIGNER_ID_PREFIX)
}

#[must_use]
pub fn is_valid_public_org_id(value: &str) -> bool {
    is_valid_public_identifier(value, PUBLIC_ORG_ID_PREFIX)
}

#[must_use]
pub fn is_valid_public_device_id(value: &str) -> bool {
    is_valid_public_identifier(value, PUBLIC_DEVICE_ID_PREFIX)
}

fn is_valid_public_identifier(value: &str, prefix: &str) -> bool {
    if !value.starts_with(prefix) {
        return false;
    }
    let suffix = &value[prefix.len()..];
    if !(PUBLIC_IDENTIFIER_SUFFIX_MIN_LENGTH..=PUBLIC_IDENTIFIER_SUFFIX_MAX_LENGTH)
        .contains(&suffix.len())
    {
        return false;
    }
    suffix
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::{
        OFFICIAL_TZAP_ROOT_PINS, TZAP_MVP_CERTIFICATE_SIGNATURE_ALGORITHMS,
        TZAP_MVP_DOCUMENT_SIGNATURE_ALGORITHMS, TZAP_MVP_LEAF_KEY_ALGORITHMS,
        TZAP_MVP_PAYLOAD_DIGEST_ALGORITHMS, TZAP_OID_CA_POLICY, TZAP_OID_DOCUMENT_SIGNING_EKU,
        TZAP_OID_LEAF_POLICY, TZAP_OID_METADATA_EXTENSION, TzapCertificateProfileError,
        TzapCertificateProfileOptions, TzapCertificateStatus, TzapIdentityAssurance,
        TzapOfficialRootPinKind, TzapRootPinSet, TzapTrustAnchorType, TzapVerificationState,
        canonical_serial_hex, format_certificate_sha256, format_crl_sha256, format_csr_sha256,
        format_issuer_sha256, format_root_sha256, format_spki_sha256,
        is_valid_base64url_no_padding, is_valid_issuer_key_identifier, is_valid_public_device_id,
        is_valid_public_org_id, is_valid_public_signer_id, is_valid_serial_hex,
        is_valid_sha256_identifier, parse_certificate_sha256, parse_crl_sha256, parse_csr_sha256,
        parse_issuer_sha256, parse_root_sha256, parse_serial_hex, parse_sha256_identifier,
        parse_spki_sha256, percent_decode_path_param, percent_encode_path_param,
        status_certificate_by_fingerprint_path, status_certificate_by_issuer_path,
        trust_intermediate_pem_path, trust_root_pem_path, validate_base64url_no_padding,
        validate_custom_tzap_certificate_chain_der, validate_official_tzap_certificate_chain_der,
    };
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, PKeyRef, Private};
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509, X509Extension, X509NameBuilder, X509Ref};
    use serde_json::{Value, json};
    use sha2::Digest as _;

    const SHA256_BYTES: [u8; 32] = [
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xca, 0xdb, 0xec,
        0xfd, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];
    const SHA256_IDENT: &str =
        "sha256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f";

    #[test]
    fn canonical_sha256_formatters_match() {
        assert_eq!(format_certificate_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_root_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_issuer_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_csr_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_crl_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_spki_sha256(&SHA256_BYTES), SHA256_IDENT);
    }

    #[test]
    fn canonical_sha256_parsers_match() {
        assert_eq!(
            parse_certificate_sha256(SHA256_IDENT).unwrap(),
            SHA256_BYTES
        );
        assert_eq!(parse_root_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
        assert_eq!(parse_issuer_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
        assert_eq!(parse_crl_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
        assert_eq!(parse_csr_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
        assert_eq!(parse_spki_sha256(SHA256_IDENT).unwrap(), SHA256_BYTES);
    }

    #[test]
    fn sha256_identifier_validation_rejects_malformed_values() {
        assert!(is_valid_sha256_identifier(SHA256_IDENT));
        assert!(parse_sha256_identifier(SHA256_IDENT).is_ok());

        let invalid_hex_character = format!("sha256:Z{}", "0".repeat(63));
        assert!(matches!(
            super::parse_sha256_identifier(&invalid_hex_character),
            Err(super::TrustIdentifierError::InvalidCharacter)
        ));
        assert!(matches!(
            super::parse_sha256_identifier(
                "SHA256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00"
            ),
            Err(super::TrustIdentifierError::InvalidPrefix)
        ));
        assert!(matches!(
            super::parse_sha256_identifier(
                "sha256:0A1B2C3D4E5F6A7B8C9DAEBFCADBECFD102132435465768798A9BACBDCEDFE0F"
            ),
            Err(super::TrustIdentifierError::MixedCase)
        ));
        assert!(super::parse_sha256_identifier(SHA256_IDENT).is_ok());
        assert!(
            super::parse_sha256_identifier(
                "0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00"
            )
            .is_err()
        );
        assert!(super::parse_sha256_identifier("c2hhMjU2OmFiYw").is_err());
    }

    #[test]
    fn serial_helper_validates_canonical_hex() {
        assert_eq!(
            canonical_serial_hex(&[0x00, 0x01, 0x0a, 0x00]).unwrap(),
            "010A00"
        );
        assert_eq!(canonical_serial_hex(&[0x0a]).unwrap(), "0A");
        assert!(canonical_serial_hex(&[]).is_err());
        assert!(canonical_serial_hex(&[0x00, 0x00]).is_err());
        assert!(is_valid_serial_hex("01ABCDEF"));
        assert!(!is_valid_serial_hex("1aB2"));
        assert!(!is_valid_serial_hex("01ABC"));
        assert!(!is_valid_serial_hex("000000"));
        assert!(!is_valid_serial_hex("0001"));

        assert!(parse_serial_hex("ABCD").is_ok());
        assert!(matches!(
            parse_serial_hex("abcd"),
            Err(super::TrustIdentifierError::MixedCase)
        ));
    }

    #[test]
    fn base64url_validation_enforces_no_padding() {
        assert!(is_valid_base64url_no_padding("SGVsbG9fV29ybGQ"));
        assert!(is_valid_issuer_key_identifier("SGVsbG9fV29ybGQ"));
        assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ").is_ok());
        assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ=").is_err());
        assert!(validate_base64url_no_padding("SGVsbG8+").is_err());
        assert!(validate_base64url_no_padding("A").is_err());
        assert!(validate_base64url_no_padding("").is_err());
    }

    #[test]
    fn percent_encode_decodes_sha256_path_parameter() {
        let encoded = percent_encode_path_param(SHA256_IDENT);
        assert_eq!(
            encoded,
            "sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f"
        );
        assert_eq!(percent_decode_path_param(&encoded).unwrap(), SHA256_IDENT);
        assert!(percent_decode_path_param("%2").is_err());
    }

    #[test]
    fn endpoint_path_builders_validate_and_encode_fingerprint() {
        let root = trust_root_pem_path(SHA256_IDENT).unwrap();
        assert_eq!(
            root,
            "/v1/trust/roots/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f/pem"
        );

        let intermediate = trust_intermediate_pem_path(SHA256_IDENT).unwrap();
        assert_eq!(
            intermediate,
            "/v1/trust/intermediates/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f/pem"
        );

        let fingerprint = status_certificate_by_fingerprint_path(SHA256_IDENT).unwrap();
        assert!(fingerprint.contains("sha256%3A"));

        let by_issuer = status_certificate_by_issuer_path(SHA256_IDENT, "01ABCDEF").unwrap();
        assert_eq!(
            by_issuer,
            "/v1/status/certificates/by-issuer/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f/01ABCDEF"
        );
    }

    #[test]
    fn public_identifier_rules() {
        assert!(is_valid_public_signer_id("psign_AbCdEfGhIjKlMnOpqR1_"));
        assert!(!is_valid_public_signer_id("sign_AbCdEfGhIjKlMnOpqR1_"));
        assert!(!is_valid_public_signer_id("psign_short"));

        assert!(is_valid_public_org_id("porg_AbCdEfGhIjKlMnOpqR1-2_3"));
        assert!(is_valid_public_device_id("pdev_AbCdEfGhIjKlMnOpqR1_2-"));
        assert!(!is_valid_public_device_id("pdev_Only-15chars___"));
    }

    #[test]
    fn enum_roundtrip_helpers_work() {
        assert_eq!(
            super::TzapIdentityAssurance::from_str("oauth_verified_email"),
            Some(TzapIdentityAssurance::OauthVerifiedEmail)
        );
        assert_eq!(
            TzapCertificateStatus::from_str("valid"),
            Some(TzapCertificateStatus::Valid)
        );
        assert_eq!(
            TzapCertificateStatus::from_str("unsupported_lookup_form"),
            Some(TzapCertificateStatus::UnsupportedLookupForm)
        );
        assert_eq!(TzapVerificationState::Invalid.as_str(), "invalid");
        assert_eq!(TzapTrustAnchorType::OfficialTzap.as_str(), "official_tzap");
    }

    #[test]
    fn root_pin_set_helpers() {
        let pins = TzapRootPinSet {
            current: &["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            planned_successors: &[
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        };
        assert!(pins.is_current_root(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(pins.is_planned_successor(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(!pins.is_official_root(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        ));
        assert!(!pins.is_official_root(
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));

        assert!(OFFICIAL_TZAP_ROOT_PINS.current.is_empty());
        assert!(OFFICIAL_TZAP_ROOT_PINS.planned_successors.is_empty());
    }

    #[test]
    fn mvp_algorithm_allowlists_are_named() {
        assert_eq!(
            TZAP_MVP_DOCUMENT_SIGNATURE_ALGORITHMS,
            &["ECDSA-P256-SHA256"]
        );
        assert_eq!(TZAP_MVP_LEAF_KEY_ALGORITHMS, &["ECDSA-P256"]);
        assert_eq!(
            TZAP_MVP_CERTIFICATE_SIGNATURE_ALGORITHMS,
            &["ECDSA-P256-SHA256"]
        );
        assert_eq!(TZAP_MVP_PAYLOAD_DIGEST_ALGORITHMS, &["SHA-256"]);
    }

    #[test]
    fn certificate_profile_accepts_valid_official_chain_and_metadata() {
        let fixture = certificate_fixture(ChainConfig::default());
        let pins = current_pin_set(&fixture.root_pin);

        let validation = validate_official_tzap_certificate_chain_der(
            &fixture.chain_der,
            &pins,
            &TzapCertificateProfileOptions::default(),
        )
        .unwrap();

        assert_eq!(
            validation.trust_anchor_type,
            TzapTrustAnchorType::OfficialTzap
        );
        assert_eq!(
            validation.official_root_pin_kind,
            Some(TzapOfficialRootPinKind::Current)
        );
        assert_eq!(validation.root_certificate_sha256, fixture.root_pin);
        assert_eq!(
            validation.public_metadata.public_signer_id,
            "psign_0123456789ABCDEFGH"
        );
        assert_eq!(
            validation.public_metadata.assurance_level,
            TzapIdentityAssurance::OauthVerifiedEmail
        );
    }

    #[test]
    fn certificate_profile_reports_planned_successor_root_pin() {
        let fixture = certificate_fixture(ChainConfig::default());
        let pins = planned_successor_pin_set(&fixture.root_pin);

        let validation = validate_official_tzap_certificate_chain_der(
            &fixture.chain_der,
            &pins,
            &TzapCertificateProfileOptions::default(),
        )
        .unwrap();

        assert_eq!(
            validation.official_root_pin_kind,
            Some(TzapOfficialRootPinKind::PlannedSuccessor)
        );
    }

    #[test]
    fn certificate_profile_custom_trust_is_distinguishable_from_official_trust() {
        let fixture = certificate_fixture(ChainConfig::default());

        let validation = validate_custom_tzap_certificate_chain_der(
            &fixture.chain_der,
            &TzapCertificateProfileOptions::default(),
        )
        .unwrap();

        assert_eq!(validation.trust_anchor_type, TzapTrustAnchorType::Custom);
        assert_eq!(validation.official_root_pin_kind, None);
    }

    #[test]
    fn certificate_profile_unpinned_or_system_root_trust_never_becomes_official() {
        let fixture = certificate_fixture(ChainConfig::default());
        let pins = TzapRootPinSet {
            current: &[],
            planned_successors: &[],
        };

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &fixture.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::RootNotPinned { .. })
        ));
    }

    #[test]
    fn certificate_profile_rejects_missing_metadata() {
        let fixture = certificate_fixture(ChainConfig {
            metadata: MetadataMode::Missing,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &fixture.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::MissingMetadata)
        ));
    }

    #[test]
    fn certificate_profile_rejects_nested_asn1_metadata() {
        let fixture = certificate_fixture(ChainConfig {
            metadata: MetadataMode::NestedOctetString,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &fixture.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::NestedAsn1Metadata)
        ));
    }

    #[test]
    fn certificate_profile_rejects_unknown_metadata_field() {
        let fixture = certificate_fixture(ChainConfig {
            metadata: MetadataMode::UnknownField,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &fixture.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::UnknownMetadataField { .. })
        ));
    }

    #[test]
    fn certificate_profile_rejects_invalid_public_ids_and_assurance_values() {
        for metadata in [
            MetadataMode::InvalidSignerId,
            MetadataMode::InvalidOrgId,
            MetadataMode::InvalidDeviceId,
            MetadataMode::InvalidAssurance,
        ] {
            let fixture = certificate_fixture(ChainConfig {
                metadata,
                ..ChainConfig::default()
            });
            let pins = current_pin_set(&fixture.root_pin);

            assert!(matches!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                ),
                Err(TzapCertificateProfileError::MalformedMetadata { .. })
            ));
        }
    }

    #[test]
    fn certificate_profile_rejects_symbolic_and_mismatched_metadata_policy_oids() {
        for metadata in [
            MetadataMode::SymbolicPolicyOid,
            MetadataMode::MismatchedPolicyOid,
        ] {
            let fixture = certificate_fixture(ChainConfig {
                metadata,
                ..ChainConfig::default()
            });
            let pins = current_pin_set(&fixture.root_pin);

            assert!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn certificate_profile_rejects_root_profile_errors() {
        for config in [
            ChainConfig {
                root_path_len: 1,
                ..ChainConfig::default()
            },
            ChainConfig {
                root_key_usage_extra_digital_signature: true,
                ..ChainConfig::default()
            },
        ] {
            let fixture = certificate_fixture(config);
            let pins = current_pin_set(&fixture.root_pin);

            assert!(matches!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                ),
                Err(TzapCertificateProfileError::RootProfile { .. })
            ));
        }
    }

    #[test]
    fn certificate_profile_rejects_intermediate_path_and_policy_errors() {
        for config in [
            ChainConfig {
                platform_path_len: 1,
                ..ChainConfig::default()
            },
            ChainConfig {
                omit_platform_ca_policy: true,
                ..ChainConfig::default()
            },
        ] {
            let fixture = certificate_fixture(config);
            let pins = current_pin_set(&fixture.root_pin);

            assert!(matches!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                ),
                Err(TzapCertificateProfileError::IntermediateProfile { .. })
            ));
        }
    }

    #[test]
    fn certificate_profile_rejects_org_intermediate_without_approved_policy() {
        let fixture = certificate_fixture(ChainConfig {
            include_org_intermediate: true,
            omit_org_policy: true,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);
        let mut options = TzapCertificateProfileOptions::default();
        options
            .approved_org_intermediate_policy_oids
            .push(TEST_ORG_POLICY_OID.to_owned());

        assert!(matches!(
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options),
            Err(TzapCertificateProfileError::IntermediateProfile { .. })
        ));
    }

    #[test]
    fn certificate_profile_accepts_org_intermediate_with_approved_policy() {
        let fixture = certificate_fixture(ChainConfig {
            include_org_intermediate: true,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);
        let mut options = TzapCertificateProfileOptions::default();
        options
            .approved_org_intermediate_policy_oids
            .push(TEST_ORG_POLICY_OID.to_owned());

        let validation =
            validate_official_tzap_certificate_chain_der(&fixture.chain_der, &pins, &options)
                .unwrap();

        assert_eq!(
            validation.trust_anchor_type,
            TzapTrustAnchorType::OfficialTzap
        );
    }

    #[test]
    fn certificate_profile_rejects_leaf_eku_for_tls_client_code_and_anyeku() {
        for leaf_eku in [
            LeafEkuMode::ServerAuth,
            LeafEkuMode::ClientAuth,
            LeafEkuMode::CodeSigning,
            LeafEkuMode::AnyExtendedKeyUsage,
        ] {
            let fixture = certificate_fixture(ChainConfig {
                leaf_eku,
                ..ChainConfig::default()
            });
            let pins = current_pin_set(&fixture.root_pin);

            assert!(matches!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                ),
                Err(TzapCertificateProfileError::LeafProfile { .. })
            ));
        }
    }

    #[test]
    fn certificate_profile_rejects_leaf_key_usage_and_san_profile_errors() {
        for config in [
            ChainConfig {
                leaf_key_usage_extra_key_encipherment: true,
                ..ChainConfig::default()
            },
            ChainConfig {
                leaf_validity_days: 181,
                ..ChainConfig::default()
            },
            ChainConfig {
                leaf_san: Some(LeafSanMode::Dns),
                ..ChainConfig::default()
            },
            ChainConfig {
                leaf_san: Some(LeafSanMode::Ip),
                ..ChainConfig::default()
            },
        ] {
            let fixture = certificate_fixture(config);
            let pins = current_pin_set(&fixture.root_pin);

            assert!(matches!(
                validate_official_tzap_certificate_chain_der(
                    &fixture.chain_der,
                    &pins,
                    &TzapCertificateProfileOptions::default(),
                ),
                Err(TzapCertificateProfileError::LeafProfile { .. })
            ));
        }
    }

    #[test]
    fn certificate_profile_rejects_aki_ski_mismatch_and_chain_order() {
        let fixture = certificate_fixture(ChainConfig {
            leaf_aki_from_root: true,
            ..ChainConfig::default()
        });
        let pins = current_pin_set(&fixture.root_pin);
        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &fixture.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::LeafProfile { .. })
        ));

        let mut reordered = certificate_fixture(ChainConfig::default());
        reordered.chain_der.swap(1, 2);
        let pins = current_pin_set(&reordered.root_pin);
        assert!(matches!(
            validate_official_tzap_certificate_chain_der(
                &reordered.chain_der,
                &pins,
                &TzapCertificateProfileOptions::default(),
            ),
            Err(TzapCertificateProfileError::ChainOrder { .. })
                | Err(TzapCertificateProfileError::RootNotSelfSigned)
        ));
    }

    const TEST_ORG_POLICY_OID: &str = "2.25.123456789012345678901234567890123456";
    const TEST_OTHER_POLICY_OID: &str = "2.25.999999999999999999999999999999999999";

    struct CertificateFixture {
        chain_der: Vec<Vec<u8>>,
        root_pin: String,
    }

    #[derive(Clone, Copy)]
    struct ChainConfig {
        include_org_intermediate: bool,
        root_path_len: u32,
        root_key_usage_extra_digital_signature: bool,
        platform_path_len: u32,
        omit_platform_ca_policy: bool,
        omit_org_policy: bool,
        leaf_eku: LeafEkuMode,
        leaf_key_usage_extra_key_encipherment: bool,
        leaf_validity_days: u32,
        leaf_san: Option<LeafSanMode>,
        leaf_aki_from_root: bool,
        metadata: MetadataMode,
    }

    impl Default for ChainConfig {
        fn default() -> Self {
            Self {
                include_org_intermediate: false,
                root_path_len: super::REQUIRED_ROOT_PATH_LEN,
                root_key_usage_extra_digital_signature: false,
                platform_path_len: super::PLATFORM_LEAF_ONLY_PATH_LEN,
                omit_platform_ca_policy: false,
                omit_org_policy: false,
                leaf_eku: LeafEkuMode::DocumentSigning,
                leaf_key_usage_extra_key_encipherment: false,
                leaf_validity_days: 90,
                leaf_san: None,
                leaf_aki_from_root: false,
                metadata: MetadataMode::Valid,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum LeafEkuMode {
        DocumentSigning,
        ServerAuth,
        ClientAuth,
        CodeSigning,
        AnyExtendedKeyUsage,
    }

    #[derive(Clone, Copy)]
    enum LeafSanMode {
        Dns,
        Ip,
    }

    #[derive(Clone, Copy)]
    enum MetadataMode {
        Valid,
        Missing,
        NestedOctetString,
        UnknownField,
        InvalidSignerId,
        InvalidOrgId,
        InvalidDeviceId,
        InvalidAssurance,
        SymbolicPolicyOid,
        MismatchedPolicyOid,
    }

    fn certificate_fixture(config: ChainConfig) -> CertificateFixture {
        let root_key = p256_private_key();
        let platform_key = p256_private_key();
        let leaf_key = p256_private_key();
        let root = root_certificate(&root_key, config);
        let platform = intermediate_certificate(
            "TZAP Platform Intermediate",
            &platform_key,
            root.as_ref(),
            root_key.as_ref(),
            root.as_ref(),
            if config.include_org_intermediate {
                super::PLATFORM_PATH_LEN_WITH_ORG_INTERMEDIATE
            } else {
                config.platform_path_len
            },
            if config.omit_platform_ca_policy {
                vec![]
            } else {
                vec![TZAP_OID_CA_POLICY]
            },
        );

        let (issuer_cert, issuer_key, org_der) = if config.include_org_intermediate {
            let org_key = p256_private_key();
            let mut policies = vec![TZAP_OID_CA_POLICY];
            if !config.omit_org_policy {
                policies.push(TEST_ORG_POLICY_OID);
            }
            let org = intermediate_certificate(
                "TZAP Organization Intermediate",
                &org_key,
                platform.as_ref(),
                platform_key.as_ref(),
                platform.as_ref(),
                super::ORG_INTERMEDIATE_PATH_LEN,
                policies,
            );
            let org_der = org.to_der().unwrap();
            (org, org_key, Some(org_der))
        } else {
            (platform.clone(), platform_key, None)
        };

        let aki_source = if config.leaf_aki_from_root {
            root.as_ref()
        } else {
            issuer_cert.as_ref()
        };
        let leaf = leaf_certificate(
            &leaf_key,
            issuer_cert.as_ref(),
            issuer_key.as_ref(),
            aki_source,
            config,
        );

        let root_der = root.to_der().unwrap();
        let mut root_digest = [0_u8; 32];
        root_digest.copy_from_slice(&sha2::Sha256::digest(&root_der));

        let mut chain_der = vec![leaf.to_der().unwrap()];
        if let Some(org_der) = org_der {
            chain_der.push(org_der);
        }
        chain_der.push(platform.to_der().unwrap());
        chain_der.push(root_der);

        CertificateFixture {
            chain_der,
            root_pin: format_root_sha256(&root_digest),
        }
    }

    fn root_certificate(key: &PKeyRef<Private>, config: ChainConfig) -> X509 {
        let mut builder = base_certificate_builder("TZAP Test Root", key, None);
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .pathlen(config.root_path_len)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut key_usage = KeyUsage::new();
        key_usage.critical().key_cert_sign().crl_sign();
        if config.root_key_usage_extra_digital_signature {
            key_usage.digital_signature();
        }
        builder
            .append_extension(key_usage.build().unwrap())
            .unwrap();
        append_subject_key_identifier(&mut builder, None);
        builder.sign(key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn intermediate_certificate(
        common_name: &str,
        key: &PKeyRef<Private>,
        issuer_cert: &X509Ref,
        issuer_key: &PKeyRef<Private>,
        aki_source: &X509Ref,
        path_len: u32,
        policies: Vec<&str>,
    ) -> X509 {
        let mut builder = base_certificate_builder(common_name, key, Some(issuer_cert));
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .pathlen(path_len)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        append_subject_key_identifier(&mut builder, None);
        append_authority_key_identifier(&mut builder, aki_source);
        if !policies.is_empty() {
            append_der_extension(
                &mut builder,
                "2.5.29.32",
                false,
                &certificate_policies_der(&policies),
            );
        }
        append_der_extension(&mut builder, "2.5.29.31", false, &[0x30, 0x00]);
        builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn leaf_certificate(
        key: &PKeyRef<Private>,
        issuer_cert: &X509Ref,
        issuer_key: &PKeyRef<Private>,
        aki_source: &X509Ref,
        config: ChainConfig,
    ) -> X509 {
        let mut builder = base_certificate_builder("TZAP Test Signer", key, Some(issuer_cert));
        builder
            .set_not_after(&Asn1Time::days_from_now(config.leaf_validity_days).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        let mut key_usage = KeyUsage::new();
        key_usage.critical().digital_signature();
        if config.leaf_key_usage_extra_key_encipherment {
            key_usage.key_encipherment();
        }
        builder
            .append_extension(key_usage.build().unwrap())
            .unwrap();
        builder.append_extension(leaf_eku(config.leaf_eku)).unwrap();
        if let Some(san) = config.leaf_san {
            append_leaf_san(&mut builder, san);
        }
        append_authority_key_identifier(&mut builder, aki_source);
        append_der_extension(
            &mut builder,
            "2.5.29.32",
            false,
            &certificate_policies_der(&[TZAP_OID_LEAF_POLICY]),
        );
        if !matches!(config.metadata, MetadataMode::Missing) {
            append_der_extension(
                &mut builder,
                TZAP_OID_METADATA_EXTENSION,
                false,
                &metadata_extension_bytes(config.metadata),
            );
        }
        builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn base_certificate_builder(
        common_name: &str,
        key: &PKeyRef<Private>,
        issuer: Option<&X509Ref>,
    ) -> openssl::x509::X509Builder {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        if let Some(issuer) = issuer {
            builder.set_issuer_name(issuer.subject_name()).unwrap();
        } else {
            builder.set_issuer_name(&name).unwrap();
        }
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(90).unwrap())
            .unwrap();
        builder
    }

    fn p256_private_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn serial_number() -> openssl::asn1::Asn1Integer {
        BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap()
    }

    fn append_subject_key_identifier(
        builder: &mut openssl::x509::X509Builder,
        issuer: Option<&X509Ref>,
    ) {
        let extension = {
            let context = builder.x509v3_context(issuer, None);
            SubjectKeyIdentifier::new().build(&context).unwrap()
        };
        builder.append_extension(extension).unwrap();
    }

    fn append_authority_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: &X509Ref) {
        let extension = {
            let context = builder.x509v3_context(Some(issuer), None);
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&context)
                .unwrap()
        };
        builder.append_extension(extension).unwrap();
    }

    fn append_leaf_san(builder: &mut openssl::x509::X509Builder, mode: LeafSanMode) {
        let extension = {
            let context = builder.x509v3_context(None, None);
            let mut san = SubjectAlternativeName::new();
            match mode {
                LeafSanMode::Dns => {
                    san.dns("example.test");
                }
                LeafSanMode::Ip => {
                    san.ip("127.0.0.1");
                }
            }
            san.build(&context).unwrap()
        };
        builder.append_extension(extension).unwrap();
    }

    fn leaf_eku(mode: LeafEkuMode) -> X509Extension {
        let mut eku = ExtendedKeyUsage::new();
        match mode {
            LeafEkuMode::DocumentSigning => {
                eku.other(TZAP_OID_DOCUMENT_SIGNING_EKU);
            }
            LeafEkuMode::ServerAuth => {
                eku.server_auth();
            }
            LeafEkuMode::ClientAuth => {
                eku.client_auth();
            }
            LeafEkuMode::CodeSigning => {
                eku.code_signing();
            }
            LeafEkuMode::AnyExtendedKeyUsage => {
                eku.other("2.5.29.37.0");
            }
        }
        eku.build().unwrap()
    }

    fn append_der_extension(
        builder: &mut openssl::x509::X509Builder,
        oid: &str,
        critical: bool,
        contents: &[u8],
    ) {
        let oid = Asn1Object::from_str(oid).unwrap();
        let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
        builder
            .append_extension(X509Extension::new_from_der(&oid, critical, &contents).unwrap())
            .unwrap();
    }

    fn certificate_policies_der(policies: &[&str]) -> Vec<u8> {
        let policy_infos = policies
            .iter()
            .flat_map(|policy| der_sequence(&der_oid(policy)))
            .collect::<Vec<_>>();
        der_sequence(&policy_infos)
    }

    fn der_oid(oid: &str) -> Vec<u8> {
        der_wrap(0x06, Asn1Object::from_str(oid).unwrap().as_slice())
    }

    fn der_sequence(contents: &[u8]) -> Vec<u8> {
        der_wrap(0x30, contents)
    }

    fn der_octet_string(contents: &[u8]) -> Vec<u8> {
        der_wrap(0x04, contents)
    }

    fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(contents.len()));
        out.extend(contents);
        out
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    fn metadata_extension_bytes(mode: MetadataMode) -> Vec<u8> {
        let mut value = json!({
            "version": 1,
            "public_signer_id": "psign_0123456789ABCDEFGH",
            "public_org_id": "porg_0123456789ABCDEFGH",
            "public_device_id": "pdev_0123456789ABCDEFGH",
            "assurance_level": "oauth_verified_email",
            "policy_oid": TZAP_OID_LEAF_POLICY,
        });

        match mode {
            MetadataMode::Valid => {}
            MetadataMode::Missing => unreachable!(),
            MetadataMode::NestedOctetString => {
                return der_octet_string(&metadata_extension_bytes(MetadataMode::Valid));
            }
            MetadataMode::UnknownField => {
                value["unexpected"] = Value::Bool(true);
            }
            MetadataMode::InvalidSignerId => {
                value["public_signer_id"] = Value::String("user_123".to_owned());
            }
            MetadataMode::InvalidOrgId => {
                value["public_org_id"] = Value::String("org_123".to_owned());
            }
            MetadataMode::InvalidDeviceId => {
                value["public_device_id"] = Value::String("device_123".to_owned());
            }
            MetadataMode::InvalidAssurance => {
                value["assurance_level"] = Value::String("verified-ish".to_owned());
            }
            MetadataMode::SymbolicPolicyOid => {
                value["policy_oid"] = Value::String("TBD".to_owned());
            }
            MetadataMode::MismatchedPolicyOid => {
                value["policy_oid"] = Value::String(TEST_OTHER_POLICY_OID.to_owned());
            }
        }

        serde_json_canonicalizer::to_vec(&value).unwrap()
    }

    fn current_pin_set(root_pin: &str) -> TzapRootPinSet {
        let pin: &'static str = Box::leak(root_pin.to_owned().into_boxed_str());
        let current: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
        TzapRootPinSet {
            current,
            planned_successors: &[],
        }
    }

    fn planned_successor_pin_set(root_pin: &str) -> TzapRootPinSet {
        let pin: &'static str = Box::leak(root_pin.to_owned().into_boxed_str());
        let planned_successors: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
        TzapRootPinSet {
            current: &[],
            planned_successors,
        }
    }
}
