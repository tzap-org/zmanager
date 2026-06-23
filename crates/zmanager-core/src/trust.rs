//! Shared TZAP trust constants and canonical identifier helpers.

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

/// MVP OIDs (numeric UUID-derived arcs).
pub const TZAP_OID_DOCUMENT_SIGNING_EKU: &str =
    "2.25.201653505380392472132808080578384925035";
pub const TZAP_OID_CA_POLICY: &str = "2.25.216801977638581014157980575261877559132";
pub const TZAP_OID_LEAF_POLICY: &str = "2.25.194500518885741369143906285659225836299";
pub const TZAP_OID_METADATA_EXTENSION: &str = "2.25.25754549376475580214508793807157112225";
pub const TZAP_OID_STATUS_PROOF_EXTENSION: &str =
    "2.25.25951712805955241282365074948746758705";

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
        self.current.iter().any(|value| value == &fingerprint)
    }

    #[must_use]
    pub fn is_planned_successor(&self, fingerprint: &str) -> bool {
        self.planned_successors
            .iter()
            .any(|value| value == &fingerprint)
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
    let mut value = String::with_capacity(SHA256_IDENTIFIER_PREFIX.len() + SHA256_IDENTIFIER_HEX_LENGTH);
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

/// Canonicalizes a positive integer from bytes to uppercase hex.
#[must_use]
pub fn canonical_serial_hex(serial_bytes: &[u8]) -> String {
    let mut start = 0usize;
    while start + 1 < serial_bytes.len() && serial_bytes[start] == b'0' {
        start += 1;
    }
    let trimmed = &serial_bytes[start..];
    let mut out = String::with_capacity(trimmed.len().saturating_mul(2));
    for byte in trimmed {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        out.push(char::from(HEX_UPPER[hi]));
        out.push(char::from(HEX_UPPER[lo]));
    }
    if out.is_empty() {
        out.push_str("00");
    }
    out
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
        if serial.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'F' | b'0'..=b'9')) {
            return Err(TrustIdentifierError::MixedCase);
        }
        return Err(TrustIdentifierError::InvalidCharacter);
    }
    if serial.bytes().all(|byte| byte == b'0') {
        return Err(TrustIdentifierError::NotPositive);
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
    if value.bytes().all(is_base64url_char) {
        return Ok(());
    }
    Err(TrustIdentifierError::InvalidCharacter)
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
    if !is_valid_sha256_identifier(identifier) {
        return Err(TrustIdentifierError::InvalidCharacter);
    }
    Ok(percent_encode_path_param(identifier))
}

pub fn trust_root_pem_path(root_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(root_sha256).map(|encoded| {
        TRUST_ROOT_PEM_PATH.replace("{root_certificate_sha256}", &encoded)
    })
}

pub fn trust_intermediate_pem_path(issuer_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(issuer_sha256).map(|encoded| {
        TRUST_INTERMEDIATE_PEM_PATH.replace("{issuer_certificate_sha256}", &encoded)
    })
}

pub fn status_certificate_by_fingerprint_path(
    certificate_sha256: &str,
) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(certificate_sha256).map(|encoded| {
        STATUS_BY_FINGERPRINT_PATH.replace("{certificate_sha256}", &encoded)
    })
}

pub fn status_certificate_by_issuer_path(
    issuer_sha256: &str,
    serial: &str,
) -> Result<String, TrustIdentifierError> {
    if !is_valid_serial_hex(serial) {
        return Err(TrustIdentifierError::InvalidCharacter);
    }
    validate_and_percent_encode(issuer_sha256).map(|encoded| {
        STATUS_BY_ISSUER_SERIAL_PATH
            .replace("{issuer_certificate_sha256}", &encoded)
            .replace("{serial_number}", serial)
    })
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
    if !(PUBLIC_IDENTIFIER_SUFFIX_MIN_LENGTH..=PUBLIC_IDENTIFIER_SUFFIX_MAX_LENGTH).contains(&suffix.len()) {
        return false;
    }
    suffix
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_serial_hex, format_certificate_sha256, format_csr_sha256, format_crl_sha256,
        format_root_sha256, format_spki_sha256, is_valid_base64url_no_padding,
        is_valid_public_device_id, is_valid_public_org_id, is_valid_public_signer_id,
        is_valid_serial_hex, is_valid_sha256_identifier, parse_serial_hex, parse_sha256_identifier,
        percent_decode_path_param, percent_encode_path_param, status_certificate_by_fingerprint_path,
        status_certificate_by_issuer_path, trust_intermediate_pem_path, trust_root_pem_path,
        validate_base64url_no_padding, TzapCertificateStatus, TzapIdentityAssurance,
        TzapTrustAnchorType, TzapVerificationState, TzapRootPinSet, OFFICIAL_TZAP_ROOT_PINS,
    };

    const SHA256_BYTES: [u8; 32] = [
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf,
        0xca, 0xdb, 0xec, 0xfd, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
        0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x00,
    ];
    const SHA256_IDENT: &str =
        "sha256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00";

    #[test]
    fn canonical_sha256_formatters_match() {
        assert_eq!(format_certificate_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_root_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_csr_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_crl_sha256(&SHA256_BYTES), SHA256_IDENT);
        assert_eq!(format_spki_sha256(&SHA256_BYTES), SHA256_IDENT);
    }

    #[test]
    fn sha256_identifier_validation_rejects_malformed_values() {
        assert!(is_valid_sha256_identifier(SHA256_IDENT));
        assert!(parse_sha256_identifier(SHA256_IDENT).is_ok());

        assert!(matches!(
            super::parse_sha256_identifier("sha256:Z0000000000000000000000000000000000000000000000000000000000000000"),
            Err(super::TrustIdentifierError::InvalidCharacter)
        ));
        assert!(matches!(
            super::parse_sha256_identifier("SHA256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00"),
            Err(super::TrustIdentifierError::InvalidPrefix)
        ));
        assert!(matches!(
            super::parse_sha256_identifier("sha256:0A1B2C3D4E5F6A7B8C9DAE... "),
            Err(super::TrustIdentifierError::InvalidLength)
        ));
        assert!(super::parse_sha256_identifier("sha256:0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00").is_ok());
        assert!(super::parse_sha256_identifier("0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00").is_err());
    }

    #[test]
    fn serial_helper_validates_canonical_hex() {
        assert_eq!(canonical_serial_hex(&[0x00, 0x01, 0x0a, 0x00]), "10A0");
        assert!(is_valid_serial_hex("01ABCDEF"));
        assert!(!is_valid_serial_hex("1aB2"));
        assert!(!is_valid_serial_hex("01ABC"));
        assert!(!is_valid_serial_hex("000000"));

        assert!(parse_serial_hex("ABCD").is_ok());
        assert!(matches!(
            parse_serial_hex("abcd"),
            Err(super::TrustIdentifierError::MixedCase)
        ));
    }

    #[test]
    fn base64url_validation_enforces_no_padding() {
        assert!(is_valid_base64url_no_padding("SGVsbG9fV29ybGQ"));
        assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ").is_ok());
        assert!(validate_base64url_no_padding("SGVsbG9fV29ybGQ=").is_err());
        assert!(validate_base64url_no_padding("SGVsbG8+").is_err());
        assert!(validate_base64url_no_padding("").is_err());
    }

    #[test]
    fn percent_encode_decodes_sha256_path_parameter() {
        let encoded = percent_encode_path_param(SHA256_IDENT);
        assert_eq!(encoded, "sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00");
        assert_eq!(percent_decode_path_param(&encoded).unwrap(), SHA256_IDENT);
        assert!(percent_decode_path_param("%2").is_err());
    }

    #[test]
    fn endpoint_path_builders_validate_and_encode_fingerprint() {
        let root = trust_root_pem_path(SHA256_IDENT).unwrap();
        assert_eq!(root, "/v1/trust/roots/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00/pem");

        let intermediate = trust_intermediate_pem_path(SHA256_IDENT).unwrap();
        assert_eq!(intermediate, "/v1/trust/intermediates/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00/pem");

        let fingerprint = status_certificate_by_fingerprint_path(SHA256_IDENT).unwrap();
        assert!(fingerprint.contains("sha256%3A"));

        let by_issuer = status_certificate_by_issuer_path(SHA256_IDENT, "01ABCDEF").unwrap();
        assert_eq!(
            by_issuer,
            "/v1/status/certificates/by-issuer/sha256%3A0a1b2c3d4e5f6a7b8c9daebfcadbecfd102132435465768798a9bacbdcedfe0f00/01ABCDEF"
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
        assert_eq!(TzapCertificateStatus::from_str("valid"), Some(TzapCertificateStatus::Valid));
        assert_eq!(TzapCertificateStatus::from_str("unsupported_lookup_form"), Some(TzapCertificateStatus::UnsupportedLookupForm));
        assert_eq!(TzapVerificationState::Invalid.as_str(), "invalid");
        assert_eq!(TzapTrustAnchorType::OfficialTzap.as_str(), "official_tzap");
    }

    #[test]
    fn root_pin_set_helpers() {
        let pins = TzapRootPinSet {
            current: &["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            planned_successors: &["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        };
        assert!(pins.is_current_root("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(pins.is_planned_successor("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(!pins.is_official_root("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));

        assert!(OFFICIAL_TZAP_ROOT_PINS.current.is_empty());
        assert!(OFFICIAL_TZAP_ROOT_PINS.planned_successors.is_empty());
    }
}
