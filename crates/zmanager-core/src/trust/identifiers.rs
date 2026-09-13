//! TZAP identifier and encoding helpers (CR-137).
//!
//! `sha256:` identifiers, URL-safe base64, serial hex, public-id validation,
//! and the status endpoint path builders. Moved out of `trust.rs`; the public
//! items are re-exported from [`crate::trust`].

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

use crate::trust::{
    PUBLIC_DEVICE_ID_PREFIX, PUBLIC_IDENTIFIER_SUFFIX_MAX_LENGTH, PUBLIC_IDENTIFIER_SUFFIX_MIN_LENGTH, PUBLIC_ORG_ID_PREFIX, PUBLIC_SIGNER_ID_PREFIX,
    SHA256_IDENTIFIER_HEX_LENGTH, SHA256_IDENTIFIER_PREFIX, STATUS_BY_FINGERPRINT_PATH, STATUS_CRL_PEM_PATH,
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

/// Computes the `sha256:` identifier of arbitrary bytes. Shared by the
/// client and service modules (CR-124).
#[must_use]
pub fn sha256_identifier(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format_sha256_identifier(&digest)
}

/// Decodes URL-safe base64 without padding, validating the alphabet first.
/// Shared by the client modules (CR-124).
pub fn decode_base64url_no_padding(value: &str) -> Result<Vec<u8>, String> {
    validate_base64url_no_padding(value).map_err(|error| format!("{error:?}"))?;
    URL_SAFE_NO_PAD.decode(value).map_err(|error| error.to_string())
}

/// Builds verification chains: the embedded chain alone plus one candidate
/// per supplied root appended to it (CR-124).
#[must_use]
pub(crate) fn candidate_chains(embedded_chain_der: &[Vec<u8>], roots_der: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
    let mut candidates = Vec::with_capacity(1 + roots_der.len());
    candidates.push(embedded_chain_der.to_vec());
    candidates.extend(roots_der.iter().map(|root_der| {
        let mut chain = Vec::with_capacity(embedded_chain_der.len() + 1);
        chain.extend_from_slice(embedded_chain_der);
        chain.push(root_der.clone());
        chain
    }));
    candidates
}

/// Formats a lower-case `sha256:` identifier from a 32-byte digest.
#[must_use]
pub fn format_sha256_identifier(digest: &[u8; 32]) -> String {
    let mut value = String::with_capacity(SHA256_IDENTIFIER_PREFIX.len() + SHA256_IDENTIFIER_HEX_LENGTH);
    value.push_str(SHA256_IDENTIFIER_PREFIX);
    value.push_str(&crate::hex::hex_lower(digest));
    value
}

#[must_use]
pub fn format_certificate_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_issuer_sha256(digest: &[u8; 32]) -> String {
    format_sha256_identifier(digest)
}

#[must_use]
pub fn format_csr_sha256(digest: &[u8; 32]) -> String {
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
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_value(chunk[0]).ok_or(TrustIdentifierError::InvalidCharacter)?;
        let lo = hex_value(chunk[1]).ok_or(TrustIdentifierError::InvalidCharacter)?;
        bytes[index] = (hi << 4) | lo;
    }
    Ok(bytes)
}

pub fn parse_certificate_sha256(value: &str) -> Result<[u8; 32], TrustIdentifierError> {
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

    let start = serial_bytes.iter().position(|byte| *byte != 0).ok_or(TrustIdentifierError::NotPositive)?;
    let trimmed = &serial_bytes[start..];
    Ok(crate::hex::hex_upper(trimmed))
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
            encoded.push_str(&crate::hex::hex_upper(&[byte]));
        }
    }
    encoded
}

fn validate_and_percent_encode(identifier: &str) -> Result<String, TrustIdentifierError> {
    parse_sha256_identifier(identifier)?;
    Ok(percent_encode_path_param(identifier))
}

pub fn status_certificate_by_fingerprint_path(certificate_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(certificate_sha256).map(|encoded| STATUS_BY_FINGERPRINT_PATH.replace("{certificate_sha256}", &encoded))
}

pub fn status_crl_pem_path(issuer_sha256: &str) -> Result<String, TrustIdentifierError> {
    validate_and_percent_encode(issuer_sha256).map(|encoded| STATUS_CRL_PEM_PATH.replace("{issuer_certificate_sha256}", &encoded))
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
    suffix.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
}
