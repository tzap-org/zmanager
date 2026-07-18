//! MVP TZAP document-envelope parsing and structural validation.

use crate::{jcs, trust};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use std::fmt;

pub const FIELD_DOCUMENT_PAYLOAD: &str = "document_payload";
pub const FIELD_SIGNED_PAYLOAD: &str = "signed_payload";
pub const FIELD_SIGNATURE: &str = "signature";
pub const FIELD_LEAF_CERTIFICATE_DER: &str = "leaf_certificate_der";
pub const FIELD_INTERMEDIATE_CHAIN_DER: &str = "intermediate_chain_der";
pub const FIELD_TIMESTAMP_TOKEN: &str = "timestamp_token";
pub const FIELD_STATUS_PROOF: &str = "status_proof";

pub const FIELD_TZAP_PAYLOAD_VERSION: &str = "tzap_payload_version";
pub const TZAP_RESERVED_FIELD_PREFIX: &str = "tzap_";

pub const FIELD_ENVELOPE_VERSION: &str = "envelope_version";
pub const FIELD_DOMAIN_SEPARATOR: &str = "domain_separator";
pub const FIELD_PAYLOAD_HASH_ALGORITHM: &str = "payload_hash_algorithm";
pub const FIELD_PAYLOAD_HASH: &str = "payload_hash";
pub const FIELD_SIGNATURE_ALGORITHM: &str = "signature_algorithm";
pub const FIELD_LEAF_CERTIFICATE_SHA256: &str = "leaf_certificate_sha256";
pub const FIELD_ISSUER_CERTIFICATE_SHA256: &str = "issuer_certificate_sha256";
pub const FIELD_ISSUER_KEY_IDENTIFIER: &str = "issuer_key_identifier";
pub const FIELD_CERTIFICATE_SERIAL_NUMBER: &str = "certificate_serial_number";
pub const FIELD_CLAIMED_SIGNING_TIME: &str = "claimed_signing_time";

const MVP_SIGNATURE_BYTES: usize = crate::p256_signature::P256_P1363_SIGNATURE_LENGTH;

const REQUIRED_ENVELOPE_FIELDS: &[&str] = &[
    FIELD_DOCUMENT_PAYLOAD,
    FIELD_SIGNED_PAYLOAD,
    FIELD_SIGNATURE,
    FIELD_LEAF_CERTIFICATE_DER,
    FIELD_INTERMEDIATE_CHAIN_DER,
];
const OPTIONAL_ENVELOPE_FIELDS: &[&str] = &[FIELD_TIMESTAMP_TOKEN, FIELD_STATUS_PROOF];
const REQUIRED_SIGNED_PAYLOAD_FIELDS: &[&str] = &[
    FIELD_ENVELOPE_VERSION,
    FIELD_DOMAIN_SEPARATOR,
    FIELD_PAYLOAD_HASH_ALGORITHM,
    FIELD_PAYLOAD_HASH,
    FIELD_SIGNATURE_ALGORITHM,
    FIELD_LEAF_CERTIFICATE_SHA256,
    FIELD_ISSUER_CERTIFICATE_SHA256,
    FIELD_ISSUER_KEY_IDENTIFIER,
    FIELD_CERTIFICATE_SERIAL_NUMBER,
];
const OPTIONAL_SIGNED_PAYLOAD_FIELDS: &[&str] = &[FIELD_CLAIMED_SIGNING_TIME];

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDocumentEnvelope {
    pub document_payload: Value,
    pub signed_payload: TzapSignedPayload,
    pub signature: Vec<u8>,
    pub leaf_certificate_der: Vec<u8>,
    pub intermediate_chain_der: Vec<Vec<u8>>,
    pub timestamp_token: Option<String>,
    pub status_proof: Option<Value>,
    pub canonical_document_payload: Vec<u8>,
    pub canonical_signed_payload: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapSignedPayload {
    pub envelope_version: u64,
    pub domain_separator: String,
    pub payload_hash_algorithm: String,
    pub payload_hash: String,
    pub signature_algorithm: String,
    pub leaf_certificate_sha256: String,
    pub issuer_certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub certificate_serial_number: String,
    pub claimed_signing_time: Option<String>,
}

#[derive(Debug)]
pub enum TzapDocumentEnvelopeError {
    InvalidJson(serde_json::Error),
    Canonicalization(jcs::JcsError),
    ExpectedObject {
        path: &'static str,
    },
    ExpectedArray {
        path: &'static str,
    },
    MissingField {
        path: &'static str,
        field: &'static str,
    },
    UnknownField {
        path: &'static str,
        field: String,
    },
    InvalidInteger {
        path: &'static str,
        field: &'static str,
    },
    UnsupportedVersion {
        field: &'static str,
        actual: u64,
        expected: u16,
    },
    InvalidString {
        path: &'static str,
        field: &'static str,
    },
    InvalidConstant {
        field: &'static str,
        expected: &'static str,
    },
    ReservedPayloadField {
        field: String,
    },
    InvalidIdentifier {
        field: &'static str,
    },
    PayloadHashMismatch {
        expected: String,
        actual: String,
    },
    InvalidBase64Url {
        field: &'static str,
    },
    InvalidSignatureLength {
        actual: usize,
    },
    EmptyDer {
        field: &'static str,
    },
    EmptyIntermediateChain,
}

impl From<serde_json::Error> for TzapDocumentEnvelopeError {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidJson(err)
    }
}

impl From<jcs::JcsError> for TzapDocumentEnvelopeError {
    fn from(err: jcs::JcsError) -> Self {
        Self::Canonicalization(err)
    }
}

impl fmt::Display for TzapDocumentEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "document envelope JSON is invalid: {err}"),
            Self::Canonicalization(_) => write!(f, "document envelope is not JCS canonicalizable"),
            Self::ExpectedObject { path } => write!(f, "{path} must be a JSON object"),
            Self::ExpectedArray { path } => write!(f, "{path} must be a JSON array"),
            Self::MissingField { path, field } => write!(f, "{path}.{field} is required"),
            Self::UnknownField { path, field } => write!(f, "{path}.{field} is not allowed"),
            Self::InvalidInteger { path, field } => {
                write!(f, "{path}.{field} must be a JSON integer")
            }
            Self::UnsupportedVersion {
                field,
                actual,
                expected,
            } => write!(
                f,
                "{field} version {actual} is unsupported; expected {expected}"
            ),
            Self::InvalidString { path, field } => {
                write!(f, "{path}.{field} must be a non-empty string")
            }
            Self::InvalidConstant { field, expected } => {
                write!(f, "{field} must be {expected}")
            }
            Self::ReservedPayloadField { field } => {
                write!(
                    f,
                    "document_payload.{field} uses a reserved TZAP field name"
                )
            }
            Self::InvalidIdentifier { field } => write!(f, "{field} is not canonical"),
            Self::PayloadHashMismatch { expected, actual } => {
                write!(
                    f,
                    "payload_hash mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidBase64Url { field } => {
                write!(f, "{field} must be base64url without padding")
            }
            Self::InvalidSignatureLength { actual } => {
                write!(
                    f,
                    "signature decodes to {actual} bytes; expected {MVP_SIGNATURE_BYTES}"
                )
            }
            Self::EmptyDer { field } => write!(f, "{field} must decode to non-empty DER bytes"),
            Self::EmptyIntermediateChain => {
                write!(
                    f,
                    "intermediate_chain_der must contain at least the issuer certificate"
                )
            }
        }
    }
}

impl std::error::Error for TzapDocumentEnvelopeError {}

pub fn parse_tzap_document_envelope_json(
    bytes: &[u8],
) -> Result<TzapDocumentEnvelope, TzapDocumentEnvelopeError> {
    let value: Value = serde_json::from_slice(bytes)?;
    validate_tzap_document_envelope_value(&value)
}

pub fn validate_tzap_document_envelope_value(
    value: &Value,
) -> Result<TzapDocumentEnvelope, TzapDocumentEnvelopeError> {
    let envelope = object_at(value, "$")?;
    validate_known_fields(
        envelope,
        "$",
        REQUIRED_ENVELOPE_FIELDS,
        OPTIONAL_ENVELOPE_FIELDS,
    )?;

    let document_payload = required_object_field(envelope, "$", FIELD_DOCUMENT_PAYLOAD)?;
    validate_document_payload(document_payload)?;
    let document_payload_value = Value::Object(document_payload.clone());
    let canonical_document_payload = jcs::canonicalize_json_bytes(&document_payload_value)?;
    let expected_payload_hash = jcs::canonical_sha256_digest(&document_payload_value)?;

    let signed_payload_object = required_object_field(envelope, "$", FIELD_SIGNED_PAYLOAD)?;
    let signed_payload = validate_signed_payload(signed_payload_object, &expected_payload_hash)?;
    let canonical_signed_payload =
        jcs::canonicalize_json_bytes(&Value::Object(signed_payload_object.clone()))?;

    let signature = decode_required_base64url(envelope, "$", FIELD_SIGNATURE)?;
    if signature.len() != MVP_SIGNATURE_BYTES {
        return Err(TzapDocumentEnvelopeError::InvalidSignatureLength {
            actual: signature.len(),
        });
    }

    let leaf_certificate_der = decode_required_non_empty_base64url_der(
        envelope,
        "$",
        FIELD_LEAF_CERTIFICATE_DER,
        FIELD_LEAF_CERTIFICATE_DER,
    )?;
    let intermediate_chain_der = decode_intermediate_chain(envelope)?;
    let timestamp_token = optional_string_field(envelope, "$", FIELD_TIMESTAMP_TOKEN)?;
    let status_proof = envelope.get(FIELD_STATUS_PROOF).cloned();

    Ok(TzapDocumentEnvelope {
        document_payload: document_payload_value,
        signed_payload,
        signature,
        leaf_certificate_der,
        intermediate_chain_der,
        timestamp_token,
        status_proof,
        canonical_document_payload,
        canonical_signed_payload,
    })
}

fn validate_document_payload(
    payload: &Map<String, Value>,
) -> Result<(), TzapDocumentEnvelopeError> {
    let version =
        required_integer_field(payload, FIELD_DOCUMENT_PAYLOAD, FIELD_TZAP_PAYLOAD_VERSION)?;
    if version != u64::from(trust::TZAP_PAYLOAD_VERSION) {
        return Err(TzapDocumentEnvelopeError::UnsupportedVersion {
            field: FIELD_TZAP_PAYLOAD_VERSION,
            actual: version,
            expected: trust::TZAP_PAYLOAD_VERSION,
        });
    }

    for field in payload.keys() {
        if field.starts_with(TZAP_RESERVED_FIELD_PREFIX) && field != FIELD_TZAP_PAYLOAD_VERSION {
            return Err(TzapDocumentEnvelopeError::ReservedPayloadField {
                field: field.clone(),
            });
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_signed_payload(
    signed_payload: &Map<String, Value>,
    expected_payload_hash: &str,
) -> Result<TzapSignedPayload, TzapDocumentEnvelopeError> {
    validate_known_fields(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        REQUIRED_SIGNED_PAYLOAD_FIELDS,
        OPTIONAL_SIGNED_PAYLOAD_FIELDS,
    )?;

    let envelope_version =
        required_integer_field(signed_payload, FIELD_SIGNED_PAYLOAD, FIELD_ENVELOPE_VERSION)?;
    if envelope_version != u64::from(trust::TZAP_ENVELOPE_VERSION) {
        return Err(TzapDocumentEnvelopeError::UnsupportedVersion {
            field: FIELD_ENVELOPE_VERSION,
            actual: envelope_version,
            expected: trust::TZAP_ENVELOPE_VERSION,
        });
    }

    let domain_separator =
        required_string_field(signed_payload, FIELD_SIGNED_PAYLOAD, FIELD_DOMAIN_SEPARATOR)?;
    require_constant(
        FIELD_DOMAIN_SEPARATOR,
        &domain_separator,
        trust::TZAP_DOCUMENT_DOMAIN_SEPARATOR,
    )?;

    let payload_hash_algorithm = required_string_field(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        FIELD_PAYLOAD_HASH_ALGORITHM,
    )?;
    require_constant(
        FIELD_PAYLOAD_HASH_ALGORITHM,
        &payload_hash_algorithm,
        trust::TZAP_PAYLOAD_DIGEST_ALGORITHM,
    )?;

    let payload_hash =
        required_string_field(signed_payload, FIELD_SIGNED_PAYLOAD, FIELD_PAYLOAD_HASH)?;
    if trust::parse_sha256_identifier(&payload_hash).is_err() {
        return Err(TzapDocumentEnvelopeError::InvalidIdentifier {
            field: FIELD_PAYLOAD_HASH,
        });
    }
    if payload_hash != expected_payload_hash {
        return Err(TzapDocumentEnvelopeError::PayloadHashMismatch {
            expected: expected_payload_hash.to_owned(),
            actual: payload_hash,
        });
    }

    let signature_algorithm = required_string_field(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        FIELD_SIGNATURE_ALGORITHM,
    )?;
    require_constant(
        FIELD_SIGNATURE_ALGORITHM,
        &signature_algorithm,
        trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM,
    )?;

    let leaf_certificate_sha256 = required_canonical_sha256(
        signed_payload,
        FIELD_LEAF_CERTIFICATE_SHA256,
        trust::parse_certificate_sha256,
    )?;
    let issuer_certificate_sha256 = required_canonical_sha256(
        signed_payload,
        FIELD_ISSUER_CERTIFICATE_SHA256,
        trust::parse_issuer_sha256,
    )?;
    let issuer_key_identifier = required_string_field(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        FIELD_ISSUER_KEY_IDENTIFIER,
    )?;
    if !trust::is_valid_issuer_key_identifier(&issuer_key_identifier) {
        return Err(TzapDocumentEnvelopeError::InvalidIdentifier {
            field: FIELD_ISSUER_KEY_IDENTIFIER,
        });
    }

    let certificate_serial_number = required_string_field(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        FIELD_CERTIFICATE_SERIAL_NUMBER,
    )?;
    if trust::parse_serial_hex(&certificate_serial_number).is_err() {
        return Err(TzapDocumentEnvelopeError::InvalidIdentifier {
            field: FIELD_CERTIFICATE_SERIAL_NUMBER,
        });
    }

    let claimed_signing_time = optional_string_field(
        signed_payload,
        FIELD_SIGNED_PAYLOAD,
        FIELD_CLAIMED_SIGNING_TIME,
    )?;

    Ok(TzapSignedPayload {
        envelope_version,
        domain_separator,
        payload_hash_algorithm,
        payload_hash: expected_payload_hash.to_owned(),
        signature_algorithm,
        leaf_certificate_sha256,
        issuer_certificate_sha256,
        issuer_key_identifier,
        certificate_serial_number,
        claimed_signing_time,
    })
}

fn decode_intermediate_chain(
    envelope: &Map<String, Value>,
) -> Result<Vec<Vec<u8>>, TzapDocumentEnvelopeError> {
    let value = required_field(envelope, "$", FIELD_INTERMEDIATE_CHAIN_DER)?
        .as_array()
        .ok_or(TzapDocumentEnvelopeError::ExpectedArray {
            path: FIELD_INTERMEDIATE_CHAIN_DER,
        })?;
    if value.is_empty() {
        return Err(TzapDocumentEnvelopeError::EmptyIntermediateChain);
    }

    value
        .iter()
        .map(|item| {
            let Some(encoded) = item.as_str() else {
                return Err(TzapDocumentEnvelopeError::InvalidString {
                    path: FIELD_INTERMEDIATE_CHAIN_DER,
                    field: FIELD_INTERMEDIATE_CHAIN_DER,
                });
            };
            decode_base64url_der(encoded, FIELD_INTERMEDIATE_CHAIN_DER)
        })
        .collect()
}

fn decode_required_non_empty_base64url_der(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
    error_field: &'static str,
) -> Result<Vec<u8>, TzapDocumentEnvelopeError> {
    let encoded = required_string_field(object, path, field)?;
    decode_base64url_der(&encoded, error_field)
}

fn decode_base64url_der(
    encoded: &str,
    field: &'static str,
) -> Result<Vec<u8>, TzapDocumentEnvelopeError> {
    let bytes = decode_base64url(encoded, field)?;
    if bytes.is_empty() {
        return Err(TzapDocumentEnvelopeError::EmptyDer { field });
    }
    Ok(bytes)
}

fn decode_required_base64url(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<Vec<u8>, TzapDocumentEnvelopeError> {
    let encoded = required_string_field(object, path, field)?;
    decode_base64url(&encoded, field)
}

fn decode_base64url(
    encoded: &str,
    field: &'static str,
) -> Result<Vec<u8>, TzapDocumentEnvelopeError> {
    trust::validate_base64url_no_padding(encoded)
        .map_err(|_| TzapDocumentEnvelopeError::InvalidBase64Url { field })?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TzapDocumentEnvelopeError::InvalidBase64Url { field })
}

fn required_canonical_sha256(
    object: &Map<String, Value>,
    field: &'static str,
    parser: fn(&str) -> Result<[u8; 32], trust::TrustIdentifierError>,
) -> Result<String, TzapDocumentEnvelopeError> {
    let value = required_string_field(object, FIELD_SIGNED_PAYLOAD, field)?;
    parser(&value).map_err(|_| TzapDocumentEnvelopeError::InvalidIdentifier { field })?;
    Ok(value)
}

fn require_constant(
    field: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), TzapDocumentEnvelopeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TzapDocumentEnvelopeError::InvalidConstant { field, expected })
    }
}

fn validate_known_fields(
    object: &Map<String, Value>,
    path: &'static str,
    required: &[&'static str],
    optional: &[&'static str],
) -> Result<(), TzapDocumentEnvelopeError> {
    for field in required {
        if !object.contains_key(*field) {
            return Err(TzapDocumentEnvelopeError::MissingField { path, field });
        }
    }

    for field in object.keys() {
        if !required.contains(&field.as_str()) && !optional.contains(&field.as_str()) {
            return Err(TzapDocumentEnvelopeError::UnknownField {
                path,
                field: field.clone(),
            });
        }
    }

    Ok(())
}

fn object_at<'a>(
    value: &'a Value,
    path: &'static str,
) -> Result<&'a Map<String, Value>, TzapDocumentEnvelopeError> {
    value
        .as_object()
        .ok_or(TzapDocumentEnvelopeError::ExpectedObject { path })
}

fn required_object_field<'a>(
    object: &'a Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<&'a Map<String, Value>, TzapDocumentEnvelopeError> {
    object_at(required_field(object, path, field)?, field)
}

fn required_field<'a>(
    object: &'a Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<&'a Value, TzapDocumentEnvelopeError> {
    object
        .get(field)
        .ok_or(TzapDocumentEnvelopeError::MissingField { path, field })
}

fn required_integer_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<u64, TzapDocumentEnvelopeError> {
    let value = required_field(object, path, field)?;
    value
        .as_u64()
        .ok_or(TzapDocumentEnvelopeError::InvalidInteger { path, field })
}

fn required_string_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<String, TzapDocumentEnvelopeError> {
    let value = required_field(object, path, field)?;
    let Some(value) = value.as_str() else {
        return Err(TzapDocumentEnvelopeError::InvalidString { path, field });
    };
    if value.is_empty() {
        return Err(TzapDocumentEnvelopeError::InvalidString { path, field });
    }
    Ok(value.to_owned())
}

fn optional_string_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<Option<String>, TzapDocumentEnvelopeError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(TzapDocumentEnvelopeError::InvalidString { path, field });
    };
    if value.is_empty() {
        return Err(TzapDocumentEnvelopeError::InvalidString { path, field });
    }
    Ok(Some(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{
        FIELD_CERTIFICATE_SERIAL_NUMBER, FIELD_DOMAIN_SEPARATOR, FIELD_ENVELOPE_VERSION,
        FIELD_INTERMEDIATE_CHAIN_DER, FIELD_PAYLOAD_HASH, FIELD_SIGNATURE, FIELD_SIGNED_PAYLOAD,
        FIELD_TZAP_PAYLOAD_VERSION, TzapDocumentEnvelopeError, parse_tzap_document_envelope_json,
        validate_tzap_document_envelope_value,
    };
    use crate::{jcs, trust};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    #[test]
    fn envelope_validator_accepts_mvp_document_envelope() {
        let envelope = valid_envelope();
        let parsed = validate_tzap_document_envelope_value(&envelope).unwrap();

        assert_eq!(parsed.signed_payload.envelope_version, 1);
        assert_eq!(
            String::from_utf8(parsed.canonical_document_payload).unwrap(),
            r#"{"body":{"amount":42,"currency":"USD"},"title":"Invoice","tzap_payload_version":1}"#
        );
        assert_eq!(parsed.signature, vec![0x11; 64]);
        assert_eq!(parsed.leaf_certificate_der, vec![0x30, 0x82, 0x01]);
        assert_eq!(parsed.intermediate_chain_der, vec![vec![0x30, 0x82, 0x02]]);
        assert_eq!(
            parsed.timestamp_token.as_deref(),
            Some("display-only-token")
        );
        assert_eq!(
            parsed.status_proof,
            Some(json!({"kind": "post_mvp_placeholder"}))
        );
    }

    #[test]
    fn envelope_validator_rejects_missing_or_bad_payload_version() {
        let mut envelope = valid_envelope();
        envelope["document_payload"]
            .as_object_mut()
            .unwrap()
            .remove(FIELD_TZAP_PAYLOAD_VERSION);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::MissingField { field, .. })
                if field == FIELD_TZAP_PAYLOAD_VERSION
        ));

        let mut envelope = valid_envelope();
        envelope["document_payload"][FIELD_TZAP_PAYLOAD_VERSION] = json!("1");
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::InvalidInteger { field, .. })
                if field == FIELD_TZAP_PAYLOAD_VERSION
        ));

        let mut envelope = valid_envelope();
        envelope["document_payload"][FIELD_TZAP_PAYLOAD_VERSION] = json!(2);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::UnsupportedVersion { field, actual: 2, .. })
                if field == FIELD_TZAP_PAYLOAD_VERSION
        ));
    }

    #[test]
    fn envelope_validator_rejects_reserved_payload_fields() {
        let mut envelope = valid_envelope();
        envelope["document_payload"]["tzap_signature"] = json!("not allowed here");

        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::ReservedPayloadField { field })
                if field == "tzap_signature"
        ));
    }

    #[test]
    fn envelope_validator_rejects_unknown_envelope_and_signed_payload_fields() {
        let mut envelope = valid_envelope();
        envelope["unexpected"] = json!(true);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::UnknownField { path, field })
                if path == "$" && field == "unexpected"
        ));

        let mut envelope = valid_envelope();
        envelope[FIELD_SIGNED_PAYLOAD]["unexpected"] = json!(true);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::UnknownField { path, field })
                if path == FIELD_SIGNED_PAYLOAD && field == "unexpected"
        ));
    }

    #[test]
    fn envelope_validator_rejects_wrong_signed_payload_constants() {
        for (field, bad_value) in [
            (FIELD_DOMAIN_SEPARATOR, "wrong-domain"),
            ("payload_hash_algorithm", "SHA512"),
            ("signature_algorithm", "RSA"),
        ] {
            let mut envelope = valid_envelope();
            envelope[FIELD_SIGNED_PAYLOAD][field] = json!(bad_value);

            assert!(matches!(
                validate_tzap_document_envelope_value(&envelope),
                Err(TzapDocumentEnvelopeError::InvalidConstant { field: actual, .. })
                    if actual == field
            ));
        }

        let mut envelope = valid_envelope();
        envelope[FIELD_SIGNED_PAYLOAD][FIELD_ENVELOPE_VERSION] = json!(2);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::UnsupportedVersion { field, actual: 2, .. })
                if field == FIELD_ENVELOPE_VERSION
        ));
    }

    #[test]
    fn envelope_validator_rejects_payload_hash_mismatch_and_noncanonical_ids() {
        let mut envelope = valid_envelope();
        envelope[FIELD_SIGNED_PAYLOAD][FIELD_PAYLOAD_HASH] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::PayloadHashMismatch { .. })
        ));

        let cases = [
            ("leaf_certificate_sha256", "sha256:ABCDEF"),
            ("issuer_certificate_sha256", "not-a-sha"),
            ("issuer_key_identifier", "abc="),
            (FIELD_CERTIFICATE_SERIAL_NUMBER, "00"),
        ];
        for (field, value) in cases {
            let mut envelope = valid_envelope();
            envelope[FIELD_SIGNED_PAYLOAD][field] = json!(value);
            assert!(matches!(
                validate_tzap_document_envelope_value(&envelope),
                Err(TzapDocumentEnvelopeError::InvalidIdentifier { field: actual })
                    if actual == field
            ));
        }
    }

    #[test]
    fn envelope_validator_rejects_bad_signature_and_der_base64() {
        let mut envelope = valid_envelope();
        envelope[FIELD_SIGNATURE] = json!(URL_SAFE_NO_PAD.encode([0x11; 63]));
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::InvalidSignatureLength { actual: 63 })
        ));

        let mut envelope = valid_envelope();
        envelope["leaf_certificate_der"] = json!("SGVsbG8=");
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::InvalidBase64Url { field })
                if field == "leaf_certificate_der"
        ));

        let mut envelope = valid_envelope();
        envelope[FIELD_INTERMEDIATE_CHAIN_DER] = json!([]);
        assert!(matches!(
            validate_tzap_document_envelope_value(&envelope),
            Err(TzapDocumentEnvelopeError::EmptyIntermediateChain)
        ));
    }

    #[test]
    fn envelope_json_parser_reports_invalid_json() {
        assert!(matches!(
            parse_tzap_document_envelope_json(br"{"),
            Err(TzapDocumentEnvelopeError::InvalidJson(_))
        ));
    }

    fn valid_envelope() -> Value {
        let document_payload = json!({
            "tzap_payload_version": 1,
            "title": "Invoice",
            "body": {
                "currency": "USD",
                "amount": 42,
            },
        });
        let payload_hash = jcs::canonical_sha256_digest(&document_payload).unwrap();

        json!({
            "document_payload": document_payload,
            "signed_payload": {
                "envelope_version": trust::TZAP_ENVELOPE_VERSION,
                "domain_separator": trust::TZAP_DOCUMENT_DOMAIN_SEPARATOR,
                "payload_hash_algorithm": trust::TZAP_PAYLOAD_DIGEST_ALGORITHM,
                "payload_hash": payload_hash,
                "signature_algorithm": trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM,
                "leaf_certificate_sha256": canonical_sha(0x01),
                "issuer_certificate_sha256": canonical_sha(0x02),
                "issuer_key_identifier": URL_SAFE_NO_PAD.encode([0x03; 20]),
                "certificate_serial_number": "01ABCDEF",
                "claimed_signing_time": "2026-06-25T00:00:00Z",
            },
            "signature": URL_SAFE_NO_PAD.encode([0x11; 64]),
            "leaf_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x82, 0x01]),
            "intermediate_chain_der": [
                URL_SAFE_NO_PAD.encode([0x30, 0x82, 0x02]),
            ],
            "timestamp_token": "display-only-token",
            "status_proof": {
                "kind": "post_mvp_placeholder",
            },
        })
    }

    fn canonical_sha(byte: u8) -> String {
        trust::format_sha256_identifier(&[byte; 32])
    }
}
