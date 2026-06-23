//! RFC 8785 JSON Canonicalization Scheme helpers.

use crate::trust;
use sha2::{Digest, Sha256};
use serde_json::Value;
use std::cmp::Ordering;

/// Errors for canonical JSON transformation.
#[derive(Debug)]
pub enum JcsError {
    /// Serialization failed while emitting canonical JSON bytes.
    Serialization(serde_json::Error),
}

impl From<serde_json::Error> for JcsError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

/// Canonicalizes RFC 8785 JSON bytes with deterministic key ordering.
pub fn canonicalize_json_bytes(value: &Value) -> Result<Vec<u8>, JcsError> {
    let canonical = canonicalize_json_value(value);
    Ok(serde_json::to_vec(&canonical)?)
}

/// Computes `sha256:<64 lower-case hex>` over RFC 8785 canonical JSON bytes.
pub fn canonical_sha256_digest(value: &Value) -> Result<String, JcsError> {
    let bytes = canonicalize_json_bytes(value)?;
    let digest = Sha256::digest(bytes);
    let mut digest_array = [0_u8; 32];
    digest_array.copy_from_slice(&digest);
    Ok(trust::format_sha256_identifier(&digest_array))
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(entries) => {
            let mut sorted: Vec<(String, Value)> = entries
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_json_value(value)))
                .collect();
            sorted.sort_unstable_by(|(left, _), (right, _)| utf16_cmp(left, right));

            let mut output = serde_json::Map::new();
            for (key, value) in sorted {
                output.insert(key, value);
            }
            Value::Object(output)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json_value).collect()),
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_json_bytes, canonical_sha256_digest};
    use serde_json::json;

    #[test]
    fn jcs_canonicalization_uses_utf16_key_order_and_utf8_bytes() {
        let payload = json!({
            "é": "unicode key",
            "a": "ascii",
            "😀": 1,
            "Z": true,
        });

        let canonical = canonicalize_json_bytes(&payload).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"Z":true,"a":"ascii","é":"unicode key","😀":1}"#
        );
    }

    #[test]
    fn jcs_canonicalizes_nested_key_order_and_whitespace() {
        let payload = json!({
            "z": "last",
            "a": {
                "b": 2,
                "a": 1,
            },
            "m": "middle",
        });

        let canonical = canonicalize_json_bytes(&payload).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"a":{"a":1,"b":2},"m":"middle","z":"last"}"#
        );
    }

    #[test]
    fn jcs_canonicalization_is_stable_across_calls() {
        let payload = json!({"b": 1, "a": 2});

        let first = canonicalize_json_bytes(&payload).unwrap();
        let second = canonicalize_json_bytes(&payload).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn jcs_sha256_digest_has_sha256_prefix() {
        let payload = json!({"a": 1, "b": 2});

        let digest = canonical_sha256_digest(&payload).unwrap();
        assert_eq!(
            digest,
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
        assert_eq!(digest.len(), trust::SHA256_IDENTIFIER_PREFIX.len() + trust::SHA256_IDENTIFIER_HEX_LENGTH);
    }
}
