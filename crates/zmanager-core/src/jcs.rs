//! RFC 8785 JSON Canonicalization Scheme helpers.

use crate::trust;
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// Computes `sha256:<64 lower-case hex>` over RFC 8785 canonical JSON bytes.
pub fn canonical_sha256_digest(value: &Value) -> Result<String, JcsError> {
    let bytes = canonicalize_json_bytes(value)?;
    let digest = Sha256::digest(bytes);
    let mut digest_array = [0_u8; 32];
    digest_array.copy_from_slice(&digest);
    Ok(trust::format_sha256_identifier(&digest_array))
}

#[cfg(test)]
mod tests {
    use super::{canonical_sha256_digest, canonicalize_json_bytes};
    use crate::trust;
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
    fn jcs_canonicalization_sorts_non_bmp_keys_by_utf16_code_units() {
        let payload = json!({
            "\u{FFA5}": 1,
            "\u{20BB7}": 2,
        });

        let canonical = canonicalize_json_bytes(&payload).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            "{\"\u{20BB7}\":2,\"\u{FFA5}\":1}"
        );
    }

    #[test]
    fn jcs_canonicalization_uses_ecmascript_number_boundaries() {
        let cases = [
            (json!({"n": 1e21}), r#"{"n":1e+21}"#),
            (json!({"n": 1e20}), r#"{"n":100000000000000000000}"#),
            (json!({"n": 1e-6}), r#"{"n":0.000001}"#),
            (json!({"n": 1e-7}), r#"{"n":1e-7}"#),
            (json!({"n": 1.50}), r#"{"n":1.5}"#),
            (json!({"n": -0.0}), r#"{"n":0}"#),
        ];

        for (payload, expected) in cases {
            let canonical = canonicalize_json_bytes(&payload).unwrap();
            assert_eq!(String::from_utf8(canonical).unwrap(), expected);
        }
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
        assert_eq!(
            digest.len(),
            trust::SHA256_IDENTIFIER_PREFIX.len() + trust::SHA256_IDENTIFIER_HEX_LENGTH
        );
    }
}
