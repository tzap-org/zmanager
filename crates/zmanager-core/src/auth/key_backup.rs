//! Key-backup envelope for TZAP recipient private keys (design §9.2).
//!
//! Provides password-authenticated encryption for recipient private keys:
//! - Argon2id derives a 256-bit wrapping key from the user-chosen backup password.
//! - A random 256-bit data key encrypts the JSON payload with AES-256-GCM.
//! - The wrapping key encrypts the data key with AES-256-GCM.
//! - Password changes re-wrap the 32-byte data key without re-encrypting the payload.
//! - `wrapped_data_key_recovery` is reserved and present as `null` (design §9.0).
//! - All recipient private keys ever held by the device are backed up without aging out.

use crate::local_identity_store::TzapRecipientEncryptionKeyRecord;
use crate::secrets::SecretBytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub const KEY_BACKUP_FORMAT_V1: &str = "v1";
pub const KEY_BACKUP_KDF_ALGO_ARGON2ID: &str = "argon2id";
pub const RECIPIENT_KEYS_BACKUP_PAYLOAD_FORMAT_V1: &str = "v1";

/// Default Argon2id parameters for mobile devices (~1s derivation) (design §9.2).
pub const DEFAULT_ARGON2ID_M_COST_KIB: u32 = 65536; // 64 MiB
pub const DEFAULT_ARGON2ID_T_COST: u32 = 3;
pub const DEFAULT_ARGON2ID_PARALLELISM: u32 = 1;

/// Fast Argon2id parameters suitable for automated unit tests.
pub const TEST_ARGON2ID_PARAMS: TzapKeyBackupKdfParams = TzapKeyBackupKdfParams { m_cost_kib: 1024, t_cost: 1, parallelism: 1 };

pub const SALT_LEN_BYTES: usize = 16;
pub const DATA_KEY_LEN_BYTES: usize = 32;
pub const GCM_NONCE_LEN_BYTES: usize = 12;
pub const GCM_TAG_LEN_BYTES: usize = 16;

/// Top-level key-backup envelope stored on the server (design §9.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapKeyBackupEnvelope {
    pub format: String,
    pub kdf: TzapKeyBackupKdf,
    pub wrapped_data_key_password: TzapWrappedDataKey,
    #[serde(default)]
    pub wrapped_data_key_recovery: Option<serde_json::Value>,
    pub nonce: String,
    pub ciphertext: String,
}

impl TzapKeyBackupEnvelope {
    /// Serializes envelope to a JSON string.
    pub fn to_json(&self) -> Result<String, TzapKeyBackupError> {
        serde_json::to_string(self).map_err(TzapKeyBackupError::from)
    }

    /// Deserializes envelope from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, TzapKeyBackupError> {
        serde_json::from_str(json_str).map_err(TzapKeyBackupError::from)
    }

    /// Serializes envelope to a `serde_json::Value`.
    pub fn to_value(&self) -> Result<serde_json::Value, TzapKeyBackupError> {
        serde_json::to_value(self).map_err(TzapKeyBackupError::from)
    }

    /// Deserializes envelope from a `serde_json::Value`.
    pub fn from_value(value: serde_json::Value) -> Result<Self, TzapKeyBackupError> {
        serde_json::from_value(value).map_err(TzapKeyBackupError::from)
    }
}

/// KDF specification recorded in the key-backup envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapKeyBackupKdf {
    pub algorithm: String,
    pub salt: String,
    pub params: TzapKeyBackupKdfParams,
}

/// Argon2id tuning parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapKeyBackupKdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub parallelism: u32,
}

impl Default for TzapKeyBackupKdfParams {
    fn default() -> Self {
        Self { m_cost_kib: DEFAULT_ARGON2ID_M_COST_KIB, t_cost: DEFAULT_ARGON2ID_T_COST, parallelism: DEFAULT_ARGON2ID_PARALLELISM }
    }
}

/// AES-256-GCM wrapped data key slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapWrappedDataKey {
    pub nonce: String,
    pub ciphertext: String,
}

/// Plaintext payload encrypted inside the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapRecipientKeysBackupPayload {
    pub format: String,
    pub keys: Vec<TzapRecipientKeyBackupEntry>,
}

/// Single recipient private key record within the backup payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapRecipientKeyBackupEntry {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_fingerprint: String,
    pub public_key_der: String,
    pub private_key_der: String,
    pub created_at_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl TzapRecipientKeyBackupEntry {
    /// Converts this backup entry to an inventory record.
    pub fn to_record(&self) -> Result<TzapRecipientEncryptionKeyRecord, TzapKeyBackupError> {
        self.try_into()
    }
}

impl From<&TzapRecipientEncryptionKeyRecord> for TzapRecipientKeyBackupEntry {
    fn from(rec: &TzapRecipientEncryptionKeyRecord) -> Self {
        Self {
            key_id: rec.key_id.clone(),
            algorithm: rec.algorithm.clone(),
            public_key_fingerprint: rec.public_key_fingerprint.clone(),
            public_key_der: URL_SAFE_NO_PAD.encode(&rec.public_key_der),
            private_key_der: URL_SAFE_NO_PAD.encode(rec.private_key_der.expose_secret()),
            created_at_unix_seconds: rec.created_at_unix_seconds,
            label: rec.label.clone(),
        }
    }
}

impl TryFrom<&TzapRecipientKeyBackupEntry> for TzapRecipientEncryptionKeyRecord {
    type Error = TzapKeyBackupError;

    fn try_from(entry: &TzapRecipientKeyBackupEntry) -> Result<Self, Self::Error> {
        let pub_der = crate::trust::decode_base64url_no_padding(&entry.public_key_der)
            .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid public_key_der: {err}")))?;
        let priv_der = crate::trust::decode_base64url_no_padding(&entry.private_key_der)
            .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid private_key_der: {err}")))?;
        Ok(Self {
            key_id: entry.key_id.clone(),
            algorithm: entry.algorithm.clone(),
            public_key_fingerprint: entry.public_key_fingerprint.clone(),
            public_key_der: pub_der,
            private_key_der: SecretBytes::from(priv_der),
            created_at_unix_seconds: entry.created_at_unix_seconds,
            label: entry.label.clone(),
        })
    }
}

/// Errors occurring during key backup envelope sealing, unsealing, or re-keying.
#[derive(Debug)]
pub enum TzapKeyBackupError {
    /// Supplied password failed wrapping-key authentication.
    WrongPassword,
    /// Structural or format violation in the envelope or payload.
    InvalidFormat(String),
    /// Cryptographic failure (e.g. corrupted payload ciphertext or OpenSSL failure).
    Crypto(String),
    /// JSON serialization or deserialization failure.
    Json(String),
}

impl fmt::Display for TzapKeyBackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => write!(f, "wrong key backup password"),
            Self::InvalidFormat(reason) => write!(f, "invalid key backup envelope: {reason}"),
            Self::Crypto(reason) => write!(f, "key backup crypto error: {reason}"),
            Self::Json(reason) => write!(f, "key backup json error: {reason}"),
        }
    }
}

impl std::error::Error for TzapKeyBackupError {}

impl From<serde_json::Error> for TzapKeyBackupError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

// --- Cryptographic helpers ---

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn derive_wrapping_key(password: &str, salt: &[u8], params: &TzapKeyBackupKdfParams) -> Result<[u8; DATA_KEY_LEN_BYTES], TzapKeyBackupError> {
    let argon2_params = argon2::Params::new(params.m_cost_kib, params.t_cost, params.parallelism, Some(DATA_KEY_LEN_BYTES))
        .map_err(|err| TzapKeyBackupError::Crypto(format!("invalid argon2 params: {err}")))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);
    let mut derived_key = [0u8; DATA_KEY_LEN_BYTES];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|err| TzapKeyBackupError::Crypto(format!("argon2 derivation failed: {err}")))?;
    Ok(derived_key)
}

fn encrypt_aes_256_gcm(key: &[u8; DATA_KEY_LEN_BYTES], nonce: &[u8; GCM_NONCE_LEN_BYTES], plaintext: &[u8]) -> Result<Vec<u8>, TzapKeyBackupError> {
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let mut tag = [0u8; GCM_TAG_LEN_BYTES];
    let mut ciphertext = openssl::symm::encrypt_aead(cipher, key, Some(nonce), &[], plaintext, &mut tag)
        .map_err(|err| TzapKeyBackupError::Crypto(format!("aes-256-gcm encrypt failed: {err}")))?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

fn decrypt_aes_256_gcm(
    key: &[u8; DATA_KEY_LEN_BYTES],
    nonce: &[u8; GCM_NONCE_LEN_BYTES],
    combined_ciphertext: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    if combined_ciphertext.len() < GCM_TAG_LEN_BYTES {
        return Err(openssl::error::ErrorStack::get());
    }
    let (ciphertext, tag) = combined_ciphertext.split_at(combined_ciphertext.len() - GCM_TAG_LEN_BYTES);
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    openssl::symm::decrypt_aead(cipher, key, Some(nonce), &[], ciphertext, tag)
}

// --- Primary API ---

/// Seals a list of recipient encryption keys into a password-authenticated backup envelope.
///
/// If `params` is `None`, default mobile Argon2id parameters are used.
pub fn seal_recipient_keys_backup(
    keys: &[TzapRecipientEncryptionKeyRecord],
    password: &str,
    params: Option<TzapKeyBackupKdfParams>,
) -> Result<TzapKeyBackupEnvelope, TzapKeyBackupError> {
    if password.is_empty() {
        return Err(TzapKeyBackupError::InvalidFormat("password cannot be empty".to_string()));
    }

    let kdf_params = params.unwrap_or_default();

    // 1. Construct payload JSON
    let entries: Vec<TzapRecipientKeyBackupEntry> = keys.iter().map(TzapRecipientKeyBackupEntry::from).collect();
    let payload = TzapRecipientKeysBackupPayload { format: RECIPIENT_KEYS_BACKUP_PAYLOAD_FORMAT_V1.to_string(), keys: entries };
    let payload_bytes = serde_json::to_vec(&payload)?;

    // 2. Generate random 32-byte data key
    let mut data_key = random_bytes::<DATA_KEY_LEN_BYTES>();

    // 3. Seal payload with data key using AES-256-GCM
    let payload_nonce = random_bytes::<GCM_NONCE_LEN_BYTES>();
    let payload_ciphertext = encrypt_aes_256_gcm(&data_key, &payload_nonce, &payload_bytes)?;

    // 4. Derive wrapping key from password using Argon2id
    let salt = random_bytes::<SALT_LEN_BYTES>();
    let mut wrapping_key = derive_wrapping_key(password, &salt, &kdf_params)?;

    // 5. Wrap data key with wrapping key using AES-256-GCM
    let wrap_nonce = random_bytes::<GCM_NONCE_LEN_BYTES>();
    let wrapped_data_key_ciphertext = encrypt_aes_256_gcm(&wrapping_key, &wrap_nonce, &data_key)?;

    // Zeroize sensitive keys
    data_key.zeroize();
    wrapping_key.zeroize();

    Ok(TzapKeyBackupEnvelope {
        format: KEY_BACKUP_FORMAT_V1.to_string(),
        kdf: TzapKeyBackupKdf { algorithm: KEY_BACKUP_KDF_ALGO_ARGON2ID.to_string(), salt: URL_SAFE_NO_PAD.encode(salt), params: kdf_params },
        wrapped_data_key_password: TzapWrappedDataKey {
            nonce: URL_SAFE_NO_PAD.encode(wrap_nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(wrapped_data_key_ciphertext),
        },
        wrapped_data_key_recovery: None,
        nonce: URL_SAFE_NO_PAD.encode(payload_nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(payload_ciphertext),
    })
}

/// Unseals a key-backup envelope and returns the parsed payload.
///
/// Fails with [`TzapKeyBackupError::WrongPassword`] if the password is incorrect.
pub fn unseal_recipient_keys_backup_payload(envelope: &TzapKeyBackupEnvelope, password: &str) -> Result<TzapRecipientKeysBackupPayload, TzapKeyBackupError> {
    if envelope.format != KEY_BACKUP_FORMAT_V1 {
        return Err(TzapKeyBackupError::InvalidFormat(format!("unsupported envelope format '{}', expected '{}'", envelope.format, KEY_BACKUP_FORMAT_V1)));
    }
    if envelope.kdf.algorithm != KEY_BACKUP_KDF_ALGO_ARGON2ID {
        return Err(TzapKeyBackupError::InvalidFormat(format!(
            "unsupported kdf algorithm '{}', expected '{}'",
            envelope.kdf.algorithm, KEY_BACKUP_KDF_ALGO_ARGON2ID
        )));
    }

    // 1. Decode salt
    let salt =
        crate::trust::decode_base64url_no_padding(&envelope.kdf.salt).map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid kdf salt: {err}")))?;

    // 2. Decode wrapped data key nonce and ciphertext
    let wrap_nonce_bytes = crate::trust::decode_base64url_no_padding(&envelope.wrapped_data_key_password.nonce)
        .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid wrapped_data_key_password nonce: {err}")))?;
    if wrap_nonce_bytes.len() != GCM_NONCE_LEN_BYTES {
        return Err(TzapKeyBackupError::InvalidFormat(format!("invalid wrap nonce length {}, expected {}", wrap_nonce_bytes.len(), GCM_NONCE_LEN_BYTES)));
    }
    let mut wrap_nonce = [0u8; GCM_NONCE_LEN_BYTES];
    wrap_nonce.copy_from_slice(&wrap_nonce_bytes);

    let wrapped_data_key_ct = crate::trust::decode_base64url_no_padding(&envelope.wrapped_data_key_password.ciphertext)
        .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid wrapped_data_key_password ciphertext: {err}")))?;

    // 3. Derive wrapping key from password
    let mut wrapping_key = derive_wrapping_key(password, &salt, &envelope.kdf.params)?;

    // 4. Unwrap data key
    let unwrapped_data_key_bytes = decrypt_aes_256_gcm(&wrapping_key, &wrap_nonce, &wrapped_data_key_ct).map_err(|_| TzapKeyBackupError::WrongPassword)?;
    wrapping_key.zeroize();

    if unwrapped_data_key_bytes.len() != DATA_KEY_LEN_BYTES {
        return Err(TzapKeyBackupError::InvalidFormat(format!(
            "unwrapped data key length {} invalid, expected {}",
            unwrapped_data_key_bytes.len(),
            DATA_KEY_LEN_BYTES
        )));
    }
    let mut data_key = [0u8; DATA_KEY_LEN_BYTES];
    data_key.copy_from_slice(&unwrapped_data_key_bytes);

    // 5. Decode payload nonce and ciphertext
    let payload_nonce_bytes = crate::trust::decode_base64url_no_padding(&envelope.nonce).map_err(|err| {
        data_key.zeroize();
        TzapKeyBackupError::InvalidFormat(format!("invalid payload nonce: {err}"))
    })?;
    if payload_nonce_bytes.len() != GCM_NONCE_LEN_BYTES {
        data_key.zeroize();
        return Err(TzapKeyBackupError::InvalidFormat(format!("invalid payload nonce length {}, expected {}", payload_nonce_bytes.len(), GCM_NONCE_LEN_BYTES)));
    }
    let mut payload_nonce = [0u8; GCM_NONCE_LEN_BYTES];
    payload_nonce.copy_from_slice(&payload_nonce_bytes);

    let payload_ct = crate::trust::decode_base64url_no_padding(&envelope.ciphertext).map_err(|err| {
        data_key.zeroize();
        TzapKeyBackupError::InvalidFormat(format!("invalid payload ciphertext: {err}"))
    })?;

    // 6. Decrypt payload
    let payload_bytes = decrypt_aes_256_gcm(&data_key, &payload_nonce, &payload_ct).map_err(|err| {
        data_key.zeroize();
        TzapKeyBackupError::Crypto(format!("failed to decrypt payload ciphertext (corrupted or tampered): {err}"))
    })?;
    data_key.zeroize();

    // 7. Parse payload JSON
    let payload: TzapRecipientKeysBackupPayload = serde_json::from_slice(&payload_bytes)?;
    if payload.format != RECIPIENT_KEYS_BACKUP_PAYLOAD_FORMAT_V1 {
        return Err(TzapKeyBackupError::InvalidFormat(format!(
            "unsupported payload format '{}', expected '{}'",
            payload.format, RECIPIENT_KEYS_BACKUP_PAYLOAD_FORMAT_V1
        )));
    }

    Ok(payload)
}

/// Unseals a key-backup envelope and converts entries into inventory key records.
pub fn unseal_recipient_keys_backup(envelope: &TzapKeyBackupEnvelope, password: &str) -> Result<Vec<TzapRecipientEncryptionKeyRecord>, TzapKeyBackupError> {
    let payload = unseal_recipient_keys_backup_payload(envelope, password)?;
    payload.keys.iter().map(TzapRecipientKeyBackupEntry::to_record).collect()
}

/// Re-wraps the envelope's data key under a new password without decrypting or re-encrypting the payload (design §9.2).
pub fn rekey_backup_envelope(
    envelope: &TzapKeyBackupEnvelope,
    old_password: &str,
    new_password: &str,
    new_params: Option<TzapKeyBackupKdfParams>,
) -> Result<TzapKeyBackupEnvelope, TzapKeyBackupError> {
    if new_password.is_empty() {
        return Err(TzapKeyBackupError::InvalidFormat("new password cannot be empty".to_string()));
    }
    if envelope.format != KEY_BACKUP_FORMAT_V1 {
        return Err(TzapKeyBackupError::InvalidFormat(format!("unsupported envelope format '{}', expected '{}'", envelope.format, KEY_BACKUP_FORMAT_V1)));
    }
    if envelope.kdf.algorithm != KEY_BACKUP_KDF_ALGO_ARGON2ID {
        return Err(TzapKeyBackupError::InvalidFormat(format!(
            "unsupported kdf algorithm '{}', expected '{}'",
            envelope.kdf.algorithm, KEY_BACKUP_KDF_ALGO_ARGON2ID
        )));
    }

    // 1. Unwrap data key using old password
    let old_salt =
        crate::trust::decode_base64url_no_padding(&envelope.kdf.salt).map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid kdf salt: {err}")))?;

    let old_wrap_nonce_bytes = crate::trust::decode_base64url_no_padding(&envelope.wrapped_data_key_password.nonce)
        .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid wrapped_data_key_password nonce: {err}")))?;
    if old_wrap_nonce_bytes.len() != GCM_NONCE_LEN_BYTES {
        return Err(TzapKeyBackupError::InvalidFormat("invalid wrap nonce length".to_string()));
    }
    let mut old_wrap_nonce = [0u8; GCM_NONCE_LEN_BYTES];
    old_wrap_nonce.copy_from_slice(&old_wrap_nonce_bytes);

    let wrapped_data_key_ct = crate::trust::decode_base64url_no_padding(&envelope.wrapped_data_key_password.ciphertext)
        .map_err(|err| TzapKeyBackupError::InvalidFormat(format!("invalid wrapped_data_key_password ciphertext: {err}")))?;

    let mut old_wrapping_key = derive_wrapping_key(old_password, &old_salt, &envelope.kdf.params)?;
    let unwrapped_data_key_bytes =
        decrypt_aes_256_gcm(&old_wrapping_key, &old_wrap_nonce, &wrapped_data_key_ct).map_err(|_| TzapKeyBackupError::WrongPassword)?;
    old_wrapping_key.zeroize();

    if unwrapped_data_key_bytes.len() != DATA_KEY_LEN_BYTES {
        return Err(TzapKeyBackupError::InvalidFormat("invalid data key length".to_string()));
    }
    let mut data_key = [0u8; DATA_KEY_LEN_BYTES];
    data_key.copy_from_slice(&unwrapped_data_key_bytes);

    // 2. Wrap data key under new password
    let kdf_params = new_params.unwrap_or(envelope.kdf.params);
    let new_salt = random_bytes::<SALT_LEN_BYTES>();
    let mut new_wrapping_key = derive_wrapping_key(new_password, &new_salt, &kdf_params)?;
    let new_wrap_nonce = random_bytes::<GCM_NONCE_LEN_BYTES>();
    let new_wrapped_data_key_ct = encrypt_aes_256_gcm(&new_wrapping_key, &new_wrap_nonce, &data_key)?;

    data_key.zeroize();
    new_wrapping_key.zeroize();

    // 3. Assemble new envelope preserving payload nonce and ciphertext verbatim
    Ok(TzapKeyBackupEnvelope {
        format: envelope.format.clone(),
        kdf: TzapKeyBackupKdf { algorithm: KEY_BACKUP_KDF_ALGO_ARGON2ID.to_string(), salt: URL_SAFE_NO_PAD.encode(new_salt), params: kdf_params },
        wrapped_data_key_password: TzapWrappedDataKey {
            nonce: URL_SAFE_NO_PAD.encode(new_wrap_nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(new_wrapped_data_key_ct),
        },
        wrapped_data_key_recovery: envelope.wrapped_data_key_recovery.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key_record(id: &str, label: Option<&str>) -> TzapRecipientEncryptionKeyRecord {
        TzapRecipientEncryptionKeyRecord {
            key_id: id.to_string(),
            algorithm: "ECDH-P256".to_string(),
            public_key_fingerprint: format!("fp-{id}"),
            public_key_der: vec![1, 2, 3, 4, 5],
            private_key_der: SecretBytes::from(vec![9, 8, 7, 6, 5]),
            created_at_unix_seconds: 1_700_000_000,
            label: label.map(str::to_string),
        }
    }

    #[test]
    fn seal_and_unseal_round_trip() {
        let keys = vec![sample_key_record("key-1", Some("Phone A Active")), sample_key_record("key-2", Some("Phone A Retired"))];

        let password = "correct horse battery staple";
        let envelope = seal_recipient_keys_backup(&keys, password, Some(TEST_ARGON2ID_PARAMS)).unwrap();

        assert_eq!(envelope.format, KEY_BACKUP_FORMAT_V1);
        assert_eq!(envelope.kdf.algorithm, KEY_BACKUP_KDF_ALGO_ARGON2ID);
        assert_eq!(envelope.kdf.params, TEST_ARGON2ID_PARAMS);
        assert!(envelope.wrapped_data_key_recovery.is_none());

        // Verify JSON serialization includes wrapped_data_key_recovery as null
        let json_str = envelope.to_json().unwrap();
        assert!(json_str.contains("\"wrapped_data_key_recovery\":null"));

        let restored = unseal_recipient_keys_backup(&envelope, password).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0], keys[0]);
        assert_eq!(restored[1], keys[1]);
    }

    #[test]
    fn wrong_password_returns_distinct_error() {
        let keys = vec![sample_key_record("key-1", None)];
        let envelope = seal_recipient_keys_backup(&keys, "correct-password", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        let result = unseal_recipient_keys_backup(&envelope, "wrong-password");
        match result {
            Err(TzapKeyBackupError::WrongPassword) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn rekey_envelope_changes_wrapper_not_payload() {
        let keys = vec![sample_key_record("key-1", Some("Initial"))];
        let original_envelope = seal_recipient_keys_backup(&keys, "old-password", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        let rekeyed_envelope = rekey_backup_envelope(&original_envelope, "old-password", "new-password", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        // Payload ciphertext and nonce are byte-for-byte identical
        assert_eq!(original_envelope.nonce, rekeyed_envelope.nonce);
        assert_eq!(original_envelope.ciphertext, rekeyed_envelope.ciphertext);

        // Wrapper ciphertext changed (new salt and new nonce)
        assert_ne!(original_envelope.wrapped_data_key_password.ciphertext, rekeyed_envelope.wrapped_data_key_password.ciphertext);

        // Old password now fails on rekeyed envelope
        assert!(matches!(unseal_recipient_keys_backup(&rekeyed_envelope, "old-password"), Err(TzapKeyBackupError::WrongPassword)));

        // New password succeeds on rekeyed envelope
        let restored = unseal_recipient_keys_backup(&rekeyed_envelope, "new-password").unwrap();
        assert_eq!(restored, keys);
    }

    #[test]
    fn rekey_with_wrong_old_password_fails() {
        let keys = vec![sample_key_record("key-1", None)];
        let envelope = seal_recipient_keys_backup(&keys, "old-password", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        let result = rekey_backup_envelope(&envelope, "incorrect-old", "new-password", Some(TEST_ARGON2ID_PARAMS));
        assert!(matches!(result, Err(TzapKeyBackupError::WrongPassword)));
    }

    #[test]
    fn corrupted_payload_ciphertext_returns_crypto_error() {
        let keys = vec![sample_key_record("key-1", None)];
        let mut envelope = seal_recipient_keys_backup(&keys, "password123", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        // Corrupt the payload ciphertext bytes
        let mut ct_bytes = URL_SAFE_NO_PAD.decode(&envelope.ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        envelope.ciphertext = URL_SAFE_NO_PAD.encode(&ct_bytes);

        // Unseal should fail with Crypto error, NOT WrongPassword
        let result = unseal_recipient_keys_backup(&envelope, "password123");
        assert!(matches!(result, Err(TzapKeyBackupError::Crypto(_))));
    }

    #[test]
    fn forward_compatible_unknown_fields_and_envelope_version() {
        let keys = vec![sample_key_record("key-1", None)];
        let envelope = seal_recipient_keys_backup(&keys, "password", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        let mut value = envelope.to_value().unwrap();
        // Add unknown future field
        value.as_object_mut().unwrap().insert("future_server_metadata".to_string(), serde_json::json!({"extra": 42}));

        let parsed = TzapKeyBackupEnvelope::from_value(value).unwrap();
        let restored = unseal_recipient_keys_backup(&parsed, "password").unwrap();
        assert_eq!(restored, keys);

        // Future format version rejected
        let mut unsupported_version = envelope.clone();
        unsupported_version.format = "v2".to_string();
        assert!(matches!(unseal_recipient_keys_backup(&unsupported_version, "password"), Err(TzapKeyBackupError::InvalidFormat(_))));

        // Unsupported KDF algorithm rejected
        let mut unsupported_kdf = envelope.clone();
        unsupported_kdf.kdf.algorithm = "pbkdf2".to_string();
        assert!(matches!(unseal_recipient_keys_backup(&unsupported_kdf, "password"), Err(TzapKeyBackupError::InvalidFormat(_))));
    }

    #[test]
    fn empty_password_rejected() {
        let keys = vec![sample_key_record("key-1", None)];
        assert!(matches!(seal_recipient_keys_backup(&keys, "", Some(TEST_ARGON2ID_PARAMS)), Err(TzapKeyBackupError::InvalidFormat(_))));

        let envelope = seal_recipient_keys_backup(&keys, "valid-password", Some(TEST_ARGON2ID_PARAMS)).unwrap();
        assert!(matches!(rekey_backup_envelope(&envelope, "valid-password", "", Some(TEST_ARGON2ID_PARAMS)), Err(TzapKeyBackupError::InvalidFormat(_))));
    }

    #[test]
    fn empty_keys_list_round_trip() {
        let keys: Vec<TzapRecipientEncryptionKeyRecord> = Vec::new();
        let envelope = seal_recipient_keys_backup(&keys, "pass", Some(TEST_ARGON2ID_PARAMS)).unwrap();
        let restored = unseal_recipient_keys_backup(&envelope, "pass").unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn malformed_base64_and_invalid_nonce_lengths_fail_closed() {
        let keys = vec![sample_key_record("key-1", None)];
        let envelope = seal_recipient_keys_backup(&keys, "pass", Some(TEST_ARGON2ID_PARAMS)).unwrap();

        // Invalid salt base64
        let mut bad_salt = envelope.clone();
        bad_salt.kdf.salt = "not-valid-base64!".to_string();
        assert!(matches!(unseal_recipient_keys_backup(&bad_salt, "pass"), Err(TzapKeyBackupError::InvalidFormat(_))));

        // Invalid wrap nonce length
        let mut bad_nonce = envelope.clone();
        bad_nonce.wrapped_data_key_password.nonce = URL_SAFE_NO_PAD.encode(b"too-short");
        assert!(matches!(unseal_recipient_keys_backup(&bad_nonce, "pass"), Err(TzapKeyBackupError::InvalidFormat(_))));

        // Invalid payload nonce length
        let mut bad_payload_nonce = envelope.clone();
        bad_payload_nonce.nonce = URL_SAFE_NO_PAD.encode(b"short");
        assert!(matches!(unseal_recipient_keys_backup(&bad_payload_nonce, "pass"), Err(TzapKeyBackupError::InvalidFormat(_))));
    }
}
