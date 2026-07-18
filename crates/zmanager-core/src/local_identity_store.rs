//! Local TZAP identity inventory and storage abstraction.

use crate::secrets::SecretBytes;
use crate::trust::{
    self, TzapCertificatePublicMetadata, TzapCertificateStatus, is_valid_public_device_id,
    is_valid_public_signer_id,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

pub const DEFAULT_IDENTITY_INVENTORY_ACCOUNT: &str = "default";
pub const IDENTITY_INVENTORY_FILE_SUFFIX: &str = ".identity.json";
const STORE_FORMAT_VERSION: u64 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalIdentityInventory {
    pub device_signing_keys: Vec<TzapDeviceSigningKeyRecord>,
    pub recipient_encryption_keys: Vec<TzapRecipientEncryptionKeyRecord>,
    pub enrolled_certificates: Vec<TzapEnrolledCertificateRecord>,
    pub certificate_status_cache: Vec<TzapCertificateStatusCacheRecord>,
    pub emergency_blocklist: TzapEmergencyBlocklistState,
    pub contacts: Vec<TzapContactRecord>,
}

impl TzapLocalIdentityInventory {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            device_signing_keys: Vec::new(),
            recipient_encryption_keys: Vec::new(),
            enrolled_certificates: Vec::new(),
            certificate_status_cache: Vec::new(),
            emergency_blocklist: TzapEmergencyBlocklistState::default(),
            contacts: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_unique(
            "device_signing_keys.key_id",
            self.device_signing_keys
                .iter()
                .map(|record| record.key_id.as_str()),
        )?;
        validate_unique(
            "recipient_encryption_keys.key_id",
            self.recipient_encryption_keys
                .iter()
                .map(|record| record.key_id.as_str()),
        )?;
        validate_unique(
            "enrolled_certificates.certificate_sha256",
            self.enrolled_certificates
                .iter()
                .map(|record| record.certificate_sha256.as_str()),
        )?;
        validate_unique(
            "contacts.contact_id",
            self.contacts
                .iter()
                .map(|record| record.contact_id.as_str()),
        )?;

        for record in &self.device_signing_keys {
            validate_non_empty_id("device_signing_keys.key_id", &record.key_id)?;
            validate_sha256(
                "device_signing_keys.public_key_fingerprint",
                &record.public_key_fingerprint,
            )?;
            validate_secret_bytes(
                "device_signing_keys.private_key_der",
                &record.private_key_der,
            )?;
        }
        for record in &self.recipient_encryption_keys {
            validate_non_empty_id("recipient_encryption_keys.key_id", &record.key_id)?;
            validate_non_empty_id("recipient_encryption_keys.algorithm", &record.algorithm)?;
            validate_sha256(
                "recipient_encryption_keys.public_key_fingerprint",
                &record.public_key_fingerprint,
            )?;
            validate_secret_bytes(
                "recipient_encryption_keys.private_key_der",
                &record.private_key_der,
            )?;
            validate_non_empty_bytes(
                "recipient_encryption_keys.public_key_der",
                &record.public_key_der,
            )?;
            if self.device_signing_keys.iter().any(|signing_key| {
                signing_key.public_key_fingerprint == record.public_key_fingerprint
            }) {
                return Err(TzapLocalIdentityStoreError::InvalidField {
                    field: "recipient_encryption_keys.public_key_fingerprint",
                });
            }
        }
        for record in &self.enrolled_certificates {
            record.validate()?;
        }
        for record in &self.certificate_status_cache {
            record.validate()?;
        }
        self.emergency_blocklist.validate()?;
        for record in &self.contacts {
            record.validate()?;
        }

        Ok(())
    }

    #[must_use]
    pub fn active_personal_sign_device_ids(&self) -> Vec<&str> {
        self.enrolled_certificates
            .iter()
            .filter(|record| record.state == TzapLocalCertificateState::Active)
            .filter_map(|record| match record.sign_device_routing {
                TzapSignDeviceRouting::Personal => Some(record.sign_device_id.as_str()),
                TzapSignDeviceRouting::Organization { .. } => None,
            })
            .collect()
    }

    #[must_use]
    pub fn active_organization_device_retirements(&self) -> Vec<TzapOrganizationDeviceRetirement> {
        self.enrolled_certificates
            .iter()
            .filter(|record| record.state == TzapLocalCertificateState::Active)
            .filter_map(|record| match &record.sign_device_routing {
                TzapSignDeviceRouting::Personal => None,
                TzapSignDeviceRouting::Organization {
                    org_id,
                    login_organization_device_id,
                } => Some(TzapOrganizationDeviceRetirement {
                    org_id: org_id.clone(),
                    login_organization_device_id: login_organization_device_id.clone(),
                    sign_device_id: record.sign_device_id.clone(),
                }),
            })
            .collect()
    }
}

impl Default for TzapLocalIdentityInventory {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDeviceSigningKeyRecord {
    pub key_id: String,
    pub public_key_fingerprint: String,
    pub private_key_der: SecretBytes,
    pub created_at_unix_seconds: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRecipientEncryptionKeyRecord {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_fingerprint: String,
    pub public_key_der: Vec<u8>,
    pub private_key_der: SecretBytes,
    pub created_at_unix_seconds: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapLocalCertificateState {
    Active,
    Revoked,
    Suspended,
    Expired,
}

impl TzapLocalCertificateState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            "suspended" => Some(Self::Suspended),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapSignDeviceRouting {
    Personal,
    Organization {
        org_id: String,
        login_organization_device_id: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapOrganizationDeviceRetirement {
    pub org_id: String,
    pub login_organization_device_id: String,
    pub sign_device_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEnrolledCertificateRecord {
    pub certificate_id: String,
    pub certificate_sha256: String,
    pub issuer_certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub serial_number: String,
    pub leaf_certificate_der: Vec<u8>,
    pub intermediate_chain_der: Vec<Vec<u8>>,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    pub public_metadata: TzapCertificatePublicMetadata,
    pub sign_device_id: String,
    pub sign_device_routing: TzapSignDeviceRouting,
    pub signing_key_id: String,
    pub state: TzapLocalCertificateState,
}

impl TzapEnrolledCertificateRecord {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("certificate_id", &self.certificate_id)?;
        validate_sha256("certificate_sha256", &self.certificate_sha256)?;
        validate_sha256("issuer_certificate_sha256", &self.issuer_certificate_sha256)?;
        if !trust::is_valid_issuer_key_identifier(&self.issuer_key_identifier) {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "issuer_key_identifier",
            });
        }
        if trust::parse_serial_hex(&self.serial_number).is_err() {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "serial_number",
            });
        }
        validate_non_empty_bytes("leaf_certificate_der", &self.leaf_certificate_der)?;
        if self.intermediate_chain_der.is_empty() {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "intermediate_chain_der",
            });
        }
        for der in &self.intermediate_chain_der {
            validate_non_empty_bytes("intermediate_chain_der", der)?;
        }
        if self.not_before_unix_seconds >= self.not_after_unix_seconds {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "certificate_validity",
            });
        }
        validate_public_metadata(&self.public_metadata)?;
        validate_non_empty_id("sign_device_id", &self.sign_device_id)?;
        match &self.sign_device_routing {
            TzapSignDeviceRouting::Personal => {}
            TzapSignDeviceRouting::Organization {
                org_id,
                login_organization_device_id,
            } => {
                validate_non_empty_id("sign_device_routing.org_id", org_id)?;
                validate_non_empty_id(
                    "sign_device_routing.login_organization_device_id",
                    login_organization_device_id,
                )?;
            }
        }
        validate_non_empty_id("signing_key_id", &self.signing_key_id)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCertificateStatusCacheRecord {
    pub certificate_sha256: String,
    pub status: TzapCertificateStatus,
    pub this_update_unix_seconds: u64,
    pub next_update_unix_seconds: u64,
}

impl TzapCertificateStatusCacheRecord {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_sha256(
            "certificate_status_cache.certificate_sha256",
            &self.certificate_sha256,
        )?;
        if self.this_update_unix_seconds >= self.next_update_unix_seconds {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "certificate_status_cache.freshness_window",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapEmergencyBlocklistState {
    pub blocked_root_sha256: Vec<String>,
    pub blocked_issuer_sha256: Vec<String>,
    pub updated_at_unix_seconds: Option<u64>,
}

impl TzapEmergencyBlocklistState {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_unique(
            "emergency_blocklist.blocked_root_sha256",
            self.blocked_root_sha256.iter().map(String::as_str),
        )?;
        validate_unique(
            "emergency_blocklist.blocked_issuer_sha256",
            self.blocked_issuer_sha256.iter().map(String::as_str),
        )?;
        for fingerprint in &self.blocked_root_sha256 {
            validate_sha256("emergency_blocklist.blocked_root_sha256", fingerprint)?;
        }
        for fingerprint in &self.blocked_issuer_sha256 {
            validate_sha256("emergency_blocklist.blocked_issuer_sha256", fingerprint)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapContactRecord {
    pub contact_id: String,
    pub display_name: String,
    pub signing_certificate_sha256: String,
    pub recipient_public_key_fingerprint: String,
    pub trust_anchor_type: trust::TzapTrustAnchorType,
    pub verification_state: trust::TzapVerificationState,
    pub missing_status_caveat: bool,
    pub contact_card_payload: Value,
    pub accepted_at_unix_seconds: u64,
}

impl TzapContactRecord {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("contacts.contact_id", &self.contact_id)?;
        validate_non_empty_id("contacts.display_name", &self.display_name)?;
        validate_sha256(
            "contacts.signing_certificate_sha256",
            &self.signing_certificate_sha256,
        )?;
        validate_sha256(
            "contacts.recipient_public_key_fingerprint",
            &self.recipient_public_key_fingerprint,
        )?;
        if self.verification_state == trust::TzapVerificationState::Invalid {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "contacts.verification_state",
            });
        }
        if !self.contact_card_payload.is_object() {
            return Err(TzapLocalIdentityStoreError::InvalidField {
                field: "contacts.contact_card_payload",
            });
        }
        Ok(())
    }
}

pub trait TzapLocalIdentityStore {
    fn load_inventory(
        &self,
        account_key: &str,
    ) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError>;

    fn save_inventory(
        &mut self,
        account_key: &str,
        inventory: TzapLocalIdentityInventory,
    ) -> Result<(), TzapLocalIdentityStoreError>;

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError>;
}

#[derive(Debug, Default)]
pub struct InMemoryTzapLocalIdentityStore {
    inventories: std::collections::HashMap<String, TzapLocalIdentityInventory>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileTzapLocalIdentityStore {
    root: PathBuf,
}

impl FileTzapLocalIdentityStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn inventory_path(&self, account_key: &str) -> Result<PathBuf, TzapLocalIdentityStoreError> {
        validate_account_key(account_key)?;
        Ok(self
            .root
            .join(format!("{account_key}{IDENTITY_INVENTORY_FILE_SUFFIX}")))
    }
}

impl TzapLocalIdentityStore for FileTzapLocalIdentityStore {
    fn load_inventory(
        &self,
        account_key: &str,
    ) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        let path = self.inventory_path(account_key)?;
        if !path.exists() {
            return Ok(TzapLocalIdentityInventory::empty());
        }

        let bytes = fs::read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        inventory_from_json(&value)
    }

    fn save_inventory(
        &mut self,
        account_key: &str,
        inventory: TzapLocalIdentityInventory,
    ) -> Result<(), TzapLocalIdentityStoreError> {
        let path = self.inventory_path(account_key)?;
        inventory.validate()?;
        fs::create_dir_all(&self.root)?;
        let value = inventory_to_json(&inventory);
        let bytes = serde_json::to_vec_pretty(&value)?;
        write_secret_file(&path, &bytes)?;
        Ok(())
    }

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        let path = self.inventory_path(account_key)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl InMemoryTzapLocalIdentityStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapLocalIdentityStore for InMemoryTzapLocalIdentityStore {
    fn load_inventory(
        &self,
        account_key: &str,
    ) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        validate_non_empty_id("account_key", account_key)?;
        Ok(self
            .inventories
            .get(account_key)
            .cloned()
            .unwrap_or_else(TzapLocalIdentityInventory::empty))
    }

    fn save_inventory(
        &mut self,
        account_key: &str,
        inventory: TzapLocalIdentityInventory,
    ) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("account_key", account_key)?;
        inventory.validate()?;
        self.inventories.insert(account_key.to_owned(), inventory);
        Ok(())
    }

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("account_key", account_key)?;
        self.inventories.remove(account_key);
        Ok(())
    }
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapLocalIdentityStoreError {
    InvalidField { field: &'static str },
    DuplicateRecord { field: &'static str, value: String },
    Io(std::io::ErrorKind),
    Json(String),
}

impl fmt::Display for TzapLocalIdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(f, "local identity field is invalid: {field}"),
            Self::DuplicateRecord { field, value } => {
                write!(f, "local identity field {field} contains duplicate {value}")
            }
            Self::Io(kind) => write!(f, "local identity store I/O failed: {kind:?}"),
            Self::Json(message) => write!(f, "local identity JSON is invalid: {message}"),
        }
    }
}

impl std::error::Error for TzapLocalIdentityStoreError {}

impl From<std::io::Error> for TzapLocalIdentityStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<serde_json::Error> for TzapLocalIdentityStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

fn inventory_to_json(inventory: &TzapLocalIdentityInventory) -> Value {
    serde_json::json!({
        "version": STORE_FORMAT_VERSION,
        "device_signing_keys": inventory.device_signing_keys.iter().map(device_signing_key_to_json).collect::<Vec<_>>(),
        "recipient_encryption_keys": inventory.recipient_encryption_keys.iter().map(recipient_encryption_key_to_json).collect::<Vec<_>>(),
        "enrolled_certificates": inventory.enrolled_certificates.iter().map(enrolled_certificate_to_json).collect::<Vec<_>>(),
        "certificate_status_cache": inventory.certificate_status_cache.iter().map(status_cache_to_json).collect::<Vec<_>>(),
        "emergency_blocklist": {
            "blocked_root_sha256": inventory.emergency_blocklist.blocked_root_sha256,
            "blocked_issuer_sha256": inventory.emergency_blocklist.blocked_issuer_sha256,
            "updated_at_unix_seconds": inventory.emergency_blocklist.updated_at_unix_seconds,
        },
        "contacts": inventory.contacts.iter().map(contact_to_json).collect::<Vec<_>>(),
    })
}

fn inventory_from_json(
    value: &Value,
) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
    let object = json_object(value, "$")?;
    let version = json_u64(object, "version")?;
    if version != STORE_FORMAT_VERSION {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "version" });
    }

    let inventory = TzapLocalIdentityInventory {
        device_signing_keys: json_array(object, "device_signing_keys")?
            .iter()
            .map(device_signing_key_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        recipient_encryption_keys: json_array(object, "recipient_encryption_keys")?
            .iter()
            .map(recipient_encryption_key_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        enrolled_certificates: json_array(object, "enrolled_certificates")?
            .iter()
            .map(enrolled_certificate_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        certificate_status_cache: json_array(object, "certificate_status_cache")?
            .iter()
            .map(status_cache_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        emergency_blocklist: emergency_blocklist_from_json(json_field(
            object,
            "emergency_blocklist",
        )?)?,
        contacts: json_array(object, "contacts")?
            .iter()
            .map(contact_from_json)
            .collect::<Result<Vec<_>, _>>()?,
    };
    inventory.validate()?;
    Ok(inventory)
}

fn device_signing_key_to_json(record: &TzapDeviceSigningKeyRecord) -> Value {
    serde_json::json!({
        "key_id": record.key_id,
        "public_key_fingerprint": record.public_key_fingerprint,
        "private_key_der": URL_SAFE_NO_PAD.encode(record.private_key_der.expose_secret()),
        "created_at_unix_seconds": record.created_at_unix_seconds,
        "label": record.label,
    })
}

fn device_signing_key_from_json(
    value: &Value,
) -> Result<TzapDeviceSigningKeyRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "device_signing_keys[]")?;
    Ok(TzapDeviceSigningKeyRecord {
        key_id: json_string(object, "key_id")?,
        public_key_fingerprint: json_string(object, "public_key_fingerprint")?,
        private_key_der: SecretBytes::from(decode_base64url(
            json_string(object, "private_key_der")?,
            "private_key_der",
        )?),
        created_at_unix_seconds: json_u64(object, "created_at_unix_seconds")?,
        label: json_optional_string(object, "label")?,
    })
}

fn recipient_encryption_key_to_json(record: &TzapRecipientEncryptionKeyRecord) -> Value {
    serde_json::json!({
        "key_id": record.key_id,
        "algorithm": record.algorithm,
        "public_key_fingerprint": record.public_key_fingerprint,
        "public_key_der": URL_SAFE_NO_PAD.encode(&record.public_key_der),
        "private_key_der": URL_SAFE_NO_PAD.encode(record.private_key_der.expose_secret()),
        "created_at_unix_seconds": record.created_at_unix_seconds,
        "label": record.label,
    })
}

fn recipient_encryption_key_from_json(
    value: &Value,
) -> Result<TzapRecipientEncryptionKeyRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "recipient_encryption_keys[]")?;
    Ok(TzapRecipientEncryptionKeyRecord {
        key_id: json_string(object, "key_id")?,
        algorithm: json_string(object, "algorithm")?,
        public_key_fingerprint: json_string(object, "public_key_fingerprint")?,
        public_key_der: decode_base64url(json_string(object, "public_key_der")?, "public_key_der")?,
        private_key_der: SecretBytes::from(decode_base64url(
            json_string(object, "private_key_der")?,
            "private_key_der",
        )?),
        created_at_unix_seconds: json_u64(object, "created_at_unix_seconds")?,
        label: json_optional_string(object, "label")?,
    })
}

fn enrolled_certificate_to_json(record: &TzapEnrolledCertificateRecord) -> Value {
    serde_json::json!({
        "certificate_sha256": record.certificate_sha256,
        "certificate_id": record.certificate_id,
        "issuer_certificate_sha256": record.issuer_certificate_sha256,
        "issuer_key_identifier": record.issuer_key_identifier,
        "serial_number": record.serial_number,
        "leaf_certificate_der": URL_SAFE_NO_PAD.encode(&record.leaf_certificate_der),
        "intermediate_chain_der": record.intermediate_chain_der.iter().map(|der| URL_SAFE_NO_PAD.encode(der)).collect::<Vec<_>>(),
        "not_before_unix_seconds": record.not_before_unix_seconds,
        "not_after_unix_seconds": record.not_after_unix_seconds,
        "public_metadata": public_metadata_to_json(&record.public_metadata),
        "sign_device_id": record.sign_device_id,
        "sign_device_routing": routing_to_json(&record.sign_device_routing),
        "signing_key_id": record.signing_key_id,
        "state": record.state.as_str(),
    })
}

fn enrolled_certificate_from_json(
    value: &Value,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "enrolled_certificates[]")?;
    Ok(TzapEnrolledCertificateRecord {
        certificate_sha256: json_string(object, "certificate_sha256")?,
        certificate_id: json_string(object, "certificate_id")?,
        issuer_certificate_sha256: json_string(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: json_string(object, "issuer_key_identifier")?,
        serial_number: json_string(object, "serial_number")?,
        leaf_certificate_der: decode_base64url(
            json_string(object, "leaf_certificate_der")?,
            "leaf_certificate_der",
        )?,
        intermediate_chain_der: json_array(object, "intermediate_chain_der")?
            .iter()
            .map(|value| {
                decode_base64url(
                    json_string_value(value, "intermediate_chain_der[]")?,
                    "intermediate_chain_der",
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
        not_before_unix_seconds: json_u64(object, "not_before_unix_seconds")?,
        not_after_unix_seconds: json_u64(object, "not_after_unix_seconds")?,
        public_metadata: public_metadata_from_json(json_field(object, "public_metadata")?)?,
        sign_device_id: json_string(object, "sign_device_id")?,
        sign_device_routing: routing_from_json(json_field(object, "sign_device_routing")?)?,
        signing_key_id: json_string(object, "signing_key_id")?,
        state: TzapLocalCertificateState::from_wire_value(&json_string(object, "state")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField { field: "state" })?,
    })
}

fn status_cache_to_json(record: &TzapCertificateStatusCacheRecord) -> Value {
    serde_json::json!({
        "certificate_sha256": record.certificate_sha256,
        "status": record.status.as_str(),
        "this_update_unix_seconds": record.this_update_unix_seconds,
        "next_update_unix_seconds": record.next_update_unix_seconds,
    })
}

fn status_cache_from_json(
    value: &Value,
) -> Result<TzapCertificateStatusCacheRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "certificate_status_cache[]")?;
    Ok(TzapCertificateStatusCacheRecord {
        certificate_sha256: json_string(object, "certificate_sha256")?,
        status: TzapCertificateStatus::parse(&json_string(object, "status")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField { field: "status" })?,
        this_update_unix_seconds: json_u64(object, "this_update_unix_seconds")?,
        next_update_unix_seconds: json_u64(object, "next_update_unix_seconds")?,
    })
}

fn emergency_blocklist_from_json(
    value: &Value,
) -> Result<TzapEmergencyBlocklistState, TzapLocalIdentityStoreError> {
    let object = json_object(value, "emergency_blocklist")?;
    Ok(TzapEmergencyBlocklistState {
        blocked_root_sha256: json_array(object, "blocked_root_sha256")?
            .iter()
            .map(|value| json_string_value(value, "blocked_root_sha256[]"))
            .collect::<Result<Vec<_>, _>>()?,
        blocked_issuer_sha256: json_array(object, "blocked_issuer_sha256")?
            .iter()
            .map(|value| json_string_value(value, "blocked_issuer_sha256[]"))
            .collect::<Result<Vec<_>, _>>()?,
        updated_at_unix_seconds: json_optional_u64(object, "updated_at_unix_seconds")?,
    })
}

fn contact_to_json(record: &TzapContactRecord) -> Value {
    serde_json::json!({
        "contact_id": record.contact_id,
        "display_name": record.display_name,
        "signing_certificate_sha256": record.signing_certificate_sha256,
        "recipient_public_key_fingerprint": record.recipient_public_key_fingerprint,
        "trust_anchor_type": record.trust_anchor_type.as_str(),
        "verification_state": record.verification_state.as_str(),
        "missing_status_caveat": record.missing_status_caveat,
        "contact_card_payload": record.contact_card_payload,
        "accepted_at_unix_seconds": record.accepted_at_unix_seconds,
    })
}

fn contact_from_json(value: &Value) -> Result<TzapContactRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "contacts[]")?;
    let trust_anchor_type = match object.get("trust_anchor_type") {
        Some(Value::Null) | None => trust::TzapTrustAnchorType::Untrusted,
        Some(_) => trust::TzapTrustAnchorType::parse(&json_string(object, "trust_anchor_type")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField {
                field: "trust_anchor_type",
            })?,
    };
    let verification_state = match object.get("verification_state") {
        Some(Value::Null) | None => trust::TzapVerificationState::CryptographicallyIntactOffline,
        Some(_) => trust::TzapVerificationState::parse(&json_string(object, "verification_state")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField {
                field: "verification_state",
            })?,
    };
    let missing_status_caveat = match object.get("missing_status_caveat") {
        Some(Value::Null) | None => true,
        Some(_) => json_bool(object, "missing_status_caveat")?,
    };
    Ok(TzapContactRecord {
        contact_id: json_string(object, "contact_id")?,
        display_name: json_string(object, "display_name")?,
        signing_certificate_sha256: json_string(object, "signing_certificate_sha256")?,
        recipient_public_key_fingerprint: json_string(object, "recipient_public_key_fingerprint")?,
        trust_anchor_type,
        verification_state,
        missing_status_caveat,
        contact_card_payload: json_field(object, "contact_card_payload")?.clone(),
        accepted_at_unix_seconds: json_u64(object, "accepted_at_unix_seconds")?,
    })
}

fn public_metadata_to_json(metadata: &TzapCertificatePublicMetadata) -> Value {
    serde_json::json!({
        "version": metadata.version,
        "public_signer_id": metadata.public_signer_id,
        "public_org_id": metadata.public_org_id,
        "public_device_id": metadata.public_device_id,
        "assurance_level": metadata.assurance_level.as_str(),
        "policy_oid": metadata.policy_oid,
    })
}

fn public_metadata_from_json(
    value: &Value,
) -> Result<TzapCertificatePublicMetadata, TzapLocalIdentityStoreError> {
    let object = json_object(value, "public_metadata")?;
    Ok(TzapCertificatePublicMetadata {
        version: json_u64(object, "version")?,
        public_signer_id: json_string(object, "public_signer_id")?,
        public_org_id: json_optional_string(object, "public_org_id")?,
        public_device_id: json_string(object, "public_device_id")?,
        assurance_level: trust::TzapIdentityAssurance::parse(&json_string(
            object,
            "assurance_level",
        )?)
        .ok_or(TzapLocalIdentityStoreError::InvalidField {
            field: "assurance_level",
        })?,
        policy_oid: json_string(object, "policy_oid")?,
    })
}

fn routing_to_json(routing: &TzapSignDeviceRouting) -> Value {
    match routing {
        TzapSignDeviceRouting::Personal => serde_json::json!({"kind": "personal"}),
        TzapSignDeviceRouting::Organization {
            org_id,
            login_organization_device_id,
        } => serde_json::json!({
            "kind": "organization",
            "org_id": org_id,
            "login_organization_device_id": login_organization_device_id,
        }),
    }
}

fn routing_from_json(value: &Value) -> Result<TzapSignDeviceRouting, TzapLocalIdentityStoreError> {
    let object = json_object(value, "sign_device_routing")?;
    match json_string(object, "kind")?.as_str() {
        "personal" => Ok(TzapSignDeviceRouting::Personal),
        "organization" => Ok(TzapSignDeviceRouting::Organization {
            org_id: json_string(object, "org_id")?,
            login_organization_device_id: json_string(object, "login_organization_device_id")?,
        }),
        _ => Err(TzapLocalIdentityStoreError::InvalidField {
            field: "sign_device_routing.kind",
        }),
    }
}

fn validate_account_key(account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
    validate_non_empty_id("account_key", account_key)?;
    if account_key
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(TzapLocalIdentityStoreError::InvalidField {
            field: "account_key",
        })
    }
}

fn decode_base64url(
    value: String,
    field: &'static str,
) -> Result<Vec<u8>, TzapLocalIdentityStoreError> {
    trust::validate_base64url_no_padding(&value)
        .map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, TzapLocalIdentityStoreError> {
    value
        .as_object()
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, TzapLocalIdentityStoreError> {
    object
        .get(field)
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a Vec<Value>, TzapLocalIdentityStoreError> {
    json_field(object, field)?
        .as_array()
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, TzapLocalIdentityStoreError> {
    json_string_value(json_field(object, field)?, field)
}

fn json_string_value(
    value: &Value,
    field: &'static str,
) -> Result<String, TzapLocalIdentityStoreError> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_optional_string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, TzapLocalIdentityStoreError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => json_string_value(value, field).map(Some),
    }
}

fn json_u64(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<u64, TzapLocalIdentityStoreError> {
    json_field(object, field)?
        .as_u64()
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_bool(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<bool, TzapLocalIdentityStoreError> {
    json_field(object, field)?
        .as_bool()
        .ok_or(TzapLocalIdentityStoreError::InvalidField { field })
}

fn json_optional_u64(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, TzapLocalIdentityStoreError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(TzapLocalIdentityStoreError::InvalidField { field }),
    }
}

fn validate_public_metadata(
    metadata: &TzapCertificatePublicMetadata,
) -> Result<(), TzapLocalIdentityStoreError> {
    if !is_valid_public_signer_id(&metadata.public_signer_id) {
        return Err(TzapLocalIdentityStoreError::InvalidField {
            field: "public_metadata.public_signer_id",
        });
    }
    if let Some(public_org_id) = &metadata.public_org_id
        && !trust::is_valid_public_org_id(public_org_id)
    {
        return Err(TzapLocalIdentityStoreError::InvalidField {
            field: "public_metadata.public_org_id",
        });
    }
    if !is_valid_public_device_id(&metadata.public_device_id) {
        return Err(TzapLocalIdentityStoreError::InvalidField {
            field: "public_metadata.public_device_id",
        });
    }
    if metadata.policy_oid.is_empty() {
        return Err(TzapLocalIdentityStoreError::InvalidField {
            field: "public_metadata.policy_oid",
        });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), TzapLocalIdentityStoreError> {
    trust::parse_sha256_identifier(value)
        .map(|_| ())
        .map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })
}

fn validate_non_empty_id(
    field: &'static str,
    value: &str,
) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() {
        Err(TzapLocalIdentityStoreError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_secret_bytes(
    field: &'static str,
    value: &SecretBytes,
) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() {
        Err(TzapLocalIdentityStoreError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_non_empty_bytes(
    field: &'static str,
    value: &[u8],
) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() {
        Err(TzapLocalIdentityStoreError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_unique<'a>(
    field: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), TzapLocalIdentityStoreError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(TzapLocalIdentityStoreError::DuplicateRecord {
                field,
                value: value.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, FileTzapLocalIdentityStore,
        IDENTITY_INVENTORY_FILE_SUFFIX, InMemoryTzapLocalIdentityStore,
        TzapCertificateStatusCacheRecord, TzapContactRecord, TzapDeviceSigningKeyRecord,
        TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
        TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError,
        TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
    };
    use crate::device_identity::{
        TzapDeviceCsrOptions, ensure_recipient_key_is_distinct_from_signing_key,
        generate_device_signing_key_and_csr, generate_recipient_encryption_key,
    };
    use crate::secrets::SecretBytes;
    use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus};
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_IDENTITY_STORE_DIR_PREFIX: &str = "zmanager-identity-store";

    #[test]
    fn in_memory_identity_store_round_trips_inventory() {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let inventory = valid_inventory();

        store
            .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory.clone())
            .unwrap();

        let loaded = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert_eq!(loaded, inventory);
        assert_eq!(
            format!("{:?}", loaded.device_signing_keys[0].private_key_der),
            "SecretBytes([redacted])"
        );

        store
            .clear_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert_eq!(
            store
                .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
                .unwrap(),
            TzapLocalIdentityInventory::empty()
        );
    }

    #[test]
    fn file_identity_store_reloads_generated_device_keys() {
        let temp_dir = TestIdentityStoreDir::new("reload-generated-keys");
        let mut store = FileTzapLocalIdentityStore::new(temp_dir.path());
        let signing_key =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();
        ensure_recipient_key_is_distinct_from_signing_key(
            &signing_key.public_key_fingerprint,
            &recipient_key.public_key_fingerprint,
        )
        .unwrap();

        let inventory = TzapLocalIdentityInventory {
            device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                key_id: "generated-signing-key".to_owned(),
                public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
                private_key_der: signing_key.private_key_der.clone(),
                created_at_unix_seconds: 100,
                label: Some("Generated signing key".to_owned()),
            }],
            recipient_encryption_keys: vec![TzapRecipientEncryptionKeyRecord {
                key_id: "generated-recipient-key".to_owned(),
                algorithm: recipient_key.algorithm.to_owned(),
                public_key_fingerprint: recipient_key.public_key_fingerprint.clone(),
                public_key_der: recipient_key.public_key_spki_der.clone(),
                private_key_der: recipient_key.private_key_der.clone(),
                created_at_unix_seconds: 101,
                label: Some("Generated recipient key".to_owned()),
            }],
            enrolled_certificates: Vec::new(),
            certificate_status_cache: Vec::new(),
            emergency_blocklist: TzapEmergencyBlocklistState::default(),
            contacts: Vec::new(),
        };

        store
            .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
            .unwrap();

        let reloaded_store = FileTzapLocalIdentityStore::new(temp_dir.path());
        let loaded = reloaded_store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();

        assert_eq!(
            loaded.device_signing_keys[0].public_key_fingerprint,
            signing_key.public_key_fingerprint
        );
        assert_eq!(
            loaded.recipient_encryption_keys[0].public_key_fingerprint,
            recipient_key.public_key_fingerprint
        );
        assert_eq!(
            format!("{:?}", loaded.device_signing_keys[0].private_key_der),
            "SecretBytes([redacted])"
        );
        assert_eq!(
            format!("{:?}", loaded.recipient_encryption_keys[0].private_key_der),
            "SecretBytes([redacted])"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(temp_dir.path().join(format!(
                "{DEFAULT_IDENTITY_INVENTORY_ACCOUNT}{IDENTITY_INVENTORY_FILE_SUFFIX}"
            )))
            .unwrap()
            .permissions()
            .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn identity_inventory_rejects_duplicates() {
        let mut inventory = valid_inventory();
        inventory.device_signing_keys.push(
            inventory
                .device_signing_keys
                .first()
                .expect("fixture has key")
                .clone(),
        );

        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::DuplicateRecord { field, .. })
                if field == "device_signing_keys.key_id"
        ));
    }

    #[test]
    fn identity_inventory_rejects_invalid_certificate_references() {
        let mut inventory = valid_inventory();
        inventory.enrolled_certificates[0].certificate_sha256 = "not-a-sha".to_owned();
        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::InvalidField { field })
                if field == "certificate_sha256"
        ));

        let mut inventory = valid_inventory();
        inventory.enrolled_certificates[0].not_after_unix_seconds = 10;
        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::InvalidField { field })
                if field == "certificate_validity"
        ));
    }

    #[test]
    fn identity_inventory_rejects_empty_private_key_material() {
        let mut inventory = valid_inventory();
        inventory.device_signing_keys[0].private_key_der = SecretBytes::from(Vec::new());

        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::InvalidField { field })
                if field == "device_signing_keys.private_key_der"
        ));
    }

    #[test]
    fn identity_inventory_rejects_recipient_key_reusing_signing_key_fingerprint() {
        let mut inventory = valid_inventory();
        inventory.recipient_encryption_keys[0].public_key_fingerprint = inventory
            .device_signing_keys[0]
            .public_key_fingerprint
            .clone();

        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::InvalidField { field })
                if field == "recipient_encryption_keys.public_key_fingerprint"
        ));
    }

    #[test]
    fn identity_inventory_reports_active_retirement_routes() {
        let mut inventory = valid_inventory();
        inventory
            .enrolled_certificates
            .push(TzapEnrolledCertificateRecord {
                certificate_id: "cert-org-1".to_owned(),
                certificate_sha256: canonical_sha(0x09),
                issuer_certificate_sha256: canonical_sha(0x04),
                issuer_key_identifier: "AQIDBA".to_owned(),
                serial_number: "02ABCDEF".to_owned(),
                leaf_certificate_der: vec![0x30, 0x09],
                intermediate_chain_der: vec![vec![0x30, 0x05]],
                not_before_unix_seconds: 100,
                not_after_unix_seconds: 200,
                public_metadata: public_metadata(),
                sign_device_id: "org-sign-device-1".to_owned(),
                sign_device_routing: TzapSignDeviceRouting::Organization {
                    org_id: "org_123".to_owned(),
                    login_organization_device_id: "login-org-device-1".to_owned(),
                },
                signing_key_id: "device-key-1".to_owned(),
                state: TzapLocalCertificateState::Active,
            });
        inventory
            .enrolled_certificates
            .push(TzapEnrolledCertificateRecord {
                certificate_id: "cert-revoked-1".to_owned(),
                certificate_sha256: canonical_sha(0x0a),
                issuer_certificate_sha256: canonical_sha(0x04),
                issuer_key_identifier: "AQIDBA".to_owned(),
                serial_number: "03ABCDEF".to_owned(),
                leaf_certificate_der: vec![0x30, 0x0a],
                intermediate_chain_der: vec![vec![0x30, 0x05]],
                not_before_unix_seconds: 100,
                not_after_unix_seconds: 200,
                public_metadata: public_metadata(),
                sign_device_id: "revoked-device".to_owned(),
                sign_device_routing: TzapSignDeviceRouting::Personal,
                signing_key_id: "device-key-1".to_owned(),
                state: TzapLocalCertificateState::Revoked,
            });

        assert_eq!(
            inventory.active_personal_sign_device_ids(),
            vec!["sign-device-1"]
        );
        let organization_routes = inventory.active_organization_device_retirements();
        assert_eq!(organization_routes.len(), 1);
        assert_eq!(organization_routes[0].org_id, "org_123");
        assert_eq!(
            organization_routes[0].login_organization_device_id,
            "login-org-device-1"
        );
        assert_eq!(organization_routes[0].sign_device_id, "org-sign-device-1");
    }

    fn valid_inventory() -> TzapLocalIdentityInventory {
        TzapLocalIdentityInventory {
            device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: canonical_sha(0x01),
                private_key_der: SecretBytes::from(vec![0x30, 0x01]),
                created_at_unix_seconds: 100,
                label: Some("MacBook".to_owned()),
            }],
            recipient_encryption_keys: vec![TzapRecipientEncryptionKeyRecord {
                key_id: "recipient-key-1".to_owned(),
                algorithm: crate::device_identity::RECIPIENT_ENCRYPTION_KEY_ALGORITHM.to_owned(),
                public_key_fingerprint: canonical_sha(0x02),
                public_key_der: vec![0x30, 0x02],
                private_key_der: SecretBytes::from(vec![0x30, 0x03]),
                created_at_unix_seconds: 101,
                label: Some("Archive sharing".to_owned()),
            }],
            enrolled_certificates: vec![TzapEnrolledCertificateRecord {
                certificate_id: "cert-personal-1".to_owned(),
                certificate_sha256: canonical_sha(0x03),
                issuer_certificate_sha256: canonical_sha(0x04),
                issuer_key_identifier: "AQIDBA".to_owned(),
                serial_number: "01ABCDEF".to_owned(),
                leaf_certificate_der: vec![0x30, 0x04],
                intermediate_chain_der: vec![vec![0x30, 0x05]],
                not_before_unix_seconds: 100,
                not_after_unix_seconds: 200,
                public_metadata: public_metadata(),
                sign_device_id: "sign-device-1".to_owned(),
                sign_device_routing: TzapSignDeviceRouting::Personal,
                signing_key_id: "device-key-1".to_owned(),
                state: TzapLocalCertificateState::Active,
            }],
            certificate_status_cache: vec![TzapCertificateStatusCacheRecord {
                certificate_sha256: canonical_sha(0x03),
                status: TzapCertificateStatus::Valid,
                this_update_unix_seconds: 120,
                next_update_unix_seconds: 180,
            }],
            emergency_blocklist: TzapEmergencyBlocklistState {
                blocked_root_sha256: vec![canonical_sha(0x05)],
                blocked_issuer_sha256: vec![canonical_sha(0x06)],
                updated_at_unix_seconds: Some(110),
            },
            contacts: vec![TzapContactRecord {
                contact_id: "contact-1".to_owned(),
                display_name: "Ada".to_owned(),
                signing_certificate_sha256: canonical_sha(0x07),
                recipient_public_key_fingerprint: canonical_sha(0x08),
                trust_anchor_type: trust::TzapTrustAnchorType::Custom,
                verification_state: trust::TzapVerificationState::CryptographicallyIntactOffline,
                missing_status_caveat: true,
                contact_card_payload: json!({"version": 1}),
                accepted_at_unix_seconds: 130,
            }],
        }
    }

    fn public_metadata() -> TzapCertificatePublicMetadata {
        TzapCertificatePublicMetadata {
            version: 1,
            public_signer_id: "psign_0123456789ABCDEFGH".to_owned(),
            public_org_id: Some("porg_0123456789ABCDEFGH".to_owned()),
            public_device_id: "pdev_0123456789ABCDEFGH".to_owned(),
            assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
        }
    }

    fn canonical_sha(byte: u8) -> String {
        trust::format_sha256_identifier(&[byte; 32])
    }

    struct TestIdentityStoreDir {
        path: PathBuf,
    }

    impl TestIdentityStoreDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "{TEST_IDENTITY_STORE_DIR_PREFIX}-{name}-{}-{now}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test identity store dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestIdentityStoreDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
