//! Local TZAP identity inventory and storage abstraction.

use crate::contact_snapshot::TzapContactTombstone;
use crate::secrets::SecretBytes;
use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus, is_valid_public_device_id, is_valid_public_signer_id};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::PathBuf;

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
    /// Tombstones for contacts removed on this device (design §8.3, §8.4).
    /// Read by `contact_snapshot::build_contact_snapshot` and merged into by
    /// `contact_snapshot::apply_contact_snapshot` so a removal survives a
    /// backup/restore round trip instead of being resurrected by a union
    /// merge. Absent on inventories written before this field existed.
    pub removed_contacts: Vec<TzapContactTombstone>,
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
            removed_contacts: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_unique("device_signing_keys.key_id", self.device_signing_keys.iter().map(|record| record.key_id.as_str()))?;
        validate_unique("recipient_encryption_keys.key_id", self.recipient_encryption_keys.iter().map(|record| record.key_id.as_str()))?;
        validate_unique("enrolled_certificates.certificate_sha256", self.enrolled_certificates.iter().map(|record| record.certificate_sha256.as_str()))?;
        validate_unique("contacts.contact_id", self.contacts.iter().map(|record| record.contact_id.as_str()))?;

        for record in &self.device_signing_keys {
            validate_non_empty_id("device_signing_keys.key_id", &record.key_id)?;
            validate_sha256("device_signing_keys.public_key_fingerprint", &record.public_key_fingerprint)?;
            validate_secret_bytes("device_signing_keys.private_key_der", &record.private_key_der)?;
        }
        for record in &self.recipient_encryption_keys {
            validate_non_empty_id("recipient_encryption_keys.key_id", &record.key_id)?;
            validate_non_empty_id("recipient_encryption_keys.algorithm", &record.algorithm)?;
            validate_sha256("recipient_encryption_keys.public_key_fingerprint", &record.public_key_fingerprint)?;
            validate_secret_bytes("recipient_encryption_keys.private_key_der", &record.private_key_der)?;
            validate_non_empty_bytes("recipient_encryption_keys.public_key_der", &record.public_key_der)?;
            if self.device_signing_keys.iter().any(|signing_key| signing_key.public_key_fingerprint == record.public_key_fingerprint) {
                return Err(TzapLocalIdentityStoreError::InvalidField { field: "recipient_encryption_keys.public_key_fingerprint" });
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
                TzapSignDeviceRouting::Organization { org_id, login_organization_device_id } => Some(TzapOrganizationDeviceRetirement {
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TzapSignDeviceRouting {
    Personal,
    Organization { org_id: String, login_organization_device_id: String },
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
    /// How many days after `not_after_unix_seconds` the server still accepts
    /// a renewal (S1, mobile-tzap-archive-signing-tracker.md). `None` when the
    /// enrolling server predates S1 or the record was never told.
    pub renewal_grace_period_days: Option<u64>,
    /// How many days before `not_after_unix_seconds` readiness should report
    /// `RenewalRecommended` instead of `Ready` (S1). `None` means no
    /// server-sourced threshold is known, so no recommendation is made.
    pub renewal_recommended_within_days: Option<u64>,
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
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "issuer_key_identifier" });
        }
        if trust::parse_serial_hex(&self.serial_number).is_err() {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "serial_number" });
        }
        validate_non_empty_bytes("leaf_certificate_der", &self.leaf_certificate_der)?;
        if self.intermediate_chain_der.is_empty() {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "intermediate_chain_der" });
        }
        for der in &self.intermediate_chain_der {
            validate_non_empty_bytes("intermediate_chain_der", der)?;
        }
        if self.not_before_unix_seconds >= self.not_after_unix_seconds {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "certificate_validity" });
        }
        validate_public_metadata(&self.public_metadata)?;
        validate_non_empty_id("sign_device_id", &self.sign_device_id)?;
        match &self.sign_device_routing {
            TzapSignDeviceRouting::Personal => {}
            TzapSignDeviceRouting::Organization { org_id, login_organization_device_id } => {
                validate_non_empty_id("sign_device_routing.org_id", org_id)?;
                validate_non_empty_id("sign_device_routing.login_organization_device_id", login_organization_device_id)?;
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
        validate_sha256("certificate_status_cache.certificate_sha256", &self.certificate_sha256)?;
        if self.this_update_unix_seconds >= self.next_update_unix_seconds {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "certificate_status_cache.freshness_window" });
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
        validate_unique("emergency_blocklist.blocked_root_sha256", self.blocked_root_sha256.iter().map(String::as_str))?;
        validate_unique("emergency_blocklist.blocked_issuer_sha256", self.blocked_issuer_sha256.iter().map(String::as_str))?;
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
    /// Origin of the locally stored contact, such as `phone_sync` or an
    /// empty value for a contact accepted directly on this device.
    pub source: String,
    pub verification_state: trust::TzapVerificationState,
    pub missing_status_caveat: bool,
    pub contact_card_payload: Value,
    pub accepted_at_unix_seconds: u64,
    /// Display name chosen by the importer, distinct from the card's own
    /// `display_name`/`device_label` (chosen by the sender). Display
    /// metadata only -- never signed, never fed back into verification.
    /// `None` for a contact the importer has not renamed, and absent from
    /// catalogs written before this field existed.
    pub local_alias: Option<String>,
    /// Original signed contact card container, retained for snapshot export
    /// and re-verification (design §8.3). `None` on legacy records.
    pub card: Option<Value>,
}

impl TzapContactRecord {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("contacts.contact_id", &self.contact_id)?;
        validate_non_empty_id("contacts.display_name", &self.display_name)?;
        validate_sha256("contacts.signing_certificate_sha256", &self.signing_certificate_sha256)?;
        validate_sha256("contacts.recipient_public_key_fingerprint", &self.recipient_public_key_fingerprint)?;
        if self.verification_state == trust::TzapVerificationState::Invalid {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "contacts.verification_state" });
        }
        if !self.contact_card_payload.is_object() {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "contacts.contact_card_payload" });
        }
        Ok(())
    }
}

pub trait TzapLocalIdentityStore {
    fn load_inventory(&self, account_key: &str) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError>;

    fn save_inventory(&mut self, account_key: &str, inventory: TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError>;

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

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

impl FileTzapLocalIdentityStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn inventory_path(&self, account_key: &str) -> Result<PathBuf, TzapLocalIdentityStoreError> {
        validate_account_key(account_key)?;
        Ok(self.root.join(format!("{account_key}{IDENTITY_INVENTORY_FILE_SUFFIX}")))
    }
}

impl TzapLocalIdentityStore for FileTzapLocalIdentityStore {
    fn load_inventory(&self, account_key: &str) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, FileTzapSecretMaterialStore, load_inventory_from_catalog, store_inventory_as_catalog};

        let catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        let secret_store = FileTzapSecretMaterialStore::new(&self.root, account_key);
        if let Some(inventory) = load_inventory_from_catalog(&catalog_store, &secret_store, account_key)? {
            return Ok(inventory);
        }

        // No catalog yet: migrate the legacy inventory file once, then treat
        // the catalog as the only on-disk format.
        let legacy_path = self.inventory_path(account_key)?;
        if !legacy_path.exists() {
            return Ok(TzapLocalIdentityInventory::empty());
        }
        let bytes = fs::read(&legacy_path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let inventory = inventory_from_json(&value)?;
        inventory.validate()?;
        store_inventory_as_catalog(
            &mut FileTzapIdentityCatalogStore::new(&self.root),
            &mut FileTzapSecretMaterialStore::new(&self.root, account_key),
            account_key,
            &inventory,
            current_unix_seconds(),
        )?;
        let _ = fs::remove_file(legacy_path);
        Ok(inventory)
    }

    fn save_inventory(&mut self, account_key: &str, inventory: TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, FileTzapSecretMaterialStore, store_inventory_as_catalog};

        inventory.validate()?;
        store_inventory_as_catalog(
            &mut FileTzapIdentityCatalogStore::new(&self.root),
            &mut FileTzapSecretMaterialStore::new(&self.root, account_key),
            account_key,
            &inventory,
            current_unix_seconds(),
        )?;
        let _ = fs::remove_file(self.inventory_path(account_key)?);
        Ok(())
    }

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, TzapIdentityCatalogStore as _};

        let mut catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        let _ = catalog_store.clear_catalog(account_key);
        let secrets_root = self.root.join("secrets").join(account_key);
        if secrets_root.exists() {
            let _ = fs::remove_dir_all(&secrets_root);
        }
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
    fn load_inventory(&self, account_key: &str) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        validate_non_empty_id("account_key", account_key)?;
        Ok(self.inventories.get(account_key).cloned().unwrap_or_else(TzapLocalIdentityInventory::empty))
    }

    fn save_inventory(&mut self, account_key: &str, inventory: TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError> {
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

#[derive(Debug)]
pub enum TzapLocalIdentityStoreError {
    InvalidField {
        field: &'static str,
    },
    DuplicateRecord {
        field: &'static str,
        value: String,
    },
    /// Filesystem I/O failed. Carries the full error (including the OS-level
    /// message) so failures are diagnosable without re-probing the path.
    Io(std::io::Error),
    Json(String),
    /// The identity catalog (the facade's storage) rejected the operation.
    /// Boxed because the catalog error carries this error type in its
    /// `Legacy` variant; an unboxed cycle would be infinitely sized.
    Catalog(Box<crate::identity_catalog::TzapIdentityCatalogError>),
}

impl fmt::Display for TzapLocalIdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(f, "local identity field is invalid: {field}"),
            Self::DuplicateRecord { field, value } => {
                write!(f, "local identity field {field} contains duplicate {value}")
            }
            Self::Io(error) => write!(f, "local identity store I/O failed: {error}"),
            Self::Json(message) => write!(f, "local identity JSON is invalid: {message}"),
            Self::Catalog(error) => write!(f, "identity catalog operation failed: {error}"),
        }
    }
}

impl std::error::Error for TzapLocalIdentityStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::InvalidField { .. } | Self::DuplicateRecord { .. } | Self::Json(_) => None,
        }
    }
}

impl From<crate::identity_catalog::TzapIdentityCatalogError> for TzapLocalIdentityStoreError {
    fn from(error: crate::identity_catalog::TzapIdentityCatalogError) -> Self {
        Self::Catalog(Box::new(error))
    }
}

impl From<std::io::Error> for TzapLocalIdentityStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for TzapLocalIdentityStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

// Thin typed wrappers over the shared json_util helpers: the extraction
// logic lives in json_util; these exist so call sites keep concrete error
// types and inference stays unambiguous.
type JsonMap<'a> = &'a serde_json::Map<String, Value>;
fn json_object<'a>(value: &'a Value, field: &'static str) -> Result<JsonMap<'a>, TzapLocalIdentityStoreError> {
    crate::json_util::json_object(value, field)
}
fn required_field<'a>(object: JsonMap<'a>, field: &'static str) -> Result<&'a Value, TzapLocalIdentityStoreError> {
    crate::json_util::required_field(object, field)
}
fn required_array<'a>(object: JsonMap<'a>, field: &'static str) -> Result<&'a Vec<Value>, TzapLocalIdentityStoreError> {
    crate::json_util::required_array(object, field)
}
fn required_string(object: JsonMap<'_>, field: &'static str) -> Result<String, TzapLocalIdentityStoreError> {
    crate::json_util::required_string(object, field)
}
fn required_string_value(value: &Value, field: &'static str) -> Result<String, TzapLocalIdentityStoreError> {
    crate::json_util::required_string_value(value, field)
}
fn optional_string(object: JsonMap<'_>, field: &'static str) -> Result<Option<String>, TzapLocalIdentityStoreError> {
    crate::json_util::optional_string(object, field)
}
fn required_u64(object: JsonMap<'_>, field: &'static str) -> Result<u64, TzapLocalIdentityStoreError> {
    crate::json_util::required_u64(object, field)
}
fn required_bool(object: JsonMap<'_>, field: &'static str) -> Result<bool, TzapLocalIdentityStoreError> {
    crate::json_util::required_bool(object, field)
}
fn optional_u64(object: JsonMap<'_>, field: &'static str) -> Result<Option<u64>, TzapLocalIdentityStoreError> {
    crate::json_util::optional_u64(object, field)
}

fn inventory_from_json(value: &Value) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
    let object = json_object(value, "$")?;
    let version = required_u64(object, "version")?;
    if version != STORE_FORMAT_VERSION {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "version" });
    }

    let inventory = TzapLocalIdentityInventory {
        device_signing_keys: required_array(object, "device_signing_keys")?.iter().map(device_signing_key_from_json).collect::<Result<Vec<_>, _>>()?,
        recipient_encryption_keys: required_array(object, "recipient_encryption_keys")?
            .iter()
            .map(recipient_encryption_key_from_json)
            .collect::<Result<Vec<_>, _>>()?,
        enrolled_certificates: required_array(object, "enrolled_certificates")?.iter().map(enrolled_certificate_from_json).collect::<Result<Vec<_>, _>>()?,
        certificate_status_cache: required_array(object, "certificate_status_cache")?.iter().map(status_cache_from_json).collect::<Result<Vec<_>, _>>()?,
        emergency_blocklist: emergency_blocklist_from_json(required_field(object, "emergency_blocklist")?)?,
        contacts: required_array(object, "contacts")?.iter().map(contact_from_json).collect::<Result<Vec<_>, _>>()?,
        // This legacy raw-file format predates tombstones entirely (read only
        // for the one-time migration to the catalog format), so there is
        // nothing to parse.
        removed_contacts: Vec::new(),
    };
    inventory.validate()?;
    Ok(inventory)
}

fn device_signing_key_from_json(value: &Value) -> Result<TzapDeviceSigningKeyRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "device_signing_keys[]")?;
    Ok(TzapDeviceSigningKeyRecord {
        key_id: required_string(object, "key_id")?,
        public_key_fingerprint: required_string(object, "public_key_fingerprint")?,
        private_key_der: SecretBytes::from(decode_base64url(required_string(object, "private_key_der")?, "private_key_der")?),
        created_at_unix_seconds: required_u64(object, "created_at_unix_seconds")?,
        label: optional_string(object, "label")?,
    })
}

fn recipient_encryption_key_from_json(value: &Value) -> Result<TzapRecipientEncryptionKeyRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "recipient_encryption_keys[]")?;
    Ok(TzapRecipientEncryptionKeyRecord {
        key_id: required_string(object, "key_id")?,
        algorithm: required_string(object, "algorithm")?,
        public_key_fingerprint: required_string(object, "public_key_fingerprint")?,
        public_key_der: decode_base64url(required_string(object, "public_key_der")?, "public_key_der")?,
        private_key_der: SecretBytes::from(decode_base64url(required_string(object, "private_key_der")?, "private_key_der")?),
        created_at_unix_seconds: required_u64(object, "created_at_unix_seconds")?,
        label: optional_string(object, "label")?,
    })
}

fn enrolled_certificate_from_json(value: &Value) -> Result<TzapEnrolledCertificateRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "enrolled_certificates[]")?;
    Ok(TzapEnrolledCertificateRecord {
        certificate_sha256: required_string(object, "certificate_sha256")?,
        certificate_id: required_string(object, "certificate_id")?,
        issuer_certificate_sha256: required_string(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: required_string(object, "issuer_key_identifier")?,
        serial_number: required_string(object, "serial_number")?,
        leaf_certificate_der: decode_base64url(required_string(object, "leaf_certificate_der")?, "leaf_certificate_der")?,
        intermediate_chain_der: required_array(object, "intermediate_chain_der")?
            .iter()
            .map(|value| decode_base64url(required_string_value(value, "intermediate_chain_der[]")?, "intermediate_chain_der"))
            .collect::<Result<Vec<_>, _>>()?,
        not_before_unix_seconds: required_u64(object, "not_before_unix_seconds")?,
        not_after_unix_seconds: required_u64(object, "not_after_unix_seconds")?,
        // Absent on every record written before S1; this legacy raw-file
        // format is read only for one-time migration, so there is nothing to
        // backfill it from.
        renewal_grace_period_days: optional_u64(object, "renewal_grace_period_days")?,
        renewal_recommended_within_days: optional_u64(object, "renewal_recommended_within_days")?,
        public_metadata: public_metadata_from_json(required_field(object, "public_metadata")?)?,
        sign_device_id: required_string(object, "sign_device_id")?,
        sign_device_routing: routing_from_json(required_field(object, "sign_device_routing")?)?,
        signing_key_id: required_string(object, "signing_key_id")?,
        state: TzapLocalCertificateState::from_wire_value(&required_string(object, "state")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField { field: "state" })?,
    })
}

fn status_cache_from_json(value: &Value) -> Result<TzapCertificateStatusCacheRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "certificate_status_cache[]")?;
    Ok(TzapCertificateStatusCacheRecord {
        certificate_sha256: required_string(object, "certificate_sha256")?,
        status: required_string(object, "status")?
            .parse::<TzapCertificateStatus>()
            .map_err(|()| TzapLocalIdentityStoreError::InvalidField { field: "status" })?,
        this_update_unix_seconds: required_u64(object, "this_update_unix_seconds")?,
        next_update_unix_seconds: required_u64(object, "next_update_unix_seconds")?,
    })
}

fn emergency_blocklist_from_json(value: &Value) -> Result<TzapEmergencyBlocklistState, TzapLocalIdentityStoreError> {
    let object = json_object(value, "emergency_blocklist")?;
    Ok(TzapEmergencyBlocklistState {
        blocked_root_sha256: required_array(object, "blocked_root_sha256")?
            .iter()
            .map(|value| required_string_value(value, "blocked_root_sha256[]"))
            .collect::<Result<Vec<_>, _>>()?,
        blocked_issuer_sha256: required_array(object, "blocked_issuer_sha256")?
            .iter()
            .map(|value| required_string_value(value, "blocked_issuer_sha256[]"))
            .collect::<Result<Vec<_>, _>>()?,
        updated_at_unix_seconds: optional_u64(object, "updated_at_unix_seconds")?,
    })
}

fn contact_from_json(value: &Value) -> Result<TzapContactRecord, TzapLocalIdentityStoreError> {
    let object = json_object(value, "contacts[]")?;
    let trust_anchor_type = match object.get("trust_anchor_type") {
        Some(Value::Null) | None => trust::TzapTrustAnchorType::Untrusted,
        Some(_) => required_string(object, "trust_anchor_type")?
            .parse::<trust::TzapTrustAnchorType>()
            .map_err(|()| TzapLocalIdentityStoreError::InvalidField { field: "trust_anchor_type" })?,
    };
    let verification_state = match object.get("verification_state") {
        // Records written before verification-state tracking existed have no
        // field at all; defaulting to CryptographicallyIntactOffline would
        // claim evidence of offline verification that never happened, so
        // treat the state as unknown instead.
        Some(Value::Null) | None => trust::TzapVerificationState::NotRecorded,
        Some(_) => required_string(object, "verification_state")?
            .parse::<trust::TzapVerificationState>()
            .map_err(|()| TzapLocalIdentityStoreError::InvalidField { field: "verification_state" })?,
    };
    let missing_status_caveat = match object.get("missing_status_caveat") {
        Some(Value::Null) | None => true,
        Some(_) => required_bool(object, "missing_status_caveat")?,
    };
    Ok(TzapContactRecord {
        contact_id: required_string(object, "contact_id")?,
        display_name: required_string(object, "display_name")?,
        signing_certificate_sha256: required_string(object, "signing_certificate_sha256")?,
        recipient_public_key_fingerprint: required_string(object, "recipient_public_key_fingerprint")?,
        trust_anchor_type,
        source: optional_string(object, "source")?.unwrap_or_default(),
        verification_state,
        missing_status_caveat,
        contact_card_payload: required_field(object, "contact_card_payload")?.clone(),
        accepted_at_unix_seconds: required_u64(object, "accepted_at_unix_seconds")?,
        local_alias: optional_string(object, "local_alias")?,
        card: object.get("card").cloned(),
    })
}

fn public_metadata_from_json(value: &Value) -> Result<TzapCertificatePublicMetadata, TzapLocalIdentityStoreError> {
    let object = json_object(value, "public_metadata")?;
    Ok(TzapCertificatePublicMetadata {
        version: required_u64(object, "version")?,
        public_signer_id: required_string(object, "public_signer_id")?,
        public_org_id: optional_string(object, "public_org_id")?,
        public_device_id: required_string(object, "public_device_id")?,
        assurance_level: trust::TzapIdentityAssurance::parse(&required_string(object, "assurance_level")?)
            .ok_or(TzapLocalIdentityStoreError::InvalidField { field: "assurance_level" })?,
        policy_oid: required_string(object, "policy_oid")?,
    })
}

fn routing_from_json(value: &Value) -> Result<TzapSignDeviceRouting, TzapLocalIdentityStoreError> {
    let object = json_object(value, "sign_device_routing")?;
    match required_string(object, "kind")?.as_str() {
        "personal" => Ok(TzapSignDeviceRouting::Personal),
        "organization" => Ok(TzapSignDeviceRouting::Organization {
            org_id: required_string(object, "org_id")?,
            login_organization_device_id: required_string(object, "login_organization_device_id")?,
        }),
        _ => Err(TzapLocalIdentityStoreError::InvalidField { field: "sign_device_routing.kind" }),
    }
}

fn validate_account_key(account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
    // Shared with the identity catalog so both stores accept the same
    // account keys: non-empty and free of path separators and traversal
    // markers, but otherwise unrestricted.
    if crate::identity_catalog::validate_account_key(account_key) { Ok(()) } else { Err(TzapLocalIdentityStoreError::InvalidField { field: "account_key" }) }
}

fn decode_base64url(value: String, field: &'static str) -> Result<Vec<u8>, TzapLocalIdentityStoreError> {
    trust::validate_base64url_no_padding(&value).map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })?;
    URL_SAFE_NO_PAD.decode(value).map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })
}

fn validate_public_metadata(metadata: &TzapCertificatePublicMetadata) -> Result<(), TzapLocalIdentityStoreError> {
    if !is_valid_public_signer_id(&metadata.public_signer_id) {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "public_metadata.public_signer_id" });
    }
    if let Some(public_org_id) = &metadata.public_org_id
        && !trust::is_valid_public_org_id(public_org_id)
    {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "public_metadata.public_org_id" });
    }
    if !is_valid_public_device_id(&metadata.public_device_id) {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "public_metadata.public_device_id" });
    }
    if metadata.policy_oid.is_empty() {
        return Err(TzapLocalIdentityStoreError::InvalidField { field: "public_metadata.policy_oid" });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), TzapLocalIdentityStoreError> {
    trust::parse_sha256_identifier(value).map(|_| ()).map_err(|_| TzapLocalIdentityStoreError::InvalidField { field })
}

fn validate_non_empty_id(field: &'static str, value: &str) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() { Err(TzapLocalIdentityStoreError::InvalidField { field }) } else { Ok(()) }
}

fn validate_secret_bytes(field: &'static str, value: &SecretBytes) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() { Err(TzapLocalIdentityStoreError::InvalidField { field }) } else { Ok(()) }
}

fn validate_non_empty_bytes(field: &'static str, value: &[u8]) -> Result<(), TzapLocalIdentityStoreError> {
    if value.is_empty() { Err(TzapLocalIdentityStoreError::InvalidField { field }) } else { Ok(()) }
}

fn validate_unique<'a>(field: &'static str, values: impl Iterator<Item = &'a str>) -> Result<(), TzapLocalIdentityStoreError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(TzapLocalIdentityStoreError::DuplicateRecord { field, value: value.to_owned() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, FileTzapLocalIdentityStore, InMemoryTzapLocalIdentityStore, TzapCertificateStatusCacheRecord, TzapContactRecord,
        TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory,
        TzapLocalIdentityStore, TzapLocalIdentityStoreError, TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
    };
    use crate::device_identity::{
        TzapDeviceCsrOptions, ensure_recipient_key_is_distinct_from_signing_key, generate_device_signing_key_and_csr, generate_recipient_encryption_key,
    };
    use crate::secrets::SecretBytes;
    use crate::test_support::TestDir;
    use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    use std::fs;

    #[test]
    fn in_memory_identity_store_round_trips_inventory() {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let inventory = valid_inventory();

        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory.clone()).unwrap();

        let loaded = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(loaded, inventory);
        assert_eq!(format!("{:?}", loaded.device_signing_keys[0].private_key_der), "SecretBytes([redacted])");

        store.clear_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap(), TzapLocalIdentityInventory::empty());
    }

    #[test]
    fn file_identity_store_reloads_generated_device_keys() {
        let temp_dir = TestDir::new("reload-generated-keys");
        let mut store = FileTzapLocalIdentityStore::new(temp_dir.path(""));
        let signing_key = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();
        ensure_recipient_key_is_distinct_from_signing_key(&signing_key.public_key_fingerprint, &recipient_key.public_key_fingerprint).unwrap();

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
            removed_contacts: Vec::new(),
        };

        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let reloaded_store = FileTzapLocalIdentityStore::new(temp_dir.path(""));
        let loaded = reloaded_store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();

        assert_eq!(loaded.device_signing_keys[0].public_key_fingerprint, signing_key.public_key_fingerprint);
        assert_eq!(loaded.recipient_encryption_keys[0].public_key_fingerprint, recipient_key.public_key_fingerprint);
        assert_eq!(format!("{:?}", loaded.device_signing_keys[0].private_key_der), "SecretBytes([redacted])");
        assert_eq!(format!("{:?}", loaded.recipient_encryption_keys[0].private_key_der), "SecretBytes([redacted])");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            // Private key material now lives in the secret store; every
            // secret file must be owner-only.
            let secrets_root = temp_dir.path("").join("secrets").join(DEFAULT_IDENTITY_INVENTORY_ACCOUNT);
            let mut secret_files = Vec::new();
            for purpose_dir in fs::read_dir(&secrets_root).unwrap() {
                let purpose_dir = purpose_dir.unwrap().path();
                for entry in fs::read_dir(&purpose_dir).unwrap() {
                    secret_files.push(entry.unwrap().path());
                }
            }
            assert!(!secret_files.is_empty(), "expected secret files under {}", secrets_root.display());
            for secret in secret_files {
                let mode = fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "secret file {secret:?} must be owner-only");
            }
        }
    }

    #[test]
    fn file_identity_store_writes_inventory_atomically() {
        let temp_dir = TestDir::new("atomic-inventory-write");
        let mut store = FileTzapLocalIdentityStore::new(temp_dir.path(""));
        let inventory = valid_inventory();

        // Saving twice (an overwrite) leaves a complete, loadable file and no
        // temporary sibling files behind.
        let expected = inventory.clone();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, expected.clone()).unwrap();

        assert_eq!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap(), expected);

        let leftovers = fs::read_dir(temp_dir.path(""))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("tmp-"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "temporary sibling files should be cleaned up: {leftovers:?}");
    }

    #[test]
    fn file_identity_store_rejects_corrupted_json() {
        let temp_dir = TestDir::new("rejects-corrupted-json");
        let store = FileTzapLocalIdentityStore::new(temp_dir.path(""));
        let legacy_path = store.inventory_path(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();

        fs::write(&legacy_path, b"{ corrupted_json: ").unwrap();

        let error = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap_err();
        assert!(matches!(error, TzapLocalIdentityStoreError::Json(_)));
    }

    #[test]
    fn legacy_contacts_without_verification_state_are_not_claimed_verified() {
        let base = json!({
            "contact_id": "contact-1",
            "display_name": "Legacy Contact",
            "signing_certificate_sha256": "a".repeat(64),
            "recipient_public_key_fingerprint": "b".repeat(64),
            "trust_anchor_type": "official_tzap",
            "missing_status_caveat": false,
            "contact_card_payload": "payload",
            "accepted_at_unix_seconds": 100,
        });

        // A legacy record with no verification_state field at all must not
        // be treated as cryptographically verified offline.
        let legacy = super::contact_from_json(&base).unwrap();
        assert_eq!(legacy.verification_state, trust::TzapVerificationState::NotRecorded);

        // An explicitly recorded state still parses as before.
        let mut recorded = base.clone();
        recorded["verification_state"] = json!("cryptographically_intact_offline");
        let contact = super::contact_from_json(&recorded).unwrap();
        assert_eq!(contact.verification_state, trust::TzapVerificationState::CryptographicallyIntactOffline);
    }

    #[test]
    fn identity_inventory_rejects_duplicates() {
        let mut inventory = valid_inventory();
        inventory.device_signing_keys.push(inventory.device_signing_keys.first().expect("fixture has key").clone());

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
        inventory.recipient_encryption_keys[0].public_key_fingerprint = inventory.device_signing_keys[0].public_key_fingerprint.clone();

        assert!(matches!(
            inventory.validate(),
            Err(TzapLocalIdentityStoreError::InvalidField { field })
                if field == "recipient_encryption_keys.public_key_fingerprint"
        ));
    }

    #[test]
    fn identity_inventory_reports_active_retirement_routes() {
        let mut inventory = valid_inventory();
        inventory.enrolled_certificates.push(TzapEnrolledCertificateRecord {
            certificate_id: "cert-org-1".to_owned(),
            certificate_sha256: canonical_sha(0x09),
            issuer_certificate_sha256: canonical_sha(0x04),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "02ABCDEF".to_owned(),
            leaf_certificate_der: vec![0x30, 0x09],
            intermediate_chain_der: vec![vec![0x30, 0x05]],
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            renewal_grace_period_days: None,
            renewal_recommended_within_days: None,
            public_metadata: public_metadata(),
            sign_device_id: "org-sign-device-1".to_owned(),
            sign_device_routing: TzapSignDeviceRouting::Organization {
                org_id: "org_123".to_owned(),
                login_organization_device_id: "login-org-device-1".to_owned(),
            },
            signing_key_id: "device-key-1".to_owned(),
            state: TzapLocalCertificateState::Active,
        });
        inventory.enrolled_certificates.push(TzapEnrolledCertificateRecord {
            certificate_id: "cert-revoked-1".to_owned(),
            certificate_sha256: canonical_sha(0x0a),
            issuer_certificate_sha256: canonical_sha(0x04),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "03ABCDEF".to_owned(),
            leaf_certificate_der: vec![0x30, 0x0a],
            intermediate_chain_der: vec![vec![0x30, 0x05]],
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            renewal_grace_period_days: None,
            renewal_recommended_within_days: None,
            public_metadata: public_metadata(),
            sign_device_id: "revoked-device".to_owned(),
            sign_device_routing: TzapSignDeviceRouting::Personal,
            signing_key_id: "device-key-1".to_owned(),
            state: TzapLocalCertificateState::Revoked,
        });

        assert_eq!(inventory.active_personal_sign_device_ids(), vec!["sign-device-1"]);
        let organization_routes = inventory.active_organization_device_retirements();
        assert_eq!(organization_routes.len(), 1);
        assert_eq!(organization_routes[0].org_id, "org_123");
        assert_eq!(organization_routes[0].login_organization_device_id, "login-org-device-1");
        assert_eq!(organization_routes[0].sign_device_id, "org-sign-device-1");
    }

    fn valid_inventory() -> TzapLocalIdentityInventory {
        // The store now persists through the identity catalog, which verifies
        // private keys against their fingerprints on write, so the fixture
        // needs real generated keys.
        let signing_key = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();
        TzapLocalIdentityInventory {
            device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: signing_key.public_key_fingerprint,
                private_key_der: signing_key.private_key_der,
                created_at_unix_seconds: 100,
                label: Some("MacBook".to_owned()),
            }],
            recipient_encryption_keys: vec![TzapRecipientEncryptionKeyRecord {
                key_id: "recipient-key-1".to_owned(),
                algorithm: crate::device_identity::RECIPIENT_ENCRYPTION_KEY_ALGORITHM.to_owned(),
                public_key_fingerprint: recipient_key.public_key_fingerprint,
                public_key_der: recipient_key.public_key_spki_der.clone(),
                private_key_der: recipient_key.private_key_der,
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
                renewal_grace_period_days: None,
                renewal_recommended_within_days: None,
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
                source: String::new(),
                verification_state: trust::TzapVerificationState::CryptographicallyIntactOffline,
                missing_status_caveat: true,
                contact_card_payload: json!({
                    "version": 1,
                    "recipient_public_key": URL_SAFE_NO_PAD.encode(recipient_key.public_key_spki_der.clone()),
                }),
                accepted_at_unix_seconds: 130,
                local_alias: Some("Ada -- work phone".to_owned()),
                card: None,
            }],
            removed_contacts: Vec::new(),
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
}
