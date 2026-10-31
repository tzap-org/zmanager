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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalIdentityInventory {
    pub device_signing_keys: Vec<TzapDeviceSigningKeyRecord>,
    pub recipient_encryption_keys: Vec<TzapRecipientEncryptionKeyRecord>,
    pub enrolled_certificates: Vec<TzapEnrolledCertificateRecord>,
    pub certificate_status_cache: Vec<TzapCertificateStatusCacheRecord>,
    pub emergency_blocklist: TzapEmergencyBlocklistState,
    pub contacts: Vec<TzapContactRecord>,
    /// Public journal entries for certificate requests whose result may have
    /// reached the server without being committed to the local inventory.
    pub pending_certificate_operations: Vec<TzapPendingCertificateOperation>,
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
            pending_certificate_operations: Vec::new(),
            removed_contacts: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        validate_unique("device_signing_keys.key_id", self.device_signing_keys.iter().map(|record| record.key_id.as_str()))?;
        validate_unique("recipient_encryption_keys.key_id", self.recipient_encryption_keys.iter().map(|record| record.key_id.as_str()))?;
        validate_unique("enrolled_certificates.certificate_sha256", self.enrolled_certificates.iter().map(|record| record.certificate_sha256.as_str()))?;
        validate_unique("contacts.contact_id", self.contacts.iter().map(|record| record.contact_id.as_str()))?;
        validate_unique("pending_certificate_operations.operation_id", self.pending_certificate_operations.iter().map(|record| record.operation_id.as_str()))?;
        validate_unique(
            "pending_certificate_operations.signing_key_id",
            self.pending_certificate_operations.iter().map(|record| record.signing_key_id.as_str()),
        )?;

        for record in &self.device_signing_keys {
            validate_non_empty_id("device_signing_keys.key_id", &record.key_id)?;
            validate_sha256("device_signing_keys.public_key_fingerprint", &record.public_key_fingerprint)?;
            validate_secret_bytes("device_signing_keys.private_key_der", &record.private_key_der)?;
            if let Some(binding) = &record.hosted_binding {
                binding.validate()?;
            }
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
        for operation in &self.pending_certificate_operations {
            operation.validate(self)?;
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
    /// Authenticated hosted ownership for an online device key. Labels are
    /// display metadata and must never choose which hosted identity is reused.
    pub hosted_binding: Option<TzapHostedDeviceBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TzapCertificateOperationKind {
    Enrollment,
    Renewal,
}

/// Restart-safe, non-secret intent for a server certificate issuance.
///
/// A request may be accepted by the server even if the response or the local
/// catalog commit is lost. Keeping this marker beside the key lets the next
/// login reconcile against the authenticated server inventory before retrying.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPendingCertificateOperation {
    pub operation_id: String,
    pub kind: TzapCertificateOperationKind,
    pub signing_key_id: String,
    pub public_key_fingerprint: String,
    pub csr_sha256: String,
    /// The public CSR is retained so restart recovery can reuse the exact
    /// request bytes. Re-signing a CSR with the same ECDSA key may produce a
    /// different signature and therefore a different CSR digest.
    #[serde(default)]
    pub csr_der: Option<Vec<u8>>,
    pub org_id: Option<String>,
    pub requested_validity_seconds: u64,
    pub created_at_unix_seconds: u64,
    #[serde(default)]
    pub previous_signing_key_id: Option<String>,
    #[serde(default)]
    pub renewal_policy: Option<String>,
    #[serde(default)]
    pub predecessor_certificate_id: Option<String>,
    #[serde(default)]
    pub predecessor_certificate_sha256: Option<String>,
}

impl TzapPendingCertificateOperation {
    fn validate(&self, inventory: &TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError> {
        validate_non_empty_id("pending_certificate_operations.operation_id", &self.operation_id)?;
        validate_non_empty_id("pending_certificate_operations.signing_key_id", &self.signing_key_id)?;
        validate_sha256("pending_certificate_operations.public_key_fingerprint", &self.public_key_fingerprint)?;
        validate_sha256("pending_certificate_operations.csr_sha256", &self.csr_sha256)?;
        if let Some(csr_der) = &self.csr_der {
            if csr_der.is_empty() || csr_der.len() > 16 * 1024 || crate::device_identity::csr_fingerprint(csr_der) != self.csr_sha256 {
                return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.csr_der" });
            }
        }
        if self.requested_validity_seconds == 0 {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.requested_validity_seconds" });
        }
        let key = inventory.device_signing_keys.iter().find(|key| key.key_id == self.signing_key_id);
        if key.is_none_or(|key| key.public_key_fingerprint != self.public_key_fingerprint) {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.signing_key" });
        }
        match &self.kind {
            TzapCertificateOperationKind::Enrollment => {
                if self.previous_signing_key_id.is_some()
                    || self.renewal_policy.is_some()
                    || self.predecessor_certificate_id.is_some()
                    || self.predecessor_certificate_sha256.is_some()
                {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.predecessor" });
                }
                if inventory
                    .enrolled_certificates
                    .iter()
                    .any(|certificate| certificate.signing_key_id == self.signing_key_id && certificate.state == TzapLocalCertificateState::Active)
                {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.enrollment_key" });
                }
            }
            TzapCertificateOperationKind::Renewal => {
                let Some(previous_signing_key_id) = self.previous_signing_key_id.as_ref() else {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.previous_signing_key" });
                };
                if !inventory.device_signing_keys.iter().any(|key| key.key_id == *previous_signing_key_id)
                    || !matches!(self.renewal_policy.as_deref(), Some("same_key_required" | "key_rotation_allowed"))
                {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.renewal_policy" });
                }
                let Some((certificate_id, certificate_sha256)) = self.predecessor_certificate_id.as_ref().zip(self.predecessor_certificate_sha256.as_ref())
                else {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.predecessor" });
                };
                if !inventory.enrolled_certificates.iter().any(|certificate| {
                    certificate.certificate_id == *certificate_id
                        && certificate.certificate_sha256 == *certificate_sha256
                        && certificate.signing_key_id == *previous_signing_key_id
                        && certificate.state == TzapLocalCertificateState::RenewalPending
                }) {
                    return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.predecessor" });
                }
            }
        }
        if self.org_id.as_ref().is_some_and(String::is_empty) {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "pending_certificate_operations.org_id" });
        }
        Ok(())
    }
}

/// Non-secret ownership/routing metadata bound to a hosted device key. The
/// key itself remains in the OS secret store. A missing binding makes a key
/// ineligible for hosted provisioning.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub struct TzapHostedDeviceBinding {
    pub owner_user_id: String,
    pub environment: String,
    pub auth_origin: String,
    pub signing_origin: String,
    pub org_id: Option<String>,
    /// Server-issued device identity, absent until the first validated
    /// certificate is received and persisted.
    #[serde(default)]
    pub sign_device_id: Option<String>,
    #[serde(default)]
    pub public_device_id: Option<String>,
    /// Signature over the binding, produced by the bound device key. This
    /// detects edits to public catalog metadata during hydration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_signature: Option<String>,
}

impl TzapHostedDeviceBinding {
    pub fn validate(&self) -> Result<(), TzapLocalIdentityStoreError> {
        let valid_id =
            |value: &str| !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte));
        if !valid_id(&self.owner_user_id) {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.owner_user_id" });
        }
        let expected = match self.environment.as_str() {
            "staging" => ("https://staging.tzap.org", "https://staging.tzap.org"),
            "prod" => ("https://login.tzap.org", "https://sign.tzap.org"),
            _ => return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.environment" }),
        };
        if self.auth_origin != expected.0 || self.signing_origin != expected.1 {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.origins" });
        }
        if self.org_id.as_deref().is_some_and(|value| !valid_id(value)) {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.org_id" });
        }
        if self.sign_device_id.as_deref().is_some_and(|value| !valid_id(value))
            || self.public_device_id.as_deref().is_some_and(|value| !is_valid_public_device_id(value))
            || self.sign_device_id.is_some() != self.public_device_id.is_some()
        {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.device_id" });
        }
        if self
            .binding_signature
            .as_deref()
            .is_some_and(|value| URL_SAFE_NO_PAD.decode(value).map_or(true, |signature| signature.is_empty() || URL_SAFE_NO_PAD.encode(signature) != value))
        {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.binding_signature" });
        }
        Ok(())
    }

    #[must_use]
    pub fn same_scope(&self, other: &Self) -> bool {
        self.owner_user_id == other.owner_user_id
            && self.environment == other.environment
            && self.auth_origin == other.auth_origin
            && self.signing_origin == other.signing_origin
            && self.org_id == other.org_id
    }

    pub fn bind_device(&mut self, sign_device_id: &str, public_device_id: &str) -> Result<(), TzapLocalIdentityStoreError> {
        let mut candidate = self.clone();
        candidate.sign_device_id = Some(sign_device_id.to_owned());
        candidate.public_device_id = Some(public_device_id.to_owned());
        candidate.validate()?;
        if (self.sign_device_id.is_some() || self.public_device_id.is_some())
            && (self.sign_device_id.as_deref() != Some(sign_device_id) || self.public_device_id.as_deref() != Some(public_device_id))
        {
            return Err(TzapLocalIdentityStoreError::InvalidField { field: "hosted_binding.device_id" });
        }
        *self = candidate;
        Ok(())
    }
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
    RenewalPending,
    Revoked,
    Suspended,
    Expired,
}

impl TzapLocalCertificateState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RenewalPending => "renewal_pending",
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "renewal_pending" => Some(Self::RenewalPending),
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
    /// `None` for a contact the importer has not renamed.
    pub local_alias: Option<String>,
    /// Original signed contact card container, retained for snapshot export
    /// and re-verification (design §8.3). `None` when the source card is not
    /// retained.
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

impl FileTzapLocalIdentityStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl TzapLocalIdentityStore for FileTzapLocalIdentityStore {
    fn load_inventory(&self, account_key: &str) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, FileTzapSecretMaterialStore, load_inventory_from_catalog};
        use crate::identity_write_journal::recover_file_inventory_writes;

        let catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        let mut secret_store = FileTzapSecretMaterialStore::new(&self.root, account_key);
        recover_file_inventory_writes(&catalog_store, &mut secret_store, account_key)?;
        Ok(load_inventory_from_catalog(&catalog_store, &secret_store, account_key)?.unwrap_or_else(TzapLocalIdentityInventory::empty))
    }

    fn save_inventory(&mut self, account_key: &str, inventory: TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, FileTzapSecretMaterialStore};
        use crate::identity_write_journal::store_file_inventory_as_catalog;

        inventory.validate()?;
        store_file_inventory_as_catalog(
            &mut FileTzapIdentityCatalogStore::new(&self.root),
            &mut FileTzapSecretMaterialStore::new(&self.root, account_key),
            account_key,
            &inventory,
        )?;
        Ok(())
    }

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        use crate::identity_catalog::{FileTzapIdentityCatalogStore, TzapIdentityCatalogStore as _};

        validate_account_key(account_key)?;
        let mut catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        catalog_store.clear_catalog(account_key)?;
        let secrets_root = self.root.join("secrets").join(account_key);
        match fs::remove_dir_all(&secrets_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
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
    /// The identity catalog (the facade's storage) rejected the operation.
    /// Boxed because the catalog error carries this error type in its
    /// `LocalStore` variant; an unboxed cycle would be infinitely sized.
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
            Self::Catalog(error) => write!(f, "identity catalog operation failed: {error}"),
        }
    }
}

impl std::error::Error for TzapLocalIdentityStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::InvalidField { .. } | Self::DuplicateRecord { .. } => None,
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

fn validate_account_key(account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
    // Shared with the identity catalog so both stores accept the same
    // account keys: non-empty and free of path separators and traversal
    // markers, but otherwise unrestricted.
    if crate::identity_catalog::validate_account_key(account_key) { Ok(()) } else { Err(TzapLocalIdentityStoreError::InvalidField { field: "account_key" }) }
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
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, FileTzapLocalIdentityStore, InMemoryTzapLocalIdentityStore, TzapCertificateOperationKind,
        TzapCertificateStatusCacheRecord, TzapContactRecord, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord,
        TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError, TzapPendingCertificateOperation,
        TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
    };
    use crate::device_identity::{
        TzapDeviceCsrOptions, ensure_recipient_key_is_distinct_from_signing_key, generate_device_csr_from_private_key, generate_device_signing_key_and_csr,
        generate_recipient_encryption_key,
    };
    use crate::secrets::SecretBytes;
    use crate::test_support::TestDir;
    use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    use std::fs;

    #[test]
    fn clearing_inventory_rejects_invalid_accounts_before_deleting_files() {
        let temp = TestDir::new("clear-invalid-account");
        temp.create_dir("store/secrets");
        let victim = temp.path("victim");
        let absolute_account = victim.to_str().unwrap();
        for account in [absolute_account, "../../victim"] {
            temp.write_file("victim/keep.txt", b"keep");
            let mut store = FileTzapLocalIdentityStore::new(temp.path("store"));

            assert!(store.clear_inventory(account).is_err());
            assert_eq!(fs::read(victim.join("keep.txt")).unwrap(), b"keep");
        }
    }

    #[test]
    fn in_memory_identity_store_round_trips_pending_certificate_operation() {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let mut inventory = valid_inventory();
        mark_pending_renewal(&mut inventory);
        assert!(inventory.active_personal_sign_device_ids().is_empty(), "a pending predecessor cannot be advertised as sign-ready");

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
                hosted_binding: None,
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
            pending_certificate_operations: Vec::new(),
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
        let mut inventory = valid_inventory();
        mark_pending_renewal(&mut inventory);

        // Saving twice (an overwrite) leaves a complete, loadable catalog and
        // no temporary sibling files behind.
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
        let private_key = openssl::pkey::PKey::private_key_from_der(signing_key.private_key_der.expose_secret()).unwrap();
        let issuer_key = crate::x509_fixture::p256_private_key();
        let issuer = crate::x509_fixture::root_certificate(&issuer_key);
        let leaf = crate::x509_fixture::leaf_certificate(&private_key, &issuer, &issuer_key, &issuer, Default::default()).to_der().unwrap();
        let issuer_der = issuer.to_der().unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();
        TzapLocalIdentityInventory {
            device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: signing_key.public_key_fingerprint,
                private_key_der: signing_key.private_key_der,
                created_at_unix_seconds: 100,
                label: Some("MacBook".to_owned()),
                hosted_binding: None,
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
                certificate_sha256: trust::sha256_identifier(&leaf),
                issuer_certificate_sha256: trust::sha256_identifier(&issuer_der),
                issuer_key_identifier: "AQIDBA".to_owned(),
                serial_number: "01ABCDEF".to_owned(),
                leaf_certificate_der: leaf.clone(),
                intermediate_chain_der: vec![issuer_der],
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
                certificate_sha256: trust::sha256_identifier(&leaf),
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
            pending_certificate_operations: Vec::new(),
            removed_contacts: Vec::new(),
        }
    }

    fn mark_pending_renewal(inventory: &mut TzapLocalIdentityInventory) {
        let predecessor = &mut inventory.enrolled_certificates[0];
        predecessor.state = TzapLocalCertificateState::RenewalPending;
        let predecessor_certificate_id = predecessor.certificate_id.clone();
        let predecessor_certificate_sha256 = predecessor.certificate_sha256.clone();
        let signing_key = &inventory.device_signing_keys[0];
        let csr_der = generate_device_csr_from_private_key(&signing_key.private_key_der, &TzapDeviceCsrOptions::default()).unwrap();
        inventory.pending_certificate_operations.push(TzapPendingCertificateOperation {
            operation_id: "operation_test".to_owned(),
            kind: TzapCertificateOperationKind::Renewal,
            signing_key_id: signing_key.key_id.clone(),
            public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
            csr_sha256: crate::device_identity::csr_fingerprint(&csr_der),
            csr_der: Some(csr_der),
            org_id: None,
            requested_validity_seconds: 86_400,
            created_at_unix_seconds: 150,
            previous_signing_key_id: Some(signing_key.key_id.clone()),
            renewal_policy: Some("same_key_required".to_owned()),
            predecessor_certificate_id: Some(predecessor_certificate_id),
            predecessor_certificate_sha256: Some(predecessor_certificate_sha256),
        });
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
