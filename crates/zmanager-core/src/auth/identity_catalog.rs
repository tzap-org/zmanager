//! Public TZAP identity catalog and purpose-specific secret-store seams.
//!
//! The legacy [`crate::local_identity_store`] remains available for migration
//! and compatibility. New readers should use this module so public metadata
//! never requires hydrating private key bytes.

use crate::contact_snapshot::TzapContactTombstone;
pub use crate::identity_migration::{FileTzapSecretMaterialStore, load_inventory_from_catalog, store_inventory_as_catalog};
pub use crate::identity_migration::{PendingMutation, TzapLegacyMigrationReport, migrate_legacy_inventory};
use crate::local_identity_store::{TzapLocalIdentityStoreError, TzapSignDeviceRouting};
use crate::secrets::SecretBytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const PUBLIC_CATALOG_SCHEMA_VERSION: u64 = 1;
pub const PUBLIC_CATALOG_FILE_SUFFIX: &str = ".identity-catalog.json";

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TzapSecretRef(String);

impl TzapSecretRef {
    /// Creates a new non-discoverable reference for secure-store material.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 24];
        rand::rng().fill_bytes(&mut bytes);
        Self(format!("secret_{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, TzapSecretStoreError> {
        let value = value.into();
        if value.starts_with("secret_") && value.len() > "secret_".len() { Ok(Self(value)) } else { Err(TzapSecretStoreError::InvalidReference) }
    }
}

impl fmt::Display for TzapSecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapSecretPurpose {
    SigningKey,
    RecipientKey,
    Session,
}

impl TzapSecretPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SigningKey => "signing_key",
            Self::RecipientKey => "recipient_key",
            Self::Session => "session",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapSecretStoreError {
    Unavailable,
    Locked,
    Denied,
    Corrupt,
    Missing { reference: TzapSecretRef },
    InvalidReference,
}

impl fmt::Display for TzapSecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("secure secret store is unavailable"),
            Self::Locked => f.write_str("secure secret store is locked"),
            Self::Denied => f.write_str("secure secret store access was denied"),
            Self::Corrupt => f.write_str("secure secret store data is corrupt"),
            Self::Missing { reference } => write!(f, "secure secret is missing: {reference}"),
            Self::InvalidReference => f.write_str("secure secret reference is invalid"),
        }
    }
}

impl std::error::Error for TzapSecretStoreError {}

/// Purpose-specific secure material interface. Implementations must not fall
/// back to a plaintext file when the native store is unavailable or locked.
pub trait TzapSecretMaterialStore {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes) -> Result<TzapSecretRef, TzapSecretStoreError>;

    /// Stores material under a caller-generated reference. This is used by
    /// crash-recoverable catalog transactions: the public catalog can record
    /// the opaque reference before the secret is written, then retry the same
    /// write after an interrupted startup.
    fn put_at(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef, material: SecretBytes) -> Result<(), TzapSecretStoreError>;

    fn resolve(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<SecretBytes, TzapSecretStoreError>;

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError>;
}

#[derive(Debug, Default)]
pub struct InMemoryTzapSecretMaterialStore {
    values: HashMap<(TzapSecretPurpose, TzapSecretRef), SecretBytes>,
}

impl InMemoryTzapSecretMaterialStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapSecretMaterialStore for InMemoryTzapSecretMaterialStore {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes) -> Result<TzapSecretRef, TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let reference = TzapSecretRef::generate();
        self.values.insert((purpose, reference.clone()), material);
        Ok(reference)
    }

    fn put_at(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef, material: SecretBytes) -> Result<(), TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        self.values.insert((purpose, reference.clone()), material);
        Ok(())
    }

    fn resolve(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<SecretBytes, TzapSecretStoreError> {
        self.values.get(&(purpose, reference.clone())).cloned().ok_or_else(|| TzapSecretStoreError::Missing { reference: reference.clone() })
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        self.values.remove(&(purpose, reference.clone())).map(|_| ()).ok_or_else(|| TzapSecretStoreError::Missing { reference: reference.clone() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicSigningIdentityRecord {
    pub id: String,
    pub local_alias: Option<String>,
    pub certificate_id: Option<String>,
    pub certificate_sha256: Option<String>,
    pub issuer_certificate_sha256: Option<String>,
    pub issuer_key_identifier: Option<String>,
    pub serial_number: Option<String>,
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub not_before_unix_seconds: Option<u64>,
    pub not_after_unix_seconds: Option<u64>,
    /// S1 (mobile-tzap-archive-signing-tracker.md). Absent on catalogs written
    /// before this field existed.
    #[serde(default)]
    pub renewal_grace_period_days: Option<u64>,
    /// S1. Absent on catalogs written before this field existed.
    #[serde(default)]
    pub renewal_recommended_within_days: Option<u64>,
    pub public_signer_id: Option<String>,
    pub public_org_id: Option<String>,
    pub public_device_id: Option<String>,
    pub assurance_level: Option<String>,
    pub sign_device_id: Option<String>,
    /// Sign-device routing carried through from the legacy inventory so the
    /// legacy facade can round-trip it losslessly. Absent on catalogs written
    /// before this field existed.
    #[serde(default)]
    pub sign_device_routing: Option<TzapSignDeviceRouting>,
    /// Creation time of the underlying signing key, carried from the legacy
    /// inventory for the same reason.
    #[serde(default)]
    pub signing_key_created_at_unix_seconds: Option<u64>,
    /// Legacy inventory key id backing this identity, when it came from the
    /// legacy store. Lets the legacy facade reuse the same secret reference
    /// across saves instead of churning refs. Absent on catalogs written
    /// before this field existed.
    #[serde(default)]
    pub legacy_key_id: Option<String>,
    /// Public-metadata fields the legacy inventory carries that the catalog
    /// does not otherwise model; carried for lossless facade round-trips.
    #[serde(default)]
    pub metadata_version: Option<u64>,
    #[serde(default)]
    pub policy_oid: Option<String>,
    pub signing_key_ref: TzapSecretRef,
    pub lifecycle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicRecipientKeyRecord {
    pub id: String,
    pub local_label: Option<String>,
    pub algorithm: String,
    pub public_key_der: Vec<u8>,
    pub fingerprint: String,
    pub private_key_ref: TzapSecretRef,
    pub lifecycle: String,
    pub created_at_unix_seconds: u64,
    pub retired_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicContactRecord {
    pub contact_id: String,
    pub display_name: String,
    pub signing_certificate_sha256: String,
    pub recipient_public_key_fingerprint: String,
    pub recipient_public_key_der: Vec<u8>,
    pub trust_source: String,
    pub verification_state: String,
    pub missing_status_caveat: bool,
    pub contact_card_payload: Value,
    pub accepted_at_unix_seconds: u64,
    /// See [`crate::local_identity_store::TzapContactRecord::local_alias`].
    #[serde(default)]
    pub local_alias: Option<String>,
    /// See [`crate::local_identity_store::TzapContactRecord::card`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicStatusCacheRecord {
    pub lookup_id: String,
    pub status: String,
    pub this_update: String,
    pub next_update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct TzapPublicEmergencyBlocklist {
    pub blocked_root_sha256: Vec<String>,
    pub blocked_issuer_sha256: Vec<String>,
    pub updated_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TzapIdentityCatalog {
    pub schema_version: u64,
    pub catalog_id: String,
    pub revision: u64,
    pub default_signing_identity_id: Option<String>,
    pub signing_identities: Vec<TzapPublicSigningIdentityRecord>,
    pub recipient_keys: Vec<TzapPublicRecipientKeyRecord>,
    pub contacts: Vec<TzapPublicContactRecord>,
    /// See [`crate::local_identity_store::TzapLocalIdentityInventory::removed_contacts`].
    #[serde(default)]
    pub removed_contacts: Vec<TzapContactTombstone>,
    pub status_cache: Vec<TzapPublicStatusCacheRecord>,
    pub emergency_blocklist: TzapPublicEmergencyBlocklist,
    pub pending_mutations: Vec<PendingMutation>,
}

impl TzapIdentityCatalog {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: PUBLIC_CATALOG_SCHEMA_VERSION,
            catalog_id: format!("catalog_{}", random_identifier()),
            revision: 0,
            default_signing_identity_id: None,
            signing_identities: Vec::new(),
            recipient_keys: Vec::new(),
            contacts: Vec::new(),
            removed_contacts: Vec::new(),
            status_cache: Vec::new(),
            emergency_blocklist: TzapPublicEmergencyBlocklist::default(),
            pending_mutations: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TzapIdentityCatalogError> {
        if self.schema_version != PUBLIC_CATALOG_SCHEMA_VERSION {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "schema_version" });
        }
        if self.catalog_id.is_empty() {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "catalog_id" });
        }
        validate_unique("signing_identities.id", self.signing_identities.iter().map(|v| v.id.as_str()))?;
        validate_unique("recipient_keys.id", self.recipient_keys.iter().map(|v| v.id.as_str()))?;
        validate_unique("contacts.contact_id", self.contacts.iter().map(|v| v.contact_id.as_str()))?;
        if let Some(default_id) = &self.default_signing_identity_id
            && !self.signing_identities.iter().any(|record| &record.id == default_id)
        {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field: "default_signing_identity_id" });
        }
        for record in &self.signing_identities {
            validate_non_empty("signing_identities.id", &record.id)?;
            validate_non_empty("signing_identities.signing_key_ref", record.signing_key_ref.as_str())?;
            validate_non_empty("signing_identities.lifecycle", &record.lifecycle)?;
        }
        for record in &self.recipient_keys {
            validate_non_empty("recipient_keys.id", &record.id)?;
            validate_non_empty("recipient_keys.algorithm", &record.algorithm)?;
            validate_non_empty("recipient_keys.fingerprint", &record.fingerprint)?;
            validate_non_empty("recipient_keys.private_key_ref", record.private_key_ref.as_str())?;
            if record.public_key_der.is_empty() {
                return Err(TzapIdentityCatalogError::InvalidCatalog { field: "recipient_keys.public_key_der" });
            }
        }
        Ok(())
    }
}

pub trait TzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError>;
    fn save_catalog(&mut self, account_key: &str, expected_revision: Option<u64>, catalog: TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError>;
    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError>;
}

#[derive(Debug, Default)]
pub struct InMemoryTzapIdentityCatalogStore {
    catalogs: HashMap<String, TzapIdentityCatalog>,
}

impl InMemoryTzapIdentityCatalogStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapIdentityCatalogStore for InMemoryTzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError> {
        Ok(self.catalogs.get(account_key).cloned())
    }

    fn save_catalog(&mut self, account_key: &str, expected_revision: Option<u64>, catalog: TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError> {
        catalog.validate()?;
        let actual = self.catalogs.get(account_key).map(|value| value.revision);
        if expected_revision != actual {
            return Err(TzapIdentityCatalogError::RevisionConflict { expected: expected_revision, actual });
        }
        self.catalogs.insert(account_key.to_owned(), catalog);
        Ok(())
    }

    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError> {
        self.catalogs.remove(account_key);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileTzapIdentityCatalogStore {
    root: PathBuf,
}

impl FileTzapIdentityCatalogStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn catalog_path(&self, account_key: &str) -> Result<PathBuf, TzapIdentityCatalogError> {
        if !validate_account_key(account_key) {
            return Err(TzapIdentityCatalogError::InvalidAccountKey);
        }
        Ok(self.root.join(format!("{account_key}{PUBLIC_CATALOG_FILE_SUFFIX}")))
    }
}

/// A catalog lock older than this is assumed to have been abandoned by a
/// crashed writer and is stolen instead of blocking all future saves.
const LOCK_STALE_AFTER_SECONDS: u64 = 30;
/// Maximum stale-lock steal attempts before reporting a concurrent write.
const MAX_LOCK_STEAL_ATTEMPTS: u32 = 3;

/// Acquires the exclusive catalog lock, returning the held file handle.
///
/// A lock left behind by a crashed writer (which never removed it) would
/// otherwise fail every future save with [`TzapIdentityCatalogError::ConcurrentWrite`]
/// forever. When the existing lock is older than [`LOCK_STALE_AFTER_SECONDS`]
/// it is stolen and the acquisition retried; a lock that young is assumed to
/// belong to a live writer, and the write is refused.
fn acquire_catalog_lock(lock_path: &Path) -> Result<fs::File, TzapIdentityCatalogError> {
    let mut steal_attempts = 0u32;
    loop {
        match fs::OpenOptions::new().write(true).create_new(true).open(lock_path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if steal_attempts >= MAX_LOCK_STEAL_ATTEMPTS || !lock_is_stale(lock_path) {
                    return Err(TzapIdentityCatalogError::ConcurrentWrite);
                }
                let _ = fs::remove_file(lock_path);
                steal_attempts += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn lock_is_stale(lock_path: &Path) -> bool {
    fs::metadata(lock_path).is_ok_and(|metadata| {
        metadata.modified().is_ok_and(|modified| SystemTime::now().duration_since(modified).is_ok_and(|age| age.as_secs() >= LOCK_STALE_AFTER_SECONDS))
    })
}

impl TzapIdentityCatalogStore for FileTzapIdentityCatalogStore {
    fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let catalog: TzapIdentityCatalog = serde_json::from_slice(&bytes)?;
        catalog.validate()?;
        Ok(Some(catalog))
    }

    fn save_catalog(&mut self, account_key: &str, expected_revision: Option<u64>, catalog: TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        catalog.validate()?;
        fs::create_dir_all(&self.root)?;
        let lock_path = path.with_extension("lock");
        let _lock = acquire_catalog_lock(&lock_path)?;
        // Check the revision while the lock is held so no writer can commit
        // between validation and the atomic replacement below.
        let actual = self.load_catalog(account_key)?.map(|value| value.revision);
        if expected_revision != actual {
            let _ = fs::remove_file(&lock_path);
            return Err(TzapIdentityCatalogError::RevisionConflict { expected: expected_revision, actual });
        }
        let result = write_catalog_atomically(&path, &catalog);
        let _ = fs::remove_file(lock_path);
        result
    }

    fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError> {
        let path = self.catalog_path(account_key)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug)]
pub enum TzapIdentityCatalogError {
    InvalidAccountKey,
    InvalidCatalog { field: &'static str },
    RevisionConflict { expected: Option<u64>, actual: Option<u64> },
    ConcurrentWrite,
    Io(io::ErrorKind),
    Json(String),
    Legacy(TzapLocalIdentityStoreError),
    Secret(TzapSecretStoreError),
}

impl fmt::Display for TzapIdentityCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccountKey => f.write_str("identity catalog account key is invalid"),
            Self::InvalidCatalog { field } => {
                write!(f, "identity catalog field is invalid: {field}")
            }
            Self::RevisionConflict { expected, actual } => {
                write!(f, "identity catalog revision conflict (expected {expected:?}, actual {actual:?})")
            }
            Self::ConcurrentWrite => f.write_str("identity catalog is already being updated"),
            Self::Io(kind) => write!(f, "identity catalog I/O failed: {kind:?}"),
            Self::Json(message) => write!(f, "identity catalog JSON is invalid: {message}"),
            Self::Legacy(error) => write!(f, "legacy identity migration failed: {error}"),
            Self::Secret(error) => write!(f, "secure secret migration failed: {error}"),
        }
    }
}

impl std::error::Error for TzapIdentityCatalogError {}

impl From<io::Error> for TzapIdentityCatalogError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<serde_json::Error> for TzapIdentityCatalogError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<TzapLocalIdentityStoreError> for TzapIdentityCatalogError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Legacy(error)
    }
}

impl From<TzapSecretStoreError> for TzapIdentityCatalogError {
    fn from(error: TzapSecretStoreError) -> Self {
        Self::Secret(error)
    }
}

fn write_catalog_atomically(path: &Path, catalog: &TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError> {
    let bytes = serde_json::to_vec_pretty(catalog)?;
    // CR-087: the previous writer opened a `tmp-{pid}` sibling with
    // `create(true).truncate(true)`, so concurrent saves (or stale files from
    // a crashed run with the same pid) could clobber each other. The shared
    // atomic writer allocates a unique `create_new` sibling and renames over
    // the destination without ever removing it first, so a crash leaves the
    // old or the new catalog — never neither.
    let mut output = crate::atomic_file::AtomicOutputFile::create(path).map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        output
            .file_mut()
            .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?;
    }
    output
        .file_mut()
        .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?
        .write_all(&bytes)
        .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?;
    output
        .file_mut()
        .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?
        .sync_all()
        .map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?;
    output.commit_with_atomic_replace().map_err(|source| TzapIdentityCatalogError::Io(source.kind()))?;
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(path.parent().unwrap_or_else(|| Path::new("."))) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn random_identifier() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validates an identity account key under the shared catalog rule.
///
/// Account keys are used as file names, so path separators and parent
/// traversal markers are rejected. This is deliberately conservative:
/// accepting a wider alphabet (spaces, dots) is fine as long as the key
/// cannot escape its directory. [`crate::local_identity_store`] uses the
/// same rule so both stores accept the same account keys.
#[must_use]
pub(crate) fn validate_account_key(value: &str) -> bool {
    !value.is_empty() && !value.contains('/') && !value.contains('\\') && !value.contains("..")
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), TzapIdentityCatalogError> {
    if value.is_empty() { Err(TzapIdentityCatalogError::InvalidCatalog { field }) } else { Ok(()) }
}

fn validate_unique<'a>(field: &'static str, values: impl Iterator<Item = &'a str>) -> Result<(), TzapIdentityCatalogError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(TzapIdentityCatalogError::InvalidCatalog { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr, generate_recipient_encryption_key};
    use crate::local_identity_store::{
        InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn empty_catalog_is_public_and_has_no_secret_fields() {
        let catalog = TzapIdentityCatalog::empty();
        let json = serde_json::to_string(&catalog).unwrap();
        assert!(!json.contains("private_key_der"));
        assert!(!json.contains("session_token"));
        catalog.validate().unwrap();
    }

    #[test]
    fn catalog_store_enforces_revision_and_writes_owner_only_file() {
        let root = std::env::temp_dir().join(format!("tzap-catalog-{}", std::process::id()));
        let mut store = FileTzapIdentityCatalogStore::new(&root);
        let mut catalog = TzapIdentityCatalog::empty();
        catalog.revision = 1;
        store.save_catalog("default", None, catalog.clone()).unwrap();
        assert!(matches!(store.save_catalog("default", None, catalog.clone()), Err(TzapIdentityCatalogError::RevisionConflict { .. })));
        let mut next = catalog.clone();
        next.revision = 2;
        store.save_catalog("default", Some(1), next.clone()).expect("an existing catalog can be replaced under its locked revision");
        assert_eq!(store.load_catalog("default").unwrap(), Some(next));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let path = root.join(format!("default{PUBLIC_CATALOG_FILE_SUFFIX}"));
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn catalog_store_refuses_concurrent_writes_but_steals_stale_locks() {
        let root = std::env::temp_dir().join(format!("tzap-catalog-lock-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut store = FileTzapIdentityCatalogStore::new(&root);
        let mut catalog = TzapIdentityCatalog::empty();
        catalog.revision = 1;
        let lock_path = root.join(format!("default{PUBLIC_CATALOG_FILE_SUFFIX}")).with_extension("lock");

        // A fresh lock belongs to a live writer: the save must be refused.
        fs::write(&lock_path, b"").unwrap();
        assert!(matches!(store.save_catalog("default", None, catalog.clone()), Err(TzapIdentityCatalogError::ConcurrentWrite)));

        // A lock abandoned by a crashed writer must not block saves forever:
        // once it is old enough it is stolen and the save succeeds.
        let lock = fs::File::options().write(true).open(&lock_path).unwrap();
        let age = std::time::Duration::from_secs(LOCK_STALE_AFTER_SECONDS + 60);
        lock.set_modified(SystemTime::now() - age).unwrap();
        drop(lock);
        store.save_catalog("default", None, catalog.clone()).expect("a stale lock should be stolen instead of blocking the save");
        assert!(!lock_path.exists(), "the stolen lock should have been removed");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migration_moves_private_material_and_is_idempotent() {
        let signing = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient = generate_recipient_encryption_key().unwrap();
        let mut legacy = InMemoryTzapLocalIdentityStore::new();
        legacy
            .save_inventory(
                "default",
                TzapLocalIdentityInventory {
                    device_signing_keys: vec![TzapDeviceSigningKeyRecord {
                        key_id: "signing-1".to_owned(),
                        public_key_fingerprint: signing.public_key_fingerprint.clone(),
                        private_key_der: signing.private_key_der.clone(),
                        created_at_unix_seconds: 1,
                        label: Some("Laptop".to_owned()),
                    }],
                    recipient_encryption_keys: vec![TzapRecipientEncryptionKeyRecord {
                        key_id: "recipient-1".to_owned(),
                        algorithm: recipient.algorithm.to_owned(),
                        public_key_fingerprint: recipient.public_key_fingerprint.clone(),
                        public_key_der: recipient.public_key_spki_der.clone(),
                        private_key_der: recipient.private_key_der.clone(),
                        created_at_unix_seconds: 2,
                        label: None,
                    }],
                    ..TzapLocalIdentityInventory::empty()
                },
            )
            .unwrap();
        let mut catalogs = InMemoryTzapIdentityCatalogStore::new();
        let mut secrets = InMemoryTzapSecretMaterialStore::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let report = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(report.migrated);
        assert_eq!(report.signing_identity_count, 1);
        assert_eq!(report.recipient_key_count, 1);
        let second = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(!second.migrated);
        let catalog = catalogs.load_catalog("default").unwrap().unwrap();
        assert!(!serde_json::to_string(&catalog).unwrap().contains("private_key_der"));
        let signing_ref = catalog.signing_identities[0].signing_key_ref.clone();
        let recipient_ref = catalog.recipient_keys[0].private_key_ref.clone();
        secrets.delete(TzapSecretPurpose::SigningKey, &signing_ref).unwrap();
        secrets.delete(TzapSecretPurpose::RecipientKey, &recipient_ref).unwrap();
        let mut interrupted = catalog.clone();
        interrupted.pending_mutations.push(PendingMutation::LegacyMigration { started_at_unix_seconds: 1 });
        let expected_revision = interrupted.revision;
        interrupted.revision += 1;
        catalogs.save_catalog("default", Some(expected_revision), interrupted).unwrap();
        let recovered = migrate_legacy_inventory(&legacy, &mut catalogs, &mut secrets, "default", now).unwrap();
        assert!(recovered.migrated);
        assert!(secrets.resolve(TzapSecretPurpose::SigningKey, &signing_ref).is_ok());
        assert!(secrets.resolve(TzapSecretPurpose::RecipientKey, &recipient_ref).is_ok());
        assert!(catalogs.load_catalog("default").unwrap().unwrap().pending_mutations.is_empty());
    }
}
