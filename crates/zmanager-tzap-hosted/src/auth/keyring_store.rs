//! Native OS keyring storage for the CLI's TZAP identity and session state.

use keyring::{Entry, Error as KeyringError};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use zmanager_core::identity_catalog::{
    FileTzapIdentityCatalogStore, FileTzapSecretMaterialStore, TzapIdentityCatalogStore, TzapSecretMaterialStore, TzapSecretPurpose, TzapSecretRef,
    TzapSecretStoreError, load_inventory_from_catalog, store_inventory_as_catalog,
};
use zmanager_core::local_identity_store::{
    FileTzapLocalIdentityStore, IDENTITY_INVENTORY_FILE_SUFFIX, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError,
};
use zmanager_core::secrets::SecretBytes;

use crate::auth_client::{TzapAuthError, TzapBearerToken, TzapSessionRecord, TzapSessionStore};
use crate::trust::TzapIdentityAssurance;

const SERVICE_NAME: &str = "org.tzap.zmanager.identity";
const SESSION_PURPOSE: &str = "session";

// Keychain access can trigger an OS authorization prompt. Keep secrets that
// this process has already retrieved in memory so one application session does
// not repeatedly ask the user to unlock the same Keychain item. Writes and
// deletes update this cache, so it cannot return stale values after a local
// mutation. The cache is process-local and is never persisted outside the OS
// keychain.
static SECRET_CACHE: OnceLock<Mutex<HashMap<String, SecretBytes>>> = OnceLock::new();

fn secret_cache() -> &'static Mutex<HashMap<String, SecretBytes>> {
    SECRET_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_secret(key: &str) -> Option<SecretBytes> {
    secret_cache().lock().ok()?.get(key).cloned()
}

fn cache_secret(key: String, secret: &SecretBytes) {
    if let Ok(mut cache) = secret_cache().lock() {
        cache.insert(key, secret.clone());
    }
}

fn invalidate_cached_secret(key: &str) {
    if let Ok(mut cache) = secret_cache().lock() {
        cache.remove(key);
    }
}

#[must_use]
pub(crate) fn pending_auth_reference() -> TzapSecretRef {
    TzapSecretRef::parse("secret_pending_auth").unwrap_or_else(|_| TzapSecretRef::generate())
}

/// Keyring-backed store shared by CLI identity and hosted-auth state.
/// `account_scope` is part of the keyring account name so separate local
/// identity accounts cannot overwrite one another.
#[derive(Debug, Clone)]
pub struct NativeTzapSecretStore {
    account_scope: String,
}

/// Public catalog plus OS-keyring private material facade used by the CLI and
/// the hosted JSON service when the `keyring` feature is enabled.
pub struct NativeTzapLocalIdentityStore {
    root: PathBuf,
    account_key: String,
}

impl NativeTzapLocalIdentityStore {
    pub fn new(root: impl Into<PathBuf>, account_key: &str) -> Result<Self, TzapLocalIdentityStoreError> {
        NativeTzapSecretStore::new(account_key)
            .map_err(|error| TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error))))?;
        let store = Self { root: root.into(), account_key: account_key.to_owned() };
        store.migrate_legacy_private_material()?;
        Ok(store)
    }

    fn migrate_legacy_private_material(&self) -> Result<(), TzapLocalIdentityStoreError> {
        let catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        if catalog_store.load_catalog(&self.account_key)?.is_none() {
            // Let the core migration convert the legacy inventory JSON into
            // the public catalog, retaining its stable secret references.
            let legacy_store = FileTzapLocalIdentityStore::new(&self.root);
            let _ = legacy_store.load_inventory(&self.account_key)?;
        }
        let Some(catalog) = catalog_store.load_catalog(&self.account_key)? else {
            return Ok(());
        };
        let legacy_store = FileTzapSecretMaterialStore::new(&self.root, &self.account_key);
        let mut secure_store = self.secret_store()?;
        for identity in &catalog.signing_identities {
            Self::copy_legacy_secret_if_needed(&mut secure_store, &legacy_store, TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
        }
        for key in &catalog.recipient_keys {
            Self::copy_legacy_secret_if_needed(&mut secure_store, &legacy_store, TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
        }
        let legacy_secret_root = self.root.join("secrets").join(&self.account_key);
        if legacy_secret_root.exists() {
            std::fs::remove_dir_all(legacy_secret_root)?;
        }
        let legacy_inventory = self.root.join(format!("{}{}", self.account_key, IDENTITY_INVENTORY_FILE_SUFFIX));
        match std::fs::remove_file(legacy_inventory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn copy_legacy_secret_if_needed(
        secure_store: &mut NativeTzapSecretStore,
        legacy_store: &FileTzapSecretMaterialStore,
        purpose: TzapSecretPurpose,
        reference: &TzapSecretRef,
    ) -> Result<(), TzapLocalIdentityStoreError> {
        match secure_store.resolve(purpose, reference) {
            Ok(_) => return Ok(()),
            Err(TzapSecretStoreError::Missing { .. }) => {}
            Err(error) => return Err(TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error)))),
        }
        let material = legacy_store
            .resolve(purpose, reference)
            .map_err(|error| TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error))))?;
        secure_store
            .put_at(purpose, reference, material)
            .map_err(|error| TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error))))
    }

    fn check_account_key(&self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        if account_key == self.account_key { Ok(()) } else { Err(TzapLocalIdentityStoreError::InvalidField { field: "account_key" }) }
    }

    fn secret_store(&self) -> Result<NativeTzapSecretStore, TzapLocalIdentityStoreError> {
        NativeTzapSecretStore::new(self.account_key.clone())
            .map_err(|error| TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error))))
    }
}

impl TzapLocalIdentityStore for NativeTzapLocalIdentityStore {
    fn load_inventory(&self, account_key: &str) -> Result<TzapLocalIdentityInventory, TzapLocalIdentityStoreError> {
        self.check_account_key(account_key)?;
        let catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        let secret_store = self.secret_store()?;
        Ok(load_inventory_from_catalog(&catalog_store, &secret_store, account_key)?.unwrap_or_else(TzapLocalIdentityInventory::empty))
    }

    fn save_inventory(&mut self, account_key: &str, inventory: TzapLocalIdentityInventory) -> Result<(), TzapLocalIdentityStoreError> {
        self.check_account_key(account_key)?;
        inventory.validate()?;
        let mut catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        let mut secret_store = self.secret_store()?;
        store_inventory_as_catalog(&mut catalog_store, &mut secret_store, account_key, &inventory, current_unix_seconds())?;
        Ok(())
    }

    fn clear_inventory(&mut self, account_key: &str) -> Result<(), TzapLocalIdentityStoreError> {
        self.check_account_key(account_key)?;
        let mut catalog_store = FileTzapIdentityCatalogStore::new(&self.root);
        if let Some(catalog) = catalog_store.load_catalog(account_key)? {
            let mut secret_store = self.secret_store()?;
            for identity in &catalog.signing_identities {
                secret_store.delete(TzapSecretPurpose::SigningKey, &identity.signing_key_ref).map_err(|error| {
                    TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error)))
                })?;
            }
            for key in &catalog.recipient_keys {
                secret_store.delete(TzapSecretPurpose::RecipientKey, &key.private_key_ref).map_err(|error| {
                    TzapLocalIdentityStoreError::Catalog(Box::new(zmanager_core::identity_catalog::TzapIdentityCatalogError::Secret(error)))
                })?;
            }
        }
        catalog_store.clear_catalog(account_key)?;
        Ok(())
    }
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

impl Default for NativeTzapSecretStore {
    fn default() -> Self {
        Self { account_scope: "default".to_owned() }
    }
}

impl NativeTzapSecretStore {
    pub fn new(account_scope: impl Into<String>) -> Result<Self, TzapSecretStoreError> {
        let account_scope = account_scope.into();
        if account_scope.is_empty()
            || account_scope.contains(':')
            || account_scope.contains('/')
            || account_scope.contains('\\')
            || account_scope.contains("..")
        {
            return Err(TzapSecretStoreError::InvalidReference);
        }
        Ok(Self { account_scope })
    }

    fn entry(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<Entry, TzapSecretStoreError> {
        TzapSecretRef::parse(reference.as_str().to_owned())?;
        Entry::new(SERVICE_NAME, &format!("{}:{}:{}", self.account_scope, purpose.as_str(), reference.as_str()))
            .map_err(|error| map_keyring_error(&error, reference))
    }

    fn session_entry(&self, account_key: &str) -> Result<Entry, TzapAuthError> {
        if account_key.is_empty() || account_key.contains(':') || account_key.contains('/') || account_key.contains('\\') || account_key.contains("..") {
            return Err(TzapAuthError::Storage { message: "invalid TZAP account key".to_owned() });
        }
        Entry::new(SERVICE_NAME, &format!("{}:{SESSION_PURPOSE}:{account_key}", self.account_scope))
            .map_err(|_| TzapAuthError::Storage { message: "keyring entry could not be created".to_owned() })
    }

    fn material_cache_key(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> String {
        format!("material:{}:{}:{}", self.account_scope, purpose.as_str(), reference.as_str())
    }

    fn session_cache_key(&self, account_key: &str) -> String {
        format!("session:{}:{account_key}", self.account_scope)
    }
}

impl TzapSecretMaterialStore for NativeTzapSecretStore {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes) -> Result<TzapSecretRef, TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let reference = TzapSecretRef::generate();
        self.entry(purpose, &reference)?.set_secret(material.expose_secret()).map_err(|error| map_keyring_error(&error, &reference))?;
        cache_secret(self.material_cache_key(purpose, &reference), &material);
        Ok(reference)
    }

    fn put_at(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef, material: SecretBytes) -> Result<(), TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        self.entry(purpose, reference)?.set_secret(material.expose_secret()).map_err(|error| map_keyring_error(&error, reference))?;
        cache_secret(self.material_cache_key(purpose, reference), &material);
        Ok(())
    }

    fn resolve(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<SecretBytes, TzapSecretStoreError> {
        let cache_key = self.material_cache_key(purpose, reference);
        if let Some(secret) = cached_secret(&cache_key) {
            return Ok(secret);
        }
        let secret = self.entry(purpose, reference)?.get_secret().map(SecretBytes::from).map_err(|error| map_keyring_error(&error, reference))?;
        cache_secret(cache_key, &secret);
        Ok(secret)
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        let cache_key = self.material_cache_key(purpose, reference);
        match self.entry(purpose, reference)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => {
                invalidate_cached_secret(&cache_key);
                Ok(())
            }
            Err(error) => Err(map_keyring_error(&error, reference)),
        }
    }
}

impl TzapSessionStore for NativeTzapSecretStore {
    fn save_session(&mut self, account_key: &str, session: TzapSessionRecord) -> Result<(), TzapAuthError> {
        let value = json!({
            "audience": session.audience,
            "access_token": session.access_token.expose(),
            "expires_at_unix_seconds": session.expires_at_unix_seconds,
            "identity_assurance": session.identity_assurance.as_str(),
            "selected_org_id": session.selected_org_id,
            "login_session_id": session.login_session_id,
        });
        let bytes = serde_json::to_vec(&value).map_err(|error| TzapAuthError::Storage { message: error.to_string() })?;
        self.session_entry(account_key)?
            .set_secret(&bytes)
            .map_err(|_| TzapAuthError::Storage { message: "could not save TZAP session to the OS keyring".to_owned() })?;
        cache_secret(self.session_cache_key(account_key), &SecretBytes::from(bytes));
        Ok(())
    }

    fn load_session(&self, account_key: &str) -> Option<TzapSessionRecord> {
        let cache_key = self.session_cache_key(account_key);
        let bytes = if let Some(bytes) = cached_secret(&cache_key) {
            bytes
        } else {
            let bytes = SecretBytes::from(self.session_entry(account_key).ok()?.get_secret().ok()?);
            cache_secret(cache_key, &bytes);
            bytes
        };
        let value: Value = serde_json::from_slice(bytes.expose_secret()).ok()?;
        let audience = value.get("audience")?.as_str()?.to_owned();
        let access_token = TzapBearerToken::new(value.get("access_token")?.as_str()?).ok()?;
        let expires_at_unix_seconds = value.get("expires_at_unix_seconds")?.as_u64()?;
        let identity_assurance = TzapIdentityAssurance::parse(value.get("identity_assurance")?.as_str()?)?;
        Some(TzapSessionRecord {
            audience,
            access_token,
            expires_at_unix_seconds,
            identity_assurance,
            selected_org_id: value.get("selected_org_id").and_then(Value::as_str).map(str::to_owned),
            login_session_id: value.get("login_session_id").and_then(Value::as_str).map(str::to_owned),
        })
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), TzapAuthError> {
        let cache_key = self.session_cache_key(account_key);
        match self.session_entry(account_key)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => {
                invalidate_cached_secret(&cache_key);
                Ok(())
            }
            Err(_) => Err(TzapAuthError::Storage { message: "could not clear TZAP session from the OS keyring".to_owned() }),
        }
    }
}

fn map_keyring_error(error: &KeyringError, reference: &TzapSecretRef) -> TzapSecretStoreError {
    match error {
        KeyringError::NoEntry => TzapSecretStoreError::Missing { reference: reference.clone() },
        KeyringError::BadEncoding(_) | KeyringError::Ambiguous(_) => TzapSecretStoreError::Corrupt,
        KeyringError::NoStorageAccess(_) => TzapSecretStoreError::Locked,
        KeyringError::Invalid(_, _) | KeyringError::TooLong(_, _) => TzapSecretStoreError::Denied,
        _ => TzapSecretStoreError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeTzapSecretStore, cache_secret, cached_secret, invalidate_cached_secret};
    use zmanager_core::secrets::SecretBytes;

    #[test]
    fn keyring_scope_rejects_path_and_namespace_injection() {
        assert!(NativeTzapSecretStore::new("default").is_ok());
        assert!(NativeTzapSecretStore::new("default:other").is_err());
        assert!(NativeTzapSecretStore::new("../other").is_err());
    }

    #[test]
    fn secret_cache_reuses_and_invalidates_material() {
        let key = "unit-test-cache-entry";
        invalidate_cached_secret(key);
        assert!(cached_secret(key).is_none());

        cache_secret(key.to_owned(), &SecretBytes::from(b"first".to_vec()));
        assert_eq!(cached_secret(key).as_ref().map(SecretBytes::expose_secret), Some(b"first".as_slice()));

        cache_secret(key.to_owned(), &SecretBytes::from(b"second".to_vec()));
        assert_eq!(cached_secret(key).as_ref().map(SecretBytes::expose_secret), Some(b"second".as_slice()));

        invalidate_cached_secret(key);
        assert!(cached_secret(key).is_none());
    }
}
