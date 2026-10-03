//! Durable recovery for file-catalogue writes to a separate secret store.
use crate::identity_catalog::{
    FileTzapIdentityCatalogStore, TzapIdentityCatalogError, TzapIdentityCatalogStore as _, TzapSecretMaterialStore, TzapSecretPurpose, TzapSecretRef,
    TzapSecretStoreError,
};
use crate::identity_migration::store_inventory_as_catalog;
use crate::local_identity_store::TzapLocalIdentityInventory;
use crate::secrets::SecretBytes;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

const JOURNAL_EXTENSION: &str = "secret-writes.json";
const LOCK_EXTENSION: &str = "secret-writes.lock";
type SecretReference = (TzapSecretPurpose, TzapSecretRef);

struct PendingWrites {
    // Keep the OS lock until catalogue publication and journal cleanup finish.
    // Never unlink its path: another writer must lock the same inode.
    _lock: fs::File,
    path: PathBuf,
    references: Vec<SecretReference>,
}

impl PendingWrites {
    fn open(store: &FileTzapIdentityCatalogStore, account: &str) -> Result<Self, TzapIdentityCatalogError> {
        let catalogue = store.catalog_path(account)?;
        fs::create_dir_all(catalogue.parent().ok_or(TzapIdentityCatalogError::InvalidAccountKey)?)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options.open(catalogue.with_extension(LOCK_EXTENSION))?;
        lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => TzapIdentityCatalogError::ConcurrentWrite,
            fs::TryLockError::Error(error) => error.into(),
        })?;
        let path = catalogue.with_extension(JOURNAL_EXTENSION);
        let references: Vec<SecretReference> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        for (purpose, reference) in &references {
            let valid = reference
                .as_str()
                .strip_prefix("secret_")
                .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')));
            if !valid || *purpose == TzapSecretPurpose::Session {
                return Err(TzapIdentityCatalogError::InvalidCatalog { field: "pending_secret_writes.reference" });
            }
        }
        Ok(Self { _lock: lock, path, references })
    }

    fn record(&mut self, entry: SecretReference) -> Result<(), TzapIdentityCatalogError> {
        if !self.references.contains(&entry) {
            self.references.push(entry);
            crate::atomic_file::write_atomic_secret_file(&self.path, &serde_json::to_vec(&self.references)?)?;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), TzapIdentityCatalogError> {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.references.clear();
        Ok(())
    }

    fn recover(
        &mut self,
        store: &FileTzapIdentityCatalogStore,
        secrets: &mut impl TzapSecretMaterialStore,
        account: &str,
    ) -> Result<(), TzapIdentityCatalogError> {
        let published = published_references(store, account)?;
        for (purpose, reference) in &self.references {
            if !published.contains(&(*purpose, reference.clone())) {
                match secrets.delete(*purpose, reference) {
                    Ok(()) | Err(TzapSecretStoreError::Missing { .. }) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        self.clear()
    }
}

fn published_references(store: &FileTzapIdentityCatalogStore, account: &str) -> Result<HashSet<SecretReference>, TzapIdentityCatalogError> {
    let Some(catalogue) = store.load_catalog(account)? else { return Ok(HashSet::new()) };
    Ok(catalogue
        .signing_identities
        .iter()
        .map(|identity| (TzapSecretPurpose::SigningKey, identity.signing_key_ref.clone()))
        .chain(catalogue.recipient_keys.iter().map(|key| (TzapSecretPurpose::RecipientKey, key.private_key_ref.clone())))
        .collect())
}

struct JournaledSecrets<'a, S> {
    inner: &'a mut S,
    journal: &'a mut PendingWrites,
    published: HashSet<SecretReference>,
    journal_error: Option<TzapIdentityCatalogError>,
}

impl<S: TzapSecretMaterialStore> TzapSecretMaterialStore for JournaledSecrets<'_, S> {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes) -> Result<TzapSecretRef, TzapSecretStoreError> {
        let reference = TzapSecretRef::generate();
        self.put_at(purpose, &reference, material)?;
        Ok(reference)
    }

    fn put_at(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef, material: SecretBytes) -> Result<(), TzapSecretStoreError> {
        let entry = (purpose, reference.clone());
        if !self.published.contains(&entry)
            && let Err(error) = self.journal.record(entry)
        {
            self.journal_error = Some(error);
            return Err(TzapSecretStoreError::Denied);
        }
        self.inner.put_at(purpose, reference, material)
    }

    fn resolve(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<SecretBytes, TzapSecretStoreError> {
        self.inner.resolve(purpose, reference)
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        self.inner.delete(purpose, reference)
    }
}

/// Removes uncommitted secrets from an interrupted write, retaining all currently
/// published references. An active writer's OS lock prevents premature cleanup.
pub fn recover_file_inventory_writes(
    store: &FileTzapIdentityCatalogStore,
    secrets: &mut impl TzapSecretMaterialStore,
    account: &str,
) -> Result<(), TzapIdentityCatalogError> {
    if store.catalog_path(account)?.with_extension(JOURNAL_EXTENSION).exists() {
        PendingWrites::open(store, account)?.recover(store, secrets, account)?;
    }
    Ok(())
}

/// Persists an inventory with a durable reference-only journal before new keys
/// reach the secret store. No private material is written to the journal.
pub fn store_file_inventory_as_catalog(
    store: &mut FileTzapIdentityCatalogStore,
    secrets: &mut impl TzapSecretMaterialStore,
    account: &str,
    inventory: &TzapLocalIdentityInventory,
    now: u64,
) -> Result<(), TzapIdentityCatalogError> {
    let mut journal = PendingWrites::open(store, account)?;
    journal.recover(store, secrets, account)?;
    let published = published_references(store, account)?;
    let mut wrapped = JournaledSecrets { inner: secrets, journal: &mut journal, published, journal_error: None };
    let result = store_inventory_as_catalog(store, &mut wrapped, account, inventory, now);
    if let Some(error) = wrapped.journal_error {
        return Err(error);
    }
    result?;
    journal.clear()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_catalog::{FileTzapSecretMaterialStore, TzapIdentityCatalog, TzapPublicRecipientKeyRecord};
    use crate::local_identity_store::TzapRecipientEncryptionKeyRecord;

    struct Fixture {
        root: PathBuf,
        catalogue: FileTzapIdentityCatalogStore,
        secrets: FileTzapSecretMaterialStore,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("zm-journal-{}", TzapSecretRef::generate()));
            let mut catalogue = FileTzapIdentityCatalogStore::new(&root);
            catalogue.save_catalog("default", None, TzapIdentityCatalog::empty()).unwrap();
            let secrets = FileTzapSecretMaterialStore::new(&root, "default");
            Self { root, catalogue, secrets }
        }

        fn pending_secret(&mut self) -> (PendingWrites, TzapSecretRef) {
            let mut journal = PendingWrites::open(&self.catalogue, "default").unwrap();
            let reference = TzapSecretRef::generate();
            journal.record((TzapSecretPurpose::RecipientKey, reference.clone())).unwrap();
            self.secrets.put_at(TzapSecretPurpose::RecipientKey, &reference, SecretBytes::from(vec![1, 2, 3])).unwrap();
            (journal, reference)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn restart_removes_unpublished_secret_preserves_catalogue_and_can_retry() {
        let mut fixture = Fixture::new();
        let original = fixture.catalogue.load_catalog("default").unwrap();
        let (journal, reference) = fixture.pending_secret();
        let path = journal.path.clone();
        drop(journal); // Releases the OS lock without completing the write.
        recover_file_inventory_writes(&fixture.catalogue, &mut fixture.secrets, "default").unwrap();
        assert!(matches!(fixture.secrets.resolve(TzapSecretPurpose::RecipientKey, &reference), Err(TzapSecretStoreError::Missing { .. })));
        assert_eq!(fixture.catalogue.load_catalog("default").unwrap(), original);
        assert!(!path.exists());

        let key = crate::device_identity::generate_recipient_encryption_key().unwrap();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.recipient_encryption_keys.push(TzapRecipientEncryptionKeyRecord {
            key_id: key.public_key_fingerprint.clone(),
            algorithm: key.algorithm.to_owned(),
            public_key_fingerprint: key.public_key_fingerprint,
            public_key_der: key.public_key_spki_der,
            private_key_der: key.private_key_der.clone(),
            created_at_unix_seconds: 1,
            label: None,
        });
        store_file_inventory_as_catalog(&mut fixture.catalogue, &mut fixture.secrets, "default", &inventory, 1).unwrap();
        let published = fixture.catalogue.load_catalog("default").unwrap().unwrap();
        assert_eq!(published.recipient_keys.len(), 1);
        assert_eq!(
            fixture.secrets.resolve(TzapSecretPurpose::RecipientKey, &published.recipient_keys[0].private_key_ref).unwrap().expose_secret(),
            key.private_key_der.expose_secret()
        );
        assert!(!path.exists());
    }

    #[test]
    fn restart_after_publication_preserves_the_committed_key() {
        let mut fixture = Fixture::new();
        let (journal, reference) = fixture.pending_secret();
        let mut published = fixture.catalogue.load_catalog("default").unwrap().unwrap();
        let revision = published.revision;
        published.revision += 1;
        published.recipient_keys.push(TzapPublicRecipientKeyRecord {
            id: "recipient".to_owned(),
            local_label: None,
            algorithm: "x25519".to_owned(),
            public_key_der: vec![1],
            fingerprint: "fixture".to_owned(),
            private_key_ref: reference.clone(),
            lifecycle: "active".to_owned(),
            created_at_unix_seconds: 1,
            retired_at_unix_seconds: None,
        });
        fixture.catalogue.save_catalog("default", Some(revision), published.clone()).unwrap();
        drop(journal);
        recover_file_inventory_writes(&fixture.catalogue, &mut fixture.secrets, "default").unwrap();
        assert_eq!(fixture.secrets.resolve(TzapSecretPurpose::RecipientKey, &reference).unwrap().expose_secret(), &[1, 2, 3]);
        assert_eq!(fixture.catalogue.load_catalog("default").unwrap().unwrap(), published);
    }

    #[test]
    fn active_writer_cannot_be_cleaned_up_by_another_handle() {
        let mut fixture = Fixture::new();
        let (journal, reference) = fixture.pending_secret();
        assert!(matches!(recover_file_inventory_writes(&fixture.catalogue, &mut fixture.secrets, "default"), Err(TzapIdentityCatalogError::ConcurrentWrite)));
        assert!(fixture.secrets.resolve(TzapSecretPurpose::RecipientKey, &reference).is_ok());
        drop(journal);
        recover_file_inventory_writes(&fixture.catalogue, &mut fixture.secrets, "default").unwrap();
    }

    #[test]
    fn malformed_reference_cannot_escape_the_secret_store() {
        let mut fixture = Fixture::new();
        let path = fixture.catalogue.catalog_path("default").unwrap().with_extension(JOURNAL_EXTENSION);
        let bytes = br#"[["recipient_key","secret_../../outside"]]"#;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            recover_file_inventory_writes(&fixture.catalogue, &mut fixture.secrets, "default"),
            Err(TzapIdentityCatalogError::InvalidCatalog { .. })
        ));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
