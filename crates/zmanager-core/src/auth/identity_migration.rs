//! Legacy-inventory migration and the legacy facade over the catalog
//! (CR-138).
//!
//! Extracted from the identity catalog: the migration transaction machinery,
//! the catalog/legacy conversions used by the `TzapLocalIdentityStore`
//! facade, and the file-backed secret store.

use crate::identity_catalog::{
    TzapIdentityCatalog, TzapIdentityCatalogError, TzapIdentityCatalogStore, TzapPublicContactRecord, TzapPublicEmergencyBlocklist,
    TzapPublicRecipientKeyRecord, TzapPublicSigningIdentityRecord, TzapPublicStatusCacheRecord, TzapSecretMaterialStore, TzapSecretPurpose, TzapSecretRef,
    TzapSecretStoreError,
};
use crate::local_identity_store::{
    TzapCertificateStatusCacheRecord, TzapContactRecord, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord,
    TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
};
use crate::secrets::SecretBytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

/// One crash-recoverable catalog transaction that was recorded before its
/// side effects completed.
///
/// The wire format deliberately matches the historical string marker
/// (`legacy-migration-<unix seconds>`), so catalogs written by older versions
/// keep loading after an upgrade.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PendingMutation {
    /// A legacy inventory migration wrote its public catalog first and is
    /// expected to finish copying secret material into the secure store.
    LegacyMigration { started_at_unix_seconds: u64 },
}

impl PendingMutation {
    fn wire_value(&self) -> String {
        match self {
            Self::LegacyMigration { started_at_unix_seconds } => {
                format!("legacy-migration-{started_at_unix_seconds}")
            }
        }
    }
}

impl Serialize for PendingMutation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.wire_value())
    }
}

impl<'de> Deserialize<'de> for PendingMutation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if let Some(started_at) = value.strip_prefix("legacy-migration-") {
            let started_at_unix_seconds = started_at.parse().map_err(|_| serde::de::Error::custom("invalid legacy migration marker"))?;
            Ok(Self::LegacyMigration { started_at_unix_seconds })
        } else {
            Err(serde::de::Error::custom(format!("unknown pending mutation marker: {value}")))
        }
    }
}

pub struct TzapLegacyMigrationReport {
    pub migrated: bool,
    pub signing_identity_count: usize,
    pub recipient_key_count: usize,
}

/// Moves legacy private bytes into the injected secure store and writes only
/// public metadata plus opaque references to the new catalog. A completed
/// pre-existing catalog makes the operation a no-op; a catalog marked with a
/// pending migration is resumed from the intact legacy inventory.
pub fn migrate_legacy_inventory(
    legacy_store: &impl TzapLocalIdentityStore,
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    now_unix_seconds: u64,
) -> Result<TzapLegacyMigrationReport, TzapIdentityCatalogError> {
    if let Some(catalog) = catalog_store.load_catalog(account_key)? {
        if has_pending_legacy_migration(&catalog) {
            return resume_pending_migration(legacy_store, catalog_store, secret_store, account_key, catalog);
        }
        return Ok(TzapLegacyMigrationReport {
            migrated: false,
            signing_identity_count: catalog.signing_identities.len(),
            recipient_key_count: catalog.recipient_keys.len(),
        });
    }

    let inventory = legacy_store.load_inventory(account_key)?;
    let (catalog, signing_refs, recipient_refs) = build_catalog_from_legacy(&inventory, now_unix_seconds)?;
    commit_migration(catalog_store, secret_store, account_key, catalog, &inventory, &signing_refs, &recipient_refs)?;

    let catalog = catalog_store.load_catalog(account_key)?.ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.catalog" })?;
    Ok(TzapLegacyMigrationReport {
        migrated: true,
        signing_identity_count: catalog.signing_identities.len(),
        recipient_key_count: catalog.recipient_keys.len(),
    })
}

fn has_pending_legacy_migration(catalog: &TzapIdentityCatalog) -> bool {
    catalog.pending_mutations.iter().any(|mutation| matches!(mutation, PendingMutation::LegacyMigration { .. }))
}

/// Resumes a migration whose public catalog was committed but whose secret
/// store writes did not finish before a crash.
///
/// A catalog is written before its secrets during migration. On a restart,
/// retry the same references from the intact legacy file instead of creating
/// a second set of orphaned keychain entries.
fn resume_pending_migration(
    legacy_store: &impl TzapLocalIdentityStore,
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    mut catalog: TzapIdentityCatalog,
) -> Result<TzapLegacyMigrationReport, TzapIdentityCatalogError> {
    let inventory = legacy_store.load_inventory(account_key)?;
    let signing_by_id = inventory.device_signing_keys.iter().map(|record| (record.key_id.as_str(), &record.private_key_der)).collect::<HashMap<_, _>>();
    let signing_by_certificate =
        inventory.enrolled_certificates.iter().map(|record| (record.certificate_id.as_str(), record.signing_key_id.as_str())).collect::<HashMap<_, _>>();
    for identity in &catalog.signing_identities {
        if matches!(secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref), Err(TzapSecretStoreError::Missing { .. })) {
            let key_id = signing_by_certificate.get(identity.id.as_str()).copied().unwrap_or(identity.id.as_str());
            let material = signing_by_id.get(key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "legacy_migration.signing_key_ref" })?;
            secret_store.put_at(TzapSecretPurpose::SigningKey, &identity.signing_key_ref, (*material).clone())?;
        }
    }
    let recipient_by_id = inventory.recipient_encryption_keys.iter().map(|record| (record.key_id.as_str(), &record.private_key_der)).collect::<HashMap<_, _>>();
    for key in &catalog.recipient_keys {
        if matches!(secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref), Err(TzapSecretStoreError::Missing { .. })) {
            let material =
                recipient_by_id.get(key.id.as_str()).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "legacy_migration.recipient_key_ref" })?;
            secret_store.put_at(TzapSecretPurpose::RecipientKey, &key.private_key_ref, (*material).clone())?;
        }
    }
    for identity in &catalog.signing_identities {
        secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
    }
    for key in &catalog.recipient_keys {
        secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
    }
    catalog.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));
    let expected_revision = catalog.revision;
    catalog.revision = catalog.revision.saturating_add(1);
    catalog_store.save_catalog(account_key, Some(expected_revision), catalog.clone())?;
    Ok(TzapLegacyMigrationReport {
        migrated: true,
        signing_identity_count: catalog.signing_identities.len(),
        recipient_key_count: catalog.recipient_keys.len(),
    })
}

/// Secret references produced while building a catalog, keyed by legacy
/// record id.
type SecretRefMap = HashMap<String, TzapSecretRef>;

/// Builds the public catalog (and its secret references) from a legacy
/// inventory without writing anything to either store.
///
/// Returns the catalog, the signing-key references, and the recipient-key
/// references, all keyed by legacy record id.
#[allow(clippy::too_many_lines)]
fn build_catalog_from_legacy(
    inventory: &TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> Result<(TzapIdentityCatalog, SecretRefMap, SecretRefMap), TzapIdentityCatalogError> {
    let mut signing_refs = HashMap::new();
    let mut recipient_refs = HashMap::new();
    for record in &inventory.device_signing_keys {
        verify_private_matches_fingerprint(&record.private_key_der, &record.public_key_fingerprint)?;
        signing_refs.insert(record.key_id.clone(), TzapSecretRef::generate());
    }
    for record in &inventory.recipient_encryption_keys {
        verify_private_matches_public_key(&record.private_key_der, &record.public_key_der)?;
        recipient_refs.insert(record.key_id.clone(), TzapSecretRef::generate());
    }

    let mut signing_identities = Vec::new();
    let mut certificate_key_ids = HashSet::new();
    for certificate in &inventory.enrolled_certificates {
        let signing_key_ref = signing_refs
            .get(&certificate.signing_key_id)
            .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "enrolled_certificates.signing_key_id" })?
            .clone();
        let backing_key = inventory.device_signing_keys.iter().find(|key| key.key_id == certificate.signing_key_id);
        let signing_key_created_at = backing_key.map(|key| key.created_at_unix_seconds);
        let signing_key_label = backing_key.and_then(|key| key.label.clone());
        certificate_key_ids.insert(certificate.signing_key_id.clone());
        signing_identities.push(TzapPublicSigningIdentityRecord {
            id: certificate.certificate_id.clone(),
            local_alias: signing_key_label,
            certificate_id: Some(certificate.certificate_id.clone()),
            certificate_sha256: Some(certificate.certificate_sha256.clone()),
            issuer_certificate_sha256: Some(certificate.issuer_certificate_sha256.clone()),
            issuer_key_identifier: Some(certificate.issuer_key_identifier.clone()),
            serial_number: Some(certificate.serial_number.clone()),
            certificate_chain_der: std::iter::once(certificate.leaf_certificate_der.clone()).chain(certificate.intermediate_chain_der.clone()).collect(),
            not_before_unix_seconds: Some(certificate.not_before_unix_seconds),
            not_after_unix_seconds: Some(certificate.not_after_unix_seconds),
            renewal_grace_period_days: certificate.renewal_grace_period_days,
            renewal_recommended_within_days: certificate.renewal_recommended_within_days,
            public_signer_id: Some(certificate.public_metadata.public_signer_id.clone()),
            public_org_id: certificate.public_metadata.public_org_id.clone(),
            public_device_id: Some(certificate.public_metadata.public_device_id.clone()),
            assurance_level: Some(certificate.public_metadata.assurance_level.as_str().to_owned()),
            sign_device_id: Some(certificate.sign_device_id.clone()),
            sign_device_routing: Some(certificate.sign_device_routing.clone()),
            signing_key_created_at_unix_seconds: signing_key_created_at,
            legacy_key_id: Some(certificate.signing_key_id.clone()),
            metadata_version: Some(certificate.public_metadata.version),
            policy_oid: Some(certificate.public_metadata.policy_oid.clone()),
            signing_key_ref,
            lifecycle: certificate.state.as_str().to_owned(),
        });
    }
    for key in &inventory.device_signing_keys {
        if !certificate_key_ids.contains(&key.key_id) {
            signing_identities.push(TzapPublicSigningIdentityRecord {
                id: key.key_id.clone(),
                local_alias: key.label.clone(),
                certificate_id: None,
                certificate_sha256: None,
                issuer_certificate_sha256: None,
                issuer_key_identifier: None,
                serial_number: None,
                certificate_chain_der: Vec::new(),
                not_before_unix_seconds: None,
                not_after_unix_seconds: None,
                renewal_grace_period_days: None,
                renewal_recommended_within_days: None,
                public_signer_id: None,
                public_org_id: None,
                public_device_id: None,
                assurance_level: None,
                sign_device_id: None,
                sign_device_routing: None,
                signing_key_created_at_unix_seconds: Some(key.created_at_unix_seconds),
                legacy_key_id: None,
                metadata_version: None,
                policy_oid: None,
                signing_key_ref: signing_refs.get(&key.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.signing_refs" })?.clone(),
                lifecycle: "pending".to_owned(),
            });
        }
    }

    let recipient_keys = inventory
        .recipient_encryption_keys
        .iter()
        .map(|key| {
            Ok::<_, TzapIdentityCatalogError>(TzapPublicRecipientKeyRecord {
                id: key.key_id.clone(),
                local_label: key.label.clone(),
                algorithm: key.algorithm.clone(),
                public_key_der: key.public_key_der.clone(),
                fingerprint: key.public_key_fingerprint.clone(),
                private_key_ref: recipient_refs.get(&key.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.recipient_refs" })?.clone(),
                lifecycle: "active".to_owned(),
                created_at_unix_seconds: key.created_at_unix_seconds,
                retired_at_unix_seconds: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut catalog = TzapIdentityCatalog::empty();
    catalog.revision = 1;
    catalog.signing_identities = signing_identities;
    catalog.recipient_keys = recipient_keys;
    catalog.contacts = inventory
        .contacts
        .iter()
        .map(|contact| {
            let recipient_public_key_der = contact
                .contact_card_payload
                .get("recipient_public_key")
                .and_then(Value::as_str)
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "contacts.recipient_public_key" })?;
            Ok::<_, TzapIdentityCatalogError>(TzapPublicContactRecord {
                contact_id: contact.contact_id.clone(),
                display_name: contact.display_name.clone(),
                signing_certificate_sha256: contact.signing_certificate_sha256.clone(),
                recipient_public_key_fingerprint: contact.recipient_public_key_fingerprint.clone(),
                recipient_public_key_der,
                trust_source: contact.trust_anchor_type.as_str().to_owned(),
                source: contact.source.clone(),
                verification_state: contact.verification_state.as_str().to_owned(),
                missing_status_caveat: contact.missing_status_caveat,
                contact_card_payload: contact.contact_card_payload.clone(),
                accepted_at_unix_seconds: contact.accepted_at_unix_seconds,
                local_alias: contact.local_alias.clone(),
                card: contact.card.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    catalog.removed_contacts.clone_from(&inventory.removed_contacts);
    catalog.status_cache = inventory
        .certificate_status_cache
        .iter()
        .map(|record| TzapPublicStatusCacheRecord {
            lookup_id: record.certificate_sha256.clone(),
            status: record.status.as_str().to_owned(),
            this_update: record.this_update_unix_seconds.to_string(),
            next_update: record.next_update_unix_seconds.to_string(),
        })
        .collect();
    catalog.emergency_blocklist = TzapPublicEmergencyBlocklist {
        blocked_root_sha256: inventory.emergency_blocklist.blocked_root_sha256.clone(),
        blocked_issuer_sha256: inventory.emergency_blocklist.blocked_issuer_sha256.clone(),
        updated_at_unix_seconds: inventory.emergency_blocklist.updated_at_unix_seconds,
    };
    catalog.pending_mutations.push(PendingMutation::LegacyMigration { started_at_unix_seconds: now_unix_seconds });
    catalog.validate()?;
    Ok((catalog, signing_refs, recipient_refs))
}

/// Commits a built catalog: writes the public intent first, copies every
/// secret into the secure store under the recorded references, verifies the
/// result, then clears the pending-migration marker.
fn commit_migration(
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    catalog: TzapIdentityCatalog,
    inventory: &TzapLocalIdentityInventory,
    signing_refs: &HashMap<String, TzapSecretRef>,
    recipient_refs: &HashMap<String, TzapSecretRef>,
) -> Result<(), TzapIdentityCatalogError> {
    // Commit the public intent first. The secret store writes below use
    // these exact references, so startup can resume this transaction.
    catalog_store.save_catalog(account_key, None, catalog)?;
    for record in &inventory.device_signing_keys {
        secret_store.put_at(
            TzapSecretPurpose::SigningKey,
            signing_refs.get(&record.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.signing_refs" })?,
            record.private_key_der.clone(),
        )?;
    }
    for record in &inventory.recipient_encryption_keys {
        secret_store.put_at(
            TzapSecretPurpose::RecipientKey,
            recipient_refs.get(&record.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.recipient_refs" })?,
            record.private_key_der.clone(),
        )?;
    }
    let mut committed = catalog_store.load_catalog(account_key)?.ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "migration.catalog" })?;
    for identity in &committed.signing_identities {
        secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
    }
    for key in &committed.recipient_keys {
        secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
    }
    committed.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));
    let expected_revision = committed.revision;
    committed.revision = committed.revision.saturating_add(1);
    catalog_store.save_catalog(account_key, Some(expected_revision), committed)?;
    Ok(())
}

/// Computes the `sha256:` public-key fingerprint of a private key, in the
/// same form the legacy inventory stores on its key records.
pub(crate) fn public_key_fingerprint_from_private_key(private_key: &SecretBytes) -> Result<String, TzapIdentityCatalogError> {
    let key = openssl::pkey::PKey::private_key_from_der(private_key.expose_secret())
        .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let public_der = key.public_key_to_der().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let digest: [u8; 32] = Sha256::digest(public_der).into();
    Ok(crate::trust::format_certificate_sha256(&digest))
}

fn verify_private_matches_fingerprint(private_key: &SecretBytes, expected_fingerprint: &str) -> Result<(), TzapIdentityCatalogError> {
    if public_key_fingerprint_from_private_key(private_key)? != expected_fingerprint {
        return Err(TzapIdentityCatalogError::InvalidCatalog { field: "private_key_public_key_match" });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy facade
//
// The legacy `TzapLocalIdentityStore` API persists through the catalog and a
// file-backed secret store, so the catalog is the only on-disk identity
// format. The legacy JSON inventory file is read once for migration and
// removed; the legacy record types remain the in-memory/wire model.

/// File-backed secret store used by the legacy facade: one 0o600 file per
/// secret under `{root}/secrets/{account_key}/{purpose}/{reference}`.
///
/// `pub` (not `pub(crate)`) so `zmanager-mobile-core` can compose it inside
/// `PlatformWrappedTzapSecretStore` rather than re-deriving this file layout
/// and atomic-write behavior — see the mobile TZAP secret-store cutover plan.
pub struct FileTzapSecretMaterialStore {
    root: PathBuf,
    account_key: String,
}

impl FileTzapSecretMaterialStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, account_key: &str) -> Self {
        Self { root: root.into(), account_key: account_key.to_owned() }
    }

    fn secret_path(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> PathBuf {
        self.root.join("secrets").join(&self.account_key).join(purpose.as_str()).join(reference.as_str())
    }
}

impl TzapSecretMaterialStore for FileTzapSecretMaterialStore {
    fn put(&mut self, purpose: TzapSecretPurpose, material: SecretBytes) -> Result<TzapSecretRef, TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let reference = TzapSecretRef::generate();
        self.put_at(purpose, &reference, material)?;
        Ok(reference)
    }

    fn put_at(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef, material: SecretBytes) -> Result<(), TzapSecretStoreError> {
        if material.is_empty() {
            return Err(TzapSecretStoreError::Corrupt);
        }
        let path = self.secret_path(purpose, reference);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| TzapSecretStoreError::Denied)?;
        }
        crate::atomic_file::write_atomic_secret_file(&path, material.expose_secret()).map_err(|_| TzapSecretStoreError::Denied)
    }

    fn resolve(&self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<SecretBytes, TzapSecretStoreError> {
        let path = self.secret_path(purpose, reference);
        match fs::read(&path) {
            Ok(bytes) => Ok(SecretBytes::from(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(TzapSecretStoreError::Missing { reference: reference.clone() }),
            Err(_) => Err(TzapSecretStoreError::Corrupt),
        }
    }

    fn delete(&mut self, purpose: TzapSecretPurpose, reference: &TzapSecretRef) -> Result<(), TzapSecretStoreError> {
        let path = self.secret_path(purpose, reference);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(TzapSecretStoreError::Denied),
        }
    }
}

/// Persists a legacy inventory through the catalog, reusing existing secret
/// references for keys that persist so refs stay stable across saves and no
/// secrets are orphaned.
pub fn store_inventory_as_catalog(
    catalog_store: &mut impl TzapIdentityCatalogStore,
    secret_store: &mut impl TzapSecretMaterialStore,
    account_key: &str,
    inventory: &TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> Result<(), TzapIdentityCatalogError> {
    let (mut catalog, mut signing_refs, mut recipient_refs) = build_catalog_from_legacy(inventory, now_unix_seconds)?;
    // The facade's normal writes are not migration transactions.
    catalog.pending_mutations.retain(|mutation| !matches!(mutation, PendingMutation::LegacyMigration { .. }));

    let existing = catalog_store.load_catalog(account_key)?;
    let mut obsolete_signing_refs = Vec::new();
    let mut obsolete_recipient_refs = Vec::new();
    if let Some(existing) = &existing {
        for identity in &existing.signing_identities {
            let Some(key_id) = identity.legacy_key_id.clone() else { continue };
            let Some(fresh) = signing_refs.get(&key_id) else { continue };
            let existing_ref = identity.signing_key_ref.clone();
            for record in &mut catalog.signing_identities {
                if &record.signing_key_ref == fresh {
                    record.signing_key_ref = existing_ref.clone();
                }
            }
            signing_refs.insert(key_id, existing_ref);
        }
        for key in &existing.recipient_keys {
            let Some(fresh) = recipient_refs.get(&key.id) else { continue };
            let existing_ref = key.private_key_ref.clone();
            for record in &mut catalog.recipient_keys {
                if &record.private_key_ref == fresh {
                    record.private_key_ref = existing_ref.clone();
                }
            }
            recipient_refs.insert(key.id.clone(), existing_ref);
        }
        // Secrets whose refs disappeared from the inventory are dropped.
        let current_signing: HashSet<&str> = catalog.signing_identities.iter().map(|identity| identity.signing_key_ref.as_str()).collect();
        let current_recipient: HashSet<&str> = catalog.recipient_keys.iter().map(|key| key.private_key_ref.as_str()).collect();
        for identity in &existing.signing_identities {
            if !current_signing.contains(identity.signing_key_ref.as_str()) {
                obsolete_signing_refs.push(identity.signing_key_ref.clone());
            }
        }
        for key in &existing.recipient_keys {
            if !current_recipient.contains(key.private_key_ref.as_str()) {
                obsolete_recipient_refs.push(key.private_key_ref.clone());
            }
        }
    }

    preserve_default_signing_identity(existing.as_ref(), &mut catalog);

    for record in &inventory.device_signing_keys {
        let reference = signing_refs.get(&record.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "facade.signing_refs" })?;
        secret_store.put_at(TzapSecretPurpose::SigningKey, reference, record.private_key_der.clone())?;
    }
    for record in &inventory.recipient_encryption_keys {
        let reference = recipient_refs.get(&record.key_id).ok_or(TzapIdentityCatalogError::InvalidCatalog { field: "facade.recipient_refs" })?;
        secret_store.put_at(TzapSecretPurpose::RecipientKey, reference, record.private_key_der.clone())?;
    }

    let expected_revision = existing.as_ref().map(|catalog| catalog.revision);
    catalog.revision = expected_revision.map_or(1, |revision| revision.saturating_add(1));
    catalog_store.save_catalog(account_key, expected_revision, catalog)?;
    // Deleting old secrets is safe only after the catalog atomically points at
    // the replacement inventory. If the commit failed, the old catalog still
    // retains these references and they must remain resolvable.
    for reference in obsolete_signing_refs {
        let _ = secret_store.delete(TzapSecretPurpose::SigningKey, &reference);
    }
    for reference in obsolete_recipient_refs {
        let _ = secret_store.delete(TzapSecretPurpose::RecipientKey, &reference);
    }
    Ok(())
}

/// Keeps the catalog's selected signing identity stable across legacy-inventory
/// writes. A renewal replaces the active certificate while retaining the
/// backing signing key, so a revoked default must migrate to the active
/// replacement with the same key and public scope.
fn preserve_default_signing_identity(existing: Option<&TzapIdentityCatalog>, next: &mut TzapIdentityCatalog) {
    let Some(existing) = existing else { return };
    let Some(default_id) = existing.default_signing_identity_id.as_deref() else { return };

    if next.signing_identities.iter().any(|identity| identity.id == default_id && identity.lifecycle == "active") {
        next.default_signing_identity_id = Some(default_id.to_owned());
        return;
    }

    let Some(previous) = existing.signing_identities.iter().find(|identity| identity.id == default_id) else {
        next.default_signing_identity_id = None;
        return;
    };
    next.default_signing_identity_id = next
        .signing_identities
        .iter()
        .find(|candidate| {
            candidate.id != default_id
                && candidate.lifecycle == "active"
                && candidate.legacy_key_id == previous.legacy_key_id
                && candidate.public_device_id == previous.public_device_id
                && candidate.public_org_id == previous.public_org_id
        })
        .map(|candidate| candidate.id.clone());
}

/// Loads a legacy-shaped inventory from the catalog, hydrating private key
/// material from the secret store.
#[allow(clippy::too_many_lines)]
pub fn load_inventory_from_catalog(
    catalog_store: &impl TzapIdentityCatalogStore,
    secret_store: &impl TzapSecretMaterialStore,
    account_key: &str,
) -> Result<Option<TzapLocalIdentityInventory>, TzapIdentityCatalogError> {
    let Some(catalog) = catalog_store.load_catalog(account_key)? else { return Ok(None) };
    let mut inventory = TzapLocalIdentityInventory::empty();

    for identity in &catalog.signing_identities {
        let private_key_der = secret_store.resolve(TzapSecretPurpose::SigningKey, &identity.signing_key_ref)?;
        let key_id = identity.legacy_key_id.clone().unwrap_or_else(|| identity.id.clone());
        inventory.device_signing_keys.push(TzapDeviceSigningKeyRecord {
            key_id: key_id.clone(),
            public_key_fingerprint: public_key_fingerprint_from_private_key(&private_key_der)?,
            private_key_der: private_key_der.clone(),
            created_at_unix_seconds: identity.signing_key_created_at_unix_seconds.unwrap_or(0),
            label: identity.local_alias.clone(),
        });
        if let (
            Some(certificate_id),
            Some(certificate_sha256),
            Some(issuer_certificate_sha256),
            Some(issuer_key_identifier),
            Some(serial_number),
            Some(not_before_unix_seconds),
            Some(not_after_unix_seconds),
            Some(public_signer_id),
            Some(public_device_id),
            Some(assurance_level),
            Some(sign_device_id),
        ) = (
            identity.certificate_id.as_ref(),
            identity.certificate_sha256.as_ref(),
            identity.issuer_certificate_sha256.as_ref(),
            identity.issuer_key_identifier.as_ref(),
            identity.serial_number.as_ref(),
            identity.not_before_unix_seconds,
            identity.not_after_unix_seconds,
            identity.public_signer_id.as_ref(),
            identity.public_device_id.as_ref(),
            identity.assurance_level.as_deref(),
            identity.sign_device_id.as_ref(),
        ) {
            let mut chain = identity.certificate_chain_der.clone();
            let leaf = chain.drain(..1).next().unwrap_or_default();
            inventory.enrolled_certificates.push(TzapEnrolledCertificateRecord {
                certificate_id: certificate_id.clone(),
                certificate_sha256: certificate_sha256.clone(),
                issuer_certificate_sha256: issuer_certificate_sha256.clone(),
                issuer_key_identifier: issuer_key_identifier.clone(),
                serial_number: serial_number.clone(),
                leaf_certificate_der: leaf,
                intermediate_chain_der: chain,
                not_before_unix_seconds,
                not_after_unix_seconds,
                renewal_grace_period_days: identity.renewal_grace_period_days,
                renewal_recommended_within_days: identity.renewal_recommended_within_days,
                public_metadata: crate::trust::TzapCertificatePublicMetadata {
                    version: identity.metadata_version.unwrap_or(u64::from(crate::trust::TZAP_ENVELOPE_VERSION)),
                    public_signer_id: public_signer_id.clone(),
                    public_org_id: identity.public_org_id.clone(),
                    public_device_id: public_device_id.clone(),
                    assurance_level: assurance_level.parse().map_err(|()| TzapIdentityCatalogError::InvalidCatalog { field: "assurance_level" })?,
                    policy_oid: identity.policy_oid.clone().unwrap_or_else(|| crate::trust::TZAP_OID_LEAF_POLICY.to_owned()),
                },
                sign_device_id: sign_device_id.clone(),
                sign_device_routing: identity.sign_device_routing.clone().unwrap_or(TzapSignDeviceRouting::Personal),
                signing_key_id: key_id,
                state: TzapLocalCertificateState::from_wire_value(&identity.lifecycle).unwrap_or(TzapLocalCertificateState::Active),
            });
        }
    }

    for key in &catalog.recipient_keys {
        let private_key_der = secret_store.resolve(TzapSecretPurpose::RecipientKey, &key.private_key_ref)?;
        inventory.recipient_encryption_keys.push(TzapRecipientEncryptionKeyRecord {
            key_id: key.id.clone(),
            algorithm: key.algorithm.clone(),
            public_key_fingerprint: key.fingerprint.clone(),
            public_key_der: key.public_key_der.clone(),
            private_key_der,
            created_at_unix_seconds: key.created_at_unix_seconds,
            label: key.local_label.clone(),
        });
    }

    for contact in &catalog.contacts {
        let (trust_source, source) = if contact.trust_source == "phone_sync" {
            // Older desktop catalogs overloaded trust_source with the
            // synchronization origin. Preserve those contacts while moving
            // the origin into the dedicated source field.
            ("official_tzap", if contact.source.is_empty() { "phone_sync" } else { contact.source.as_str() })
        } else {
            (contact.trust_source.as_str(), contact.source.as_str())
        };
        inventory.contacts.push(TzapContactRecord {
            contact_id: contact.contact_id.clone(),
            display_name: contact.display_name.clone(),
            signing_certificate_sha256: contact.signing_certificate_sha256.clone(),
            recipient_public_key_fingerprint: contact.recipient_public_key_fingerprint.clone(),
            trust_anchor_type: trust_source.parse().map_err(|()| TzapIdentityCatalogError::InvalidCatalog { field: "contacts.trust_source" })?,
            source: source.to_owned(),
            verification_state: contact
                .verification_state
                .parse()
                .map_err(|()| TzapIdentityCatalogError::InvalidCatalog { field: "contacts.verification_state" })?,
            missing_status_caveat: contact.missing_status_caveat,
            contact_card_payload: contact.contact_card_payload.clone(),
            accepted_at_unix_seconds: contact.accepted_at_unix_seconds,
            local_alias: contact.local_alias.clone(),
            card: contact.card.clone(),
        });
    }

    inventory.removed_contacts.clone_from(&catalog.removed_contacts);

    for record in &catalog.status_cache {
        inventory.certificate_status_cache.push(TzapCertificateStatusCacheRecord {
            certificate_sha256: record.lookup_id.clone(),
            status: record.status.parse().map_err(|()| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.status" })?,
            this_update_unix_seconds: record.this_update.parse().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.this_update" })?,
            next_update_unix_seconds: record.next_update.parse().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "status_cache.next_update" })?,
        });
    }

    inventory.emergency_blocklist = TzapEmergencyBlocklistState {
        blocked_root_sha256: catalog.emergency_blocklist.blocked_root_sha256.clone(),
        blocked_issuer_sha256: catalog.emergency_blocklist.blocked_issuer_sha256.clone(),
        updated_at_unix_seconds: catalog.emergency_blocklist.updated_at_unix_seconds,
    };
    Ok(Some(inventory))
}

fn verify_private_matches_public_key(private_key: &SecretBytes, public_key_der: &[u8]) -> Result<(), TzapIdentityCatalogError> {
    let key = openssl::pkey::PKey::private_key_from_der(private_key.expose_secret())
        .map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    let derived = key.public_key_to_der().map_err(|_| TzapIdentityCatalogError::InvalidCatalog { field: "private_key_der" })?;
    if derived != public_key_der {
        return Err(TzapIdentityCatalogError::InvalidCatalog { field: "private_key_public_key_match" });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_catalog::{InMemoryTzapIdentityCatalogStore, InMemoryTzapSecretMaterialStore, TzapPublicRecipientKeyRecord};

    fn signing_identity(id: &str, lifecycle: &str, key_id: &str) -> TzapPublicSigningIdentityRecord {
        TzapPublicSigningIdentityRecord {
            id: id.to_owned(),
            local_alias: Some("Desktop".to_owned()),
            certificate_id: Some(id.to_owned()),
            certificate_sha256: None,
            issuer_certificate_sha256: None,
            issuer_key_identifier: None,
            serial_number: None,
            certificate_chain_der: Vec::new(),
            not_before_unix_seconds: None,
            not_after_unix_seconds: None,
            renewal_grace_period_days: None,
            renewal_recommended_within_days: None,
            public_signer_id: Some("signer-1".to_owned()),
            public_org_id: Some("org-1".to_owned()),
            public_device_id: Some("device-1".to_owned()),
            assurance_level: Some("enrolled".to_owned()),
            sign_device_id: Some("sign-device-1".to_owned()),
            sign_device_routing: Some(TzapSignDeviceRouting::Organization {
                org_id: "org-1".to_owned(),
                login_organization_device_id: "login-device-1".to_owned(),
            }),
            signing_key_created_at_unix_seconds: Some(1),
            legacy_key_id: Some(key_id.to_owned()),
            metadata_version: Some(1),
            policy_oid: Some("policy".to_owned()),
            signing_key_ref: TzapSecretRef::generate(),
            lifecycle: lifecycle.to_owned(),
        }
    }

    #[test]
    fn default_identity_survives_inventory_round_trip() {
        let mut existing = TzapIdentityCatalog::empty();
        existing.default_signing_identity_id = Some("identity-1".to_owned());
        existing.signing_identities.push(signing_identity("identity-1", "active", "key-1"));
        let mut next = TzapIdentityCatalog::empty();
        next.signing_identities.push(signing_identity("identity-1", "active", "key-1"));

        preserve_default_signing_identity(Some(&existing), &mut next);

        assert_eq!(next.default_signing_identity_id.as_deref(), Some("identity-1"));
    }

    #[test]
    fn default_identity_moves_to_active_same_key_renewal() {
        let mut existing = TzapIdentityCatalog::empty();
        existing.default_signing_identity_id = Some("certificate-old".to_owned());
        existing.signing_identities.push(signing_identity("certificate-old", "active", "key-1"));
        let mut next = TzapIdentityCatalog::empty();
        next.signing_identities.push(signing_identity("certificate-old", "revoked", "key-1"));
        next.signing_identities.push(signing_identity("certificate-new", "active", "key-1"));

        preserve_default_signing_identity(Some(&existing), &mut next);

        assert_eq!(next.default_signing_identity_id.as_deref(), Some("certificate-new"));
    }

    struct FailingCatalogStore {
        inner: InMemoryTzapIdentityCatalogStore,
    }

    impl TzapIdentityCatalogStore for FailingCatalogStore {
        fn load_catalog(&self, account_key: &str) -> Result<Option<TzapIdentityCatalog>, TzapIdentityCatalogError> {
            self.inner.load_catalog(account_key)
        }

        fn save_catalog(&mut self, _account_key: &str, _expected_revision: Option<u64>, _catalog: TzapIdentityCatalog) -> Result<(), TzapIdentityCatalogError> {
            Err(TzapIdentityCatalogError::ConcurrentWrite)
        }

        fn clear_catalog(&mut self, account_key: &str) -> Result<(), TzapIdentityCatalogError> {
            self.inner.clear_catalog(account_key)
        }
    }

    #[test]
    fn failed_catalog_commit_keeps_old_secret_references_resolvable() {
        let old_reference = TzapSecretRef::generate();
        let mut existing = TzapIdentityCatalog::empty();
        existing.recipient_keys.push(TzapPublicRecipientKeyRecord {
            id: "recipient-1".to_owned(),
            local_label: None,
            algorithm: "x25519".to_owned(),
            public_key_der: vec![1, 2, 3],
            fingerprint: format!("sha256:{}", "a".repeat(64)),
            private_key_ref: old_reference.clone(),
            lifecycle: "active".to_owned(),
            created_at_unix_seconds: 1,
            retired_at_unix_seconds: None,
        });
        let mut inner = InMemoryTzapIdentityCatalogStore::new();
        inner.save_catalog("default", None, existing).unwrap();
        let mut catalogs = FailingCatalogStore { inner };
        let mut secrets = InMemoryTzapSecretMaterialStore::new();
        secrets.put_at(TzapSecretPurpose::RecipientKey, &old_reference, SecretBytes::from(vec![7])).unwrap();

        let result = store_inventory_as_catalog(&mut catalogs, &mut secrets, "default", &TzapLocalIdentityInventory::empty(), 2);

        assert!(result.is_err());
        assert!(secrets.resolve(TzapSecretPurpose::RecipientKey, &old_reference).is_ok());
    }
}
