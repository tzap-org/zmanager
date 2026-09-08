//! TZAP contact list snapshot format, merge, build, and apply operations.
//!
//! Design reference: `docs/mobile-contact-book-design.md` §8.3, §8.4, §8.5, §8.6.

use std::collections::BTreeMap;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::contact_card::{self, TzapContactCardImportOptions};
use crate::local_identity_store::{TzapContactRecord, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError};

/// Format identifier for the plaintext snapshot envelope (design §8.2, §8.5).
pub const CONTACT_SNAPSHOT_FORMAT_PLAIN: &str = "plain";

/// Current schema version of the contact snapshot envelope.
pub const CONTACT_SNAPSHOT_SCHEMA_VERSION: u64 = 1;

/// Tombstone retention window: tombstones are pruned after 1 year (365 days)
/// (design §8.3, §14).
pub const TOMBSTONE_RETENTION_SECONDS: u64 = 365 * 24 * 3600;

fn default_snapshot_version() -> u64 {
    CONTACT_SNAPSHOT_SCHEMA_VERSION
}

/// A versioned, serializable contact list snapshot envelope (design §8.3, §8.5).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TzapContactSnapshot {
    /// Format discriminator (`"plain"`).
    pub format: String,
    /// Format version number (defaults to 1).
    #[serde(default = "default_snapshot_version")]
    pub version: u64,
    /// Live contact entries.
    pub contacts: Vec<TzapContactSnapshotEntry>,
    /// Tombstones for deleted contacts.
    #[serde(default)]
    pub removed: Vec<TzapContactTombstone>,
}

impl TzapContactSnapshot {
    /// Creates a new contact snapshot with format `"plain"` and version 1.
    #[must_use]
    pub fn new(contacts: Vec<TzapContactSnapshotEntry>, removed: Vec<TzapContactTombstone>) -> Self {
        Self { format: CONTACT_SNAPSHOT_FORMAT_PLAIN.to_owned(), version: CONTACT_SNAPSHOT_SCHEMA_VERSION, contacts, removed }
    }
}

/// One live contact in the snapshot envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TzapContactSnapshotEntry {
    /// Deterministic contact ID (`recipient_public_key_fingerprint`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    /// Full signed contact card container JSON (version, payload,
    /// `signature_algorithm`, signature) (design §8.3).
    pub card: Value,
    /// Local alias chosen by the user, if any (design §4, §8.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_alias: Option<String>,
    /// Timestamp of when the user accepted this contact.
    #[serde(alias = "accepted_at_unix_seconds")]
    pub accepted_at: u64,
}

impl TzapContactSnapshotEntry {
    /// Resolves the contact's ID, preferring explicit `contact_id` and falling
    /// back to the recipient key fingerprint in the card payload.
    pub fn resolved_contact_id(&self) -> Result<String, TzapContactSnapshotError> {
        if let Some(ref id) = self.contact_id
            && !id.trim().is_empty()
        {
            return Ok(id.trim().to_owned());
        }
        let payload = if let Some(p) = self.card.get("payload") { p } else { &self.card };
        if let Some(fp) = payload.get("recipient_key_fingerprint").and_then(Value::as_str)
            && !fp.trim().is_empty()
        {
            return Ok(fp.trim().to_owned());
        }
        if let Some(pk_b64) = payload.get("recipient_public_key").and_then(Value::as_str)
            && let Ok(der) = URL_SAFE_NO_PAD.decode(pk_b64)
        {
            return Ok(crate::trust::certificate_sha256_identifier_for_der(&der));
        }
        Err(TzapContactSnapshotError::InvalidSnapshot("contact entry card missing recipient key fingerprint".to_owned()))
    }
}

/// A tombstone representing a deleted contact (design §8.3).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TzapContactTombstone {
    /// Contact ID of the deleted contact.
    pub contact_id: String,
    /// Timestamp when the contact was removed.
    #[serde(alias = "removed_at_unix_seconds")]
    pub removed_at: u64,
}

/// Report of the outcome of applying a contact snapshot.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapContactSnapshotApplyReport {
    /// Contacts successfully verified and restored into the store.
    pub restored_contacts: Vec<TzapContactRecord>,
    /// Contacts that failed signature, chain, or expiry verification (design §8.3).
    pub failed_contacts: Vec<TzapContactSnapshotRestoreFailure>,
    /// Contacts removed due to snapshot tombstones.
    pub removed_contact_ids: Vec<String>,
}

/// Description of a contact card that failed verification on restore.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapContactSnapshotRestoreFailure {
    pub contact_id: String,
    pub display_name: Option<String>,
    pub error: String,
}

/// Errors occurring during contact snapshot operations.
#[derive(Debug)]
pub enum TzapContactSnapshotError {
    InvalidFormat { expected: &'static str, actual: String },
    InvalidSnapshot(String),
    Store(TzapLocalIdentityStoreError),
    Json(String),
}

impl fmt::Display for TzapContactSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat { expected, actual } => {
                write!(f, "unsupported contact snapshot format '{actual}', expected '{expected}'")
            }
            Self::InvalidSnapshot(reason) => write!(f, "invalid contact snapshot: {reason}"),
            Self::Store(error) => write!(f, "contact snapshot store operation failed: {error}"),
            Self::Json(reason) => write!(f, "contact snapshot JSON error: {reason}"),
        }
    }
}

impl std::error::Error for TzapContactSnapshotError {}

impl From<TzapLocalIdentityStoreError> for TzapContactSnapshotError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<serde_json::Error> for TzapContactSnapshotError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

/// Prunes tombstones older than 1 year (365 days) relative to `now_unix_seconds`
/// (design §8.3, §14).
pub fn prune_tombstones(tombstones: &mut Vec<TzapContactTombstone>, now_unix_seconds: u64) {
    tombstones.retain(|tombstone| now_unix_seconds.saturating_sub(tombstone.removed_at) <= TOMBSTONE_RETENTION_SECONDS);
}

/// Merges two contact snapshots by union, resolving per contact by the later of
/// `accepted_at` / `removed_at`, and pruning tombstones older than 1 year
/// (design §8.3, §13).
///
/// # Errors
///
/// Returns [`TzapContactSnapshotError`] when a snapshot format is unsupported
/// or an entry is malformed.
pub fn merge_contact_snapshots(
    base: &TzapContactSnapshot,
    incoming: &TzapContactSnapshot,
    now_unix_seconds: u64,
) -> Result<TzapContactSnapshot, TzapContactSnapshotError> {
    if base.format != CONTACT_SNAPSHOT_FORMAT_PLAIN {
        return Err(TzapContactSnapshotError::InvalidFormat { expected: CONTACT_SNAPSHOT_FORMAT_PLAIN, actual: base.format.clone() });
    }
    if incoming.format != CONTACT_SNAPSHOT_FORMAT_PLAIN {
        return Err(TzapContactSnapshotError::InvalidFormat { expected: CONTACT_SNAPSHOT_FORMAT_PLAIN, actual: incoming.format.clone() });
    }

    // 1. Collect all tombstones, keeping the newest removed_at per contact_id.
    let mut tombstones = BTreeMap::<String, u64>::new();
    for t in base.removed.iter().chain(incoming.removed.iter()) {
        tombstones.entry(t.contact_id.clone()).and_modify(|existing| *existing = (*existing).max(t.removed_at)).or_insert(t.removed_at);
    }

    // 2. Collect all live contacts, resolving collisions by newer accepted_at.
    let mut live_contacts = BTreeMap::<String, TzapContactSnapshotEntry>::new();
    for entry in base.contacts.iter().chain(incoming.contacts.iter()) {
        let contact_id = entry.resolved_contact_id()?;
        let mut entry_to_insert = entry.clone();
        if entry_to_insert.contact_id.is_none() {
            entry_to_insert.contact_id = Some(contact_id.clone());
        }

        match live_contacts.get_mut(&contact_id) {
            Some(existing) => {
                if entry_to_insert.accepted_at > existing.accepted_at {
                    *existing = entry_to_insert;
                } else if entry_to_insert.accepted_at == existing.accepted_at {
                    // Prefer whichever entry has a local_alias, if one does.
                    if existing.local_alias.is_none() && entry_to_insert.local_alias.is_some() {
                        existing.local_alias = entry_to_insert.local_alias;
                    }
                }
            }
            None => {
                live_contacts.insert(contact_id, entry_to_insert);
            }
        }
    }

    // 3. Resolve conflicts between live contacts and tombstones by the later of
    //    accepted_at / removed_at (design §8.3).
    //    If removed_at >= accepted_at: tombstone wins.
    //    If accepted_at > removed_at: acceptance wins (re-added contact).
    let mut resolved_contacts = BTreeMap::<String, TzapContactSnapshotEntry>::new();
    for (contact_id, entry) in live_contacts {
        if let Some(&removed_at) = tombstones.get(&contact_id) {
            if entry.accepted_at > removed_at {
                // Re-added contact wins over older tombstone.
                tombstones.remove(&contact_id);
                resolved_contacts.insert(contact_id, entry);
            }
            // else removed_at >= entry.accepted_at: tombstone wins, live contact dropped.
        } else {
            resolved_contacts.insert(contact_id, entry);
        }
    }

    // 4. Prune tombstones older than 1 year (design §8.3).
    let mut pruned_tombstones = Vec::new();
    for (contact_id, removed_at) in tombstones {
        if now_unix_seconds.saturating_sub(removed_at) <= TOMBSTONE_RETENTION_SECONDS {
            pruned_tombstones.push(TzapContactTombstone { contact_id, removed_at });
        }
    }

    Ok(TzapContactSnapshot {
        format: CONTACT_SNAPSHOT_FORMAT_PLAIN.to_owned(),
        version: std::cmp::max(base.version, incoming.version),
        contacts: resolved_contacts.into_values().collect(),
        removed: pruned_tombstones,
    })
}

/// Builds a contact snapshot from an inventory and known tombstones (design §8.3).
///
/// # Errors
///
/// Returns [`TzapContactSnapshotError`] when card data is invalid.
pub fn build_contact_snapshot(
    inventory: &TzapLocalIdentityInventory,
    tombstones: &[TzapContactTombstone],
    now_unix_seconds: u64,
) -> Result<TzapContactSnapshot, TzapContactSnapshotError> {
    let mut tombstone_map = BTreeMap::<String, u64>::new();
    for t in tombstones {
        // Prune expired tombstones at build time.
        if now_unix_seconds.saturating_sub(t.removed_at) <= TOMBSTONE_RETENTION_SECONDS {
            tombstone_map.entry(t.contact_id.clone()).and_modify(|existing| *existing = (*existing).max(t.removed_at)).or_insert(t.removed_at);
        }
    }

    let mut contacts = BTreeMap::<String, TzapContactSnapshotEntry>::new();
    for contact in &inventory.contacts {
        // Bare compatibility keys are intentionally local-only. A snapshot
        // entry is a signed card and must never manufacture an unsigned card
        // that another device could mistake for an accepted contact.
        if contact.trust_anchor_type == crate::trust::TzapTrustAnchorType::Untrusted {
            continue;
        }
        // Check if there is a tombstone for this contact.
        if let Some(&removed_at) = tombstone_map.get(&contact.contact_id) {
            if removed_at >= contact.accepted_at_unix_seconds {
                // Tombstone is newer than local contact: do not include contact.
                continue;
            }
            // Local contact is newer than tombstone: drop the tombstone.
            tombstone_map.remove(&contact.contact_id);
        }

        let card = if let Some(ref c) = contact.card {
            c.clone()
        } else if contact.contact_card_payload.get("payload").is_some() {
            contact.contact_card_payload.clone()
        } else {
            json!({
                "version": contact_card::CONTACT_CARD_CONTAINER_VERSION,
                "payload": contact.contact_card_payload,
                "signature_algorithm": contact_card::CONTACT_CARD_SIGNATURE_ALGORITHM,
                "signature": "",
            })
        };

        contacts.insert(
            contact.contact_id.clone(),
            TzapContactSnapshotEntry {
                contact_id: Some(contact.contact_id.clone()),
                card,
                local_alias: contact.local_alias.clone(),
                accepted_at: contact.accepted_at_unix_seconds,
            },
        );
    }

    let removed = tombstone_map.into_iter().map(|(contact_id, removed_at)| TzapContactTombstone { contact_id, removed_at }).collect();

    Ok(TzapContactSnapshot {
        format: CONTACT_SNAPSHOT_FORMAT_PLAIN.to_owned(),
        version: CONTACT_SNAPSHOT_SCHEMA_VERSION,
        contacts: contacts.into_values().collect(),
        removed,
    })
}

/// Applies a contact snapshot to a local store: re-verifies live contact cards
/// against root pins, removes contacts matching newer tombstones, and updates
/// inventory (design §8.3, §8.6).
///
/// # Errors
///
/// Returns [`TzapContactSnapshotError`] when the snapshot format is unsupported
/// or store operations fail.
pub fn apply_contact_snapshot(
    store: &mut impl TzapLocalIdentityStore,
    account_key: &str,
    snapshot: &TzapContactSnapshot,
    options: &TzapContactCardImportOptions<'_>,
    now_unix_seconds: u64,
) -> Result<TzapContactSnapshotApplyReport, TzapContactSnapshotError> {
    if snapshot.format != CONTACT_SNAPSHOT_FORMAT_PLAIN {
        return Err(TzapContactSnapshotError::InvalidFormat { expected: CONTACT_SNAPSHOT_FORMAT_PLAIN, actual: snapshot.format.clone() });
    }

    let mut inventory = store.load_inventory(account_key)?;
    let mut report = TzapContactSnapshotApplyReport::default();

    // 1. Process tombstones: remove local contacts whose accepted_at is older
    //    than the tombstone. Seed from this device's own tombstones too, so a
    //    restore doesn't forget a removal the remote snapshot doesn't (yet)
    //    carry, and so the merged set can be written back to the inventory
    //    below for the next `build_contact_snapshot` to see.
    let mut tombstone_map = BTreeMap::<String, u64>::new();
    for t in inventory.removed_contacts.iter().chain(snapshot.removed.iter()) {
        if now_unix_seconds.saturating_sub(t.removed_at) <= TOMBSTONE_RETENTION_SECONDS {
            tombstone_map.entry(t.contact_id.clone()).and_modify(|existing| *existing = (*existing).max(t.removed_at)).or_insert(t.removed_at);
        }
    }

    let mut contacts_to_keep = Vec::new();
    for contact in inventory.contacts.drain(..) {
        if let Some(&removed_at) = tombstone_map.get(&contact.contact_id)
            && contact.accepted_at_unix_seconds <= removed_at
        {
            report.removed_contact_ids.push(contact.contact_id);
            continue;
        }
        contacts_to_keep.push(contact);
    }
    inventory.contacts = contacts_to_keep;

    // 2. Process snapshot contacts: re-verify and restore valid contacts.
    for entry in &snapshot.contacts {
        let contact_id = match entry.resolved_contact_id() {
            Ok(id) => id,
            Err(e) => {
                report.failed_contacts.push(TzapContactSnapshotRestoreFailure { contact_id: "unknown".to_owned(), display_name: None, error: e.to_string() });
                continue;
            }
        };

        // If a tombstone in the snapshot is newer, do not restore this contact.
        if let Some(&removed_at) = tombstone_map.get(&contact_id)
            && removed_at >= entry.accepted_at
        {
            continue;
        }

        // If local inventory already holds a newer or equal version of this contact, keep local.
        if let Some(existing) = inventory.contacts.iter_mut().find(|c| c.contact_id == contact_id) {
            if existing.accepted_at_unix_seconds > entry.accepted_at {
                continue;
            }
            if existing.accepted_at_unix_seconds == entry.accepted_at {
                // If local has alias and snapshot does not, keep local alias.
                if existing.local_alias.is_some() && entry.local_alias.is_none() {
                    continue;
                }
            }
        }

        // Re-verify the card (design §8.3: "restore re-verifies, but does not re-interrogate").
        match contact_card::verify_tzap_contact_card(&entry.card, options) {
            Ok(verified) => {
                let record = TzapContactRecord {
                    contact_id: verified.recipient_public_key_fingerprint.clone(),
                    display_name: verified.display_name,
                    signing_certificate_sha256: verified.signing_certificate_sha256,
                    recipient_public_key_fingerprint: verified.recipient_public_key_fingerprint,
                    trust_anchor_type: verified.trust_anchor_type,
                    source: String::new(),
                    verification_state: verified.verification_state,
                    missing_status_caveat: verified.missing_status_caveat,
                    contact_card_payload: verified.payload,
                    accepted_at_unix_seconds: entry.accepted_at,
                    local_alias: entry.local_alias.clone(),
                    card: Some(entry.card.clone()),
                };
                inventory.contacts.retain(|c| c.contact_id != record.contact_id);
                inventory.contacts.push(record.clone());
                report.restored_contacts.push(record);
            }
            Err(error) => {
                let display_name = entry.card.pointer("/payload/display_name").and_then(Value::as_str).map(str::to_owned);
                report.failed_contacts.push(TzapContactSnapshotRestoreFailure { contact_id, display_name, error: error.to_string() });
            }
        }
    }

    // 3. Persist the merged tombstone set so a later build_contact_snapshot on
    //    this device (§8.3) re-uploads removals learned from this restore too,
    //    not only ones made locally.
    inventory.removed_contacts = tombstone_map.into_iter().map(|(contact_id, removed_at)| TzapContactTombstone { contact_id, removed_at }).collect();

    store.save_inventory(account_key, inventory)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_card::{export_tzap_contact_card, import_tzap_contact_card};
    use crate::local_identity_store::InMemoryTzapLocalIdentityStore;

    #[test]
    fn prune_tombstones_drops_entries_older_than_one_year() {
        let now = 2_000_000_000;
        let mut tombstones = vec![
            TzapContactTombstone { contact_id: "recent".to_owned(), removed_at: now - 100 },
            TzapContactTombstone { contact_id: "borderline".to_owned(), removed_at: now - TOMBSTONE_RETENTION_SECONDS },
            TzapContactTombstone { contact_id: "expired".to_owned(), removed_at: now - TOMBSTONE_RETENTION_SECONDS - 1 },
            TzapContactTombstone { contact_id: "very_old".to_owned(), removed_at: now - 40_000_000 },
        ];

        prune_tombstones(&mut tombstones, now);
        let ids: Vec<_> = tombstones.iter().map(|t| t.contact_id.as_str()).collect();
        assert_eq!(ids, vec!["recent", "borderline"]);
    }

    #[test]
    fn build_snapshot_excludes_unverified_bare_keys() {
        let mut inventory = crate::local_identity_store::TzapLocalIdentityInventory::empty();
        inventory.contacts.push(crate::local_identity_store::TzapContactRecord {
            contact_id: crate::trust::sha256_identifier(&[0x01]),
            display_name: "Unverified key".to_owned(),
            signing_certificate_sha256: crate::trust::sha256_identifier(&[0x02]),
            recipient_public_key_fingerprint: crate::trust::sha256_identifier(&[0x01]),
            trust_anchor_type: crate::trust::TzapTrustAnchorType::Untrusted,
            source: String::new(),
            verification_state: crate::trust::TzapVerificationState::NotRecorded,
            missing_status_caveat: true,
            contact_card_payload: json!({"unverified": true}),
            accepted_at_unix_seconds: 100,
            local_alias: None,
            card: None,
        });

        let snapshot = build_contact_snapshot(&inventory, &[], 200).unwrap();
        assert!(snapshot.contacts.is_empty());
    }

    #[test]
    fn merge_contact_snapshots_union_and_tombstone_precedence() {
        let now = 1_000_000;

        let snapshot_a = TzapContactSnapshot::new(
            vec![
                TzapContactSnapshotEntry {
                    contact_id: Some("c1".to_owned()),
                    card: json!({"payload": {"recipient_key_fingerprint": "c1"}}),
                    local_alias: Some("Alice Work".to_owned()),
                    accepted_at: 100,
                },
                TzapContactSnapshotEntry {
                    contact_id: Some("c2".to_owned()),
                    card: json!({"payload": {"recipient_key_fingerprint": "c2"}}),
                    local_alias: None,
                    accepted_at: 100,
                },
            ],
            vec![TzapContactTombstone { contact_id: "c3".to_owned(), removed_at: 50 }],
        );

        let snapshot_b = TzapContactSnapshot::new(
            vec![
                // c2 deleted on device B at t=150 (newer than acceptance t=100) -> tombstone wins
                // c3 re-accepted on device B at t=200 (newer than tombstone t=50) -> acceptance wins
                TzapContactSnapshotEntry {
                    contact_id: Some("c3".to_owned()),
                    card: json!({"payload": {"recipient_key_fingerprint": "c3"}}),
                    local_alias: Some("Charlie Mobile".to_owned()),
                    accepted_at: 200,
                },
                TzapContactSnapshotEntry {
                    contact_id: Some("c4".to_owned()),
                    card: json!({"payload": {"recipient_key_fingerprint": "c4"}}),
                    local_alias: None,
                    accepted_at: 120,
                },
            ],
            vec![TzapContactTombstone { contact_id: "c2".to_owned(), removed_at: 150 }],
        );

        let merged = merge_contact_snapshots(&snapshot_a, &snapshot_b, now).unwrap();

        let live_ids: Vec<_> = merged.contacts.iter().map(|c| c.contact_id.as_deref().unwrap()).collect();
        assert_eq!(live_ids, vec!["c1", "c3", "c4"]);

        let removed_ids: Vec<_> = merged.removed.iter().map(|t| t.contact_id.as_str()).collect();
        assert_eq!(removed_ids, vec!["c2"]);

        // Verify c1 preserved its alias
        let c1 = merged.contacts.iter().find(|c| c.contact_id.as_deref() == Some("c1")).unwrap();
        assert_eq!(c1.local_alias.as_deref(), Some("Alice Work"));
    }

    #[test]
    fn merge_contact_snapshots_prunes_stale_tombstones() {
        let now = 100_000_000;
        let stale_time = now - TOMBSTONE_RETENTION_SECONDS - 500;
        let recent_time = now - 500;

        let a = TzapContactSnapshot::new(vec![], vec![TzapContactTombstone { contact_id: "stale".to_owned(), removed_at: stale_time }]);
        let b = TzapContactSnapshot::new(vec![], vec![TzapContactTombstone { contact_id: "recent".to_owned(), removed_at: recent_time }]);

        let merged = merge_contact_snapshots(&a, &b, now).unwrap();
        assert_eq!(merged.removed.len(), 1);
        assert_eq!(merged.removed[0].contact_id, "recent");
    }

    #[test]
    fn build_and_apply_snapshot_round_trip() {
        use crate::contact_card::tests::ContactFixture;

        let fixture = ContactFixture::new();
        let mut source_store = fixture.store();
        let account_key = crate::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;

        // 1. Export a signed contact card.
        let export_req = fixture.export_request();
        let card = export_tzap_contact_card(&source_store, &export_req).unwrap();

        // 2. Import into source store as contact.
        let import_options = fixture.import_options();
        let imported = import_tzap_contact_card(&mut source_store, account_key, &card, &import_options, Some(1_050)).unwrap();
        // Give it an alias
        let mut inv = source_store.load_inventory(account_key).unwrap();
        inv.contacts[0].local_alias = Some("Ada Work".to_owned());
        source_store.save_inventory(account_key, inv).unwrap();

        // 3. Build snapshot from source store.
        let inv = source_store.load_inventory(account_key).unwrap();
        let tombstones = vec![TzapContactTombstone { contact_id: "old-contact-9".to_owned(), removed_at: 950 }];
        let snapshot = build_contact_snapshot(&inv, &tombstones, 1_060).unwrap();
        assert_eq!(snapshot.format, CONTACT_SNAPSHOT_FORMAT_PLAIN);
        assert_eq!(snapshot.contacts.len(), 1);
        assert_eq!(snapshot.contacts[0].local_alias.as_deref(), Some("Ada Work"));
        assert_eq!(snapshot.removed.len(), 1);

        // 4. Apply snapshot onto a completely fresh destination store.
        let mut dest_store = InMemoryTzapLocalIdentityStore::new();
        let report = apply_contact_snapshot(&mut dest_store, account_key, &snapshot, &import_options, 1_070).unwrap();
        assert_eq!(report.restored_contacts.len(), 1);
        assert_eq!(report.failed_contacts.len(), 0);
        assert_eq!(report.restored_contacts[0].display_name, "Ada Lovelace");
        assert_eq!(report.restored_contacts[0].local_alias.as_deref(), Some("Ada Work"));

        let dest_inv = dest_store.load_inventory(account_key).unwrap();
        assert_eq!(dest_inv.contacts.len(), 1);
        assert_eq!(dest_inv.contacts[0].contact_id, imported.contact_id);
    }

    #[test]
    fn apply_snapshot_rejects_tampered_card_and_reports_failure() {
        use crate::contact_card::tests::ContactFixture;

        let fixture = ContactFixture::new();
        let import_options = fixture.import_options();
        let mut dest_store = InMemoryTzapLocalIdentityStore::new();
        let account_key = crate::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;

        let forged_card = json!({
            "version": 1,
            "signature_algorithm": "ECDSA-P256-SHA256",
            "signature": URL_SAFE_NO_PAD.encode(vec![0u8; 64]),
            "payload": {
                "contact_card_version": 1,
                "recipient_key_algorithm": "P256-SPKI-DER",
                "recipient_public_key": URL_SAFE_NO_PAD.encode(&fixture.recipient_key.public_key_der),
                "recipient_key_fingerprint": fixture.recipient_key.public_key_fingerprint.clone(),
                "display_name": "Forged User",
                "device_label": "Hacker Phone",
                "created_at_unix_seconds": 1_000,
                "signing_certificate_sha256": fixture.certificate.certificate_sha256.clone(),
                "signing_certificate_der": URL_SAFE_NO_PAD.encode(&fixture.certificate.leaf_certificate_der),
                "intermediate_chain_der": [
                    URL_SAFE_NO_PAD.encode(&fixture.platform_der),
                    URL_SAFE_NO_PAD.encode(&fixture.root_der)
                ]
            }
        });

        let snapshot = TzapContactSnapshot::new(
            vec![TzapContactSnapshotEntry {
                contact_id: Some(fixture.recipient_key.public_key_fingerprint.clone()),
                card: forged_card,
                local_alias: None,
                accepted_at: 1_000,
            }],
            vec![],
        );

        let report = apply_contact_snapshot(&mut dest_store, account_key, &snapshot, &import_options, 1_050).unwrap();
        assert_eq!(report.restored_contacts.len(), 0);
        assert_eq!(report.failed_contacts.len(), 1);
        assert_eq!(report.failed_contacts[0].contact_id, fixture.recipient_key.public_key_fingerprint);
        assert_eq!(report.failed_contacts[0].display_name.as_deref(), Some("Forged User"));

        // Store inventory remains clean!
        let inv = dest_store.load_inventory(account_key).unwrap();
        assert!(inv.contacts.is_empty());
    }

    #[test]
    fn apply_snapshot_tombstone_removes_older_local_contact() {
        use crate::contact_card::tests::ContactFixture;

        let fixture = ContactFixture::new();
        let import_options = fixture.import_options();
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let account_key = crate::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;

        let mut inv = TzapLocalIdentityInventory::empty();
        inv.contacts.push(TzapContactRecord {
            contact_id: "c-to-delete".to_owned(),
            display_name: "Bob".to_owned(),
            signing_certificate_sha256: format!("sha256:{}", "a".repeat(64)),
            recipient_public_key_fingerprint: format!("sha256:{}", "b".repeat(64)),
            trust_anchor_type: crate::trust::TzapTrustAnchorType::OfficialTzap,
            source: String::new(),
            verification_state: crate::trust::TzapVerificationState::CryptographicallyIntactOffline,
            missing_status_caveat: false,
            contact_card_payload: json!({}),
            accepted_at_unix_seconds: 1_000,
            local_alias: None,
            card: None,
        });
        store.save_inventory(account_key, inv).unwrap();

        let snapshot = TzapContactSnapshot::new(
            vec![],
            vec![TzapContactTombstone {
                contact_id: "c-to-delete".to_owned(),
                removed_at: 1_500, // Newer than 1_000
            }],
        );

        let report = apply_contact_snapshot(&mut store, account_key, &snapshot, &import_options, 1_600).unwrap();
        assert_eq!(report.removed_contact_ids, vec!["c-to-delete"]);

        let updated_inv = store.load_inventory(account_key).unwrap();
        assert!(updated_inv.contacts.is_empty());
    }

    #[test]
    fn local_removal_tombstone_survives_snapshot_round_trip_and_is_not_resurrected() {
        // Device A removes a contact locally (recording a tombstone in its own
        // inventory, as mobile-core's remove_contact will do), then uploads a
        // snapshot. Device B has a stale copy of the same contact from before
        // the removal and hasn't synced since. Merging A's and B's snapshots
        // and applying the result to B must drop the contact, not resurrect
        // it -- and the tombstone must persist into B's own inventory so a
        // later snapshot built from B still carries it (design §8.3, §8.4).
        let contact_id = "c-shared".to_owned();
        let live_contact = |accepted_at: u64| TzapContactRecord {
            contact_id: contact_id.clone(),
            display_name: "Shared Contact".to_owned(),
            signing_certificate_sha256: format!("sha256:{}", "a".repeat(64)),
            recipient_public_key_fingerprint: format!("sha256:{}", "b".repeat(64)),
            trust_anchor_type: crate::trust::TzapTrustAnchorType::OfficialTzap,
            source: String::new(),
            verification_state: crate::trust::TzapVerificationState::CryptographicallyIntactOffline,
            missing_status_caveat: false,
            contact_card_payload: json!({"payload": {"recipient_key_fingerprint": contact_id}}),
            accepted_at_unix_seconds: accepted_at,
            local_alias: None,
            card: None,
        };

        // Device A: accepted at t=1000, removed locally at t=2000.
        let mut inv_a = TzapLocalIdentityInventory::empty();
        inv_a.contacts.push(live_contact(1_000));
        inv_a.removed_contacts.push(TzapContactTombstone { contact_id: contact_id.clone(), removed_at: 2_000 });
        let snapshot_a = build_contact_snapshot(&inv_a, &inv_a.removed_contacts, 2_500).unwrap();
        assert!(snapshot_a.contacts.is_empty(), "build_contact_snapshot must not export a tombstoned contact");
        assert_eq!(snapshot_a.removed.len(), 1);

        // Device B: still holds the pre-removal acceptance, hasn't synced.
        let mut store_b = InMemoryTzapLocalIdentityStore::new();
        let account_key = crate::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;
        let mut inv_b = TzapLocalIdentityInventory::empty();
        inv_b.contacts.push(live_contact(1_000));
        store_b.save_inventory(account_key, inv_b.clone()).unwrap();
        let snapshot_b = build_contact_snapshot(&inv_b, &inv_b.removed_contacts, 2_500).unwrap();
        assert_eq!(snapshot_b.contacts.len(), 1, "device B's own snapshot still carries the stale contact");

        let merged = merge_contact_snapshots(&snapshot_a, &snapshot_b, 2_500).unwrap();
        assert!(merged.contacts.is_empty(), "tombstone (t=2000) beats the older acceptance (t=1000)");
        assert_eq!(merged.removed.len(), 1);

        let fixture = crate::contact_card::tests::ContactFixture::new();
        let import_options = fixture.import_options();
        let report = apply_contact_snapshot(&mut store_b, account_key, &merged, &import_options, 2_600).unwrap();
        assert_eq!(report.removed_contact_ids, vec![contact_id.clone()]);

        let updated_inv_b = store_b.load_inventory(account_key).unwrap();
        assert!(updated_inv_b.contacts.is_empty(), "the contact must not be resurrected on device B");
        assert_eq!(
            updated_inv_b.removed_contacts.iter().map(|t| t.contact_id.as_str()).collect::<Vec<_>>(),
            vec![contact_id.as_str()],
            "the tombstone must persist into B's inventory for the next snapshot build"
        );
    }

    #[test]
    fn snapshot_json_roundtrip_with_alias_fields() {
        let json_str = r#"{
            "format": "plain",
            "version": 1,
            "contacts": [
                {
                    "contact_id": "contact-abc",
                    "card": {"payload": {"recipient_key_fingerprint": "contact-abc"}},
                    "local_alias": "My Friend",
                    "accepted_at_unix_seconds": 123456
                }
            ],
            "removed": [
                {
                    "contact_id": "contact-xyz",
                    "removed_at_unix_seconds": 789101
                }
            ]
        }"#;

        let parsed: TzapContactSnapshot = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed.format, "plain");
        assert_eq!(parsed.contacts[0].contact_id.as_deref(), Some("contact-abc"));
        assert_eq!(parsed.contacts[0].accepted_at, 123_456);
        assert_eq!(parsed.removed[0].contact_id, "contact-xyz");
        assert_eq!(parsed.removed[0].removed_at, 789_101);

        let serialized = serde_json::to_string(&parsed).unwrap();
        let roundtrip: TzapContactSnapshot = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, roundtrip);
    }
}
