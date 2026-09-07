//! Signed TZAP contact-card import and export.

use crate::device_identity::RECIPIENT_ENCRYPTION_KEY_ALGORITHM;
use crate::jcs;
use crate::local_identity_store::{
    TzapContactRecord, TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityStore,
    TzapLocalIdentityStoreError, TzapRecipientEncryptionKeyRecord,
};
use crate::p256_signature;
use crate::trust::{self, TzapCertificateProfileOptions, TzapRootPinSet, TzapTrustAnchorType, TzapVerificationState};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde_json::{Map, Value, json};
use std::fmt;

pub const CONTACT_CARD_CONTAINER_VERSION: u64 = 1;
pub const CONTACT_CARD_PAYLOAD_VERSION: u64 = 1;
pub const CONTACT_CARD_SIGNATURE_ALGORITHM: &str = "ECDSA-P256-SHA256";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapContactCardExportRequest {
    pub account_key: String,
    pub recipient_key_id: String,
    pub certificate_id: String,
    pub display_name: String,
    pub device_label: String,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: Option<u64>,
    pub compact: bool,
}

#[derive(Debug, Clone)]
pub struct TzapContactCardImportOptions<'a> {
    pub verifier_time_unix_seconds: i64,
    pub official_root_pins: &'a TzapRootPinSet,
    pub official_root_certificates_der: Vec<Vec<u8>>,
    pub custom_trust_root_sha256: Vec<String>,
    pub custom_trust_root_certificates_der: Vec<Vec<u8>>,
    pub certificate_profile_options: TzapCertificateProfileOptions,
    pub intermediate_resolver: Option<&'a (dyn trust::TzapIntermediateResolver + 'a)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapVerifiedContactCard {
    pub payload: Value,
    pub trust_anchor_type: TzapTrustAnchorType,
    pub verification_state: TzapVerificationState,
    pub missing_status_caveat: bool,
    pub signing_certificate_sha256: String,
    pub recipient_public_key_fingerprint: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAcceptedContactRecipient {
    pub contact_id: String,
    pub recipient_public_key_der: Vec<u8>,
    pub trust_anchor_type: TzapTrustAnchorType,
    pub verification_state: TzapVerificationState,
    pub missing_status_caveat: bool,
}

#[derive(Debug)]
pub enum TzapContactCardError {
    Store(TzapLocalIdentityStoreError),
    InvalidField { field: &'static str },
    MissingRecord { field: &'static str },
    CertificateNotActive,
    Canonicalization(String),
    Crypto(String),
    CertificateChain(String),
    AcceptanceRequired,
    IntermediateCacheMiss { issuer_key_identifier: String, reason: String },
}

impl fmt::Display for TzapContactCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "contact-card store operation failed: {error}"),
            Self::InvalidField { field } => write!(f, "contact-card field is invalid: {field}"),
            Self::MissingRecord { field } => write!(f, "contact-card record is missing: {field}"),
            Self::CertificateNotActive => {
                write!(f, "contact-card signing certificate is not active")
            }
            Self::Canonicalization(reason) => {
                write!(f, "contact-card canonicalization failed: {reason}")
            }
            Self::Crypto(reason) => write!(f, "contact-card crypto failed: {reason}"),
            Self::CertificateChain(reason) => {
                write!(f, "contact-card certificate rejected: {reason}")
            }
            Self::AcceptanceRequired => {
                write!(f, "contact-card import requires explicit acceptance")
            }
            Self::IntermediateCacheMiss { issuer_key_identifier, reason } => {
                write!(f, "intermediate certificate for issuer '{issuer_key_identifier}' is missing: {reason}")
            }
        }
    }
}

impl std::error::Error for TzapContactCardError {}

impl From<TzapLocalIdentityStoreError> for TzapContactCardError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

pub fn export_tzap_contact_card(store: &impl TzapLocalIdentityStore, request: &TzapContactCardExportRequest) -> Result<Value, TzapContactCardError> {
    validate_export_request(request)?;
    let inventory = store.load_inventory(&request.account_key)?;
    let recipient_key = inventory
        .recipient_encryption_keys
        .iter()
        .find(|record| record.key_id == request.recipient_key_id)
        .ok_or(TzapContactCardError::MissingRecord { field: "recipient_key_id" })?;
    let certificate = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == request.certificate_id)
        .ok_or(TzapContactCardError::MissingRecord { field: "certificate_id" })?;
    if certificate.state != TzapLocalCertificateState::Active {
        return Err(TzapContactCardError::CertificateNotActive);
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|record| record.key_id == certificate.signing_key_id)
        .ok_or(TzapContactCardError::MissingRecord { field: "signing_key_id" })?;
    let payload = contact_card_payload(request, recipient_key, certificate);
    let signature = sign_contact_card_payload(signing_key, &payload)?;
    Ok(json!({
        "version": CONTACT_CARD_CONTAINER_VERSION,
        "payload": payload,
        "signature_algorithm": CONTACT_CARD_SIGNATURE_ALGORITHM,
        "signature": URL_SAFE_NO_PAD.encode(signature),
    }))
}

/// Verifies a contact card's chain and signature, always recording the
/// offline verification state. See
/// [`verify_tzap_contact_card_with_missing_status_caveat`] for the
/// parameterized form; this wrapper always reports the caveat (this
/// verification itself never performs an online status check).
///
/// # Errors
///
/// Returns [`TzapContactCardError`] when the card is malformed, the chain is
/// rejected, or the signature does not verify.
pub fn verify_tzap_contact_card(card: &Value, options: &TzapContactCardImportOptions<'_>) -> Result<TzapVerifiedContactCard, TzapContactCardError> {
    verify_tzap_contact_card_with_missing_status_caveat(card, options, true)
}

/// Verifies a contact card's chain and signature, recording the offline
/// verification state.
///
/// `missing_status_caveat` records whether an online certificate-status check
/// was not performed for this card. Callers should pass `false` only when
/// they independently performed a status lookup (for example via
/// the status verifier and it succeeded; `true` (the default, used by
/// [`verify_tzap_contact_card`]) is the honest value for any verification
/// that does not include such a check, so downstream consumers never mistake
/// a card whose status is unknown for one that was checked.
///
/// # Errors
///
/// Returns [`TzapContactCardError`] when the card is malformed, the chain is
/// rejected, or the signature does not verify.
pub fn verify_tzap_contact_card_with_missing_status_caveat(
    card: &Value,
    options: &TzapContactCardImportOptions<'_>,
    missing_status_caveat: bool,
) -> Result<TzapVerifiedContactCard, TzapContactCardError> {
    let object = json_object(card, "$")?;
    require_u64(object, "version", CONTACT_CARD_CONTAINER_VERSION)?;
    require_string_equals(object, "signature_algorithm", CONTACT_CARD_SIGNATURE_ALGORITHM)?;
    let payload = json_field(object, "payload")?.clone();
    let payload_object = json_object(&payload, "payload")?;
    require_u64(payload_object, "contact_card_version", CONTACT_CARD_PAYLOAD_VERSION)?;
    require_string_equals(payload_object, "recipient_key_algorithm", RECIPIENT_ENCRYPTION_KEY_ALGORITHM)?;
    if let Some(expires_at) = optional_u64(payload_object, "expires_at_unix_seconds")?
        && options.verifier_time_unix_seconds >= expires_at.cast_signed()
    {
        return Err(TzapContactCardError::InvalidField { field: "expires_at_unix_seconds" });
    }

    let signature = decode_base64url(&json_string(object, "signature")?, "signature")?;
    let leaf_der = decode_base64url(&json_string(payload_object, "signing_certificate_der")?, "signing_certificate_der")?;
    let mut intermediate_chain_der = match payload_object.get("intermediate_chain_der") {
        Some(value) => decode_der_array(value)?,
        None => Vec::new(),
    };
    #[allow(clippy::collapsible_if)]
    if intermediate_chain_der.is_empty() {
        if let Some(leaf_aki) = trust::extract_authority_key_identifier(&leaf_der) {
            let aki_b64 = URL_SAFE_NO_PAD.encode(&leaf_aki);
            if let Some(resolver) = options.intermediate_resolver {
                match resolver.resolve_intermediate(&leaf_aki) {
                    Ok(Some(intermediate_der)) => {
                        intermediate_chain_der.push(intermediate_der);
                    }
                    Ok(None) => {
                        return Err(TzapContactCardError::IntermediateCacheMiss {
                            issuer_key_identifier: aki_b64,
                            reason: "intermediate certificate not found in cache or online".to_owned(),
                        });
                    }
                    Err(error) => {
                        return Err(TzapContactCardError::IntermediateCacheMiss { issuer_key_identifier: aki_b64, reason: error.to_string() });
                    }
                }
            } else {
                return Err(TzapContactCardError::IntermediateCacheMiss {
                    issuer_key_identifier: aki_b64,
                    reason: "no intermediate resolver configured".to_owned(),
                });
            }
        }
    }
    let chain_der = contact_chain_der(&leaf_der, &intermediate_chain_der);
    let validation = validate_contact_card_chain(&chain_der, options)?;
    let signing_certificate_sha256 = trust::certificate_sha256_identifier_for_der(&leaf_der);
    if signing_certificate_sha256 != json_string(payload_object, "signing_certificate_sha256")? {
        return Err(TzapContactCardError::InvalidField { field: "signing_certificate_sha256" });
    }
    let recipient_public_key = decode_base64url(&json_string(payload_object, "recipient_public_key")?, "recipient_public_key")?;
    let recipient_public_key_fingerprint = trust::certificate_sha256_identifier_for_der(&recipient_public_key);
    if recipient_public_key_fingerprint != json_string(payload_object, "recipient_key_fingerprint")? {
        return Err(TzapContactCardError::InvalidField { field: "recipient_key_fingerprint" });
    }

    let canonical_payload = jcs::canonicalize_json_bytes(&payload).map_err(|error| TzapContactCardError::Canonicalization(format!("{error:?}")))?;
    let public_key =
        X509::from_der(&leaf_der).and_then(|certificate| certificate.public_key()).map_err(|error| TzapContactCardError::Crypto(error.to_string()))?;
    let verified = p256_signature::verify_p256_sha256_p1363(&public_key, &canonical_payload, &signature)
        .map_err(|error| TzapContactCardError::Crypto(format!("{error:?}")))?;
    if !verified {
        return Err(TzapContactCardError::Crypto("contact-card signature did not verify".to_owned()));
    }
    let display_name = json_string(payload_object, "display_name")?;

    Ok(TzapVerifiedContactCard {
        payload,
        trust_anchor_type: validation.trust_anchor_type,
        verification_state: TzapVerificationState::CryptographicallyIntactOffline,
        missing_status_caveat,
        signing_certificate_sha256,
        recipient_public_key_fingerprint,
        display_name,
    })
}

/// Imports a verified contact card into the store.
///
/// `accepted_at_unix_seconds` doubles as the consent flag: `None` means the
/// caller has not obtained explicit user acceptance and the import is
/// refused ([`TzapContactCardError::AcceptanceRequired`]); `Some(timestamp)`
/// records the moment of acceptance. A timestamp is used instead of a
/// separate boolean so the stored record carries the consent evidence itself
/// rather than a bare flag that cannot be audited.
///
/// Import replaces an existing contact with the same `contact_id`
/// (deterministic from the recipient public key), silently overwriting the
/// previous record with the freshly verified one. Re-importing a card for the
/// same recipient therefore refreshes the stored contact; callers that need
/// to detect replacement must compare the previous inventory themselves.
///
/// # Errors
///
/// Returns [`TzapContactCardError`] when acceptance is missing, the card does
/// not verify, or the store write fails.
pub fn import_tzap_contact_card(
    store: &mut impl TzapLocalIdentityStore,
    account_key: &str,
    card: &Value,
    options: &TzapContactCardImportOptions<'_>,
    accepted_at_unix_seconds: Option<u64>,
) -> Result<TzapContactRecord, TzapContactCardError> {
    let Some(accepted_at_unix_seconds) = accepted_at_unix_seconds else {
        return Err(TzapContactCardError::AcceptanceRequired);
    };
    let verified = verify_tzap_contact_card(card, options)?;
    let mut inventory = store.load_inventory(account_key)?;
    let contact = TzapContactRecord {
        contact_id: verified.recipient_public_key_fingerprint.clone(),
        display_name: verified.display_name,
        signing_certificate_sha256: verified.signing_certificate_sha256,
        recipient_public_key_fingerprint: verified.recipient_public_key_fingerprint,
        trust_anchor_type: verified.trust_anchor_type,
        verification_state: verified.verification_state,
        missing_status_caveat: verified.missing_status_caveat,
        contact_card_payload: verified.payload,
        accepted_at_unix_seconds,
        // Display metadata only, set by the importer afterward -- import
        // itself never invents or carries one over (design §4).
        local_alias: None,
        card: Some(card.clone()),
    };
    inventory.contacts.retain(|existing| existing.contact_id != contact.contact_id);
    inventory.contacts.push(contact.clone());
    store.save_inventory(account_key, inventory)?;
    Ok(contact)
}

pub fn accepted_contact_recipients(
    store: &impl TzapLocalIdentityStore,
    account_key: &str,
    contact_ids: &[String],
    now_unix_seconds: u64,
) -> Result<Vec<TzapAcceptedContactRecipient>, TzapContactCardError> {
    if contact_ids.is_empty() {
        return Err(TzapContactCardError::InvalidField { field: "contact_ids" });
    }
    let inventory = store.load_inventory(account_key)?;
    contact_ids
        .iter()
        .map(|contact_id| {
            let contact =
                inventory.contacts.iter().find(|record| &record.contact_id == contact_id).ok_or(TzapContactCardError::MissingRecord { field: "contact_id" })?;
            let payload_object = json_object(&contact.contact_card_payload, "contact_card_payload")?;
            if let Some(expires_at) = optional_u64(payload_object, "expires_at_unix_seconds")?
                && now_unix_seconds >= expires_at
            {
                return Err(TzapContactCardError::InvalidField { field: "expires_at_unix_seconds" });
            }
            let recipient_public_key_der = decode_base64url(&json_string(payload_object, "recipient_public_key")?, "recipient_public_key")?;
            Ok(TzapAcceptedContactRecipient {
                contact_id: contact.contact_id.clone(),
                recipient_public_key_der,
                trust_anchor_type: contact.trust_anchor_type,
                verification_state: contact.verification_state,
                missing_status_caveat: contact.missing_status_caveat,
            })
        })
        .collect()
}

fn validate_export_request(request: &TzapContactCardExportRequest) -> Result<(), TzapContactCardError> {
    if request.account_key.is_empty() {
        return Err(TzapContactCardError::InvalidField { field: "account_key" });
    }
    if request.display_name.is_empty() {
        return Err(TzapContactCardError::InvalidField { field: "display_name" });
    }
    if request.device_label.is_empty() {
        return Err(TzapContactCardError::InvalidField { field: "device_label" });
    }
    if let Some(expires_at) = request.expires_at_unix_seconds
        && expires_at <= request.created_at_unix_seconds
    {
        return Err(TzapContactCardError::InvalidField { field: "expires_at_unix_seconds" });
    }
    Ok(())
}

fn contact_card_payload(
    request: &TzapContactCardExportRequest,
    recipient_key: &TzapRecipientEncryptionKeyRecord,
    certificate: &TzapEnrolledCertificateRecord,
) -> Value {
    let mut payload = json!({
        "contact_card_version": CONTACT_CARD_PAYLOAD_VERSION,
        "recipient_key_algorithm": recipient_key.algorithm,
        "recipient_public_key": URL_SAFE_NO_PAD.encode(&recipient_key.public_key_der),
        "recipient_key_fingerprint": recipient_key.public_key_fingerprint,
        "display_name": request.display_name,
        "device_label": request.device_label,
        "created_at_unix_seconds": request.created_at_unix_seconds,
        "expires_at_unix_seconds": request.expires_at_unix_seconds,
        "signing_certificate_sha256": certificate.certificate_sha256,
        "signing_certificate_der": URL_SAFE_NO_PAD.encode(&certificate.leaf_certificate_der),
        "signing_public_metadata": {
            "version": certificate.public_metadata.version,
            "public_signer_id": certificate.public_metadata.public_signer_id,
            "public_org_id": certificate.public_metadata.public_org_id,
            "public_device_id": certificate.public_metadata.public_device_id,
            "assurance_level": certificate.public_metadata.assurance_level.as_str(),
            "policy_oid": certificate.public_metadata.policy_oid,
        },
    });
    if !request.compact {
        payload["intermediate_chain_der"] =
            json!(trust::public_intermediate_chain_der(&certificate.intermediate_chain_der).iter().map(|der| URL_SAFE_NO_PAD.encode(der)).collect::<Vec<_>>());
    }
    payload
}

fn sign_contact_card_payload(
    signing_key: &TzapDeviceSigningKeyRecord,
    payload: &Value,
) -> Result<[u8; p256_signature::P256_P1363_SIGNATURE_LENGTH], TzapContactCardError> {
    let private_key =
        PKey::<Private>::private_key_from_der(signing_key.private_key_der.expose_secret()).map_err(|error| TzapContactCardError::Crypto(error.to_string()))?;
    let canonical_payload = jcs::canonicalize_json_bytes(payload).map_err(|error| TzapContactCardError::Canonicalization(format!("{error:?}")))?;
    p256_signature::sign_p256_sha256_p1363(&private_key, &canonical_payload).map_err(|error| TzapContactCardError::Crypto(format!("{error:?}")))
}

fn validate_contact_card_chain(
    embedded_chain_der: &[Vec<u8>],
    options: &TzapContactCardImportOptions<'_>,
) -> Result<trust::TzapCertificateProfileValidation, TzapContactCardError> {
    let mut official_error = None;
    for chain_der in crate::trust::candidate_chains(embedded_chain_der, &options.official_root_certificates_der) {
        match trust::validate_official_tzap_certificate_chain_der(&chain_der, options.official_root_pins, &options.certificate_profile_options) {
            Ok(validation) => return Ok(validation),
            Err(error) => official_error = Some(error),
        }
    }

    let mut custom_error = None;
    for chain_der in crate::trust::candidate_chains(embedded_chain_der, &options.custom_trust_root_certificates_der) {
        let Some(root_sha256) = chain_der.last().map(Vec::as_slice).map(trust::certificate_sha256_identifier_for_der) else {
            continue;
        };
        if !options.custom_trust_root_sha256.iter().any(|configured| configured == &root_sha256) {
            continue;
        }
        match trust::validate_custom_tzap_certificate_chain_der(&chain_der, &options.certificate_profile_options) {
            Ok(validation) => return Ok(validation),
            Err(error) => custom_error = Some(error),
        }
    }

    let reason = custom_error
        .map(|error| error.to_string())
        .or_else(|| official_error.map(|error| error.to_string()))
        .unwrap_or_else(|| "root is not pinned official or configured custom trust".to_owned());
    Err(TzapContactCardError::CertificateChain(reason))
}

fn contact_chain_der(leaf_der: &[u8], intermediate_chain_der: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut chain = Vec::with_capacity(1 + intermediate_chain_der.len());
    chain.push(leaf_der.to_vec());
    chain.extend(intermediate_chain_der.iter().cloned());
    chain
}

// Thin typed wrappers over the shared json_util helpers; the extraction
// logic lives in json_util.
fn json_object<'a>(value: &'a Value, field: &'static str) -> Result<&'a Map<String, Value>, TzapContactCardError> {
    crate::json_util::json_object(value, field)
}

fn json_field<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a Value, TzapContactCardError> {
    crate::json_util::required_field(object, field)
}

fn json_string(object: &Map<String, Value>, field: &'static str) -> Result<String, TzapContactCardError> {
    crate::json_util::required_string(object, field)
}

fn optional_u64(object: &Map<String, Value>, field: &'static str) -> Result<Option<u64>, TzapContactCardError> {
    crate::json_util::optional_u64(object, field)
}

fn require_u64(object: &Map<String, Value>, field: &'static str, expected: u64) -> Result<(), TzapContactCardError> {
    if object.get(field).and_then(Value::as_u64) == Some(expected) { Ok(()) } else { Err(TzapContactCardError::InvalidField { field }) }
}

fn require_string_equals(object: &Map<String, Value>, field: &'static str, expected: &'static str) -> Result<(), TzapContactCardError> {
    if object.get(field).and_then(Value::as_str) == Some(expected) { Ok(()) } else { Err(TzapContactCardError::InvalidField { field }) }
}

fn decode_der_array(value: &Value) -> Result<Vec<Vec<u8>>, TzapContactCardError> {
    value
        .as_array()
        .ok_or(TzapContactCardError::InvalidField { field: "intermediate_chain_der" })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(TzapContactCardError::InvalidField { field: "intermediate_chain_der" })
                .and_then(|encoded| decode_base64url(encoded, "intermediate_chain_der"))
        })
        .collect()
}

fn decode_base64url(value: &str, field: &'static str) -> Result<Vec<u8>, TzapContactCardError> {
    crate::trust::decode_base64url_no_padding(value).map_err(|_| TzapContactCardError::InvalidField { field })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        TzapContactCardError, TzapContactCardExportRequest, TzapContactCardImportOptions, export_tzap_contact_card, import_tzap_contact_card,
        verify_tzap_contact_card,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr, generate_recipient_encryption_key};
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord,
        TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
    };
    use crate::test_support::x509_factory::*;
    use crate::trust::{self, TzapCertificateProfileOptions, TzapCertificatePublicMetadata, TzapRootPinSet};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use openssl::pkey::{PKey, Private};
    use serde_json::json;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    #[test]
    fn contact_card_exports_imports_after_explicit_acceptance() {
        let fixture = ContactFixture::new();
        let source_store = fixture.store();
        let card = export_tzap_contact_card(&source_store, &fixture.export_request()).unwrap();
        let options = fixture.import_options();
        let verified = verify_tzap_contact_card(&card, &options).unwrap();

        assert!(verified.missing_status_caveat);
        assert_eq!(verified.display_name, "Ada Lovelace");

        let mut fresh_store = InMemoryTzapLocalIdentityStore::new();
        assert!(matches!(
            import_tzap_contact_card(&mut fresh_store, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, &card, &options, None,),
            Err(TzapContactCardError::AcceptanceRequired)
        ));

        let contact = import_tzap_contact_card(&mut fresh_store, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, &card, &options, Some(1_000)).unwrap();
        assert_eq!(contact.display_name, "Ada Lovelace");
        assert_eq!(contact.trust_anchor_type, verified.trust_anchor_type);
        assert_eq!(contact.verification_state, verified.verification_state);
        assert!(contact.missing_status_caveat);
        assert_eq!(fresh_store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().contacts.len(), 1);
        let selected_recipients = super::accepted_contact_recipients(&fresh_store, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, &[contact.contact_id], 1_001).unwrap();
        assert_eq!(selected_recipients.len(), 1);
        assert!(selected_recipients[0].missing_status_caveat);
    }

    #[test]
    fn contact_card_compact_export_omits_intermediate_chain_der() {
        let fixture = ContactFixture::new();
        let source_store = fixture.store();
        let default_request = fixture.export_request();
        let default_card = export_tzap_contact_card(&source_store, &default_request).unwrap();
        assert!(default_card["payload"].get("intermediate_chain_der").is_some());

        let mut compact_request = fixture.export_request();
        compact_request.compact = true;
        let compact_card = export_tzap_contact_card(&source_store, &compact_request).unwrap();
        assert!(compact_card["payload"].get("intermediate_chain_der").is_none());

        // Compact export should be substantially smaller
        let default_json = serde_json::to_string(&default_card).unwrap();
        let compact_json = serde_json::to_string(&compact_card).unwrap();
        assert!(compact_json.len() < default_json.len(), "compact {compact_json} should be smaller than default {default_json}");
    }

    #[test]
    fn contact_card_rejects_tampered_payload_certificate_and_signature() {
        let fixture = ContactFixture::new();
        let source_store = fixture.store();
        let options = fixture.import_options();
        let card = export_tzap_contact_card(&source_store, &fixture.export_request()).unwrap();

        let mut tampered_name = card.clone();
        tampered_name["payload"]["display_name"] = json!("Mallory");
        assert!(verify_tzap_contact_card(&tampered_name, &options).is_err());

        let mut tampered_key = card.clone();
        tampered_key["payload"]["recipient_public_key"] = json!(URL_SAFE_NO_PAD.encode([0x42; 65]));
        assert!(verify_tzap_contact_card(&tampered_key, &options).is_err());

        let mut tampered_signature = card.clone();
        tampered_signature["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        assert!(verify_tzap_contact_card(&tampered_signature, &options).is_err());
    }

    #[test]
    fn contact_card_compact_card_verifies_with_intermediate_cache() {
        let fixture = ContactFixture::new();
        let source_store = fixture.store();
        let mut compact_request = fixture.export_request();
        compact_request.compact = true;
        let compact_card = export_tzap_contact_card(&source_store, &compact_request).unwrap();

        // 1. Without intermediate resolver: fails with IntermediateCacheMiss
        let options_no_resolver = fixture.import_options();
        let err = verify_tzap_contact_card(&compact_card, &options_no_resolver).unwrap_err();
        match err {
            TzapContactCardError::IntermediateCacheMiss { issuer_key_identifier, reason } => {
                assert_eq!(issuer_key_identifier, fixture.certificate.issuer_key_identifier);
                assert!(reason.contains("no intermediate resolver configured"));
            }
            other => panic!("expected IntermediateCacheMiss, got: {other:?}"),
        }

        // 2. With intermediate cache populated with the platform intermediate
        let temp_dir = std::env::temp_dir().join(format!("tzap-contact-cache-{}", rand::random::<u64>()));
        let cache = trust::TzapIntermediateCache::new(&temp_dir);
        cache.store(&fixture.platform_der).unwrap();

        let mut options_with_cache = fixture.import_options();
        options_with_cache.intermediate_resolver = Some(&cache);

        let verified = verify_tzap_contact_card(&compact_card, &options_with_cache).unwrap();
        assert_eq!(verified.display_name, "Ada Lovelace");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    pub(crate) struct ContactFixture {
        pub(crate) signing_key: TzapDeviceSigningKeyRecord,
        pub(crate) recipient_key: TzapRecipientEncryptionKeyRecord,
        pub(crate) certificate: TzapEnrolledCertificateRecord,
        pub(crate) root_sha256: String,
        pub(crate) root_der: Vec<u8>,
        pub(crate) platform_der: Vec<u8>,
    }

    impl ContactFixture {
        pub(crate) fn new() -> Self {
            let signing_material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
            let recipient_material = generate_recipient_encryption_key().unwrap();
            let chain = certificate_fixture(&PKey::private_key_from_der(signing_material.private_key_der.expose_secret()).unwrap());
            Self {
                signing_key: TzapDeviceSigningKeyRecord {
                    key_id: "signing-key-1".to_owned(),
                    public_key_fingerprint: signing_material.public_key_fingerprint,
                    private_key_der: signing_material.private_key_der,
                    created_at_unix_seconds: 900,
                    label: Some("Signing".to_owned()),
                },
                recipient_key: TzapRecipientEncryptionKeyRecord {
                    key_id: "recipient-key-1".to_owned(),
                    algorithm: recipient_material.algorithm.to_owned(),
                    public_key_fingerprint: recipient_material.public_key_fingerprint,
                    public_key_der: recipient_material.public_key_spki_der,
                    private_key_der: recipient_material.private_key_der,
                    created_at_unix_seconds: 900,
                    label: Some("Recipient".to_owned()),
                },
                certificate: TzapEnrolledCertificateRecord {
                    certificate_id: "cert-1".to_owned(),
                    certificate_sha256: trust::certificate_sha256_identifier_for_der(&chain.leaf_der),
                    issuer_certificate_sha256: trust::certificate_sha256_identifier_for_der(&chain.platform_der),
                    issuer_key_identifier: chain.issuer_key_identifier,
                    serial_number: chain.serial_number,
                    leaf_certificate_der: chain.leaf_der,
                    intermediate_chain_der: vec![chain.platform_der.clone(), chain.root_der.clone()],
                    not_before_unix_seconds: 900,
                    not_after_unix_seconds: 2_000,
                    renewal_grace_period_days: None,
                    renewal_recommended_within_days: None,
                    public_metadata: public_metadata(),
                    sign_device_id: "sign-device-1".to_owned(),
                    sign_device_routing: TzapSignDeviceRouting::Personal,
                    signing_key_id: "signing-key-1".to_owned(),
                    state: TzapLocalCertificateState::Active,
                },
                root_sha256: chain.root_sha256,
                root_der: chain.root_der,
                platform_der: chain.platform_der,
            }
        }

        pub(crate) fn store(&self) -> InMemoryTzapLocalIdentityStore {
            let mut inventory = TzapLocalIdentityInventory::empty();
            inventory.device_signing_keys.push(self.signing_key.clone());
            inventory.recipient_encryption_keys.push(self.recipient_key.clone());
            inventory.enrolled_certificates.push(self.certificate.clone());
            let mut store = InMemoryTzapLocalIdentityStore::new();
            store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
            store
        }

        pub(crate) fn export_request(&self) -> TzapContactCardExportRequest {
            TzapContactCardExportRequest {
                account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
                recipient_key_id: self.recipient_key.key_id.clone(),
                certificate_id: self.certificate.certificate_id.clone(),
                display_name: "Ada Lovelace".to_owned(),
                device_label: "MacBook".to_owned(),
                created_at_unix_seconds: 1_000,
                expires_at_unix_seconds: None,
                compact: false,
            }
        }

        pub(crate) fn import_options(&self) -> TzapContactCardImportOptions<'_> {
            TzapContactCardImportOptions {
                verifier_time_unix_seconds: now_unix_seconds(),
                official_root_pins: &TzapRootPinSet { current: &[], planned_successors: &[] },
                official_root_certificates_der: Vec::new(),
                custom_trust_root_sha256: vec![self.root_sha256.clone()],
                custom_trust_root_certificates_der: vec![self.root_der.clone()],
                certificate_profile_options: TzapCertificateProfileOptions::default(),
                intermediate_resolver: None,
            }
        }
    }

    struct CertificateFixture {
        leaf_der: Vec<u8>,
        platform_der: Vec<u8>,
        root_der: Vec<u8>,
        root_sha256: String,
        issuer_key_identifier: String,
        serial_number: String,
    }

    fn certificate_fixture(leaf_key: &PKey<Private>) -> CertificateFixture {
        let root_key = p256_private_key();
        let platform_key = p256_private_key();
        let root = root_certificate(&root_key);
        let platform = intermediate_certificate(&platform_key, root.as_ref(), root_key.as_ref(), root.as_ref());
        let leaf =
            leaf_certificate(leaf_key, platform.as_ref(), platform_key.as_ref(), platform.as_ref(), crate::test_support::x509_factory::ChainConfig::default());
        let leaf_der = leaf.to_der().unwrap();
        let platform_der = platform.to_der().unwrap();
        let root_der = root.to_der().unwrap();
        let platform_parsed = X509Certificate::from_der(&platform_der).unwrap().1;
        let leaf_parsed = X509Certificate::from_der(&leaf_der).unwrap().1;
        let issuer_key_identifier = URL_SAFE_NO_PAD.encode(subject_key_identifier(&platform_parsed).unwrap());
        let serial_number = trust::canonical_serial_hex(leaf_parsed.raw_serial()).unwrap();
        CertificateFixture {
            leaf_der,
            issuer_key_identifier,
            serial_number,
            platform_der,
            root_sha256: trust::certificate_sha256_identifier_for_der(&root_der),
            root_der,
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

    fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
        certificate.iter_extensions().find_map(|extension| {
            if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() { Some(identifier.0.to_vec()) } else { None }
        })
    }

    fn now_unix_seconds() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap()
    }
}
