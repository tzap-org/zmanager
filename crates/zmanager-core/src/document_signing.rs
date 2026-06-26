//! Local TZAP document-envelope signing.

use crate::document_envelope::{
    self, FIELD_DOCUMENT_PAYLOAD, FIELD_INTERMEDIATE_CHAIN_DER, FIELD_LEAF_CERTIFICATE_DER,
    FIELD_SIGNATURE, FIELD_SIGNED_PAYLOAD,
};
use crate::jcs;
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityStore,
};
use crate::p256_signature;
use crate::trust::{self, TzapCertificateStatus};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::pkey::{PKey, Private};
use serde_json::{Value, json};
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDocumentSigningRequest {
    pub account_key: String,
    pub certificate_id: String,
    pub now_unix_seconds: u64,
    pub claimed_signing_time: Option<String>,
    pub signature_algorithm: String,
}

impl TzapDocumentSigningRequest {
    #[must_use]
    pub fn new(
        account_key: impl Into<String>,
        certificate_id: impl Into<String>,
        now_unix_seconds: u64,
    ) -> Self {
        Self {
            account_key: account_key.into(),
            certificate_id: certificate_id.into(),
            now_unix_seconds,
            claimed_signing_time: None,
            signature_algorithm: trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM.to_owned(),
        }
    }
}

#[derive(Debug)]
pub enum TzapDocumentSigningError {
    Store(crate::local_identity_store::TzapLocalIdentityStoreError),
    Envelope(document_envelope::TzapDocumentEnvelopeError),
    Canonicalization(String),
    Crypto(String),
    CertificateNotFound,
    PrivateKeyNotFound,
    CertificateNotActive,
    CertificateNotYetValid,
    CertificateExpired,
    CertificateStatusBlocked,
    IssuerBlocked,
    UnsupportedAlgorithm,
}

impl fmt::Display for TzapDocumentSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "document signing store read failed: {error}"),
            Self::Envelope(error) => write!(f, "document signing envelope is invalid: {error}"),
            Self::Canonicalization(reason) => {
                write!(f, "document signing canonicalization failed: {reason}")
            }
            Self::Crypto(reason) => write!(f, "document signing crypto failed: {reason}"),
            Self::CertificateNotFound => write!(f, "document signing certificate was not found"),
            Self::PrivateKeyNotFound => write!(f, "document signing private key was not found"),
            Self::CertificateNotActive => write!(f, "document signing certificate is not active"),
            Self::CertificateNotYetValid => {
                write!(f, "document signing certificate is not valid yet")
            }
            Self::CertificateExpired => write!(f, "document signing certificate is expired"),
            Self::CertificateStatusBlocked => {
                write!(f, "document signing certificate status blocks signing")
            }
            Self::IssuerBlocked => write!(f, "document signing issuer is blocked locally"),
            Self::UnsupportedAlgorithm => write!(f, "document signing algorithm is unsupported"),
        }
    }
}

impl std::error::Error for TzapDocumentSigningError {}

impl From<crate::local_identity_store::TzapLocalIdentityStoreError> for TzapDocumentSigningError {
    fn from(error: crate::local_identity_store::TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<document_envelope::TzapDocumentEnvelopeError> for TzapDocumentSigningError {
    fn from(error: document_envelope::TzapDocumentEnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

pub fn sign_tzap_document_payload(
    store: &impl TzapLocalIdentityStore,
    request: &TzapDocumentSigningRequest,
    document_payload: Value,
) -> Result<Value, TzapDocumentSigningError> {
    if request.signature_algorithm != trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM {
        return Err(TzapDocumentSigningError::UnsupportedAlgorithm);
    }
    let inventory = store.load_inventory(&request.account_key)?;
    let certificate = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == request.certificate_id)
        .ok_or(TzapDocumentSigningError::CertificateNotFound)?;
    validate_certificate_gate(certificate, request.now_unix_seconds)?;
    if inventory
        .emergency_blocklist
        .blocked_issuer_sha256
        .iter()
        .any(|issuer| issuer == &certificate.issuer_certificate_sha256)
    {
        return Err(TzapDocumentSigningError::IssuerBlocked);
    }
    if inventory.certificate_status_cache.iter().any(|status| {
        status.certificate_sha256 == certificate.certificate_sha256
            && status.status != TzapCertificateStatus::Valid
    }) {
        return Err(TzapDocumentSigningError::CertificateStatusBlocked);
    }

    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|record| record.key_id == certificate.signing_key_id)
        .ok_or(TzapDocumentSigningError::PrivateKeyNotFound)?;

    let payload_hash = jcs::canonical_sha256_digest(&document_payload)
        .map_err(|error| TzapDocumentSigningError::Canonicalization(format!("{error:?}")))?;
    let mut signed_payload = json!({
        "envelope_version": trust::TZAP_ENVELOPE_VERSION,
        "domain_separator": trust::TZAP_DOCUMENT_DOMAIN_SEPARATOR,
        "payload_hash_algorithm": trust::TZAP_PAYLOAD_DIGEST_ALGORITHM,
        "payload_hash": payload_hash,
        "signature_algorithm": trust::TZAP_DOCUMENT_SIGNATURE_ALGORITHM,
        "leaf_certificate_sha256": certificate.certificate_sha256,
        "issuer_certificate_sha256": certificate.issuer_certificate_sha256,
        "issuer_key_identifier": certificate.issuer_key_identifier,
        "certificate_serial_number": certificate.serial_number,
    });
    if let Some(claimed_signing_time) = &request.claimed_signing_time {
        signed_payload["claimed_signing_time"] = json!(claimed_signing_time);
    }
    let canonical_signed_payload = jcs::canonicalize_json_bytes(&signed_payload)
        .map_err(|error| TzapDocumentSigningError::Canonicalization(format!("{error:?}")))?;
    let signature = sign_signed_payload(signing_key, &canonical_signed_payload)?;

    let envelope = json!({
        FIELD_DOCUMENT_PAYLOAD: document_payload,
        FIELD_SIGNED_PAYLOAD: signed_payload,
        FIELD_SIGNATURE: URL_SAFE_NO_PAD.encode(signature),
        FIELD_LEAF_CERTIFICATE_DER: URL_SAFE_NO_PAD.encode(&certificate.leaf_certificate_der),
        FIELD_INTERMEDIATE_CHAIN_DER: trust::public_intermediate_chain_der(&certificate.intermediate_chain_der)
            .iter()
            .map(|der| URL_SAFE_NO_PAD.encode(der))
            .collect::<Vec<_>>(),
    });
    document_envelope::validate_tzap_document_envelope_value(&envelope)?;
    Ok(envelope)
}

fn validate_certificate_gate(
    certificate: &TzapEnrolledCertificateRecord,
    now_unix_seconds: u64,
) -> Result<(), TzapDocumentSigningError> {
    if !matches!(certificate.state, TzapLocalCertificateState::Active) {
        return Err(TzapDocumentSigningError::CertificateNotActive);
    }
    if now_unix_seconds < certificate.not_before_unix_seconds {
        return Err(TzapDocumentSigningError::CertificateNotYetValid);
    }
    if now_unix_seconds >= certificate.not_after_unix_seconds {
        return Err(TzapDocumentSigningError::CertificateExpired);
    }
    Ok(())
}

fn sign_signed_payload(
    signing_key: &TzapDeviceSigningKeyRecord,
    canonical_signed_payload: &[u8],
) -> Result<[u8; p256_signature::P256_P1363_SIGNATURE_LENGTH], TzapDocumentSigningError> {
    let private_key =
        PKey::<Private>::private_key_from_der(signing_key.private_key_der.expose_secret())
            .map_err(|error| TzapDocumentSigningError::Crypto(error.to_string()))?;
    p256_signature::sign_p256_sha256_p1363(&private_key, canonical_signed_payload)
        .map_err(|error| TzapDocumentSigningError::Crypto(format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use super::{TzapDocumentSigningError, TzapDocumentSigningRequest, sign_tzap_document_payload};
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::document_envelope::validate_tzap_document_envelope_value;
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore,
        TzapCertificateStatusCacheRecord, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState,
        TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory,
        TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord, TzapSignDeviceRouting,
    };
    use crate::p256_signature::verify_p256_sha256_p1363;
    use crate::secrets::SecretBytes;
    use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus};
    use openssl::pkey::PKey;
    use serde_json::{Value, json};

    #[test]
    fn valid_enrolled_certificate_signs_parseable_low_s_envelope() {
        let fixture = SigningFixture::new();
        let store = fixture.store(TzapLocalCertificateState::Active, false, None);
        let payload = json!({
            "tzap_payload_version": 1,
            "title": "Invoice",
            "body": {"amount": 42}
        });

        let envelope = sign_tzap_document_payload(&store, &fixture.request(), payload).unwrap();
        let parsed = validate_tzap_document_envelope_value(&envelope).unwrap();
        let public_key = PKey::public_key_from_der(&fixture.public_key_spki_der).unwrap();
        assert!(
            verify_p256_sha256_p1363(
                &public_key,
                &parsed.canonical_signed_payload,
                &parsed.signature
            )
            .unwrap()
        );
        assert!(envelope["document_payload"].get("signature").is_none());
        assert!(
            envelope["document_payload"]
                .get("leaf_certificate_der")
                .is_none()
        );
    }

    #[test]
    fn signing_rejects_missing_key_and_certificate_state_gates() {
        let fixture = SigningFixture::new();
        let payload = valid_payload();

        let mut store = fixture.store(TzapLocalCertificateState::Active, false, None);
        let mut inventory = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        inventory.device_signing_keys.clear();
        store
            .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
            .unwrap();
        assert!(matches!(
            sign_tzap_document_payload(&store, &fixture.request(), payload.clone()),
            Err(TzapDocumentSigningError::PrivateKeyNotFound)
        ));

        for (state, expected) in [
            (TzapLocalCertificateState::Revoked, "not_active"),
            (TzapLocalCertificateState::Suspended, "not_active"),
        ] {
            let store = fixture.store(state, false, None);
            let error = sign_tzap_document_payload(&store, &fixture.request(), payload.clone())
                .unwrap_err();
            assert!(matches!(
                error,
                TzapDocumentSigningError::CertificateNotActive
            ));
            assert_eq!(expected, "not_active");
        }

        let mut future = fixture.request();
        future.now_unix_seconds = 50;
        let store = fixture.store(TzapLocalCertificateState::Active, false, None);
        assert!(matches!(
            sign_tzap_document_payload(&store, &future, payload.clone()),
            Err(TzapDocumentSigningError::CertificateNotYetValid)
        ));

        let mut expired = fixture.request();
        expired.now_unix_seconds = 200;
        assert!(matches!(
            sign_tzap_document_payload(&store, &expired, payload.clone()),
            Err(TzapDocumentSigningError::CertificateExpired)
        ));
    }

    #[test]
    fn signing_rejects_blocklists_status_cache_unsupported_algorithm_and_reserved_payloads() {
        let fixture = SigningFixture::new();
        let payload = valid_payload();

        let store = fixture.store(TzapLocalCertificateState::Active, true, None);
        assert!(matches!(
            sign_tzap_document_payload(&store, &fixture.request(), payload.clone()),
            Err(TzapDocumentSigningError::IssuerBlocked)
        ));

        let store = fixture.store(
            TzapLocalCertificateState::Active,
            false,
            Some(TzapCertificateStatus::Suspended),
        );
        assert!(matches!(
            sign_tzap_document_payload(&store, &fixture.request(), payload.clone()),
            Err(TzapDocumentSigningError::CertificateStatusBlocked)
        ));

        let store = fixture.store(TzapLocalCertificateState::Active, false, None);
        let mut request = fixture.request();
        request.signature_algorithm = "RSA".to_owned();
        assert!(matches!(
            sign_tzap_document_payload(&store, &request, payload.clone()),
            Err(TzapDocumentSigningError::UnsupportedAlgorithm)
        ));

        let mut bad_payload = valid_payload();
        bad_payload["tzap_signature"] = json!("nope");
        assert!(matches!(
            sign_tzap_document_payload(&store, &fixture.request(), bad_payload),
            Err(TzapDocumentSigningError::Envelope(_))
        ));
    }

    struct SigningFixture {
        signing_key: TzapDeviceSigningKeyRecord,
        public_key_spki_der: Vec<u8>,
    }

    impl SigningFixture {
        fn new() -> Self {
            let material =
                generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
            Self {
                signing_key: TzapDeviceSigningKeyRecord {
                    key_id: "device-key-1".to_owned(),
                    public_key_fingerprint: material.public_key_fingerprint,
                    private_key_der: material.private_key_der,
                    created_at_unix_seconds: 100,
                    label: None,
                },
                public_key_spki_der: material.public_key_spki_der,
            }
        }

        fn request(&self) -> TzapDocumentSigningRequest {
            TzapDocumentSigningRequest::new(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert-1", 150)
        }

        fn store(
            &self,
            state: TzapLocalCertificateState,
            block_issuer: bool,
            status: Option<TzapCertificateStatus>,
        ) -> InMemoryTzapLocalIdentityStore {
            let mut inventory = TzapLocalIdentityInventory::empty();
            inventory
                .device_signing_keys
                .push(TzapDeviceSigningKeyRecord {
                    key_id: self.signing_key.key_id.clone(),
                    public_key_fingerprint: self.signing_key.public_key_fingerprint.clone(),
                    private_key_der: SecretBytes::from(
                        self.signing_key.private_key_der.expose_secret().to_vec(),
                    ),
                    created_at_unix_seconds: self.signing_key.created_at_unix_seconds,
                    label: None,
                });
            inventory.recipient_encryption_keys = Vec::<TzapRecipientEncryptionKeyRecord>::new();
            inventory
                .enrolled_certificates
                .push(certificate_record(state));
            if block_issuer {
                inventory.emergency_blocklist = TzapEmergencyBlocklistState {
                    blocked_root_sha256: Vec::new(),
                    blocked_issuer_sha256: vec![canonical_sha(0x04)],
                    updated_at_unix_seconds: Some(140),
                };
            }
            if let Some(status) = status {
                inventory
                    .certificate_status_cache
                    .push(TzapCertificateStatusCacheRecord {
                        certificate_sha256: canonical_sha(0x03),
                        status,
                        this_update_unix_seconds: 140,
                        next_update_unix_seconds: 180,
                    });
            }

            let mut store = InMemoryTzapLocalIdentityStore::new();
            store
                .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
                .unwrap();
            store
        }
    }

    fn valid_payload() -> Value {
        json!({
            "tzap_payload_version": 1,
            "title": "Invoice",
        })
    }

    fn certificate_record(state: TzapLocalCertificateState) -> TzapEnrolledCertificateRecord {
        TzapEnrolledCertificateRecord {
            certificate_id: "cert-1".to_owned(),
            certificate_sha256: canonical_sha(0x03),
            issuer_certificate_sha256: canonical_sha(0x04),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "01ABCDEF".to_owned(),
            leaf_certificate_der: vec![0x30, 0x01],
            intermediate_chain_der: vec![vec![0x30, 0x02]],
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            public_metadata: public_metadata(),
            sign_device_id: "sign-device-1".to_owned(),
            sign_device_routing: TzapSignDeviceRouting::Personal,
            signing_key_id: "device-key-1".to_owned(),
            state,
        }
    }

    fn public_metadata() -> TzapCertificatePublicMetadata {
        TzapCertificatePublicMetadata {
            version: 1,
            public_signer_id: "psign_0123456789ABCDEFGH".to_owned(),
            public_org_id: None,
            public_device_id: "pdev_0123456789ABCDEFGH".to_owned(),
            assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
        }
    }

    fn canonical_sha(byte: u8) -> String {
        trust::format_sha256_identifier(&[byte; 32])
    }
}
