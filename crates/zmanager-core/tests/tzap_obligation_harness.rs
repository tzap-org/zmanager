use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Extension, X509Ref};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zmanager_core::auth_client::{
    AUTH_HANDOFF_LIFETIME_SECONDS, InMemoryTzapSessionStore, SESSION_AUDIENCE_LOGIN_TZAP,
    SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpRequest, TzapAuthHttpResponse,
    TzapAuthHttpTransport, TzapAuthRelayCompletion, TzapBearerToken, TzapHostedAuthCallback,
    TzapHostedAuthEnvironment, TzapHostedAuthLaunchConfig, TzapOAuthStateTracker,
    TzapPendingAuthState, TzapPkcePair, TzapSessionRecord, TzapSessionStore,
    complete_hosted_auth_handoff,
};
use zmanager_core::certificate_lifecycle::{
    TzapCertificateLifecycleClient, TzapCertificateLifecycleError, TzapRenewalPolicy,
    TzapRenewalRequest, TzapRetirementCompletion,
};
use zmanager_core::contact_card::{
    TzapContactCardError, TzapContactCardExportRequest, TzapContactCardImportOptions,
    accepted_contact_recipients, export_tzap_contact_card, import_tzap_contact_card,
};
use zmanager_core::device_identity::{
    TzapDeviceCsrOptions, generate_device_signing_key_and_csr, generate_recipient_encryption_key,
};
use zmanager_core::document_envelope::validate_tzap_document_envelope_value;
use zmanager_core::document_signing::{TzapDocumentSigningRequest, sign_tzap_document_payload};
use zmanager_core::document_verification::{
    TzapOfflineVerificationOptions, verify_tzap_document_envelope_offline,
};
use zmanager_core::enrollment_client::{
    ENROLL_OPERATION, ENROLLMENT_CHALLENGE_CANONICALIZATION,
    TzapCustomEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentDenialKind,
    TzapEnrollmentError, TzapEnrollmentRequest, enroll_device_certificate,
};
use zmanager_core::jobs::{CancellationToken, JobContext};
use zmanager_core::local_identity_store::{
    DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord,
    TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord,
    TzapSignDeviceRouting,
};
use zmanager_core::manifest::{ManifestEntry, ManifestFileType, PermissionSnapshot};
use zmanager_core::safety::ExtractionPolicy;
use zmanager_core::status_client::{
    TzapBulkStatusLookup, TzapDocumentStatusTarget, TzapStatusClient, TzapStatusResponse,
    online_verification_result_from_status,
};
use zmanager_core::trust::{
    self, TzapCertificateProfileOptions, TzapCertificatePublicMetadata, TzapCertificateStatus,
    TzapRootPinSet, TzapTrustAnchorType, TzapVerificationState,
};
use zmanager_core::tzap_backend::{
    TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context,
    extract_tzap_with_recipient_key, list_tzap_with_recipient_key,
};

const ACCOUNT_KEY: &str = DEFAULT_IDENTITY_INVENTORY_ACCOUNT;
const FIXED_NOW: u64 = 1_700_010_000;
const FIXED_NOT_BEFORE: i64 = 1_700_000_000;
const FIXED_NOT_AFTER: i64 = 1_707_776_000;
const REQUESTED_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
const SIGN_BASE_URL: &str = "https://sign.tzap.test";
const LOGIN_BASE_URL: &str = "https://login.tzap.test";
const CALLBACK_REDIRECT_URI: &str = "zmanager://auth/callback";
const FIXED_PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const FIXED_STATE: &str = "state_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";
const FIXED_PROVIDER_ID: &str = "hosted";

#[test]
fn hosted_auth_handoff_obligations_are_enforced() {
    let pkce = TzapPkcePair::from_verifier(FIXED_PKCE_VERIFIER).unwrap();
    let pending = pending_state(pkce.clone(), FIXED_NOW);
    let launch = TzapHostedAuthLaunchConfig::for_environment(
        TzapHostedAuthEnvironment::Local,
        "zmanager-cli",
        CALLBACK_REDIRECT_URI,
    )
    .launch_url(&pending)
    .unwrap();

    assert!(launch.starts_with("http://localhost:8787/auth/launch?"));
    assert!(launch.contains("client_id=zmanager-cli"));
    assert!(launch.contains("code_challenge_method=S256"));
    assert!(launch.contains("response_mode=native_app_relay"));
    assert!(launch.contains(&format!("state={FIXED_STATE}")));
    assert!(!launch.contains("session_token"));

    let mut store = InMemoryTzapSessionStore::new();
    let session = complete_callback(pending.clone(), &mut store, ok_relay_body(), FIXED_NOW)
        .expect("valid handoff should create a local session");
    assert_eq!(session.audience, SESSION_AUDIENCE_SIGN_TZAP);
    assert!(!session.is_expired_at(FIXED_NOW));
    assert!(session.is_expired_at(FIXED_NOW + 3_600));
    assert!(session.require_audience(SESSION_AUDIENCE_SIGN_TZAP).is_ok());
    assert!(
        session
            .require_audience(SESSION_AUDIENCE_LOGIN_TZAP)
            .is_err()
    );
    store.clear_session(ACCOUNT_KEY).unwrap();
    assert!(store.load_session(ACCOUNT_KEY).is_none());

    let wrong_pkce = callback_with(pending.clone(), ok_relay_body(), Some("wrong-verifier"));
    let mut tracker = tracker_with_pending(pending.clone());
    let mut store = InMemoryTzapSessionStore::new();
    assert!(matches!(
        complete_hosted_auth_handoff(
            &mut tracker,
            &mut store,
            ACCOUNT_KEY,
            &wrong_pkce,
            FIXED_NOW
        ),
        Err(TzapAuthError::PkceVerifierMismatch)
    ));

    let expired_pending = pending_state(pkce, FIXED_NOW - AUTH_HANDOFF_LIFETIME_SECONDS - 1);
    let mut store = InMemoryTzapSessionStore::new();
    assert!(matches!(
        complete_callback(expired_pending, &mut store, ok_relay_body(), FIXED_NOW),
        Err(TzapAuthError::ExpiredHandoff)
    ));

    for (status, expected) in [
        ("denied", "denied"),
        ("cancelled", "cancelled"),
        ("expired", "expired"),
    ] {
        let result = TzapAuthRelayCompletion::from_json_value(&json!({"status": status}));
        assert!(
            result.unwrap_err().to_string().contains(expected),
            "relay status should stay stable: {status}"
        );
    }
}

#[test]
fn personal_happy_path_signs_verifies_imports_contact_and_unwraps_share() {
    let mut harness = PersonalHarness::new();
    let challenge = enrollment_challenge_response(&harness);
    let certificate = enrollment_certificate_response(&harness.chain);
    let transport = FakeTransport::new(vec![challenge, certificate]);
    let client = TzapEnrollmentClient::new(SIGN_BASE_URL, &transport);
    let validator = TzapCustomEnrollmentCertificateValidator {
        options: TzapCertificateProfileOptions::default(),
    };

    let enrolled = enroll_device_certificate(
        &client,
        &validator,
        &mut harness.store,
        &harness.sign_session,
        &harness.enrollment_request,
        &harness.signing_key,
        &harness.csr_der,
    )
    .unwrap();

    assert_eq!(enrolled.certificate_id, "cert_personal_1");
    assert_eq!(enrolled.sign_device_id, "sdev_personal_1");
    assert_eq!(transport.requests().len(), 2);
    assert_eq!(
        transport.requests()[0].url,
        "https://sign.tzap.test/v1/certificates/enrollment-challenges"
    );
    assert_eq!(
        transport.requests()[1].url,
        "https://sign.tzap.test/v1/certificates/enroll"
    );

    let envelope = sign_tzap_document_payload(
        &harness.store,
        &TzapDocumentSigningRequest::new(ACCOUNT_KEY, "cert_personal_1", FIXED_NOW),
        json!({"tzap_payload_version": 1, "title": "Harness document"}),
    )
    .unwrap();
    let parsed = validate_tzap_document_envelope_value(&envelope).unwrap();
    assert_eq!(
        parsed.intermediate_chain_der,
        vec![harness.chain.platform_der.clone()]
    );
    let empty_official = TzapRootPinSet {
        current: &[],
        planned_successors: &[],
    };
    let mut custom_options =
        TzapOfflineVerificationOptions::official(FIXED_NOW.try_into().unwrap(), &empty_official);
    custom_options.custom_trust_root_sha256 = vec![harness.chain.root_sha256.clone()];
    custom_options.custom_trust_root_certificates_der = vec![harness.chain.root_der.clone()];
    let custom = verify_tzap_document_envelope_offline(&parsed, &custom_options);
    assert_eq!(
        custom.state,
        TzapVerificationState::CryptographicallyIntactOffline
    );
    assert_eq!(custom.trust_anchor_type, TzapTrustAnchorType::Custom);

    let official_pins = pin_set(&harness.chain.root_sha256);
    let mut official_options =
        TzapOfflineVerificationOptions::official(FIXED_NOW.try_into().unwrap(), &official_pins);
    official_options.official_root_certificates_der = vec![harness.chain.root_der.clone()];
    let offline = verify_tzap_document_envelope_offline(&parsed, &official_options);
    assert_eq!(
        offline.state,
        TzapVerificationState::CryptographicallyIntactOffline
    );
    assert_eq!(offline.trust_anchor_type, TzapTrustAnchorType::OfficialTzap);

    let fresh_status = TzapStatusResponse::from_json_value(&valid_status(
        &harness.chain.leaf_sha256,
        &harness.chain.platform_sha256,
        &harness.chain.issuer_key_identifier,
        &harness.chain.serial_number,
    ))
    .unwrap();
    let expected_status_target = TzapDocumentStatusTarget::from_envelope(&parsed);
    let valid_now = online_verification_result_from_status(
        offline,
        &expected_status_target,
        &fresh_status,
        FIXED_NOW as i64,
    );
    assert_eq!(valid_now.state, TzapVerificationState::ValidNow);

    let card = export_tzap_contact_card(&harness.store, &harness.contact_export()).unwrap();
    assert!(matches!(
        import_tzap_contact_card(
            &mut InMemoryTzapLocalIdentityStore::new(),
            ACCOUNT_KEY,
            &card,
            &harness.contact_import_options(),
            None,
        ),
        Err(TzapContactCardError::AcceptanceRequired)
    ));
    let mut recipient_store = InMemoryTzapLocalIdentityStore::new();
    let contact = import_tzap_contact_card(
        &mut recipient_store,
        ACCOUNT_KEY,
        &card,
        &harness.contact_import_options(),
        Some(FIXED_NOW),
    )
    .unwrap();
    let selected_recipients = accepted_contact_recipients(
        &recipient_store,
        ACCOUNT_KEY,
        std::slice::from_ref(&contact.contact_id),
        FIXED_NOW + 1,
    )
    .unwrap();
    assert_eq!(selected_recipients.len(), 1);
    assert!(selected_recipients[0].missing_status_caveat);
    let recipients = selected_recipients
        .into_iter()
        .map(|recipient| recipient.recipient_public_key_der)
        .collect::<Vec<_>>();
    assert_eq!(recipients.len(), 1);

    let temp = TestDir::new("tzap-obligation-harness-share");
    let source = temp.path("payload.txt");
    let archive = temp.path("shared.tzap");
    let out = temp.path("out");
    let recipient_key_path = temp.path("recipient.key");
    fs::write(&source, b"shared obligation payload").unwrap();
    fs::write(
        &recipient_key_path,
        harness
            .recipient_private_key()
            .private_key_to_pem_pkcs8()
            .unwrap(),
    )
    .unwrap();

    let manifest = single_file_manifest(&source, "payload.txt");
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientPublicKeys(recipients),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_tzap_with_recipient_key(&archive, &recipient_key_path).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");
    extract_tzap_with_recipient_key(
        &archive,
        &out,
        ExtractionPolicy::default(),
        &recipient_key_path,
    )
    .unwrap();
    assert_eq!(
        fs::read(out.join("payload.txt")).unwrap(),
        b"shared obligation payload"
    );
}

#[test]
fn negative_status_renewal_revocation_and_blocklist_obligations_are_exercised() {
    let harness = PersonalHarness::new();
    let status_transport = FakeTransport::new(vec![json_response(json!({
        "results": [
            {"lookup_id": "valid", "status_response": valid_status(
                &harness.chain.leaf_sha256,
                &harness.chain.platform_sha256,
                &harness.chain.issuer_key_identifier,
                &harness.chain.serial_number,
            )},
            {"lookup_id": "unknown", "status_response": {
                "status": "unknown_certificate",
                "query": {"certificate_sha256": trust::format_certificate_sha256(&[0x90; 32])},
                "this_update_unix_seconds": FIXED_NOW as i64 - 60,
                "next_update_unix_seconds": FIXED_NOW as i64 + 60
            }},
            {"lookup_id": "malformed", "status_response": {
                "status": "malformed_lookup",
                "query": {"certificate_sha256": trust::format_certificate_sha256(&[0x91; 32])},
                "this_update_unix_seconds": FIXED_NOW as i64 - 60,
                "next_update_unix_seconds": FIXED_NOW as i64 + 60
            }}
        ]
    }))]);
    let status_client = TzapStatusClient::new(SIGN_BASE_URL, &status_transport);
    let statuses = status_client
        .bulk_status(&[
            TzapBulkStatusLookup::by_fingerprint("valid", &harness.chain.leaf_sha256),
            TzapBulkStatusLookup::by_fingerprint(
                "unknown",
                trust::format_certificate_sha256(&[0x90; 32]),
            ),
            TzapBulkStatusLookup::by_fingerprint(
                "malformed",
                trust::format_certificate_sha256(&[0x91; 32]),
            ),
        ])
        .unwrap();
    assert_eq!(statuses[0].response.status, TzapCertificateStatus::Valid);
    assert_eq!(
        statuses[1].response.status,
        TzapCertificateStatus::UnknownCertificate
    );
    assert_eq!(
        statuses[2].response.status,
        TzapCertificateStatus::MalformedLookup
    );

    for status in [
        "suspended",
        "revoked",
        "issuer_revoked",
        "unknown_issuer",
        "unsupported_lookup_form",
    ] {
        let value = non_valid_status(
            status,
            &harness.chain.leaf_sha256,
            &harness.chain.platform_sha256,
            &harness.chain.issuer_key_identifier,
            &harness.chain.serial_number,
        );
        assert!(
            !TzapStatusResponse::from_json_value(&value)
                .unwrap()
                .is_fresh_valid_for_valid_now(FIXED_NOW as i64),
            "status should not produce valid_now: {status}"
        );
    }

    let crl_manifest_transport = FakeTransport::new(vec![json_response(json!({
        "crls": [{
            "crl_scope": trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA,
            "crl_url": trust::status_crl_pem_path(&harness.chain.platform_sha256).unwrap(),
            "issuer_certificate_sha256": harness.chain.platform_sha256,
            "crl_number": "01",
            "crl_sha256": trust::format_crl_sha256(&[0x33; 32]),
            "this_update_unix_seconds": FIXED_NOW as i64 - 60,
            "next_update_unix_seconds": FIXED_NOW as i64 + 60
        }]
    }))]);
    let crl_entries = TzapStatusClient::new(SIGN_BASE_URL, &crl_manifest_transport)
        .crl_manifest()
        .unwrap();
    assert_eq!(
        crl_entries[0].crl_scope,
        trust::TZAP_CRL_SCOPE_ALL_CERTIFICATES_ISSUED_BY_CA
    );

    let planned_successor_pin = Box::leak(harness.chain.root_sha256.clone().into_boxed_str());
    let planned_successor_pins = TzapRootPinSet {
        current: &[],
        planned_successors: Box::leak(
            vec![planned_successor_pin as &'static str].into_boxed_slice(),
        ),
    };
    let planned_successor_validation = trust::validate_official_tzap_certificate_chain_der(
        &harness.chain_der(),
        &planned_successor_pins,
        &TzapCertificateProfileOptions::default(),
    )
    .unwrap();
    assert_eq!(
        planned_successor_validation
            .official_root_pin_kind
            .unwrap()
            .as_str(),
        "planned_successor"
    );

    let enrollment_transport = FakeTransport::new(vec![
        enrollment_challenge_response(&harness),
        json_response(json!({
            "denial": {
                "reason": "device_approval_required",
                "retry_after": FIXED_NOW + 300,
                "support_reference": "approval-1"
            }
        })),
        enrollment_challenge_response_with_id(&harness, "chal_personal_2"),
    ]);
    let enrollment_client = TzapEnrollmentClient::new(SIGN_BASE_URL, &enrollment_transport);
    let first_challenge = enrollment_client
        .request_enrollment_challenge(
            &harness.sign_session,
            &harness.enrollment_request,
            &harness.signing_key,
            &harness.csr_der,
        )
        .unwrap();
    let denial = enrollment_client
        .submit_enrollment(
            &harness.sign_session,
            &first_challenge,
            &harness.signing_key,
            &harness.csr_der,
        )
        .unwrap_err();
    assert!(matches!(
        denial,
        TzapEnrollmentError::Denied(denial)
            if denial.kind == TzapEnrollmentDenialKind::DeviceApprovalRequired
    ));
    let fresh_challenge = enrollment_client
        .request_enrollment_challenge(
            &harness.sign_session,
            &harness.enrollment_request,
            &harness.signing_key,
            &harness.csr_der,
        )
        .unwrap();
    assert_eq!(fresh_challenge.challenge_id, "chal_personal_2");

    let mut store = harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal);
    let same_key_renewal_transport = FakeTransport::new(vec![
        renewal_challenge_response(&harness, None),
        renewal_certificate_response("cert_renewed_same_key", &harness.chain, 0x55),
    ]);
    let lifecycle = TzapCertificateLifecycleClient::new(
        SIGN_BASE_URL,
        LOGIN_BASE_URL,
        &same_key_renewal_transport,
    );
    let renewed = lifecycle
        .renew_certificate(
            &AcceptingLifecycleValidator,
            &mut store,
            &harness.sign_session,
            &harness.renewal_request(TzapRenewalPolicy::SameKeyRequired),
            &harness.signing_key,
            &harness.signing_key,
            &harness.csr_der,
        )
        .unwrap();
    assert_eq!(renewed.certificate_id, "cert_renewed_same_key");
    assert!(
        same_key_renewal_transport.requests()[1]
            .body
            .as_ref()
            .and_then(|body| body.get("old_certificate_signature"))
            .and_then(Value::as_str)
            .is_some()
    );

    let rotated_material =
        generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
    let rotated_signing_key = TzapDeviceSigningKeyRecord {
        key_id: "rotated-device-key-1".to_owned(),
        public_key_fingerprint: rotated_material.public_key_fingerprint,
        private_key_der: rotated_material.private_key_der,
        created_at_unix_seconds: FIXED_NOW,
        label: Some("Rotated signing key".to_owned()),
    };
    let mut rotated_store = harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal);
    let mut rotated_inventory = rotated_store.load_inventory(ACCOUNT_KEY).unwrap();
    rotated_inventory
        .device_signing_keys
        .push(rotated_signing_key.clone());
    rotated_store
        .save_inventory(ACCOUNT_KEY, rotated_inventory)
        .unwrap();
    let rotated_transport = FakeTransport::new(vec![
        renewal_challenge_response(&harness, None),
        renewal_certificate_response("cert_renewed_rotated_key", &harness.chain, 0x56),
    ]);
    let lifecycle =
        TzapCertificateLifecycleClient::new(SIGN_BASE_URL, LOGIN_BASE_URL, &rotated_transport);
    lifecycle
        .renew_certificate(
            &AcceptingLifecycleValidator,
            &mut rotated_store,
            &harness.sign_session,
            &harness.renewal_request(TzapRenewalPolicy::KeyRotationAllowed),
            &rotated_signing_key,
            &harness.signing_key,
            &rotated_material.csr_der,
        )
        .unwrap();
    assert!(
        rotated_transport.requests()[1]
            .body
            .as_ref()
            .and_then(|body| body.get("old_certificate_signature"))
            .is_some_and(Value::is_null)
    );

    let personal_revocation = TzapCertificateLifecycleClient::new(
        SIGN_BASE_URL,
        LOGIN_BASE_URL,
        &FakeTransport::new(vec![json_response(json!({"result": "revoked"}))]),
    )
    .revoke_personal_certificate(
        &mut harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal),
        &harness.sign_session,
        ACCOUNT_KEY,
        "cert_personal_1",
    )
    .unwrap();
    assert_eq!(personal_revocation, TzapRetirementCompletion::Complete);

    let mut store = harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal);
    let renewal_target = trust::format_certificate_sha256(&[0x44; 32]);
    let renewal_transport = FakeTransport::new(vec![renewal_challenge_response(
        &harness,
        Some(&renewal_target),
    )]);
    let lifecycle =
        TzapCertificateLifecycleClient::new(SIGN_BASE_URL, LOGIN_BASE_URL, &renewal_transport);
    let renewal_error = lifecycle
        .renew_certificate(
            &AcceptingLifecycleValidator,
            &mut store,
            &harness.sign_session,
            &harness.renewal_request(TzapRenewalPolicy::SameKeyRequired),
            &harness.signing_key,
            &harness.signing_key,
            &harness.csr_der,
        )
        .unwrap_err();
    assert!(matches!(
        renewal_error,
        TzapCertificateLifecycleError::RenewalTargetMismatch
    ));

    let pending_retirement = TzapCertificateLifecycleClient::new(
        SIGN_BASE_URL,
        LOGIN_BASE_URL,
        &FakeTransport::new(vec![json_response_with_code(
            202,
            json!({"result": "revocation_pending_sync"}),
        )]),
    )
    .retire_personal_devices(
        &harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal),
        &harness.sign_session,
        ACCOUNT_KEY,
    )
    .unwrap();
    assert_eq!(
        pending_retirement.completion,
        TzapRetirementCompletion::Incomplete
    );

    let org_store = harness.store_with_certificate_routing(TzapSignDeviceRouting::Organization {
        org_id: "org_123".to_owned(),
        login_organization_device_id: "odev_123".to_owned(),
    });
    let org_pending = TzapCertificateLifecycleClient::new(
        SIGN_BASE_URL,
        LOGIN_BASE_URL,
        &FakeTransport::new(vec![json_response_with_code(
            409,
            json!({"error": "device_linkage_pending"}),
        )]),
    )
    .retire_organization_devices(&org_store, &harness.login_session, ACCOUNT_KEY)
    .unwrap();
    assert_eq!(org_pending.completion, TzapRetirementCompletion::Incomplete);
    assert!(org_pending.incomplete_reasons[0].contains("device_linkage_pending"));

    let mut blocked_store = harness.store_with_certificate_routing(TzapSignDeviceRouting::Personal);
    let mut inventory = blocked_store.load_inventory(ACCOUNT_KEY).unwrap();
    inventory.emergency_blocklist = TzapEmergencyBlocklistState {
        blocked_root_sha256: vec![harness.chain.root_sha256.clone()],
        blocked_issuer_sha256: vec![harness.chain.platform_sha256.clone()],
        updated_at_unix_seconds: Some(FIXED_NOW),
    };
    blocked_store
        .save_inventory(ACCOUNT_KEY, inventory)
        .unwrap();
    let signing_error = sign_tzap_document_payload(
        &blocked_store,
        &TzapDocumentSigningRequest::new(ACCOUNT_KEY, "cert_personal_1", FIXED_NOW),
        json!({"tzap_payload_version": 1, "title": "Blocked"}),
    )
    .unwrap_err();
    assert!(signing_error.to_string().contains("issuer is blocked"));
}

struct PersonalHarness {
    sign_session: TzapSessionRecord,
    login_session: TzapSessionRecord,
    enrollment_request: TzapEnrollmentRequest,
    signing_key: TzapDeviceSigningKeyRecord,
    recipient_key: TzapRecipientEncryptionKeyRecord,
    csr_der: Vec<u8>,
    chain: IssuedChain,
    store: InMemoryTzapLocalIdentityStore,
}

impl PersonalHarness {
    fn new() -> Self {
        let signing_material =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_material = generate_recipient_encryption_key().unwrap();
        let signing_private_key =
            PKey::private_key_from_der(signing_material.private_key_der.expose_secret()).unwrap();
        let chain = certificate_chain_for_leaf_key(signing_private_key.as_ref());
        let signing_key = TzapDeviceSigningKeyRecord {
            key_id: "device-key-1".to_owned(),
            public_key_fingerprint: signing_material.public_key_fingerprint,
            private_key_der: signing_material.private_key_der,
            created_at_unix_seconds: FIXED_NOW,
            label: Some("Harness signing key".to_owned()),
        };
        let recipient_key = TzapRecipientEncryptionKeyRecord {
            key_id: "recipient-key-1".to_owned(),
            algorithm: recipient_material.algorithm.to_owned(),
            public_key_fingerprint: recipient_material.public_key_fingerprint,
            public_key_der: recipient_material.public_key_spki_der,
            private_key_der: recipient_material.private_key_der,
            created_at_unix_seconds: FIXED_NOW,
            label: Some("Harness recipient key".to_owned()),
        };
        let sign_session = session(SESSION_AUDIENCE_SIGN_TZAP, "sign-session-1");
        let login_session = session(SESSION_AUDIENCE_LOGIN_TZAP, "login-session-1");
        let enrollment_request = TzapEnrollmentRequest {
            account_key: ACCOUNT_KEY.to_owned(),
            org_id: None,
            requested_validity_seconds: REQUESTED_VALIDITY_SECONDS,
            now_unix_seconds: FIXED_NOW,
        };
        let mut harness = Self {
            sign_session,
            login_session,
            enrollment_request,
            signing_key,
            recipient_key,
            csr_der: signing_material.csr_der,
            chain,
            store: InMemoryTzapLocalIdentityStore::new(),
        };
        harness.store = harness.store_with_keys();
        harness
    }

    fn store_with_keys(&self) -> InMemoryTzapLocalIdentityStore {
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(self.signing_key.clone());
        inventory
            .recipient_encryption_keys
            .push(self.recipient_key.clone());
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(ACCOUNT_KEY, inventory).unwrap();
        store
    }

    fn store_with_certificate_routing(
        &self,
        routing: TzapSignDeviceRouting,
    ) -> InMemoryTzapLocalIdentityStore {
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(self.signing_key.clone());
        inventory
            .recipient_encryption_keys
            .push(self.recipient_key.clone());
        inventory
            .enrolled_certificates
            .push(self.enrolled_certificate(routing));
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(ACCOUNT_KEY, inventory).unwrap();
        store
    }

    fn enrolled_certificate(
        &self,
        routing: TzapSignDeviceRouting,
    ) -> TzapEnrolledCertificateRecord {
        TzapEnrolledCertificateRecord {
            certificate_id: "cert_personal_1".to_owned(),
            certificate_sha256: self.chain.leaf_sha256.clone(),
            issuer_certificate_sha256: self.chain.platform_sha256.clone(),
            issuer_key_identifier: self.chain.issuer_key_identifier.clone(),
            serial_number: self.chain.serial_number.clone(),
            leaf_certificate_der: self.chain.leaf_der.clone(),
            intermediate_chain_der: vec![
                self.chain.platform_der.clone(),
                self.chain.root_der.clone(),
            ],
            not_before_unix_seconds: FIXED_NOT_BEFORE.try_into().unwrap(),
            not_after_unix_seconds: FIXED_NOT_AFTER.try_into().unwrap(),
            public_metadata: public_metadata(),
            sign_device_id: "sdev_personal_1".to_owned(),
            sign_device_routing: routing,
            signing_key_id: self.signing_key.key_id.clone(),
            state: TzapLocalCertificateState::Active,
        }
    }

    fn chain_der(&self) -> Vec<Vec<u8>> {
        vec![
            self.chain.leaf_der.clone(),
            self.chain.platform_der.clone(),
            self.chain.root_der.clone(),
        ]
    }

    fn contact_export(&self) -> TzapContactCardExportRequest {
        TzapContactCardExportRequest {
            account_key: ACCOUNT_KEY.to_owned(),
            recipient_key_id: self.recipient_key.key_id.clone(),
            certificate_id: "cert_personal_1".to_owned(),
            display_name: "Harness User".to_owned(),
            device_label: "Harness Mac".to_owned(),
            created_at_unix_seconds: FIXED_NOW,
            expires_at_unix_seconds: None,
        }
    }

    fn contact_import_options(&self) -> TzapContactCardImportOptions<'_> {
        TzapContactCardImportOptions {
            verifier_time_unix_seconds: FIXED_NOW.try_into().unwrap(),
            official_root_pins: &TzapRootPinSet {
                current: &[],
                planned_successors: &[],
            },
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256: vec![self.chain.root_sha256.clone()],
            custom_trust_root_certificates_der: vec![self.chain.root_der.clone()],
            certificate_profile_options: TzapCertificateProfileOptions::default(),
        }
    }

    fn renewal_request(&self, policy: TzapRenewalPolicy) -> TzapRenewalRequest {
        TzapRenewalRequest {
            account_key: ACCOUNT_KEY.to_owned(),
            previous_certificate_id: "cert_personal_1".to_owned(),
            previous_certificate_sha256: self.chain.leaf_sha256.clone(),
            org_id: None,
            requested_validity_seconds: REQUESTED_VALIDITY_SECONDS,
            renewal_policy: policy,
            now_unix_seconds: FIXED_NOW,
            server_grace_seconds: 60,
        }
    }

    fn recipient_private_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(self.recipient_key.private_key_der.expose_secret()).unwrap()
    }
}

fn pending_state(pkce: TzapPkcePair, created_at_unix_seconds: u64) -> TzapPendingAuthState {
    TzapPendingAuthState {
        state: FIXED_STATE.to_owned(),
        provider_id: FIXED_PROVIDER_ID.to_owned(),
        redirect_uri: CALLBACK_REDIRECT_URI.to_owned(),
        pkce,
        created_at_unix_seconds,
    }
}

fn complete_callback(
    pending: TzapPendingAuthState,
    store: &mut impl TzapSessionStore,
    relay_body: Vec<u8>,
    now: u64,
) -> Result<TzapSessionRecord, TzapAuthError> {
    let callback = callback_with(pending.clone(), relay_body, None);
    let mut tracker = tracker_with_pending(pending);
    complete_hosted_auth_handoff(&mut tracker, store, ACCOUNT_KEY, &callback, now)
}

fn callback_with(
    pending: TzapPendingAuthState,
    relay_body: Vec<u8>,
    pkce_verifier: Option<&str>,
) -> TzapHostedAuthCallback {
    TzapHostedAuthCallback {
        state: pending.state,
        redirect_uri: pending.redirect_uri,
        pkce_verifier: pkce_verifier.unwrap_or(&pending.pkce.verifier).to_owned(),
        callback_url: Some("zmanager://auth/callback?state=state-only".to_owned()),
        relay_body,
    }
}

fn tracker_with_pending(pending: TzapPendingAuthState) -> TzapOAuthStateTracker {
    let mut tracker = TzapOAuthStateTracker::new();
    tracker.insert_pending(pending).unwrap();
    tracker
}

fn ok_relay_body() -> Vec<u8> {
    json!({
        "status": "ok",
        "session": {
            "audience": SESSION_AUDIENCE_SIGN_TZAP,
            "access_token": "secret-session-token",
            "expires_at_unix_seconds": FIXED_NOW + 3_600,
            "identity_assurance": "oauth_verified_email",
            "selected_org_id": Value::Null,
            "login_session_id": "login-session-1"
        }
    })
    .to_string()
    .into_bytes()
}

fn session(audience: &str, login_session_id: &str) -> TzapSessionRecord {
    TzapSessionRecord {
        audience: audience.to_owned(),
        access_token: TzapBearerToken::new(format!("token-for-{audience}")).unwrap(),
        expires_at_unix_seconds: FIXED_NOW + 3_600,
        identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
        selected_org_id: None,
        login_session_id: Some(login_session_id.to_owned()),
    }
}

fn enrollment_challenge_response(harness: &PersonalHarness) -> TzapAuthHttpResponse {
    enrollment_challenge_response_with_id(harness, "chal_personal_1")
}

fn enrollment_challenge_response_with_id(
    harness: &PersonalHarness,
    challenge_id: &str,
) -> TzapAuthHttpResponse {
    let payload = json!({
        "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
        "audience": SESSION_AUDIENCE_SIGN_TZAP,
        "operation": ENROLL_OPERATION,
        "challenge_id": challenge_id,
        "session_id": harness.sign_session.login_session_id,
        "csr_sha256": csr_sha256(&harness.csr_der),
        "device_public_key_fingerprint": harness.signing_key.public_key_fingerprint,
        "org_id": harness.enrollment_request.org_id,
        "requested_validity_seconds": harness.enrollment_request.requested_validity_seconds,
        "renewal_of_certificate_sha256": Value::Null,
        "expires_at_unix_seconds": FIXED_NOW + 300
    });
    json_response(json!({
        "challenge_id": challenge_id,
        "challenge_payload": payload
    }))
}

fn enrollment_certificate_response(chain: &IssuedChain) -> TzapAuthHttpResponse {
    json_response(json!({"certificate": certificate_json("cert_personal_1", chain)}))
}

fn renewal_certificate_response(
    certificate_id: &str,
    chain: &IssuedChain,
    fingerprint_byte: u8,
) -> TzapAuthHttpResponse {
    let mut certificate = certificate_json(certificate_id, chain);
    certificate["certificate_sha256"] =
        json!(trust::format_certificate_sha256(&[fingerprint_byte; 32]));
    json_response(json!({"certificate": certificate}))
}

fn renewal_challenge_response(
    harness: &PersonalHarness,
    renewal_target_override: Option<&str>,
) -> TzapAuthHttpResponse {
    json_response(json!({
        "challenge_id": "chal_renewal_1",
        "challenge_payload": {
            "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
            "operation": "renew",
            "challenge_id": "chal_renewal_1",
            "certificate_id": "cert_personal_1",
            "renewal_of_certificate_sha256": renewal_target_override
                .unwrap_or(&harness.chain.leaf_sha256),
            "org_id": Value::Null,
        }
    }))
}

fn certificate_json(certificate_id: &str, chain: &IssuedChain) -> Value {
    json!({
        "certificate_id": certificate_id,
        "leaf_certificate_der": URL_SAFE_NO_PAD.encode(&chain.leaf_der),
        "intermediate_chain_der": [
            URL_SAFE_NO_PAD.encode(&chain.platform_der),
            URL_SAFE_NO_PAD.encode(&chain.root_der),
        ],
        "issuer_certificate_sha256": chain.platform_sha256,
        "issuer_key_identifier": chain.issuer_key_identifier,
        "serial_number": chain.serial_number,
        "certificate_sha256": chain.leaf_sha256,
        "not_before_unix_seconds": FIXED_NOT_BEFORE,
        "not_after_unix_seconds": FIXED_NOT_AFTER,
        "sign_device_id": "sdev_personal_1",
        "login_organization_device_id": Value::Null,
    })
}

fn valid_status(
    certificate_sha256: &str,
    issuer_sha256: &str,
    issuer_key_identifier: &str,
    serial_number: &str,
) -> Value {
    json!({
        "status": "valid",
        "certificate_sha256": certificate_sha256,
        "issuer_certificate_sha256": issuer_sha256,
        "issuer_key_identifier": issuer_key_identifier,
        "serial_number": serial_number,
        "not_before_unix_seconds": FIXED_NOT_BEFORE,
        "not_after_unix_seconds": FIXED_NOT_AFTER,
        "this_update_unix_seconds": FIXED_NOW as i64 - 60,
        "next_update_unix_seconds": FIXED_NOW as i64 + 60,
        "query": {"certificate_sha256": certificate_sha256}
    })
}

fn non_valid_status(
    status: &str,
    certificate_sha256: &str,
    issuer_sha256: &str,
    issuer_key_identifier: &str,
    serial_number: &str,
) -> Value {
    match status {
        "unknown_issuer" | "unsupported_lookup_form" => {
            json!({
                "status": status,
                "query": {
                    "issuer_certificate_sha256": issuer_sha256,
                    "serial_number": serial_number
                },
                "this_update_unix_seconds": FIXED_NOW as i64 - 60,
                "next_update_unix_seconds": FIXED_NOW as i64 + 60
            })
        }
        _ => {
            let mut value = valid_status(
                certificate_sha256,
                issuer_sha256,
                issuer_key_identifier,
                serial_number,
            );
            value["status"] = json!(status);
            if status == "revoked" {
                value["revoked_at_unix_seconds"] = json!(FIXED_NOW as i64 - 1);
                value["revocation_reason"] = json!("key_compromise");
            }
            value
        }
    }
}

fn csr_sha256(csr_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(csr_der).into();
    trust::format_csr_sha256(&digest)
}

fn single_file_manifest(
    source: &Path,
    archive_path: &str,
) -> zmanager_core::manifest::ArchiveManifest {
    zmanager_core::manifest::ArchiveManifest {
        root: source.parent().unwrap().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: archive_path.to_owned(),
            source_path: source.to_path_buf(),
            file_type: ManifestFileType::File,
            size: fs::metadata(source).unwrap().len(),
            modified: None,
            permissions: PermissionSnapshot {
                readonly: false,
                unix_mode: Some(0o644),
            },
            symlink_target: None,
        }],
        total_bytes: fs::metadata(source).unwrap().len(),
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    }
}

#[derive(Clone)]
struct IssuedChain {
    leaf_der: Vec<u8>,
    platform_der: Vec<u8>,
    root_der: Vec<u8>,
    leaf_sha256: String,
    platform_sha256: String,
    root_sha256: String,
    issuer_key_identifier: String,
    serial_number: String,
}

fn certificate_chain_for_leaf_key(leaf_key: &PKeyRef<Private>) -> IssuedChain {
    let root_key = p256_private_key();
    let platform_key = p256_private_key();
    let root = root_certificate(root_key.as_ref());
    let platform = intermediate_certificate(
        platform_key.as_ref(),
        root.as_ref(),
        root_key.as_ref(),
        root.as_ref(),
    );
    let leaf = leaf_certificate(
        leaf_key,
        platform.as_ref(),
        platform_key.as_ref(),
        platform.as_ref(),
    );
    let leaf_der = leaf.to_der().unwrap();
    let platform_der = platform.to_der().unwrap();
    let root_der = root.to_der().unwrap();
    let platform_parsed = X509Certificate::from_der(&platform_der).unwrap().1;
    let leaf_parsed = X509Certificate::from_der(&leaf_der).unwrap().1;
    IssuedChain {
        issuer_key_identifier: URL_SAFE_NO_PAD
            .encode(subject_key_identifier(&platform_parsed).unwrap()),
        serial_number: trust::canonical_serial_hex(leaf_parsed.raw_serial()).unwrap(),
        leaf_sha256: sha256_identifier(&leaf_der),
        platform_sha256: sha256_identifier(&platform_der),
        root_sha256: sha256_identifier(&root_der),
        leaf_der,
        platform_der,
        root_der,
    }
}

fn root_certificate(key: &PKeyRef<Private>) -> X509 {
    let mut builder = base_certificate_builder("TZAP Harness Root", key, None);
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(2)
                .build()
                .unwrap(),
        )
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    append_subject_key_identifier(&mut builder, None);
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn intermediate_certificate(
    key: &PKeyRef<Private>,
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    aki_source: &X509Ref,
) -> X509 {
    let mut builder =
        base_certificate_builder("TZAP Harness Platform Intermediate", key, Some(issuer_cert));
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .unwrap(),
        )
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    append_subject_key_identifier(&mut builder, None);
    append_authority_key_identifier(&mut builder, aki_source);
    append_der_extension(
        &mut builder,
        "2.5.29.32",
        false,
        &certificate_policies_der(&[trust::TZAP_OID_CA_POLICY]),
    );
    append_der_extension(&mut builder, "2.5.29.31", false, &[0x30, 0x00]);
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn leaf_certificate(
    key: &PKeyRef<Private>,
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    aki_source: &X509Ref,
) -> X509 {
    let mut builder = base_certificate_builder("TZAP Harness Signer", key, Some(issuer_cert));
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    let mut eku = ExtendedKeyUsage::new();
    eku.other(trust::TZAP_OID_DOCUMENT_SIGNING_EKU);
    builder.append_extension(eku.build().unwrap()).unwrap();
    append_authority_key_identifier(&mut builder, aki_source);
    append_der_extension(
        &mut builder,
        "2.5.29.32",
        false,
        &certificate_policies_der(&[trust::TZAP_OID_LEAF_POLICY]),
    );
    append_der_extension(
        &mut builder,
        trust::TZAP_OID_METADATA_EXTENSION,
        false,
        &metadata_extension_bytes(),
    );
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn base_certificate_builder(
    common_name: &str,
    key: &PKeyRef<Private>,
    issuer: Option<&X509Ref>,
) -> openssl::x509::X509Builder {
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    if let Some(issuer) = issuer {
        builder.set_issuer_name(issuer.subject_name()).unwrap();
    } else {
        builder.set_issuer_name(&name).unwrap();
    }
    builder.set_pubkey(key).unwrap();
    let not_before = Asn1Time::from_unix(FIXED_NOT_BEFORE).unwrap();
    let not_after = Asn1Time::from_unix(FIXED_NOT_AFTER).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder
}

fn p256_private_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn serial_number() -> openssl::asn1::Asn1Integer {
    BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap()
}

fn append_subject_key_identifier(
    builder: &mut openssl::x509::X509Builder,
    issuer: Option<&X509Ref>,
) {
    let extension = {
        let context = builder.x509v3_context(issuer, None);
        SubjectKeyIdentifier::new().build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

fn append_authority_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: &X509Ref) {
    let extension = {
        let context = builder.x509v3_context(Some(issuer), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .unwrap()
    };
    builder.append_extension(extension).unwrap();
}

fn append_der_extension(
    builder: &mut openssl::x509::X509Builder,
    oid: &str,
    critical: bool,
    contents: &[u8],
) {
    let oid = Asn1Object::from_str(oid).unwrap();
    let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
    builder
        .append_extension(X509Extension::new_from_der(&oid, critical, &contents).unwrap())
        .unwrap();
}

fn certificate_policies_der(policies: &[&str]) -> Vec<u8> {
    let policy_infos = policies
        .iter()
        .flat_map(|policy| der_sequence(&der_oid(policy)))
        .collect::<Vec<_>>();
    der_sequence(&policy_infos)
}

fn der_oid(oid: &str) -> Vec<u8> {
    der_wrap(0x06, Asn1Object::from_str(oid).unwrap().as_slice())
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x30, contents)
}

fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(contents.len()));
    out.extend(contents);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn metadata_extension_bytes() -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&json!({
        "version": 1,
        "public_signer_id": "psign_0123456789ABCDEFGH",
        "public_org_id": Value::Null,
        "public_device_id": "pdev_0123456789ABCDEFGH",
        "assurance_level": "oauth_verified_email",
        "policy_oid": trust::TZAP_OID_LEAF_POLICY,
    }))
    .unwrap()
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

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            Some(identifier.0.to_vec())
        } else {
            None
        }
    })
}

fn sha256_identifier(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    trust::format_sha256_identifier(&digest)
}

fn pin_set(root_sha256: &str) -> TzapRootPinSet {
    let pin: &'static str = Box::leak(root_sha256.to_owned().into_boxed_str());
    let current: &'static [&'static str] = Box::leak(vec![pin].into_boxed_slice());
    TzapRootPinSet {
        current,
        planned_successors: &[
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    }
}

fn json_response(value: Value) -> TzapAuthHttpResponse {
    json_response_with_code(200, value)
}

fn json_response_with_code(status_code: u16, value: Value) -> TzapAuthHttpResponse {
    TzapAuthHttpResponse {
        status_code,
        body: serde_json::to_vec(&value).unwrap(),
    }
}

#[derive(Clone)]
struct AcceptingLifecycleValidator;

impl zmanager_core::enrollment_client::TzapEnrollmentCertificateValidator
    for AcceptingLifecycleValidator
{
    fn validate_certificate_chain(
        &self,
        _chain_der: &[Vec<u8>],
    ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
        Ok(public_metadata())
    }
}

struct FakeTransport {
    responses: RefCell<VecDeque<TzapAuthHttpResponse>>,
    requests: RefCell<Vec<TzapAuthHttpRequest>>,
}

impl FakeTransport {
    fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            requests: RefCell::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<TzapAuthHttpRequest> {
        self.requests.borrow().clone()
    }
}

impl TzapAuthHttpTransport for FakeTransport {
    fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
        self.requests.borrow_mut().push(request.clone());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or(TzapAuthError::HttpStatus { status_code: 599 })
    }
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self, child: &str) -> PathBuf {
        self.path.join(child)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.path.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
