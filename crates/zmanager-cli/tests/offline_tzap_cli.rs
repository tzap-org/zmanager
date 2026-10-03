//! Exercise the offline CLI with a pre-existing identity, without hosted login.
mod common;

use common::*;
use serde_json::{Value, json};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::identity_catalog::{FileTzapIdentityCatalogStore, TzapIdentityCatalogStore as _, TzapSecretPurpose};
use zmanager_core::local_identity_store::{FileTzapLocalIdentityStore, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord};
use zmanager_tzap_hosted::auth_client::{TzapBearerToken, TzapSessionRecord};
#[cfg(not(target_os = "macos"))]
use zmanager_tzap_hosted::keyring_store::NativeTzapSecretStore;
use zmanager_tzap_hosted::local_tzap_service::{TzapLocalServiceOptions, enroll_local_certificate};
use zmanager_tzap_hosted::trust::TzapIdentityAssurance;

struct TestIdentity(FileTzapLocalIdentityStore, std::path::PathBuf);

impl Drop for TestIdentity {
    fn drop(&mut self) {
        // Delete only this fixture's random references, without resolving keys
        // created by the CLI (which would ask for cross-application Keychain access).
        let catalogs = FileTzapIdentityCatalogStore::new(&self.1);
        if let Some(catalog) = catalogs.load_catalog("default").unwrap() {
            for identity in catalog.signing_identities {
                delete_fixture_secret(TzapSecretPurpose::SigningKey, &identity.signing_key_ref);
            }
            for key in catalog.recipient_keys {
                delete_fixture_secret(TzapSecretPurpose::RecipientKey, &key.private_key_ref);
            }
        }
    }
}

#[test]
// Keep the sequence together: later steps consume identities and contacts
// produced by earlier CLI invocations, just as an offline user would.
#[allow(clippy::too_many_lines)]
fn offline_document_sign_verify_contacts_and_share() {
    let temp = TestDir::new("offline-sign-verify");
    let state = temp.path("identity");
    let mut identity = TestIdentity(FileTzapLocalIdentityStore::new(&state), state.clone());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Provision a TEST identity directly. No Full CLI, auth session file, or
    // network service is involved. Users must already have an enrolled identity.
    let session = TzapSessionRecord {
        audience: "sign.tzap.org".to_owned(),
        access_token: TzapBearerToken::new("test-only-local-fixture").unwrap(),
        expires_at_unix_seconds: now + 3600,
        identity_assurance: TzapIdentityAssurance::OauthVerifiedEmail,
        selected_org_id: None,
        login_session_id: None,
    };
    let certificate =
        enroll_local_certificate(&mut identity.0, &session, &TzapLocalServiceOptions { account_key: "default".to_owned(), now_unix_seconds: now }).unwrap();
    let mut inventory = identity.0.load_inventory("default").unwrap();
    for _ in 0..2 {
        let material = zmanager_core::device_identity::generate_recipient_encryption_key().unwrap();
        inventory.recipient_encryption_keys.push(TzapRecipientEncryptionKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            algorithm: material.algorithm.to_owned(),
            public_key_fingerprint: material.public_key_fingerprint,
            public_key_der: material.public_key_spki_der,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: now,
            label: Some("Offline fixture recipient".to_owned()),
        });
    }
    identity.0.save_inventory("default", inventory.clone()).unwrap();
    let root = temp.path("root.der");
    fs::write(&root, certificate.intermediate_chain_der.last().unwrap()).unwrap();
    let payload = temp.path("payload with spaces 雪.json");
    let envelope = temp.path("envelope.json");
    fs::write(&payload, br#"{"tzap_payload_version":1,"title":"Offline audit","amount":42}"#).unwrap();
    let binary = zm_path();
    let list = Command::new(&binary).args(["tzap", "certs", "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
    assert_success("offline certs", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains(&certificate.certificate_id));
    let sign = Command::new(&binary)
        .args([
            "tzap",
            "sign",
            payload.to_str().unwrap(),
            "--certificate-id",
            &certificate.certificate_id,
            "--output",
            envelope.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("offline sign", &sign);
    #[cfg(unix)]
    {
        let previous = fs::read(&envelope).unwrap();
        let mut command = Command::new(&binary);
        command.args([
            "tzap",
            "sign",
            payload.to_str().unwrap(),
            "--certificate-id",
            &certificate.certificate_id,
            "--output",
            envelope.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ]);
        let failed = output_with_file_size_limit(&command, 1024);
        assert_failure("document output exceeds OS file limit", &failed);
        assert!(String::from_utf8_lossy(&failed.stderr).contains("sign failed:"));
        assert_eq!(fs::read(&envelope).unwrap(), previous, "failed document write must preserve the previous envelope");
        assert_success("document export recovers after write failure", &command.output().unwrap());
    }
    let verify = || {
        Command::new(&binary)
            .args(["tzap", "verify", envelope.to_str().unwrap(), "--custom-trust-root-cert", root.to_str().unwrap(), "--json"])
            .output()
            .unwrap()
    };
    let valid = verify();
    assert_success("offline verify", &valid);
    let result: Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(result["state"], "cryptographically_intact_offline");
    assert_eq!(result["trust_anchor_type"], "custom");
    let untrusted = Command::new(&binary).args(["tzap", "verify", envelope.to_str().unwrap(), "--json"]).output().unwrap();
    assert_failure("custom signer requires explicit trust", &untrusted);
    let mut signed: Value = serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
    signed["document_payload"]["amount"] = json!(43);
    fs::write(&envelope, serde_json::to_vec(&signed).unwrap()).unwrap();
    let invalid = verify();
    assert_failure("tampered document", &invalid);
    let result: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(result["state"], "invalid");

    let mut contact_ids = Vec::new();
    let mut key_ids = Vec::new();
    let mut generated_key_ids = Vec::new();
    for number in 0..2 {
        let keygen = Command::new(&binary).args(["tzap", "contact", "keygen", "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
        assert_success("offline contact keygen", &keygen);
        let result: Value = serde_json::from_slice(&keygen.stdout).unwrap();
        let generated_key_id = result["recipient_key_id"].as_str().unwrap().to_owned();
        assert!(!generated_key_ids.contains(&generated_key_id));
        generated_key_ids.push(generated_key_id);
        // Use the provisioned fixture keys for round-trip checks. Keeping their
        // private material in memory avoids granting the test binary access to
        // keys created by a different application on macOS.
        let key_id = inventory.recipient_encryption_keys[number].key_id.clone();
        let card = temp.path(format!("contact-{number}.json"));
        let export = Command::new(&binary)
            .args([
                "tzap",
                "contact",
                "export",
                "--recipient-key-id",
                &key_id,
                "--certificate-id",
                &certificate.certificate_id,
                "--display-name",
                "Offline Test Contact",
                "--output",
                card.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_success("offline contact export", &export);
        #[cfg(unix)]
        {
            let previous = fs::read(&card).unwrap();
            let mut command = Command::new(&binary);
            command.args([
                "tzap",
                "contact",
                "export",
                "--recipient-key-id",
                &key_id,
                "--certificate-id",
                &certificate.certificate_id,
                "--display-name",
                "Offline Test Contact",
                "--output",
                card.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ]);
            assert_failure("contact output exceeds OS file limit", &output_with_file_size_limit(&command, 1024));
            assert_eq!(fs::read(&card).unwrap(), previous, "failed contact write must preserve the previous card");
            assert_success("contact export recovers after write failure", &command.output().unwrap());
        }
        let import = || {
            Command::new(&binary)
                .args([
                    "tzap",
                    "contact",
                    "import",
                    card.to_str().unwrap(),
                    "--custom-trust-root-cert",
                    root.to_str().unwrap(),
                    "--state-dir",
                    state.to_str().unwrap(),
                    "--accept",
                    "--json",
                ])
                .output()
                .unwrap()
        };
        let imported = import();
        assert_success("offline contact import", &imported);
        let result: Value = serde_json::from_slice(&imported.stdout).unwrap();
        contact_ids.push(result["contact"]["contact_id"].as_str().unwrap().to_owned());
        key_ids.push(key_id);
        // Changing a signed card must not overwrite an accepted contact.
        let mut card_json: Value = serde_json::from_slice(&fs::read(&card).unwrap()).unwrap();
        card_json["payload"]["display_name"] = json!("Tampered Contact");
        fs::write(&card, serde_json::to_vec(&card_json).unwrap()).unwrap();
        assert_failure("tampered contact import", &import());
    }
    let catalog = FileTzapIdentityCatalogStore::new(&state).load_catalog("default").unwrap().unwrap();
    for key_id in generated_key_ids {
        assert!(catalog.recipient_keys.iter().any(|key| key.id == key_id && !key.public_key_der.is_empty()), "generated recipient key must persist");
    }
    let list = Command::new(&binary).args(["tzap", "contact", "list", "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
    assert_success("offline contact list", &list);
    let result: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(result["contacts"].as_array().unwrap().len(), 2);
    let archive = temp.path("shared with spaces 雪.tzap");
    let share = |force: bool| {
        let mut command = Command::new(&binary);
        command.args([
            "tzap",
            "share",
            archive.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--certificate-id",
            &certificate.certificate_id,
            "--contact",
            &contact_ids[0],
            "--contact",
            &contact_ids[1],
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ]);
        if force {
            command.arg("--force");
        }
        command.output().unwrap()
    };
    let shared = share(false);
    assert_success("offline share to two contacts", &shared);
    let result: Value = serde_json::from_slice(&shared.stdout).unwrap();
    assert_eq!(result["recipients"], 2);
    assert_failure("share refuses overwrite", &share(false));
    assert_success("share force replaces archive", &share(true));
    let no_key = Command::new(&binary)
        .args(["extract", archive.to_str().unwrap(), "-C", temp.path("no-key").to_str().unwrap(), "--no-password-prompt"])
        .output()
        .unwrap();
    assert_failure("recipient archive rejects missing key", &no_key);
    for (number, key_id) in key_ids.iter().enumerate() {
        let key = inventory.recipient_encryption_keys.iter().find(|key| &key.key_id == key_id).unwrap();
        let key_path = temp.path(format!("recipient-{number}.der"));
        fs::write(&key_path, key.private_key_der.expose_secret()).unwrap();
        let output_dir = temp.path(format!("recipient-out-{number}"));
        let extract = Command::new(&binary)
            .args(["extract", archive.to_str().unwrap(), "-C", output_dir.to_str().unwrap(), "--recipient-key", key_path.to_str().unwrap(), "--no-progress"])
            .output()
            .unwrap();
        assert_success("each recipient decrypts shared archive", &extract);
        assert_eq!(fs::read(output_dir.join(payload.file_name().unwrap())).unwrap(), fs::read(&payload).unwrap());
        let list = Command::new(&binary).args(["list", archive.to_str().unwrap(), "--recipient-key", key_path.to_str().unwrap(), "--json"]).output().unwrap();
        assert_success("recipient lists encrypted archive", &list);
        let streamed = Command::new(&binary)
            .args(["extract", archive.to_str().unwrap(), "--recipient-key", key_path.to_str().unwrap(), "--to-stdout", "--no-progress"])
            .output()
            .unwrap();
        assert_success("recipient extracts payload to stdout", &streamed);
        assert_eq!(streamed.stdout, fs::read(&payload).unwrap());
    }
    for contact_id in &contact_ids {
        let remove = Command::new(&binary).args(["tzap", "contact", "remove", contact_id, "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
        assert_success("offline contact remove", &remove);
    }
    let previous_archive = fs::read(&archive).unwrap();
    assert_failure("removed recipients cannot be shared to", &share(true));
    assert_eq!(fs::read(&archive).unwrap(), previous_archive, "failed forced share must preserve the existing archive");
}

fn delete_fixture_secret(purpose: TzapSecretPurpose, reference: &zmanager_core::identity_catalog::TzapSecretRef) {
    #[cfg(target_os = "macos")]
    {
        // The keyring crate resolves a secret before deletion on macOS. The
        // system tool deletes by attributes, avoiding cross-application access.
        let output = Command::new("/usr/bin/security")
            .args(["delete-generic-password", "-s", "org.tzap.zmanager.identity", "-a"])
            .arg(format!("default:{}:{}", purpose.as_str(), reference.as_str()))
            .output()
            .unwrap();
        assert_success("remove fixture Keychain item", &output);
    }
    #[cfg(not(target_os = "macos"))]
    {
        use zmanager_core::identity_catalog::TzapSecretMaterialStore as _;
        NativeTzapSecretStore::new("default").unwrap().delete(purpose, reference).unwrap();
    }
}

fn offline_command(args: &[&str], state: &std::path::Path) -> std::process::Output {
    Command::new(zm_path())
        .args(args)
        .args(["--state-dir", state.to_str().unwrap(), "--json"])
        // Offline commands must work with no reachable hosted endpoint.
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap()
}

#[test]
fn fresh_offline_install_lists_empty_certificates_without_creating_state() {
    let temp = TestDir::new("offline-empty-certs");
    let state = temp.path("absent-state");
    let result = offline_command(&["tzap", "certs"], &state);
    assert_success("empty certificates", &result);
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap(), json!({"certificates": []}));
    assert!(result.stderr.is_empty());
    assert!(!state.exists());
}

#[test]
fn certificate_discovery_does_not_require_private_keys() {
    let temp = TestDir::new("offline-public-certs");
    let state = temp.path("identity");
    let mut store = FileTzapLocalIdentityStore::new(&state);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let session = TzapSessionRecord {
        audience: "sign.tzap.org".to_owned(),
        access_token: TzapBearerToken::new("test-only-local-fixture").unwrap(),
        expires_at_unix_seconds: now + 3600,
        identity_assurance: TzapIdentityAssurance::OauthVerifiedEmail,
        selected_org_id: None,
        login_session_id: None,
    };
    let certificate =
        enroll_local_certificate(&mut store, &session, &TzapLocalServiceOptions { account_key: "default".to_owned(), now_unix_seconds: now }).unwrap();
    fs::remove_dir_all(state.join("secrets")).unwrap();
    let result = offline_command(&["tzap", "certs"], &state);
    assert_success("public certificate discovery with unavailable keys", &result);
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["certificates"].as_array().unwrap().len(), 1);
    assert_eq!(result["certificates"][0]["certificate_id"], certificate.certificate_id);
    assert_eq!(result["certificates"][0]["certificate_sha256"], certificate.certificate_sha256);
    assert_eq!(result["certificates"][0]["state"], "active");
    assert!(!state.join("secrets").exists());
    let text = Command::new(zm_path()).args(["tzap", "certs", "--state-dir", state.to_str().unwrap()]).output().unwrap();
    assert_success("public certificate text listing", &text);
    assert!(String::from_utf8_lossy(&text.stdout).contains(&certificate.certificate_id));
}

#[test]
fn offline_certificate_discovery_rejects_invalid_account_paths() {
    let temp = TestDir::new("offline-invalid-account");
    for account in ["../outside", "a/b", "a\\b"] {
        let output = offline_command(&["tzap", "certs", "--account-key", account], temp.root());
        assert_failure("invalid account", &output);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}

#[test]
fn fresh_offline_install_explains_how_to_obtain_signing_certificates() {
    let temp = TestDir::new("offline-first-run");
    let result = Command::new(zm_path()).args(["tzap", "certs", "--state-dir", temp.root().to_str().unwrap()]).output().unwrap();
    assert_success("first-run guidance", &result);
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(output.contains("no local certificates"));
    assert!(output.contains("Full build or desktop/mobile app"));
    assert!(output.contains("zm create --help"));
}

#[test]
fn offline_sign_rejects_malformed_payload_without_writing_output() {
    let temp = TestDir::new("offline-invalid-payload");
    let payload = temp.path("broken.json");
    let envelope = temp.path("envelope.json");
    fs::write(&payload, b"{broken").unwrap();
    let result = offline_command(
        &["tzap", "sign", payload.to_str().unwrap(), "--certificate-id", "missing", "--output", envelope.to_str().unwrap()],
        &temp.path("state"),
    );
    assert_failure("malformed payload", &result);
    assert!(!envelope.exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
}

#[test]
fn offline_sign_requires_an_enrolled_identity_without_creating_output() {
    let temp = TestDir::new("offline-no-identity");
    let payload = temp.path("document.json");
    let envelope = temp.path("envelope.json");
    fs::write(&payload, br#"{"tzap_payload_version":1,"title":"Offline"}"#).unwrap();
    let result = offline_command(
        &["tzap", "sign", payload.to_str().unwrap(), "--certificate-id", "missing", "--output", envelope.to_str().unwrap()],
        &temp.path("state"),
    );
    assert_failure("missing enrolled identity", &result);
    assert!(!envelope.exists());
    let error: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(error["ok"], false);
    assert_eq!(error["error"], "document signing certificate was not found");
}

#[test]
fn offline_verify_rejects_malformed_envelope() {
    let temp = TestDir::new("offline-invalid-envelope");
    let envelope = temp.path("invalid.json");
    fs::write(&envelope, b"{}").unwrap();
    let result = Command::new(zm_path()).args(["tzap", "verify", envelope.to_str().unwrap(), "--json"]).output().unwrap();
    assert_failure("invalid envelope", &result);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
}

#[test]
fn offline_contact_import_rejects_malformed_card_without_accepting_contact() {
    let temp = TestDir::new("offline-invalid-card");
    let card = temp.path("card.json");
    let state = temp.path("state");
    fs::write(&card, b"{}").unwrap();
    let result = offline_command(&["tzap", "contact", "import", card.to_str().unwrap(), "--accept"], &state);
    assert_failure("invalid contact card", &result);
    let list = offline_command(&["tzap", "contact", "list"], &state);
    assert_success("contacts remain empty", &list);
    assert!(serde_json::from_slice::<Value>(&list.stdout).unwrap()["contacts"].as_array().unwrap().is_empty());
}

#[test]
fn offline_share_rejects_unknown_contact_without_creating_archive() {
    let temp = TestDir::new("offline-invalid-share");
    let source = temp.path("source.txt");
    let archive = temp.path("shared.tzap");
    fs::write(&source, b"offline payload").unwrap();
    let result = offline_command(
        &["tzap", "share", archive.to_str().unwrap(), source.to_str().unwrap(), "--certificate-id", "missing", "--contact", "unknown"],
        &temp.path("state"),
    );
    assert_failure("unknown contact", &result);
    assert!(!archive.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn unavailable_secret_service_preserves_catalog_and_keygen_recovers() {
    use zmanager_core::identity_catalog::TzapIdentityCatalog;

    let temp = TestDir::new("offline-unavailable-keyring");
    let state = temp.path("state");
    let mut catalog_store = FileTzapIdentityCatalogStore::new(&state);
    let initial = TzapIdentityCatalog::empty();
    catalog_store.save_catalog("default", None, initial.clone()).unwrap();
    let unavailable = Command::new(zm_path())
        .args(["tzap", "contact", "keygen", "--state-dir", state.to_str().unwrap(), "--json"])
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", temp.path("absent-bus").display()))
        .output()
        .unwrap();
    assert_failure("keygen without Secret Service", &unavailable);
    let result: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(result["operation"], "contact_keygen");
    assert!(result["error"].as_str().unwrap().contains("secure secret store is unavailable"));
    assert_eq!(catalog_store.load_catalog("default").unwrap().unwrap(), initial, "failed keygen must not commit an unusable key");
    let recovered = offline_command(&["tzap", "contact", "keygen"], &state);
    assert_success("keygen after Secret Service recovery", &recovered);
    let catalog = catalog_store.load_catalog("default").unwrap().unwrap();
    assert_eq!(catalog.recipient_keys.len(), 1);
    delete_fixture_secret(TzapSecretPurpose::RecipientKey, &catalog.recipient_keys[0].private_key_ref);
}
