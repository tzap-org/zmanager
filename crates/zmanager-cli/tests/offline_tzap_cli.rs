//! Exercise the offline CLI with a pre-existing identity, without hosted login.
#![cfg(windows)]
mod common;

use common::*;
use serde_json::{Value, json};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::local_identity_store::TzapLocalIdentityStore;
use zmanager_tzap_hosted::auth_client::{TzapBearerToken, TzapSessionRecord};
use zmanager_tzap_hosted::keyring_store::NativeTzapLocalIdentityStore;
use zmanager_tzap_hosted::local_tzap_service::{TzapLocalServiceOptions, enroll_local_certificate};
use zmanager_tzap_hosted::trust::TzapIdentityAssurance;

struct TestIdentity(NativeTzapLocalIdentityStore);

impl Drop for TestIdentity {
    fn drop(&mut self) {
        self.0.clear_inventory("default").unwrap();
    }
}

#[test]
// Keep the sequence together: later steps consume identities and contacts
// produced by earlier CLI invocations, just as an offline user would.
#[allow(clippy::too_many_lines)]
fn offline_document_sign_verify_contacts_and_share() {
    let temp = TestDir::new("offline-sign-verify");
    let state = temp.path("identity");
    let mut identity = TestIdentity(NativeTzapLocalIdentityStore::new(&state, "default").unwrap());
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
    let root = temp.path("root.der");
    fs::write(&root, certificate.intermediate_chain_der.last().unwrap()).unwrap();
    let payload = temp.path("payload.json");
    let envelope = temp.path("envelope.json");
    fs::write(&payload, br#"{"tzap_payload_version":1,"title":"Offline audit","amount":42}"#).unwrap();
    let binary = std::env::var_os("ZMANAGER_AUDIT_BINARY").map_or_else(zm_path, std::path::PathBuf::from);
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
    let mut signed: Value = serde_json::from_slice(&fs::read(&envelope).unwrap()).unwrap();
    signed["document_payload"]["amount"] = json!(43);
    fs::write(&envelope, serde_json::to_vec(&signed).unwrap()).unwrap();
    let invalid = verify();
    assert_failure("tampered document", &invalid);
    let result: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(result["state"], "invalid");

    let mut contact_ids = Vec::new();
    let mut key_ids = Vec::new();
    for number in 0..2 {
        let keygen = Command::new(&binary).args(["tzap", "contact", "keygen", "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
        assert_success("offline contact keygen", &keygen);
        let result: Value = serde_json::from_slice(&keygen.stdout).unwrap();
        let key_id = result["recipient_key_id"].as_str().unwrap().to_owned();
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
    let list = Command::new(&binary).args(["tzap", "contact", "list", "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
    assert_success("offline contact list", &list);
    let result: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(result["contacts"].as_array().unwrap().len(), 2);
    let archive = temp.path("shared.tzap");
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
    let inventory = identity.0.load_inventory("default").unwrap();
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
        assert_eq!(fs::read(output_dir.join("payload.json")).unwrap(), fs::read(&payload).unwrap());
    }
    for contact_id in &contact_ids {
        let remove = Command::new(&binary).args(["tzap", "contact", "remove", contact_id, "--state-dir", state.to_str().unwrap(), "--json"]).output().unwrap();
        assert_success("offline contact remove", &remove);
    }
    assert_failure("removed recipients cannot be shared to", &share(true));
}
