#![cfg(feature = "tzap-online")]
mod common;

use common::*;
use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

#[test]
fn callback_rejects_mixed_and_retired_inputs_before_secure_storage() {
    let temp = TestDir::new("callback-input-boundary");
    let state = temp.path("state");
    let relay = temp.path("retired-relay.json");
    const PRIVATE: &str = "fixture-private-relay-must-never-be-read";
    fs::write(&relay, format!("{{\"access_token\":\"{PRIVATE}\"}}")).unwrap();
    for args in [
        vec!["--stdin", "--callback-url", "tzap://auth/callback"],
        vec!["--callback-url", "tzap://auth/callback", "--state", "fixture"],
        vec!["--state", "fixture", "--state", "fixture"],
        vec!["--stdin", "--stdin"],
        vec!["--relay-body", relay.to_str().unwrap()],
    ] {
        let output = zm().args(["auth", "callback", "--state-dir", state.to_str().unwrap()]).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(PRIVATE));
        assert!(!state.exists(), "invalid input touched storage");
    }
}

#[test]
fn callback_stdin_is_bounded_utf8_and_never_echoes_invalid_input() {
    let temp = TestDir::new("callback-bounded-stdin");
    let state = temp.path("state");
    const PRIVATE: &str = "fixture-confidential-input-must-not-be-echoed";
    for bytes in [Vec::new(), vec![0xff], PRIVATE.repeat(300).into_bytes()] {
        let mut child = zm()
            .args(["auth", "callback", "--stdin", "--state-dir", state.to_str().unwrap(), "--json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&bytes);
        let output = child.wait_with_output().unwrap();
        assert_failure("invalid callback stdin", &output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIVATE));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(PRIVATE));
        assert!(!state.exists(), "invalid input touched storage");
    }
}

#[test]
fn verify_json_reports_invalid_without_claiming_official_validity() {
    let temp = TestDir::new("zm_tzap_verify");
    let envelope = temp.path("bad-envelope.json");
    fs::write(&envelope, br#"{"not":"a tzap envelope"}"#).unwrap();

    let output = zm().args(["tzap", "verify", envelope.to_str().unwrap(), "--json"]).output().unwrap();
    assert_failure("verify", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"state\":\"invalid\""));
    assert!(stdout.contains("\"trust_anchor_type\":\"untrusted\""));
    assert!(!stdout.contains("official_tzap"));
}

/// Run explicitly with the ignored credential file and installed Playwright.
/// The runner uses a real browser/server and the native credential store.
#[test]
#[ignore = "requires staging credentials, a browser, and native secure storage"]
fn real_staging_browser_native_identity_flow() {
    assert!(std::env::var_os("ZM_STAGING_ENV_FILE").is_some(), "set ZM_STAGING_ENV_FILE to the ignored staging credential file");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/staging-cli-native-e2e.mjs");
    let output = Command::new("node").arg(script).env("ZM_STAGING_BINARY", zm_path()).output().unwrap();
    assert_success("real staging browser/native identity E2E", &output);
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

fn zm() -> Command {
    Command::new(zm_path())
}
