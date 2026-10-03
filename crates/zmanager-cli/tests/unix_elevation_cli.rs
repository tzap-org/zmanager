//! Terminal-level checks of sudo consent without requiring a real password.
#![cfg(unix)]
mod common;
use common::{assert_failure, assert_success, find_on_path, record_optional_skip, zm_path};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn protected_destination_consent_cancellation_and_unattended_modes() {
    // Root cannot reproduce a normal user's permission failure. The Docker
    // validation runs this harness separately as an unprivileged fixture user.
    if rustix::process::geteuid().is_root() {
        record_optional_skip("requires an unprivileged user");
        return;
    }
    let python = find_on_path("python3").expect("Python is required for Unix terminal coverage");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/test-unix-elevation.py");
    let output = Command::new(python).arg(script).arg(zm_path()).env_remove("ZMANAGER_TEST_SUDO_PASSWORD").output().unwrap();
    assert_success("Unix sudo terminal UX", &output);
}

#[test]
fn elevated_retry_rejects_an_unprivileged_process() {
    if rustix::process::geteuid().is_root() {
        record_optional_skip("requires an unprivileged user");
        return;
    }
    let output = Command::new(zm_path()).args(["__unix-elevated-extract", "--version"]).output().unwrap();
    assert_failure("unprivileged elevated retry", &output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a root process"));
}
