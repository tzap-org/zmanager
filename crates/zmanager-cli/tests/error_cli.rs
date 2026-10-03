mod common;
use common::*;
use std::io::Write as _;
use std::process::{Command, Stdio};

#[cfg(windows)]
#[test]
fn windows_symlink_extraction_failure_explains_privilege_and_retry() {
    use zmanager_core::backend_test_support::tzap::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};
    use zmanager_core::jobs::{CancellationToken, JobContext};
    use zmanager_core::manifest::{ManifestEntry, ManifestFileType, PermissionSnapshot, PlanOptions, plan_archive};

    let temp = TestDir::new("symlink-permission-guidance");
    let source = temp.path("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file.txt"), b"symlink target").unwrap();
    let probe = temp.path("probe");
    let lacks_privilege = match std::os::windows::fs::symlink_file("file.txt", &probe) {
        Ok(()) => {
            std::fs::remove_file(probe).unwrap();
            false
        }
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(1314), "unexpected probe failure: {error}");
            true
        }
    };
    // A synthetic manifest lets an unprivileged host create an archive that
    // contains a symlink, so the actual CLI failure remains testable.
    let mut manifest = plan_archive(&source, &PlanOptions::default()).unwrap();
    manifest.entries.push(ManifestEntry {
        archive_path: "source/link.txt".to_owned(),
        source_path: temp.path("synthetic-link"),
        file_type: ManifestFileType::Symlink,
        size: 0,
        modified: None,
        permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o777) },
        symlink_target: Some("file.txt".into()),
    });
    let archive = temp.path("links.tzap");
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: false,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();
    let output =
        Command::new(zm_path()).args(["extract", archive.to_str().unwrap(), "-C", temp.path("out").to_str().unwrap(), "--no-progress"]).output().unwrap();
    if lacks_privilege {
        assert_failure("unprivileged symlink extraction", &output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("[y/N]"), "redirected CLI invocation must never offer elevation: {stderr}");
        for guidance in ["failed to create symlink", "Developer Mode", "Run as administrator", "fresh output directory"] {
            assert!(stderr.contains(guidance), "missing {guidance}: {stderr}");
        }
    } else {
        assert_success("privileged symlink extraction", &output);
        assert_eq!(std::fs::read_link(temp.path("out/source/link.txt")).unwrap(), std::path::PathBuf::from("file.txt"));
        assert_eq!(std::fs::read(temp.path("out/source/link.txt")).unwrap(), b"symlink target");
    }
}

#[test]
fn incorrect_tzap_password_explains_how_unlocking_failed() {
    let temp = TestDir::new("tzap-password-guidance");
    let source = temp.path("hello.txt");
    let archive = temp.path("secret.tzap");
    std::fs::write(&source, b"offline password UX test").unwrap();
    let mut create = Command::new(zm_path())
        .args(["create", archive.to_str().unwrap(), source.to_str().unwrap(), "--password-stdin", "--no-progress"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    create.stdin.take().unwrap().write_all(b"correct-test-password\n").unwrap();
    assert_success("create encrypted TZAP", &create.wait_with_output().unwrap());
    let mut extract = Command::new(zm_path())
        .args(["extract", archive.to_str().unwrap(), "-C", temp.path("out").to_str().unwrap(), "--password-stdin", "--no-progress"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    extract.stdin.take().unwrap().write_all(b"incorrect-test-password\n").unwrap();
    let output = extract.wait_with_output().unwrap();
    assert_failure("incorrect password", &output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incorrect password or damaged encrypted header"), "{stderr}");
    assert!(!stderr.contains("HMAC verification failed"), "default guidance should use everyday language: {stderr}");
    assert!(!temp.path("out/hello.txt").exists());
}

#[test]
// Auth-command argument handling only exists in the full build; the
// offline binary's `zm auth` is a stub that rejects everything.
#[cfg(feature = "tzap-online")]
fn test_missing_argument_value_does_not_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_zm"))
        .arg("auth")
        .arg("login")
        .arg("--state-dir")
        // Missing the actual value for --state-dir
        .output()
        .expect("Failed to execute zm");

    // It should exit with a non-zero code (1), not a panic (e.g. 101)
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check that it didn't panic (Rust panics usually contain "thread 'main' panicked")
    assert!(!stderr.contains("panicked"));
    assert!(stderr.contains("missing value for"));
}

#[cfg(not(feature = "tzap-online"))]
#[test]
fn reduced_profile_has_no_auth_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_zm")).args(["auth", "login"]).output().expect("Failed to execute zm");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The reduced build has no auth surface at all: `zm auth` is an unknown
    // command that falls through to the usage error, which must not
    // advertise the auth command.
    assert!(stderr.contains("Usage:"));
    assert!(!stderr.contains("auth <command>"));
}
