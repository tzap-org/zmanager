use super::{ArchiveFormat, CreateRequest, ExtractRequest, InteractiveOverwriteResolver, ListRequest, TestRequest, publish_archive};
use crate::cli::create::*;
use crate::cli::extract::*;
use crate::cli::open::*;
use crate::cli::options::*;
use crate::cli::tzap::*;
use crate::cli::usage::*;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;
use zmanager_core::safety::{OverwriteConflict, OverwriteDecision, OverwriteResolver};

#[cfg(feature = "tzap-online")]
#[test]
fn native_auth_defaults_match_registered_zmanager_cli_redirect() {
    assert_eq!(DEFAULT_TZAP_REDIRECT_URI, "tzap://auth/callback");
}

#[cfg(feature = "tzap-online")]
#[test]
fn hosted_http_transport_accepts_https_urls() {
    let client = reqwest::blocking::Client::new();
    let request = build_hosted_http_request(&client, "GET", "https://staging.tzap.org/v1/me", None, None, &[]).unwrap();

    assert_eq!(request.url().scheme(), "https");
    assert_eq!(request.url().host_str(), Some("staging.tzap.org"));
    assert_eq!(request.url().path(), "/v1/me");
}

#[cfg(feature = "tzap-online")]
#[test]
fn hosted_http_transport_attaches_headers_and_supports_all_methods() {
    let client = reqwest::blocking::Client::new();
    let headers = vec![("If-Match".to_string(), "\"etag-123\"".to_string())];
    let request = build_hosted_http_request(&client, "PUT", "https://staging.tzap.org/v1/backup", None, None, &headers).unwrap();

    assert_eq!(request.method(), reqwest::Method::PUT);
    assert_eq!(request.headers().get("if-match").and_then(|v| v.to_str().ok()), Some("\"etag-123\""));
}

#[test]
fn contact_keygen_persists_a_distinct_recipient_key() {
    let temp = TestDir::new("contact-keygen");
    let args = vec!["--state-dir".to_owned(), temp.root.display().to_string(), "--label".to_owned(), "Test recipient".to_owned(), "--json".to_owned()];

    let status = contact_keygen_command(&args, GlobalOptions::default());
    if status != std::process::ExitCode::SUCCESS {
        return;
    }

    let mut store = NativeTzapLocalIdentityStore::new(&temp.root, "default").unwrap();
    let inventory = store.load_inventory("default").unwrap();
    assert_eq!(inventory.recipient_encryption_keys.len(), 1);
    assert_eq!(inventory.recipient_encryption_keys[0].label.as_deref(), Some("Test recipient"));
    assert!(inventory.device_signing_keys.is_empty());
    store.clear_inventory("default").unwrap();
}

#[cfg(feature = "tzap-online")]
#[test]
fn pending_organization_enrollment_reuses_the_same_device_key() {
    let temp = TestDir::new("organization-enrollment-key-retry");
    let mut store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&temp.root);
    let request = zmanager_tzap_hosted::enrollment_client::TzapEnrollmentRequest {
        account_key: "default".to_owned(),
        org_id: Some("porg_test".to_owned()),
        requested_validity_seconds: 86_400,
        now_unix_seconds: 1_000,
    };

    let (first_key, first_csr) = create_and_store_staging_enrollment_key(&mut store, &request, 1_000).unwrap();
    let (retried_key, retried_csr) = create_and_store_staging_enrollment_key(&mut store, &request, 1_001).unwrap();

    assert_eq!(retried_key.key_id, first_key.key_id);
    assert_eq!(retried_key.private_key_der, first_key.private_key_der);
    assert!(!first_csr.is_empty());
    assert!(!retried_csr.is_empty());
    let inventory = store.load_inventory("default").unwrap();
    assert_eq!(inventory.device_signing_keys.len(), 1);
}

#[test]
fn password_prompt_treats_eof_as_cancelled() {
    assert_eq!(normalize_prompted_password(String::new(), 0), None);
}

#[test]
fn password_prompt_treats_empty_line_as_cancelled() {
    assert_eq!(normalize_prompted_password("\n".to_owned(), 1), None);
}

#[test]
fn password_prompt_strips_line_endings_without_logging_secret() {
    assert_eq!(normalize_prompted_password("secret\r\n".to_owned(), 8), Some("secret".to_owned()));
}

#[test]
fn password_prompt_preserves_utf8_encoding() {
    assert_eq!(normalize_prompted_password("パスワード\r\n".to_owned(), 17), Some("パスワード".to_owned()));
}

#[test]
fn retry_password_required_fails_if_prompts_disabled() {
    let global = GlobalOptions { no_password_prompt: true, ..Default::default() };
    let mut reported = String::new();
    let code = retry_password_required(&global, "test: ", Some("password: "), |msg| reported = msg.to_owned(), |_| std::process::ExitCode::SUCCESS);
    // 2 is usage error
    assert_eq!(format!("{code:?}"), format!("{:?}", std::process::ExitCode::from(2)));
    assert_eq!(reported, "test: password required and prompts are disabled");
}

#[test]
fn retry_password_required_fails_if_no_prompt_label() {
    let global = GlobalOptions::default();
    let mut reported = String::new();
    let code = retry_password_required(&global, "test: ", None, |msg| reported = msg.to_owned(), |_| std::process::ExitCode::SUCCESS);
    assert_eq!(format!("{code:?}"), format!("{:?}", std::process::ExitCode::from(2)));
    assert_eq!(reported, "test: password required but no prompt is available");
}

#[test]
fn create_parser_accepts_tzap_x509_signing_options() {
    let mut request = CreateRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings([
        "signed.tzap",
        "src",
        "--format",
        "tzap",
        "--password-stdin",
        "--signing-cert",
        "signer.pem",
        "--signing-private-key",
        "signer.key",
        "--signing-chain",
        "intermediate.pem",
    ]);

    parse_create_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.tzap_signing_cert, Some(PathBuf::from("signer.pem")));
    assert_eq!(request.tzap_signing_private_key, Some(PathBuf::from("signer.key")));
    assert_eq!(request.tzap_signing_chain, vec![PathBuf::from("intermediate.pem")]);
    assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
}

#[test]
fn create_validation_restricts_x509_signing_to_tzap() {
    let request = CreateRequest {
        archive: "signed.zip".to_owned(),
        sources: vec![PathBuf::from("src")],
        tzap_signing_cert: Some(PathBuf::from("signer.pem")),
        tzap_signing_private_key: Some(PathBuf::from("signer.key")),
        ..CreateRequest::default()
    };

    let error = validate_create_options(ArchiveFormat::Zip, &request).unwrap_err();

    assert!(error.contains("only for TZAP"));
}

#[test]
fn create_parser_accepts_signing_identity_with_no_certificate_id() {
    let mut request = CreateRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["signed.tzap", "src", "--format", "tzap", "--signing-identity", "--password-stdin"]);

    parse_create_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.tzap_signing_identity, Some(None));
    assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
}

#[test]
fn create_parser_accepts_signing_identity_with_explicit_certificate_id() {
    let mut request = CreateRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["signed.tzap", "src", "--format", "tzap", "--signing-identity", "cert-abc123"]);

    parse_create_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.tzap_signing_identity, Some(Some("cert-abc123".to_owned())));
    assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
}

#[test]
fn create_validation_rejects_signing_identity_combined_with_signing_cert() {
    let request = CreateRequest {
        archive: "signed.tzap".to_owned(),
        sources: vec![PathBuf::from("src")],
        tzap_signing_cert: Some(PathBuf::from("signer.pem")),
        tzap_signing_private_key: Some(PathBuf::from("signer.key")),
        tzap_signing_identity: Some(None),
        ..CreateRequest::default()
    };

    let error = validate_create_options(ArchiveFormat::Tzap, &request).unwrap_err();

    assert!(error.contains("--signing-identity cannot be combined"));
}

#[test]
fn create_validation_restricts_signing_identity_to_tzap() {
    let request =
        CreateRequest { archive: "signed.zip".to_owned(), sources: vec![PathBuf::from("src")], tzap_signing_identity: Some(None), ..CreateRequest::default() };

    let error = validate_create_options(ArchiveFormat::Zip, &request).unwrap_err();

    assert!(error.contains("only for TZAP"));
}

#[test]
fn create_validation_rejects_signing_identity_combined_with_recipient_cert() {
    let request = CreateRequest {
        archive: "sealed.tzap".to_owned(),
        sources: vec![PathBuf::from("src")],
        tzap_recipient_cert: Some(PathBuf::from("recipient.pem")),
        tzap_signing_identity: Some(None),
        ..CreateRequest::default()
    };

    let error = validate_create_options(ArchiveFormat::Tzap, &request).unwrap_err();

    assert!(error.contains("--recipient-cert cannot be combined with X.509 signing options"));
}

#[test]
fn create_parser_accepts_tzap_recipient_certificate() {
    let mut request = CreateRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["sealed.tzap", "src", "--format", "tzap", "--recipient-cert", "recipient.pem"]);

    parse_create_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.tzap_recipient_cert, Some(PathBuf::from("recipient.pem")));
    assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
}

#[test]
fn create_validation_rejects_recipient_certificate_password_mode() {
    let request = CreateRequest {
        archive: "sealed.tzap".to_owned(),
        sources: vec![PathBuf::from("src")],
        format: Some(ArchiveFormat::Tzap),
        password_stdin: true,
        tzap_recipient_cert: Some(PathBuf::from("recipient.pem")),
        ..CreateRequest::default()
    };

    let error = validate_create_options(ArchiveFormat::Tzap, &request).unwrap_err();

    assert!(error.contains("--recipient-cert cannot be combined"));
}

#[test]
fn create_validation_restricts_sidecar_to_tzap() {
    let request = CreateRequest { archive: "archive.zip".to_owned(), sources: vec![PathBuf::from("src")], tzap_sidecar: true, ..CreateRequest::default() };

    let error = validate_create_options(ArchiveFormat::Zip, &request).unwrap_err();
    assert!(error.contains("--sidecar is supported only for TZAP archives"));
}

#[test]
fn create_validation_rejects_sidecar_with_stdout() {
    let request = CreateRequest { archive: "-".to_owned(), sources: vec![PathBuf::from("src")], tzap_sidecar: true, ..CreateRequest::default() };

    let error = validate_create_options(ArchiveFormat::Tzap, &request).unwrap_err();
    assert!(error.contains("--sidecar cannot be used with stdout archive output"));
}

#[test]
fn open_parsers_accept_tzap_recipient_key() {
    let mut global = GlobalOptions::default();

    let mut extract = ExtractRequest::default();
    let extract_args = strings(["sealed.tzap", "-C", "out", "--recipient-key", "recipient.key"]);
    parse_extract_request(&extract_args, &mut global, &mut extract).unwrap();
    assert_eq!(extract.recipient_key, Some(PathBuf::from("recipient.key")));

    let mut list = ListRequest::default();
    let list_args = strings(["sealed.tzap", "--recipient-key", "recipient.key"]);
    parse_list_request(&list_args, &mut global, &mut list).unwrap();
    assert_eq!(list.recipient_key, Some(PathBuf::from("recipient.key")));

    let mut test = TestRequest::default();
    let test_args = strings(["sealed.tzap", "--recipient-key", "recipient.key"]);
    parse_test_request(&test_args, &mut global, &mut test).unwrap();
    assert_eq!(test.recipient_key, Some(PathBuf::from("recipient.key")));
}

#[test]
fn extract_parser_accepts_tzap_metadata_restore_options() {
    let mut request = ExtractRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["archive.tzap", "-C", "out", "--restore", "same-os", "--allow-degraded"]);

    parse_extract_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.tzap_restore_policy, zmanager_core::engine::TzapRestorePolicy::SameOs);
    assert!(request.tzap_allow_degraded);
}

#[test]
fn extract_parser_rejects_unknown_tzap_restore_policy() {
    let mut request = ExtractRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["archive.tzap", "--restore", "everything"]);

    let error = parse_extract_request(&args, &mut global, &mut request).unwrap_err();

    assert!(error.contains("content, portable, same-os, or system"));
}

#[test]
fn tzap_split_create_defaults_to_one_volume_loss_tolerance() {
    assert_eq!(tzap_default_volume_loss_tolerance(None), 0);
    assert_eq!(tzap_default_volume_loss_tolerance(Some(10 * 1024 * 1024)), 1);
}

#[test]
fn test_parser_accepts_tzap_x509_trust_options() {
    let mut request = TestRequest::default();
    let mut global = GlobalOptions::default();
    let args = strings(["signed.tzap", "--password-stdin", "--public-no-key", "--trusted-ca-cert", "root.pem", "--trusted-system-roots"]);

    parse_test_request(&args, &mut global, &mut request).unwrap();

    assert_eq!(request.trusted_ca_certs, vec![PathBuf::from("root.pem")]);
    assert!(request.trusted_system_roots);
    assert!(request.public_no_key);
}

#[test]
fn overwrite_prompt_maps_single_entry_choices() {
    assert_eq!(overwrite_decision_for("yes\n"), OverwriteDecision::Replace);
    assert_eq!(overwrite_decision_for("no\n"), OverwriteDecision::Skip);
    assert_eq!(overwrite_decision_for("rename\n"), OverwriteDecision::Rename);
    assert_eq!(overwrite_decision_for("quit\n"), OverwriteDecision::Quit);
}

#[test]
fn overwrite_prompt_all_replaces_subsequent_conflicts_without_prompting() {
    let input = Cursor::new("all\n");
    let output = Vec::new();
    let mut resolver = InteractiveOverwriteResolver::new(input, output);
    let first = overwrite_conflict("first.txt");
    let second = overwrite_conflict("second.txt");

    assert_eq!(resolver.decide(&first), OverwriteDecision::Replace);
    assert_eq!(resolver.decide(&second), OverwriteDecision::Replace);

    let output = String::from_utf8(resolver.output).unwrap();
    assert_eq!(output.matches("overwrite ").count(), 1);
}

#[test]
fn overwrite_prompt_retries_invalid_answers() {
    let input = Cursor::new("maybe\ny\n");
    let output = Vec::new();
    let mut resolver = InteractiveOverwriteResolver::new(input, output);

    assert_eq!(resolver.decide(&overwrite_conflict("file.txt")), OverwriteDecision::Replace);

    let output = String::from_utf8(resolver.output).unwrap();
    assert!(output.contains("please answer yes, no, all, rename, or quit"));
}

#[test]
fn publish_archive_refuses_existing_destination_without_force() {
    let temp = TestDir::new("publish_refuses_existing");
    let archive_temp = temp.path("archive.tmp");
    let destination = temp.path("archive.zip");
    fs::write(&archive_temp, b"new").unwrap();
    fs::write(&destination, b"old").unwrap();

    let error = publish_archive(&archive_temp, &destination, false).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&destination).unwrap(), b"old");
    assert_eq!(fs::read(&archive_temp).unwrap(), b"new");
}

#[test]
fn publish_archive_replaces_existing_file_with_force() {
    let temp = TestDir::new("publish_force_replaces");
    let archive_temp = temp.path("archive.tmp");
    let destination = temp.path("archive.zip");
    fs::write(&archive_temp, b"new").unwrap();
    fs::write(&destination, b"old").unwrap();

    publish_archive(&archive_temp, &destination, true).unwrap();

    assert_eq!(fs::read(&destination).unwrap(), b"new");
    assert!(!archive_temp.exists());
}

#[test]
fn publish_archive_force_refuses_directory_destination() {
    let temp = TestDir::new("publish_force_refuses_directory");
    let archive_temp = temp.path("archive.tmp");
    let destination = temp.path("archive.zip");
    fs::write(&archive_temp, b"new").unwrap();
    fs::create_dir(&destination).unwrap();

    let error = publish_archive(&archive_temp, &destination, true).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
    assert!(destination.is_dir());
    assert_eq!(fs::read(&archive_temp).unwrap(), b"new");
}

fn overwrite_decision_for(input: &str) -> OverwriteDecision {
    let input = Cursor::new(input.as_bytes());
    let output = Vec::new();
    let mut resolver = InteractiveOverwriteResolver::new(input, output);
    resolver.decide(&overwrite_conflict("file.txt"))
}

fn overwrite_conflict(path: &str) -> OverwriteConflict {
    OverwriteConflict { archive_path: path.to_owned(), destination_path: PathBuf::from(path) }
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.map(ToOwned::to_owned).to_vec()
}

struct TestDir {
    root: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("zmanager-cli-{name}-{}-{now}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
