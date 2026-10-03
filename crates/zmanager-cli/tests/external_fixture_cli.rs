//! Cross-check committed fixtures against the external tools that authored or
//! commonly consume them. The fixture files keep this coverage deterministic;
//! the external tools are only test oracles and are never runtime dependencies.

#![cfg(unix)]

mod common;

use common::{TestDir, assert_failure, assert_success, assert_trees_match, collect_tree_entries, find_on_path, is_apple_double, record_optional_skip, zm_path};

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone, Copy)]
enum ExternalArchiveTool {
    SevenZip,
    Unzip,
    Tar,
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn compress_program_for(archive: &Path) -> Option<&'static str> {
    let name = archive.file_name().and_then(|n| n.to_str())?;
    if name.ends_with(".lz4") {
        Some("lz4")
    } else if name.ends_with(".lz") {
        Some("lzip")
    } else if name.ends_with(".lzo") {
        Some("lzop")
    } else if name.ends_with(".zst") {
        Some("zstd")
    } else if name.ends_with(".tar.Z") || name.ends_with(".taz") {
        if find_on_path("uncompress").is_some() {
            Some("uncompress")
        } else if find_on_path("ncompress").is_some() {
            Some("ncompress")
        } else {
            Some("compress")
        }
    } else {
        None
    }
}

impl ExternalArchiveTool {
    fn binary(self) -> Option<PathBuf> {
        match self {
            Self::SevenZip => find_on_path("7zz").or_else(|| find_on_path("7z")),
            Self::Unzip => find_on_path("unzip"),
            Self::Tar => find_on_path("bsdtar").or_else(|| find_on_path("tar")),
        }
    }

    #[allow(clippy::collapsible_if)]
    fn list(self, binary: &Path, archive: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).args(["l", "-ba"]).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-Z1"]).arg(archive).output().unwrap(),
            Self::Tar => {
                let mut cmd = Command::new(binary);
                let binary_name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if binary_name == "tar" {
                    if let Some(program) = compress_program_for(archive) {
                        cmd.arg(format!("--use-compress-program={program}"));
                    }
                }
                cmd.arg("-tf").arg(archive).output().unwrap()
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    fn extract(self, binary: &Path, archive: &Path, destination: &Path) -> Output {
        match self {
            Self::SevenZip => Command::new(binary).arg("x").arg("-y").arg(format!("-o{}", destination.display())).arg(archive).output().unwrap(),
            Self::Unzip => Command::new(binary).args(["-q", "-o"]).arg(archive).arg("-d").arg(destination).output().unwrap(),
            Self::Tar => {
                let mut cmd = Command::new(binary);
                let binary_name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if binary_name == "tar" {
                    if let Some(program) = compress_program_for(archive) {
                        cmd.arg(format!("--use-compress-program={program}"));
                    }
                }
                cmd.arg("-xf").arg(archive).arg("-C").arg(destination).output().unwrap()
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureCase {
    filename: &'static str,
    tool: ExternalArchiveTool,
}

impl FixtureCase {
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn skip_reason(self, binary: &Path) -> Option<&'static str> {
        let name = binary.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "tar" {
            if self.filename.ends_with(".cpio") {
                return Some("reference tar does not support cpio");
            }
            if self.filename.ends_with(".lz") && find_on_path("lzip").is_none() {
                return Some("missing lzip filter");
            }
            if self.filename.ends_with(".lzo") && find_on_path("lzop").is_none() {
                return Some("missing lzop filter");
            }
            if (self.filename.ends_with(".tar.Z") || self.filename.ends_with(".taz"))
                && find_on_path("uncompress").is_none()
                && find_on_path("ncompress").is_none()
                && find_on_path("compress").is_none()
            {
                return Some("missing compress/uncompress filter");
            }
            if self.filename.ends_with(".lz4") && find_on_path("lz4").is_none() {
                return Some("missing lz4 filter");
            }
            if self.filename.ends_with(".zst") && find_on_path("zstd").is_none() {
                return Some("missing zstd filter");
            }
            if (self.filename.ends_with(".xz") || self.filename.ends_with(".lzma")) && find_on_path("xz").is_none() && find_on_path("lzma").is_none() {
                return Some("missing xz/lzma filter");
            }
            if (self.filename.ends_with(".bz2") || self.filename.ends_with(".tbz") || self.filename.ends_with(".tbz2")) && find_on_path("bzip2").is_none() {
                return Some("missing bzip2 filter");
            }
            if (self.filename.ends_with(".gz") || self.filename.ends_with(".tgz")) && find_on_path("gzip").is_none() {
                return Some("missing gzip filter");
            }
        }
        None
    }
}

#[test]
fn external_tools_list_and_extract_committed_fixtures() {
    let cases = [
        FixtureCase { filename: "basic.zip", tool: ExternalArchiveTool::Unzip },
        FixtureCase { filename: "basic.7z", tool: ExternalArchiveTool::SevenZip },
        FixtureCase { filename: "basic.tar", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.gz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.bz2", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.xz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lzma", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lz", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lzo", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.Z", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.lz4", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.tar.zst", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.cpio", tool: ExternalArchiveTool::Tar },
        FixtureCase { filename: "basic.cab", tool: ExternalArchiveTool::SevenZip },
        // Ubuntu 22.04 ships 7-Zip 21.07, which cannot read the RAR5 stream
        // emitted by the supported RAR creator. The native fixture test still
        // validates this archive through the bundled UnRAR backend.
        FixtureCase { filename: "basic.lha", tool: ExternalArchiveTool::SevenZip },
    ];

    let archives = repo_root().join("fixtures/archives");
    for case in cases {
        let Some(binary) = case.tool.binary() else {
            record_optional_skip(&format!("external fixture {}: required tool is not installed", case.filename));
            continue;
        };
        if let Some(reason) = case.skip_reason(&binary) {
            record_optional_skip(&format!("external fixture {}: {reason} ({})", case.filename, binary.display()));
            continue;
        }
        validate_fixture(case, &binary, &archives.join(case.filename));
    }
}

#[test]
fn reference_tzap_cross_checks_basic_and_feature_matrix() {
    let Some(tzap) = find_on_path("tzap") else {
        record_optional_skip("TZAP cross-check: reference tzap command is not installed");
        return;
    };

    // First make sure a repository-produced archive is still consumable by
    // the current reference CLI. This is the producer-to-consumer direction
    // that catches wire-format drift in the checked-in fixture.
    cross_check_tzap_archive(&tzap, &repo_root().join("fixtures/archives/basic.tzap"), &TzapAccess::default(), 1);

    let temp = TestDir::new("external-tzap-matrix");
    create_tzap_reference_payload(&temp);
    let source = temp.path("payload");

    let password_archive = temp.path("password.tzap");
    let mut password_create = Command::new(&tzap);
    password_create
        .args(["create", "--quiet", "--password-stdin", "--argon2-t-cost", "1", "--argon2-m-cost-kib", "8192", "--argon2-parallelism", "1", "--output"])
        .arg(&password_archive)
        .arg(&source);
    assert_success("tzap creates password archive", &run_with_optional_stdin(password_create, Some("reference password")));
    cross_check_tzap_archive(&tzap, &password_archive, &TzapAccess::password("reference password"), 1);
    assert_tzap_and_zm_open_rejected(&tzap, &password_archive, &TzapAccess::default(), "password is required");
    assert_tzap_and_zm_open_rejected(&tzap, &password_archive, &TzapAccess::password("wrong password"), "wrong password");

    let redundant_base = temp.path("redundant.tzap");
    let mut redundant_create = Command::new(&tzap);
    redundant_create
        .args(["create", "--quiet", "--no-encryption", "--volumes", "3", "--volume-loss-tolerance", "1", "--bit-rot-buffer-pct", "20", "--output"])
        .arg(&redundant_base)
        .arg(&source);
    assert_success("tzap creates redundant split archive", &redundant_create.output().unwrap());
    cross_check_tzap_archive(&tzap, &temp.path("redundant.vol000.tzap"), &TzapAccess::default(), 3);

    // One missing volume is an expected recovery path when the archive was
    // authored with one-volume loss tolerance. Two missing volumes must still
    // fail closed.
    let redundant_one_missing = copy_tzap_volume_set(&temp, "redundant", "redundant-one-missing", 3, &[1]);
    cross_check_tzap_archive(&tzap, &redundant_one_missing, &TzapAccess::default(), 3);
    let redundant_two_missing = copy_tzap_volume_set(&temp, "redundant", "redundant-two-missing", 3, &[1, 2]);
    assert_tzap_and_zm_open_rejected(&tzap, &redundant_two_missing, &TzapAccess::default(), "too many missing volumes");

    let zero_redundancy_base = temp.path("zero-redundancy.tzap");
    let mut zero_redundancy_create = Command::new(&tzap);
    zero_redundancy_create
        .args(["create", "--quiet", "--no-encryption", "--volumes", "2", "--volume-loss-tolerance", "0", "--bit-rot-buffer-pct", "0", "--output"])
        .arg(&zero_redundancy_base)
        .arg(&source);
    assert_success("tzap creates zero-redundancy split archive", &zero_redundancy_create.output().unwrap());
    cross_check_tzap_archive(&tzap, &temp.path("zero-redundancy.vol000.tzap"), &TzapAccess::default(), 2);
    let zero_one_missing = copy_tzap_volume_set(&temp, "zero-redundancy", "zero-one-missing", 2, &[1]);
    assert_tzap_and_zm_open_rejected(&tzap, &zero_one_missing, &TzapAccess::default(), "missing zero-redundancy volume");

    // Corrupt the critical volume-header magic. This must be rejected by both
    // readers before any metadata or payload recovery is attempted.
    let tampered_archive = temp.path("tampered.tzap");
    let mut tampered_bytes = fs::read(&password_archive).unwrap();
    tampered_bytes[0] ^= 1;
    fs::write(&tampered_archive, tampered_bytes).unwrap();
    assert_tzap_and_zm_open_rejected(&tzap, &tampered_archive, &TzapAccess::password("reference password"), "tampered header");

    let Some(openssl) = find_on_path("openssl") else {
        record_optional_skip("X.509 TZAP cross-checks: openssl command is not installed");
        return;
    };
    let (signer_certificate, signer_key) = create_self_signed_rsa_certificate(&openssl, &temp, "reference-signer");
    let signed_archive = temp.path("signed.tzap");
    let mut signed_create = Command::new(&tzap);
    signed_create
        .args(["create", "--quiet", "--no-encryption", "--signing-cert"])
        .arg(&signer_certificate)
        .args(["--signing-private-key"])
        .arg(&signer_key)
        .args(["--output"])
        .arg(&signed_archive)
        .arg(&source);
    assert_success("tzap creates X.509-signed archive", &signed_create.output().unwrap());
    let signed_access = TzapAccess { public_no_key: true, trusted_ca_cert: Some(&signer_certificate), ..TzapAccess::default() };
    cross_check_tzap_archive(&tzap, &signed_archive, &signed_access, 1);
    let untrusted_signed_access = TzapAccess { public_no_key: true, ..TzapAccess::default() };
    assert_tzap_and_zm_verification_rejected(&tzap, &signed_archive, &untrusted_signed_access, "unsigned trust configuration");

    let (recipient_certificate, recipient_key) = create_self_signed_p256_certificate(&openssl, &temp, "reference-recipient");
    let recipient_archive = temp.path("recipient.tzap");
    let mut recipient_create = Command::new(&tzap);
    recipient_create.args(["create", "--quiet", "--recipient-cert"]).arg(&recipient_certificate).args(["--output"]).arg(&recipient_archive).arg(&source);
    assert_success("tzap creates RecipientWrap archive", &recipient_create.output().unwrap());
    let recipient_access = TzapAccess { recipient_key: Some(&recipient_key), ..TzapAccess::default() };
    cross_check_tzap_archive(&tzap, &recipient_archive, &recipient_access, 1);
    assert_tzap_and_zm_open_rejected(&tzap, &recipient_archive, &TzapAccess::default(), "recipient key is required");
    let (_wrong_recipient_certificate, wrong_recipient_key) = create_self_signed_p256_certificate(&openssl, &temp, "wrong-recipient");
    let wrong_recipient_access = TzapAccess { recipient_key: Some(&wrong_recipient_key), ..TzapAccess::default() };
    assert_tzap_and_zm_open_rejected(&tzap, &recipient_archive, &wrong_recipient_access, "wrong recipient key");
}

#[derive(Default)]
struct TzapAccess<'a> {
    password: Option<&'a str>,
    recipient_key: Option<&'a Path>,
    public_no_key: bool,
    trusted_ca_cert: Option<&'a Path>,
}

impl<'a> TzapAccess<'a> {
    fn password(password: &'a str) -> Self {
        Self { password: Some(password), ..Self::default() }
    }
}

fn cross_check_tzap_archive(tzap: &Path, archive: &Path, access: &TzapAccess<'_>, expected_volume_count: u64) {
    assert!(archive.is_file(), "missing TZAP cross-check archive: {}", archive.display());

    let mut reference_list = Command::new(tzap);
    reference_list.args(["list", "--quiet"]).arg(archive);
    add_tzap_open_args(&mut reference_list, access);
    let reference_list = run_with_optional_stdin(reference_list, access.password);
    assert_success(&format!("tzap lists {}", archive.display()), &reference_list);
    let reference_names = reference_list
        .stdout
        .split(|byte| *byte == b'\n')
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<_>>();

    let mut zm_list = Command::new(zm_path());
    zm_list.args(["list"]).arg(archive).arg("--json");
    add_zm_open_args(&mut zm_list, access);
    let zm_list = run_with_optional_stdin(zm_list, access.password);
    assert_success(&format!("zm lists {}", archive.display()), &zm_list);
    let listing: Value = serde_json::from_slice(&zm_list.stdout)
        .unwrap_or_else(|error| panic!("invalid ZManager listing for {}: {error}\nstdout:\n{}", archive.display(), String::from_utf8_lossy(&zm_list.stdout)));
    let zm_names = listing["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("ZManager listing for {} has no entries array: {listing}", archive.display()))
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(zm_names, reference_names, "ZManager listing differs from tzap for {}", archive.display());

    let mut reference_verify = Command::new(tzap);
    reference_verify.args(["verify", "--json"]).arg(archive);
    add_tzap_verify_args(&mut reference_verify, access);
    let reference_verify = run_with_optional_stdin(reference_verify, access.password);
    assert_success(&format!("tzap verifies {}", archive.display()), &reference_verify);
    let verification: Value = serde_json::from_slice(&reference_verify.stdout).unwrap_or_else(|error| {
        panic!("invalid tzap verification JSON for {}: {error}\nstdout:\n{}", archive.display(), String::from_utf8_lossy(&reference_verify.stdout))
    });
    assert_eq!(verification["ok"], true, "tzap did not report a successful verification for {}", archive.display());
    assert_eq!(verification["volume_count"], expected_volume_count, "tzap reported an unexpected volume count for {}", archive.display());

    let mut zm_test = Command::new(zm_path());
    zm_test.args(["test"]).arg(archive).arg("--json");
    add_zm_test_args(&mut zm_test, access);
    let zm_test = run_with_optional_stdin(zm_test, access.password);
    assert_success(&format!("zm tests {}", archive.display()), &zm_test);

    let reference_out = TestDir::new("external-tzap-reference-extract");
    let mut reference_extract = Command::new(tzap);
    reference_extract.args(["extract", "--quiet", "--overwrite", "--directory"]).arg(reference_out.path("out")).arg(archive);
    add_tzap_open_args(&mut reference_extract, access);
    let reference_extract = run_with_optional_stdin(reference_extract, access.password);
    assert_success(&format!("tzap extracts {}", archive.display()), &reference_extract);

    let zm_out = TestDir::new("external-tzap-zm-extract");
    let mut zm_extract = Command::new(zm_path());
    zm_extract.args(["extract"]).arg(archive).arg("-C").arg(zm_out.path("out"));
    add_zm_open_args(&mut zm_extract, access);
    let zm_extract = run_with_optional_stdin(zm_extract, access.password);
    assert_success(&format!("zm extracts {}", archive.display()), &zm_extract);
    assert_trees_match(&format!("tzap and zm trees for {}", archive.display()), &reference_out.path("out"), &zm_out.path("out"));
}

fn assert_tzap_and_zm_open_rejected(tzap: &Path, archive: &Path, access: &TzapAccess<'_>, label: &str) {
    let mut reference_list = Command::new(tzap);
    reference_list.args(["list", "--quiet"]).arg(archive);
    add_tzap_open_args(&mut reference_list, access);
    let reference_list = run_with_optional_stdin(reference_list, access.password);
    assert_failure(&format!("tzap rejects {label}"), &reference_list);

    let mut zm_list = Command::new(zm_path());
    zm_list.args(["--no-password-prompt", "list"]).arg(archive).arg("--json");
    add_zm_open_args(&mut zm_list, access);
    let zm_list = run_with_optional_stdin(zm_list, access.password);
    assert_failure(&format!("zm rejects {label}"), &zm_list);

    assert_tzap_and_zm_extraction_rejected(tzap, archive, access, label);
}

fn assert_tzap_and_zm_verification_rejected(tzap: &Path, archive: &Path, access: &TzapAccess<'_>, label: &str) {
    let mut reference_verify = Command::new(tzap);
    reference_verify.args(["verify", "--json"]).arg(archive);
    add_tzap_verify_args(&mut reference_verify, access);
    let reference_verify = run_with_optional_stdin(reference_verify, access.password);
    assert_failure(&format!("tzap rejects {label}"), &reference_verify);

    let mut zm_test = Command::new(zm_path());
    zm_test.args(["--no-password-prompt", "test"]).arg(archive).arg("--json");
    add_zm_test_args(&mut zm_test, access);
    let zm_test = run_with_optional_stdin(zm_test, access.password);
    assert_failure(&format!("zm rejects {label}"), &zm_test);
}

fn assert_tzap_and_zm_extraction_rejected(tzap: &Path, archive: &Path, access: &TzapAccess<'_>, label: &str) {
    let reference_out = TestDir::new("external-tzap-reference-rejected-extract");
    let mut reference_extract = Command::new(tzap);
    reference_extract.args(["extract", "--quiet", "--overwrite", "--directory"]).arg(reference_out.path("out")).arg(archive);
    add_tzap_open_args(&mut reference_extract, access);
    let reference_extract = run_with_optional_stdin(reference_extract, access.password);
    assert_failure(&format!("tzap rejects {label} extraction"), &reference_extract);

    let zm_out = TestDir::new("external-tzap-zm-rejected-extract");
    let mut zm_extract = Command::new(zm_path());
    zm_extract.args(["--no-password-prompt", "extract"]).arg(archive).arg("-C").arg(zm_out.path("out"));
    add_zm_open_args(&mut zm_extract, access);
    let zm_extract = run_with_optional_stdin(zm_extract, access.password);
    assert_failure(&format!("zm rejects {label} extraction"), &zm_extract);
}

fn copy_tzap_volume_set(temp: &TestDir, source_stem: &str, destination_stem: &str, volume_count: usize, missing_indices: &[usize]) -> PathBuf {
    let destination = temp.path(destination_stem);
    fs::create_dir_all(&destination).unwrap();
    for index in 0..volume_count {
        if missing_indices.contains(&index) {
            continue;
        }
        let source = temp.path(format!("{source_stem}.vol{index:03}.tzap"));
        let target = destination.join(format!("{destination_stem}.vol{index:03}.tzap"));
        fs::copy(&source, &target).unwrap();
    }
    destination.join(format!("{destination_stem}.vol000.tzap"))
}

fn add_tzap_open_args(command: &mut Command, access: &TzapAccess<'_>) {
    if access.password.is_some() {
        command.arg("--password-stdin");
    }
    if let Some(recipient_key) = access.recipient_key {
        command.arg("--recipient-key").arg(recipient_key);
    }
}

fn add_tzap_verify_args(command: &mut Command, access: &TzapAccess<'_>) {
    if access.password.is_some() {
        command.arg("--password-stdin");
    }
    if let Some(recipient_key) = access.recipient_key {
        command.arg("--recipient-key").arg(recipient_key);
    }
    if access.public_no_key {
        command.arg("--public-no-key");
    }
    if let Some(certificate) = access.trusted_ca_cert {
        command.arg("--trusted-ca-cert").arg(certificate);
    }
}

fn add_zm_open_args(command: &mut Command, access: &TzapAccess<'_>) {
    if access.password.is_some() {
        command.arg("--password-stdin");
    }
    if let Some(recipient_key) = access.recipient_key {
        command.arg("--recipient-key").arg(recipient_key);
    }
}

fn add_zm_test_args(command: &mut Command, access: &TzapAccess<'_>) {
    add_zm_open_args(command, access);
    if access.public_no_key {
        command.arg("--public-no-key");
    }
    if let Some(certificate) = access.trusted_ca_cert {
        command.arg("--trusted-ca-cert").arg(certificate);
    }
}

fn run_with_optional_stdin(mut command: Command, input: Option<&str>) -> Output {
    match input {
        Some(input) => {
            command.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
            let mut child = command.spawn().unwrap();
            child.stdin.take().unwrap().write_all(format!("{input}\n").as_bytes()).unwrap();
            child.wait_with_output().unwrap()
        }
        None => command.output().unwrap(),
    }
}

fn create_tzap_reference_payload(temp: &TestDir) {
    fs::create_dir_all(temp.path("payload/nested/empty-dir")).unwrap();
    fs::create_dir_all(temp.path("payload/unicode")).unwrap();
    fs::write(temp.path("payload/README.txt"), b"reference TZAP payload\n").unwrap();
    fs::write(temp.path("payload/nested/file.txt"), b"reference nested payload\n").unwrap();
    fs::write(temp.path("payload/unicode/こんにちは.txt"), b"reference unicode payload\n").unwrap();
}

fn create_self_signed_rsa_certificate(openssl: &Path, temp: &TestDir, label: &str) -> (PathBuf, PathBuf) {
    let certificate = temp.path(format!("{label}.pem"));
    let key = temp.path(format!("{label}.key"));
    let output = Command::new(openssl)
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-keyout"])
        .arg(&key)
        .args(["-out"])
        .arg(&certificate)
        .args(["-subj", &format!("/CN=ZManager {label}"), "-addext", "keyUsage=critical,digitalSignature"])
        .output()
        .unwrap();
    assert_success("openssl creates RSA certificate", &output);
    (certificate, key)
}

fn create_self_signed_p256_certificate(openssl: &Path, temp: &TestDir, label: &str) -> (PathBuf, PathBuf) {
    let certificate = temp.path(format!("{label}.pem"));
    let key = temp.path(format!("{label}.key"));
    let keygen = Command::new(openssl).args(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out"]).arg(&key).output().unwrap();
    assert_success("openssl creates P-256 recipient key", &keygen);
    let certificate_output = Command::new(openssl)
        .args(["req", "-new", "-x509", "-key"])
        .arg(&key)
        .args(["-nodes", "-days", "365", "-out"])
        .arg(&certificate)
        .args(["-subj", &format!("/CN=ZManager {label}"), "-addext", "keyUsage=critical,keyAgreement,digitalSignature"])
        .output()
        .unwrap();
    assert_success("openssl creates P-256 recipient certificate", &certificate_output);
    (certificate, key)
}

fn validate_fixture(case: FixtureCase, binary: &Path, archive: &Path) {
    assert!(archive.is_file(), "missing committed fixture: {}", archive.display());
    assert!(fs::metadata(archive).unwrap().len() <= 64 * 1024, "external compatibility fixture grew beyond the small-fixture budget: {}", archive.display());

    let list = case.tool.list(binary, archive);
    assert_success(&format!("{} lists {}", binary.display(), case.filename), &list);

    let external = TestDir::new("external-fixture");
    let external_out = external.path("out");
    fs::create_dir_all(&external_out).unwrap();
    let extract = case.tool.extract(binary, archive, &external_out);
    assert_success(&format!("{} extracts {}", binary.display(), case.filename), &extract);
    assert!(external_out.is_dir(), "external extraction did not create {}", external_out.display());

    let external_entries = collect_tree_entries(&external_out);
    assert!(!external_entries.is_empty(), "external extraction of {} produced no entries", case.filename);
    assert_external_listing_contains_all_entries(case.tool, case.filename, &list, &external_out, &external_entries);

    let zm_list = Command::new(zm_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    assert_success(&format!("zm lists {}", case.filename), &zm_list);
    assert_zm_listing_matches_tree(case.tool, case.filename, &zm_list.stdout, &external_out, &external_entries);

    let zm = TestDir::new("external-fixture-zm");
    let zm_out = zm.path("out");
    let zm_extract = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&zm_out).output().unwrap();
    assert_success(&format!("zm extracts {}", case.filename), &zm_extract);
    assert_trees_match(&format!("external and zm trees for {}", case.filename), &external_out, &zm_out);
}

/// Decodes the `\NNN` octal escapes bsdtar writes for non-ASCII bytes in its
/// listing output.
///
/// This runs before the backslash-to-slash normalization in
/// [`assert_external_listing_contains_all_entries`], which would otherwise
/// destroy the escape markers. Decoding keeps the oracle strict for Unicode
/// names instead of skipping them: GNU tar on Linux prints the bytes
/// literally, so without this the same assertion passes on CI and fails on a
/// macOS developer machine.
fn decode_tar_octal_escapes(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let is_octal_escape = raw[index] == b'\\' && index + 3 < raw.len() && raw[index + 1..index + 4].iter().all(|byte| (b'0'..=b'7').contains(byte));
        if is_octal_escape {
            let value = raw[index + 1..index + 4].iter().fold(0u16, |accumulator, byte| accumulator * 8 + u16::from(byte - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                decoded.push(byte);
                index += 4;
                continue;
            }
        }
        decoded.push(raw[index]);
        index += 1;
    }
    decoded
}

fn assert_external_listing_contains_all_entries(tool: ExternalArchiveTool, filename: &str, output: &Output, root: &Path, entries: &[PathBuf]) {
    let raw = match tool {
        ExternalArchiveTool::Tar => decode_tar_octal_escapes(&output.stdout),
        _ => output.stdout.clone(),
    };
    let listing = String::from_utf8_lossy(&raw).replace('\\', "/");
    assert!(!listing.trim().is_empty(), "external listing for {filename} was empty");
    for entry in entries {
        // Some 7-Zip codecs (notably CAB and LHA) synthesize parent
        // directories during extraction without emitting directory records.
        if matches!(tool, ExternalArchiveTool::SevenZip) && fs::symlink_metadata(root.join(entry)).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        let normalized = entry.to_string_lossy().replace('\\', "/");
        // Info-ZIP on macOS emits non-ASCII names in the current locale even
        // when the archive carries the Unicode path extra field. Extraction
        // below still verifies the exact name and bytes; keep the listing
        // assertion strict for every name the oracle can represent as UTF-8.
        if matches!(tool, ExternalArchiveTool::Unzip) && !normalized.is_ascii() {
            continue;
        }
        assert!(listing.contains(&normalized), "external listing for {filename} missed {normalized}\nstdout:\n{listing}");
    }
}

fn assert_zm_listing_matches_tree(tool: ExternalArchiveTool, filename: &str, stdout: &[u8], root: &Path, external_entries: &[PathBuf]) {
    let listing: Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|error| panic!("invalid JSON listing for {filename}: {error}\nstdout:\n{}", String::from_utf8_lossy(stdout)));
    let actual = listing["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("JSON listing for {filename} has no entries array: {listing}"))
        .iter()
        .filter(|entry| !(matches!(tool, ExternalArchiveTool::SevenZip) && entry["kind"] == "directory"))
        .filter_map(|entry| entry["name"].as_str())
        .filter(|name| !is_apple_double(Path::new(name)))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected = external_entries
        .iter()
        .filter(|entry| !(matches!(tool, ExternalArchiveTool::SevenZip) && fs::symlink_metadata(root.join(entry)).is_ok_and(|metadata| metadata.is_dir())))
        .map(|entry| entry.to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "zm JSON listing differs from external extraction for {filename}");
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}
