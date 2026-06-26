use std::env;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn auth_login_callback_status_and_forget_keep_session_secret_out_of_output() {
    let temp = TestDir::new("zm_tzap_auth");
    let state_dir = temp.path("state");

    let login = zm()
        .args([
            "auth",
            "login",
            "--environment",
            "local",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth login", &login);
    let login_stdout = String::from_utf8_lossy(&login.stdout);
    assert!(login_stdout.contains("\"status\":\"pending\""));
    assert!(login_stdout.contains("http://localhost:8787/auth/launch"));

    let pending: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("auth-pending.json")).unwrap()).unwrap();
    assert_owner_only_file(state_dir.join("auth-pending.json"));
    let state = pending["state"].as_str().unwrap();
    let relay = temp.path("relay.json");
    fs::write(
        &relay,
        br#"{"status":"ok","session":{"audience":"sign.tzap.org","access_token":"secret-token","expires_at_unix_seconds":9999999999,"identity_assurance":"oauth_verified_email","selected_org_id":null,"login_session_id":"login-session-1"}}"#,
    )
    .unwrap();

    let callback = zm()
        .args([
            "auth",
            "callback",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--state",
            state,
            "--relay-body",
            relay.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth callback", &callback);
    let callback_stdout = String::from_utf8_lossy(&callback.stdout);
    assert!(callback_stdout.contains("\"authenticated\":true"));
    assert!(!callback_stdout.contains("secret-token"));
    assert_owner_only_file(state_dir.join("auth-session.json"));

    let status = zm()
        .args([
            "auth",
            "status",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth status", &status);
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status_stdout.contains("\"authenticated\":true"));
    assert!(!status_stdout.contains("secret-token"));

    let forget = zm()
        .args([
            "auth",
            "forget",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth forget", &forget);
    assert!(String::from_utf8_lossy(&forget.stdout).contains("\"forgotten\":true"));
}

#[test]
fn cert_enroll_uses_local_fake_service_and_updates_inventory() {
    let temp = TestDir::new("zm_tzap_cert");
    let state_dir = temp.path("state");
    sign_in_with_fake_relay(&temp, &state_dir);

    let list = zm()
        .args([
            "cert",
            "list",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("cert list", &list);
    assert_eq!(
        String::from_utf8_lossy(&list.stdout).trim(),
        "{\"certificates\":[]}"
    );

    let enroll = zm()
        .args([
            "cert",
            "enroll",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("cert enroll", &enroll);
    let stdout = String::from_utf8_lossy(&enroll.stdout);
    assert!(stdout.contains("\"operation\":\"cert_enroll\""));
    assert!(stdout.contains("\"certificate_id\""));

    let list = zm()
        .args([
            "cert",
            "list",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("cert list after enroll", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("\"certificates\":[{"));
    assert!(stdout.contains("\"state\":\"active\""));
}

#[test]
fn auth_callback_exchanges_handoff_code_without_printing_session_secret() {
    let temp = TestDir::new("zm_tzap_auth_exchange");
    let state_dir = temp.path("state");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0, "client closed before sending a complete request");
            request.extend_from_slice(&buffer[..count]);
            if request_is_complete(&request) {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("POST /auth/session/exchange HTTP/1.1"));
        assert!(request.contains("\"handoff_code\":\"handoff-123\""));
        assert!(request.contains("\"client_id\":\"test-client\""));
        let body = br#"{"user_id":"user-1","session_id":"login-session-2","session_token":"exchanged-secret-token","audience":"sign.tzap.org","expires_at":"2099-01-01T00:00:00Z","identity_assurance_level":"oauth_verified_email"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });

    let login = zm()
        .args([
            "auth",
            "login",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--auth-base-url",
            &format!("http://127.0.0.1:{port}"),
            "--client-id",
            "test-client",
            "--redirect-uri",
            "tzap://auth/email/callback",
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth login", &login);
    let pending: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("auth-pending.json")).unwrap()).unwrap();
    let state = pending["state"].as_str().unwrap();
    let callback_url = format!("tzap://auth/email/callback?state={state}&handoff_code=handoff-123");

    let callback = zm()
        .args([
            "auth",
            "callback",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--callback-url",
            &callback_url,
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth callback exchange", &callback);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&callback.stdout);
    assert!(stdout.contains("\"authenticated\":true"));
    assert!(!stdout.contains("exchanged-secret-token"));
}

#[test]
fn verify_accepts_custom_trust_root_certificate_file() {
    let temp = TestDir::new("zm_tzap_verify_root_cert");
    let state_dir = temp.path("state");
    sign_in_with_fake_relay(&temp, &state_dir);

    let enroll = zm()
        .args([
            "cert",
            "enroll",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("cert enroll", &enroll);
    let enroll_json: serde_json::Value = serde_json::from_slice(&enroll.stdout).unwrap();
    let certificate_id = enroll_json["certificate"]["certificate_id"]
        .as_str()
        .unwrap();
    let payload = temp.path("payload.json");
    let envelope = temp.path("envelope.json");
    fs::write(
        &payload,
        br#"{"tzap_payload_version":1,"title":"Root cert verification"}"#,
    )
    .unwrap();
    let sign = zm()
        .args([
            "sign",
            payload.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--certificate-id",
            certificate_id,
            "--output",
            envelope.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("sign", &sign);

    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("default.identity.json")).unwrap())
            .unwrap();
    let root_der = base64url_decode(
        inventory["enrolled_certificates"][0]["intermediate_chain_der"][1]
            .as_str()
            .unwrap(),
    );
    let root_path = temp.path("root.der");
    fs::write(&root_path, root_der).unwrap();

    let verify = zm()
        .args([
            "verify",
            envelope.to_str().unwrap(),
            "--custom-trust-root-cert",
            root_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("verify with root cert", &verify);
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("\"state\":\"cryptographically_intact_offline\""));
    assert!(stdout.contains("\"trust_anchor_type\":\"custom\""));
}

#[test]
fn verify_json_reports_invalid_without_claiming_official_validity() {
    let temp = TestDir::new("zm_tzap_verify");
    let envelope = temp.path("bad-envelope.json");
    fs::write(&envelope, br#"{"not":"a tzap envelope"}"#).unwrap();

    let output = zm()
        .args(["verify", envelope.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_failure("verify", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"state\":\"invalid\""));
    assert!(stdout.contains("\"trust_anchor_type\":\"untrusted\""));
    assert!(!stdout.contains("official_tzap"));
}

fn base64url_decode(value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => continue,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    output
}

fn request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
    else {
        return false;
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    content_length.is_none_or(|length| request.len() >= header_end + length)
}

fn zm() -> Command {
    Command::new(zm_path())
}

fn zm_path() -> PathBuf {
    if let Ok(path) = env::var("CARGO_BIN_EXE_zm") {
        return PathBuf::from(path);
    }
    let mut path = env::current_exe().unwrap();
    while path.file_name().is_some_and(|name| name != "target") {
        path.pop();
    }
    path.push("debug");
    path.push(if cfg!(windows) { "zm.exe" } else { "zm" });
    path
}

fn sign_in_with_fake_relay(temp: &TestDir, state_dir: &std::path::Path) {
    let login = zm()
        .args([
            "auth",
            "login",
            "--environment",
            "local",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth login", &login);
    let pending: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("auth-pending.json")).unwrap()).unwrap();
    let state = pending["state"].as_str().unwrap();
    let relay = temp.path("relay.json");
    fs::write(
        &relay,
        br#"{"status":"ok","session":{"audience":"sign.tzap.org","access_token":"secret-token","expires_at_unix_seconds":9999999999,"identity_assurance":"oauth_verified_email","selected_org_id":null,"login_session_id":"login-session-1"}}"#,
    )
    .unwrap();
    let callback = zm()
        .args([
            "auth",
            "callback",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--state",
            state,
            "--relay-body",
            relay.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_success("auth callback", &callback);
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(label: &str, output: &Output) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn assert_owner_only_file(path: PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(not(unix))]
fn assert_owner_only_file(_path: PathBuf) {}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self, child: &str) -> PathBuf {
        self.path.join(child)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.path.starts_with(env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
