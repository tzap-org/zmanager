//! Same-process loopback verification: a receiver started by this crate
//! actually accepts a push sent by this crate's own send path, over a real
//! TCP socket. This is the one thing that can be verified without a second
//! physical device or simulator — it confirms the registry wiring (runtime,
//! server lifecycle, client send) is actually connected correctly, not just
//! that each piece compiles in isolation. It does **not** substitute for
//! real interop testing against the existing mobile app, which needs a
//! real second device — see the crate's implementation plan.

use std::io::Write as _;
use std::sync::Mutex;
use std::time::Duration;

use zmanager_localsend::{CancelSendRequest, DeviceInfoDto, LocalSendBridgeError, QueuedEvent, SendFileRequest, StartReceiverRequest};

/// [`zmanager_localsend::registry`] is a single process-wide singleton (one
/// `server` slot, one `active_sends` map) — every test in this binary shares
/// it, so running them concurrently (cargo's default) would race two tests'
/// `start_receiver`/`stop_receiver` calls against each other. Serializing on
/// this lock is cheaper than teaching the registry to support multiple
/// independent instances just for tests.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn a_pushed_file_arrives_intact_on_the_receiver_this_crate_started() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = zmanager_localsend::registry();
    let receive_dir = tempfile::tempdir().expect("tempdir");
    let source_dir = tempfile::tempdir().expect("tempdir");

    let source_path = source_dir.path().join("hello.txt");
    let contents = b"loopback verification payload";
    std::fs::File::create(&source_path).expect("create source file").write_all(contents).expect("write source file");

    // Request port 0 (OS-assigned) rather than probing a free port and
    // rebinding it a moment later — the latter is a real, reproducible race
    // on some machines (confirmed directly against the vendored fork,
    // independent of this crate: a `std` probe-then-drop followed by a
    // `tokio::net::TcpListener::bind` on that exact port a moment later can
    // return `AddrInUse` even though nothing else was observably holding
    // it). Port 0 avoids the race entirely: the OS assigns an available
    // port atomically as part of the one real bind, and
    // `LocalSendRegistry::receiver_port` reads back what it picked.
    registry
        .start_receiver(StartReceiverRequest {
            alias: "loopback-receiver".to_owned(),
            port: 0,
            https: false,
            save_dir: receive_dir.path().to_path_buf(),
            auto_accept: true,
            pin: None,
        })
        .expect("receiver must start on an OS-assigned port");
    let port = registry.receiver_port().expect("receiver_port must report the just-bound port");

    let target = DeviceInfoDto {
        alias: "loopback-receiver".to_owned(),
        fingerprint: String::new(),
        port,
        protocol: "http".to_owned(),
        ip: Some("127.0.0.1".to_owned()),
        device_model: None,
        last_seen_unix_seconds: None,
    };

    let result = registry.send_file(SendFileRequest {
        send_id: "loopback-send".to_owned(),
        alias: "loopback-sender".to_owned(),
        // The client never binds `self_port` — it's only a label carried in
        // outbound requests (see `LocalSendClient::new`) — so 0 is fine here.
        self_port: 0,
        https: false,
        target,
        file_path: source_path.clone(),
        pin: None,
    });

    // Give the receiver's async write-and-publish a moment to land before
    // asserting on disk state; poll rather than sleep-and-hope.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let received_path = receive_dir.path().join("hello.txt");
    while std::time::Instant::now() < deadline && !received_path.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }

    registry.stop_receiver().expect("receiver was running and must stop cleanly");

    let send_result = result.expect("send_file must succeed against a receiver that just auto-accepted");
    assert!(!send_result.session_id.is_empty());

    let received = std::fs::read(&received_path).expect("receiver must have written the file to its save_dir");
    assert_eq!(received, contents, "received bytes must match exactly what was sent");

    let events = registry.poll_events().events;
    assert!(
        events.iter().any(|event| matches!(event, QueuedEvent::FileSendProgress { send_id, .. } if send_id == "loopback-send")),
        "a successful send_file must have queued at least one FileSendProgress event tagged with its send_id, got: {events:?}"
    );
}

#[test]
fn cancel_send_aborts_an_in_flight_upload_before_it_reaches_the_receiver() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = zmanager_localsend::registry();
    let receive_dir = tempfile::tempdir().expect("tempdir");
    let source_dir = tempfile::tempdir().expect("tempdir");

    // Large enough that, even when the other loopback tests have warmed the
    // shared runtime, the retry loop below reliably lands its cancel before
    // the transfer finishes — a sparse file keeps setup itself fast.
    let source_path = source_dir.path().join("large.bin");
    let file = std::fs::File::create(&source_path).expect("create source file");
    file.set_len(1024 * 1024 * 1024).expect("grow source file to 1GiB (sparse)");
    drop(file);

    registry
        .start_receiver(StartReceiverRequest {
            alias: "loopback-receiver".to_owned(),
            port: 0,
            https: false,
            save_dir: receive_dir.path().to_path_buf(),
            auto_accept: true,
            pin: None,
        })
        .expect("receiver must start on an OS-assigned port");
    let port = registry.receiver_port().expect("receiver_port must report the just-bound port");

    let target = DeviceInfoDto {
        alias: "loopback-receiver".to_owned(),
        fingerprint: String::new(),
        port,
        protocol: "http".to_owned(),
        ip: Some("127.0.0.1".to_owned()),
        device_model: None,
        last_seen_unix_seconds: None,
    };

    let send_id = "loopback-cancel-me".to_owned();
    let send_thread = std::thread::spawn({
        let registry = registry.clone();
        let send_id = send_id.clone();
        move || {
            registry.send_file(SendFileRequest {
                send_id,
                alias: "loopback-sender".to_owned(),
                self_port: 0,
                https: false,
                target,
                file_path: source_path,
                pin: None,
            })
        }
    });

    // `send_file` registers its abort handle before it starts streaming, but
    // the exact moment that registration becomes visible to this thread is
    // not observable directly — so retry `cancel_send` until it stops
    // reporting `UnknownSendId`, rather than guessing a sleep duration. This
    // converges as soon as the handle exists, well before a 256MiB transfer
    // could complete even over loopback.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match registry.cancel_send(&CancelSendRequest { send_id: send_id.clone() }) {
            Ok(()) => break,
            Err(LocalSendBridgeError::UnknownSendId(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("cancel_send failed before the send could be observed as active: {error}"),
        }
    }

    let send_result = send_thread.join().expect("send_file thread must not panic");

    registry.stop_receiver().expect("receiver was running and must stop cleanly");

    assert!(
        matches!(send_result, Err(LocalSendBridgeError::SendCancelled)),
        "a send aborted immediately after registration must fail as SendCancelled, got: {send_result:?}"
    );
    // The receiver reserves the final name before streaming into its
    // temporary file. The sender's abort can therefore return before the
    // receiver has finished asynchronously removing that reservation; wait
    // for the receiver-side cleanup before checking the visible path.
    let received_path = receive_dir.path().join("large.bin");
    let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while received_path.exists() && std::time::Instant::now() < cleanup_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!receive_dir.path().join("large.bin").exists(), "the receiver must not end up with a fully-written file from a cancelled send");
    assert!(
        matches!(registry.cancel_send(&CancelSendRequest { send_id }), Err(LocalSendBridgeError::UnknownSendId(_))),
        "cancelling the same send_id again after it's done must report UnknownSendId, not silently succeed"
    );
}

/// `https: true` is untested elsewhere: the two tests above only exercise
/// plain HTTP. Mobile's receiver now starts with `https: true` (decision 3
/// of the migration plan), which takes a different path inside
/// `start_receiver` — real TLS cert generation (`generate_tls_certificate`)
/// and an actual TLS accept/handshake on every connection, not just a raw
/// TCP one. `LocalSendClient`'s transport accepts any cert
/// (`danger_accept_invalid_certs(true)` in the vendored fork — fingerprint
/// pinning is an opt-in check callers do at discovery time, not something
/// the transport enforces), so this can push over HTTPS without needing to
/// learn the receiver's real cert fingerprint first.
#[test]
fn an_https_receiver_starts_and_accepts_a_pushed_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = zmanager_localsend::registry();
    let receive_dir = tempfile::tempdir().expect("tempdir");
    let source_dir = tempfile::tempdir().expect("tempdir");

    let source_path = source_dir.path().join("secure.txt");
    let contents = b"https loopback verification payload";
    std::fs::File::create(&source_path).expect("create source file").write_all(contents).expect("write source file");

    registry
        .start_receiver(StartReceiverRequest {
            alias: "loopback-https-receiver".to_owned(),
            port: 0,
            https: true,
            save_dir: receive_dir.path().to_path_buf(),
            auto_accept: true,
            pin: None,
        })
        .expect("an HTTPS receiver must start cleanly (TLS cert generation + bind must not fail)");
    let port = registry.receiver_port().expect("receiver_port must report the just-bound port");
    let fingerprint = registry.receiver_fingerprint().expect("receiver_fingerprint must report the cert's fingerprint");
    assert!(!fingerprint.is_empty(), "an HTTPS receiver's fingerprint must be the real cert fingerprint, never blank");

    let target = DeviceInfoDto {
        alias: "loopback-https-receiver".to_owned(),
        fingerprint,
        port,
        protocol: "https".to_owned(),
        ip: Some("127.0.0.1".to_owned()),
        device_model: None,
        last_seen_unix_seconds: None,
    };

    let result = registry.send_file(SendFileRequest {
        send_id: "loopback-https-send".to_owned(),
        alias: "loopback-https-sender".to_owned(),
        self_port: 0,
        https: true,
        target,
        file_path: source_path,
        pin: None,
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let received_path = receive_dir.path().join("secure.txt");
    while std::time::Instant::now() < deadline && !received_path.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }

    registry.stop_receiver().expect("receiver was running and must stop cleanly");

    result.expect("send_file over HTTPS must succeed against a receiver that just auto-accepted");
    let received = std::fs::read(&received_path).expect("receiver must have written the file to its save_dir");
    assert_eq!(received, contents, "received bytes must match exactly what was sent over HTTPS");
}
