//! Ephemeral loopback receiver for the hosted CLI's browser handoff.
//!
//! The listener binds one literal loopback address, keeps that socket open for
//! the whole login, and accepts only a bounded GET to its exact callback path.
//! It never logs the request target or returns untrusted request data in HTML.

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 48;
const MAX_CONNECTIONS: usize = 128;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(60);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(40);

pub(super) struct LoopbackCallbackListener {
    listener: TcpListener,
    redirect_uri: String,
    authority: String,
}

pub(super) struct PendingLoopbackCallback {
    stream: TcpStream,
    callback_url: String,
}

impl LoopbackCallbackListener {
    pub(super) fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).or_else(|_| TcpListener::bind(("::1", 0)))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let authority = authority(address);
        let redirect_uri = format!("http://{authority}/auth/callback");
        Ok(Self { listener, redirect_uri, authority })
    }

    pub(super) fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub(super) fn wait_for_callback(&self, expected_state: &str, timeout: Duration) -> Result<PendingLoopbackCallback, LoopbackError> {
        let deadline = Instant::now() + timeout;
        let mut accepted = 0usize;
        loop {
            if Instant::now() >= deadline {
                return Err(LoopbackError::Timeout);
            }
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    accepted += 1;
                    if accepted > MAX_CONNECTIONS {
                        return Err(LoopbackError::TooManyConnections);
                    }
                    let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));
                    if !peer.ip().is_loopback() {
                        write_error_response(&mut stream, 403);
                        continue;
                    }
                    let request_deadline = (Instant::now() + CONNECTION_IO_TIMEOUT).min(deadline);
                    let Ok(raw) = read_bounded_request(&mut stream, request_deadline) else {
                        write_error_response(&mut stream, 400);
                        continue;
                    };
                    let callback_url = match parse_callback_request(&raw, &self.authority, &self.redirect_uri, expected_state) {
                        Ok(callback_url) => callback_url,
                        Err(RequestRejection::NotCallback) => {
                            write_error_response(&mut stream, 404);
                            continue;
                        }
                        Err(RequestRejection::Invalid) => {
                            write_error_response(&mut stream, 400);
                            continue;
                        }
                    };
                    return Ok(PendingLoopbackCallback { stream, callback_url });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
                }
                Err(error) => return Err(LoopbackError::Io(error)),
            }
        }
    }
}

impl PendingLoopbackCallback {
    pub(super) fn callback_url(&self) -> &str {
        &self.callback_url
    }

    /// Acknowledge only after the auth service has committed the session.
    pub(super) fn acknowledge(mut self) -> io::Result<()> {
        const BODY: &str = "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><title>Return to ZManager</title><p>Sign-in reached ZManager. Continue setup in the terminal.</p>";
        write!(
            self.stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{}",
            BODY.len(),
            BODY
        )?;
        self.stream.flush()
    }
}

#[derive(Debug)]
pub(super) enum LoopbackError {
    Timeout,
    TooManyConnections,
    Io(io::Error),
}

impl std::fmt::Display for LoopbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("browser sign-in timed out"),
            Self::TooManyConnections => f.write_str("too many local callback requests"),
            Self::Io(error) => write!(f, "loopback callback listener failed: {error}"),
        }
    }
}

fn authority(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => format!("{}:{}", address.ip(), address.port()),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

fn read_bounded_request(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = header_end(&bytes) {
            if end != bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "request body is not accepted"));
            }
            return Ok(bytes);
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request headers exceed limit"));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request read deadline elapsed"));
        }
        stream.set_read_timeout(Some(remaining))?;
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete request"));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RequestRejection {
    NotCallback,
    Invalid,
}

fn parse_callback_request(raw: &[u8], authority: &str, redirect_uri: &str, expected_state: &str) -> Result<String, RequestRejection> {
    if raw.len() > MAX_HEADER_BYTES {
        return Err(RequestRejection::Invalid);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request.parse(raw).map_err(|_| RequestRejection::Invalid)?;
    let httparse::Status::Complete(consumed) = parsed else { return Err(RequestRejection::Invalid) };
    if consumed != raw.len() {
        return Err(RequestRejection::Invalid);
    }
    let path = request.path.ok_or(RequestRejection::Invalid)?;
    if path == "/favicon.ico" || path == "/" {
        return Err(RequestRejection::NotCallback);
    }
    if request.method != Some("GET") || !path.starts_with("/auth/callback?") || path.contains('#') || path.len() > 8192 {
        return Err(RequestRejection::Invalid);
    }
    let mut host = None;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") && host.replace(header.value).is_some() {
            return Err(RequestRejection::Invalid);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("content-length")
            || header.name.eq_ignore_ascii_case("upgrade")
        {
            return Err(RequestRejection::Invalid);
        }
    }
    if host != Some(authority.as_bytes()) {
        return Err(RequestRejection::Invalid);
    }
    let callback_suffix = path.strip_prefix("/auth/callback").ok_or(RequestRejection::Invalid)?;
    let callback_url = format!("{redirect_uri}{callback_suffix}");
    let parsed = zmanager_tzap_hosted::browser_callback::parse_browser_callback(&callback_url, redirect_uri).map_err(|_| RequestRejection::Invalid)?;
    if parsed.state != expected_state {
        return Err(RequestRejection::Invalid);
    }
    Ok(callback_url)
}

fn write_error_response(stream: &mut TcpStream, status: u16) {
    let (label, body) = match status {
        403 => ("Forbidden", "This local callback is unavailable."),
        404 => ("Not Found", "This local callback is unavailable."),
        _ => ("Bad Request", "This callback request is invalid."),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {label}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    const CODE: &str = "tzap_handoff_fixture_only";

    fn request(path: &str, host: &str, extra_headers: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n").into_bytes()
    }

    #[test]
    fn binds_only_literal_loopback_and_builds_exact_redirect() {
        let listener = LoopbackCallbackListener::bind().unwrap();
        assert!(listener.redirect_uri().starts_with("http://127.0.0.1:") || listener.redirect_uri().starts_with("http://[::1]:"));
        assert!(listener.redirect_uri().ends_with("/auth/callback"));
    }

    #[test]
    fn connection_io_timeout_is_at_least_one_minute() {
        assert!(CONNECTION_IO_TIMEOUT >= Duration::from_secs(60));
    }

    #[test]
    fn accepts_exact_host_get_and_one_valid_callback() {
        let listener = LoopbackCallbackListener::bind().unwrap();
        let path = format!("/auth/callback?state={STATE}&handoff_code={CODE}");
        let raw = request(&path, &listener.authority, "Connection: close\r\n");
        let assembled = format!("{}{}", listener.redirect_uri(), path.strip_prefix("/auth/callback").unwrap());
        assert!(zmanager_tzap_hosted::browser_callback::parse_browser_callback(&assembled, listener.redirect_uri()).is_ok());
        let callback =
            parse_callback_request(&raw, &listener.authority, listener.redirect_uri(), STATE).unwrap_or_else(|error| panic!("request rejected: {error:?}"));
        assert_eq!(callback, format!("{}?state={STATE}&handoff_code={CODE}", listener.redirect_uri()));
    }

    #[test]
    fn rejects_wrong_host_method_path_state_duplicates_and_body_headers() {
        let listener = LoopbackCallbackListener::bind().unwrap();
        let valid_path = format!("/auth/callback?state={STATE}&handoff_code={CODE}");
        for raw in [
            request(&valid_path, "localhost", ""),
            request(&valid_path, &listener.authority, "Content-Length: 0\r\n"),
            request(&valid_path, &listener.authority, "Transfer-Encoding: chunked\r\n"),
            request("/auth/callback", &listener.authority, ""),
            request("/favicon.ico", &listener.authority, ""),
            request(&format!("/auth/callback?state={STATE}&handoff_code={CODE}&state={STATE}"), &listener.authority, ""),
            request(&format!("/auth/callback?state=wrong&handoff_code={CODE}"), &listener.authority, ""),
            format!("POST {valid_path} HTTP/1.1\r\nHost: {}\r\n\r\n", listener.authority).into_bytes(),
            request(&valid_path, &listener.authority, &format!("Host: {}\r\n", listener.authority)),
        ] {
            assert!(parse_callback_request(&raw, &listener.authority, listener.redirect_uri(), STATE).is_err());
        }
    }

    #[test]
    fn rejects_oversized_or_incomplete_http_requests() {
        assert!(parse_callback_request(&vec![b'x'; MAX_HEADER_BYTES + 1], "127.0.0.1:1", "http://127.0.0.1:1/auth/callback", STATE).is_err());
        assert!(parse_callback_request(b"GET /auth/callback?", "127.0.0.1:1", "http://127.0.0.1:1/auth/callback", STATE).is_err());
    }

    #[test]
    fn slow_drip_request_cannot_reset_the_connection_read_deadline() {
        use std::net::TcpStream;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut client = TcpStream::connect(address).unwrap();
            client.write_all(b"G").unwrap();
            thread::sleep(Duration::from_millis(150));
            let _ = client.write_all(b"E");
        });
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let started = Instant::now();
        let result = read_bounded_request(&mut stream, deadline);
        assert!(matches!(result, Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)));
        assert!(started.elapsed() < Duration::from_millis(400));
        writer.join().unwrap();
    }

    #[test]
    fn overall_login_deadline_caps_a_slow_connection() {
        let callback_listener = LoopbackCallbackListener::bind().unwrap();
        let address = callback_listener.listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut client = TcpStream::connect(address).unwrap();
            client.write_all(b"G").unwrap();
            thread::sleep(Duration::from_millis(300));
            let _ = client.write_all(b"ET /auth/callback HTTP/1.1\r\nHost: invalid\r\n\r\n");
        });
        let started = Instant::now();
        let result = callback_listener.wait_for_callback(STATE, Duration::from_millis(100));
        assert!(matches!(result, Err(LoopbackError::Timeout)));
        assert!(started.elapsed() < Duration::from_millis(400));
        writer.join().unwrap();
    }
}
