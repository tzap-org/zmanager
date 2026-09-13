//! Persistent `LocalSend` receiver + one-shot discovery/send, bridged to a
//! synchronous, JSON-shaped surface for FFI callers (`zmanager-ffi`) and for
//! `zmanager-desktop`'s direct-Rust callers alike.
//!
//! `localsend-rs` is async-native (tokio, axum) throughout, unlike the rest
//! of this workspace's HTTP-backed logic (`zmanager-tzap-hosted` stays
//! synchronous behind an injected transport trait). This crate owns the one
//! tokio runtime that bridges the two worlds; nothing above this module
//! needs to know `LocalSend` is async at all.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use localsend_rs::client::client::ProgressCallback;
use localsend_rs::protocol::{DeviceInfo, FileId, Protocol};
use localsend_rs::server::{LocalSendServer, PendingRequest, ServerEvent};
use localsend_rs::{DeviceInfoBuilder, Discovery};
use serde::{Deserialize, Serialize};
use tokio::task::AbortHandle;

const MAX_QUEUED_EVENTS: usize = 512;

static REGISTRY: OnceLock<Arc<LocalSendRegistry>> = OnceLock::new();

/// The process-wide registry. Callers should go through [`registry`] rather
/// than constructing this directly.
pub struct LocalSendRegistry {
    runtime: tokio::runtime::Runtime,
    state: Mutex<RegistryState>,
    /// The process-wide `LocalSend` TLS identity. It must be shared by the
    /// receiver, discovery clients, and send clients so peers see one stable
    /// certificate instead of a new client identity per operation.
    tls_certificate: Mutex<Option<localsend_rs::TlsCertificate>>,
    /// Where that identity is persisted, once a shell has told us where its
    /// application data lives. Set it with
    /// [`LocalSendRegistry::set_identity_dir`]; until then the identity lives
    /// only as long as this process.
    identity_dir: Mutex<Option<PathBuf>>,
}

#[derive(Default)]
struct RegistryState {
    server: Option<LocalSendServer>,
    /// The official `LocalSend` app keeps discovery alive alongside its HTTP
    /// server so a receiver can answer announcements and register back with
    /// the announcing peer. Keep that lifecycle in the shared Rust registry,
    /// not in the Android/iOS shells.
    discovery: Option<localsend_rs::MulticastDiscovery>,
    /// The discovery currently collecting results, while a sweep runs.
    ///
    /// A peer answers an announcement by `POST`ing `/register` to our HTTP
    /// server, so that reply surfaces as [`ServerEvent::PeerRegistered`] and
    /// never reaches the multicast listener. Official `LocalSend` feeds such
    /// confirmations into the same store its listener writes to; this slot is
    /// how that happens here, so an in-flight sweep sees the replies its own
    /// announcement provoked instead of waiting out its timeout.
    active_discovery: Option<localsend_rs::MulticastDiscovery>,
    /// Confirmed peers keyed by `LocalSend` fingerprint. The official client
    /// keeps this store alive across discovery sweeps and merges confirmations
    /// from both directions (our probes and incoming `/register` events).
    confirmed_devices: HashMap<String, ConfirmedDevice>,
    pending_requests: HashMap<String, PendingRequest>,
    next_request_id: u64,
    events: VecDeque<QueuedEvent>,
    /// Abort handles for in-flight `send_file` tasks, keyed by the
    /// caller-supplied `SendFileRequest::send_id`. `send_file` blocks the
    /// calling thread on the spawned task's `JoinHandle`, so aborting via
    /// this handle from a *different* thread (e.g. a "Cancel" button) is the
    /// only way to unblock it early — cooperative checks inside the upload
    /// loop aren't reachable from here the way they were in the native
    /// per-platform implementations this crate replaces.
    active_sends: HashMap<String, AbortHandle>,
}

/// Returns the shared registry, creating it (and its runtime) on first use.
///
/// # Panics
///
/// Panics if the Tokio runtime cannot be created.
pub fn registry() -> Arc<LocalSendRegistry> {
    REGISTRY
        .get_or_init(|| {
            Arc::new(LocalSendRegistry {
                runtime: tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("zmanager-localsend runtime failed to start"),
                state: Mutex::new(RegistryState::default()),
                tls_certificate: Mutex::new(None),
                identity_dir: Mutex::new(None),
            })
        })
        .clone()
}

#[derive(Debug, thiserror::Error)]
pub enum LocalSendBridgeError {
    #[error("localsend error: {0}")]
    LocalSend(#[from] localsend_rs::error::LocalSendError),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("no receiver is running")]
    NoReceiverRunning,
    #[error("receiver is already running")]
    ReceiverAlreadyRunning,
    #[error("unknown transfer request id: {0}")]
    UnknownRequestId(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("send was cancelled")]
    SendCancelled,
    #[error("unknown send id: {0}")]
    UnknownSendId(String),
}

pub type BridgeResult<T> = Result<T, LocalSendBridgeError>;

// ---------------------------------------------------------------------
// Receiver lifecycle
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartReceiverRequest {
    pub alias: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub save_dir: PathBuf,
    #[serde(default)]
    pub auto_accept: bool,
    #[serde(default)]
    pub pin: Option<String>,
}

fn default_port() -> u16 {
    localsend_rs::protocol::DEFAULT_HTTP_PORT
}

impl LocalSendRegistry {
    /// Tells the registry where to persist this device's `LocalSend` identity.
    ///
    /// In `LocalSend` a device *is* its certificate fingerprint: peers store it,
    /// de-duplicate their device lists on it, and pin it for later
    /// connections. An identity that is regenerated per launch therefore makes
    /// `ZManager` a brand-new device on every start — a fresh row in every
    /// peer's list, and a pin that can never match — so the shells hand us a
    /// directory that outlives the process. `directory` is created if needed;
    /// the private key inside it is written owner-only.
    ///
    /// Call this once during startup, before any discover/receive/send. The
    /// certificate is materialised here so a bad path fails at configuration
    /// time rather than midway through a transfer.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity cannot be read or written, or if an
    /// identity has already been materialised for this process — one process
    /// announcing two fingerprints is exactly the split this method exists to
    /// prevent.
    ///
    /// # Panics
    ///
    /// Panics if the TLS certificate mutex is poisoned.
    pub fn set_identity_dir(&self, directory: impl Into<PathBuf>) -> BridgeResult<()> {
        let directory = directory.into();
        let mut certificate = self.tls_certificate.lock().expect("TLS certificate lock poisoned");
        if certificate.is_some() {
            return Err(LocalSendBridgeError::InvalidRequest(
                "the LocalSend identity is already in use; set the identity directory before discovering, receiving or sending".to_owned(),
            ));
        }

        let loaded = localsend_rs::load_or_generate_tls_certificate(directory.join("certificate.pem"), directory.join("private-key.pem"))?;
        *self.identity_dir.lock().expect("identity directory lock poisoned") = Some(directory);
        *certificate = Some(loaded);
        Ok(())
    }

    /// This process's `LocalSend` identity, loaded from the configured directory
    /// on first use.
    ///
    /// Without [`Self::set_identity_dir`] the identity is generated in memory
    /// and lasts only for this process. That still works, but every restart
    /// looks like a new device to peers, so shells are expected to configure a
    /// directory at startup.
    fn client_certificate(&self) -> BridgeResult<localsend_rs::TlsCertificate> {
        let mut certificate = self.tls_certificate.lock().expect("TLS certificate lock poisoned");
        if let Some(certificate) = certificate.as_ref() {
            return Ok(certificate.clone());
        }

        let directory = self.identity_dir.lock().expect("identity directory lock poisoned").clone();
        let loaded = match directory {
            Some(directory) => localsend_rs::load_or_generate_tls_certificate(directory.join("certificate.pem"), directory.join("private-key.pem"))?,
            None => localsend_rs::generate_tls_certificate()?,
        };
        *certificate = Some(loaded.clone());
        Ok(loaded)
    }

    /// Starts a `LocalSend` receiver with the requested configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if a receiver is already running, TLS setup fails, or
    /// the underlying `LocalSend` server cannot start.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn start_receiver(&self, request: StartReceiverRequest) -> BridgeResult<()> {
        {
            let state = self.state.lock().expect("registry lock poisoned");
            if state.server.is_some() {
                return Err(LocalSendBridgeError::ReceiverAlreadyRunning);
            }
        }

        let protocol = if request.https { Protocol::Https } else { Protocol::Http };
        let mut builder =
            LocalSendServer::builder().alias(request.alias).port(request.port).save_dir(&request.save_dir).protocol(protocol).auto_accept(request.auto_accept);
        if let Some(pin) = request.pin.as_ref() {
            builder = builder.pin(pin.clone());
        }
        if request.https {
            let cert = self.client_certificate()?;
            builder = builder.tls_certificate(cert);
        }

        // `LocalSendServerBuilder::build()` already starts the server
        // internally (binds the real socket and spawns the serve task,
        // `localsend-rs/src/server/server.rs:587`) before handing back the
        // events receiver via `take_events()` — it is not a "configure only"
        // step the way the name suggests. Calling `.start()` again here
        // would try to rebind the port it just bound.
        let (server, mut events_rx) = self.runtime.block_on(builder.build())?;

        let mut discovery = localsend_rs::MulticastDiscovery::new_with_device(server.device().clone());
        if request.https {
            discovery.set_client_certificate(self.client_certificate()?);
        }
        let discovery_started = if let Err(error) = self.runtime.block_on(discovery.start()) {
            // Official LocalSend continues with HTTP discovery when multicast
            // cannot be bound, e.g. after an OS network-socket reclaim.
            discovery = localsend_rs::MulticastDiscovery::new_with_device(server.device().clone());
            let _ = error;
            false
        } else {
            true
        };

        if discovery_started {
            let discovery_for_announce = discovery.clone();
            self.runtime.spawn(async move {
                let _ = discovery_for_announce.announce_presence().await;
            });
        }

        let registry_for_pump = registry();
        self.runtime.spawn(async move {
            while let Some(event) = events_rx.recv().await {
                registry_for_pump.absorb_event(event);
            }
        });

        let mut state = self.state.lock().expect("registry lock poisoned");
        state.server = Some(server);
        state.discovery = Some(discovery);
        Ok(())
    }

    /// Stops the running `LocalSend` receiver.
    ///
    /// # Errors
    ///
    /// Returns [`LocalSendBridgeError::NoReceiverRunning`] when there is no
    /// receiver to stop.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn stop_receiver(&self) -> BridgeResult<()> {
        let (mut discovery, server) = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.pending_requests.clear();
            (state.discovery.take(), state.server.take())
        };
        let Some(mut server) = server else {
            return Err(LocalSendBridgeError::NoReceiverRunning);
        };
        if let Some(discovery) = discovery.as_mut() {
            discovery.stop();
        }
        self.runtime.block_on(server.stop());
        Ok(())
    }

    /// The receiver's actual bound port, useful when [`StartReceiverRequest::port`]
    /// was `0` (OS-assigned) — the server resolves the real port during its
    /// own bind, before any caller could otherwise learn it. `None` if no
    /// receiver is running.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn receiver_port(&self) -> Option<u16> {
        let state = self.state.lock().expect("registry lock poisoned");
        state.server.as_ref().map(LocalSendServer::port)
    }

    /// The receiver's own fingerprint — under `https: true` this is the SHA-256
    /// of the TLS certificate `start_receiver` generated, resolved only once
    /// the server has actually bound (same reasoning as [`receiver_port`](Self::receiver_port)).
    /// `None` if no receiver is running.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn receiver_fingerprint(&self) -> Option<String> {
        let state = self.state.lock().expect("registry lock poisoned");
        state.server.as_ref().map(|server| server.device().fingerprint.clone())
    }

    /// Converts one `ServerEvent` into a queued, JSON-serializable event.
    /// `TransferRequest`/`WebShareRequest` carry a non-serializable
    /// one-shot responder, so those are stashed by request id and only
    /// their descriptive fields are queued; the app responds later via
    /// [`LocalSendRegistry::respond_to_transfer`].
    fn absorb_event(&self, event: ServerEvent) {
        let queued = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            match event {
                ServerEvent::PeerRegistered(device) => {
                    state
                        .confirmed_devices
                        .insert(device.fingerprint.clone(), ConfirmedDevice { device: device.clone(), last_seen: std::time::Instant::now() });
                    if let Some(discovery) = state.active_discovery.as_ref() {
                        discovery.add_device(device.clone());
                    }
                    QueuedEvent::PeerRegistered { device: device.into() }
                }
                ServerEvent::TransferRequest(pending) => {
                    state.next_request_id = state.next_request_id.saturating_add(1);
                    let request_id = format!("transfer-{}-{}", std::process::id(), state.next_request_id);
                    let sender = pending.sender().clone().into();
                    let files: Vec<TransferFile> = pending
                        .files()
                        .values()
                        .map(|metadata| TransferFile {
                            id: metadata.id.as_str().to_owned(),
                            file_name: metadata.file_name.clone(),
                            size: metadata.size,
                            file_type: metadata.file_type.clone(),
                        })
                        .collect();
                    state.pending_requests.insert(request_id.clone(), pending);
                    QueuedEvent::TransferRequest { request_id, sender, files }
                }
                ServerEvent::TextReceived { session_id, text, sender_alias } => {
                    QueuedEvent::TextReceived { session_id: session_id.as_str().to_owned(), text, sender_alias }
                }
                ServerEvent::FileReceiveProgress { session_id, file_id, file_name, sender_alias, bytes_received, total_bytes, file_count } => {
                    QueuedEvent::FileReceiveProgress {
                        session_id: session_id.as_str().to_owned(),
                        file_id: file_id.as_str().to_owned(),
                        file_name,
                        sender_alias,
                        bytes_received,
                        total_bytes,
                        file_count,
                    }
                }
                ServerEvent::FileReceived { session_id, file_id, file_name, path, .. } => {
                    QueuedEvent::FileReceived { session_id: session_id.as_str().to_owned(), file_id: file_id.as_str().to_owned(), file_name, path }
                }
                ServerEvent::SessionDone { session_id } => QueuedEvent::SessionDone { session_id: session_id.as_str().to_owned() },
                // Web Share (browser-facing) events are out of scope for the
                // device-to-device workflows this crate wraps; drop them.
                ServerEvent::WebShareRequest(_) | ServerEvent::WebShareDownloadProgress { .. } | ServerEvent::WebShareSessionDone { .. } => return,
            }
        };
        self.push_event(queued);
    }

    /// Appends one event to the shared, bounded queue `poll_events` drains.
    /// Shared by the receive-event pump (`absorb_event`) and the send-side
    /// progress callback in [`LocalSendRegistry::send_file`] — both push
    /// into the same queue, so the eviction policy only needs to live once.
    fn push_event(&self, event: QueuedEvent) {
        let mut state = self.state.lock().expect("registry lock poisoned");
        if state.events.len() >= MAX_QUEUED_EVENTS {
            state.events.pop_front();
        }
        state.events.push_back(event);
    }

    /// Drains and returns all queued receiver and sender events.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn poll_events(&self) -> PollEventsResult {
        let mut state = self.state.lock().expect("registry lock poisoned");
        PollEventsResult { events: state.events.drain(..).collect() }
    }

    /// Applies the caller's decision to a queued incoming transfer request.
    ///
    /// # Errors
    ///
    /// Returns [`LocalSendBridgeError::UnknownRequestId`] when the request is
    /// no longer pending, or an error from the underlying transfer responder.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn respond_to_transfer(&self, request: RespondToTransferRequest) -> BridgeResult<()> {
        let pending = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.pending_requests.remove(&request.request_id).ok_or_else(|| LocalSendBridgeError::UnknownRequestId(request.request_id.clone()))?
        };
        match request.decision {
            TransferDecisionKind::Accept => pending.accept(),
            TransferDecisionKind::AcceptFiles => {
                let ids = request.file_ids.into_iter().map(FileId).collect();
                pending.accept_files(ids);
            }
            TransferDecisionKind::Decline => pending.decline(),
            TransferDecisionKind::Refuse => pending.refuse(request.reason.unwrap_or_else(|| "rejected".to_owned())),
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Discovery — a bounded sweep, not a persistent background listener.
    // ---------------------------------------------------------------------

    /// Discovers nearby `LocalSend` devices for the requested timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if discovery cannot start, announce, or stop cleanly.
    ///
    /// # Panics
    ///
    /// Panics if the discovery result mutex is poisoned or the Tokio runtime
    /// cannot synchronously drive the discovery task.
    #[allow(clippy::too_many_lines)]
    pub fn discover(&self, request: DiscoverRequest) -> BridgeResult<Vec<DiscoveredDevice>> {
        let own_fingerprint = self.state.lock().expect("registry lock poisoned").server.as_ref().map(|server| server.device().fingerprint.clone());
        let client_certificate = request.https.then(|| self.client_certificate()).transpose()?;
        let local_ips = if request.interface_ips.is_empty() {
            localsend_rs::local_ipv4_addresses()?
        } else {
            request
                .interface_ips
                .iter()
                .map(|ip| ip.parse().map_err(|error| LocalSendBridgeError::InvalidRequest(format!("invalid LocalSend interface IP {ip}: {error}"))))
                .collect::<BridgeResult<Vec<std::net::Ipv4Addr>>>()?
        };

        self.runtime.block_on(async move {
            use localsend_rs::{Discovery, HttpDiscovery, MulticastDiscovery};

            // Keyed by fingerprint rather than a Vec scanned linearly: every
            // announcement and every subnet-scan hit is deduplicated against
            // everything already seen, so a list is quadratic in peer count.
            let found: Arc<Mutex<HashMap<String, DeviceInfo>>> = Arc::new(Mutex::new(HashMap::new()));
            let sink = found.clone();

            // A peer answers an announcement by POSTing `/register` back to us,
            // so that reply lands on the HTTP server and never reaches the
            // multicast listener. Official LocalSend feeds such confirmations
            // into the same store its listener writes to
            // (`RsDiscovery::add_device`); `active_discovery` below is how the
            // server reaches this sweep, so `found` sees the replies this
            // announcement provokes rather than only overheard announcements.
            let peers_found = || !found.lock().expect("discovery result lock poisoned").is_empty();

            let protocol = if request.https { Protocol::Https } else { Protocol::Http };
            let device = DeviceInfoBuilder::new(request.alias.clone(), request.port).protocol(protocol).build();
            let mut discovery = MulticastDiscovery::new_with_device(device);
            if let Some(certificate) = client_certificate.clone() {
                discovery.set_client_certificate(certificate);
            }
            discovery.on_discovered(move |found_device| {
                let mut guard = sink.lock().expect("discovery result lock poisoned");
                guard.entry(found_device.fingerprint.clone()).or_insert(found_device);
            });

            // LocalSend's multicast announcement is the fast path. The
            // official app treats multicast as optional: iOS can lose or
            // reject a socket while HTTP discovery remains usable. Start it
            // first, but never let a multicast bind failure suppress the
            // register-first fallback.
            let multicast_started = discovery.start().await.is_ok();
            // Publish this sweep's discovery so `/register` replies reach it.
            self.state.lock().expect("registry lock poisoned").active_discovery = Some(discovery.clone());
            let multicast = async {
                if multicast_started {
                    // The announcement burst deliberately repeats over a few
                    // seconds so a peer that missed the first packet still
                    // hears one, but a peer that did hear it registers back
                    // within ~100ms. Awaiting the whole burst made every sweep
                    // cost its full length; official `LocalSend` lets the burst
                    // run while devices surface as they confirm, so it is sent
                    // in the background and the wait below settles as soon as
                    // anyone answers.
                    let announcer = discovery.clone();
                    tokio::spawn(async move {
                        let _ = announcer.announce_presence().await;
                    });

                    // `timeout_ms` is the budget for hearing nothing, not a
                    // fixed cost to pay on every sweep. Sleeping it out
                    // unconditionally made discovery take the whole timeout
                    // (3s from the desktop shell, 10s from this crate's
                    // default) even when a peer answered in milliseconds.
                    // Peers that are going to answer answer fast, so once the
                    // first one does, wait only a short settle window for
                    // stragglers before stopping.
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(request.timeout_ms);
                    let mut settle_deadline = None;
                    loop {
                        let now = tokio::time::Instant::now();
                        if now >= deadline {
                            break;
                        }
                        match settle_deadline {
                            Some(settle) if now >= settle => break,
                            None if peers_found() => {
                                settle_deadline = Some(now + DISCOVERY_SETTLE);
                            }
                            _ => {}
                        }
                        tokio::time::sleep(DISCOVERY_POLL.min(deadline - now)).await;
                    }
                }
                discovery.stop();
            };

            let http = async {
                if multicast_started {
                    // Match the official staged discovery grace period: give
                    // multicast/known-peer confirmation a chance before
                    // opening a full subnet sweep.
                    // Poll rather than sleeping the grace period out: a peer
                    // that is going to answer answers in milliseconds, and the
                    // subnet sweep below is the expensive fallback.
                    let grace_deadline = tokio::time::Instant::now() + DISCOVERY_HTTP_GRACE;
                    while tokio::time::Instant::now() < grace_deadline {
                        if peers_found() {
                            return Ok::<Vec<DeviceInfo>, localsend_rs::error::LocalSendError>(Vec::new());
                        }
                        tokio::time::sleep(DISCOVERY_POLL).await;
                    }
                    if peers_found() {
                        return Ok::<Vec<DeviceInfo>, localsend_rs::error::LocalSendError>(Vec::new());
                    }
                }
                let mut scans = Vec::with_capacity(local_ips.len());
                for local_ip in local_ips {
                    let scanner = match client_certificate.as_ref() {
                        Some(certificate) => HttpDiscovery::new_with_client_certificate(request.alias.clone(), request.port, protocol, certificate)?,
                        None => HttpDiscovery::new(request.alias.clone(), request.port, protocol)?,
                    };
                    let base_ip = local_ip.to_string();
                    let timeout = std::time::Duration::from_millis(request.timeout_ms);
                    scans.push(tokio::spawn(async move { scanner.scan_subnet_register_within(&base_ip, timeout).await }));
                }

                let mut devices: HashMap<String, DeviceInfo> = HashMap::new();
                for scan in scans {
                    if let Ok(Ok(outcome)) = scan.await {
                        for device in outcome.devices {
                            devices.entry(device.fingerprint.clone()).or_insert(device);
                        }
                    }
                }
                Ok::<Vec<DeviceInfo>, localsend_rs::error::LocalSendError>(devices.into_values().collect())
            };

            let ((), http_result) = tokio::join!(multicast, http);
            self.state.lock().expect("registry lock poisoned").active_discovery = None;

            let mut guard = found.lock().expect("discovery result lock poisoned");
            for device in http_result? {
                guard.entry(device.fingerprint.clone()).or_insert(device);
            }

            let devices = exclude_self_devices(guard.values().cloned().collect(), own_fingerprint.as_deref());
            let mut state = self.state.lock().expect("registry lock poisoned");
            for device in devices {
                state.confirmed_devices.insert(device.fingerprint.clone(), ConfirmedDevice { device, last_seen: std::time::Instant::now() });
            }

            // Drop peers that have stopped confirming before reporting: the
            // store is what the UI offers as send targets, and a device that
            // left the network must not keep appearing as a live one.
            let now = std::time::Instant::now();
            state.confirmed_devices.retain(|_, confirmed| now.duration_since(confirmed.last_seen) < CONFIRMED_DEVICE_TTL);

            let persisted = state
                .confirmed_devices
                .values()
                .filter(|confirmed| own_fingerprint.as_deref() != Some(confirmed.device.fingerprint.as_str()))
                .map(|confirmed| DiscoveredDevice::from(confirmed.device.clone()))
                .collect();
            Ok(persisted)
        })
    }

    // ---------------------------------------------------------------------
    // Send — one file, one push, blocking on completion.
    // ---------------------------------------------------------------------

    /// Sends one file to a discovered `LocalSend` device.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not a file, the upload fails, or the
    /// transfer is cancelled.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned or this synchronous API
    /// is called from a Tokio runtime context that cannot be nested.
    pub fn send_file(&self, request: SendFileRequest) -> BridgeResult<SendFileResult> {
        if !request.file_path.is_file() {
            return Err(LocalSendBridgeError::InvalidRequest(format!("not a file: {}", request.file_path.display())));
        }

        let send_id = request.send_id.clone();
        let alias = request.alias;
        let self_port = request.self_port;
        let https = request.https;
        let target: DeviceInfo = request.target.into();
        let client_certificate = (https || target.protocol == Protocol::Https).then(|| self.client_certificate()).transpose()?;
        let file_path = request.file_path;
        let pin = request.pin;

        let progress_registry = registry();
        let progress_send_id = send_id.clone();

        let task = self.runtime.spawn(async move {
            use localsend_rs::{LocalSendClient, TlsTrustPolicy};

            let protocol = if https { Protocol::Https } else { Protocol::Http };
            let self_device = DeviceInfoBuilder::new(alias, self_port).protocol(protocol).build();
            // `LocalSendClient::new` builds a plain reqwest client that does
            // ordinary TLS validation — it will always reject a LocalSend
            // peer's self-signed cert. HTTPS targets need the pinned trust
            // policy instead, keyed off the fingerprint `discover()` already
            // returned for this device (LocalSend's actual security model:
            // trust is established by the fingerprint shown to the user at
            // send time, not by a CA chain).
            let client = if matches!(target.protocol, Protocol::Https) {
                match client_certificate.as_ref() {
                    Some(certificate) => LocalSendClient::with_trust_policy_and_client_certificate(
                        self_device,
                        TlsTrustPolicy::PinnedFingerprint(target.fingerprint.clone()),
                        certificate,
                    )?,
                    None => LocalSendClient::with_trust_policy(self_device, TlsTrustPolicy::PinnedFingerprint(target.fingerprint.clone()))?,
                }
            } else {
                LocalSendClient::new(self_device)
            };

            let metadata = localsend_rs::build_file_metadata(&file_path).await?;
            let file_id = metadata.id.clone();
            let file_name = metadata.file_name.clone();
            let mut files = HashMap::new();
            files.insert(file_id.clone(), metadata);

            let prepared = client.prepare_upload(&target, files, pin.as_deref()).await?;
            let token = prepared
                .files
                .get(&file_id)
                .ok_or_else(|| LocalSendBridgeError::InvalidRequest("receiver did not return an upload token for the offered file".to_owned()))?
                .clone();

            let session_id = prepared.session_id.clone();
            let progress: ProgressCallback = {
                let registry = progress_registry.clone();
                let send_id = progress_send_id.clone();
                let session_id = session_id.as_str().to_owned();
                let file_id = file_id.as_str().to_owned();
                let file_name = file_name.clone();
                Box::new(move |bytes_sent, total_bytes, rate_bytes_per_second| {
                    registry.push_event(QueuedEvent::FileSendProgress {
                        send_id: send_id.clone(),
                        session_id: session_id.clone(),
                        file_id: file_id.clone(),
                        file_name: file_name.clone(),
                        bytes_sent,
                        total_bytes,
                        rate_bytes_per_second,
                    });
                })
            };

            client.upload_file_with_rate_limit(&target, &session_id, &file_id, &token, &file_path, Some(progress), None).await?;

            Ok::<SendFileResult, LocalSendBridgeError>(SendFileResult { session_id: session_id.as_str().to_owned(), file_id: file_id.as_str().to_owned() })
        });

        {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.active_sends.insert(send_id.clone(), task.abort_handle());
        }

        let result = self.runtime.block_on(task);

        {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.active_sends.remove(&send_id);
        }

        match result {
            Ok(inner) => inner,
            Err(join_error) if join_error.is_cancelled() => Err(LocalSendBridgeError::SendCancelled),
            Err(join_error) => Err(LocalSendBridgeError::InvalidRequest(format!("send task failed unexpectedly: {join_error}"))),
        }
    }

    /// Aborts the in-flight `send_file` task identified by `request.send_id`,
    /// unblocking its `block_on` on this or another thread with
    /// [`LocalSendBridgeError::SendCancelled`]. This is a hard abort (the
    /// underlying connection is simply dropped), not a protocol-level cancel
    /// notice to the peer — `localsend-rs`'s `LocalSendClient::cancel` exists
    /// for that and is a separate concern.
    ///
    /// # Errors
    ///
    /// Returns [`LocalSendBridgeError::UnknownSendId`] when no active send has
    /// that identifier.
    ///
    /// # Panics
    ///
    /// Panics if the registry state mutex is poisoned.
    pub fn cancel_send(&self, request: &CancelSendRequest) -> BridgeResult<()> {
        let state = self.state.lock().expect("registry lock poisoned");
        let handle = state.active_sends.get(&request.send_id).ok_or_else(|| LocalSendBridgeError::UnknownSendId(request.send_id.clone()))?;
        handle.abort();
        Ok(())
    }
}

// ---------------------------------------------------------------------
// JSON-facing DTOs
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfoDto {
    pub alias: String,
    pub fingerprint: String,
    pub port: u16,
    pub protocol: String,
    pub ip: Option<String>,
    pub device_model: Option<String>,
}

impl From<DeviceInfo> for DeviceInfoDto {
    fn from(device: DeviceInfo) -> Self {
        Self {
            alias: device.alias,
            fingerprint: device.fingerprint,
            port: device.port,
            protocol: device.protocol.as_str().to_owned(),
            ip: device.ip,
            device_model: device.device_model,
        }
    }
}

impl From<DeviceInfoDto> for DeviceInfo {
    fn from(dto: DeviceInfoDto) -> Self {
        let mut device = DeviceInfo::new(dto.alias, dto.port, Protocol::from(dto.protocol.as_str()));
        device.fingerprint = dto.fingerprint;
        device.ip = dto.ip;
        device.device_model = dto.device_model;
        device
    }
}

pub type DiscoveredDevice = DeviceInfoDto;

#[derive(Debug, Deserialize)]
pub struct DiscoverRequest {
    pub alias: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    #[serde(default = "default_discover_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub interface_ips: Vec<String>,
}

/// A peer confirmation plus when it was last seen.
///
/// `LocalSend` has no goodbye: a device that leaves the network simply stops
/// answering. Without a last-seen stamp the store only ever grows, and a
/// device that left hours ago is returned to the UI as though it were still
/// there, indistinguishable from a live one.
#[derive(Debug, Clone)]
struct ConfirmedDevice {
    device: DeviceInfo,
    last_seen: std::time::Instant,
}

/// How long a peer stays in the store after its last confirmation.
///
/// Long enough to survive a sweep the device happened to miss, short enough
/// that a device which has actually left stops being offered as a target.
const CONFIRMED_DEVICE_TTL: std::time::Duration = std::time::Duration::from_mins(2);

/// How long to wait for `/register` replies before falling back to the
/// subnet sweep. Replies observed on a healthy LAN arrive in ~100ms.
const DISCOVERY_HTTP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// How often the multicast wait checks whether any peer has answered.
const DISCOVERY_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// How long the multicast wait keeps listening after the first peer answers,
/// so a slightly slower device on the same sweep is still collected.
const DISCOVERY_SETTLE: std::time::Duration = std::time::Duration::from_millis(400);

fn default_discover_timeout_ms() -> u64 {
    10_000
}

fn exclude_self_devices(devices: Vec<DeviceInfo>, own_fingerprint: Option<&str>) -> Vec<DeviceInfo> {
    devices.into_iter().filter(|device| own_fingerprint != Some(device.fingerprint.as_str())).collect()
}

#[derive(Debug, Serialize)]
pub struct TransferFile {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum QueuedEvent {
    PeerRegistered {
        device: DeviceInfoDto,
    },
    TransferRequest {
        request_id: String,
        sender: DeviceInfoDto,
        files: Vec<TransferFile>,
    },
    TextReceived {
        session_id: String,
        text: String,
        sender_alias: String,
    },
    FileReceiveProgress {
        session_id: String,
        file_id: String,
        file_name: String,
        sender_alias: String,
        bytes_received: u64,
        total_bytes: u64,
        file_count: usize,
    },
    FileReceived {
        session_id: String,
        file_id: String,
        file_name: String,
        path: PathBuf,
    },
    SessionDone {
        session_id: String,
    },
    FileSendProgress {
        send_id: String,
        session_id: String,
        file_id: String,
        file_name: String,
        bytes_sent: u64,
        total_bytes: u64,
        rate_bytes_per_second: f64,
    },
}

#[derive(Debug, Serialize)]
pub struct PollEventsResult {
    pub events: Vec<QueuedEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDecisionKind {
    Accept,
    AcceptFiles,
    Decline,
    Refuse,
}

#[derive(Debug, Deserialize)]
pub struct RespondToTransferRequest {
    pub request_id: String,
    pub decision: TransferDecisionKind,
    #[serde(default)]
    pub file_ids: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendFileRequest {
    /// Caller-generated identifier for this send, used to key
    /// [`LocalSendRegistry::cancel_send`] and to tag [`QueuedEvent::FileSendProgress`]
    /// events — the registry has no way to name an in-flight send otherwise,
    /// since `send_file` may be called for several files/targets concurrently.
    pub send_id: String,
    pub alias: String,
    #[serde(default = "default_port")]
    pub self_port: u16,
    #[serde(default)]
    pub https: bool,
    pub target: DeviceInfoDto,
    pub file_path: PathBuf,
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendFileResult {
    pub session_id: String,
    pub file_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CancelSendRequest {
    pub send_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmed(fingerprint: &str, age: std::time::Duration) -> ConfirmedDevice {
        ConfirmedDevice {
            device: DeviceInfo {
                alias: "peer".to_owned(),
                version: "2.1".to_owned(),
                device_model: None,
                device_type: None,
                fingerprint: fingerprint.to_owned(),
                port: 53317,
                protocol: Protocol::Http,
                download: false,
                ip: Some("192.168.0.2".to_owned()),
            },
            last_seen: std::time::Instant::now().checked_sub(age).expect("test ages are small"),
        }
    }

    /// `LocalSend` has no goodbye, so a departed device just stops confirming.
    /// Without pruning it is offered as a live send target indefinitely.
    #[test]
    fn peers_that_stopped_confirming_are_dropped_from_the_store() {
        let mut store: HashMap<String, ConfirmedDevice> = HashMap::new();
        store.insert("fresh".to_owned(), confirmed("fresh", std::time::Duration::from_secs(1)));
        store.insert("stale".to_owned(), confirmed("stale", CONFIRMED_DEVICE_TTL + std::time::Duration::from_secs(1)));

        let now = std::time::Instant::now();
        store.retain(|_, entry| now.duration_since(entry.last_seen) < CONFIRMED_DEVICE_TTL);

        assert!(store.contains_key("fresh"), "a peer confirmed moments ago must stay");
        assert!(!store.contains_key("stale"), "a peer past the TTL must not be offered as a target");
    }

    /// The TTL has to outlast a single missed sweep, or a device that simply
    /// did not answer one announcement would vanish and reappear.
    #[test]
    fn the_confirmation_ttl_outlasts_a_missed_sweep() {
        assert!(CONFIRMED_DEVICE_TTL > std::time::Duration::from_secs(30), "TTL {CONFIRMED_DEVICE_TTL:?} is too short to survive a sweep a device missed");
    }

    #[test]
    fn discovery_results_exclude_the_running_receiver_identity() {
        let own_fingerprint = "own-fingerprint".to_owned();
        let devices = vec![
            DeviceInfo {
                alias: "ZManager Desktop".to_owned(),
                version: "2.1".to_owned(),
                device_model: Some("macos".to_owned()),
                device_type: None,
                fingerprint: own_fingerprint.clone(),
                port: default_port(),
                protocol: Protocol::Http,
                download: false,
                ip: Some("10.211.55.2".to_owned()),
            },
            DeviceInfo {
                alias: "Lovely Melon".to_owned(),
                version: "2.1".to_owned(),
                device_model: Some("Windows".to_owned()),
                device_type: None,
                fingerprint: "remote-fingerprint".to_owned(),
                port: default_port(),
                protocol: Protocol::Https,
                download: false,
                ip: Some("10.211.55.8".to_owned()),
            },
        ];

        let filtered = exclude_self_devices(devices, Some(own_fingerprint.as_str()));

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].alias, "Lovely Melon");
    }
}
