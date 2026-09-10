//! LocalSend endpoints. Thin, typed wrappers over `zmanager-localsend`'s
//! registry — no LAN/protocol logic lives here. Track 12a of
//! zmanager-mobile's docs/mobile-code-health-remediation-plan.md: these used
//! to be JSON-string passthroughs (`localsend_discover_json` and friends),
//! hand-mirrored on both native shells; now the request/response shapes are
//! UniFFI-generated types and native holds no hand-written JSON mapping.

use std::path::PathBuf;

use crate::ffi::error::map_localsend_error;
use crate::ffi::types::{
    CancelSendRequest, DeviceInfoDto, DiscoverRequest, PollEventsResult, QueuedEvent, RespondToTransferRequest, SendFileRequest, SendFileResult,
    StartReceiverRequest, TransferDecisionKind, TransferFile, ZmanagerGuiError,
};

impl From<zmanager_localsend::DeviceInfoDto> for DeviceInfoDto {
    fn from(value: zmanager_localsend::DeviceInfoDto) -> Self {
        Self { alias: value.alias, fingerprint: value.fingerprint, port: value.port, protocol: value.protocol, ip: value.ip, device_model: value.device_model }
    }
}

impl From<DeviceInfoDto> for zmanager_localsend::DeviceInfoDto {
    fn from(value: DeviceInfoDto) -> Self {
        Self { alias: value.alias, fingerprint: value.fingerprint, port: value.port, protocol: value.protocol, ip: value.ip, device_model: value.device_model }
    }
}

impl From<zmanager_localsend::TransferFile> for TransferFile {
    fn from(value: zmanager_localsend::TransferFile) -> Self {
        Self { id: value.id, file_name: value.file_name, size: value.size, file_type: value.file_type }
    }
}

impl From<zmanager_localsend::QueuedEvent> for QueuedEvent {
    fn from(value: zmanager_localsend::QueuedEvent) -> Self {
        match value {
            zmanager_localsend::QueuedEvent::PeerRegistered { device } => Self::PeerRegistered { device: device.into() },
            zmanager_localsend::QueuedEvent::TransferRequest { request_id, sender, files } => {
                Self::TransferRequest { request_id, sender: sender.into(), files: files.into_iter().map(TransferFile::from).collect() }
            }
            zmanager_localsend::QueuedEvent::TextReceived { session_id, text, sender_alias } => Self::TextReceived { session_id, text, sender_alias },
            zmanager_localsend::QueuedEvent::FileReceiveProgress { session_id, file_id, file_name, sender_alias, bytes_received, total_bytes, file_count } => {
                Self::FileReceiveProgress {
                    session_id,
                    file_id,
                    file_name,
                    sender_alias,
                    bytes_received,
                    total_bytes,
                    file_count: crate::ffi::types::usize_to_u64(file_count),
                }
            }
            zmanager_localsend::QueuedEvent::FileReceived { session_id, file_id, file_name, path } => {
                Self::FileReceived { session_id, file_id, file_name, path: path.to_string_lossy().into_owned() }
            }
            zmanager_localsend::QueuedEvent::SessionDone { session_id } => Self::SessionDone { session_id },
            zmanager_localsend::QueuedEvent::FileSendProgress { send_id, session_id, file_id, file_name, bytes_sent, total_bytes, rate_bytes_per_second } => {
                Self::FileSendProgress { send_id, session_id, file_id, file_name, bytes_sent, total_bytes, rate_bytes_per_second }
            }
        }
    }
}

impl From<TransferDecisionKind> for zmanager_localsend::TransferDecisionKind {
    fn from(value: TransferDecisionKind) -> Self {
        match value {
            TransferDecisionKind::Accept => Self::Accept,
            TransferDecisionKind::AcceptFiles => Self::AcceptFiles,
            TransferDecisionKind::Decline => Self::Decline,
            TransferDecisionKind::Refuse => Self::Refuse,
        }
    }
}

/// Points the shared registry at the shell's application-data directory so
/// this device keeps one LocalSend identity across launches.
///
/// Desktop calls [`zmanager_localsend::LocalSendRegistry::set_identity_dir`]
/// directly; this is that same method, reachable from Swift and Kotlin. Only
/// the directory differs per platform — the persistence itself is one
/// implementation in `localsend-rs`.
#[allow(non_snake_case)]
pub fn localsendSetIdentityDir(directory: String) -> Result<(), ZmanagerGuiError> {
    zmanager_localsend::registry().set_identity_dir(PathBuf::from(directory)).map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendDiscover(request: DiscoverRequest) -> Result<Vec<DeviceInfoDto>, ZmanagerGuiError> {
    let native = zmanager_localsend::DiscoverRequest {
        alias: request.alias,
        port: request.port,
        https: request.https,
        timeout_ms: request.timeout_ms,
        interface_ips: request.interface_ips,
    };
    zmanager_localsend::registry().discover(native).map(|devices| devices.into_iter().map(DeviceInfoDto::from).collect()).map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendStartReceiver(request: StartReceiverRequest) -> Result<(), ZmanagerGuiError> {
    let native = zmanager_localsend::StartReceiverRequest {
        alias: request.alias,
        port: request.port,
        https: request.https,
        save_dir: PathBuf::from(request.save_dir),
        auto_accept: request.auto_accept,
        pin: request.pin,
    };
    zmanager_localsend::registry().start_receiver(native).map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendStopReceiver() -> Result<(), ZmanagerGuiError> {
    zmanager_localsend::registry().stop_receiver().map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendPollEvents() -> PollEventsResult {
    let native = zmanager_localsend::registry().poll_events();
    PollEventsResult { events: native.events.into_iter().map(QueuedEvent::from).collect() }
}

#[allow(non_snake_case)]
pub fn localsendRespondToTransfer(request: RespondToTransferRequest) -> Result<(), ZmanagerGuiError> {
    let native = zmanager_localsend::RespondToTransferRequest {
        request_id: request.request_id,
        decision: request.decision.into(),
        file_ids: request.file_ids,
        reason: request.reason,
    };
    zmanager_localsend::registry().respond_to_transfer(native).map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendSendFile(request: SendFileRequest) -> Result<SendFileResult, ZmanagerGuiError> {
    let native = zmanager_localsend::SendFileRequest {
        send_id: request.send_id,
        alias: request.alias,
        self_port: request.self_port,
        https: request.https,
        target: request.target.into(),
        file_path: PathBuf::from(request.file_path),
        pin: request.pin,
    };
    zmanager_localsend::registry()
        .send_file(native)
        .map(|result| SendFileResult { session_id: result.session_id, file_id: result.file_id })
        .map_err(map_localsend_error)
}

#[allow(non_snake_case)]
pub fn localsendCancelSend(request: CancelSendRequest) -> Result<(), ZmanagerGuiError> {
    let native = zmanager_localsend::CancelSendRequest { send_id: request.send_id };
    zmanager_localsend::registry().cancel_send(&native).map_err(map_localsend_error)
}
