//! Public DTOs exposed across the FFI surface.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BridgeSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
    pub recovery_hint: Option<String>,
    pub severity: BridgeSeverity,
    pub retryable: bool,
}

#[derive(Debug, Error)]
pub enum ZmanagerGuiError {
    #[error("{user_message}")]
    Bridge { code: String, user_message: String, recovery_hint: Option<String>, severity: BridgeSeverity, retryable: bool },
}

impl From<BridgeError> for ZmanagerGuiError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge { code: error.code, user_message: error.message, recovery_hint: error.recovery_hint, severity: error.severity, retryable: error.retryable }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckResult {
    pub status: String,
    pub engine: String,
    pub version: String,
    pub ready: bool,
    pub summary: String,
}

/// One row of the compile-time format capability registry, exposed so
/// downstream consumers (gui/mobile) can build or verify their format tables
/// against the same source of truth as the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatDescriptor {
    /// Debug name of the core `ArchiveFormatKind`, for example "Zip" or "AppleArchive".
    pub kind: String,
    /// Human-readable display label.
    pub label: String,
    /// Extension suffixes (with leading dot) this format is recognized by.
    /// Predicate-detected formats (split volumes, raw streams) carry an empty list.
    pub extensions: Vec<String>,
    /// Whether this build can list the format's contents.
    pub can_list: bool,
    /// Whether this build can extract the format.
    pub can_extract: bool,
    /// Whether this build can create the format.
    pub can_create: bool,
    /// Whether the canonical detector recognizes this format.
    pub recognized: bool,
    /// Whether the current build has a registered operation adapter.
    pub platform_available: bool,
    /// Stable explanation when the format is unavailable.
    pub unavailable_reason: Option<String>,
    /// Source access required by the registered adapter.
    pub source_access: Option<String>,
    /// Whether the registered adapter supports encrypted archives.
    pub encryption_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFormatsResult {
    pub formats: Vec<FormatDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Zip,
    SplitZip,
    Rar,
    MultipartRar,
    SevenZ,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    TarLzma,
    TarLz,
    TarLzo,
    TarCompress,
    TarLz4,
    TarUu,
    Iso,
    Cab,
    Cpio,
    Rpm,
    Xar,
    Pkg,
    Dmg,
    Lha,
    Ar,
    Warc,
    Mtree,
    Deb,
    Msi,
    Vhd,
    Vmdk,
    Udf,
    Squashfs,
    AppImage,
    Wim,
    Vdi,
    Nrg,
    Mdf,
    Cdi,
    Isz,
    Ccd,
    Cue,
    Vhdx,
    Qcow2,
    Ewf,
    Ad1,
    Dar,
    Aff4,
    RawDisk,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Tzap,
    AppleArchive,
    Xip,
    RawStream,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveRequest {
    pub archive_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub exists: bool,
    pub is_file: bool,
    pub can_list: bool,
    pub can_extract: bool,
    pub can_create: bool,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: ArchiveEntryKind,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub modified_at: Option<String>,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub entries: Vec<ArchiveEntry>,
    pub entry_count: u64,
    pub total_size: Option<u64>,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveRequest {
    pub archive_path: String,
    pub password: Option<String>,
    pub selected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestArchiveResult {
    pub archive_path: String,
    pub format: ArchiveFormat,
    pub format_label: String,
    pub verified: bool,
    pub tested_entries: u64,
    pub skipped_entries: u64,
    pub total_entries: u64,
    pub tested_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewRequest {
    pub archive_path: String,
    pub entry_path: String,
    pub password: Option<String>,
    pub strip_components: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializePreviewResult {
    pub archive_path: String,
    pub entry_path: String,
    pub cleanup_root: String,
    pub preview_path: String,
    pub written_bytes: u64,
    pub warnings: Vec<BridgeError>,
}

#[cfg(feature = "localsend")]
pub(crate) fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------
// LocalSend (Track 12a) — mirrors zmanager-localsend::registry's request
// and response shapes; conversions to/from that crate's own types live in
// ffi/ops/localsend.rs, next to the calls that need them.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartReceiverRequest {
    pub alias: String,
    pub port: u16,
    pub https: bool,
    pub save_dir: String,
    pub auto_accept: bool,
    pub pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverRequest {
    pub alias: String,
    pub port: u16,
    pub https: bool,
    pub timeout_ms: u64,
    pub interface_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfoDto {
    pub alias: String,
    pub fingerprint: String,
    pub port: u16,
    pub protocol: String,
    pub ip: Option<String>,
    pub device_model: Option<String>,
    /// When this peer last confirmed itself, for discovery results.
    ///
    /// `LocalSend` has no goodbye: a peer that left simply stops confirming.
    /// Discovery drops peers that go quiet, but inside that window a shell
    /// still needs to tell a device seen moments ago from one about to be
    /// dropped. `None` where the device is not a discovery result - an
    /// event's sender, or a send target.
    pub last_seen_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferFile {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueuedEvent {
    PeerRegistered { device: DeviceInfoDto },
    TransferRequest { request_id: String, sender: DeviceInfoDto, files: Vec<TransferFile> },
    TextReceived { session_id: String, text: String, sender_alias: String },
    FileReceiveProgress { session_id: String, file_id: String, file_name: String, sender_alias: String, bytes_received: u64, total_bytes: u64, file_count: u64 },
    FileReceived { session_id: String, file_id: String, file_name: String, path: String },
    SessionDone { session_id: String },
    FileSendProgress { send_id: String, session_id: String, file_id: String, file_name: String, bytes_sent: u64, total_bytes: u64, rate_bytes_per_second: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollEventsResult {
    pub events: Vec<QueuedEvent>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TransferDecisionKind {
    Accept,
    AcceptFiles,
    Decline,
    Refuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondToTransferRequest {
    pub request_id: String,
    pub decision: TransferDecisionKind,
    pub file_ids: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendFileRequest {
    pub send_id: String,
    pub alias: String,
    pub self_port: u16,
    pub https: bool,
    pub target: DeviceInfoDto,
    pub file_path: String,
    pub pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendFileResult {
    pub session_id: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelSendRequest {
    pub send_id: String,
}

// ---------------------------------------------------------------------
// TZAP hosted identity (Track 12a) — mirrors the UDL dictionaries above.
// Conversion to/from zmanager-tzap-hosted's JSON contract lives in
// ffi/ops/tzap.rs, next to the calls that need it.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapAuthLoginRequest {
    pub state_dir: String,
    pub account_key: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub auth_base_url: String,
    pub account_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapAuthLoginResult {
    pub launch_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapAuthCallbackRequest {
    pub state_dir: String,
    pub account_key: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub auth_base_url: String,
    pub callback_url: String,
    pub state: String,
    pub handoff_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapAuthStatusRequest {
    pub state_dir: String,
    pub account_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapAuthStatusResult {
    pub authenticated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapCertEnrollRequest {
    pub state_dir: String,
    pub account_key: String,
    pub service_base_url: String,
    pub custom_trust_root_cert_paths: Vec<String>,
    pub requested_validity_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapCertificateInventoryRequest {
    pub state_dir: String,
    pub account_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapCertificateInventoryResult {
    pub certificate_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapDocumentPayload {
    pub tzap_payload_version: u32,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapDocumentSignRequest {
    pub state_dir: String,
    pub account_key: String,
    pub certificate_id: String,
    pub payload: TzapDocumentPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapDocumentSignResult {
    pub envelope_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapDocumentVerifyRequest {
    pub envelope_json: String,
    pub custom_trust_root_cert_paths: Vec<String>,
    pub verifier_time_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TzapDocumentVerifyResult {
    pub state: String,
}
