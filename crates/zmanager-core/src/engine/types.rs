//! Normalized read domain types and errors for the core engine (ARC-103).

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::source::{ArchiveSource, SourceAccess};
use crate::jobs::CancellationToken;
use crate::manifest::ArchiveManifest;
use crate::safety::{ExtractionPolicy, OverwriteResolver};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

/// Session-scoped entry identifier (ARC-103).
///
/// `EntryId` is issued during listing and uniquely identifies physical entry
/// records within one opened `ArchiveHandle` session. Duplicate paths retain
/// distinct `EntryId` values. `EntryId` is invalidated when the handle closes.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EntryId(pub u64);

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Archive format and source layout detected by the engine.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DetectedArchive {
    /// Detected format identifier.
    pub format: FormatId,
    /// Resolved source descriptor.
    pub source: ArchiveSource,
}

/// Bounded source limits applied while opening an archive handle.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct OpenLimits {
    /// Optional aggregate byte limit for the owned source/volume set.
    pub max_source_bytes: Option<u64>,
}

/// Immutable credentials and source options bound to an opened archive handle.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OpenOptions {
    /// Optional password for encrypted headers or entries.
    pub password: Option<String>,
    /// Optional private key used to unwrap recipient-encrypted TZAP archives.
    pub recipient_key: Option<PathBuf>,
    /// Optional in-memory private key candidates used to unwrap
    /// recipient-encrypted TZAP archives, for callers that hold key material
    /// only in memory (for example a platform-sealed secret store) and must
    /// not write it to disk. A device that has rotated its recipient key
    /// holds several candidates at once -- its active key plus any retired
    /// ones -- and the first whose SPKI matches the archive's keywrap record
    /// wins.
    pub recipient_key_bytes: Option<Vec<Vec<u8>>>,
    /// Bounds applied to the owned source before adapter dispatch.
    pub limits: OpenLimits,
}

impl OpenOptions {
    /// Returns the optional recipient key path as a borrowed path.
    #[must_use]
    pub fn recipient_key_path(&self) -> Option<&Path> {
        self.recipient_key.as_deref()
    }

    /// Returns the optional in-memory recipient key candidate bytes as a
    /// borrowed slice.
    #[must_use]
    pub fn recipient_key_bytes(&self) -> Option<&[Vec<u8>]> {
        self.recipient_key_bytes.as_deref()
    }
}

impl fmt::Debug for OpenOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenOptions")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("recipient_key", &self.recipient_key)
            .field("recipient_key_bytes", &self.recipient_key_bytes.as_ref().map(Vec::len))
            .field("limits", &self.limits)
            .finish()
    }
}

/// One normalized entry record returned by engine listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EngineEntry {
    /// Session-scoped physical entry handle.
    pub id: EntryId,
    /// Normalized archive path (forward slashes, trimmed leading `./`).
    pub path: String,
    /// Portable entry type.
    pub kind: BrowserEntryKind,
    /// Uncompressed size when known.
    pub size: Option<u64>,
    /// Compressed size when known.
    pub compressed_size: Option<u64>,
    /// Modification time string.
    pub modified: Option<String>,
    /// Unix permission bits when available.
    pub mode: Option<u32>,
    /// Encryption status.
    pub encrypted: Option<bool>,
    /// Compression algorithm or method name.
    pub method: Option<String>,
    /// Checksum (e.g. CRC-32) when available.
    pub crc: Option<u32>,
    /// Entry comment when available.
    pub comment: Option<String>,
    /// Symlink or hardlink target path when applicable.
    pub link_target: Option<String>,
    /// Creation time string when available.
    pub created: Option<String>,
    /// Access time string when available.
    pub accessed: Option<String>,
    /// Solid archive member indicator.
    pub solid: Option<bool>,
    /// Format-specific attribute flags.
    pub attributes: Option<String>,
    /// User identifier.
    pub uid: Option<u32>,
    /// Group identifier.
    pub gid: Option<u32>,
    /// Owner username.
    pub owner: Option<String>,
    /// Group name.
    pub group: Option<String>,
}

/// Canonicalizes archive names for the engine contract without deciding
/// whether a name is safe to extract. Traversal components remain visible so
/// the safety planner can reject them deliberately at extraction time.
#[must_use]
pub fn normalize_engine_path(raw_path: &str) -> std::borrow::Cow<'_, str> {
    if raw_path.is_empty() {
        return std::borrow::Cow::Borrowed("");
    }
    let bytes = raw_path.as_bytes();
    let mut needs_normalization = false;
    if bytes[0] == b'/' || bytes[bytes.len() - 1] == b'/' {
        needs_normalization = true;
    } else {
        let mut prev_slash = false;
        let mut comp_start = 0;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\\' {
                needs_normalization = true;
                break;
            }
            if b == b'/' {
                if prev_slash {
                    needs_normalization = true;
                    break;
                }
                let comp = &raw_path[comp_start..i];
                if comp == "." {
                    needs_normalization = true;
                    break;
                }
                prev_slash = true;
                comp_start = i + 1;
            } else {
                prev_slash = false;
            }
        }
        if !needs_normalization {
            let comp = &raw_path[comp_start..];
            if comp == "." {
                needs_normalization = true;
            }
        }
    }

    if needs_normalization {
        std::borrow::Cow::Owned(
            raw_path.replace('\\', "/").split('/').filter(|component| !component.is_empty() && *component != ".").collect::<Vec<_>>().join("/"),
        )
    } else {
        std::borrow::Cow::Borrowed(raw_path)
    }
}

impl Default for EngineEntry {
    fn default() -> Self {
        Self {
            id: EntryId(0),
            path: String::new(),
            kind: BrowserEntryKind::File,
            size: None,
            compressed_size: None,
            modified: None,
            mode: None,
            encrypted: None,
            method: None,
            crc: None,
            comment: None,
            link_target: None,
            created: None,
            accessed: None,
            solid: None,
            attributes: None,
            uid: None,
            gid: None,
            owner: None,
            group: None,
        }
    }
}

/// Archive listing returned by an opened engine handle.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArchiveListing {
    /// Entries in archive order.
    pub entries: Vec<EngineEntry>,
}

/// Options for a normalized archive integrity test.
#[derive(Clone, Default)]
pub struct TestOptions {
    /// Exact archive paths to verify. An empty list verifies every entry.
    pub selected_paths: Vec<String>,
    /// Optional recipient key used by encrypted TZAP archives.
    pub recipient_key: Option<PathBuf>,
    /// Optional in-memory recipient key candidates used by encrypted TZAP
    /// archives (see [`OpenOptions::recipient_key_bytes`]).
    pub recipient_key_bytes: Option<Vec<Vec<u8>>>,
    /// Optional X.509 trust policy for TZAP root-auth verification.
    pub tzap_x509_trust: Option<TzapX509TrustOptions>,
    /// Cooperative cancellation flag checked before and during test work.
    pub cancellation: Option<Arc<AtomicBool>>,
}

impl fmt::Debug for TestOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestOptions")
            .field("selected_paths", &self.selected_paths)
            .field("recipient_key", &self.recipient_key)
            .field("recipient_key_bytes", &self.recipient_key_bytes.as_ref().map(Vec::len))
            .field("tzap_x509_trust", &self.tzap_x509_trust)
            .field("cancellation", &self.cancellation)
            .finish()
    }
}

impl TestOptions {
    /// Returns whether an entry path is selected by this request.
    #[must_use]
    pub fn selects(&self, path: &str) -> bool {
        self.selected_paths.is_empty() || self.selected_paths.iter().any(|selected| selected == path)
    }

    /// Returns whether the operation was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.as_ref().is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Normalized data-verification report shared by every test adapter.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TestReport {
    /// Number of entries whose payload or integrity metadata was verified.
    pub tested_entries: u64,
    /// Number of entries excluded by the request or not meaningfully testable.
    pub skipped_entries: u64,
    /// Number of decoded regular-file bytes consumed during verification.
    pub tested_bytes: u64,
    /// Non-fatal diagnostics produced by the adapter.
    pub warnings: Vec<String>,
}

/// Request for a normalized full extraction operation.
pub struct ExtractOptions<'a> {
    /// Destination directory committed by the adapter.
    pub destination: PathBuf,
    /// Shared extraction safety and overwrite policy.
    pub policy: ExtractionPolicy,
    /// Optional private key used by recipient-encrypted formats.
    pub recipient_key: Option<PathBuf>,
    /// Optional in-memory private key candidates used by recipient-encrypted
    /// formats (see [`OpenOptions::recipient_key_bytes`]).
    pub recipient_key_bytes: Option<Vec<Vec<u8>>>,
    /// Optional TZAP metadata restoration policy for full extraction.
    pub tzap_restore_options: Option<TzapRestoreOptions>,
    /// Optional password for TZAP extraction, independent of the archive open password.
    pub tzap_password: Option<String>,
    /// Optional cancellation token owned by the consumer/job registry.
    pub cancellation: Option<CancellationToken>,
    /// Optional event sink for live progress and diagnostics.
    pub event_sink: Option<&'a mut dyn crate::jobs::JobEventSink>,
    /// Optional resolver used when the policy is `OverwritePolicy::Ask`.
    pub overwrite_resolver: Option<&'a mut dyn OverwriteResolver>,
}

impl std::fmt::Debug for ExtractOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractOptions")
            .field("destination", &self.destination)
            .field("policy", &self.policy)
            .field("recipient_key", &self.recipient_key)
            .field("recipient_key_bytes", &self.recipient_key_bytes.as_ref().map(Vec::len))
            .field("tzap_restore_options", &self.tzap_restore_options)
            .field("cancellation", &self.cancellation)
            .field("event_sink", &self.event_sink.is_some())
            .field("overwrite_resolver", &self.overwrite_resolver.is_some())
            .finish()
    }
}

impl Default for ExtractOptions<'_> {
    fn default() -> Self {
        Self {
            destination: PathBuf::new(),
            policy: ExtractionPolicy::default(),
            recipient_key: None,
            recipient_key_bytes: None,
            tzap_restore_options: None,
            tzap_password: None,
            cancellation: None,
            event_sink: None,
            overwrite_resolver: None,
        }
    }
}

impl ExtractOptions<'_> {
    /// Returns whether this request has been cancelled before or during work.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.as_ref().is_some_and(CancellationToken::is_cancelled)
    }
}

/// Normalized full extraction report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ExtractReport {
    /// Number of entries committed to the destination.
    pub written_entries: u64,
    /// Number of entries skipped by policy or unsupported materialization.
    pub skipped_entries: u64,
    /// Regular-file bytes committed to the destination.
    pub written_bytes: u64,
    /// Non-fatal extraction warnings.
    pub warnings: Vec<String>,
}

/// Request for extracting one retained archive entry by session-scoped ID.
pub struct SelectedExtractOptions<'a> {
    /// Destination directory for the selected entry.
    pub destination: PathBuf,
    /// Shared safety and overwrite policy.
    pub policy: ExtractionPolicy,
    /// Optional TZAP metadata restoration policy for selected extraction.
    pub tzap_restore_options: Option<TzapRestoreOptions>,
    /// Optional cancellation token.
    pub cancellation: Option<CancellationToken>,
    /// Optional event sink for live progress and diagnostics.
    pub event_sink: Option<&'a mut dyn crate::jobs::JobEventSink>,
    /// Optional overwrite resolver for `Ask` policy.
    pub overwrite_resolver: Option<&'a mut dyn OverwriteResolver>,
}

impl std::fmt::Debug for SelectedExtractOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectedExtractOptions")
            .field("destination", &self.destination)
            .field("policy", &self.policy)
            .field("tzap_restore_options", &self.tzap_restore_options)
            .field("cancellation", &self.cancellation)
            .field("event_sink", &self.event_sink.is_some())
            .field("overwrite_resolver", &self.overwrite_resolver.is_some())
            .finish()
    }
}

impl Default for SelectedExtractOptions<'_> {
    fn default() -> Self {
        Self {
            destination: PathBuf::new(),
            policy: ExtractionPolicy::default(),
            tzap_restore_options: None,
            cancellation: None,
            event_sink: None,
            overwrite_resolver: None,
        }
    }
}

/// Normalized result for copying one entry payload to a caller-owned writer.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct CopyReport {
    /// Decoded regular-file bytes written to the caller's writer.
    pub written_bytes: u64,
}

/// ZIP compression selected by the engine creation contract.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ZipCompression {
    /// Store file data without compression.
    Store,
    /// Deflate file data.
    #[default]
    Deflate,
}

/// Engine-owned ZIP creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZipCreateOptions {
    /// Compression method for regular files.
    pub compression: ZipCompression,
    /// Optional compression level.
    pub level: Option<i64>,
    /// Preserve portable metadata.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
    /// Optional password.
    pub password: Option<crate::secrets::SecretString>,
    /// Optional split volume size.
    pub volume_size: Option<u64>,
}

impl Default for ZipCreateOptions {
    fn default() -> Self {
        Self { compression: ZipCompression::default(), level: None, preserve_metadata: true, replace_existing: false, password: None, volume_size: None }
    }
}

/// Engine-owned 7z creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SevenZCreateOptions {
    /// Whether regular files share a solid block.
    pub solid: bool,
    /// LZMA2 compression level.
    pub level: Option<u32>,
    /// LZMA2 worker count.
    pub threads: Option<u32>,
    /// LZMA2 independent chunk size.
    pub chunk_size: Option<u64>,
    /// Preserve timestamps and attributes.
    pub preserve_metadata: bool,
    /// Optional AES password.
    pub password: Option<crate::secrets::SecretString>,
    /// Encrypt archive headers.
    pub encrypt_file_names: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
    /// Optional split volume size.
    pub volume_size: Option<u64>,
}

impl Default for SevenZCreateOptions {
    fn default() -> Self {
        Self {
            solid: true,
            level: None,
            threads: crate::tar_metadata::available_parallelism_at_least_two(),
            chunk_size: Some(16 * 1024 * 1024),
            preserve_metadata: true,
            password: None,
            encrypt_file_names: true,
            replace_existing: false,
            volume_size: None,
        }
    }
}

/// Engine-owned TAR.ZST creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdCreateOptions {
    /// Zstandard compression level.
    pub level: i32,
    /// Zstandard worker count.
    pub threads: Option<u32>,
    /// Preserve portable metadata.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
}

impl Default for TarZstdCreateOptions {
    fn default() -> Self {
        Self { level: 3, threads: crate::tar_metadata::available_parallelism_at_least_two(), preserve_metadata: true, replace_existing: false }
    }
}

/// Engine-owned TAR.GZ creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzCreateOptions {
    /// Gzip compression level.
    pub level: i32,
    /// Preserve portable metadata.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
}

impl Default for TarGzCreateOptions {
    fn default() -> Self {
        Self { level: 6, preserve_metadata: true, replace_existing: false }
    }
}

/// Apple Archive compression selected by the engine creation contract.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AppleArchiveCompression {
    /// No compression.
    None,
    /// LZ4 compression.
    Lz4,
    /// ZLIB compression.
    Zlib,
    /// LZMA compression.
    Lzma,
    /// LZFSE compression.
    #[default]
    Lzfse,
    /// LZBITMAP compression.
    Lzbitmap,
}

/// Engine-owned Apple Archive creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppleArchiveCreateOptions {
    /// Compression algorithm.
    pub compression: AppleArchiveCompression,
    /// Compression block size.
    pub block_size: usize,
    /// Native worker count.
    pub threads: i32,
    /// Preserve portable metadata.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
    /// Optional encryption password.
    pub password: Option<String>,
}

impl Default for AppleArchiveCreateOptions {
    fn default() -> Self {
        Self {
            compression: AppleArchiveCompression::default(),
            block_size: 4 * 1024 * 1024,
            threads: 0,
            preserve_metadata: true,
            replace_existing: false,
            password: None,
        }
    }
}

/// Engine-owned TZAP metadata restoration policy.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum TzapRestorePolicy {
    /// Restore payload bytes only.
    Content,
    /// Restore portable metadata.
    #[default]
    Portable,
    /// Request authenticated metadata for the current operating system.
    SameOs,
    /// Explicitly authorize system metadata restoration.
    System,
}

/// Engine-owned TZAP extraction restoration options.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct TzapRestoreOptions {
    /// Requested restoration level.
    pub policy: TzapRestorePolicy,
    /// Permit unsupported metadata to be skipped with diagnostics.
    pub allow_degraded: bool,
    /// Allow absolute symlinks.
    pub allow_absolute_symlinks: bool,
}

/// Engine-owned TZAP X.509 signing options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapX509SigningOptions {
    /// PKCS#12 signing identity.
    Pkcs12 { identity: PathBuf, password: crate::secrets::SecretString },
    /// PEM/DER signing certificate and key.
    CertificateAndKey { signing_certificate: PathBuf, signing_private_key: PathBuf, signing_chain: Vec<PathBuf> },
    /// Signing material resolved from a secure local store.
    InMemory { signing_certificate: Vec<u8>, signing_private_key: crate::secrets::SecretBytes, signing_chain: Vec<Vec<u8>> },
}

/// Engine-owned TZAP X.509 trust options.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapX509TrustOptions {
    /// PEM or DER trusted CA certificates.
    pub trusted_ca_certificates: Vec<PathBuf>,
    /// Allow system trust roots.
    pub trusted_system_roots: bool,
    /// Include the embedded official TZAP root.
    pub include_official_tzap_root: bool,
}

impl TzapX509TrustOptions {
    /// Returns whether verification has at least one configured trust source.
    #[must_use]
    pub fn has_trust_source(&self) -> bool {
        self.include_official_tzap_root || !self.trusted_ca_certificates.is_empty() || self.trusted_system_roots
    }
}

/// Engine-owned public TZAP X.509 verification report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509VerificationReport {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Subjects in the verified chain.
    pub verified_chain_subjects: Vec<String>,
    /// Trust anchor subject, when available.
    pub trust_anchor_subject: Option<String>,
    /// Verification diagnostics.
    pub diagnostics: Vec<String>,
}

/// Engine-owned public TZAP X.509 signer inspection report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509SignerInspection {
    /// Archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of covered data blocks.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// Leaf certificate SHA-256 fingerprint.
    pub certificate_sha256: [u8; 32],
    /// Diagnostics from signer inspection.
    pub diagnostics: Vec<String>,
}

/// Engine-owned TZAP archive key source.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapKeySource {
    /// Password-derived key.
    Passphrase(crate::secrets::SecretString),
    /// One recipient certificate.
    RecipientCertificate(PathBuf),
    /// Multiple recipient certificates.
    RecipientCertificates(Vec<PathBuf>),
    /// Multiple recipient public keys.
    RecipientPublicKeys(Vec<Vec<u8>>),
    /// Unencrypted archive.
    NoPassword,
}

/// Engine-owned TZAP creation options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCreateOptions {
    /// Archive key source.
    pub key_source: TzapKeySource,
    /// Zstandard compression level.
    pub level: i32,
    /// Preserve portable metadata.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive.
    pub replace_existing: bool,
    /// Optional split volume size. Mutually exclusive with `volume_count`.
    pub volume_size: Option<u64>,
    /// Optional exact output volume count (striped rather than size-targeted).
    /// Mutually exclusive with `volume_size`.
    pub volume_count: Option<u32>,
    /// Recovery percentage.
    pub recovery_percentage: u8,
    /// Missing-volume tolerance.
    pub volume_loss_tolerance: u8,
    /// Optional X.509 `RootAuth` signer.
    pub x509_signing: Option<TzapX509SigningOptions>,
    /// Emit bootstrap sidecar file beside output.
    pub emit_bootstrap_sidecar: bool,
}

/// Typed format-specific options for one-shot archive creation.
#[derive(Debug, Clone)]
pub enum CreateOptions {
    /// Native seekable or split ZIP creation.
    Zip(ZipCreateOptions),
    /// Native 7z creation.
    SevenZ(SevenZCreateOptions),
    /// Native TAR.ZST creation.
    TarZstd(TarZstdCreateOptions),
    /// Native TAR.GZ creation.
    TarGz(TarGzCreateOptions),
    /// Native TZAP creation.
    Tzap(TzapCreateOptions),
    /// Native Apple Archive creation.
    AppleArchive(AppleArchiveCreateOptions),
}

impl CreateOptions {
    /// Returns the canonical format selected by these typed options.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        match self {
            Self::Zip(options) => match options.volume_size {
                Some(_) => FormatId::SPLIT_ZIP,
                None => FormatId::ZIP,
            },
            Self::SevenZ(_) => FormatId::SEVEN_Z,
            Self::TarZstd(_) => FormatId::TAR_ZST,
            Self::TarGz(_) => FormatId::TAR_GZ,
            Self::Tzap(_) => FormatId::TZAP,
            Self::AppleArchive(_) => FormatId::APPLE_ARCHIVE,
        }
    }
}

/// One-shot archive creation request.
#[derive(Debug, Clone)]
pub struct CreateRequest {
    /// Fully planned archive contents.
    pub manifest: ArchiveManifest,
    /// Final archive path. Adapters commit atomically to this path.
    pub destination: PathBuf,
    /// Typed options for the selected writer.
    pub options: CreateOptions,
}

impl CreateRequest {
    /// Creates a request and binds its format to the typed options.
    #[must_use]
    pub fn new(manifest: ArchiveManifest, destination: impl Into<PathBuf>, options: CreateOptions) -> Self {
        Self { manifest, destination: destination.into(), options }
    }

    /// Returns the format selected by this request.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.options.format()
    }
}

/// Normalized result returned only after an archive has been finalized and
/// atomically committed.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct CreateReport {
    /// Format written by the adapter.
    pub format: FormatId,
    /// Number of archive entries written.
    pub written_entries: u64,
    /// Number of source bytes copied into regular-file entries.
    pub written_bytes: u64,
    /// Whether encryption was enabled, when the format exposes this state.
    pub encrypted: Option<bool>,
    /// Whether solid compression was enabled, when applicable.
    pub solid: Option<bool>,
    /// Requested split volume size, when applicable.
    pub volume_size: Option<u64>,
    /// Number of output files created.
    pub volume_count: u64,
    /// Non-fatal diagnostics produced by the adapter.
    pub warnings: Vec<String>,
}

/// Archive operation supported by the engine seam.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ArchiveOperation {
    /// List entries in the archive.
    List,
    /// Data verification / integrity test.
    Test,
    /// Full extraction to destination directory.
    Extract,
    /// Selected single or batch entry extraction.
    SelectedExtract,
    /// Copy single entry payload to writer.
    CopyToWriter,
    /// Create new archive from manifest.
    Create,
}

/// Session disposition after an operation or error (ARC-103).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SessionDisposition {
    /// Session remains usable for subsequent operations.
    Usable,
    /// Session cursor or parser state is corrupted/uncertain; subsequent operations must fail.
    Unusable,
}

/// Category of operation error.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ErrorKind {
    /// Unsupported or unrecognized format.
    InvalidFormat,
    /// Password required to read header or payload.
    PasswordRequired,
    /// Provided password was rejected.
    WrongPassword,
    /// Data corruption or checksum failure.
    CorruptData,
    /// Resource or security limit exceeded.
    ResourceLimitExceeded,
    /// Extraction safety policy violation.
    SafetyViolation,
    /// Underlying filesystem I/O error.
    Io,
    /// The opened source changed after the handle was created or listed.
    SourceChanged,
    /// Operation not supported by this format/adapter.
    UnsupportedOperation,
    /// Operation was cooperatively cancelled.
    Cancelled,
}

/// Structured error returned by the archive engine interface.
#[derive(Debug)]
pub struct ArchiveError {
    /// Category of error.
    pub kind: ErrorKind,
    /// User-facing descriptive message.
    pub message: String,
    /// Handle session state disposition after this error.
    pub disposition: SessionDisposition,
    /// Optional underlying path.
    pub path: Option<PathBuf>,
}

impl ArchiveError {
    /// Creates a usable session error.
    #[must_use]
    pub fn usable(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), disposition: SessionDisposition::Usable, path: None }
    }

    /// Creates an unusable session error.
    #[must_use]
    pub fn unusable(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), disposition: SessionDisposition::Unusable, path: None }
    }

    /// Attaches an associated file path to this error.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{}: {} ({})", self.kind_str(), self.message, path.display())
        } else {
            write!(f, "{}: {}", self.kind_str(), self.message)
        }
    }
}

impl ArchiveError {
    fn kind_str(&self) -> &'static str {
        match self.kind {
            ErrorKind::InvalidFormat => "invalid format",
            ErrorKind::PasswordRequired => "password required",
            ErrorKind::WrongPassword => "wrong password",
            ErrorKind::CorruptData => "corrupt data",
            ErrorKind::ResourceLimitExceeded => "resource limit exceeded",
            ErrorKind::SafetyViolation => "safety violation",
            ErrorKind::Io => "I/O error",
            ErrorKind::SourceChanged => "source changed",
            ErrorKind::UnsupportedOperation => "unsupported operation",
            ErrorKind::Cancelled => "cancelled",
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Immutable capability summary reported by an engine handle or registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HandleCapabilities {
    /// Format identifier.
    pub format: FormatId,
    /// Source access capability.
    pub source_access: SourceAccess,
    /// How the adapter navigates entries after listing.
    pub navigation: NavigationMode,
    /// Credentials accepted by the adapter, if any.
    pub credential_requirement: CredentialRequirement,
    /// Supported operations.
    pub operations: Vec<ArchiveOperation>,
    /// Whether header or payload encryption is supported.
    pub encryption_supported: bool,
}

/// One immutable capability row for a canonical format registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FormatCapabilities {
    /// Canonical engine format identity.
    pub format: FormatId,
    /// Whether the canonical detector recognizes this format.
    pub recognized: bool,
    /// Whether the current build can execute a registered operation.
    pub platform_available: bool,
    /// Stable reason when the format is recognized but unavailable.
    pub unavailable_reason: Option<String>,
    /// Registered operations for this format.
    pub operations: Vec<ArchiveOperation>,
    /// Source access required by the registered adapters.
    pub source_access: Option<SourceAccess>,
    /// Navigation behavior exposed by the registered read adapter.
    pub navigation: Option<NavigationMode>,
    /// Credential behavior exposed by the registered adapter.
    pub credential_requirement: CredentialRequirement,
    /// Whether any registered adapter supports encryption.
    pub encryption_supported: bool,
    /// Product-facing role derived from registered operations.
    pub role: Option<ArchivePluginRole>,
}

/// Entry-navigation behavior promised by an adapter claim.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum NavigationMode {
    /// The session can service arbitrary retained entry IDs.
    RandomAccess,
    /// The session must scan from the beginning for entry operations.
    SequentialScan,
}

/// Credential shape accepted by an adapter claim.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum CredentialRequirement {
    /// The format is not encrypted or does not require credentials.
    None,
    /// A password may be supplied.
    Password,
    /// A password or recipient private key may be supplied.
    PasswordOrRecipientKey,
}

/// Product-facing capability role derived from operation registrations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ArchivePluginRole {
    /// The format can create archives but has no registered read operation.
    Archive,
    /// The format can read/extract archives but has no registered creator.
    Extraction,
    /// The format has both creation and read/extraction operations.
    Both,
}

#[cfg(test)]
mod tests {
    use super::normalize_engine_path;

    #[test]
    fn engine_path_normalization_is_display_stable_without_hiding_traversal() {
        assert_eq!(normalize_engine_path("./folder\\\\file.txt"), "folder/file.txt");
        assert_eq!(normalize_engine_path("//folder///file.txt"), "folder/file.txt");
        assert_eq!(normalize_engine_path("../outside.txt"), "../outside.txt");
    }
}
