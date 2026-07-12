use crate::atomic_file::AtomicOutputFile;
use crate::jobs::{JobCancelled, JobContext, JobPhase, ProgressBatch, ProgressCoalescer};
use crate::manifest::{ArchiveManifest, ManifestFileType, PlanError};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use crate::x509_format::x509_name_to_string;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use openssl::x509::X509;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use rand::RngCore as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::format::{
    AeadAlgo, CRYPTO_HEADER_FIXED_LEN, CompressionAlgo, FORMAT_VERSION, FecAlgo, FormatError,
    KdfAlgo, READER_MAX_ARGON2ID_M_COST_KIB, READER_MAX_ARGON2ID_PARALLELISM,
    READER_MAX_ARGON2ID_T_COST, VOLUME_FORMAT_REV_44, VOLUME_HEADER_LEN,
};
use tzap_core::reader::{
    ArchiveEntry, ArchiveIndexEntry, ExtractedArchiveMember, PublicNoKeyDiagnostic,
    PublicNoKeyVerification, RecipientWrapRecordContext, RootAuthDiagnostic, RootAuthVerification,
};
use tzap_core::wire::{
    CryptoHeader, CryptoHeaderFixed, RecipientRecordV1, RootAuthFooterV1, VolumeHeader,
};
use tzap_core::{
    ArchiveWriteError, ArchiveWritePhase, ArchiveWriteProgressSink, ArchiveWriteSink, ExtractError,
    KdfParams, MasterKey, OpenedArchive, ReaderOptions, RegularFileSource, RootAuthSigningRequest,
    SafeExtractionOptions, TarEntryKind, WriterOptions, open_seekable_archive,
    open_seekable_archive_volumes,
    open_seekable_archive_volumes_with_recipient_wrap_resolver_options,
    public_no_key_verify_volumes_with,
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress,
    write_archive_sources_to_sink_with_progress,
};
use tzap_plugin_keywrap::{
    ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup,
    RecipientRecordInput, RecipientRecordMetadata, dispatch_key_wrap_record,
    wrap_master_key_for_recipient,
};
use tzap_plugin_signing::x509_chain::{
    X509_AUTHENTICATOR_ID, X509_SIGNER_IDENTITY_TYPE_DER_CERT, X509RootAuthReport,
    X509RootAuthSigner, certificate_der_from_pem_or_der, certificates_der_from_pem_or_der,
    signing_input, verify_root_auth_footer,
};

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;
const TZAP_EXTENSION: &str = "tzap";
const TZAP_EXTENSION_SUFFIX: &str = ".tzap";
const TZAP_VOLUME_MARKER: &str = ".vol";
const TZAP_VOLUME_INDEX_WIDTH: usize = 3;
const TZAP_TEMP_EXTRACT_PREFIX: &str = ".zmanager-tzap-extract";
const TZAP_TEMP_EXTRACT_ATTEMPTS: u32 = 100;
const TZAP_PLACEHOLDER_MASTER_KEY: [u8; 32] = [0; 32];
const X509_ROOT_AUTH_MAGIC: &[u8; 4] = b"TZXC";
const X509_ROOT_AUTH_VERSION: u16 = 1;
const X509_ROOT_AUTH_OPENSSL_SHA256_SCHEME: u16 = 1;
const X509_ROOT_AUTH_FIXED_AUTHENTICATOR_LEN: usize = 60;
const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str =
    "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d";
const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("trust/tzap-production-root-ca-2026.pem");

/// Returns whether a path names a TZAP archive or one of its numbered volumes.
#[must_use]
pub fn is_tzap_archive_path(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(TZAP_EXTENSION))
    {
        return true;
    }

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_tzap_volume_archive_file_name)
}

fn is_tzap_volume_archive_file_name(name: &str) -> bool {
    parse_tzap_volume_file_name(name).is_some()
}

/// Options for `.tzap` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCreateOptions {
    /// Archive key source.
    pub key_source: TzapKeySource,
    /// Zstd compression level.
    pub level: i32,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
    /// Split output into TZAP volumes of this size when present.
    pub volume_size: Option<u64>,
    /// Percent of archive data reserved for bit-rot recovery structures.
    pub recovery_percentage: u8,
    /// Number of missing output volumes the archive should tolerate.
    pub volume_loss_tolerance: u8,
    /// X.509 `RootAuth` signing configuration.
    pub x509_signing: Option<TzapX509SigningOptions>,
}

/// Key source for `.tzap` creation and opening.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapKeySource {
    /// Derive the archive master key from a passphrase with Argon2id.
    Passphrase(SecretString),
    /// Wrap a random archive master key to one X.509 recipient certificate.
    RecipientCertificate(PathBuf),
    /// Wrap a random archive master key to multiple X.509 recipient certificates.
    RecipientCertificates(Vec<PathBuf>),
    /// Wrap a random archive master key to multiple recipient public keys.
    RecipientPublicKeys(Vec<Vec<u8>>),
    /// Create the archive without password-based encryption.
    NoPassword,
}

impl TzapKeySource {
    /// Returns whether this key source uses secret user input.
    #[must_use]
    pub fn uses_secret(&self) -> bool {
        matches!(self, Self::Passphrase(_))
    }
}

/// X.509 `RootAuth` signing inputs for `.tzap` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapX509SigningOptions {
    /// PKCS#12 signing identity containing the leaf certificate, private key,
    /// and optional intermediate certificates.
    Pkcs12 {
        /// PKCS#12 identity file path.
        identity: PathBuf,
        /// PKCS#12 import password.
        password: SecretString,
    },
    /// Advanced PEM/DER signing inputs.
    CertificateAndKey {
        /// PEM or DER leaf signing certificate. PEM bundles may include
        /// intermediate certificates after the leaf certificate.
        signing_certificate: PathBuf,
        /// PEM or DER private key matching the leaf signing certificate.
        signing_private_key: PathBuf,
        /// Optional PEM or DER intermediate certificates.
        signing_chain: Vec<PathBuf>,
    },
}

/// X.509 `RootAuth` trust configuration for `.tzap` verification.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapX509TrustOptions {
    /// PEM or DER trusted CA certificates.
    pub trusted_ca_certificates: Vec<PathBuf>,
    /// Allow OpenSSL's default system trust roots.
    pub trusted_system_roots: bool,
    /// Include ZManager's embedded official TZAP root certificate.
    pub include_official_tzap_root: bool,
}

impl TzapX509TrustOptions {
    /// Returns whether verification has any trust source to use.
    #[must_use]
    pub fn has_trust_source(&self) -> bool {
        self.include_official_tzap_root
            || !self.trusted_ca_certificates.is_empty()
            || self.trusted_system_roots
    }
}

impl TzapPublicFormatSummary {
    fn from_headers(volume_header: &VolumeHeader, crypto_header: &CryptoHeaderFixed) -> Self {
        Self {
            format_version: volume_header.format_version,
            volume_format_revision: volume_header.volume_format_rev,
            archive_uuid: volume_header.archive_uuid,
            session_id: volume_header.session_id,
            compression_algorithm: compression_algorithm_label(crypto_header.compression_algo),
            encryption_algorithm: aead_algorithm_label(crypto_header.aead_algo),
            recovery_algorithm: fec_algorithm_label(crypto_header.fec_algo),
            key_derivation: kdf_algorithm_label(crypto_header.kdf_algo),
            password_required: crypto_header.kdf_algo == KdfAlgo::Argon2id,
            bit_rot_buffer_percentage: crypto_header.bit_rot_buffer_pct,
            volume_loss_tolerance: crypto_header.volume_loss_tolerance,
            data_shard_count: crypto_header.fec_data_shards,
            parity_shard_count: crypto_header.fec_parity_shards,
            index_data_shard_count: crypto_header.index_fec_data_shards,
            index_parity_shard_count: crypto_header.index_fec_parity_shards,
            index_root_data_shard_count: crypto_header.index_root_fec_data_shards,
            index_root_parity_shard_count: crypto_header.index_root_fec_parity_shards,
            block_size: crypto_header.block_size,
            chunk_size: crypto_header.chunk_size,
            envelope_target_size: crypto_header.envelope_target_size,
            has_dictionary: crypto_header.has_dictionary != 0,
        }
    }
}

/// Successful X.509 `RootAuth` verification report.
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
    /// Signer-claimed signing time as Unix seconds.
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
    /// Trust anchor subject, when OpenSSL reported one.
    pub trust_anchor_subject: Option<String>,
    /// Root-auth verification diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

/// X.509 `RootAuth` signer details inspected without trust validation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509SignerInspection {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time as Unix seconds.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Root-auth inspection diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

/// Public, no-password `.tzap` archive metadata.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPublicMetadataSummary {
    /// Path that was requested by the caller.
    pub requested_path: PathBuf,
    /// Expected total volume count from the archive header.
    pub expected_volume_count: usize,
    /// Number of expected volumes found beside the selected path.
    pub present_volume_count: usize,
    /// Missing volume indexes in the expected set.
    pub missing_volume_indices: Vec<usize>,
    /// Total bytes across the expected volumes that are present.
    pub total_size: u64,
    /// Requested volume size embedded in the crypto header, when present.
    pub expected_volume_size: u64,
    /// Per-volume details for expected volumes that were found.
    pub volumes: Vec<TzapPublicVolumeSummary>,
    /// Header and recovery policy details.
    pub format: TzapPublicFormatSummary,
}

/// Public details for one `.tzap` volume.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPublicVolumeSummary {
    /// Path of the volume file.
    pub path: PathBuf,
    /// Zero-based volume index encoded in the volume header.
    pub index: usize,
    /// Volume bytes on disk.
    pub size: u64,
}

/// Public `.tzap` format and recovery policy details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPublicFormatSummary {
    /// TZAP format version.
    pub format_version: u16,
    /// TZAP volume format revision.
    pub volume_format_revision: u16,
    /// Archive UUID encoded in every volume header.
    pub archive_uuid: [u8; 16],
    /// Session identifier encoded in every volume header.
    pub session_id: [u8; 16],
    /// Compression algorithm label.
    pub compression_algorithm: &'static str,
    /// Authenticated encryption algorithm label.
    pub encryption_algorithm: &'static str,
    /// Forward error correction algorithm label.
    pub recovery_algorithm: &'static str,
    /// Key derivation mode label.
    pub key_derivation: &'static str,
    /// Whether opening archive contents requires a password.
    pub password_required: bool,
    /// Per-object bit-rot recovery budget percentage.
    pub bit_rot_buffer_percentage: u8,
    /// Number of missing volumes the archive is intended to tolerate.
    pub volume_loss_tolerance: u8,
    /// Number of data shards per regular payload FEC class.
    pub data_shard_count: u16,
    /// Number of parity shards per regular payload FEC class.
    pub parity_shard_count: u16,
    /// Number of data shards per index FEC class.
    pub index_data_shard_count: u16,
    /// Number of parity shards per index FEC class.
    pub index_parity_shard_count: u16,
    /// Number of data shards per index-root FEC class.
    pub index_root_data_shard_count: u16,
    /// Number of parity shards per index-root FEC class.
    pub index_root_parity_shard_count: u16,
    /// Archive block size in bytes.
    pub block_size: u32,
    /// Compression chunk size in bytes.
    pub chunk_size: u32,
    /// Target plaintext envelope size in bytes.
    pub envelope_target_size: u32,
    /// Whether the archive has a compression dictionary object.
    pub has_dictionary: bool,
}

/// `.tzap` creation report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCreateReport {
    /// Number of regular file entries written.
    pub written_entries: usize,
    /// Number of archive volume bytes written.
    pub written_bytes: u64,
    /// Compression level used.
    pub level: i32,
    /// Requested split volume size, when the archive was split.
    pub volume_size: Option<u64>,
    /// Number of output volumes written.
    pub volume_count: usize,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tzap` archive listing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapListing {
    /// Listed entries.
    pub entries: Vec<TzapEntry>,
}

/// One `.tzap` archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEntry {
    /// Archive path.
    pub path: String,
    /// Entry kind.
    pub kind: TzapEntryKind,
    /// Uncompressed file bytes.
    pub size: u64,
    /// Portable mode bits.
    pub mode: u32,
    /// Modification time as Unix seconds.
    pub mtime: u64,
}

/// Public entry kind for `.tzap` listings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TzapEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
}

/// `.tzap` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tzap` test report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapTestReport {
    /// Number of entries in the archive.
    pub entries: usize,
    /// Number of entries selected by the filter.
    pub tested_entries: usize,
    /// Number of entries skipped by the filter.
    pub skipped_entries: usize,
    /// Total selected regular-file bytes.
    pub tested_bytes: u64,
    /// Verified X.509 `RootAuth` details when trust options were supplied.
    pub x509_root_auth: Option<TzapX509VerificationReport>,
}

/// `.tzap` backend error.
#[derive(Debug)]
pub enum TzapError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Archive format, cryptographic, or metadata validation failed.
    Format(FormatError),
    /// X.509 `RootAuth` signing or verification failed.
    X509RootAuth(String),
    /// X.509 recipient key wrapping failed.
    KeyWrap(String),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A passphrase-protected `.tzap` archive was opened without a password.
    PasswordRequired,
    /// A recipient-wrapped `.tzap` archive was opened without a recipient private key.
    RecipientKeyRequired,
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TzapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "{source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Format(source) => write!(f, "{source}"),
            Self::X509RootAuth(message) => write!(f, "{message}"),
            Self::KeyWrap(message) => write!(f, "{message}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::PasswordRequired => write!(f, "tzap password required"),
            Self::RecipientKeyRequired => write!(f, "tzap recipient private key required"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TzapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Format(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::X509RootAuth(_)
            | Self::KeyWrap(_)
            | Self::PasswordRequired
            | Self::RecipientKeyRequired
            | Self::Cancelled => None,
        }
    }
}

impl From<FormatError> for TzapError {
    fn from(source: FormatError) -> Self {
        Self::Format(source)
    }
}

impl From<PlanError> for TzapError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<ExtractionSafetyError> for TzapError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TzapError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Creates a `.tzap` archive from a manifest.
///
/// # Errors
///
/// Returns [`TzapError`] when source files cannot be read, key derivation fails,
/// tzap encoding fails, filesystem writes fail, or cancellation is requested.
pub fn create_tzap_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TzapCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TzapCreateReport, TzapError> {
    context.check_cancelled()?;
    let (file_sources, mut warnings) =
        collect_regular_file_sources(manifest, options, Some(context))?;
    context.check_cancelled()?;

    let mut writer_options = WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.recovery_percentage,
        target_volume_size: options.volume_size,
        zstd_level: options.level,
        ..WriterOptions::default()
    };
    if !options.preserve_metadata {
        writer_options.closed_at_ns = 0;
    }
    if matches!(options.key_source, TzapKeySource::NoPassword) {
        writer_options.aead_algo = AeadAlgo::None;
    }

    let (master_key, kdf_params) = create_key_material(&options.key_source)?;
    let recipient_records = match &options.key_source {
        TzapKeySource::RecipientCertificate(recipient_certificate) => {
            validate_recipient_wrap_create_options(options)?;
            Some(vec![build_recipient_wrap_record_from_certificate_path(
                recipient_certificate,
                &master_key,
                &mut writer_options,
            )?])
        }
        TzapKeySource::RecipientCertificates(recipient_certificates) => {
            validate_recipient_wrap_create_options(options)?;
            if recipient_certificates.is_empty() {
                return Err(TzapError::KeyWrap(
                    "at least one recipient certificate is required".to_owned(),
                ));
            }
            let archive_identity = recipient_wrap_archive_identity_for_writer(&mut writer_options);
            Some(
                recipient_certificates
                    .iter()
                    .map(|path| {
                        let certificate =
                            load_single_x509_certificate_file("recipient certificate", path)?;
                        build_recipient_wrap_record_from_certificate_der(
                            certificate,
                            &master_key,
                            archive_identity.clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        TzapKeySource::RecipientPublicKeys(recipient_public_keys) => {
            validate_recipient_wrap_create_options(options)?;
            if recipient_public_keys.is_empty() {
                return Err(TzapError::KeyWrap(
                    "at least one recipient public key is required".to_owned(),
                ));
            }
            let archive_identity = recipient_wrap_archive_identity_for_writer(&mut writer_options);
            Some(
                recipient_public_keys
                    .iter()
                    .map(|public_key_der| {
                        let certificate = synthetic_recipient_certificate_der(public_key_der)?;
                        build_recipient_wrap_record_from_certificate_der(
                            certificate,
                            &master_key,
                            archive_identity.clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        TzapKeySource::Passphrase(_) | TzapKeySource::NoPassword => None,
    };
    let destination = destination.as_ref();
    let mut sink = TzapArchiveFileSink::new(destination, options.replace_existing)?;
    let x509_signer = options
        .x509_signing
        .as_ref()
        .map(load_x509_signer)
        .transpose()?;
    let root_auth = x509_signer
        .as_ref()
        .map(X509RootAuthSigner::root_auth_writer_config)
        .transpose()
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let mut authenticator = |request: &RootAuthSigningRequest| {
        x509_signer
            .as_ref()
            .ok_or(FormatError::WriterInvariant("missing X.509 signer"))
            .and_then(|signer| {
                signer
                    .authenticator_value_for_request(request)
                    .map_err(|_| FormatError::WriterUnsupported("X.509 RootAuth signing failed"))
            })
    };
    let authenticator = root_auth.as_ref().map(|_| {
        &mut authenticator
            as &mut dyn FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>
    });
    let file_sizes = file_sources
        .iter()
        .map(|file| (file.archive_path.clone(), file.size))
        .collect::<BTreeMap<_, _>>();
    let mut started_paths = BTreeSet::new();
    let mut finished_paths = BTreeSet::new();
    let mut processed_by_path = BTreeMap::<String, u64>::new();

    let summary = {
        let mut progress = TzapWriteJobProgress {
            context,
            total_source_bytes: manifest.total_bytes,
            file_sizes: &file_sizes,
            started_paths: &mut started_paths,
            finished_paths: &mut finished_paths,
            processed_by_path: &mut processed_by_path,
            active_phase: None,
            phase_progress: ProgressCoalescer::new(None),
        };
        let result = if let Some(recipient_records) = recipient_records {
            write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress(
                &file_sources,
                &master_key,
                writer_options,
                recipient_records,
                root_auth,
                authenticator,
                &mut sink,
                &mut progress,
            )
        } else {
            write_archive_sources_to_sink_with_progress(
                &file_sources,
                &master_key,
                writer_options,
                None,
                &kdf_params,
                root_auth,
                authenticator,
                &mut sink,
                &mut progress,
            )
        };
        progress.flush_pending();
        result
    }
    .map_err(|source| tzap_write_error(destination, source))?;

    context.phase_started(JobPhase::CommittingOutput, None);
    let volume_count = sink.commit()?;
    if summary.volume_count != volume_count {
        return Err(TzapError::Format(FormatError::WriterInvariant(
            "TZAP writer summary did not match committed volume count",
        )));
    }
    for file in &file_sources {
        if started_paths.insert(file.archive_path.clone()) {
            context.entry_started(&file.archive_path, Some(file.size));
        }
        if finished_paths.insert(file.archive_path.clone()) {
            context.entry_finished(&file.archive_path, file.size);
        }
    }

    warnings.extend(
        manifest
            .warnings
            .iter()
            .map(|warning| warning.message.clone()),
    );

    Ok(TzapCreateReport {
        written_entries: file_sources.len(),
        written_bytes: summary.archive_bytes,
        level: options.level,
        volume_size: options.volume_size,
        volume_count,
        warnings,
    })
}

fn tzap_output_volume_paths(destination: &Path, count: usize) -> Vec<PathBuf> {
    if count == 1 {
        return vec![destination.to_path_buf()];
    }

    (0..count)
        .map(|index| tzap_output_volume_path(destination, index))
        .collect()
}

fn tzap_output_volume_path(destination: &Path, zero_based_index: usize) -> PathBuf {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        let mut path = destination.as_os_str().to_os_string();
        path.push(format!(
            "{TZAP_VOLUME_MARKER}{zero_based_index:0TZAP_VOLUME_INDEX_WIDTH$}{TZAP_EXTENSION_SUFFIX}"
        ));
        return PathBuf::from(path);
    };
    let base_name = tzap_multi_volume_base_name(file_name);
    let volume_file_name = format!(
        "{base_name}{TZAP_VOLUME_MARKER}{zero_based_index:0TZAP_VOLUME_INDEX_WIDTH$}{TZAP_EXTENSION_SUFFIX}"
    );
    match destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join(volume_file_name),
        None => PathBuf::from(volume_file_name),
    }
}

fn ensure_tzap_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), TzapError> {
    ensure_file_destination_available(destination, replace_existing)?;
    for path in unique_paths(volume_paths, existing_volume_paths) {
        ensure_file_destination_available(path, replace_existing)?;
    }
    Ok(())
}

fn unique_paths<'a>(left: &'a [PathBuf], right: &'a [PathBuf]) -> Vec<&'a Path> {
    let mut seen = BTreeSet::new();
    left.iter()
        .chain(right.iter())
        .filter_map(|path| {
            if seen.insert(path.clone()) {
                Some(path.as_path())
            } else {
                None
            }
        })
        .collect()
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), TzapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) if !replace_existing => Err(io_error(
            path,
            io::ErrorKind::AlreadyExists,
            format!("destination already exists: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_tzap_destinations_for_replace(
    destination: &Path,
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), TzapError> {
    if !replace_existing {
        return Ok(());
    }

    for path in existing_volume_paths {
        remove_file_destination_for_replace(path)?;
    }
    remove_file_destination_for_replace(destination)
}

fn remove_file_destination_for_replace(path: &Path) -> Result<(), TzapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(
                path,
                io::ErrorKind::IsADirectory,
                format!("cannot replace directory {}", path.display()),
            ))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn existing_tzap_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, TzapError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let Some(destination_file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let destination_base_name = tzap_multi_volume_base_name(destination_file_name);

    let mut paths = Vec::new();
    for entry in fs::read_dir(parent).map_err(|source| TzapError::Io {
        path: parent.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if let Some(pattern) = parse_tzap_volume_file_name(file_name)
            && pattern.base == destination_base_name
        {
            paths.push((pattern.volume_index, entry.path()));
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(paths.into_iter().map(|(_, path)| path).collect())
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TzapVolumeFileName {
    base: String,
    volume_index: usize,
}

fn parse_tzap_volume_file_name(file_name: &str) -> Option<TzapVolumeFileName> {
    let stem = strip_ascii_case_insensitive_suffix(file_name, TZAP_EXTENSION_SUFFIX)?;
    let (base, digits) = stem.rsplit_once(TZAP_VOLUME_MARKER)?;
    if base.is_empty() || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    Some(TzapVolumeFileName {
        base: base.to_owned(),
        volume_index: digits.parse().ok()?,
    })
}

fn tzap_multi_volume_base_name(file_name: &str) -> String {
    strip_ascii_case_insensitive_suffix(file_name, TZAP_EXTENSION_SUFFIX)
        .unwrap_or(file_name)
        .to_owned()
}

fn strip_ascii_case_insensitive_suffix<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    if value.len() < suffix.len() {
        return None;
    }
    let prefix_len = value.len() - suffix.len();
    let candidate = value.get(prefix_len..)?;
    if !candidate.eq_ignore_ascii_case(suffix) {
        return None;
    }
    value.get(..prefix_len)
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> TzapError {
    TzapError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(kind, message.into()),
    }
}

fn load_x509_signer(options: &TzapX509SigningOptions) -> Result<X509RootAuthSigner, TzapError> {
    match options {
        TzapX509SigningOptions::Pkcs12 { identity, password } => {
            load_x509_signer_from_pkcs12(identity, password)
        }
        TzapX509SigningOptions::CertificateAndKey {
            signing_certificate,
            signing_private_key,
            signing_chain,
        } => load_x509_signer_from_certificate_files(
            signing_certificate,
            signing_private_key,
            signing_chain,
        ),
    }
}

fn load_x509_signer_from_certificate_files(
    signing_certificate: &Path,
    signing_private_key: &Path,
    signing_chain: &[PathBuf],
) -> Result<X509RootAuthSigner, TzapError> {
    let certificate = read_x509_input_file(signing_certificate)?;
    let mut certificate_der = certificates_der_from_pem_or_der(&certificate)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let leaf_certificate_der = certificate_der.remove(0);
    let private_key = read_x509_input_file(signing_private_key)?;
    let mut chain_der = certificate_der;
    chain_der.extend(load_x509_certificate_files(signing_chain)?);
    X509RootAuthSigner::from_pem_or_der(
        &leaf_certificate_der,
        &private_key,
        chain_der,
        current_unix_seconds_i64()?,
    )
    .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

fn load_x509_signer_from_pkcs12(
    identity: &Path,
    password: &SecretString,
) -> Result<X509RootAuthSigner, TzapError> {
    let identity_bytes = read_x509_input_file(identity)?;
    let pkcs12 = Pkcs12::from_der(&identity_bytes)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let parsed = pkcs12
        .parse2(password.expose_secret())
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let certificate = parsed
        .cert
        .ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no certificate".to_owned()))?;
    let private_key = parsed
        .pkey
        .ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no private key".to_owned()))?;
    let chain_der = parsed
        .ca
        .map(|chain| {
            chain
                .iter()
                .map(|certificate| {
                    certificate
                        .to_der()
                        .map_err(|source| TzapError::X509RootAuth(source.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    X509RootAuthSigner::new(
        certificate
            .to_der()
            .map_err(|source| TzapError::X509RootAuth(source.to_string()))?,
        private_key,
        chain_der,
        current_unix_seconds_i64()?,
    )
    .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

fn load_x509_certificate_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = read_x509_input_file(path)?;
        let mut parsed = certificates_der_from_pem_or_der(&bytes)
            .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
        certificates.append(&mut parsed);
    }
    Ok(certificates)
}

fn read_x509_input_file(path: &Path) -> Result<Vec<u8>, TzapError> {
    fs::read(path).map_err(|source| TzapError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn load_x509_trusted_roots(trust: &TzapX509TrustOptions) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    if trust.include_official_tzap_root {
        certificates.push(
            certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).map_err(|source| {
                TzapError::X509RootAuth(format!(
                    "failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}: {source}"
                ))
            })?,
        );
    }
    certificates.extend(load_x509_certificate_files(&trust.trusted_ca_certificates)?);
    Ok(certificates)
}

fn validate_recipient_wrap_create_options(options: &TzapCreateOptions) -> Result<(), TzapError> {
    if options.x509_signing.is_some() {
        return Err(TzapError::Format(FormatError::WriterUnsupported(
            "recipient certificate encryption is not yet supported with X.509 RootAuth signing",
        )));
    }
    if options.volume_size.is_some() || options.volume_loss_tolerance != 0 {
        return Err(TzapError::Format(FormatError::WriterUnsupported(
            "recipient certificate encryption is currently supported only for single-volume TZAP create",
        )));
    }
    Ok(())
}

fn build_recipient_wrap_record_from_certificate_path(
    recipient_certificate_path: &Path,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<RecipientRecordV1, TzapError> {
    let recipient_certificate =
        load_single_x509_certificate_file("recipient certificate", recipient_certificate_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    build_recipient_wrap_record_from_certificate_der(
        recipient_certificate,
        master_key,
        archive_identity,
    )
}

fn build_recipient_wrap_record_from_certificate_der(
    recipient_certificate: Vec<u8>,
    master_key: &MasterKey,
    archive_identity: KeyWrapArchiveIdentity,
) -> Result<RecipientRecordV1, TzapError> {
    let master_key_bytes = master_key.0;
    for suite in [
        KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        KeyWrapSuite::P256HkdfSha256Aes256Gcm,
    ] {
        match wrap_master_key_for_recipient(
            archive_identity.clone(),
            &recipient_certificate,
            &master_key_bytes,
            suite,
        ) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(outcome)),
        }
    }
    Err(TzapError::Format(FormatError::WriterUnsupported(
        "recipient certificate is not supported by keywrap-v1 suites",
    )))
}

fn synthetic_recipient_certificate_der(public_key_spki_der: &[u8]) -> Result<Vec<u8>, TzapError> {
    let public_key =
        PKey::<Public>::public_key_from_der(public_key_spki_der).map_err(|source| {
            TzapError::KeyWrap(format!("recipient public key is invalid: {source}"))
        })?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|source| {
        TzapError::KeyWrap(format!("recipient certificate key failed: {source}"))
    })?;
    let issuer_key = PKey::from_ec_key(EcKey::generate(&group).map_err(|source| {
        TzapError::KeyWrap(format!("recipient certificate key failed: {source}"))
    })?)
    .map_err(|source| TzapError::KeyWrap(format!("recipient certificate key failed: {source}")))?;
    let mut name = openssl::x509::X509NameBuilder::new().map_err(|source| {
        TzapError::KeyWrap(format!("recipient certificate name failed: {source}"))
    })?;
    name.append_entry_by_text("CN", "ZManager Contact Recipient")
        .map_err(|source| {
            TzapError::KeyWrap(format!("recipient certificate name failed: {source}"))
        })?;
    let name = name.build();
    let mut builder = X509::builder()
        .map_err(|source| TzapError::KeyWrap(format!("recipient certificate failed: {source}")))?;
    builder
        .set_version(2)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let serial = BigNum::from_u32(1)
        .and_then(|number| number.to_asn1_integer())
        .map_err(|source| {
            TzapError::KeyWrap(format!("recipient certificate serial failed: {source}"))
        })?;
    builder
        .set_serial_number(&serial)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .set_subject_name(&name)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .set_issuer_name(&name)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .set_pubkey(&public_key)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let not_before =
        Asn1Time::days_from_now(0).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let not_after =
        Asn1Time::days_from_now(365).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .map_err(|source| TzapError::KeyWrap(source.to_string()))?,
        )
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_agreement()
                .build()
                .map_err(|source| TzapError::KeyWrap(source.to_string()))?,
        )
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let subject_key_identifier = {
        let context = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(|source| TzapError::KeyWrap(source.to_string()))?
    };
    builder
        .append_extension(subject_key_identifier)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .sign(&issuer_key, MessageDigest::sha256())
        .map_err(|source| {
            TzapError::KeyWrap(format!("recipient certificate signing failed: {source}"))
        })?;
    builder
        .build()
        .to_der()
        .map_err(|source| TzapError::KeyWrap(format!("recipient certificate DER failed: {source}")))
}

fn load_single_x509_certificate_file(
    label: &'static str,
    path: &Path,
) -> Result<Vec<u8>, TzapError> {
    let bytes = read_x509_input_file(path)?;
    let certificates = certificates_der_from_pem_or_der(&bytes).map_err(|source| {
        TzapError::KeyWrap(format!(
            "failed to parse {label} {}: {source}",
            path.display()
        ))
    })?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] => Err(TzapError::KeyWrap(format!(
            "{label} must contain exactly one X.509 certificate"
        ))),
        _ => Err(TzapError::KeyWrap(format!(
            "{label} must contain exactly one X.509 certificate"
        ))),
    }
}

fn recipient_wrap_archive_identity_for_writer(
    options: &mut WriterOptions,
) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity {
        archive_uuid,
        session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV_44,
    }
}

fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn key_wrap_outcome_error(outcome: KeyWrapOutcome) -> TzapError {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => TzapError::Format(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient profile",
        )),
        KeyWrapOutcome::UnsupportedArchiveIdentity => TzapError::Format(
            FormatError::ReaderUnsupported("unsupported keywrap archive identity"),
        ),
        KeyWrapOutcome::UnsupportedRecipientIdentity => TzapError::Format(
            FormatError::ReaderUnsupported("unsupported keywrap recipient identity"),
        ),
        KeyWrapOutcome::UnsupportedSuite => TzapError::Format(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient suite",
        )),
        KeyWrapOutcome::CertificatePolicyRejected => TzapError::Format(
            FormatError::ReaderUnsupported("recipient certificate policy rejected"),
        ),
        KeyWrapOutcome::InvalidRecord => TzapError::Format(FormatError::InvalidArchive(
            "invalid keywrap recipient record",
        )),
        KeyWrapOutcome::NoMatchingPrivateKey => {
            TzapError::KeyWrap("no matching recipient private key for archive".to_owned())
        }
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => TzapError::Format(
            FormatError::WriterInvariant("keywrap success outcome cannot be converted to error"),
        ),
    }
}

#[derive(Debug)]
struct TzapRecipientPrivateKeyLookup {
    private_key_bytes: Vec<u8>,
    private_key_spki_der: Option<Vec<u8>>,
}

impl PrivateKeyLookup for TzapRecipientPrivateKeyLookup {
    fn lookup_private_key(
        &self,
        _archive_identity: &KeyWrapArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(private_key_spki_der) = self.private_key_spki_der.as_ref() {
            let certificate = X509::from_der(recipient_identity_bytes).ok()?;
            let certificate_spki_der = certificate.public_key().ok()?.public_key_to_der().ok()?;
            if certificate_spki_der != *private_key_spki_der {
                return None;
            }
        }
        Some(self.private_key_bytes.clone())
    }
}

fn load_recipient_private_key_lookup(
    path: &Path,
) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    let bytes = fs::read(path).map_err(|source| TzapError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() == 32 {
        return Ok(TzapRecipientPrivateKeyLookup {
            private_key_bytes: bytes,
            private_key_spki_der: None,
        });
    }
    let private_key = if bytes.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem(&bytes)
    } else {
        PKey::private_key_from_der(&bytes)
    }
    .map_err(|source| {
        TzapError::KeyWrap(format!(
            "failed to parse recipient private key {}: {source}",
            path.display()
        ))
    })?;
    let private_key_bytes = private_key.private_key_to_der().map_err(|source| {
        TzapError::KeyWrap(format!(
            "failed to normalize recipient private key {}: {source}",
            path.display()
        ))
    })?;
    let private_key_spki_der = private_key.public_key_to_der().ok();
    Ok(TzapRecipientPrivateKeyLookup {
        private_key_bytes,
        private_key_spki_der,
    })
}

#[derive(Debug, Default)]
struct RecipientWrapOpenStats {
    records_seen: usize,
    no_matching_private_key: usize,
    invalid_record_or_unwrap: usize,
    unsupported_record: usize,
    candidate_count: usize,
}

fn recipient_wrap_candidates_for_record(
    context: RecipientWrapRecordContext<'_>,
    lookup: &TzapRecipientPrivateKeyLookup,
    stats: &mut RecipientWrapOpenStats,
) -> Result<Vec<[u8; 32]>, FormatError> {
    stats.records_seen += 1;
    let input = RecipientRecordInput {
        archive_identity: KeyWrapArchiveIdentity {
            archive_uuid: context.archive_identity.archive_uuid,
            session_id: context.archive_identity.session_id,
            format_version: context.archive_identity.format_version,
            volume_format_rev: context.archive_identity.volume_format_rev,
        },
        metadata: RecipientRecordMetadata {
            profile_id: context.record.profile_id,
            recipient_identity_type: context.record.recipient_identity_type,
            recipient_identity_digest: context.record.recipient_identity_digest,
        },
        recipient_identity_bytes: context.record.recipient_identity_bytes.clone(),
        profile_payload_bytes: context.record.profile_payload_bytes.clone(),
    };
    match dispatch_key_wrap_record(input, lookup) {
        KeyWrapOutcome::UnwrappedCandidateMasterKey { master_key, .. } => {
            stats.candidate_count += 1;
            Ok(vec![master_key])
        }
        KeyWrapOutcome::NoMatchingPrivateKey => {
            stats.no_matching_private_key += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::CertificatePolicyRejected => {
            stats.invalid_record_or_unwrap += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::UnsupportedProfileId
        | KeyWrapOutcome::UnsupportedArchiveIdentity
        | KeyWrapOutcome::UnsupportedRecipientIdentity
        | KeyWrapOutcome::UnsupportedSuite => {
            stats.unsupported_record += 1;
            Ok(Vec::new())
        }
    }
}

fn recipient_wrap_open_error(source: FormatError, stats: &RecipientWrapOpenStats) -> TzapError {
    if !matches!(source, FormatError::KeyMaterialMismatch) {
        return TzapError::Format(source);
    }
    if stats.candidate_count > 0 {
        return TzapError::KeyWrap(format!(
            "{source}: recipient private key unwrapped a candidate, but archive header HMAC did not verify"
        ));
    }
    if stats.records_seen == 0 {
        return TzapError::KeyWrap(format!(
            "{source}: recipient-wrap archive has no recipient records"
        ));
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return TzapError::KeyWrap(format!(
            "{source}: no matching recipient private key for archive"
        ));
    }
    TzapError::KeyWrap(format!(
        "{source}: recipient private key did not match any recipient record or failed recipient unwrap"
    ))
}

fn current_unix_seconds_i64() -> Result<i64, TzapError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| TzapError::X509RootAuth("current Unix time exceeds i64".to_owned()))
}

fn verify_opened_x509_root_auth(
    opened: &OpenedArchive,
    trust: &TzapX509TrustOptions,
) -> Result<TzapX509VerificationReport, TzapError> {
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| {
            match verify_root_auth_footer(
                footer,
                archive_root,
                &trusted_roots_der,
                trust.trusted_system_roots,
            ) {
                Ok(value) => {
                    report = Some(value);
                    Ok(true)
                }
                Err(error) => {
                    x509_error = Some(error.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|source| {
            if let Some(detail) = x509_error {
                TzapError::X509RootAuth(format!("{source}: {detail}"))
            } else {
                TzapError::Format(source)
            }
        })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive(
        "missing X.509 RootAuth verification report",
    )))?;

    Ok(x509_report_from_root_auth_verification(
        &verification,
        report,
    ))
}

fn x509_report_from_root_auth_verification(
    verification: &RootAuthVerification,
    report: X509RootAuthReport,
) -> TzapX509VerificationReport {
    TzapX509VerificationReport {
        archive_root: verification.archive_root,
        authenticator_id: verification.authenticator_id,
        signer_identity_type: verification.signer_identity_type,
        total_data_block_count: verification.total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: report.subject,
        issuer: report.issuer,
        serial_number_hex: report.serial_number_hex,
        certificate_sha256: report.certificate_sha256,
        verified_chain_subjects: report.verified_chain_subjects,
        trust_anchor_subject: report.trust_anchor_subject,
        diagnostics: root_auth_diagnostic_labels(&verification.diagnostics),
    }
}

fn x509_report_from_public_no_key_verification(
    verification: &PublicNoKeyVerification,
    report: X509RootAuthReport,
) -> TzapX509VerificationReport {
    TzapX509VerificationReport {
        archive_root: verification.archive_root,
        authenticator_id: verification.authenticator_id,
        signer_identity_type: verification.signer_identity_type,
        total_data_block_count: verification.total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: report.subject,
        issuer: report.issuer,
        serial_number_hex: report.serial_number_hex,
        certificate_sha256: report.certificate_sha256,
        verified_chain_subjects: report.verified_chain_subjects,
        trust_anchor_subject: report.trust_anchor_subject,
        diagnostics: public_no_key_diagnostic_labels(&verification.diagnostics),
    }
}

fn root_auth_diagnostic_labels(diagnostics: &[RootAuthDiagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label().to_owned())
        .collect()
}

fn public_no_key_diagnostic_labels(diagnostics: &[PublicNoKeyDiagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label().to_owned())
        .collect()
}

/// Lists `.tzap` archive entries with a passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_password(
    archive: impl AsRef<Path>,
    password: &str,
) -> Result<TzapListing, TzapError> {
    list_tzap_with_optional_password(archive, Some(password))
}

/// Lists `.tzap` archive entries with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_optional_password(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<TzapListing, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    list_opened_tzap_archive(opened)
}

/// Lists `.tzap` archive index entries with an optional passphrase.
///
/// This returns only index metadata from encrypted index records and skips full
/// tar member decoding. Entry kinds from the full tar member metadata are not
/// available from this path.
pub(crate) fn list_tzap_index_entries_with_optional_password(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<Vec<ArchiveIndexEntry>, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    opened.list_index_entries().map_err(TzapError::from)
}

/// Lists recipient-wrapped `.tzap` archive entries with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or listed.
pub fn list_tzap_with_recipient_key(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
) -> Result<TzapListing, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    list_opened_tzap_archive(opened)
}

fn list_opened_tzap_archive(opened: OpenedArchive) -> Result<TzapListing, TzapError> {
    let entries = opened
        .list_files()?
        .into_iter()
        .map(tzap_entry_from_archive_entry)
        .collect();
    Ok(TzapListing { entries })
}

/// Extracts `.tzap` entries with a passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: &str,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_with_optional_password(archive, destination, policy, Some(password))
}

/// Extracts `.tzap` entries with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_optional_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(archive, destination, policy, password, None, None, None)
}

/// Extracts recipient-wrapped `.tzap` entries with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_recipient_key(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    recipient_private_key: impl AsRef<Path>,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(
        archive,
        destination,
        policy,
        None,
        Some(recipient_private_key.as_ref()),
        None,
        None,
    )
}

/// Extracts `.tzap` entries with a passphrase, emitting job events.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_optional_password_and_context(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(
        archive,
        destination,
        policy,
        password,
        None,
        None,
        Some(context),
    )
}

/// Extracts `.tzap` regular entries with index metadata and optional extraction
/// context.
///
/// This skips decoding full tar member metadata up front and uses index entries
/// when possible. Directory-only entries are created from index paths that end
/// with `/`. Unsupported or missing entries are skipped with warnings.
pub fn extract_tzap_with_optional_password_and_context_fast(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    context: &mut JobContext<'_>,
) -> Result<TzapExtractReport, TzapError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    let opened = open_tzap_archive(archive, password)?;
    let entries = opened.list_index_entries()?;
    let mut planner = ExtractionSafetyPlanner::new(&destination_root, policy);
    let mut report = TzapExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in entries {
        context.check_cancelled()?;
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: tzap_index_entry_kind(&entry.path),
            uncompressed_size: Some(entry.file_data_size),
            compressed_size: None,
        };
        context.entry_started(&safety_entry.archive_path, Some(entry.file_data_size));

        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                ..
            } => match safety_entry.kind {
                ExtractionEntryKind::File => {
                    match stream_regular_member_to_destination(
                        &opened,
                        &safety_entry.archive_path,
                        entry.file_data_size,
                        &destination_path,
                        replace_existing,
                        Some(context),
                    ) {
                        Ok(Some(processed)) => {
                            report.written_entries = report.written_entries.saturating_add(1);
                            report.written_bytes = report.written_bytes.saturating_add(processed);
                            context.entry_finished(&safety_entry.archive_path, processed);
                        }
                        Ok(None) => {
                            report.skipped_entries = report.skipped_entries.saturating_add(1);
                            let warning =
                                format!("skipped missing entry {}", safety_entry.archive_path);
                            report.warnings.push(warning.clone());
                            context.warning(warning);
                            context.entry_finished(&safety_entry.archive_path, 0);
                        }
                        Err(error) => {
                            if let TzapError::Format(
                                tzap_core::format::FormatError::ReaderUnsupported(_),
                            ) = error
                            {
                                report.skipped_entries = report.skipped_entries.saturating_add(1);
                                let warning = format!(
                                    "skipped unsupported entry {}",
                                    safety_entry.archive_path
                                );
                                report.warnings.push(warning.clone());
                                context.warning(warning);
                                context.entry_finished(&safety_entry.archive_path, 0);
                            } else {
                                return Err(error);
                            }
                        }
                    }
                }
                ExtractionEntryKind::Directory => {
                    fs::create_dir_all(&destination_path).map_err(|source| TzapError::Io {
                        path: destination_path.clone(),
                        source,
                    })?;
                    report.written_entries = report.written_entries.saturating_add(1);
                    context.entry_finished(&safety_entry.archive_path, 0);
                }
                _ => {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    let warning =
                        format!("skipped unsupported entry {}", safety_entry.archive_path);
                    report.warnings.push(warning.clone());
                    context.warning(warning);
                    context.entry_finished(&safety_entry.archive_path, 0);
                }
            },
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                let warning = format!("skipped {}: {}", safety_entry.archive_path, reason);
                report.warnings.push(warning.clone());
                context.warning(warning);
                context.entry_finished(&safety_entry.archive_path, 0);
            }
        }
    }

    Ok(report)
}

fn tzap_index_entry_kind(path: &str) -> ExtractionEntryKind {
    if path.ends_with('/') {
        ExtractionEntryKind::Directory
    } else {
        ExtractionEntryKind::File
    }
}

/// Extracts `.tzap` entries with a passphrase and overwrite resolver.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_overwrite_resolver_and_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: &str,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_with_overwrite_resolver_and_optional_password(
        archive,
        destination,
        policy,
        Some(password),
        overwrite_resolver,
    )
}

/// Extracts `.tzap` entries with an optional passphrase and overwrite resolver.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_overwrite_resolver_and_optional_password(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(
        archive,
        destination,
        policy,
        password,
        None,
        Some(overwrite_resolver),
        None,
    )
}

/// Extracts recipient-wrapped `.tzap` entries with a private key and overwrite resolver.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, an entry is unsafe,
/// or filesystem writes fail.
pub fn extract_tzap_with_overwrite_resolver_and_recipient_key(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    recipient_private_key: impl AsRef<Path>,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<TzapExtractReport, TzapError> {
    extract_tzap_inner(
        archive,
        destination,
        policy,
        None,
        Some(recipient_private_key.as_ref()),
        Some(overwrite_resolver),
        None,
    )
}

/// Tests `.tzap` archive readability and integrity with a filter.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or verified.
pub fn test_tzap_with_password_filter(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(archive, Some(password), selector, None)
}

/// Tests `.tzap` archive readability and integrity with optional X.509 `RootAuth` verification.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(
        archive,
        Some(password),
        selector,
        x509_trust,
    )
}

/// Tests `.tzap` archive readability and integrity with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_optional_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    test_opened_tzap_archive(opened, selector, x509_trust)
}

/// Tests recipient-wrapped `.tzap` readability and integrity with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_recipient_key_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    test_opened_tzap_archive(opened, selector, x509_trust)
}

fn test_opened_tzap_archive(
    opened: OpenedArchive,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    opened.verify()?;
    let x509_root_auth = match x509_trust.filter(|trust| trust.has_trust_source()) {
        Some(trust) if should_verify_opened_x509_root_auth(&opened, trust) => {
            Some(verify_opened_x509_root_auth(&opened, trust)?)
        }
        _ => None,
    };
    let entries = opened.list_files()?;
    let mut tested_entries = 0usize;
    let mut tested_bytes = 0u64;
    for entry in &entries {
        if selector(&entry.path) {
            tested_entries += 1;
            if entry.kind == TarEntryKind::Regular {
                tested_bytes = tested_bytes.saturating_add(entry.file_data_size);
            }
        }
    }
    Ok(TzapTestReport {
        entries: entries.len(),
        tested_entries,
        skipped_entries: entries.len().saturating_sub(tested_entries),
        tested_bytes,
        x509_root_auth,
    })
}

fn should_verify_opened_x509_root_auth(
    opened: &OpenedArchive,
    trust: &TzapX509TrustOptions,
) -> bool {
    let explicit_trust = !trust.trusted_ca_certificates.is_empty() || trust.trusted_system_roots;
    let has_x509_root_auth = opened
        .root_auth_footer
        .as_ref()
        .is_some_and(|footer| footer.authenticator_id == X509_AUTHENTICATOR_ID);
    explicit_trust || has_x509_root_auth
}

/// Verifies a TZAP X.509 `RootAuth` without the archive key.
///
/// This checks the public data-block commitment and X.509 authenticator, but it
/// does not decrypt entries or prove that recovery/parity material is complete.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive volumes cannot be read, the public
/// commitment does not verify, or X.509 trust validation fails.
pub fn verify_tzap_x509_public_no_key(
    archive: impl AsRef<Path>,
    trust: &TzapX509TrustOptions,
) -> Result<TzapX509VerificationReport, TzapError> {
    if !trust.has_trust_source() {
        return Err(TzapError::X509RootAuth(
            "X.509 verification requires trusted roots".to_owned(),
        ));
    }

    let archive_path = archive.as_ref();
    let volume_bytes = read_tzap_input_volume_bytes(archive_path)?;
    let volume_refs = volume_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut x509_error = None;
    let verification = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
        if footer.authenticator_id != X509_AUTHENTICATOR_ID {
            return Err(FormatError::ReaderUnsupported(
                "X.509 trust can only verify X.509 RootAuth",
            ));
        }
        match verify_root_auth_footer(
            footer,
            archive_root,
            &trusted_roots_der,
            trust.trusted_system_roots,
        ) {
            Ok(value) => {
                report = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        }
    })
    .map_err(|source| {
        if let Some(detail) = x509_error {
            TzapError::X509RootAuth(format!("{source}: {detail}"))
        } else {
            TzapError::Format(source)
        }
    })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive(
        "missing X.509 public no-key verification report",
    )))?;

    Ok(x509_report_from_public_no_key_verification(
        &verification,
        report,
    ))
}

/// Inspects a TZAP X.509 `RootAuth` signer without validating trust roots.
///
/// This verifies archive content, RootAuth commitments, and the RootAuth
/// signature made by the embedded leaf certificate. It intentionally does not
/// validate that certificate against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the RootAuth
/// signature does not match the embedded certificate, or the archive is not
/// signed with the X.509 RootAuth profile.
pub fn inspect_tzap_x509_signer(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<TzapX509SignerInspection, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    inspect_opened_x509_signer(&opened)
}

/// Inspects a TZAP X.509 `RootAuth` signer without the archive key or trust roots.
///
/// This checks the public data-block commitment and the RootAuth signature, but
/// does not decrypt entries, prove recovery/parity material is complete, or
/// validate the certificate chain against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when public no-key inspection cannot read the volume
/// set, the RootAuth signature does not match the embedded certificate, or the
/// archive is not signed with the X.509 RootAuth profile.
pub fn inspect_tzap_x509_public_no_key_signer(
    archive: impl AsRef<Path>,
) -> Result<TzapX509SignerInspection, TzapError> {
    let archive_path = archive.as_ref();
    let volume_bytes = read_tzap_input_volume_bytes(archive_path)?;
    let volume_refs = volume_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mut inspection = None;
    let mut x509_error = None;
    let verification = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
        match inspect_x509_root_auth_footer(footer, archive_root) {
            Ok(value) => {
                inspection = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        }
    })
    .map_err(|source| {
        if let Some(detail) = x509_error {
            TzapError::X509RootAuth(format!("{source}: {detail}"))
        } else {
            TzapError::Format(source)
        }
    })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive(
        "missing X.509 public no-key signer inspection report",
    )))?;
    inspection.diagnostics = public_no_key_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

fn inspect_opened_x509_signer(
    opened: &OpenedArchive,
) -> Result<TzapX509SignerInspection, TzapError> {
    let mut inspection = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| {
            match inspect_x509_root_auth_footer(footer, archive_root) {
                Ok(value) => {
                    inspection = Some(value);
                    Ok(true)
                }
                Err(error) => {
                    x509_error = Some(error.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|source| {
            if let Some(detail) = x509_error {
                TzapError::X509RootAuth(format!("{source}: {detail}"))
            } else {
                TzapError::Format(source)
            }
        })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive(
        "missing X.509 signer inspection report",
    )))?;
    inspection.diagnostics = root_auth_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

fn inspect_x509_root_auth_footer(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
) -> Result<TzapX509SignerInspection, TzapError> {
    if footer.authenticator_id != X509_AUTHENTICATOR_ID {
        return Err(TzapError::X509RootAuth(
            "unsupported authenticator id".to_owned(),
        ));
    }
    if footer.signer_identity_type != X509_SIGNER_IDENTITY_TYPE_DER_CERT {
        return Err(TzapError::X509RootAuth(
            "unsupported signer identity type".to_owned(),
        ));
    }

    let leaf_certificate = X509::from_der(&footer.signer_identity_bytes)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let authenticator = parse_x509_authenticator_for_inspection(&footer.authenticator_value)?;
    let signing_input = signing_input(
        &footer.archive_uuid,
        &footer.session_id,
        archive_root,
        authenticator.signed_at_unix_seconds,
        &authenticator.chain_digest,
    );
    let leaf_public_key = leaf_certificate
        .public_key()
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &leaf_public_key)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    verifier
        .update(&signing_input)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    if !verifier
        .verify(&authenticator.signature)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?
    {
        return Err(TzapError::X509RootAuth(
            "X.509 RootAuth signature failed".to_owned(),
        ));
    }

    let fingerprint = leaf_certificate
        .digest(MessageDigest::sha256())
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let mut certificate_sha256 = [0u8; 32];
    certificate_sha256.copy_from_slice(&fingerprint);
    Ok(TzapX509SignerInspection {
        archive_root: *archive_root,
        authenticator_id: footer.authenticator_id,
        signer_identity_type: footer.signer_identity_type,
        total_data_block_count: footer.total_data_block_count,
        signed_at_unix_seconds: authenticator.signed_at_unix_seconds,
        subject: x509_name_to_string(leaf_certificate.subject_name()),
        issuer: x509_name_to_string(leaf_certificate.issuer_name()),
        serial_number_hex: leaf_certificate
            .serial_number()
            .to_bn()
            .and_then(|serial| serial.to_hex_str())
            .map_err(|source| TzapError::X509RootAuth(source.to_string()))?
            .to_string(),
        certificate_sha256,
        diagnostics: Vec::new(),
    })
}

struct X509AuthenticatorInspection {
    signed_at_unix_seconds: i64,
    chain_digest: [u8; 32],
    signature: Vec<u8>,
}

fn parse_x509_authenticator_for_inspection(
    value: &[u8],
) -> Result<X509AuthenticatorInspection, TzapError> {
    if value.len() < X509_ROOT_AUTH_FIXED_AUTHENTICATOR_LEN {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator is too short".to_owned(),
        ));
    }
    if &value[0..4] != X509_ROOT_AUTH_MAGIC {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator magic mismatch".to_owned(),
        ));
    }
    if read_x509_u16(value, 4)? != X509_ROOT_AUTH_VERSION {
        return Err(TzapError::X509RootAuth(
            "unsupported X.509 authenticator version".to_owned(),
        ));
    }
    if read_x509_u16(value, 6)? != X509_ROOT_AUTH_OPENSSL_SHA256_SCHEME {
        return Err(TzapError::X509RootAuth(
            "unsupported X.509 signature scheme".to_owned(),
        ));
    }

    let signed_at_unix_seconds = read_x509_i64(value, 8)?;
    let mut chain_digest = [0u8; 32];
    chain_digest.copy_from_slice(&value[16..48]);
    let signature_len = usize::try_from(read_x509_u32(value, 48)?)
        .map_err(|_| TzapError::X509RootAuth("X.509 signature length overflow".to_owned()))?;
    let signature_capacity = usize::try_from(read_x509_u32(value, 52)?)
        .map_err(|_| TzapError::X509RootAuth("X.509 signature capacity overflow".to_owned()))?;
    let chain_count = usize::try_from(read_x509_u32(value, 56)?)
        .map_err(|_| TzapError::X509RootAuth("X.509 chain count overflow".to_owned()))?;
    if signature_len > signature_capacity {
        return Err(TzapError::X509RootAuth(
            "X.509 signature length exceeds capacity".to_owned(),
        ));
    }

    let mut offset = X509_ROOT_AUTH_FIXED_AUTHENTICATOR_LEN
        .checked_add(signature_capacity)
        .ok_or_else(|| TzapError::X509RootAuth("X.509 authenticator length overflow".to_owned()))?;
    if value.len() < offset {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator signature is truncated".to_owned(),
        ));
    }
    if chain_count > value.len().saturating_sub(offset) / 4 {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator chain count exceeds payload".to_owned(),
        ));
    }

    let signature_start = X509_ROOT_AUTH_FIXED_AUTHENTICATOR_LEN;
    let signature_end = signature_start
        .checked_add(signature_len)
        .ok_or_else(|| TzapError::X509RootAuth("X.509 authenticator length overflow".to_owned()))?;
    if value[signature_end..offset].iter().any(|byte| *byte != 0) {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator signature padding is non-zero".to_owned(),
        ));
    }
    let signature = value[signature_start..signature_end].to_vec();

    for _ in 0..chain_count {
        let cert_len = usize::try_from(read_x509_u32(value, offset)?).map_err(|_| {
            TzapError::X509RootAuth("X.509 chain certificate length overflow".to_owned())
        })?;
        offset = offset.checked_add(4).ok_or_else(|| {
            TzapError::X509RootAuth("X.509 authenticator length overflow".to_owned())
        })?;
        let cert_end = offset.checked_add(cert_len).ok_or_else(|| {
            TzapError::X509RootAuth("X.509 authenticator length overflow".to_owned())
        })?;
        if cert_end > value.len() {
            return Err(TzapError::X509RootAuth(
                "X.509 authenticator certificate chain is truncated".to_owned(),
            ));
        }
        offset = cert_end;
    }
    if offset != value.len() {
        return Err(TzapError::X509RootAuth(
            "X.509 authenticator has trailing bytes".to_owned(),
        ));
    }

    Ok(X509AuthenticatorInspection {
        signed_at_unix_seconds,
        chain_digest,
        signature,
    })
}

fn read_x509_u16(value: &[u8], offset: usize) -> Result<u16, TzapError> {
    let bytes = value
        .get(offset..offset + 2)
        .ok_or_else(|| TzapError::X509RootAuth("X.509 authenticator is truncated".to_owned()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_x509_u32(value: &[u8], offset: usize) -> Result<u32, TzapError> {
    let bytes = value
        .get(offset..offset + 4)
        .ok_or_else(|| TzapError::X509RootAuth("X.509 authenticator is truncated".to_owned()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_x509_i64(value: &[u8], offset: usize) -> Result<i64, TzapError> {
    let bytes = value
        .get(offset..offset + 8)
        .ok_or_else(|| TzapError::X509RootAuth("X.509 authenticator is truncated".to_owned()))?;
    Ok(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_tzap_input_volume_bytes(archive_path: &Path) -> Result<Vec<Vec<u8>>, TzapError> {
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let mut volume_bytes = Vec::with_capacity(volume_paths.len());
    for path in &volume_paths {
        volume_bytes.push(fs::read(path).map_err(|source| TzapError::Io {
            path: path.clone(),
            source,
        })?);
    }
    Ok(volume_bytes)
}

/// Reads public `.tzap` metadata without decrypting archive contents.
///
/// This is intentionally limited to header and volume-level details suitable
/// for Finder/Quick Look surfaces where no password is available.
///
/// # Errors
///
/// Returns an error when no TZAP volume can be found, the public headers are
/// malformed, sibling volumes do not belong to the same archive, or filesystem
/// metadata cannot be read.
pub fn summarize_tzap_public_metadata(
    archive_path: impl AsRef<Path>,
) -> Result<TzapPublicMetadataSummary, TzapError> {
    let requested_path = archive_path.as_ref();
    let discovered_volume_paths = discover_tzap_input_volume_paths(requested_path);
    let first_volume_path = discovered_volume_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| {
            io_error(
                requested_path,
                io::ErrorKind::NotFound,
                "no TZAP input volumes found",
            )
        })?;
    let first_header = read_public_tzap_header(first_volume_path)?;
    let expected_volume_count =
        usize::try_from(first_header.volume_header.stripe_width).map_err(|_| {
            TzapError::Format(FormatError::InvalidArchive("TZAP volume count overflow"))
        })?;
    let expected_paths =
        expected_tzap_input_volume_paths(requested_path, first_volume_path, expected_volume_count);

    let mut volumes = Vec::new();
    let mut missing_volume_indices = Vec::new();
    let mut total_size = 0u64;

    for (expected_index, volume_path) in expected_paths.iter().enumerate() {
        if !volume_path.exists() {
            missing_volume_indices.push(expected_index);
            continue;
        }

        let metadata = fs::metadata(volume_path).map_err(|source| TzapError::Io {
            path: volume_path.clone(),
            source,
        })?;
        let header = read_public_tzap_header(volume_path)?;
        validate_public_tzap_volume_header(&first_header.volume_header, &header.volume_header)?;

        let index = usize::try_from(header.volume_header.volume_index).map_err(|_| {
            TzapError::Format(FormatError::InvalidArchive("TZAP volume index overflow"))
        })?;
        if index != expected_index {
            return Err(TzapError::Format(FormatError::InvalidArchive(
                "TZAP volume index does not match expected path",
            )));
        }
        total_size = total_size
            .checked_add(metadata.len())
            .ok_or(TzapError::Format(FormatError::InvalidArchive(
                "TZAP volume size overflow",
            )))?;
        volumes.push(TzapPublicVolumeSummary {
            path: volume_path.clone(),
            index,
            size: metadata.len(),
        });
    }

    volumes.sort_by_key(|volume| volume.index);

    Ok(TzapPublicMetadataSummary {
        requested_path: requested_path.to_path_buf(),
        expected_volume_count,
        present_volume_count: volumes.len(),
        missing_volume_indices,
        total_size,
        expected_volume_size: first_header.crypto_header.expected_volume_size,
        volumes,
        format: TzapPublicFormatSummary::from_headers(
            &first_header.volume_header,
            &first_header.crypto_header,
        ),
    })
}

/// Copies selected regular `.tzap` members to a writer.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or selected members
/// cannot be extracted.
pub fn copy_tzap_files_to_writer(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    copy_tzap_files_to_writer_with_optional_password(archive, Some(password), selector, writer)
}

/// Copies selected regular `.tzap` members to a writer with an optional passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or selected members
/// cannot be extracted.
pub fn copy_tzap_files_to_writer_with_optional_password(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    copy_opened_tzap_files_to_writer(&opened, selector, writer)
}

/// Copies selected regular recipient-wrapped `.tzap` members to a writer.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or selected members
/// cannot be extracted.
pub fn copy_tzap_files_to_writer_with_recipient_key(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    copy_opened_tzap_files_to_writer(&opened, selector, writer)
}

fn copy_opened_tzap_files_to_writer(
    opened: &OpenedArchive,
    selector: impl Fn(&str) -> bool,
    writer: &mut dyn io::Write,
) -> Result<TzapExtractReport, TzapError> {
    let entries = opened.list_index_entries()?;
    let mut report = TzapExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    for entry in entries {
        if !selector(&entry.path) {
            report.skipped_entries += 1;
            continue;
        }
        let mut writer_ref = &mut *writer;
        let Some(_diagnostics) = opened
            .extract_file_to_writer(&entry.path, &mut writer_ref)
            .map_err(|source| tzap_extract_error(&entry.path, source))?
        else {
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped missing entry {}", entry.path));
            continue;
        };
        report.written_entries += 1;
        report.written_bytes += entry.file_data_size;
    }
    Ok(report)
}

fn tzap_extract_error(path: &str, source: ExtractError) -> TzapError {
    match source {
        ExtractError::Format(source) => TzapError::Format(source),
        ExtractError::Output(source) => TzapError::Io {
            path: PathBuf::from(path),
            source,
        },
    }
}

/// Extracts one regular `.tzap` file member to an exact destination path.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the member cannot be
/// extracted by tzap-core, or the destination cannot be committed.
pub fn extract_tzap_file_to_destination(
    archive: impl AsRef<Path>,
    password: &str,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<Option<u64>, TzapError> {
    extract_tzap_file_to_destination_with_optional_password(
        archive,
        Some(password),
        entry_path,
        destination_path,
        replace_existing,
    )
}

/// Extracts one regular `.tzap` file member to an exact destination path with
/// an optional passphrase.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the member cannot be
/// extracted by tzap-core, or the destination cannot be committed.
pub fn extract_tzap_file_to_destination_with_optional_password(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<Option<u64>, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    extract_tzap_file_from_opened_archive(&opened, entry_path, destination_path, replace_existing)
}

/// Extracts one regular recipient-wrapped `.tzap` member to an exact destination path.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the member cannot be
/// extracted by tzap-core, or the destination cannot be committed.
pub fn extract_tzap_file_to_destination_with_recipient_key(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<Option<u64>, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    extract_tzap_file_from_opened_archive(&opened, entry_path, destination_path, replace_existing)
}

fn extract_tzap_file_from_opened_archive(
    opened: &OpenedArchive,
    entry_path: &str,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<Option<u64>, TzapError> {
    let Some(index_entry) = opened.lookup_index_entry(entry_path)? else {
        return Ok(None);
    };
    let temp_root = TemporaryTzapExtractionRoot::new(destination_path)?;
    let Some(_diagnostics) = opened.extract_file_to(
        entry_path,
        temp_root.path(),
        SafeExtractionOptions {
            overwrite_existing: false,
        },
    )?
    else {
        return Ok(None);
    };
    let extracted_path = archive_member_path_under_root(temp_root.path(), entry_path)?;
    commit_extracted_file(&extracted_path, destination_path, replace_existing)?;
    Ok(Some(index_entry.file_data_size))
}

fn collect_regular_file_sources(
    manifest: &ArchiveManifest,
    options: &TzapCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(Vec<TzapRegularFileSource>, Vec<String>), TzapError> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    for entry in &manifest.entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
            context.entry_started(&entry.archive_path, Some(entry.size));
        }

        match entry.file_type {
            ManifestFileType::File => {
                files.push(TzapRegularFileSource {
                    archive_path: entry.archive_path.clone(),
                    source_path: entry.source_path.clone(),
                    size: entry.size,
                    mode: if options.preserve_metadata {
                        entry.permissions.unix_mode.unwrap_or(0o644) & 0o7777
                    } else {
                        0o644
                    },
                    mtime: if options.preserve_metadata {
                        entry
                            .modified
                            .and_then(system_time_to_unix_seconds)
                            .unwrap_or(0)
                    } else {
                        0
                    },
                });
            }
            ManifestFileType::Directory => {
                if let Some(context) = context.as_deref_mut() {
                    context.entry_finished(&entry.archive_path, 0);
                }
            }
            ManifestFileType::Symlink | ManifestFileType::Other => {
                let warning = format!(
                    "skipped {}: tzap backend currently writes regular files only",
                    entry.archive_path
                );
                warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.archive_path, 0);
                }
            }
        }
    }

    Ok((files, warnings))
}

fn extract_tzap_inner(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    password: Option<&str>,
    recipient_private_key: Option<&Path>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TzapExtractReport, TzapError> {
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| TzapError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
    let opened = open_tzap_archive_with_key_options(archive, password, recipient_private_key)?;
    let entries = opened.list_files()?;
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(
            &destination_root,
            policy,
            resolver,
        ),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = TzapExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };

    for entry in entries {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let preloaded_member =
            if matches!(entry.kind, TarEntryKind::Symlink | TarEntryKind::Hardlink) {
                opened.extract_member(&entry.path)?
            } else {
                None
            };
        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: extraction_kind_from_tzap_entry(&entry, preloaded_member.as_ref()),
            uncompressed_size: Some(entry.file_data_size),
            compressed_size: None,
        };
        if let Some(context) = context.as_deref_mut() {
            context.entry_started(&entry.path, Some(entry.file_data_size));
        }
        match planner.validate_entry(&safety_entry)? {
            ExtractionDecision::Write {
                destination_path,
                replace_existing,
                link_target_path,
                ..
            } => {
                if matches!(&safety_entry.kind, ExtractionEntryKind::File) {
                    let Some(processed) = stream_regular_member_to_destination(
                        &opened,
                        &entry.path,
                        entry.file_data_size,
                        &destination_path,
                        replace_existing,
                        context.as_deref_mut(),
                    )?
                    else {
                        report.skipped_entries += 1;
                        report
                            .warnings
                            .push(format!("skipped missing entry {}", entry.path));
                        if let Some(context) = context.as_deref_mut() {
                            context.warning(format!("skipped missing entry {}", entry.path));
                            context.entry_finished(&entry.path, 0);
                        }
                        continue;
                    };
                    report.written_entries += 1;
                    report.written_bytes += processed;
                    if let Some(context) = context.as_deref_mut() {
                        context.entry_finished(&entry.path, processed);
                    }
                    continue;
                }

                let member = match preloaded_member {
                    Some(member) => Some(member),
                    None => opened.extract_member(&entry.path)?,
                };
                let Some(member) = member else {
                    report.skipped_entries += 1;
                    report
                        .warnings
                        .push(format!("skipped missing entry {}", entry.path));
                    if let Some(context) = context.as_deref_mut() {
                        context.warning(format!("skipped missing entry {}", entry.path));
                        context.entry_finished(&entry.path, 0);
                    }
                    continue;
                };
                let processed = materialize_non_regular_member(
                    &member,
                    &destination_path,
                    replace_existing,
                    link_target_path.as_deref(),
                    &mut report,
                )?;
                if let Some(context) = context.as_deref_mut() {
                    context.bytes_processed(Some(&entry.path), processed);
                    context.entry_finished(&entry.path, processed);
                }
            }
            ExtractionDecision::Skip { reason, .. } => {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped {}: {reason}", entry.path));
                if let Some(context) = context.as_deref_mut() {
                    context.warning(format!("skipped {}: {reason}", entry.path));
                    context.entry_finished(&entry.path, 0);
                }
            }
        }
    }

    Ok(report)
}

fn stream_regular_member_to_destination(
    opened: &OpenedArchive,
    entry_path: &str,
    entry_size: u64,
    destination_path: &Path,
    replace_existing: bool,
    context: Option<&mut JobContext<'_>>,
) -> Result<Option<u64>, TzapError> {
    let mut output =
        AtomicOutputFile::create(destination_path).map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    let output_file = output.file_mut().map_err(|source| TzapError::Io {
        path: destination_path.to_path_buf(),
        source,
    })?;
    let extracted = match context {
        Some(context) => {
            let mut progress = |archive_path: &str, bytes: u64| {
                context.bytes_processed(Some(archive_path), bytes);
            };
            opened.extract_file_to_writer_with_progress(entry_path, output_file, &mut progress)
        }
        None => opened.extract_file_to_writer(entry_path, output_file),
    }
    .map_err(|source| tzap_extract_error(entry_path, source))?;

    let Some(_diagnostics) = extracted else {
        return Ok(None);
    };

    output
        .commit_with_replace(replace_existing)
        .map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    Ok(Some(entry_size))
}

fn materialize_non_regular_member(
    member: &ExtractedArchiveMember,
    destination_path: &Path,
    replace_existing: bool,
    link_target_path: Option<&Path>,
    report: &mut TzapExtractReport,
) -> Result<u64, TzapError> {
    if replace_existing && member.kind != TarEntryKind::Regular {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    match member.kind {
        TarEntryKind::Regular => {
            return Err(TzapError::Format(FormatError::InvalidArchive(
                "regular TZAP member reached non-regular materializer",
            )));
        }
        TarEntryKind::Directory => {
            fs::create_dir_all(destination_path).map_err(|source| TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            })?;
            report.written_entries += 1;
            return Ok(0);
        }
        TarEntryKind::Symlink => {
            if crate::safety::should_skip_symlink_materialization(&ExtractionEntryKind::Symlink {
                target: member
                    .link_target
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_default(),
            }) {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(crate::safety::unsupported_symlink_warning(&member.path));
            } else if let Some(target) = &member.link_target {
                write_symlink(Path::new(target), destination_path)?;
                report.written_entries += 1;
            } else {
                report.skipped_entries += 1;
                report
                    .warnings
                    .push(format!("skipped symlink {}: missing target", member.path));
            }
        }
        TarEntryKind::Hardlink => {
            let source_path = link_target_path.ok_or_else(|| TzapError::Io {
                path: destination_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hardlink target was not resolved by extraction safety planning",
                ),
            })?;
            write_hardlink(source_path, destination_path)?;
            report.written_entries += 1;
            return Ok(0);
        }
    }
    Ok(0)
}

fn open_tzap_archive(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<OpenedArchive, TzapError> {
    open_tzap_archive_with_key_options(archive, password, None)
}

fn open_tzap_archive_with_recipient_key(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
) -> Result<OpenedArchive, TzapError> {
    open_tzap_archive_with_key_options(archive, None, Some(recipient_private_key.as_ref()))
}

fn open_tzap_archive_with_key_options(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    recipient_private_key: Option<&Path>,
) -> Result<OpenedArchive, TzapError> {
    let archive_path = archive.as_ref();
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume = volume_paths.first().ok_or_else(|| {
        io_error(
            archive_path,
            io::ErrorKind::NotFound,
            "no TZAP input volumes found",
        )
    })?;
    let kdf_params = read_kdf_params_from_path(first_volume)?;
    let volume_files = volume_paths
        .iter()
        .map(|path| {
            File::open(path).map_err(|source| TzapError::Io {
                path: path.clone(),
                source,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if matches!(kdf_params, KdfParams::RecipientWrap { .. }) {
        if password.is_some() {
            return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
        }
        let Some(recipient_private_key) = recipient_private_key else {
            return Err(TzapError::RecipientKeyRequired);
        };
        let lookup = load_recipient_private_key_lookup(recipient_private_key)?;
        let mut stats = RecipientWrapOpenStats::default();
        return open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
            volume_files,
            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
            ReaderOptions::default(),
        )
        .map_err(|source| recipient_wrap_open_error(source, &stats));
    }
    if recipient_private_key.is_some() {
        return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
    }
    let master_key = match (&kdf_params, password) {
        (KdfParams::None, _) | (KdfParams::Raw, None | Some("")) => placeholder_master_key()?,
        (KdfParams::Argon2id { .. }, Some(password)) => {
            MasterKey::derive_from_passphrase(&kdf_params, password)?
        }
        (KdfParams::Argon2id { .. }, None) => return Err(TzapError::PasswordRequired),
        (KdfParams::Raw, Some(_)) => {
            return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
        }
        (KdfParams::RecipientWrap { .. }, _) => unreachable!("recipient wrap handled above"),
    };
    if volume_files.len() == 1 {
        let volume_file = volume_files
            .into_iter()
            .next()
            .ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        return open_seekable_archive(volume_file, &master_key).map_err(Into::into);
    }

    open_seekable_archive_volumes(volume_files, &master_key).map_err(Into::into)
}

pub(crate) fn discover_tzap_input_volume_paths(archive_path: &Path) -> Vec<PathBuf> {
    if let Some(volume_paths) = discover_tzap_sibling_volume_paths(archive_path)
        && !volume_paths.is_empty()
    {
        return volume_paths;
    }

    if archive_path.exists() {
        return vec![archive_path.to_path_buf()];
    }

    let volume_paths = discover_tzap_volume_paths_for_destination(archive_path);
    if !volume_paths.is_empty() {
        return volume_paths;
    }

    vec![archive_path.to_path_buf()]
}

fn tzap_destination_path_from_volume_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    let pattern = parse_tzap_volume_file_name(file_name)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Some(parent.join(format!("{}{TZAP_EXTENSION_SUFFIX}", pattern.base)))
}

fn discover_tzap_sibling_volume_paths(path: &Path) -> Option<Vec<PathBuf>> {
    let file_name = path.file_name()?.to_str()?;
    let pattern = parse_tzap_volume_file_name(file_name)?;
    Some(discover_tzap_volume_paths_by_base(
        path.parent().unwrap_or_else(|| Path::new(".")),
        &pattern.base,
    ))
}

fn discover_tzap_volume_paths_for_destination(destination: &Path) -> Vec<PathBuf> {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let base_name = tzap_multi_volume_base_name(file_name);
    discover_tzap_volume_paths_by_base(
        destination.parent().unwrap_or_else(|| Path::new(".")),
        &base_name,
    )
}

fn discover_tzap_volume_paths_by_base(parent: &Path, base_name: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if let Some(candidate) = parse_tzap_volume_file_name(file_name)
            && candidate.base == base_name
        {
            paths.push((candidate.volume_index, entry.path()));
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    paths.into_iter().map(|(_, path)| path).collect()
}

#[derive(Debug, Clone)]
struct PublicTzapHeader {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
}

fn expected_tzap_input_volume_paths(
    requested_path: &Path,
    first_volume_path: &Path,
    expected_volume_count: usize,
) -> Vec<PathBuf> {
    if expected_volume_count <= 1 {
        return vec![first_volume_path.to_path_buf()];
    }

    let base_path = tzap_destination_path_from_volume_path(first_volume_path)
        .or_else(|| tzap_destination_path_from_volume_path(requested_path))
        .unwrap_or_else(|| {
            if first_volume_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case(TZAP_EXTENSION))
            {
                first_volume_path.to_path_buf()
            } else {
                requested_path.to_path_buf()
            }
        });

    (0..expected_volume_count)
        .map(|index| tzap_output_volume_path(&base_path, index))
        .collect()
}

fn read_public_tzap_header(path: &Path) -> Result<PublicTzapHeader, TzapError> {
    let (volume_header, crypto_header_bytes) = read_tzap_crypto_header_bytes(path)?;
    let fixed_bytes =
        crypto_header_bytes
            .get(..CRYPTO_HEADER_FIXED_LEN)
            .ok_or(FormatError::InvalidLength {
                structure: "CryptoHeaderFixed",
                expected: CRYPTO_HEADER_FIXED_LEN,
                actual: crypto_header_bytes.len(),
            })?;
    let crypto_header = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        )));
    }

    Ok(PublicTzapHeader {
        volume_header,
        crypto_header,
    })
}

fn read_tzap_crypto_header_bytes(path: &Path) -> Result<(VolumeHeader, Vec<u8>), TzapError> {
    let mut file = File::open(path).map_err(|source| TzapError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut header_bytes = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes)
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = u64::from(volume_header.crypto_header_offset);
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes)
        .map_err(|source| TzapError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok((volume_header, crypto_header_bytes))
}

fn validate_public_tzap_volume_header(
    first: &VolumeHeader,
    current: &VolumeHeader,
) -> Result<(), TzapError> {
    if first.archive_uuid != current.archive_uuid {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "TZAP volume archive UUID mismatch",
        )));
    }
    if first.session_id != current.session_id {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "TZAP volume session ID mismatch",
        )));
    }
    if first.stripe_width != current.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "TZAP volume count mismatch",
        )));
    }
    if first.format_version != current.format_version
        || first.volume_format_rev != current.volume_format_rev
    {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "TZAP volume format mismatch",
        )));
    }

    Ok(())
}

fn read_kdf_params_from_path(path: &Path) -> Result<KdfParams, TzapError> {
    let (volume_header, crypto_header_bytes) = read_tzap_crypto_header_bytes(path)?;
    let fixed_bytes =
        crypto_header_bytes
            .get(..CRYPTO_HEADER_FIXED_LEN)
            .ok_or(FormatError::InvalidLength {
                structure: "CryptoHeaderFixed",
                expected: CRYPTO_HEADER_FIXED_LEN,
                actual: crypto_header_bytes.len(),
            })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        )));
    }
    let crypto_header =
        CryptoHeader::parse(&crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(crypto_header.kdf_params)
}

const fn compression_algorithm_label(algorithm: CompressionAlgo) -> &'static str {
    match algorithm {
        CompressionAlgo::None => "none",
        CompressionAlgo::ZstdFramed => "zstd",
    }
}

const fn aead_algorithm_label(algorithm: AeadAlgo) -> &'static str {
    match algorithm {
        AeadAlgo::None => "none",
        AeadAlgo::AesGcmSiv256 => "aes-gcm-siv-256",
        AeadAlgo::XChaCha20Poly1305 => "xchacha20-poly1305",
        AeadAlgo::AesGcm256 => "aes-gcm-256",
    }
}

const fn fec_algorithm_label(algorithm: FecAlgo) -> &'static str {
    match algorithm {
        FecAlgo::None => "none",
        FecAlgo::ReedSolomonGF16 => "reed-solomon-gf16",
        FecAlgo::Wirehair => "wirehair",
    }
}

const fn kdf_algorithm_label(algorithm: KdfAlgo) -> &'static str {
    match algorithm {
        KdfAlgo::None => "none",
        KdfAlgo::Raw => "raw",
        KdfAlgo::Argon2id => "argon2id",
        KdfAlgo::RecipientWrap => "recipient-wrap",
    }
}

fn commit_extracted_file(
    source_path: &Path,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<(), TzapError> {
    if let Some(parent) = destination_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if replace_existing {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            TzapError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
        fs::rename(source_path, destination_path).map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    } else {
        fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn archive_member_path_under_root(root: &Path, entry_path: &str) -> Result<PathBuf, TzapError> {
    let mut path = root.to_path_buf();
    for component in entry_path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(TzapError::Format(FormatError::UnsafeArchivePath));
        }
        path.push(component);
    }
    Ok(path)
}

struct TemporaryTzapExtractionRoot {
    path: PathBuf,
}

impl TemporaryTzapExtractionRoot {
    fn new(destination_path: &Path) -> Result<Self, TzapError> {
        let parent = destination_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| TzapError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let destination_name = destination_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("entry");

        for attempt in 0..TZAP_TEMP_EXTRACT_ATTEMPTS {
            let path = parent.join(format!(
                "{TZAP_TEMP_EXTRACT_PREFIX}-{destination_name}-{}-{now}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(TzapError::Io { path, source });
                }
            }
        }

        Err(io_error(
            parent,
            io::ErrorKind::AlreadyExists,
            "could not allocate temporary TZAP extraction root",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryTzapExtractionRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_kdf_params() -> KdfParams {
    let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    KdfParams::Argon2id {
        t_cost: DEFAULT_ARGON2_T_COST.min(READER_MAX_ARGON2ID_T_COST),
        m_cost_kib: DEFAULT_ARGON2_M_COST_KIB.min(READER_MAX_ARGON2ID_M_COST_KIB),
        parallelism: DEFAULT_ARGON2_PARALLELISM.min(READER_MAX_ARGON2ID_PARALLELISM),
        salt,
    }
}

fn create_key_material(key_source: &TzapKeySource) -> Result<(MasterKey, KdfParams), TzapError> {
    match key_source {
        TzapKeySource::Passphrase(passphrase) => {
            let kdf_params = create_kdf_params();
            let master_key =
                MasterKey::derive_from_passphrase(&kdf_params, passphrase.expose_secret())?;
            Ok((master_key, kdf_params))
        }
        TzapKeySource::RecipientCertificate(_)
        | TzapKeySource::RecipientCertificates(_)
        | TzapKeySource::RecipientPublicKeys(_) => {
            Ok((generate_random_master_key()?, KdfParams::None))
        }
        TzapKeySource::NoPassword => Ok((placeholder_master_key()?, KdfParams::None)),
    }
}

fn generate_random_master_key() -> Result<MasterKey, TzapError> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    MasterKey::from_raw_key(&bytes).map_err(Into::into)
}

fn placeholder_master_key() -> Result<MasterKey, TzapError> {
    MasterKey::from_raw_key(&TZAP_PLACEHOLDER_MASTER_KEY).map_err(Into::into)
}

fn extraction_kind_from_tzap_entry(
    entry: &ArchiveEntry,
    member: Option<&ExtractedArchiveMember>,
) -> ExtractionEntryKind {
    match entry.kind {
        TarEntryKind::Regular => ExtractionEntryKind::File,
        TarEntryKind::Directory => ExtractionEntryKind::Directory,
        TarEntryKind::Symlink => ExtractionEntryKind::Symlink {
            target: member
                .and_then(|member| member.link_target.as_deref())
                .map(PathBuf::from)
                .unwrap_or_default(),
        },
        TarEntryKind::Hardlink => ExtractionEntryKind::Hardlink {
            target: member
                .and_then(|member| member.link_target.as_deref())
                .map(PathBuf::from)
                .unwrap_or_default(),
        },
    }
}

fn tzap_entry_from_archive_entry(entry: ArchiveEntry) -> TzapEntry {
    TzapEntry {
        path: entry.path,
        kind: tzap_entry_kind_from_member_kind(entry.kind),
        size: entry.file_data_size,
        mode: entry.mode,
        mtime: entry.mtime,
    }
}

fn tzap_entry_kind_from_member_kind(kind: TarEntryKind) -> TzapEntryKind {
    match kind {
        TarEntryKind::Regular => TzapEntryKind::File,
        TarEntryKind::Directory => TzapEntryKind::Directory,
        TarEntryKind::Symlink => TzapEntryKind::Symlink,
        TarEntryKind::Hardlink => TzapEntryKind::Hardlink,
    }
}

#[derive(Debug)]
struct TzapRegularFileSource {
    archive_path: String,
    source_path: PathBuf,
    size: u64,
    mode: u32,
    mtime: u64,
}

impl RegularFileSource for TzapRegularFileSource {
    fn archive_path(&self) -> &str {
        &self.archive_path
    }

    fn file_data_size(&self) -> u64 {
        self.size
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> u64 {
        self.mtime
    }

    fn open(&self) -> Result<Box<dyn io::Read + '_>, ArchiveWriteError> {
        let file = File::open(&self.source_path).map_err(|source| {
            ArchiveWriteError::Io(io::Error::new(
                source.kind(),
                format!(
                    "failed to open TZAP source file {}: {source}",
                    self.source_path.display()
                ),
            ))
        })?;
        Ok(Box::new(file))
    }
}

struct TzapWriteJobProgress<'context, 'job, 'state> {
    context: &'context mut JobContext<'job>,
    total_source_bytes: u64,
    file_sizes: &'state BTreeMap<String, u64>,
    started_paths: &'state mut BTreeSet<String>,
    finished_paths: &'state mut BTreeSet<String>,
    processed_by_path: &'state mut BTreeMap<String, u64>,
    active_phase: Option<JobPhase>,
    phase_progress: ProgressCoalescer,
}

impl TzapWriteJobProgress<'_, '_, '_> {
    fn flush_pending(&mut self) {
        if let (Some(phase), Some(batch)) = (self.active_phase, self.phase_progress.flush()) {
            self.emit_phase_batch(phase, batch);
        }
    }

    fn emit_phase_batch(&mut self, phase: JobPhase, batch: ProgressBatch) {
        self.context.phase_bytes_processed_with_recent_paths(
            phase,
            batch.path.as_deref(),
            batch.recent_paths,
            batch.bytes,
            phase_total_bytes(phase, self.total_source_bytes),
        );
    }
}

impl ArchiveWriteProgressSink for TzapWriteJobProgress<'_, '_, '_> {
    fn phase_started(&mut self, phase: ArchiveWritePhase) {
        self.flush_pending();
        let phase = job_phase_from_tzap(phase);
        let total_bytes = phase_total_bytes(phase, self.total_source_bytes);
        self.active_phase = Some(phase);
        self.phase_progress.reset(total_bytes);
        self.context.phase_started(phase, total_bytes);
    }

    fn source_bytes_read(&mut self, phase: ArchiveWritePhase, archive_path: &str, bytes: u64) {
        let phase = job_phase_from_tzap(phase);
        debug_assert_eq!(self.active_phase, Some(phase));

        if phase == JobPhase::EmittingPayload {
            if !self.started_paths.contains(archive_path) {
                self.started_paths.insert(archive_path.to_owned());
                self.context
                    .entry_started(archive_path, self.file_sizes.get(archive_path).copied());
            }
        }

        if let Some(batch) = self.phase_progress.record(Some(archive_path), bytes) {
            self.emit_phase_batch(phase, batch);
        }

        if phase == JobPhase::EmittingPayload {
            self.context.bytes_processed(Some(archive_path), bytes);
            let processed = if let Some(processed) = self.processed_by_path.get_mut(archive_path) {
                processed
            } else {
                self.processed_by_path.insert(archive_path.to_owned(), 0);
                self.processed_by_path
                    .get_mut(archive_path)
                    .expect("inserted TZAP progress path must exist")
            };
            *processed = processed.saturating_add(bytes);
            if let Some(size) = self.file_sizes.get(archive_path).copied() {
                if *processed >= size && !self.finished_paths.contains(archive_path) {
                    self.finished_paths.insert(archive_path.to_owned());
                    self.context.entry_finished(archive_path, size);
                }
            }
        }
    }
}

const fn phase_total_bytes(phase: JobPhase, total_source_bytes: u64) -> Option<u64> {
    match phase {
        JobPhase::PlanningPayload | JobPhase::EmittingPayload => Some(total_source_bytes),
        JobPhase::PlanningMetadata | JobPhase::EmittingMetadata | JobPhase::CommittingOutput => {
            None
        }
    }
}

const fn job_phase_from_tzap(phase: ArchiveWritePhase) -> JobPhase {
    match phase {
        ArchiveWritePhase::PlanningPayload => JobPhase::PlanningPayload,
        ArchiveWritePhase::PlanningMetadata => JobPhase::PlanningMetadata,
        ArchiveWritePhase::EmittingPayload => JobPhase::EmittingPayload,
        ArchiveWritePhase::EmittingMetadata => JobPhase::EmittingMetadata,
    }
}

struct TzapArchiveFileSink {
    destination: PathBuf,
    replace_existing: bool,
    existing_volume_paths: Vec<PathBuf>,
    volume_paths: Vec<PathBuf>,
    outputs: Vec<AtomicOutputFile>,
}

impl TzapArchiveFileSink {
    fn new(destination: &Path, replace_existing: bool) -> Result<Self, TzapError> {
        Ok(Self {
            destination: destination.to_path_buf(),
            replace_existing,
            existing_volume_paths: existing_tzap_volume_paths(destination)?,
            volume_paths: Vec::new(),
            outputs: Vec::new(),
        })
    }

    fn commit(self) -> Result<usize, TzapError> {
        let volume_count = self.volume_paths.len();
        if volume_count == 0 {
            return Err(TzapError::Format(FormatError::WriterInvariant(
                "no TZAP volumes emitted",
            )));
        }
        if self.outputs.len() != volume_count {
            return Err(TzapError::Format(FormatError::WriterInvariant(
                "TZAP output sink did not open every planned volume",
            )));
        }

        remove_tzap_destinations_for_replace(
            &self.destination,
            &self.existing_volume_paths,
            self.replace_existing,
        )?;

        for (output, volume_path) in self.outputs.into_iter().zip(self.volume_paths) {
            output
                .commit_with_file_replace(self.replace_existing)
                .map_err(|source| TzapError::Io {
                    path: volume_path,
                    source,
                })?;
        }

        Ok(volume_count)
    }
}

impl ArchiveWriteSink for TzapArchiveFileSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        if volume_count == 0 {
            return Err(ArchiveWriteError::Format(FormatError::WriterInvariant(
                "no TZAP volumes emitted",
            )));
        }

        let volume_paths = tzap_output_volume_paths(&self.destination, volume_count);
        ensure_tzap_destinations_available(
            &self.destination,
            &volume_paths,
            &self.existing_volume_paths,
            self.replace_existing,
        )
        .map_err(tzap_archive_write_error)?;

        let mut outputs = Vec::with_capacity(volume_paths.len());
        for volume_path in &volume_paths {
            outputs.push(AtomicOutputFile::create(volume_path).map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to create TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })?);
        }

        self.volume_paths = volume_paths;
        self.outputs = outputs;
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        let volume_path = self
            .volume_paths
            .get(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "TZAP volume path index is out of bounds",
            ))?
            .clone();
        let output = self
            .outputs
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "TZAP volume sink index is out of bounds",
            ))?;
        output
            .file_mut()
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to access TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })?
            .write_all(bytes)
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(
                    source.kind(),
                    format!(
                        "failed to write TZAP output volume {}: {source}",
                        volume_path.display()
                    ),
                ))
            })
    }

    fn write_bootstrap_sidecar(&mut self, _bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        Ok(())
    }
}

fn tzap_archive_write_error(error: TzapError) -> ArchiveWriteError {
    match error {
        TzapError::Format(source) => ArchiveWriteError::Format(source),
        TzapError::Io { source, .. } => ArchiveWriteError::Io(source),
        TzapError::Cancelled => ArchiveWriteError::Io(io::Error::other(JobCancelled)),
        TzapError::Plan(_)
        | TzapError::X509RootAuth(_)
        | TzapError::KeyWrap(_)
        | TzapError::Safety(_)
        | TzapError::PasswordRequired
        | TzapError::RecipientKeyRequired => ArchiveWriteError::Io(io::Error::other(error)),
    }
}

fn tzap_write_error(path: &Path, error: ArchiveWriteError) -> TzapError {
    match error {
        ArchiveWriteError::Format(source) => TzapError::Format(source),
        ArchiveWriteError::Io(source) => {
            if source
                .get_ref()
                .is_some_and(|source| source.downcast_ref::<JobCancelled>().is_some())
            {
                TzapError::Cancelled
            } else {
                TzapError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            }
        }
    }
}

fn system_time_to_unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(unix)]
fn write_symlink(target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    std::os::unix::fs::symlink(target, destination_path).map_err(|source| TzapError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn write_symlink(_target: &Path, destination_path: &Path) -> Result<(), TzapError> {
    Err(TzapError::Io {
        path: destination_path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink extraction is not supported on this platform",
        ),
    })
}

fn write_hardlink(source_path: &Path, destination_path: &Path) -> Result<(), TzapError> {
    fs::hard_link(source_path, destination_path).map_err(|source| TzapError::Io {
        path: destination_path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        TzapCreateOptions, TzapKeySource, TzapX509SigningOptions, TzapX509TrustOptions,
        create_tzap_from_manifest_with_context, extract_tzap_file_to_destination,
        extract_tzap_with_recipient_key, is_tzap_archive_path, list_tzap_with_optional_password,
        list_tzap_with_password, list_tzap_with_recipient_key, load_x509_trusted_roots,
        summarize_tzap_public_metadata, test_tzap_with_password_filter_and_x509_trust,
        test_tzap_with_recipient_key_filter_and_x509_trust, verify_tzap_x509_public_no_key,
    };
    use crate::jobs::{CancellationToken, JobContext};
    use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot};
    use crate::safety::ExtractionPolicy;
    use crate::secrets::SecretString;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::{PKey, PKeyRef, Private};
    use openssl::rsa::Rsa;
    use openssl::stack::Stack;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509NameBuilder, X509Ref};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tzap_core::{KdfParams, MasterKey, RegularFile, WriterOptions, write_archive_with_kdf};

    #[test]
    fn x509_trust_options_can_include_embedded_official_root() {
        let trust = TzapX509TrustOptions {
            trusted_ca_certificates: Vec::new(),
            trusted_system_roots: false,
            include_official_tzap_root: true,
        };

        let roots = load_x509_trusted_roots(&trust).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(
            crate::trust::certificate_sha256_identifier_for_der(&roots[0]),
            "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d"
        );
        let root = X509::from_der(&roots[0]).unwrap();
        assert_eq!(
            crate::x509_format::x509_name_to_string(root.subject_name()),
            "CN=TZAP Production Root CA 2026, O=TZAP, C=AU"
        );
    }

    #[test]
    fn recognizes_tzap_base_and_numbered_volumes() {
        assert!(is_tzap_archive_path(Path::new("project.tzap")));
        assert!(is_tzap_archive_path(Path::new("project.vol000.tzap")));
        assert!(is_tzap_archive_path(Path::new("project.vol001.tzap")));
        assert!(is_tzap_archive_path(Path::new("PROJECT.vol000.TZAP")));

        assert!(!is_tzap_archive_path(Path::new("project.tzap.tmp")));
        assert!(!is_tzap_archive_path(Path::new("project.zip.000")));
    }

    #[test]
    fn selected_extract_uses_seekable_core_for_numbered_volumes() {
        let temp = TestDir::new("tzap_seekable_selected");
        let large = vec![7u8; 1024 * 1024];
        let archive = create_test_tzap_archive(&[
            RegularFile::new("large.bin", &large),
            RegularFile::new("nested/small.txt", b"small target"),
        ]);
        for (index, volume) in archive.volumes.iter().enumerate() {
            fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
        }

        let selected_volume_path = temp.path("sample.vol001.tzap");
        let listing = list_tzap_with_password(&selected_volume_path, "secret").unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.path == "nested/small.txt")
        );

        let destination = temp.path("out/selected.txt");
        let written = extract_tzap_file_to_destination(
            &selected_volume_path,
            "secret",
            "nested/small.txt",
            &destination,
            false,
        )
        .unwrap();

        assert_eq!(written, Some(12));
        assert_eq!(fs::read(&destination).unwrap(), b"small target");
    }

    #[test]
    fn public_metadata_summary_reads_numbered_volume_headers_without_password() {
        let temp = TestDir::new("tzap_public_metadata");
        let base_path = temp.path("sample.tzap");
        let archive = create_test_tzap_archive(&[RegularFile::new("hello.txt", b"hello")]);
        for (index, volume) in archive.volumes.iter().enumerate() {
            fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
        }

        let summary = summarize_tzap_public_metadata(&base_path).unwrap();

        assert_eq!(summary.expected_volume_count, 4);
        assert_eq!(summary.present_volume_count, 4);
        assert_eq!(summary.missing_volume_indices, Vec::<usize>::new());
        assert_eq!(summary.volumes.len(), 4);
        assert!(summary.format.password_required);
        assert_eq!(summary.format.volume_loss_tolerance, 0);
        assert_eq!(summary.format.bit_rot_buffer_percentage, 0);
        assert_eq!(
            summary.total_size,
            archive.volumes.iter().map(Vec::len).sum::<usize>() as u64
        );
    }

    #[test]
    fn create_tzap_without_password_uses_unencrypted_mode() {
        let temp = TestDir::new("tzap_unencrypted_create");
        let source = temp.path("payload.txt");
        let archive = temp.path("public.tzap");
        fs::write(&source, b"public payload").unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 14,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 14,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        let report =
            create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
                .unwrap();

        let listing = list_tzap_with_optional_password(&archive, None).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        assert_eq!(report.written_entries, 1);
        assert_eq!(report.written_bytes, fs::metadata(&archive).unwrap().len());
        assert_ne!(report.written_bytes, manifest.total_bytes);

        let summary = summarize_tzap_public_metadata(&archive).unwrap();
        assert_eq!(summary.format.encryption_algorithm, "none");
        assert_eq!(summary.format.key_derivation, "none");
        assert!(!summary.format.password_required);
    }

    #[test]
    fn list_tzap_with_optional_password_includes_mtime() {
        let temp = TestDir::new("tzap_list_with_optional_password_includes_mtime");
        let source = temp.path("payload.txt");
        let archive = temp.path("public.tzap");
        fs::write(&source, b"payload").unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 7,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 7,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let listing = list_tzap_with_optional_password(&archive, None).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        assert_ne!(listing.entries[0].mtime, 0);
    }

    #[test]
    fn create_tzap_with_recipient_certificate_opens_with_private_key() {
        let temp = TestDir::new("tzap_recipient_wrap_create");
        let source = temp.path("payload.txt");
        let archive = temp.path("sealed.tzap");
        let recipient_cert_path = temp.path("recipient.pem");
        let recipient_key_path = temp.path("recipient.key");
        fs::write(&source, b"sealed payload").unwrap();

        let (recipient_cert, recipient_key) = test_p256_recipient_cert("ZManager Test Recipient");
        fs::write(&recipient_cert_path, recipient_cert.to_pem().unwrap()).unwrap();
        fs::write(
            &recipient_key_path,
            recipient_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 14,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 14,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientCertificate(recipient_cert_path),
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let summary = summarize_tzap_public_metadata(&archive).unwrap();
        assert_eq!(summary.format.key_derivation, "recipient-wrap");
        assert_eq!(summary.format.encryption_algorithm, "aes-gcm-siv-256");
        assert!(!summary.format.password_required);

        let no_key_error = list_tzap_with_optional_password(&archive, None).unwrap_err();
        assert!(no_key_error.to_string().contains("recipient private key"));

        let listing = list_tzap_with_recipient_key(&archive, &recipient_key_path).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");

        let report = test_tzap_with_recipient_key_filter_and_x509_trust(
            &archive,
            &recipient_key_path,
            |_| true,
            None,
        )
        .unwrap();
        assert_eq!(report.tested_entries, 1);
        assert_eq!(report.tested_bytes, 14);

        let out = temp.path("out");
        let extract_report = extract_tzap_with_recipient_key(
            &archive,
            &out,
            ExtractionPolicy::default(),
            &recipient_key_path,
        )
        .unwrap();
        assert_eq!(extract_report.written_entries, 1);
        assert_eq!(
            fs::read(out.join("payload.txt")).unwrap(),
            b"sealed payload"
        );
    }

    #[test]
    fn multi_recipient_public_keys_can_open_same_archive() {
        let temp = TestDir::new("tzap_multi_recipient_wrap_create");
        let source = temp.path("payload.txt");
        let archive = temp.path("sealed.tzap");
        let recipient_one_key_path = temp.path("recipient-one.key");
        let recipient_two_key_path = temp.path("recipient-two.key");
        let outsider_key_path = temp.path("outsider.key");
        fs::write(&source, b"shared payload").unwrap();

        let (_recipient_one_cert, recipient_one_key) =
            test_p256_recipient_cert("ZManager Test Recipient One");
        let (_recipient_two_cert, recipient_two_key) =
            test_p256_recipient_cert("ZManager Test Recipient Two");
        let (_outsider_cert, outsider_key) = test_p256_recipient_cert("ZManager Test Outsider");
        fs::write(
            &recipient_one_key_path,
            recipient_one_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        fs::write(
            &recipient_two_key_path,
            recipient_two_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        fs::write(
            &outsider_key_path,
            outsider_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        let manifest = single_file_manifest(&temp, source, 14);
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientPublicKeys(vec![
                recipient_one_key.public_key_to_der().unwrap(),
                recipient_two_key.public_key_to_der().unwrap(),
            ]),
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        for recipient_key_path in [&recipient_one_key_path, &recipient_two_key_path] {
            let listing = list_tzap_with_recipient_key(&archive, recipient_key_path).unwrap();
            assert_eq!(listing.entries.len(), 1);
            assert_eq!(listing.entries[0].path, "payload.txt");
        }

        let outsider_error = list_tzap_with_recipient_key(&archive, outsider_key_path).unwrap_err();
        assert!(
            outsider_error
                .to_string()
                .contains("no matching recipient private key")
        );
    }

    #[test]
    fn create_split_tzap_uses_os_friendly_volume_names() {
        let temp = TestDir::new("tzap_split_volume_names");
        let source = temp.path("payload.bin");
        let archive = temp.path("public.tzap");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        fs::write(&source, &payload).unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.bin".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: payload.len() as u64,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: payload.len() as u64,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: Some(1024 * 1024),
            recovery_percentage: 0,
            volume_loss_tolerance: 1,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);

        let report =
            create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
                .unwrap();

        assert!(report.volume_count > 1);
        assert!(!archive.exists());
        assert!(temp.path("public.vol000.tzap").exists());
        assert!(temp.path("public.vol001.tzap").exists());

        let selected_volume = temp.path("public.vol001.tzap");
        let listing = list_tzap_with_optional_password(&selected_volume, None).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.bin");
    }

    #[test]
    fn create_and_test_tzap_with_x509_root_auth() {
        let temp = TestDir::new("tzap_x509_root_auth");
        let source = temp.path("payload.txt");
        let archive = temp.path("signed.tzap");
        let root_ca_path = temp.path("root-ca.pem");
        let signer_cert_path = temp.path("signer.pem");
        let signer_key_path = temp.path("signer.key");
        fs::write(&source, b"signed payload").unwrap();

        let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
        let (signer_cert, signer_key) = test_leaf_cert(
            "ZManager Test Signer",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
        fs::write(&signer_cert_path, signer_cert.to_pem().unwrap()).unwrap();
        fs::write(
            &signer_key_path,
            signer_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 14,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 14,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: Some(TzapX509SigningOptions::CertificateAndKey {
                signing_certificate: signer_cert_path,
                signing_private_key: signer_key_path,
                signing_chain: Vec::new(),
            }),
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);
        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let trust = TzapX509TrustOptions {
            trusted_ca_certificates: vec![root_ca_path],
            trusted_system_roots: false,
            include_official_tzap_root: false,
        };
        let report = test_tzap_with_password_filter_and_x509_trust(
            &archive,
            "secret",
            |_| true,
            Some(&trust),
        )
        .unwrap();
        let root_auth = report.x509_root_auth.unwrap();

        assert_eq!(report.tested_entries, 1);
        assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
        assert_eq!(root_auth.issuer, "CN=ZManager Test Root CA");
        assert_eq!(
            root_auth.trust_anchor_subject.as_deref(),
            Some("CN=ZManager Test Root CA")
        );
        assert!(
            root_auth
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic == "root_auth_content_verified")
        );

        let public_report = verify_tzap_x509_public_no_key(&archive, &trust).unwrap();
        assert_eq!(public_report.archive_root, root_auth.archive_root);
        assert_eq!(public_report.subject, "CN=ZManager Test Signer");
        assert_eq!(
            public_report.trust_anchor_subject.as_deref(),
            Some("CN=ZManager Test Root CA")
        );
        assert_eq!(
            public_report.diagnostics.first().map(String::as_str),
            Some("public_data_block_commitment_verified")
        );
    }

    #[test]
    fn create_tzap_embeds_chain_from_signing_certificate_bundle() {
        let temp = TestDir::new("tzap_x509_root_auth_bundle");
        let source = temp.path("payload.txt");
        let archive = temp.path("signed.tzap");
        let root_ca_path = temp.path("root-ca.pem");
        let signer_bundle_path = temp.path("signer-fullchain.pem");
        let signer_key_path = temp.path("signer.key");
        fs::write(&source, b"signed payload").unwrap();

        let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
        let (intermediate_cert, intermediate_key) = test_child_ca_cert(
            "ZManager Test Intermediate CA",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let (signer_cert, signer_key) = test_leaf_cert(
            "ZManager Test Signer",
            intermediate_cert.as_ref(),
            intermediate_key.as_ref(),
        );
        fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
        let mut signer_bundle = signer_cert.to_pem().unwrap();
        signer_bundle.extend(intermediate_cert.to_pem().unwrap());
        fs::write(&signer_bundle_path, signer_bundle).unwrap();
        fs::write(
            &signer_key_path,
            signer_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 14,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 14,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: Some(TzapX509SigningOptions::CertificateAndKey {
                signing_certificate: signer_bundle_path,
                signing_private_key: signer_key_path,
                signing_chain: Vec::new(),
            }),
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);
        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let trust = TzapX509TrustOptions {
            trusted_ca_certificates: vec![root_ca_path],
            trusted_system_roots: false,
            include_official_tzap_root: false,
        };
        let report = test_tzap_with_password_filter_and_x509_trust(
            &archive,
            "secret",
            |_| true,
            Some(&trust),
        )
        .unwrap();
        let root_auth = report.x509_root_auth.unwrap();

        assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
        assert_eq!(root_auth.issuer, "CN=ZManager Test Intermediate CA");
        assert_eq!(
            root_auth.verified_chain_subjects,
            vec![
                "CN=ZManager Test Signer".to_owned(),
                "CN=ZManager Test Intermediate CA".to_owned(),
                "CN=ZManager Test Root CA".to_owned(),
            ]
        );
        assert_eq!(
            root_auth.trust_anchor_subject.as_deref(),
            Some("CN=ZManager Test Root CA")
        );
    }

    #[test]
    fn create_tzap_signs_with_pkcs12_identity() {
        let temp = TestDir::new("tzap_x509_root_auth_p12");
        let source = temp.path("payload.txt");
        let archive = temp.path("signed.tzap");
        let root_ca_path = temp.path("root-ca.pem");
        let identity_path = temp.path("signer.p12");
        fs::write(&source, b"signed payload").unwrap();

        let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
        let (intermediate_cert, intermediate_key) = test_child_ca_cert(
            "ZManager Test Intermediate CA",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let (signer_cert, signer_key) = test_leaf_cert(
            "ZManager Test Signer",
            intermediate_cert.as_ref(),
            intermediate_key.as_ref(),
        );
        fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
        let mut chain = Stack::new().unwrap();
        chain.push(intermediate_cert).unwrap();
        let identity = Pkcs12::builder()
            .name("ZManager Test Signer")
            .pkey(&signer_key)
            .cert(&signer_cert)
            .ca(chain)
            .build2("identity-password")
            .unwrap();
        fs::write(&identity_path, identity.to_der().unwrap()).unwrap();

        let manifest = ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size: 14,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: 14,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        };
        let options = TzapCreateOptions {
            key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: Some(TzapX509SigningOptions::Pkcs12 {
                identity: identity_path,
                password: SecretString::from("identity-password"),
            }),
        };
        let token = CancellationToken::new();
        let mut events = |_| {};
        let mut context = JobContext::new(&token, &mut events);
        create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context)
            .unwrap();

        let trust = TzapX509TrustOptions {
            trusted_ca_certificates: vec![root_ca_path],
            trusted_system_roots: false,
            include_official_tzap_root: false,
        };
        let report = test_tzap_with_password_filter_and_x509_trust(
            &archive,
            "secret",
            |_| true,
            Some(&trust),
        )
        .unwrap();
        let root_auth = report.x509_root_auth.unwrap();

        assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
        assert_eq!(root_auth.issuer, "CN=ZManager Test Intermediate CA");
        assert_eq!(
            root_auth.trust_anchor_subject.as_deref(),
            Some("CN=ZManager Test Root CA")
        );
    }

    fn create_test_tzap_archive(files: &[RegularFile<'_>]) -> tzap_core::writer::WrittenArchive {
        let kdf = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        };
        let key = MasterKey::derive_from_passphrase(&kdf, "secret").unwrap();
        let options = WriterOptions {
            stripe_width: 4,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            zstd_level: 1,
            ..WriterOptions::default()
        };
        write_archive_with_kdf(files, &key, options, &kdf).unwrap()
    }

    fn single_file_manifest(temp: &TestDir, source: PathBuf, size: u64) -> ArchiveManifest {
        ArchiveManifest {
            root: temp.root.clone(),
            entries: vec![ManifestEntry {
                archive_path: "payload.txt".to_owned(),
                source_path: source,
                file_type: ManifestFileType::File,
                size,
                modified: None,
                permissions: PermissionSnapshot {
                    readonly: false,
                    unix_mode: Some(0o644),
                },
                symlink_target: None,
            }],
            total_bytes: size,
            excluded_entries: Vec::new(),
            excluded_bytes: 0,
            warnings: Vec::new(),
        }
    }

    fn test_ca_cert(common_name: &str) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_child_ca_cert(
        common_name: &str,
        ca_cert: &X509Ref,
        ca_key: &PKeyRef<Private>,
    ) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_leaf_cert(
        common_name: &str,
        ca_cert: &X509Ref,
        ca_key: &PKeyRef<Private>,
    ) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_p256_recipient_cert(common_name: &str) -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_agreement()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn random_serial_number() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                u8::try_from((index.wrapping_mul(31).wrapping_add(17)) % 251)
                    .expect("deterministic byte is reduced below u8::MAX")
            })
            .collect()
    }

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("zmanager-{name}-{}-{now}", std::process::id()));
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
}
