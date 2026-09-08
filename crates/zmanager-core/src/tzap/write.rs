//! TZAP archive writing: manifest-driven creation, destination and volume
//! naming, the regular-file source adapter, write progress reporting, and the
//! file sink that commits volumes and the bootstrap sidecar.

use super::{TzapError, io_error};
use crate::atomic_file::AtomicOutputFile;
use crate::jobs::{CancellationToken, JobCancelled, JobContext, JobPhase, ProgressBatch, ProgressCoalescer};
use crate::manifest::{ArchiveManifest, ManifestFileType};
use crate::secrets::SecretString;
use crate::tzap::metadata::{CapturedPortableFileMetadata, portable_file_metadata, system_time_to_archive_timestamp};
use crate::tzap::x509::{
    TzapX509SigningOptions, build_recipient_wrap_record_from_certificate_der, build_recipient_wrap_record_from_certificate_path,
    load_single_x509_certificate_file, load_x509_signer, recipient_wrap_archive_identity_for_writer, synthetic_recipient_certificate_der,
    validate_recipient_wrap_create_options,
};
use rand::RngCore as _;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use tzap_core::format::{AeadAlgo, FormatError, READER_MAX_ARGON2ID_M_COST_KIB, READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST};
use tzap_core::{
    ArchiveTimestamp, ArchiveWriteError, ArchiveWritePhase, ArchiveWriteProgressSink, ArchiveWriteSink, KdfParams, MasterKey, PortableFileMetadata,
    RegularFileSource, RootAuthSigningRequest, SourceEntryKind, WriterOptions,
    volume_file::{discover_sibling_volume_paths, multi_volume_base_name, volume_output_path},
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress, write_archive_sources_to_sink_with_progress,
};
use tzap_plugin_signing::x509_chain::X509RootAuthSigner;

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;

const TZAP_PLACEHOLDER_MASTER_KEY: [u8; 32] = [0; 32];

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
    /// Split output into TZAP volumes of this size when present. Mutually
    /// exclusive with `volume_count`.
    pub volume_size: Option<u64>,
    /// Split output into exactly this many TZAP volumes (striped rather than
    /// size-targeted) when present. Mutually exclusive with `volume_size`.
    pub volume_count: Option<u32>,
    /// Percent of archive data reserved for bit-rot recovery structures.
    pub recovery_percentage: u8,
    /// Number of missing output volumes the archive should tolerate.
    pub volume_loss_tolerance: u8,
    /// X.509 `RootAuth` signing configuration.
    pub x509_signing: Option<TzapX509SigningOptions>,
    /// Emit bootstrap sidecar file beside output.
    pub emit_bootstrap_sidecar: bool,
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

/// Creates a `.tzap` archive from a manifest.
///
/// # Errors
///
/// Returns [`TzapError`] when source files cannot be read, key derivation fails,
/// tzap encoding fails, filesystem writes fail, or cancellation is requested.
#[allow(clippy::too_many_lines)]
pub fn create_tzap_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TzapCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TzapCreateReport, TzapError> {
    context.check_cancelled()?;
    if options.volume_size.is_some() && options.volume_count.is_some_and(|count| count > 1) {
        return Err(FormatError::WriterUnsupported("volume_size and volume_count are mutually exclusive").into());
    }
    let (file_sources, mut warnings) = collect_archive_sources(manifest, options, context)?;
    context.check_cancelled()?;

    let mut writer_options = WriterOptions {
        stripe_width: options.volume_count.unwrap_or(1).max(1),
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
    let recipient_records = build_recipient_records(options, &master_key, &mut writer_options)?;
    let destination = destination.as_ref();
    let mut sink = TzapArchiveFileSink::new(destination, options.replace_existing, options.emit_bootstrap_sidecar, context.cancellation_token())?;
    let x509_signer = options.x509_signing.as_ref().map(load_x509_signer).transpose()?;
    let root_auth =
        x509_signer.as_ref().map(X509RootAuthSigner::root_auth_writer_config).transpose().map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let mut authenticator = |request: &RootAuthSigningRequest| {
        x509_signer
            .as_ref()
            .ok_or(FormatError::WriterInvariant("missing X.509 signer"))
            .and_then(|signer| signer.authenticator_value_for_request(request).map_err(|_| FormatError::WriterUnsupported("X.509 RootAuth signing failed")))
    };
    let authenticator = root_auth.as_ref().map(|_| &mut authenticator as &mut dyn FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>);
    let mut entry_progress = TzapEntryProgress::new(&file_sources);

    let summary = {
        let mut progress = TzapWriteJobProgress {
            context,
            total_source_bytes: manifest.total_bytes,
            entries: &mut entry_progress,
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

    context.check_cancelled()?;
    context.phase_started(JobPhase::CommittingOutput, None);
    let volume_count = sink.commit()?;
    if summary.volume_count != volume_count {
        return Err(TzapError::Format(FormatError::WriterInvariant("TZAP writer summary did not match committed volume count")));
    }
    // Entries the writer never reported progress for still owe a started and a
    // finished event apiece.
    for file in &file_sources {
        let Some(slot) = entry_progress.slot(&file.archive_path) else { continue };
        if entry_progress.mark_started(slot) {
            context.entry_started(&file.archive_path, Some(file.size));
        }
        if entry_progress.mark_finished(slot) {
            context.entry_finished(&file.archive_path, file.size);
        }
    }

    warnings.extend(manifest.warnings.iter().map(|warning| warning.message.clone()));

    Ok(TzapCreateReport {
        written_entries: file_sources.len(),
        written_bytes: summary.archive_bytes,
        level: options.level,
        volume_size: options.volume_size,
        volume_count,
        warnings,
    })
}

/// Builds the recipient-wrap records for the key source, or `None` for
/// passphrase/no-password archives (CR-143).
fn build_recipient_records(
    options: &TzapCreateOptions,
    master_key: &MasterKey,
    writer_options: &mut WriterOptions,
) -> Result<Option<Vec<tzap_core::wire::RecipientRecordV1>>, TzapError> {
    Ok(match &options.key_source {
        TzapKeySource::RecipientCertificate(recipient_certificate) => {
            validate_recipient_wrap_create_options(options)?;
            Some(vec![build_recipient_wrap_record_from_certificate_path(recipient_certificate, master_key, writer_options)?])
        }
        TzapKeySource::RecipientCertificates(recipient_certificates) => {
            validate_recipient_wrap_create_options(options)?;
            if recipient_certificates.is_empty() {
                return Err(TzapError::KeyWrap("at least one recipient certificate is required".to_owned()));
            }
            let archive_identity = recipient_wrap_archive_identity_for_writer(writer_options);
            Some(
                recipient_certificates
                    .iter()
                    .map(|path| {
                        let certificate = load_single_x509_certificate_file("recipient certificate", path)?;
                        build_recipient_wrap_record_from_certificate_der(&certificate, master_key, &archive_identity)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        TzapKeySource::RecipientPublicKeys(recipient_public_keys) => {
            validate_recipient_wrap_create_options(options)?;
            if recipient_public_keys.is_empty() {
                return Err(TzapError::KeyWrap("at least one recipient public key is required".to_owned()));
            }
            let archive_identity = recipient_wrap_archive_identity_for_writer(writer_options);
            Some(
                recipient_public_keys
                    .iter()
                    .map(|public_key_der| {
                        let certificate = synthetic_recipient_certificate_der(public_key_der)?;
                        build_recipient_wrap_record_from_certificate_der(&certificate, master_key, &archive_identity)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        TzapKeySource::Passphrase(_) | TzapKeySource::NoPassword => None,
    })
}

fn tzap_output_volume_paths(destination: &Path, count: usize) -> Vec<PathBuf> {
    if count == 1 {
        return vec![destination.to_path_buf()];
    }

    (0..count).map(|index| volume_output_path(destination, index)).collect()
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
    left.iter().chain(right.iter()).filter_map(|path| if seen.insert(path.clone()) { Some(path.as_path()) } else { None }).collect()
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), TzapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io_error(path, io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())))
        }
        Ok(_) if !replace_existing => Err(io_error(path, io::ErrorKind::AlreadyExists, format!("destination already exists: {}", path.display()))),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io { path: path.to_path_buf(), source }),
    }
}

fn remove_tzap_destinations_for_replace(destination: &Path, existing_volume_paths: &[PathBuf], replace_existing: bool) -> Result<(), TzapError> {
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
            Err(io_error(path, io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TzapError::Io { path: path.to_path_buf(), source }),
    }
}

fn existing_tzap_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, TzapError> {
    let parent = destination.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let Some(destination_file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let destination_base_name = multi_volume_base_name(destination_file_name);

    discover_sibling_volume_paths(parent, &destination_base_name).map_err(|source| TzapError::Io { path: parent.to_path_buf(), source })
}

fn collect_archive_sources(
    manifest: &ArchiveManifest,
    options: &TzapCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<(Vec<TzapRegularFileSource>, Vec<String>), TzapError> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    for entry in &manifest.entries {
        context.check_cancelled()?;
        context.entry_started(&entry.archive_path, Some(entry.size));

        match entry.file_type {
            ManifestFileType::File | ManifestFileType::Directory | ManifestFileType::Symlink => {
                let captured_metadata =
                    if options.preserve_metadata { portable_file_metadata(&entry.source_path)? } else { CapturedPortableFileMetadata::default() };
                files.push(TzapRegularFileSource {
                    archive_path: entry.archive_path.clone(),
                    source_path: entry.source_path.clone(),
                    kind: match entry.file_type {
                        ManifestFileType::File => SourceEntryKind::Regular,
                        ManifestFileType::Directory => SourceEntryKind::Directory,
                        ManifestFileType::Symlink => SourceEntryKind::Symlink,
                        ManifestFileType::Other => unreachable!(),
                    },
                    link_target: entry.symlink_target.as_deref().map(path_bytes),
                    size: if entry.file_type == ManifestFileType::File { entry.size } else { 0 },
                    mode: if options.preserve_metadata {
                        entry.permissions.unix_mode.unwrap_or_else(|| if entry.file_type == ManifestFileType::Directory { 0o755 } else { 0o644 }) & 0o7777
                    } else if entry.file_type == ManifestFileType::Directory {
                        0o755
                    } else {
                        0o644
                    },
                    mtime: if options.preserve_metadata {
                        entry.modified.and_then(system_time_to_archive_timestamp).unwrap_or(ArchiveTimestamp::UNIX_EPOCH)
                    } else {
                        ArchiveTimestamp::UNIX_EPOCH
                    },
                    portable_metadata: captured_metadata.metadata,
                    #[cfg(target_os = "macos")]
                    macos_metadata_identity: captured_metadata.macos_identity,
                    cancellation_token: context.cancellation_token(),
                });
            }
            ManifestFileType::Other => {
                let warning = format!("skipped {}: tzap backend does not write special files", entry.archive_path);
                warnings.push(warning.clone());
                context.warning(warning);
                context.entry_finished(&entry.archive_path, 0);
            }
        }
    }

    Ok((files, warnings))
}

fn create_kdf_params() -> KdfParams {
    let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
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
            let master_key = MasterKey::derive_from_passphrase(&kdf_params, passphrase.expose_secret())?;
            Ok((master_key, kdf_params))
        }
        TzapKeySource::RecipientCertificate(_) | TzapKeySource::RecipientCertificates(_) | TzapKeySource::RecipientPublicKeys(_) => {
            Ok((generate_random_master_key()?, KdfParams::None))
        }
        TzapKeySource::NoPassword => Ok((placeholder_master_key()?, KdfParams::None)),
    }
}

fn generate_random_master_key() -> Result<MasterKey, TzapError> {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    MasterKey::from_raw_key(&bytes).map_err(Into::into)
}

pub(crate) fn placeholder_master_key() -> Result<MasterKey, TzapError> {
    MasterKey::from_raw_key(&TZAP_PLACEHOLDER_MASTER_KEY).map_err(Into::into)
}

#[derive(Debug)]
struct TzapRegularFileSource {
    archive_path: String,
    source_path: PathBuf,
    kind: SourceEntryKind,
    link_target: Option<Vec<u8>>,
    size: u64,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: PortableFileMetadata,
    #[cfg(target_os = "macos")]
    macos_metadata_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
    cancellation_token: CancellationToken,
}

impl RegularFileSource for TzapRegularFileSource {
    fn archive_path(&self) -> &str {
        &self.archive_path
    }

    fn entry_kind(&self) -> SourceEntryKind {
        self.kind
    }

    fn link_target(&self) -> Option<&[u8]> {
        self.link_target.as_deref()
    }

    fn file_data_size(&self) -> u64 {
        self.size
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> ArchiveTimestamp {
        self.mtime
    }

    fn portable_metadata(&self) -> PortableFileMetadata {
        self.portable_metadata.clone()
    }

    fn open(&self) -> Result<Box<dyn io::Read + '_>, ArchiveWriteError> {
        if self.kind != SourceEntryKind::Regular {
            return Ok(Box::new(io::empty()));
        }
        let file = File::open(&self.source_path).map_err(|source| {
            ArchiveWriteError::Io(io::Error::new(source.kind(), format!("failed to open TZAP source file {}: {source}", self.source_path.display())))
        })?;
        Ok(Box::new(CancellationAwareReader { inner: file, token: self.cancellation_token.clone() }))
    }

    fn open_auxiliary(&self, ordinal: usize) -> Result<Box<dyn io::Read + '_>, ArchiveWriteError> {
        let record = self.portable_metadata.native.auxiliary_records.get(ordinal).ok_or(FormatError::WriterInvariant("auxiliary source ordinal is missing"))?;
        if !record.is_streamed() {
            return Ok(Box::new(io::Cursor::new(record.payload.clone())));
        }
        #[cfg(target_os = "macos")]
        {
            if record.kind != "macos.resource-fork" {
                return Err(FormatError::WriterUnsupported("unsupported streamed macOS auxiliary source").into());
            }
            let identity = self.macos_metadata_identity.ok_or(FormatError::WriterInvariant("macOS metadata identity is missing"))?;
            tzap_core::macos_metadata::open_macos_resource_fork(&self.source_path, self.kind == SourceEntryKind::Symlink, identity, record.logical_size)
                .map_err(ArchiveWriteError::Io)
        }
        #[cfg(not(target_os = "macos"))]
        Err(FormatError::WriterUnsupported("streamed auxiliary source is unsupported on this platform").into())
    }
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().replace('\\', "/").into_bytes()
}

#[cfg(all(not(unix), not(windows)))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

struct CancellationAwareReader<R> {
    inner: R,
    token: CancellationToken,
}

impl<R: io::Read> io::Read for CancellationAwareReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.token.is_cancelled() {
            return Err(io::Error::other(JobCancelled));
        }
        self.inner.read(buffer)
    }
}

/// Per-entry progress bookkeeping resolved to dense slots.
///
/// `source_bytes_read` runs once per read chunk, so this keeps the hot path to
/// a single hash lookup. The string-keyed maps it replaces re-allocated the
/// archive path two or three times per chunk just to query them.
struct TzapEntryProgress {
    /// Archive path to its slot. Duplicate paths collapse onto one slot, which
    /// is how the previous set-of-paths bookkeeping behaved.
    slots: HashMap<String, usize>,
    sizes: Vec<u64>,
    started: Vec<bool>,
    finished: Vec<bool>,
    processed: Vec<u64>,
}

impl TzapEntryProgress {
    fn new(sources: &[TzapRegularFileSource]) -> Self {
        let mut slots = HashMap::with_capacity(sources.len());
        let mut sizes = Vec::with_capacity(sources.len());
        for file in sources {
            if let Some(&slot) = slots.get(file.archive_path.as_str()) {
                // A repeated path keeps its first slot and the last size seen,
                // matching the map this replaced.
                sizes[slot] = file.size;
            } else {
                slots.insert(file.archive_path.clone(), sizes.len());
                sizes.push(file.size);
            }
        }
        let count = sizes.len();
        Self { slots, sizes, started: vec![false; count], finished: vec![false; count], processed: vec![0; count] }
    }

    fn slot(&self, archive_path: &str) -> Option<usize> {
        self.slots.get(archive_path).copied()
    }

    fn size(&self, slot: usize) -> u64 {
        self.sizes[slot]
    }

    /// Claims the started event for `slot`, returning true on the first claim.
    fn mark_started(&mut self, slot: usize) -> bool {
        !std::mem::replace(&mut self.started[slot], true)
    }

    /// Claims the finished event for `slot`, returning true on the first claim.
    fn mark_finished(&mut self, slot: usize) -> bool {
        !std::mem::replace(&mut self.finished[slot], true)
    }

    /// Adds `bytes` to `slot` and returns its size the one time that completes
    /// the entry.
    fn record_processed(&mut self, slot: usize, bytes: u64) -> Option<u64> {
        let processed = &mut self.processed[slot];
        *processed = processed.saturating_add(bytes);
        let size = self.sizes[slot];
        (*processed >= size && self.mark_finished(slot)).then_some(size)
    }
}

struct TzapWriteJobProgress<'context, 'job, 'state> {
    context: &'context mut JobContext<'job>,
    total_source_bytes: u64,
    entries: &'state mut TzapEntryProgress,
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
        self.context.phase_bytes_processed_with_path_identities(
            phase,
            batch.path.as_deref(),
            batch.recent_paths,
            batch.recent_path_identities,
            batch.bytes,
            phase_total_bytes(phase, self.total_source_bytes),
            batch.recent_paths_truncated,
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

        // Every path the writer reports comes from the same source list this
        // state was built from. An unrecognized one has no size to report
        // against, so it contributes to phase progress only.
        let slot = self.entries.slot(archive_path);
        debug_assert!(slot.is_some(), "TZAP writer reported progress for an unplanned path: {archive_path}");

        if phase == JobPhase::EmittingPayload
            && let Some(slot) = slot
            && self.entries.mark_started(slot)
        {
            self.context.entry_started(archive_path, Some(self.entries.size(slot)));
        }

        if let Some(batch) = self.phase_progress.record(Some(archive_path), bytes) {
            self.emit_phase_batch(phase, batch);
        }

        if phase == JobPhase::EmittingPayload {
            self.context.bytes_processed(Some(archive_path), bytes);
            if let Some(slot) = slot
                && let Some(size) = self.entries.record_processed(slot, bytes)
            {
                self.context.entry_finished(archive_path, size);
            }
        }
    }
}

const fn phase_total_bytes(phase: JobPhase, total_source_bytes: u64) -> Option<u64> {
    match phase {
        JobPhase::PlanningPayload | JobPhase::EmittingPayload => Some(total_source_bytes),
        JobPhase::PlanningMetadata | JobPhase::EmittingMetadata | JobPhase::CommittingOutput => None,
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
    emit_bootstrap_sidecar: bool,
    existing_volume_paths: Vec<PathBuf>,
    volume_paths: Vec<PathBuf>,
    outputs: Vec<AtomicOutputFile>,
    bootstrap_sidecar: Option<Vec<u8>>,
    cancellation_token: CancellationToken,
}

impl TzapArchiveFileSink {
    fn new(destination: &Path, replace_existing: bool, emit_bootstrap_sidecar: bool, cancellation_token: CancellationToken) -> Result<Self, TzapError> {
        Ok(Self {
            destination: destination.to_path_buf(),
            replace_existing,
            emit_bootstrap_sidecar,
            existing_volume_paths: existing_tzap_volume_paths(destination)?,
            volume_paths: Vec::new(),
            outputs: Vec::new(),
            bootstrap_sidecar: None,
            cancellation_token,
        })
    }

    fn commit(self) -> Result<usize, TzapError> {
        if self.cancellation_token.is_cancelled() {
            return Err(TzapError::Cancelled);
        }
        let volume_count = self.volume_paths.len();
        if volume_count == 0 {
            return Err(TzapError::Format(FormatError::WriterInvariant("no TZAP volumes emitted")));
        }
        if self.outputs.len() != volume_count {
            return Err(TzapError::Format(FormatError::WriterInvariant("TZAP output sink did not open every planned volume")));
        }

        remove_tzap_destinations_for_replace(&self.destination, &self.existing_volume_paths, self.replace_existing)?;

        for (output, volume_path) in self.outputs.into_iter().zip(self.volume_paths) {
            output.commit_with_file_replace(self.replace_existing).map_err(|source| TzapError::Io { path: volume_path, source })?;
        }

        if self.emit_bootstrap_sidecar
            && let Some(sidecar) = self.bootstrap_sidecar.filter(|bytes| !bytes.is_empty())
        {
            commit_bootstrap_sidecar(&self.destination, &sidecar, self.replace_existing)?;
        }

        Ok(volume_count)
    }
}

/// Path of the tzap-core bootstrap sidecar beside a destination archive.
///
/// The sidecar is named after the archive base name (the destination with any
/// `.tzap` suffix stripped), mirroring the `{base}.volNNN.tzap` volume naming.
#[must_use]
pub fn tzap_bootstrap_sidecar_path(destination: &Path) -> PathBuf {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return destination.with_extension("sidecar");
    };
    let base_name = multi_volume_base_name(file_name);
    let sidecar_file_name = format!("{base_name}.sidecar");
    match destination.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        Some(parent) => parent.join(sidecar_file_name),
        None => PathBuf::from(sidecar_file_name),
    }
}

/// Commits the tzap-core bootstrap sidecar next to the destination archive.
///
/// tzap-core's writer emits a bootstrap sidecar only for single-volume
/// archives (`stripe_width == 1`); `create_tzap_from_manifest_with_context`
/// requests that unless `options.volume_count` asks for more. The blob
/// carries the manifest footer and index-root block records consumed by
/// tzap-core's `open_seekable_archive_with_bootstrap_sidecar` recovery API,
/// so discarding it would permanently lose the archive's bootstrap material.
fn commit_bootstrap_sidecar(destination: &Path, bytes: &[u8], replace_existing: bool) -> Result<(), TzapError> {
    let sidecar_path = tzap_bootstrap_sidecar_path(destination);
    if replace_existing {
        remove_file_destination_for_replace(&sidecar_path)?;
    } else {
        ensure_file_destination_available(&sidecar_path, false)?;
    }
    let mut output = AtomicOutputFile::create(&sidecar_path).map_err(|source| TzapError::Io { path: sidecar_path.clone(), source })?;
    output
        .file_mut()
        .map_err(|source| TzapError::Io { path: sidecar_path.clone(), source })?
        .write_all(bytes)
        .map_err(|source| TzapError::Io { path: sidecar_path.clone(), source })?;
    output.commit_with_file_replace(replace_existing).map_err(|source| TzapError::Io { path: sidecar_path, source })
}

impl ArchiveWriteSink for TzapArchiveFileSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        check_tzap_write_cancelled(&self.cancellation_token)?;
        if volume_count == 0 {
            return Err(ArchiveWriteError::Format(FormatError::WriterInvariant("no TZAP volumes emitted")));
        }

        let volume_paths = tzap_output_volume_paths(&self.destination, volume_count);
        ensure_tzap_destinations_available(&self.destination, &volume_paths, &self.existing_volume_paths, self.replace_existing)
            .map_err(tzap_archive_write_error)?;

        let mut outputs = Vec::with_capacity(volume_paths.len());
        for volume_path in &volume_paths {
            outputs.push(AtomicOutputFile::create(volume_path).map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(source.kind(), format!("failed to create TZAP output volume {}: {source}", volume_path.display())))
            })?);
        }

        self.volume_paths = volume_paths;
        self.outputs = outputs;
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        check_tzap_write_cancelled(&self.cancellation_token)?;
        let volume_path = self.volume_paths.get(volume_index).ok_or(FormatError::WriterInvariant("TZAP volume path index is out of bounds"))?.clone();
        let output = self.outputs.get_mut(volume_index).ok_or(FormatError::WriterInvariant("TZAP volume sink index is out of bounds"))?;
        output
            .file_mut()
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(source.kind(), format!("failed to access TZAP output volume {}: {source}", volume_path.display())))
            })?
            .write_all(bytes)
            .map_err(|source| {
                ArchiveWriteError::Io(io::Error::new(source.kind(), format!("failed to write TZAP output volume {}: {source}", volume_path.display())))
            })
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        // tzap-core only calls this for single-volume archives
        // (`stripe_width == 1`); a `volume_count`-striped multi-volume
        // archive never reaches it, and `commit()` treats an unset sidecar
        // as "nothing to write" rather than an invariant violation. Bytes
        // received here are buffered and committed beside the destination
        // archive in `commit()`.
        check_tzap_write_cancelled(&self.cancellation_token)?;
        self.bootstrap_sidecar = Some(bytes.to_vec());
        Ok(())
    }
}

fn check_tzap_write_cancelled(token: &CancellationToken) -> Result<(), ArchiveWriteError> {
    if token.is_cancelled() { Err(ArchiveWriteError::Io(io::Error::other(JobCancelled))) } else { Ok(()) }
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
            if source.get_ref().is_some_and(|source| source.downcast_ref::<JobCancelled>().is_some()) {
                TzapError::Cancelled
            } else {
                TzapError::Io { path: path.to_path_buf(), source }
            }
        }
    }
}
