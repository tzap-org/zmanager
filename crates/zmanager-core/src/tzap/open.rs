//! TZAP archive opening: key-option dispatch, volume discovery, and public
//! header parsing used for password-free metadata summaries.

use super::{TzapError, io_error};
use crate::tzap::write::placeholder_master_key;
use crate::tzap::x509::{
    RecipientWrapOpenStats, load_recipient_private_key_lookup, load_recipient_private_key_lookup_from_bytes_list, recipient_wrap_candidates_for_record,
    recipient_wrap_open_error,
};
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use tzap_core::format::{AeadAlgo, CRYPTO_HEADER_FIXED_LEN, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, VOLUME_HEADER_LEN};
use tzap_core::volume_file::{
    TZAP_EXTENSION, TZAP_EXTENSION_SUFFIX, discover_sibling_volume_paths, multi_volume_base_name, parse_volume_file_name, volume_output_path,
};
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    KdfParams, MasterKey, OpenedArchive, ReaderOptions, open_seekable_archive, open_seekable_archive_volumes,
    open_seekable_archive_volumes_with_recipient_wrap_resolver_options, validate_volume_set_member_metadata,
};

/// Returns whether a path names a TZAP archive or one of its numbered volumes.
#[must_use]
pub fn is_tzap_archive_path(path: &Path) -> bool {
    if path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case(TZAP_EXTENSION)) {
        return true;
    }

    path.file_name().and_then(|name| name.to_str()).is_some_and(is_tzap_volume_archive_file_name)
}

fn is_tzap_volume_archive_file_name(name: &str) -> bool {
    // `tzap-core`'s volume parser assumes the `.tzap` suffix is present before
    // byte-slicing the filename.  Avoid calling it for unrelated extensions:
    // a Unicode filename can otherwise put that byte split inside a UTF-8
    // character and panic while merely checking the archive format.
    name.get(name.len().saturating_sub(TZAP_EXTENSION_SUFFIX.len())..).is_some_and(|suffix| suffix.eq_ignore_ascii_case(TZAP_EXTENSION_SUFFIX))
        && parse_volume_file_name(name).is_some()
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPublicVolumeSummary {
    /// Path of the volume file.
    pub path: PathBuf,
    /// Zero-based volume index encoded in the volume header.
    pub index: usize,
    /// Volume bytes on disk.
    pub size: u64,
}

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

/// Opens each of an archive's volumes as a `File` (which implements
/// `ArchiveReadAt`) rather than reading it into memory (T2/Z4): callers pass
/// these to a reader-based verification entry point, which then reads each
/// `BlockRecord` with a bounded seek rather than requiring the whole volume
/// resident at once.
pub(crate) fn open_tzap_input_volume_readers(archive_path: &Path) -> Result<Vec<File>, TzapError> {
    discover_tzap_input_volume_paths(archive_path).iter().map(|path| File::open(path).map_err(|source| TzapError::Io { path: path.clone(), source })).collect()
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
pub fn summarize_tzap_public_metadata(archive_path: impl AsRef<Path>) -> Result<TzapPublicMetadataSummary, TzapError> {
    let requested_path = archive_path.as_ref();
    let volume_paths = discover_tzap_input_volume_paths(requested_path);
    let first_volume_path =
        volume_paths.iter().find(|path| path.exists()).ok_or_else(|| io_error(requested_path, io::ErrorKind::NotFound, "no TZAP input volumes found"))?;
    let mut first_volume_file = File::open(first_volume_path).map_err(|source| TzapError::Io { path: first_volume_path.clone(), source })?;
    summarize_tzap_public_metadata_from(requested_path, &volume_paths, &mut first_volume_file)
}

/// Summarizes public metadata from an already-opened first volume.
///
/// Caller contract: `volume_paths` is the output of
/// [`discover_tzap_input_volume_paths`] for `requested_path`, and
/// `first_volume_file` is a handle to the first existing path in it (the
/// caller must have opened it — the first volume's header is read through
/// this handle so a single open serves the whole summary).
pub(crate) fn summarize_tzap_public_metadata_from(
    requested_path: &Path,
    volume_paths: &[PathBuf],
    first_volume_file: &mut File,
) -> Result<TzapPublicMetadataSummary, TzapError> {
    let first_volume_path = volume_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| io_error(requested_path, io::ErrorKind::NotFound, "no existing TZAP input volume is available for the opened handle"))?;
    let first_header = read_public_tzap_header_from(first_volume_file, first_volume_path)?;
    let expected_volume_count =
        usize::try_from(first_header.volume_header.stripe_width).map_err(|_| TzapError::Format(FormatError::InvalidArchive("TZAP volume count overflow")))?;
    let expected_paths = expected_tzap_input_volume_paths(requested_path, first_volume_path, expected_volume_count);

    let mut volumes = Vec::new();
    let mut missing_volume_indices = Vec::new();
    let mut total_size = 0u64;

    for (expected_index, volume_path) in expected_paths.iter().enumerate() {
        if !volume_path.exists() {
            missing_volume_indices.push(expected_index);
            continue;
        }

        let metadata = fs::metadata(volume_path).map_err(|source| TzapError::Io { path: volume_path.clone(), source })?;
        // The first volume's header was already read through the caller's
        // handle; its self cross-check trivially passes, while the
        // volume-index check below still runs.
        let header = if expected_index == 0 { &first_header } else { &read_public_tzap_header(volume_path)? };
        validate_volume_set_member_metadata(
            &first_header.volume_header,
            &first_header.crypto_header,
            &first_header.crypto_header_bytes,
            &header.volume_header,
            &header.crypto_header,
            &header.crypto_header_bytes,
        )?;

        let index =
            usize::try_from(header.volume_header.volume_index).map_err(|_| TzapError::Format(FormatError::InvalidArchive("TZAP volume index overflow")))?;
        if index != expected_index {
            return Err(TzapError::Format(FormatError::InvalidArchive("TZAP volume index does not match expected path")));
        }
        total_size = total_size.checked_add(metadata.len()).ok_or(TzapError::Format(FormatError::InvalidArchive("TZAP volume size overflow")))?;
        volumes.push(TzapPublicVolumeSummary { path: volume_path.clone(), index, size: metadata.len() });
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
        format: TzapPublicFormatSummary::from_headers(&first_header.volume_header, &first_header.crypto_header),
    })
}

pub(crate) fn open_tzap_archive(archive: impl AsRef<Path>, password: Option<&str>) -> Result<OpenedArchive, TzapError> {
    open_tzap_archive_with_key_options(archive, password, None, None)
}

pub(crate) fn open_tzap_archive_with_recipient_key(archive: impl AsRef<Path>, recipient_private_key: impl AsRef<Path>) -> Result<OpenedArchive, TzapError> {
    open_tzap_archive_with_key_options(archive, None, Some(recipient_private_key.as_ref()), None)
}

pub(crate) fn open_tzap_archive_with_key_options(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    recipient_private_key: Option<&Path>,
    recipient_private_key_bytes: Option<&[u8]>,
) -> Result<OpenedArchive, TzapError> {
    let bytes_list = recipient_private_key_bytes.map(|bytes| vec![bytes.to_vec()]);
    open_tzap_archive_with_key_options_multi(archive, password, recipient_private_key, bytes_list.as_deref())
}

/// Plural form of [`open_tzap_archive_with_key_options`] for a device holding
/// several recipient private keys at once (design §9.4): every candidate's
/// SPKI is tried against each keywrap record, so an archive addressed to any
/// held key -- active or retired -- opens.
pub(crate) fn open_tzap_archive_with_key_options_multi(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    recipient_private_key: Option<&Path>,
    recipient_private_key_bytes_list: Option<&[Vec<u8>]>,
) -> Result<OpenedArchive, TzapError> {
    let archive_path = archive.as_ref();
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume = volume_paths.first().ok_or_else(|| io_error(archive_path, io::ErrorKind::NotFound, "no TZAP input volumes found"))?;
    let kdf_params = read_kdf_params_from_path(first_volume)?;
    let volume_files =
        volume_paths.iter().map(|path| File::open(path).map_err(|source| TzapError::Io { path: path.clone(), source })).collect::<Result<Vec<_>, _>>()?;
    if matches!(kdf_params, KdfParams::RecipientWrap { .. }) {
        if password.is_some() {
            return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
        }
        if recipient_private_key.is_none() && recipient_private_key_bytes_list.is_none() {
            return Err(TzapError::RecipientKeyRequired);
        }
        let lookup = match (recipient_private_key, recipient_private_key_bytes_list) {
            (Some(path), None) => load_recipient_private_key_lookup(path)?,
            (None, Some(bytes_list)) => load_recipient_private_key_lookup_from_bytes_list(bytes_list, "in-memory recipient key")?,
            _ => return Err(TzapError::Format(FormatError::KeyMaterialMismatch)),
        };
        let mut stats = RecipientWrapOpenStats::default();
        return open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
            volume_files,
            |context| Ok(recipient_wrap_candidates_for_record(&context, &lookup, &mut stats)),
            ReaderOptions::default(),
        )
        .map_err(|source| recipient_wrap_open_error(source, &stats));
    }
    if recipient_private_key.is_some() || recipient_private_key_bytes_list.is_some() {
        return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
    }
    let master_key = match (&kdf_params, password) {
        // Deliberate contract: an explicitly empty password ("") is
        // equivalent to no password and opens raw archives with the
        // placeholder master key, so an empty string can never be confused
        // with a real passphrase that happens to derive to the same key.
        // Callers that want confidentiality must reject empty input before
        // reaching this point.
        (KdfParams::None, _) | (KdfParams::Raw, None | Some("")) => placeholder_master_key()?,
        (KdfParams::Argon2id { .. }, Some(password)) => MasterKey::derive_from_passphrase(&kdf_params, password)?,
        (KdfParams::Argon2id { .. }, None) => return Err(TzapError::PasswordRequired),
        (KdfParams::Raw, Some(_)) => {
            return Err(TzapError::Format(FormatError::KeyMaterialMismatch));
        }
        (KdfParams::RecipientWrap { .. }, _) => unreachable!("recipient wrap handled above"),
    };
    if volume_files.len() == 1 {
        let volume_file = volume_files.into_iter().next().ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
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

/// Returns whether the path resolves to at least one existing TZAP input
/// volume under the same discovery rules the archive open path uses.
#[must_use]
pub fn has_existing_tzap_input_volume(path: &Path) -> bool {
    discover_tzap_input_volume_paths(path).iter().any(|candidate| candidate.exists())
}

pub(crate) fn tzap_destination_path_from_volume_path(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    let pattern = parse_volume_file_name(file_name)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Some(parent.join(format!("{}{TZAP_EXTENSION_SUFFIX}", pattern.base)))
}

fn discover_tzap_sibling_volume_paths(path: &Path) -> Option<Vec<PathBuf>> {
    let file_name = path.file_name()?.to_str()?;
    let pattern = parse_volume_file_name(file_name)?;
    Some(discover_tzap_volume_paths_by_base(archive_directory(path), &pattern.base))
}

fn discover_tzap_volume_paths_for_destination(destination: &Path) -> Vec<PathBuf> {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let base_name = multi_volume_base_name(file_name);
    discover_tzap_volume_paths_by_base(archive_directory(destination), &base_name)
}

/// The directory to search for sibling volumes of `path`. A bare relative
/// file name (`archive.vol000.tzap`, no directory component) has
/// `parent() == Some("")`, not `None`, so `unwrap_or_else` never substitutes
/// "." for it -- `read_dir("")` then fails with `NotFound`, which callers
/// here treat as "no siblings found", silently discovering zero volumes for
/// the single most common way to invoke this against an archive in the
/// current directory.
fn archive_directory(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}

fn discover_tzap_volume_paths_by_base(parent: &Path, base_name: &str) -> Vec<PathBuf> {
    discover_sibling_volume_paths(parent, base_name).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub(crate) struct PublicTzapHeader {
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
}

pub(crate) fn expected_tzap_input_volume_paths(requested_path: &Path, first_volume_path: &Path, expected_volume_count: usize) -> Vec<PathBuf> {
    if expected_volume_count <= 1 {
        return vec![first_volume_path.to_path_buf()];
    }

    let base_path =
        tzap_destination_path_from_volume_path(first_volume_path).or_else(|| tzap_destination_path_from_volume_path(requested_path)).unwrap_or_else(|| {
            if first_volume_path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case(TZAP_EXTENSION)) {
                first_volume_path.to_path_buf()
            } else {
                requested_path.to_path_buf()
            }
        });

    (0..expected_volume_count).map(|index| volume_output_path(&base_path, index)).collect()
}

pub(crate) fn read_public_tzap_header(path: &Path) -> Result<PublicTzapHeader, TzapError> {
    let mut file = File::open(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    read_public_tzap_header_from(&mut file, path)
}

/// Reads the public headers through an already-opened handle.
///
/// `path` is used only for error reporting.
pub(crate) fn read_public_tzap_header_from(file: &mut File, path: &Path) -> Result<PublicTzapHeader, TzapError> {
    let (volume_header, crypto_header_bytes) = read_tzap_crypto_header_bytes_from(file, path)?;
    let fixed_bytes = crypto_header_bytes.get(..CRYPTO_HEADER_FIXED_LEN).ok_or(FormatError::InvalidLength {
        structure: "CryptoHeaderFixed",
        expected: CRYPTO_HEADER_FIXED_LEN,
        actual: crypto_header_bytes.len(),
    })?;
    let crypto_header = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ")));
    }

    Ok(PublicTzapHeader { volume_header, crypto_header, crypto_header_bytes })
}

pub(crate) fn read_tzap_crypto_header_bytes(path: &Path) -> Result<(VolumeHeader, Vec<u8>), TzapError> {
    let mut file = File::open(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    read_tzap_crypto_header_bytes_from(&mut file, path)
}

/// Reads the volume and crypto headers through an already-opened handle.
///
/// `path` is used only for error reporting.
pub(crate) fn read_tzap_crypto_header_bytes_from(file: &mut File, path: &Path) -> Result<(VolumeHeader, Vec<u8>), TzapError> {
    let mut header_bytes = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = u64::from(volume_header.crypto_header_offset);
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset)).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    Ok((volume_header, crypto_header_bytes))
}

fn read_kdf_params_from_path(path: &Path) -> Result<KdfParams, TzapError> {
    let (volume_header, crypto_header_bytes) = read_tzap_crypto_header_bytes(path)?;
    let fixed_bytes = crypto_header_bytes.get(..CRYPTO_HEADER_FIXED_LEN).ok_or(FormatError::InvalidLength {
        structure: "CryptoHeaderFixed",
        expected: CRYPTO_HEADER_FIXED_LEN,
        actual: crypto_header_bytes.len(),
    })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(TzapError::Format(FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ")));
    }
    let crypto_header = CryptoHeader::parse(&crypto_header_bytes, volume_header.crypto_header_length)?;
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

#[cfg(test)]
mod tests {
    use super::{archive_directory, is_tzap_archive_path};
    use std::path::Path;

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
    fn unicode_non_tzap_name_is_safe_to_classify() {
        assert!(!is_tzap_archive_path(Path::new("游戏存档管理器.zip")));
    }

    /// Regression test for a silent sibling-volume discovery failure: a bare
    /// relative file name (no directory component, e.g. invoking the CLI
    /// from inside the archive's own directory) has `Path::parent() ==
    /// Some("")`, not `None`. `unwrap_or_else` only substitutes "." on
    /// `None`, so this used to pass an empty path straight through to
    /// `read_dir`, which fails with `NotFound` and was silently treated as
    /// "no sibling volumes found" instead of "every volume is present".
    #[test]
    fn archive_directory_normalizes_bare_relative_file_name_to_current_dir() {
        assert_eq!(archive_directory(Path::new("archive.vol000.tzap")), Path::new("."));
        assert_eq!(archive_directory(Path::new("./archive.vol000.tzap")), Path::new("."));
        assert_eq!(archive_directory(Path::new("subdir/archive.vol000.tzap")), Path::new("subdir"));
        assert_eq!(archive_directory(Path::new("/abs/subdir/archive.vol000.tzap")), Path::new("/abs/subdir"));
    }

    #[test]
    fn discover_tzap_sibling_volume_paths_finds_bare_relative_siblings() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = format!("zm_bare_sibling_{unique}");
        let vol0_name = format!("{base}.vol000.tzap");
        let vol1_name = format!("{base}.vol001.tzap");
        let vol0 = std::path::PathBuf::from(&vol0_name);
        let vol1 = std::path::PathBuf::from(&vol1_name);
        let _ = std::fs::remove_file(&vol0);
        let _ = std::fs::remove_file(&vol1);
        std::fs::write(&vol0, b"vol0").unwrap();
        std::fs::write(&vol1, b"vol1").unwrap();

        struct Cleanup(Vec<std::path::PathBuf>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for p in &self.0 {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        let _guard = Cleanup(vec![vol0.clone(), vol1.clone()]);

        let discovered = super::discover_tzap_sibling_volume_paths(Path::new(&vol0_name));
        assert!(discovered.is_some(), "failed to discover bare sibling volumes");
        let volumes = discovered.unwrap();
        assert_eq!(volumes, vec![std::path::PathBuf::from(".").join(&vol0_name), std::path::PathBuf::from(".").join(&vol1_name)]);
    }
}
