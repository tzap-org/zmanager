use crate::ar_backend;
use crate::archive_format::{self, ArchiveFormatKind};
use crate::jobs::{JobCancelled, JobContext};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::temp_names::{TempDirAllocError, TemporaryDirectory};
use std::collections::BTreeSet;
use std::fmt;
#[cfg(any(unix, test))]
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const DEB_TEMP_PREFIX: &str = "zmanager-deb";
const DEBIAN_BINARY_MEMBER: &str = "debian-binary";
const CONTROL_PAYLOAD_BASE: &str = "control.tar";
const CONTROL_PAYLOAD_GLOB: &str = "control.tar[.*]";
const DATA_PAYLOAD_BASE: &str = "data.tar";
const DATA_PAYLOAD_GLOB: &str = "data.tar[.*]";
const MAX_DEBIAN_BINARY_BYTES: u64 = 64 * 1024;
const CONTROL_OUTPUT_DIR: &str = "control";
const DATA_OUTPUT_DIR: &str = "data";

/// Nested `.deb` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DebExtractReport {
    /// Entries written to disk.
    pub written_entries: usize,
    /// Entries skipped by policy.
    pub skipped_entries: usize,
    /// Regular file bytes copied.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Error returned by the `.deb` payload extractor.
#[derive(Debug)]
pub enum DebError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Native engine extraction failed.
    Engine(crate::engine::ArchiveError),
    /// Native AR parsing or member extraction failed.
    Ar(ar_backend::ArError),
    /// Shared TAR payload extraction failed.
    Tar(crate::tar_backend::TarError),
    /// Shared compression decoder failed.
    RawStream(crate::raw_stream_backend::RawStreamError),
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A required `.deb` member was missing.
    MissingMember { member: &'static str },
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Engine(source) => write!(f, "nested archive engine extraction failed: {source}"),
            Self::Ar(source) => write!(f, "deb AR container failed: {source}"),
            Self::Tar(source) => write!(f, "deb TAR payload failed: {source}"),
            Self::RawStream(source) => write!(f, "deb payload decoder failed: {source}"),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingMember { member } => write!(f, "deb package is missing {member}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for DebError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Engine(source) => Some(source),
            Self::Ar(source) => Some(source),
            Self::Tar(source) => Some(source),
            Self::RawStream(source) => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingMember { .. } | Self::Cancelled => None,
        }
    }
}

impl From<JobCancelled> for DebError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<crate::engine::ArchiveError> for DebError {
    fn from(source: crate::engine::ArchiveError) -> Self {
        Self::Engine(source)
    }
}

impl From<ar_backend::ArError> for DebError {
    fn from(source: ar_backend::ArError) -> Self {
        Self::Ar(source)
    }
}

impl From<crate::tar_backend::TarError> for DebError {
    fn from(source: crate::tar_backend::TarError) -> Self {
        Self::Tar(source)
    }
}

impl From<crate::raw_stream_backend::RawStreamError> for DebError {
    fn from(source: crate::raw_stream_backend::RawStreamError) -> Self {
        Self::RawStream(source)
    }
}

impl From<ExtractionSafetyError> for DebError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Extracts a `.deb` into a package-aware layout:
///
/// - `debian-binary` at the destination root
/// - `control.tar.*` expanded under `control/`
/// - `data.tar.*` expanded under `data/`
///
/// # Errors
///
/// Returns [`DebError`] when the package is malformed, a payload archive cannot
/// be read, a safety policy rejects an entry, or filesystem writes fail.
pub fn extract_deb_nested(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: &ExtractionPolicy) -> Result<DebExtractReport, DebError> {
    extract_deb_nested_inner(archive_path, destination, policy, None, None)
}

/// Extracts a `.deb` package-aware layout with an overwrite resolver.
///
/// # Errors
///
/// Returns [`DebError`] when the package is malformed, a payload archive cannot
/// be read, a safety policy rejects an entry, filesystem writes fail, or the
/// resolver aborts extraction.
pub fn extract_deb_nested_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: &ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<DebExtractReport, DebError> {
    extract_deb_nested_inner(archive_path, destination, policy, Some(overwrite_resolver), None)
}

/// Extracts a `.deb` package-aware layout with a reporting context, and
/// optionally an overwrite resolver.
///
/// # Errors
///
/// Returns [`DebError`] when the package is malformed, a payload archive cannot
/// be read, a safety policy rejects an entry, filesystem writes fail, the
/// resolver aborts extraction, or the job is cancelled.
pub(crate) fn extract_deb_nested_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: &ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<DebExtractReport, DebError> {
    extract_deb_nested_inner(archive_path, destination, policy, overwrite_resolver, context)
}

fn extract_deb_nested_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: &ExtractionPolicy,
    mut overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<DebExtractReport, DebError> {
    let destination = destination.as_ref();
    let destination_root = crate::safety::prepare_destination_root(destination).map_err(|source| DebError::Io { path: destination.to_path_buf(), source })?;

    let archive_path = archive_path.as_ref();
    let temp = TemporaryDirectory::new(DEB_TEMP_PREFIX)?;
    let members = ar_backend::list(archive_path)?;
    validate_member_layout(archive_path, &members)?;
    let debian_binary =
        materialize_member(archive_path, &members, DEBIAN_BINARY_MEMBER, temp.path())?.ok_or(DebError::MissingMember { member: DEBIAN_BINARY_MEMBER })?;
    let control_member = materialize_payload_member(archive_path, &members, CONTROL_PAYLOAD_BASE, CONTROL_PAYLOAD_GLOB, temp.path())?;
    let data_member = materialize_payload_member(archive_path, &members, DATA_PAYLOAD_BASE, DATA_PAYLOAD_GLOB, temp.path())?;

    let mut report = DebExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

    match overwrite_resolver {
        Some(ref mut resolver) => {
            copy_synthetic_file(
                &debian_binary,
                DEBIAN_BINARY_MEMBER,
                &destination_root,
                policy.clone(),
                Some(&mut **resolver),
                &mut report,
                context.as_deref_mut(),
            )?;
        }
        None => copy_synthetic_file(&debian_binary, DEBIAN_BINARY_MEMBER, &destination_root, policy.clone(), None, &mut report, context.as_deref_mut())?,
    }

    let control_policy = policy_with_remaining_budget(policy, &report);
    let control_report = match overwrite_resolver {
        Some(ref mut resolver) => {
            extract_payload_archive(&control_member, &destination_root.join(CONTROL_OUTPUT_DIR), control_policy, Some(&mut **resolver), context.as_deref_mut())?
        }
        None => extract_payload_archive(&control_member, &destination_root.join(CONTROL_OUTPUT_DIR), control_policy, None, context.as_deref_mut())?,
    };
    absorb_archive_report(CONTROL_OUTPUT_DIR, control_report, &mut report);

    // Cancelling right after control.tar finishes must not fall through to a
    // full (often much larger) data.tar extraction.
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
    }

    let data_policy = policy_with_remaining_budget(policy, &report);
    let data_report = match overwrite_resolver {
        Some(ref mut resolver) => {
            extract_payload_archive(&data_member, &destination_root.join(DATA_OUTPUT_DIR), data_policy, Some(&mut **resolver), context.as_deref_mut())?
        }
        None => extract_payload_archive(&data_member, &destination_root.join(DATA_OUTPUT_DIR), data_policy, None, context)?,
    };
    absorb_archive_report(DATA_OUTPUT_DIR, data_report, &mut report);

    Ok(report)
}

pub(crate) fn validate_member_layout(archive_path: &Path, members: &[ar_backend::ArEntry]) -> Result<(), DebError> {
    let mut names = BTreeSet::new();
    for member in members {
        if !names.insert(member.path.as_str()) {
            return Err(invalid_layout(archive_path, format!("duplicate DEB member {}", member.path)));
        }
    }

    let Some(debian_binary) = members.first().filter(|entry| entry.path == DEBIAN_BINARY_MEMBER) else {
        return Err(DebError::MissingMember { member: DEBIAN_BINARY_MEMBER });
    };
    if debian_binary.size > MAX_DEBIAN_BINARY_BYTES {
        return Err(invalid_layout(archive_path, "debian-binary is unreasonably large".to_owned()));
    }
    let mut version = Vec::with_capacity(usize::try_from(debian_binary.size).unwrap_or(0));
    ar_backend::copy(archive_path, debian_binary.index, &mut version)?;
    validate_debian_binary_version(archive_path, &version)?;

    let control = validate_single_payload_member(archive_path, members, CONTROL_PAYLOAD_BASE, CONTROL_PAYLOAD_GLOB)?;
    let data = validate_single_payload_member(archive_path, members, DATA_PAYLOAD_BASE, DATA_PAYLOAD_GLOB)?;
    if control.index >= data.index {
        return Err(invalid_layout(archive_path, "control payload must precede the data payload".to_owned()));
    }
    Ok(())
}

pub(crate) fn test_payload_members(archive_path: &Path, members: &[ar_backend::ArEntry], options: &crate::engine::TestOptions) -> Result<(), DebError> {
    let temporary = TemporaryDirectory::new("zmanager-deb-test")?;
    for (base, required_name) in [(CONTROL_PAYLOAD_BASE, CONTROL_PAYLOAD_GLOB), (DATA_PAYLOAD_BASE, DATA_PAYLOAD_GLOB)] {
        let member = validate_single_payload_member(archive_path, members, base, required_name)?;
        if !options.selects(&member.path) {
            continue;
        }
        let payload = materialize_payload_member(archive_path, members, base, required_name, temporary.path())?;
        let engine = crate::engine::create_default_engine()?;
        let source = crate::engine::ArchiveSource::from_path_autodetect(&payload);
        let mut handle = engine.open(source, crate::engine::OpenOptions::default())?;
        let nested_options = crate::engine::TestOptions { cancellation: options.cancellation.clone(), ..crate::engine::TestOptions::default() };
        handle.test(&nested_options)?;
        handle.close()?;
    }
    Ok(())
}

fn validate_single_payload_member<'a>(
    archive_path: &Path,
    members: &'a [ar_backend::ArEntry],
    base: &str,
    required_name: &'static str,
) -> Result<&'a ar_backend::ArEntry, DebError> {
    let mut matches = members.iter().filter(|entry| is_payload_member(&entry.path, base));
    let Some(member) = matches.next() else {
        return Err(DebError::MissingMember { member: required_name });
    };
    if matches.next().is_some() {
        return Err(invalid_layout(archive_path, format!("multiple DEB payload members match {required_name}")));
    }
    if member.path.bytes().any(|byte| matches!(byte, b'/' | b'\\')) {
        return Err(invalid_layout(archive_path, format!("DEB payload member name is not a top-level name: {}", member.path)));
    }
    Ok(member)
}

fn validate_debian_binary_version(archive_path: &Path, contents: &[u8]) -> Result<(), DebError> {
    let first_line = contents.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let version = std::str::from_utf8(first_line).map_err(|_| invalid_layout(archive_path, "debian-binary version is not UTF-8".to_owned()))?;
    let major = version.split_once('.').map_or(version, |(major, _)| major);
    if major != "2" {
        return Err(invalid_layout(archive_path, format!("unsupported debian-binary major version {major:?}")));
    }
    Ok(())
}

fn is_payload_member(name: &str, base: &str) -> bool {
    name == base || name.strip_prefix(base).is_some_and(|suffix| suffix.starts_with('.'))
}

fn invalid_layout(archive_path: &Path, message: String) -> DebError {
    DebError::Ar(ar_backend::ArError::Invalid { path: archive_path.to_path_buf(), message })
}

fn policy_with_remaining_budget(policy: &ExtractionPolicy, report: &DebExtractReport) -> ExtractionPolicy {
    let mut remaining = policy.clone();
    if let Some(limit) = policy.limits.max_expanded_bytes {
        remaining.limits.max_expanded_bytes = Some(limit.saturating_sub(report.written_bytes));
    }
    if let Some(limit) = policy.limits.max_entries {
        remaining.limits.max_entries = Some(limit.saturating_sub(u64::try_from(report.written_entries).unwrap_or(u64::MAX)));
    }
    remaining
}

fn copy_synthetic_file(
    source_path: &Path,
    archive_path: &str,
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    report: &mut DebExtractReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), DebError> {
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
    }
    let source_metadata = source_path.symlink_metadata().map_err(|source| DebError::Io { path: source_path.to_path_buf(), source })?;
    let source_size = source_metadata.len();
    let entry = ExtractionEntry {
        archive_path: archive_path.to_owned(),
        kind: ExtractionEntryKind::File,
        uncompressed_size: Some(source_size),
        compressed_size: Some(source_size),
    };
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(destination, policy, resolver),
        None => ExtractionSafetyPlanner::new(destination, policy),
    };
    match planner.validate_entry(&entry)? {
        ExtractionDecision::Write { destination_path, replace_existing, .. } => {
            let mut input = File::open(source_path).map_err(|source| DebError::Io { path: source_path.to_path_buf(), source })?;
            let mut output =
                crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| DebError::Io { path: destination_path.clone(), source })?;
            let written_bytes = io::copy(&mut input, output.file_mut().map_err(|source| DebError::Io { path: destination_path.clone(), source })?)
                .map_err(|source| DebError::Io { path: destination_path.clone(), source })?;
            output.commit_with_replace(replace_existing).map_err(|source| DebError::Io { path: destination_path.clone(), source })?;

            // Mode and mtime go through the shared metadata application so
            // every backend restores modes (including privileged bits) the
            // same way (CR-034).
            #[cfg(unix)]
            let source_mode = {
                use std::os::unix::fs::PermissionsExt as _;
                Some(source_metadata.permissions().mode())
            };
            #[cfg(not(unix))]
            let source_mode = source_metadata.permissions().readonly().then_some(0o444);
            let mtime = source_metadata.modified().map_err(|source| DebError::Io { path: source_path.to_path_buf(), source })?;
            crate::extract_materialize::apply_metadata(&destination_path, source_mode, Some(filetime::FileTime::from_system_time(mtime)))
                .map_err(|source| DebError::Io { path: destination_path.clone(), source })?;

            report.written_entries += 1;
            report.written_bytes += written_bytes;
            if let Some(context) = context {
                context.entry_finished(archive_path, written_bytes);
            }
        }
        ExtractionDecision::Skip { reason, .. } => {
            report.skipped_entries += 1;
            report.warnings.push(format!("skipped {archive_path}: {reason}"));
        }
    }
    Ok(())
}

fn extract_payload_archive(
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<ArchiveReport, DebError> {
    extract_payload_with_engine(archive_path, destination, policy, overwrite_resolver, context)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ArchiveReport {
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    warnings: Vec<String>,
}

fn extract_payload_with_engine(
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<ArchiveReport, DebError> {
    // `JobContext` already wraps the cancellation token; cloning it here lets
    // the nested `tar_backend::extract` call observe cancellation the same
    // way every other format's context-carrying call does.
    let cancellation = context.as_deref().map(JobContext::cancellation_token);
    let report = match archive_format::detect_archive_format(archive_path) {
        ArchiveFormatKind::Tar => {
            let file = File::open(archive_path).map_err(|source| DebError::Io { path: archive_path.to_path_buf(), source })?;
            crate::tar_backend::extract(file, archive_path, destination, policy, overwrite_resolver, None, cancellation.as_ref(), context.as_deref_mut())?
        }
        ArchiveFormatKind::TarGz => {
            let file = File::open(archive_path).map_err(|source| DebError::Io { path: archive_path.to_path_buf(), source })?;
            crate::tar_backend::extract(
                crate::tar_backend::Decoded(flate2::read::GzDecoder::new(file)),
                archive_path,
                destination,
                policy,
                overwrite_resolver,
                None,
                cancellation.as_ref(),
                context.as_deref_mut(),
            )?
        }
        ArchiveFormatKind::TarZst => {
            let file = File::open(archive_path).map_err(|source| DebError::Io { path: archive_path.to_path_buf(), source })?;
            let decoder = zstd::stream::read::Decoder::new(file).map_err(|source| DebError::Io { path: archive_path.to_path_buf(), source })?;
            crate::tar_backend::extract(
                crate::tar_backend::Decoded(decoder),
                archive_path,
                destination,
                policy,
                overwrite_resolver,
                None,
                cancellation.as_ref(),
                context.as_deref_mut(),
            )?
        }
        ArchiveFormatKind::TarBz2 | ArchiveFormatKind::TarXz | ArchiveFormatKind::TarLzma => {
            let format = match archive_format::detect_archive_format(archive_path) {
                ArchiveFormatKind::TarBz2 => crate::raw_stream_backend::RawStreamFormat::Bzip2,
                ArchiveFormatKind::TarXz => crate::raw_stream_backend::RawStreamFormat::Xz,
                ArchiveFormatKind::TarLzma => crate::raw_stream_backend::RawStreamFormat::Lzma,
                _ => unreachable!("outer match limits filtered TAR formats"),
            };
            let decoder = crate::raw_stream_backend::open_decoder(archive_path, format)?;
            crate::tar_backend::extract(
                crate::tar_backend::Decoded(decoder),
                archive_path,
                destination,
                policy,
                overwrite_resolver,
                None,
                cancellation.as_ref(),
                context,
            )?
        }
        format => {
            return Err(DebError::Engine(crate::engine::ArchiveError::usable(
                crate::engine::ErrorKind::UnsupportedOperation,
                format!("unsupported native DEB payload format: {format:?}"),
            )));
        }
    };
    Ok(ArchiveReport { written_entries: report.entries, skipped_entries: report.skipped_entries, written_bytes: report.bytes, warnings: report.warnings })
}

fn absorb_archive_report(prefix: &str, source: ArchiveReport, destination: &mut DebExtractReport) {
    destination.written_entries += source.written_entries;
    destination.skipped_entries += source.skipped_entries;
    destination.written_bytes += source.written_bytes;
    destination.warnings.extend(source.warnings.into_iter().map(|warning| format!("{prefix}: {warning}")));
}

fn materialize_member(archive_path: &Path, members: &[ar_backend::ArEntry], member_name: &str, destination: &Path) -> Result<Option<PathBuf>, DebError> {
    let Some(member) = members.iter().find(|entry| entry.path == member_name) else {
        return Ok(None);
    };
    let path = destination.join(member_name);
    let mut output = File::create(&path).map_err(|source| DebError::Io { path: path.clone(), source })?;
    ar_backend::copy(archive_path, member.index, &mut output)?;
    apply_ar_metadata(&path, member)?;
    Ok(Some(path))
}

fn materialize_payload_member(
    archive_path: &Path,
    members: &[ar_backend::ArEntry],
    base: &str,
    required_name: &'static str,
    destination: &Path,
) -> Result<PathBuf, DebError> {
    let member = members.iter().find(|entry| is_payload_member(&entry.path, base)).ok_or(DebError::MissingMember { member: required_name })?;
    if member.path.bytes().any(|byte| matches!(byte, b'/' | b'\\')) {
        return Err(DebError::Ar(ar_backend::ArError::Invalid {
            path: archive_path.to_path_buf(),
            message: format!("DEB payload member name is not a top-level name: {}", member.path),
        }));
    }
    let path = destination.join(&member.path);
    let mut output = File::create(&path).map_err(|source| DebError::Io { path: path.clone(), source })?;
    ar_backend::copy(archive_path, member.index, &mut output)?;
    apply_ar_metadata(&path, member)?;
    Ok(path)
}

fn apply_ar_metadata(path: &Path, member: &ar_backend::ArEntry) -> Result<(), DebError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(member.mode & 0o7777)).map_err(|source| DebError::Io { path: path.to_path_buf(), source })?;
    }
    filetime::set_file_mtime(path, filetime::FileTime::from_system_time(UNIX_EPOCH + Duration::from_secs(member.modified)))
        .map_err(|source| DebError::Io { path: path.to_path_buf(), source })?;
    Ok(())
}

impl From<TempDirAllocError> for DebError {
    fn from(error: TempDirAllocError) -> Self {
        Self::Io { path: error.path, source: error.source }
    }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::jobs::CancellationToken;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn build_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            for &(name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, name, data).unwrap();
            }
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    fn build_tar_zst(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        {
            let mut tar = tar::Builder::new(&mut encoder);
            for &(name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, name, data).unwrap();
            }
            tar.finish().unwrap();
        }
        encoder.finish().unwrap()
    }

    fn build_ar_header(name: &str, size: usize) -> [u8; 60] {
        let mut header = [b' '; 60];
        let name_bytes = name.as_bytes();
        header[0..name_bytes.len().min(16)].copy_from_slice(&name_bytes[0..name_bytes.len().min(16)]);
        header[16..26].copy_from_slice(b"1700000000");
        header[28..29].copy_from_slice(b"0");
        header[34..35].copy_from_slice(b"0");
        header[40..46].copy_from_slice(b"100644");
        let size_str = format!("{size}");
        header[48..48 + size_str.len()].copy_from_slice(size_str.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        header
    }

    fn build_deb(debian_binary: Option<&[u8]>, control_gz: Option<&[u8]>, data_zst: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"!<arch>\n");

        if let Some(db) = debian_binary {
            bytes.extend_from_slice(&build_ar_header("debian-binary", db.len()));
            bytes.extend_from_slice(db);
            if db.len() % 2 == 1 {
                bytes.push(b'\n');
            }
        }
        if let Some(ctrl) = control_gz {
            bytes.extend_from_slice(&build_ar_header("control.tar.gz", ctrl.len()));
            bytes.extend_from_slice(ctrl);
            if ctrl.len() % 2 == 1 {
                bytes.push(b'\n');
            }
        }
        if let Some(dt) = data_zst {
            bytes.extend_from_slice(&build_ar_header("data.tar.zst", dt.len()));
            bytes.extend_from_slice(dt);
            if dt.len() % 2 == 1 {
                bytes.push(b'\n');
            }
        }
        bytes
    }

    #[test]
    fn test_extract_deb_nested_complete() {
        let temp = TestDir::new("deb-backend-test");
        let archive_path = temp.path("sample.deb");

        let control_bytes = build_tar_gz(&[("control", b"Package: test\nVersion: 1.0\n")]);
        let data_bytes = build_tar_zst(&[("usr/bin/app", b"binary payload here")]);
        let deb_bytes = build_deb(Some(b"2.0\n"), Some(&control_bytes), Some(&data_bytes));
        fs::write(&archive_path, deb_bytes).unwrap();

        let dest = temp.path("out");
        let policy = ExtractionPolicy::default();
        let report = extract_deb_nested(&archive_path, &dest, &policy).unwrap();

        assert_eq!(report.written_entries, 3);
        assert_eq!(fs::read(dest.join("debian-binary")).unwrap(), b"2.0\n");
        assert_eq!(fs::read(dest.join("control/control")).unwrap(), b"Package: test\nVersion: 1.0\n");
        assert_eq!(fs::read(dest.join("data/usr/bin/app")).unwrap(), b"binary payload here");
    }

    #[test]
    fn test_deb_missing_members_and_errors() {
        let temp = TestDir::new("deb-backend-errors");

        // Missing control
        let data_bytes = build_tar_zst(&[("file.txt", b"content")]);
        let deb_no_control = build_deb(Some(b"2.0\n"), None, Some(&data_bytes));
        let p1 = temp.path("no_control.deb");
        fs::write(&p1, deb_no_control).unwrap();
        assert!(matches!(extract_deb_nested(&p1, temp.path("out1"), &ExtractionPolicy::default()), Err(DebError::MissingMember { .. })));

        // Missing data
        let control_bytes = build_tar_gz(&[("control", b"test")]);
        let deb_no_data = build_deb(Some(b"2.0\n"), Some(&control_bytes), None);
        let p2 = temp.path("no_data.deb");
        fs::write(&p2, deb_no_data).unwrap();
        assert!(matches!(extract_deb_nested(&p2, temp.path("out2"), &ExtractionPolicy::default()), Err(DebError::MissingMember { .. })));

        // debian-binary is the required first member of a new-format package.
        let deb_no_bin = build_deb(None, Some(&control_bytes), Some(&data_bytes));
        let p3 = temp.path("no_bin.deb");
        fs::write(&p3, deb_no_bin).unwrap();
        assert!(matches!(extract_deb_nested(&p3, temp.path("out3"), &ExtractionPolicy::default()), Err(DebError::MissingMember { .. })));

        // Error types & Display coverage
        let err_missing = DebError::MissingMember { member: "control.tar.*" };
        assert!(err_missing.to_string().contains("missing control.tar.*"));
        assert!(std::error::Error::source(&err_missing).is_none());

        let io_err = DebError::Io { path: PathBuf::from("a.deb"), source: io::Error::new(io::ErrorKind::NotFound, "err") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());
    }

    fn sample_deb_bytes() -> Vec<u8> {
        let control_bytes = build_tar_gz(&[("control", b"Package: test\nVersion: 1.0\n")]);
        let data_bytes = build_tar_zst(&[("usr/bin/app", b"binary payload here")]);
        build_deb(Some(b"2.0\n"), Some(&control_bytes), Some(&data_bytes))
    }

    #[test]
    fn cancelling_when_data_tar_entry_starts_leaves_it_unwritten() {
        let temp = TestDir::new("deb-cancel-mid-data");
        let archive_path = temp.path("sample.deb");
        fs::write(&archive_path, sample_deb_bytes()).unwrap();

        let dest = temp.path("out");
        let policy = ExtractionPolicy::default();

        let token = CancellationToken::new();
        let cancel = token.clone();
        // `EntryStarted` fires before any payload bytes are copied, so
        // cancelling here interrupts data.tar's only entry at its first
        // decoded chunk, well after control.tar has already finished.
        let mut sink = |event| {
            if let crate::jobs::JobEvent::EntryStarted { path, .. } = &event
                && path == "usr/bin/app"
            {
                cancel.cancel();
            }
        };
        let mut context = JobContext::new(&token, &mut sink);

        let error = extract_deb_nested_with_context(&archive_path, &dest, &policy, None, Some(&mut context)).unwrap_err();

        assert!(matches!(error, DebError::Tar(crate::tar_backend::TarError::Cancelled)), "{error}");
        assert_eq!(
            fs::read(dest.join("control/control")).unwrap(),
            b"Package: test\nVersion: 1.0\n",
            "control.tar must have completed before data.tar started"
        );
        assert!(!dest.join("data/usr/bin/app").exists(), "the interrupted data.tar entry must not be written");
    }

    #[test]
    fn cancelling_right_after_control_finishes_skips_data_extraction() {
        let temp = TestDir::new("deb-cancel-after-control");
        let archive_path = temp.path("sample.deb");
        fs::write(&archive_path, sample_deb_bytes()).unwrap();

        let dest = temp.path("out");
        let policy = ExtractionPolicy::default();

        let token = CancellationToken::new();
        let cancel = token.clone();
        let mut sink = |event| {
            if let crate::jobs::JobEvent::EntryFinished { path, .. } = &event
                && path == "control"
            {
                cancel.cancel();
            }
        };
        let mut context = JobContext::new(&token, &mut sink);

        let error = extract_deb_nested_with_context(&archive_path, &dest, &policy, None, Some(&mut context)).unwrap_err();

        assert!(matches!(error, DebError::Cancelled), "{error}");
        assert_eq!(fs::read(dest.join("control/control")).unwrap(), b"Package: test\nVersion: 1.0\n");
        assert!(!dest.join("data").exists(), "cancelling right after control.tar finishes must skip data.tar entirely");
    }
}
