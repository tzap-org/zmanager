//! Decoder-agnostic TAR read operations shared by native TAR adapters.

use crate::archive_browser::BrowserEntryKind;
use crate::extract_materialize::DeferredHardlink;
use crate::jobs::{CancellationToken, JobCancelled, JobContext};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, OverwriteResolver};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

const TAR_BLOCK_BYTES: usize = 512;

/// Observes zero records read at structural TAR header boundaries.
///
/// Validation uses `tar::Archive::entries_with_seek` without reading regular
/// file payloads, so 512-byte reads here are headers (or extension metadata),
/// never ordinary entry contents. Tracking offsets prevents zero-filled
/// extension data from being confused with consecutive end records.
struct TarStructureObserver<R> {
    inner: R,
    last_observed_end: Option<u64>,
    zero_run_start: Option<u64>,
    zero_run_bytes: u64,
    consecutive_zero_records: usize,
}

impl<R> TarStructureObserver<R> {
    fn new(inner: R) -> Self {
        Self { inner, last_observed_end: None, zero_run_start: None, zero_run_bytes: 0, consecutive_zero_records: 0 }
    }
}

impl<R: Read + Seek> Read for TarStructureObserver<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let offset = self.inner.stream_position()?;
        let read = self.inner.read(output)?;
        if self.last_observed_end != Some(offset) {
            self.zero_run_start = None;
            self.zero_run_bytes = 0;
        }
        for (index, byte) in output[..read].iter().enumerate() {
            let byte_offset = offset.saturating_add(index as u64);
            if *byte == 0 {
                self.zero_run_start.get_or_insert(byte_offset);
                self.zero_run_bytes = self.zero_run_bytes.saturating_add(1);
            } else {
                self.zero_run_start = None;
                self.zero_run_bytes = 0;
            }
        }
        self.last_observed_end = Some(offset.saturating_add(read as u64));
        self.consecutive_zero_records = self.zero_run_start.map_or(0, |start| {
            let block_bytes = TAR_BLOCK_BYTES as u64;
            let first_full_block = start.saturating_add(block_bytes - 1) / block_bytes * block_bytes;
            let run_end = start.saturating_add(self.zero_run_bytes);
            usize::try_from(run_end.saturating_sub(first_full_block) / block_bytes).unwrap_or(usize::MAX)
        });
        Ok(read)
    }
}

impl<R: Seek> Seek for TarStructureObserver<R> {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

/// One normalized TAR listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarEntry {
    /// Archive-order index used as the retained engine entry ID.
    pub index: usize,
    /// Archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Uncompressed payload size when present.
    pub size: Option<u64>,
    /// Modification time in seconds since the Unix epoch.
    pub modified: Option<String>,
    /// Portable Unix mode bits.
    pub mode: Option<u32>,
    /// Link target for symlink and hardlink entries.
    pub link_target: Option<String>,
}

/// Normalized TAR operation report.
pub type TarReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by shared TAR read operations.
#[derive(Debug)]
pub enum TarError {
    /// Filesystem or decoder I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// A TAR link entry omitted its target.
    MissingLinkTarget { archive_path: String },
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for TarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingLinkTarget { archive_path } => write!(f, "tar link entry has no target: {archive_path}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingLinkTarget { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for TarError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for TarError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

/// Lists entries from any TAR-compatible decoder.
pub fn list<R: Read>(reader: R, archive_path: &Path) -> Result<Vec<TarEntry>, TarError> {
    list_with_temp_root(reader, archive_path, None)
}

/// Lists entries using an optional caller-owned temporary root.
pub fn list_with_temp_root<R: Read>(reader: R, archive_path: &Path, temp_root: Option<&Path>) -> Result<Vec<TarEntry>, TarError> {
    let (_temporary, reader) = spool_validated_tar(reader, archive_path, &|| false, temp_root)?;
    let mut archive = tar::Archive::new(reader);
    archive
        .entries()
        .map_err(|source| io_error(archive_path, source))?
        .enumerate()
        .map(|(index, entry)| {
            let mut entry = entry.map_err(|source| io_error(archive_path, source))?;
            let path = entry_path(&mut entry, archive_path)?;
            let kind = entry_kind(&mut entry, &path)?;
            Ok(TarEntry {
                index,
                path,
                kind: browser_kind(&kind),
                size: entry.header().size().ok(),
                modified: entry.header().mtime().ok().map(|value| value.to_string()),
                mode: entry.header().mode().ok(),
                link_target: entry.link_name().ok().flatten().map(|value| value.to_string_lossy().into_owned()),
            })
        })
        .collect()
}

/// Verifies payloads from any TAR-compatible decoder.
pub fn test<R: Read>(reader: R, archive_path: &Path, selects: impl Fn(&str) -> bool, is_cancelled: impl Fn() -> bool) -> Result<TarReport, TarError> {
    test_with_temp_root(reader, archive_path, selects, is_cancelled, None)
}

/// Verifies payloads using an optional caller-owned temporary root.
pub fn test_with_temp_root<R: Read>(
    reader: R,
    archive_path: &Path,
    selects: impl Fn(&str) -> bool,
    is_cancelled: impl Fn() -> bool,
    temp_root: Option<&Path>,
) -> Result<TarReport, TarError> {
    let (_temporary, reader) = spool_validated_tar(reader, archive_path, &is_cancelled, temp_root)?;
    let mut archive = tar::Archive::new(reader);
    let mut report = TarReport::default();
    for entry in archive.entries().map_err(|source| io_error(archive_path, source))? {
        if is_cancelled() {
            return Err(TarError::Cancelled);
        }
        let mut entry = entry.map_err(|source| io_error(archive_path, source))?;
        let path = entry_path(&mut entry, archive_path)?;
        if !selects(&path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if entry.header().entry_type().is_file() {
            let bytes = io::copy(&mut entry, &mut io::sink()).map_err(|source| io_error(archive_path, source))?;
            report.bytes = report.bytes.saturating_add(bytes);
        }
        report.entries = report.entries.saturating_add(1);
    }
    Ok(report)
}

/// Extracts all entries, or one retained archive-order entry, from any TAR-compatible decoder.
#[allow(clippy::too_many_arguments)]
pub fn extract<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_index: Option<usize>,
    cancellation: Option<&CancellationToken>,
    context: Option<&mut JobContext<'_>>,
) -> Result<TarReport, TarError> {
    extract_with_temp_root(reader, archive_path, destination, policy, resolver, selected_index, cancellation, context, None)
}

/// Extracts using an optional caller-owned temporary root.
#[allow(clippy::too_many_arguments)]
pub fn extract_with_temp_root<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_index: Option<usize>,
    cancellation: Option<&CancellationToken>,
    context: Option<&mut JobContext<'_>>,
    temp_root: Option<&Path>,
) -> Result<TarReport, TarError> {
    extract_with_selector(reader, archive_path, destination, policy, resolver, selected_index.map(TarSelection::Index), cancellation, context, temp_root)
}

/// Extracts one retained TAR entry by its path and duplicate occurrence in the
/// session listing.
#[allow(clippy::too_many_arguments)]
pub fn extract_by_path_occurrence<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selector: TarEntrySelector<'_>,
    cancellation: Option<&CancellationToken>,
    context: Option<&mut JobContext<'_>>,
) -> Result<TarReport, TarError> {
    extract_by_path_occurrence_with_temp_root(reader, archive_path, destination, policy, resolver, selector, cancellation, context, None)
}

/// Extracts one retained TAR entry using an optional caller-owned temporary root.
#[allow(clippy::too_many_arguments)]
pub fn extract_by_path_occurrence_with_temp_root<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selector: TarEntrySelector<'_>,
    cancellation: Option<&CancellationToken>,
    context: Option<&mut JobContext<'_>>,
    temp_root: Option<&Path>,
) -> Result<TarReport, TarError> {
    extract_with_selector(
        reader,
        archive_path,
        destination,
        policy,
        resolver,
        Some(TarSelection::PathOccurrence { path: selector.path, occurrence: selector.occurrence }),
        cancellation,
        context,
        temp_root,
    )
}

/// Extracts retained TAR entries using an optional caller-owned temporary root.
#[allow(clippy::too_many_arguments)]
pub fn extract_by_selectors_with_temp_root<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selectors: &[TarEntrySelector<'_>],
    cancellation: Option<&CancellationToken>,
    context: Option<&mut JobContext<'_>>,
    temp_root: Option<&Path>,
) -> Result<TarReport, TarError> {
    extract_with_selector(
        reader,
        archive_path,
        destination,
        policy,
        resolver,
        Some(TarSelection::MultipleSelectors(selectors)),
        cancellation,
        context,
        temp_root,
    )
}

/// Stable path-based identity for a TAR entry retained by the engine session.
#[derive(Debug, Clone, Copy)]
pub struct TarEntrySelector<'a> {
    /// Raw normalized archive path from the retained listing.
    pub path: &'a str,
    /// Zero-based occurrence among entries with the same path.
    pub occurrence: usize,
}

#[derive(Debug, Clone, Copy)]
enum TarSelection<'a> {
    Index(usize),
    PathOccurrence { path: &'a str, occurrence: usize },
    MultipleSelectors(&'a [TarEntrySelector<'a>]),
}

#[allow(clippy::too_many_arguments)]
fn extract_with_selector<R: Read>(
    reader: R,
    archive_path: &Path,
    destination: &Path,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selection: Option<TarSelection<'_>>,
    cancellation: Option<&CancellationToken>,
    mut context: Option<&mut JobContext<'_>>,
    temp_root: Option<&Path>,
) -> Result<TarReport, TarError> {
    // Validate and spool before touching the destination. This keeps corrupt
    // TAR input fail-closed even when the missing end records occur after a
    // large, otherwise readable entry.
    let (_temporary, reader) = spool_validated_tar(reader, archive_path, &|| cancellation.is_some_and(CancellationToken::is_cancelled), temp_root)?;
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let mut archive = tar::Archive::new(reader);
    let mut planner = crate::safety::ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = TarReport::default();
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut deferred_directories = Vec::new();
    let mut deferred_hardlinks = Vec::new();

    let mut path_occurrences: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, item) in archive.entries().map_err(|source| io_error(archive_path, source))?.enumerate() {
        if context.as_deref_mut().is_some_and(|ctx| ctx.check_cancelled().is_err()) || cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(TarError::Cancelled);
        }
        let mut entry = item.map_err(|source| io_error(archive_path, source))?;
        let path = entry_path(&mut entry, archive_path)?;
        let current_occ = {
            let occ = path_occurrences.entry(path.clone()).or_insert(0);
            let val = *occ;
            *occ += 1;
            val
        };
        let selected = match selection {
            None => true,
            Some(TarSelection::Index(selected)) => selected == index,
            Some(TarSelection::PathOccurrence { path: selected_path, occurrence }) => path == selected_path && current_occ == occurrence,
            Some(TarSelection::MultipleSelectors(selectors)) => selectors.iter().any(|s| s.path == path && s.occurrence == current_occ),
        };
        if !selected {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let kind = entry_kind(&mut entry, &path)?;
        let size = entry.header().size().unwrap_or(0);
        let safety_entry = ExtractionEntry { archive_path: path.clone(), kind, uncompressed_size: Some(size), compressed_size: None };
        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, job_context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                        crate::extract_loop::skip_entry(report, job_context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                        return Ok(0);
                    }
                    let metadata = entry_metadata(&mut entry, archive_path)?;
                    if decision.replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(decision.destination_path)
                            .map_err(|source| io_error(decision.destination_path, source))?;
                    }
                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            fs::create_dir_all(decision.destination_path).map_err(|source| io_error(decision.destination_path, source))?;
                            deferred_directories.push((decision.destination_path.to_path_buf(), metadata));
                            report.entries = report.entries.saturating_add(1);
                            Ok(0)
                        }
                        ExtractionEntryKind::File => {
                            let copied = crate::extract_loop::copy_file_entry(
                                decision.destination_path,
                                decision.replace_existing,
                                Some(&safety_entry.archive_path),
                                job_context,
                                &mut buffer,
                                |buf| entry.read(buf).map_err(|source| io_error(decision.destination_path, source)),
                                |source, path| io_error(path, source),
                            )?;
                            apply_metadata(decision.destination_path, metadata)?;
                            report.entries = report.entries.saturating_add(1);
                            report.bytes = report.bytes.saturating_add(copied);
                            Ok(copied)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            crate::extract_materialize::write_symlink(target, decision.destination_path)
                                .map_err(|source| io_error(decision.destination_path, source))?;
                            apply_symlink_mtime(decision.destination_path, metadata.mtime)?;
                            report.entries = report.entries.saturating_add(1);
                            Ok(0)
                        }
                        ExtractionEntryKind::Hardlink { .. } => {
                            let source = decision.link_target_path.ok_or_else(|| TarError::MissingLinkTarget { archive_path: path.clone() })?;
                            deferred_hardlinks
                                .push(DeferredHardlink { source_path: source.to_path_buf(), destination_path: decision.destination_path.to_path_buf() });
                            Ok(0)
                        }
                        ExtractionEntryKind::Device | ExtractionEntryKind::Special => Err(TarError::Io {
                            path: decision.destination_path.to_path_buf(),
                            source: io::Error::new(io::ErrorKind::Unsupported, "special tar entry reached materialization after safety planning"),
                        }),
                    }
                }
            }
        })?;
    }

    crate::extract_materialize::materialize_deferred_hardlinks(&deferred_hardlinks)
        .map_err(|source| io_error(deferred_hardlinks.first().map_or(destination, |link| link.destination_path.as_path()), source))?;
    for (path, metadata) in deferred_directories {
        apply_metadata(&path, metadata)?;
    }
    report.entries = report.entries.saturating_add(deferred_hardlinks.len());
    Ok(report)
}

/// Copies one retained regular-file TAR entry to a caller-owned writer.
pub fn copy<R: Read>(reader: R, archive_path: &Path, entry_index: usize, output: &mut dyn Write) -> Result<u64, TarError> {
    copy_with_selector(reader, archive_path, TarSelection::Index(entry_index), output, None)
}

/// Copies one retained regular-file TAR entry by path and duplicate occurrence.
pub fn copy_by_path_occurrence<R: Read>(reader: R, archive_path: &Path, selector: TarEntrySelector<'_>, output: &mut dyn Write) -> Result<u64, TarError> {
    copy_by_path_occurrence_with_temp_root(reader, archive_path, selector, output, None)
}

/// Copies one retained regular-file TAR entry using an optional caller-owned temporary root.
pub fn copy_by_path_occurrence_with_temp_root<R: Read>(
    reader: R,
    archive_path: &Path,
    selector: TarEntrySelector<'_>,
    output: &mut dyn Write,
    temp_root: Option<&Path>,
) -> Result<u64, TarError> {
    copy_with_selector(reader, archive_path, TarSelection::PathOccurrence { path: selector.path, occurrence: selector.occurrence }, output, temp_root)
}

fn copy_with_selector<R: Read>(
    reader: R,
    archive_path: &Path,
    selection: TarSelection<'_>,
    output: &mut dyn Write,
    temp_root: Option<&Path>,
) -> Result<u64, TarError> {
    let (_temporary, reader) = spool_validated_tar(reader, archive_path, &|| false, temp_root)?;
    let mut archive = tar::Archive::new(reader);
    let mut path_occurrence = 0_usize;
    let mut entry = None;
    for (index, item) in archive.entries().map_err(|source| io_error(archive_path, source))?.enumerate() {
        let mut candidate = item.map_err(|source| io_error(archive_path, source))?;
        let path = entry_path(&mut candidate, archive_path)?;
        let selected = match selection {
            TarSelection::Index(selected) => selected == index,
            TarSelection::PathOccurrence { path: selected_path, occurrence } => {
                let matches = path == selected_path && path_occurrence == occurrence;
                if path == selected_path {
                    path_occurrence = path_occurrence.saturating_add(1);
                }
                matches
            }
            TarSelection::MultipleSelectors(selectors) => {
                let matches = selectors.iter().any(|s| s.path == path && s.occurrence == path_occurrence);
                path_occurrence = path_occurrence.saturating_add(1);
                matches
            }
        };
        if selected {
            entry = Some(candidate);
            break;
        }
    }
    let mut entry = entry.ok_or_else(|| io_error(archive_path, io::Error::new(io::ErrorKind::NotFound, "retained TAR entry is not present")))?;
    let path = entry_path(&mut entry, archive_path)?;
    if !entry.header().entry_type().is_file() {
        return Err(io_error(Path::new(&path), io::Error::new(io::ErrorKind::InvalidInput, "retained TAR entry is not a regular file")));
    }
    io::copy(&mut entry, output).map_err(|source| io_error(Path::new(&path), source))
}

fn spool_validated_tar<R: Read>(
    reader: R,
    archive_path: &Path,
    is_cancelled: &dyn Fn() -> bool,
    temp_root: Option<&Path>,
) -> Result<(crate::temp_names::TemporaryDirectory, File), TarError> {
    let temporary = match temp_root {
        Some(parent) => crate::temp_names::TemporaryDirectory::new_in(parent, "zmanager-tar-validation"),
        None => crate::temp_names::TemporaryDirectory::new("zmanager-tar-validation"),
    }
    .map_err(|error| io_error(&error.path, error.source))?;
    let spool_path = temporary.path().join("archive.tar");
    let mut spool = File::options().read(true).write(true).create_new(true).open(&spool_path).map_err(|source| io_error(&spool_path, source))?;
    let mut decoded = reader;
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    loop {
        if is_cancelled() {
            return Err(TarError::Cancelled);
        }
        let read = decoded.read(&mut buffer).map_err(|source| io_error(archive_path, source))?;
        if read == 0 {
            break;
        }
        spool.write_all(&buffer[..read]).map_err(|source| io_error(&spool_path, source))?;
    }
    spool.rewind().map_err(|source| io_error(&spool_path, source))?;
    let consecutive_zero_records = {
        let mut archive = tar::Archive::new(TarStructureObserver::new(&mut spool));
        archive.set_ignore_zeros(true);
        for entry in archive.entries_with_seek().map_err(|source| io_error(archive_path, source))? {
            if is_cancelled() {
                return Err(TarError::Cancelled);
            }
            entry.map_err(|source| io_error(archive_path, source))?;
        }
        archive.into_inner().consecutive_zero_records
    };
    if consecutive_zero_records < 2 {
        return Err(io_error(archive_path, io::Error::new(io::ErrorKind::UnexpectedEof, "TAR archive is missing its two zero-filled end records")));
    }
    spool.rewind().map_err(|source| io_error(&spool_path, source))?;
    Ok((temporary, spool))
}

#[derive(Debug, Clone, Copy)]
struct TarMetadata {
    mode: Option<u32>,
    mtime: Option<crate::tar_metadata::TarTimestamp>,
}

fn entry_path<R: Read>(entry: &mut tar::Entry<'_, R>, archive_path: &Path) -> Result<String, TarError> {
    entry.path().map(|path| path.to_string_lossy().into_owned()).map_err(|source| io_error(archive_path, source))
}

fn entry_kind<R: Read>(entry: &mut tar::Entry<'_, R>, path: &str) -> Result<ExtractionEntryKind, TarError> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_dir() {
        return Ok(ExtractionEntryKind::Directory);
    }
    if entry_type.is_symlink() {
        return Ok(ExtractionEntryKind::Symlink { target: link_target(entry, path)?.into() });
    }
    if entry_type.is_hard_link() {
        return Ok(ExtractionEntryKind::Hardlink { target: link_target(entry, path)?.into() });
    }
    Ok(if entry_type.is_file() { ExtractionEntryKind::File } else { ExtractionEntryKind::Special })
}

fn link_target<R: Read>(entry: &mut tar::Entry<'_, R>, path: &str) -> Result<String, TarError> {
    entry
        .link_name()
        .map_err(|source| io_error(Path::new(path), source))?
        .map(|target| target.into_owned().to_string_lossy().into_owned())
        .ok_or_else(|| TarError::MissingLinkTarget { archive_path: path.to_owned() })
}

fn browser_kind(kind: &ExtractionEntryKind) -> BrowserEntryKind {
    match kind {
        ExtractionEntryKind::File => BrowserEntryKind::File,
        ExtractionEntryKind::Directory => BrowserEntryKind::Directory,
        ExtractionEntryKind::Symlink { .. } => BrowserEntryKind::Symlink,
        ExtractionEntryKind::Hardlink { .. } => BrowserEntryKind::Hardlink,
        ExtractionEntryKind::Device | ExtractionEntryKind::Special => BrowserEntryKind::Special,
    }
}

fn entry_metadata<R: Read>(entry: &mut tar::Entry<'_, R>, archive_path: &Path) -> Result<TarMetadata, TarError> {
    let mut metadata = TarMetadata {
        mode: entry.header().mode().ok(),
        mtime: entry
            .header()
            .mtime()
            .ok()
            .and_then(|seconds| i64::try_from(seconds).ok())
            .map(|seconds| crate::tar_metadata::TarTimestamp { seconds, nanoseconds: 0 }),
    };
    if let Some(extensions) = entry.pax_extensions().map_err(|source| io_error(archive_path, source))? {
        for extension in extensions {
            let extension = extension.map_err(|source| io_error(archive_path, source))?;
            if extension.key_bytes() == b"mtime" {
                metadata.mtime = Some(
                    crate::tar_metadata::parse_pax_mtime(extension.value_bytes())
                        .ok_or_else(|| io_error(archive_path, io::Error::new(io::ErrorKind::InvalidData, "invalid PAX modification time")))?,
                );
            }
        }
    }
    Ok(metadata)
}

fn apply_metadata(path: &Path, metadata: TarMetadata) -> Result<(), TarError> {
    crate::extract_materialize::apply_metadata(
        path,
        metadata.mode,
        metadata.mtime.map(|mtime| filetime::FileTime::from_unix_time(mtime.seconds, mtime.nanoseconds)),
    )
    .map_err(|source| io_error(path, source))
}

fn apply_symlink_mtime(path: &Path, mtime: Option<crate::tar_metadata::TarTimestamp>) -> Result<(), TarError> {
    crate::extract_materialize::apply_symlink_mtime(path, mtime.map(|mtime| filetime::FileTime::from_unix_time(mtime.seconds, mtime.nanoseconds)))
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: impl Into<io::Error>) -> TarError {
    TarError::Io { path: path.to_path_buf(), source: source.into() }
}
