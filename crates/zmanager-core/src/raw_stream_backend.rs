use crate::jobs::{JobCancelled, JobContext};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use crate::temp_names::TempDirAllocError;
use crate::{lzop_decoder::LzopReader, unix_compress_decoder::UnixCompressReader, uu_decoder::UuDecoder};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

type ProgressCallback<'a> = Option<&'a mut dyn FnMut(u64)>;

/// Suffixes recognized as raw single-file streams, in
/// [`RAW_STREAM_FORMATS`] order.
///
/// Derived from [`RawStreamFormat::suffixes`] so the two lists cannot drift;
/// the only multi-suffix format is [`RawStreamFormat::Uu`] (`.uu` and
/// `.b64`), which contributes both entries.
pub const RAW_STREAM_SUFFIXES: &[&str] = &[
    RawStreamFormat::Zstd.suffixes()[0],
    RawStreamFormat::Gzip.suffixes()[0],
    RawStreamFormat::Bzip2.suffixes()[0],
    RawStreamFormat::Xz.suffixes()[0],
    RawStreamFormat::Lzma.suffixes()[0],
    RawStreamFormat::Lzip.suffixes()[0],
    RawStreamFormat::Brotli.suffixes()[0],
    RawStreamFormat::Lz4.suffixes()[0],
    RawStreamFormat::Lzo.suffixes()[0],
    RawStreamFormat::UnixCompress.suffixes()[0],
    RawStreamFormat::Uu.suffixes()[0],
    RawStreamFormat::Uu.suffixes()[1],
];

/// A raw single-file compression stream.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RawStreamFormat {
    /// Zstandard `.zst`.
    Zstd,
    /// gzip `.gz`.
    Gzip,
    /// bzip2 `.bz2`.
    Bzip2,
    /// XZ `.xz`.
    Xz,
    /// legacy LZMA `.lzma`.
    Lzma,
    /// lzip `.lz`.
    Lzip,
    /// Brotli `.br`.
    Brotli,
    /// LZ4 frame `.lz4`.
    Lz4,
    /// LZOP `.lzo`.
    Lzo,
    /// Unix compress `.Z`.
    UnixCompress,
    /// uuencode `.uu` / base64 `.b64`.
    Uu,
}

impl RawStreamFormat {
    /// Human-readable format name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Lzip => "lzip",
            Self::Brotli => "brotli",
            Self::Lz4 => "lz4",
            Self::Lzo => "lzop",
            Self::UnixCompress => "compress",
            Self::Uu => "uuencode",
        }
    }

    #[must_use]
    pub const fn suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Zstd => &[".zst"],
            Self::Gzip => &[".gz"],
            Self::Bzip2 => &[".bz2"],
            Self::Xz => &[".xz"],
            Self::Lzma => &[".lzma"],
            Self::Lzip => &[".lz"],
            Self::Brotli => &[".br"],
            Self::Lz4 => &[".lz4"],
            Self::Lzo => &[".lzo"],
            Self::UnixCompress => &[".Z"],
            Self::Uu => &[".uu", ".b64"],
        }
    }
}

pub const RAW_STREAM_FORMATS: &[RawStreamFormat] = &[
    RawStreamFormat::Zstd,
    RawStreamFormat::Gzip,
    RawStreamFormat::Bzip2,
    RawStreamFormat::Xz,
    RawStreamFormat::Lzma,
    RawStreamFormat::Lzip,
    RawStreamFormat::Brotli,
    RawStreamFormat::Lz4,
    RawStreamFormat::Lzo,
    RawStreamFormat::UnixCompress,
    RawStreamFormat::Uu,
];

/// Extraction report for a raw single-file stream.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawStreamExtractReport {
    /// Number of output files written.
    pub written_entries: usize,
    /// Number of synthetic output entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of decompressed bytes written.
    pub written_bytes: u64,
    /// Final output path when a file was written.
    pub output_path: Option<PathBuf>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Error returned by the raw stream backend.
#[derive(Debug)]
pub enum RawStreamError {
    /// Filesystem or decoder I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected the synthetic output entry.
    Safety(ExtractionSafetyError),
    /// The archive file name cannot produce a safe output file name.
    MissingOutputName { archive_path: PathBuf },
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for RawStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingOutputName { archive_path } => {
                write!(f, "could not derive raw stream output name from {}", archive_path.display())
            }
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for RawStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingOutputName { .. } | Self::Cancelled => None,
        }
    }
}

impl From<JobCancelled> for RawStreamError {
    fn from(_source: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<ExtractionSafetyError> for RawStreamError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Detects raw single-file streams by extension.
///
/// Container archive spellings such as `.tar.gz`, `.tar.zst`, `.cpio.gz`,
/// and `.cpgz` intentionally return `None` so the archive backends can handle
/// the inner member tree.
#[must_use]
pub fn detect_raw_stream_format(path: impl AsRef<Path>) -> Option<RawStreamFormat> {
    let name = path.as_ref().file_name().and_then(|name| name.to_str())?;
    if is_compressed_archive_container(name) {
        return None;
    }

    RAW_STREAM_FORMATS.iter().copied().find(|format| format.suffixes().iter().any(|suffix| crate::strings::ends_with_ignore_ascii_case(name, suffix)))
}

/// Returns the synthetic archive entry name for a raw single-file stream.
#[must_use]
pub fn output_name_for_raw_stream(path: impl AsRef<Path>, format: RawStreamFormat) -> Option<String> {
    let name = path.as_ref().file_name().and_then(|name| name.to_str())?;
    let stem = format.suffixes().iter().find_map(|suffix| crate::strings::strip_suffix_ignore_ascii_case(name, suffix))?;

    (!stem.is_empty()).then(|| stem.to_owned())
}

/// Extracts a raw single-file compression stream to a destination directory.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the stream cannot be decoded, the output
/// name is unsafe, or filesystem writes fail.
pub fn extract_raw_stream(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<RawStreamExtractReport, RawStreamError> {
    extract_raw_stream_inner(archive_path, format, destination, policy, None, None)
}

/// Attempts to return the uncompressed byte size for a raw stream before
/// extraction.
///
/// For formats where this metadata is not reliably recoverable from the stream
/// header, this returns `None`.
#[must_use]
pub fn estimate_raw_stream_uncompressed_size(archive_path: impl AsRef<Path>, format: RawStreamFormat) -> Option<u64> {
    let archive_path = archive_path.as_ref();

    match format {
        RawStreamFormat::Gzip => estimate_gzip_uncompressed_size(archive_path),
        RawStreamFormat::Zstd
        | RawStreamFormat::Bzip2
        | RawStreamFormat::Xz
        | RawStreamFormat::Lzma
        | RawStreamFormat::Lzip
        | RawStreamFormat::Brotli
        | RawStreamFormat::Lz4
        | RawStreamFormat::Lzo
        | RawStreamFormat::UnixCompress
        | RawStreamFormat::Uu => None,
    }
}

/// Extracts a raw single-file compression stream with an overwrite resolver.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the stream cannot be decoded, the output
/// name is unsafe, filesystem writes fail, or the resolver aborts extraction.
pub fn extract_raw_stream_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<RawStreamExtractReport, RawStreamError> {
    extract_raw_stream_inner(archive_path, format, destination, policy, Some(overwrite_resolver), None)
}

/// Extracts a raw single-file compression stream with a job context for
/// progress and cancellation, and optionally an overwrite resolver.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the stream cannot be decoded, the output
/// name is unsafe, filesystem writes fail, the resolver aborts extraction, or
/// the job is cancelled.
pub(crate) fn extract_raw_stream_with_context(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<RawStreamExtractReport, RawStreamError> {
    extract_raw_stream_inner(archive_path, format, destination, policy, overwrite_resolver, context)
}

/// Returns whether raw stream extraction can report input-stream byte
/// progress independently from output bytes. Every registered raw-stream
/// decoder is a streaming reader, so this is always true.
#[must_use]
pub const fn can_track_source_progress(_format: RawStreamFormat) -> bool {
    true
}

fn extract_raw_stream_inner(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<RawStreamExtractReport, RawStreamError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let output_name =
        output_name_for_raw_stream(archive_path, format).ok_or_else(|| RawStreamError::MissingOutputName { archive_path: archive_path.to_path_buf() })?;

    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| RawStreamError::Io { path: destination.to_path_buf(), source })?;

    let max_expanded_bytes = policy.limits.max_expanded_bytes;
    let mut planner = match overwrite_resolver {
        Some(resolver) => ExtractionSafetyPlanner::new_with_overwrite_resolver(&destination_root, policy, resolver),
        None => ExtractionSafetyPlanner::new(&destination_root, policy),
    };
    let mut report = RawStreamExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, output_path: None, warnings: Vec::new() };
    let entry = ExtractionEntry {
        archive_path: output_name,
        kind: ExtractionEntryKind::File,
        uncompressed_size: None,
        compressed_size: archive_path.metadata().ok().map(|metadata| metadata.len()),
    };

    let decision = planner.validate_entry(&entry)?;
    crate::extract_loop::process_planned_entry(&mut report, context, &entry, decision, &mut |action, report, context| match action {
        crate::extract_loop::EntryAction::Skip => Ok::<u64, RawStreamError>(0),
        crate::extract_loop::EntryAction::Write(decision) => {
            let written_bytes = write_raw_stream_to_file(
                archive_path,
                format,
                decision.destination_path,
                decision.replace_existing,
                max_expanded_bytes,
                context,
                &entry.archive_path,
            )?;
            report.written_entries = 1;
            report.written_bytes = written_bytes;
            report.output_path = Some(decision.destination_path.to_path_buf());
            Ok(written_bytes)
        }
    })?;

    Ok(report)
}

/// Copies a raw single-file compression stream to any writer.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the input cannot be decoded or the output
/// writer fails.
pub fn copy_raw_stream_to_writer<W: Write + ?Sized>(archive_path: impl AsRef<Path>, format: RawStreamFormat, output: &mut W) -> Result<u64, RawStreamError> {
    copy_raw_stream_to_writer_with_progress(archive_path, format, output, None, false)
}

pub fn copy_raw_stream_to_writer_with_progress<W: Write + ?Sized>(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    output: &mut W,
    on_progress: ProgressCallback<'_>,
    track_source_progress: bool,
) -> Result<u64, RawStreamError> {
    let archive_path = archive_path.as_ref();

    if track_source_progress && let Some(on_progress) = on_progress {
        let file = File::open(archive_path).map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source })?;
        let reader = BufReader::new(file);
        let mut reader = open_decoder_from_reader(CountingRead::new(reader, on_progress), format, archive_path)?;
        return copy_reader_to_writer_with_progress(&mut reader, output, archive_path, None);
    }

    let mut reader = open_decoder(archive_path, format)?;

    copy_reader_to_writer_with_progress(&mut reader, output, archive_path, on_progress)
}

struct CountingRead<R, F> {
    inner: R,
    on_progress: F,
}

impl<R, F> CountingRead<R, F> {
    fn new(inner: R, on_progress: F) -> Self {
        Self { inner, on_progress }
    }
}

impl<R, F> Read for CountingRead<R, F>
where
    R: Read,
    F: FnMut(u64),
{
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read > 0 {
            let read_u64 = u64::try_from(read).map_err(|_| io::Error::other("read chunk size exceeded u64"))?;
            (self.on_progress)(read_u64);
        }
        Ok(read)
    }
}

pub(crate) fn open_decoder_from_reader<'a, R: Read + 'a>(
    reader: R,
    format: RawStreamFormat,
    archive_path: &Path,
) -> Result<Box<dyn Read + 'a>, RawStreamError> {
    match format {
        RawStreamFormat::Zstd => zstd::stream::read::Decoder::new(reader)
            .map(|decoder| Box::new(decoder) as Box<dyn Read + 'a>)
            .map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source }),
        RawStreamFormat::Gzip => Ok(Box::new(flate2::read::MultiGzDecoder::new(reader))),
        RawStreamFormat::Bzip2 => Ok(Box::new(bzip2::read::BzDecoder::new(reader))),
        RawStreamFormat::Xz => Ok(Box::new(lzma_rust2::XzReader::new(reader, true))),
        RawStreamFormat::Lzma => lzma_rust2::LzmaReader::new_mem_limit(reader, u32::MAX, None)
            .map(|decoder| Box::new(decoder) as Box<dyn Read + 'a>)
            .map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source }),
        RawStreamFormat::Lzip => Ok(Box::new(lzma_rust2::LzipReader::new(reader))),
        RawStreamFormat::Brotli => Ok(Box::new(brotli::Decompressor::new(reader, crate::DEFAULT_IO_BUFFER_BYTES))),
        RawStreamFormat::Lz4 => Ok(Box::new(lz4_flex::frame::FrameDecoder::new(reader))),
        RawStreamFormat::Lzo => LzopReader::new(reader)
            .map(|decoder| Box::new(decoder) as Box<dyn Read + 'a>)
            .map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source }),
        RawStreamFormat::UnixCompress => UnixCompressReader::new(reader)
            .map(|decoder| Box::new(decoder) as Box<dyn Read + 'a>)
            .map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source }),
        RawStreamFormat::Uu => Ok(Box::new(UuDecoder::new(reader))),
    }
}

fn copy_reader_to_writer_with_progress<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    output: &mut W,
    path: &Path,
    on_progress: ProgressCallback<'_>,
) -> Result<u64, RawStreamError> {
    copy_bytes_with_progress(reader, output, on_progress).map_err(|source| RawStreamError::Io { path: path.to_path_buf(), source })
}

/// Shared byte-copy loop with an optional byte-count progress callback, used
/// by both the decoder-reader path and the external-tool stdout path so the
/// progress accounting cannot drift between them.
fn copy_bytes_with_progress<R: Read, W: Write + ?Sized>(reader: &mut R, output: &mut W, mut on_progress: ProgressCallback<'_>) -> io::Result<u64> {
    let mut total_written = 0_u64;
    let mut buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;

        let read_u64 = u64::try_from(read).map_err(|_| io::Error::other("read chunk size exceeded u64"))?;
        if let Some(on_progress) = &mut on_progress {
            on_progress(read_u64);
        }
        total_written = total_written.saturating_add(read_u64);
    }

    Ok(total_written)
}

/// Reads a raw stream and discards decoded bytes.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the stream cannot be decoded.
pub fn test_raw_stream(archive_path: impl AsRef<Path>, format: RawStreamFormat) -> Result<u64, RawStreamError> {
    copy_raw_stream_to_writer(archive_path, format, &mut io::sink())
}

/// Like [`test_raw_stream`], stopping with [`RawStreamError::Cancelled`] once
/// the job is cancelled.
pub(crate) fn test_raw_stream_with_context(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    payload_name: &str,
    context: &mut JobContext<'_>,
) -> Result<u64, RawStreamError> {
    let mut output = crate::extract_loop::JobProgressWriter::new(io::sink(), Some(context), payload_name);
    match copy_raw_stream_to_writer(archive_path, format, &mut output) {
        Err(RawStreamError::Io { source, .. }) if crate::extract_loop::is_job_cancelled(&source) => Err(RawStreamError::Cancelled),
        result => result,
    }
}

fn write_raw_stream_to_file(
    archive_path: &Path,
    format: RawStreamFormat,
    destination_path: &Path,
    replace_existing: bool,
    max_expanded_bytes: Option<u64>,
    context: Option<&mut JobContext<'_>>,
    output_name: &str,
) -> Result<u64, RawStreamError> {
    let mut mtime_to_restore = None;
    if format == RawStreamFormat::Gzip
        && let Ok(file) = File::open(archive_path)
    {
        let decoder = flate2::read::GzDecoder::new(file);
        if let Some(header) = decoder.header() {
            let mtime = header.mtime();
            if mtime > 0 {
                mtime_to_restore = Some(mtime);
            }
        }
    }

    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| RawStreamError::Io { path: destination_path.to_path_buf(), source })?;
    let written = {
        let file = output.file_mut().map_err(|source| RawStreamError::Io { path: destination_path.to_path_buf(), source })?;
        let mut output = crate::extract_loop::JobProgressWriter::new(SizeLimitWriter::new(file, max_expanded_bytes), context, output_name);
        let written = match copy_raw_stream_to_writer(archive_path, format, &mut output) {
            Err(RawStreamError::Io { source, .. }) if crate::extract_loop::is_job_cancelled(&source) => return Err(RawStreamError::Cancelled),
            result => result?,
        };
        output.flush().map_err(|source| RawStreamError::Io { path: destination_path.to_path_buf(), source })?;
        written
    };

    output.commit_with_replace(replace_existing).map_err(|source| RawStreamError::Io { path: destination_path.to_path_buf(), source })?;

    if let Some(mtime) = mtime_to_restore {
        let system_time = UNIX_EPOCH + std::time::Duration::from_secs(u64::from(mtime));
        filetime::set_file_mtime(destination_path, filetime::FileTime::from_system_time(system_time))
            .map_err(|source| RawStreamError::Io { path: destination_path.to_path_buf(), source })?;
    }

    Ok(written)
}

pub(crate) fn open_decoder(archive_path: &Path, format: RawStreamFormat) -> Result<Box<dyn Read>, RawStreamError> {
    let file = File::open(archive_path).map_err(|source| RawStreamError::Io { path: archive_path.to_path_buf(), source })?;
    let reader = BufReader::new(file);
    open_decoder_from_reader(reader, format, archive_path)
}

struct SizeLimitWriter<'a, W> {
    inner: &'a mut W,
    max_bytes: Option<u64>,
    written_bytes: u64,
}

impl<'a, W> SizeLimitWriter<'a, W> {
    fn new(inner: &'a mut W, max_bytes: Option<u64>) -> Self {
        Self { inner, max_bytes, written_bytes: 0 }
    }
}

impl<W: Write> Write for SizeLimitWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(max_bytes) = self.max_bytes else {
            return self.inner.write(buffer);
        };
        if self.written_bytes >= max_bytes {
            return Err(expanded_size_limit_error(max_bytes, self.written_bytes));
        }

        let remaining = max_bytes - self.written_bytes;
        let allowed = usize::try_from(remaining).ok().map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let written = self.inner.write(&buffer[..allowed])?;
        self.written_bytes += written as u64;

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn expanded_size_limit_error(max_bytes: u64, written_bytes: u64) -> io::Error {
    io::Error::other(format!("expanded stream reached {written_bytes} bytes, exceeding the {max_bytes} byte limit"))
}

fn estimate_gzip_uncompressed_size(archive_path: &Path) -> Option<u64> {
    let mut archive = File::open(archive_path).ok()?;

    let mut header = [0_u8; 2];
    archive.read_exact(&mut header).ok()?;
    if header != [0x1f, 0x8b] {
        return None;
    }

    let mut compression_method = [0_u8; 1];
    archive.read_exact(&mut compression_method).ok()?;
    if compression_method[0] != 8 {
        return None;
    }

    let archive_len = archive.metadata().ok()?.len();
    if archive_len < 18 {
        return None;
    }

    archive.seek(SeekFrom::End(-8)).ok()?;

    let mut trailer = [0_u8; 8];
    archive.read_exact(&mut trailer).ok()?;

    Some(u64::from(u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]])))
}

fn is_compressed_archive_container(name: &str) -> bool {
    [
        ".tar.zst",
        ".tzst",
        ".tar.gz",
        ".tgz",
        ".taz",
        ".tar.bz2",
        ".tbz",
        ".tbz2",
        ".tar.xz",
        ".txz",
        ".tar.lzma",
        ".tlzma",
        ".tar.lz",
        ".tlz",
        ".tar.lzo",
        ".tlzo",
        ".tar.z",
        ".tz",
        ".tar.lz4",
        ".tlz4",
        ".tar.uu",
        ".tar.b64",
        ".tar.br",
        ".tbr",
        ".cpio.gz",
        ".cpgz",
        ".cpio.bz2",
        ".cpio.xz",
        ".cpio.lzma",
        ".cpio.zst",
        ".cpio.lz",
        ".cpio.lzo",
        ".cpio.z",
        ".cpio.lz4",
        ".cpio.br",
    ]
    .iter()
    .any(|suffix| crate::strings::ends_with_ignore_ascii_case(name, suffix))
}

impl From<TempDirAllocError> for RawStreamError {
    fn from(error: TempDirAllocError) -> Self {
        Self::Io { path: error.path, source: error.source }
    }
}

#[cfg(test)]
mod tests {
    use super::{RawStreamFormat, detect_raw_stream_format, estimate_raw_stream_uncompressed_size, extract_raw_stream, output_name_for_raw_stream};
    use crate::safety::{ExtractionLimits, ExtractionPolicy};
    use crate::temp_names::TemporaryDirectory;
    use crate::test_support::TestDir;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs::{self, File};
    use std::io::Write as _;
    use std::time::UNIX_EPOCH;

    #[test]
    fn detects_raw_streams_but_not_compressed_archives() {
        assert_eq!(detect_raw_stream_format("file.txt.zst"), Some(RawStreamFormat::Zstd));
        assert_eq!(detect_raw_stream_format("file.txt.GZ"), Some(RawStreamFormat::Gzip));
        assert_eq!(detect_raw_stream_format("payload.tar.zst"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.gz"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.lzo"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.Z"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.lz4"), None);
        assert_eq!(detect_raw_stream_format("payload.cpgz"), None);
    }

    #[test]
    fn test_gz_mtime_preservation() {
        let dir = TemporaryDirectory::new("test_gz_mtime").unwrap();
        let archive_path = dir.path().join("test.gz");
        let extract_path = dir.path().join("extracted.txt");

        let mtime = 1_600_000_000;
        let file = File::create(&archive_path).unwrap();
        let builder = flate2::GzBuilder::new().mtime(mtime);
        let mut encoder = builder.write(file, Compression::default());
        encoder.write_all(b"hello world").unwrap();
        encoder.finish().unwrap();

        super::write_raw_stream_to_file(&archive_path, RawStreamFormat::Gzip, &extract_path, true, None, None, "extracted.txt").unwrap();

        let meta = fs::metadata(&extract_path).unwrap();
        let modified = meta.modified().unwrap();
        let duration = modified.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(duration.as_secs(), u64::from(mtime));
    }

    #[test]
    fn derives_output_name_from_raw_stream_suffix() {
        assert_eq!(output_name_for_raw_stream("file.txt.zst", RawStreamFormat::Zstd).as_deref(), Some("file.txt"));
        assert_eq!(output_name_for_raw_stream("FILE.TXT.GZ", RawStreamFormat::Gzip).as_deref(), Some("FILE.TXT"));
        assert_eq!(output_name_for_raw_stream(".zst", RawStreamFormat::Zstd), None);
    }

    #[test]
    fn extraction_enforces_expanded_size_limit() {
        let temp = TestDir::new("raw_stream_expanded_size_limit");
        let archive = temp.path("payload.txt.zst");
        let file = File::create(&archive).unwrap();
        let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        encoder.write_all(b"0123456789abcdef").unwrap();
        encoder.finish().unwrap();
        let policy = ExtractionPolicy {
            limits: ExtractionLimits { max_expanded_bytes: Some(8), max_entry_expansion_ratio: None, max_entries: None },
            ..ExtractionPolicy::default()
        };

        let error = extract_raw_stream(&archive, RawStreamFormat::Zstd, temp.path("out"), policy).unwrap_err();

        assert!(error.to_string().contains("expanded stream reached"));
        assert!(!temp.path("out/payload.txt").exists());
    }

    #[test]
    fn estimates_gzip_uncompressed_size_from_trailer() {
        let temp = TestDir::new("raw_stream_gzip_uncompressed_size");
        let archive = temp.path("payload.txt.gz");

        let payload = b"raw stream size hint";
        {
            let output = File::create(&archive).unwrap();
            let mut encoder = GzEncoder::new(output, Compression::default());
            encoder.write_all(payload).unwrap();
            encoder.finish().unwrap();
        }

        let estimated = estimate_raw_stream_uncompressed_size(&archive, RawStreamFormat::Gzip).expect("expected gzip uncompressed size hint");

        assert_eq!(estimated, payload.len() as u64);
    }

    #[test]
    fn archive_test_stops_when_cancelled() {
        let token = crate::jobs::CancellationToken::new();
        token.cancel();
        let mut sink = |_event: crate::jobs::JobEvent| {};
        let mut context = crate::jobs::JobContext::new(&token, &mut sink);
        let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.txt.gz");
        let error = super::test_raw_stream_with_context(&archive, RawStreamFormat::Gzip, "basic.txt", &mut context).unwrap_err();
        assert!(matches!(error, super::RawStreamError::Cancelled), "{error}");
    }
}
