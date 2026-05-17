use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner,
};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const TEMP_OUTPUT_PREFIX: &str = ".zmanager";
const TEMP_OUTPUT_SUFFIX: &str = ".tmp";
const RAW_STREAM_TEMP_EXTENSION: &str = "tmp.Z";

pub const RAW_STREAM_SUFFIXES: &[&str] = &[
    ".zst", ".gz", ".bz2", ".xz", ".lzma", ".lz", ".br", ".lz4", ".lzo", ".Z", ".lrz",
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
    /// LRZIP `.lrz`.
    Lrzip,
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
            Self::Lrzip => "lrzip",
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
            Self::Lrzip => &[".lrz"],
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
    RawStreamFormat::Lrzip,
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
    /// A tool-backed decoder could not be started.
    ExternalToolUnavailable {
        tool: &'static str,
        source: io::Error,
    },
    /// A tool-backed decoder exited unsuccessfully.
    ExternalToolFailed {
        tool: &'static str,
        archive_path: PathBuf,
        status: Option<i32>,
        message: String,
    },
}

impl fmt::Display for RawStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::MissingOutputName { archive_path } => write!(
                f,
                "could not derive raw stream output name from {}",
                archive_path.display()
            ),
            Self::ExternalToolUnavailable { tool, source } => {
                write!(f, "required decoder tool {tool} is not available: {source}")
            }
            Self::ExternalToolFailed {
                tool,
                archive_path,
                status,
                message,
            } => write!(
                f,
                "{tool} failed to decode {} with status {}{}",
                archive_path.display(),
                status.map_or_else(|| "unknown".to_owned(), |status| status.to_string()),
                if message.is_empty() {
                    String::new()
                } else {
                    format!(": {message}")
                }
            ),
        }
    }
}

impl std::error::Error for RawStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::ExternalToolUnavailable { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::MissingOutputName { .. } | Self::ExternalToolFailed { .. } => None,
        }
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

    RAW_STREAM_FORMATS.iter().copied().find(|format| {
        format
            .suffixes()
            .iter()
            .any(|suffix| ends_with_ignore_ascii_case(name, suffix))
    })
}

/// Returns the synthetic archive entry name for a raw single-file stream.
#[must_use]
pub fn output_name_for_raw_stream(
    path: impl AsRef<Path>,
    format: RawStreamFormat,
) -> Option<String> {
    let name = path.as_ref().file_name().and_then(|name| name.to_str())?;
    let stem = format
        .suffixes()
        .iter()
        .find_map(|suffix| strip_suffix_ignore_ascii_case(name, suffix))?;

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
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let output_name = output_name_for_raw_stream(archive_path, format).ok_or_else(|| {
        RawStreamError::MissingOutputName {
            archive_path: archive_path.to_path_buf(),
        }
    })?;

    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| {
            RawStreamError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;

    let max_expanded_bytes = policy.limits.max_expanded_bytes;
    let mut planner = ExtractionSafetyPlanner::new(&destination_root, policy);
    let mut report = RawStreamExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        output_path: None,
        warnings: Vec::new(),
    };
    let entry = ExtractionEntry {
        archive_path: output_name,
        kind: ExtractionEntryKind::File,
        uncompressed_size: None,
        compressed_size: archive_path.metadata().ok().map(|metadata| metadata.len()),
    };

    match planner.validate_entry(&entry)? {
        ExtractionDecision::Write {
            destination_path,
            replace_existing,
            ..
        } => {
            let written_bytes = write_raw_stream_to_file(
                archive_path,
                format,
                &destination_path,
                replace_existing,
                max_expanded_bytes,
            )?;
            report.written_entries = 1;
            report.written_bytes = written_bytes;
            report.output_path = Some(destination_path);
        }
        ExtractionDecision::Skip { reason, .. } => {
            report.skipped_entries = 1;
            report
                .warnings
                .push(format!("skipped {}: {reason}", entry.archive_path));
        }
    }

    Ok(report)
}

/// Copies a raw single-file compression stream to any writer.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the input cannot be decoded or the output
/// writer fails.
pub fn copy_raw_stream_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    output: &mut W,
) -> Result<u64, RawStreamError> {
    let archive_path = archive_path.as_ref();
    if format == RawStreamFormat::Lrzip {
        return copy_lrzip_to_writer(archive_path, output);
    }
    if format == RawStreamFormat::UnixCompress {
        return copy_unix_compress_to_writer(archive_path, output);
    }
    if let Some(tool) = external_stream_tool(format) {
        return copy_external_tool_to_writer(tool, archive_path, output);
    }
    let mut reader = open_decoder(archive_path, format)?;
    io::copy(&mut reader, output).map_err(|source| RawStreamError::Io {
        path: archive_path.to_path_buf(),
        source,
    })
}

/// Reads a raw stream and discards decoded bytes.
///
/// # Errors
///
/// Returns [`RawStreamError`] when the stream cannot be decoded.
pub fn test_raw_stream(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
) -> Result<u64, RawStreamError> {
    copy_raw_stream_to_writer(archive_path, format, &mut io::sink())
}

fn write_raw_stream_to_file(
    archive_path: &Path,
    format: RawStreamFormat,
    destination_path: &Path,
    replace_existing: bool,
    max_expanded_bytes: Option<u64>,
) -> Result<u64, RawStreamError> {
    if let Some(parent) = destination_path.parent() {
        fs::create_dir_all(parent).map_err(|source| RawStreamError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let temp_path = temp_destination_path(destination_path);
    let mut output = File::create(&temp_path).map_err(|source| RawStreamError::Io {
        path: temp_path.clone(),
        source,
    })?;
    let mut output = SizeLimitWriter::new(&mut output, max_expanded_bytes);
    let written = match copy_raw_stream_to_writer(archive_path, format, &mut output) {
        Ok(written) => written,
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
    };
    output.flush().map_err(|source| RawStreamError::Io {
        path: temp_path.clone(),
        source,
    })?;

    if replace_existing {
        crate::safety::remove_destination_for_replace(destination_path).map_err(|source| {
            RawStreamError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    }

    fs::rename(&temp_path, destination_path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        RawStreamError::Io {
            path: destination_path.to_path_buf(),
            source,
        }
    })?;

    Ok(written)
}

fn open_decoder(
    archive_path: &Path,
    format: RawStreamFormat,
) -> Result<Box<dyn Read>, RawStreamError> {
    let file = File::open(archive_path).map_err(|source| RawStreamError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);

    match format {
        RawStreamFormat::Zstd => zstd::stream::read::Decoder::new(reader)
            .map(|decoder| Box::new(decoder) as Box<dyn Read>)
            .map_err(|source| RawStreamError::Io {
                path: archive_path.to_path_buf(),
                source,
            }),
        RawStreamFormat::Gzip => Ok(Box::new(flate2::read::MultiGzDecoder::new(reader))),
        RawStreamFormat::Bzip2 => Ok(Box::new(bzip2::read::BzDecoder::new(reader))),
        RawStreamFormat::Xz => Ok(Box::new(lzma_rust2::XzReader::new(reader, true))),
        RawStreamFormat::Lzma => lzma_rust2::LzmaReader::new_mem_limit(reader, u32::MAX, None)
            .map(|decoder| Box::new(decoder) as Box<dyn Read>)
            .map_err(|source| RawStreamError::Io {
                path: archive_path.to_path_buf(),
                source,
            }),
        RawStreamFormat::Lzip => Ok(Box::new(lzma_rust2::LzipReader::new(reader))),
        RawStreamFormat::Brotli => Ok(Box::new(brotli::Decompressor::new(
            reader,
            crate::DEFAULT_IO_BUFFER_BYTES,
        ))),
        RawStreamFormat::Lz4 => Ok(Box::new(lz4_flex::frame::FrameDecoder::new(reader))),
        RawStreamFormat::Lzo | RawStreamFormat::UnixCompress | RawStreamFormat::Lrzip => {
            Err(RawStreamError::ExternalToolFailed {
                tool: format.name(),
                archive_path: archive_path.to_path_buf(),
                status: None,
                message: "format is handled by a streaming tool adapter".to_owned(),
            })
        }
    }
}

fn external_stream_tool(format: RawStreamFormat) -> Option<ExternalStreamTool> {
    match format {
        RawStreamFormat::Lzo => Some(ExternalStreamTool {
            name: "lzop",
            args: &["-q", "-d", "-c"],
        }),
        _ => None,
    }
}

struct SizeLimitWriter<'a, W> {
    inner: &'a mut W,
    max_bytes: Option<u64>,
    written_bytes: u64,
}

impl<'a, W> SizeLimitWriter<'a, W> {
    fn new(inner: &'a mut W, max_bytes: Option<u64>) -> Self {
        Self {
            inner,
            max_bytes,
            written_bytes: 0,
        }
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
        let allowed = usize::try_from(remaining)
            .ok()
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let written = self.inner.write(&buffer[..allowed])?;
        self.written_bytes += written as u64;

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn expanded_size_limit_error(max_bytes: u64, written_bytes: u64) -> io::Error {
    io::Error::other(format!(
        "expanded stream reached {written_bytes} bytes, exceeding the {max_bytes} byte limit"
    ))
}

#[derive(Debug, Clone, Copy)]
struct ExternalStreamTool {
    name: &'static str,
    args: &'static [&'static str],
}

fn copy_external_tool_to_writer<W: Write>(
    tool: ExternalStreamTool,
    archive_path: &Path,
    output: &mut W,
) -> Result<u64, RawStreamError> {
    let mut child = Command::new(tool.name)
        .args(tool.args)
        .arg(archive_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| RawStreamError::ExternalToolUnavailable {
            tool: tool.name,
            source,
        })?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| RawStreamError::ExternalToolFailed {
            tool: tool.name,
            archive_path: archive_path.to_path_buf(),
            status: None,
            message: "decoder stdout was not available".to_owned(),
        })?;
    let written_bytes = io::copy(&mut stdout, output).map_err(|source| RawStreamError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let process_output =
        child
            .wait_with_output()
            .map_err(|source| RawStreamError::ExternalToolUnavailable {
                tool: tool.name,
                source,
            })?;

    if !process_output.status.success() {
        return Err(RawStreamError::ExternalToolFailed {
            tool: tool.name,
            archive_path: archive_path.to_path_buf(),
            status: process_output.status.code(),
            message: String::from_utf8_lossy(&process_output.stderr)
                .trim()
                .to_owned(),
        });
    }

    Ok(written_bytes)
}

fn copy_lrzip_to_writer<W: Write>(
    archive_path: &Path,
    output: &mut W,
) -> Result<u64, RawStreamError> {
    let temp_path = temp_external_output_path("lrzip");
    let process_output = Command::new("lrzip")
        .env("LRZIP", "NOCONFIG")
        .arg("-d")
        .arg("-q")
        .arg("-f")
        .arg("-o")
        .arg(&temp_path)
        .arg(archive_path)
        .output()
        .map_err(|source| RawStreamError::ExternalToolUnavailable {
            tool: "lrzip",
            source,
        })?;

    if !process_output.status.success() {
        let _ = fs::remove_file(&temp_path);
        return Err(RawStreamError::ExternalToolFailed {
            tool: "lrzip",
            archive_path: archive_path.to_path_buf(),
            status: process_output.status.code(),
            message: external_process_message(&process_output),
        });
    }

    let mut decoded = File::open(&temp_path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        RawStreamError::Io {
            path: temp_path.clone(),
            source,
        }
    })?;
    let written_bytes = io::copy(&mut decoded, output).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        RawStreamError::Io {
            path: temp_path.clone(),
            source,
        }
    })?;
    fs::remove_file(&temp_path).map_err(|source| RawStreamError::Io {
        path: temp_path,
        source,
    })?;

    Ok(written_bytes)
}

fn copy_unix_compress_to_writer<W: Write>(
    archive_path: &Path,
    output: &mut W,
) -> Result<u64, RawStreamError> {
    let temp_input =
        temp_external_output_path("compress").with_extension(RAW_STREAM_TEMP_EXTENSION);
    let temp_output = temp_input.with_extension("");
    fs::copy(archive_path, &temp_input).map_err(|source| RawStreamError::Io {
        path: temp_input.clone(),
        source,
    })?;

    let process_output = Command::new("uncompress")
        .arg("-f")
        .arg(&temp_input)
        .output()
        .map_err(|source| RawStreamError::ExternalToolUnavailable {
            tool: "uncompress",
            source,
        })?;

    if !process_output.status.success() {
        let _ = fs::remove_file(&temp_input);
        let _ = fs::remove_file(&temp_output);
        return Err(RawStreamError::ExternalToolFailed {
            tool: "uncompress",
            archive_path: archive_path.to_path_buf(),
            status: process_output.status.code(),
            message: external_process_message(&process_output),
        });
    }

    let mut decoded = File::open(&temp_output).map_err(|source| {
        let _ = fs::remove_file(&temp_input);
        let _ = fs::remove_file(&temp_output);
        RawStreamError::Io {
            path: temp_output.clone(),
            source,
        }
    })?;
    let written_bytes = io::copy(&mut decoded, output).map_err(|source| {
        let _ = fs::remove_file(&temp_output);
        RawStreamError::Io {
            path: temp_output.clone(),
            source,
        }
    })?;
    fs::remove_file(&temp_output).map_err(|source| RawStreamError::Io {
        path: temp_output,
        source,
    })?;

    Ok(written_bytes)
}

fn external_process_message(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }

    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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
        ".tar.lrz",
        ".tlrz",
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
        ".cpio.lrz",
        ".cpio.br",
    ]
    .iter()
    .any(|suffix| ends_with_ignore_ascii_case(name, suffix))
}

fn temp_destination_path(destination_path: &Path) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let file_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");

    destination_path.with_file_name(format!(
        "{TEMP_OUTPUT_PREFIX}-{file_name}-{}-{now}{TEMP_OUTPUT_SUFFIX}",
        std::process::id()
    ))
}

fn temp_external_output_path(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "{TEMP_OUTPUT_PREFIX}-{label}-{}-{now}{TEMP_OUTPUT_SUFFIX}",
        std::process::id()
    ))
}

fn strip_suffix_ignore_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let value_bytes = value.as_bytes();
    let suffix_bytes = suffix.as_bytes();
    if value_bytes.len() < suffix_bytes.len()
        || !value_bytes[value_bytes.len() - suffix_bytes.len()..].eq_ignore_ascii_case(suffix_bytes)
    {
        return None;
    }

    Some(&value[..value.len() - suffix.len()])
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    strip_suffix_ignore_ascii_case(value, suffix).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        RawStreamFormat, detect_raw_stream_format, extract_raw_stream, output_name_for_raw_stream,
    };
    use crate::safety::{ExtractionLimits, ExtractionPolicy};
    use std::fs::{self, File};
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_raw_streams_but_not_compressed_archives() {
        assert_eq!(
            detect_raw_stream_format("file.txt.zst"),
            Some(RawStreamFormat::Zstd)
        );
        assert_eq!(
            detect_raw_stream_format("file.txt.GZ"),
            Some(RawStreamFormat::Gzip)
        );
        assert_eq!(detect_raw_stream_format("payload.tar.zst"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.gz"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.lzo"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.Z"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.lz4"), None);
        assert_eq!(detect_raw_stream_format("payload.tar.lrz"), None);
        assert_eq!(detect_raw_stream_format("payload.cpgz"), None);
    }

    #[test]
    fn derives_output_name_from_raw_stream_suffix() {
        assert_eq!(
            output_name_for_raw_stream("file.txt.zst", RawStreamFormat::Zstd).as_deref(),
            Some("file.txt")
        );
        assert_eq!(
            output_name_for_raw_stream("FILE.TXT.GZ", RawStreamFormat::Gzip).as_deref(),
            Some("FILE.TXT")
        );
        assert_eq!(
            output_name_for_raw_stream(".zst", RawStreamFormat::Zstd),
            None
        );
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
            limits: ExtractionLimits {
                max_expanded_bytes: Some(8),
                max_entry_expansion_ratio: None,
            },
            ..ExtractionPolicy::default()
        };

        let error = extract_raw_stream(&archive, RawStreamFormat::Zstd, temp.path("out"), policy)
            .unwrap_err();

        assert!(error.to_string().contains("expanded stream reached"));
        assert!(!temp.path("out/payload.txt").exists());
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
