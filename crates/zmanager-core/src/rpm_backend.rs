//! Bounded native RPM container reader composing an RPM header with CPIO.

use crate::cpio_backend;
use crate::engine::types::TestOptions;
use crate::safety::{ExtractionPolicy, OverwriteResolver};
use crate::temp_names::{TempDirAllocError, TemporaryDirectory};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

const RPM_LEAD_SIZE: u64 = 96;
const RPM_LEAD_SIZE_BYTES: usize = 96;
const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];
const PAYLOAD_COMPRESSOR_TAG: u32 = 1125;
const MAX_HEADER_INDEXES: u32 = 1_000_000;
const MAX_HEADER_DATA_BYTES: u32 = 64 * 1024 * 1024;

/// Native RPM payload description.
#[derive(Debug, Clone, Eq, PartialEq)]
struct RpmPayload {
    offset: u64,
    size: u64,
    suffix: &'static str,
}

/// Error returned by native RPM operations.
#[derive(Debug)]
pub enum RpmError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The RPM framing or header is malformed.
    Invalid { path: PathBuf, message: String },
    /// The embedded CPIO payload failed.
    Cpio(cpio_backend::CpioError),
    /// The embedded payload compression stream failed.
    RawStream(crate::raw_stream_backend::RawStreamError),
}

impl fmt::Display for RpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid RPM {}: {message}", path.display()),
            Self::Cpio(source) => write!(f, "RPM CPIO payload failed: {source}"),
            Self::RawStream(source) => write!(f, "RPM payload decoder failed: {source}"),
        }
    }
}

impl std::error::Error for RpmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cpio(source) => Some(source),
            Self::RawStream(source) => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}

impl From<cpio_backend::CpioError> for RpmError {
    fn from(source: cpio_backend::CpioError) -> Self {
        Self::Cpio(source)
    }
}

impl From<crate::raw_stream_backend::RawStreamError> for RpmError {
    fn from(source: crate::raw_stream_backend::RawStreamError) -> Self {
        Self::RawStream(source)
    }
}

impl From<TempDirAllocError> for RpmError {
    fn from(error: TempDirAllocError) -> Self {
        Self::Io { path: error.path, source: error.source }
    }
}

/// Lists entries from the RPM's embedded CPIO payload.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<cpio_backend::CpioEntry>, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::list(payload).map_err(RpmError::from)
}

/// Verifies entries and checksums in the RPM's embedded CPIO payload.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<cpio_backend::CpioReport, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::test(payload, options).map_err(RpmError::from)
}

/// Extracts the RPM's embedded CPIO payload using the shared safety policy.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<cpio_backend::CpioReport, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::extract(payload, destination, policy, resolver, None, cancellation).map_err(RpmError::from)
}

/// Copies one retained CPIO payload entry to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn io::Write) -> Result<u64, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::copy(payload, entry_index, writer).map_err(RpmError::from)
}

/// Copies one retained CPIO payload entry by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn io::Write) -> Result<u64, RpmError> {
    let (_temporary, payload) = materialize_payload(path.as_ref())?;
    cpio_backend::copy_by_path_occurrence(&payload, selected_path, selected_occurrence, writer).map_err(RpmError::from)
}

fn materialize_payload(path: &Path) -> Result<(TemporaryDirectory, PathBuf), RpmError> {
    let payload = parse_payload(path)?;
    let temporary = TemporaryDirectory::new("zmanager-rpm")?;
    let payload_path = temporary.path().join(format!("payload.cpio{}", payload.suffix));
    let mut input = File::open(path).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    input.seek(SeekFrom::Start(payload.offset)).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    let mut limited = input.take(payload.size);
    let mut output = File::create(&payload_path).map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    io::copy(&mut limited, &mut output).map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    if limited.limit() != 0 {
        return Err(RpmError::Invalid { path: path.to_path_buf(), message: "RPM payload is truncated".to_owned() });
    }
    output.flush().map_err(|source| RpmError::Io { path: payload_path.clone(), source })?;
    if payload.suffix.is_empty() {
        return Ok((temporary, payload_path));
    }
    let format = match payload.suffix {
        ".gz" => crate::raw_stream_backend::RawStreamFormat::Gzip,
        ".bz2" => crate::raw_stream_backend::RawStreamFormat::Bzip2,
        ".xz" => crate::raw_stream_backend::RawStreamFormat::Xz,
        ".lzma" => crate::raw_stream_backend::RawStreamFormat::Lzma,
        ".zst" => crate::raw_stream_backend::RawStreamFormat::Zstd,
        _ => return Err(invalid(path, "RPM payload compression suffix has no decoder")),
    };
    let mut decoder = crate::raw_stream_backend::open_decoder(&payload_path, format)?;
    let decoded_path = temporary.path().join("payload.cpio");
    let mut decoded_output = File::create(&decoded_path).map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    io::copy(&mut decoder, &mut decoded_output).map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    decoded_output.flush().map_err(|source| RpmError::Io { path: decoded_path.clone(), source })?;
    Ok((temporary, decoded_path))
}

fn parse_payload(path: &Path) -> Result<RpmPayload, RpmError> {
    let mut file = File::open(path).map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?;
    let file_size = file.metadata().map_err(|source| RpmError::Io { path: path.to_path_buf(), source })?.len();
    if file_size < RPM_LEAD_SIZE {
        return Err(invalid(path, "RPM lead is truncated"));
    }
    let mut lead = [0_u8; RPM_LEAD_SIZE_BYTES];
    file.read_exact(&mut lead).map_err(|source| io_error(path, source))?;
    if lead[..4] != RPM_LEAD_MAGIC {
        return Err(invalid(path, "RPM lead magic is invalid"));
    }

    let signature = read_header(&mut file, path)?;
    let aligned = align_eight(signature.end)?;
    if aligned > signature.end {
        file.seek(SeekFrom::Start(aligned)).map_err(|source| io_error(path, source))?;
    }
    let main = read_header(&mut file, path)?;
    let payload_offset = main.end;
    if payload_offset > file_size {
        return Err(invalid(path, "RPM main header extends past end of file"));
    }
    let compressor = main.string_value(PAYLOAD_COMPRESSOR_TAG).unwrap_or_default();
    let suffix = payload_suffix(&compressor, path)?;
    Ok(RpmPayload { offset: payload_offset, size: file_size - payload_offset, suffix })
}

fn payload_suffix<'a>(compressor: &str, path: &Path) -> Result<&'a str, RpmError> {
    match compressor.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(""),
        "gzip" | "gz" => Ok(".gz"),
        "bzip2" | "bzip" | "bz2" => Ok(".bz2"),
        "xz" => Ok(".xz"),
        "lzma" => Ok(".lzma"),
        "zstd" | "zstandard" => Ok(".zst"),
        other => Err(invalid(path, &format!("unsupported RPM payload compressor {other}"))),
    }
}

#[derive(Debug)]
struct Header {
    end: u64,
    indexes: Vec<Index>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Index {
    tag: u32,
    kind: u32,
    offset: u32,
    count: u32,
}

impl Header {
    fn string_value(&self, tag: u32) -> Option<String> {
        let index = self.indexes.iter().find(|index| index.tag == tag && matches!(index.kind, 6 | 9))?;
        if index.count == 0 {
            return None;
        }
        let start = usize::try_from(index.offset).ok()?;
        let bytes = self.data.get(start..)?;
        let bytes = if index.kind == 6 {
            bytes
        } else {
            let count = usize::try_from(index.count).ok()?;
            bytes.get(..count.min(bytes.len()))?
        };
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).ok()
    }
}

fn read_header(file: &mut File, path: &Path) -> Result<Header, RpmError> {
    let mut fixed = [0_u8; 16];
    file.read_exact(&mut fixed).map_err(|source| io_error(path, source))?;
    if fixed[..4] != RPM_HEADER_MAGIC {
        return Err(invalid(path, "RPM header magic is invalid"));
    }
    let count = u32::from_be_bytes(fixed[8..12].try_into().unwrap());
    let data_size = u32::from_be_bytes(fixed[12..16].try_into().unwrap());
    if count > MAX_HEADER_INDEXES || data_size > MAX_HEADER_DATA_BYTES {
        return Err(invalid(path, "RPM header exceeds bounded index or data limits"));
    }
    let index_bytes = usize::try_from(count).unwrap().checked_mul(16).ok_or_else(|| invalid(path, "RPM header index size overflows"))?;
    let mut raw_indexes = vec![0_u8; index_bytes];
    file.read_exact(&mut raw_indexes).map_err(|source| io_error(path, source))?;
    let mut indexes = Vec::with_capacity(usize::try_from(count).unwrap());
    for chunk in raw_indexes.as_chunks::<16>().0 {
        indexes.push(Index {
            tag: u32::from_be_bytes(chunk[0..4].try_into().unwrap()),
            kind: u32::from_be_bytes(chunk[4..8].try_into().unwrap()),
            offset: u32::from_be_bytes(chunk[8..12].try_into().unwrap()),
            count: u32::from_be_bytes(chunk[12..16].try_into().unwrap()),
        });
    }
    let mut data = vec![0_u8; usize::try_from(data_size).unwrap()];
    file.read_exact(&mut data).map_err(|source| io_error(path, source))?;
    let end = file.stream_position().map_err(|source| io_error(path, source))?;
    Ok(Header { end, indexes, data })
}

fn align_eight(value: u64) -> Result<u64, RpmError> {
    value.checked_add(7).map(|aligned| aligned & !7).ok_or_else(|| invalid(Path::new("<RPM>"), "RPM header alignment overflows"))
}

fn invalid(path: &Path, message: &str) -> RpmError {
    RpmError::Invalid { path: path.to_path_buf(), message: message.to_owned() }
}

fn io_error(path: &Path, source: io::Error) -> RpmError {
    RpmError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs;

    fn pad(output: &mut Vec<u8>, alignment: usize) {
        while output.len() % alignment != 0 {
            output.push(0);
        }
    }

    fn newc_record(name: &str, mode: u32, inode: u64, data: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let fields = [inode, u64::from(mode), 0, 0, 1, 0, u64::try_from(data.len()).unwrap(), 0, 0, 0, 0, u64::try_from(name_bytes.len() + 1).unwrap(), 0];
        let mut output = Vec::from(b"070701".as_slice());
        for field in fields {
            output.extend(format!("{field:08x}").as_bytes());
        }
        output.extend_from_slice(name_bytes);
        output.push(0);
        pad(&mut output, 4);
        output.extend_from_slice(data);
        pad(&mut output, 4);
        output
    }

    fn build_cpio(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cpio = Vec::new();
        for (i, &(name, data)) in files.iter().enumerate() {
            cpio.extend(newc_record(name, 0o100_644, (i + 1) as u64, data));
        }
        cpio.extend(newc_record("TRAILER!!!", 0, 0, &[]));
        cpio
    }

    fn build_rpm(compressor: Option<&str>, payload_bytes: &[u8]) -> Vec<u8> {
        let mut rpm = Vec::new();
        // 1. Lead (96 bytes)
        rpm.extend_from_slice(&RPM_LEAD_MAGIC);
        rpm.resize(96, 0);

        // 2. Signature Header (16 bytes, empty)
        rpm.extend_from_slice(&RPM_HEADER_MAGIC);
        rpm.extend_from_slice(&[0; 12]);

        // 3. Align 8
        pad(&mut rpm, 8);

        // 4. Main Header
        rpm.extend_from_slice(&RPM_HEADER_MAGIC);
        rpm.extend_from_slice(&[0; 4]); // reserved

        if let Some(comp) = compressor {
            // 1 index entry for tag 1125
            rpm.extend_from_slice(&1_u32.to_be_bytes()); // count = 1
            let comp_null = format!("{comp}\0");
            rpm.extend_from_slice(&(comp_null.len() as u32).to_be_bytes()); // data_size

            // Index entry: tag, kind (6 = string), offset (0), count (1)
            rpm.extend_from_slice(&PAYLOAD_COMPRESSOR_TAG.to_be_bytes());
            rpm.extend_from_slice(&6_u32.to_be_bytes());
            rpm.extend_from_slice(&0_u32.to_be_bytes());
            rpm.extend_from_slice(&1_u32.to_be_bytes());

            // Data
            rpm.extend_from_slice(comp_null.as_bytes());
        } else {
            rpm.extend_from_slice(&[0; 8]); // count = 0, data_size = 0
        }

        // 5. Payload
        rpm.extend_from_slice(payload_bytes);
        rpm
    }

    #[test]
    fn test_rpm_uncompressed_and_compressed() {
        let temp = TestDir::new("rpm-backend-test");

        // 1. Uncompressed RPM
        let cpio_data = build_cpio(&[("etc/app.conf", b"setting=true\n")]);
        let rpm_bytes = build_rpm(None, &cpio_data);
        let rpm_path = temp.path("sample.rpm");
        fs::write(&rpm_path, rpm_bytes).unwrap();

        // List
        let entries = list(&rpm_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "etc/app.conf");
        assert_eq!(entries[0].size, 13);

        // Test
        let test_report = test(&rpm_path, &TestOptions::default()).unwrap();
        assert_eq!(test_report.entries, 1);
        assert_eq!(test_report.bytes, 13);

        // Extract
        let dest = temp.path("out");
        let extract_report = extract(&rpm_path, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(extract_report.entries, 1);
        assert_eq!(fs::read(dest.join("etc/app.conf")).unwrap(), b"setting=true\n");

        // Copy by index
        let mut copied = Vec::new();
        let written = copy(&rpm_path, 0, &mut copied).unwrap();
        assert_eq!(written, 13);
        assert_eq!(copied, b"setting=true\n");

        // Copy by path occurrence
        let mut copied_occ = Vec::new();
        let written_occ = copy_by_path_occurrence(&rpm_path, "etc/app.conf", 0, &mut copied_occ).unwrap();
        assert_eq!(written_occ, 13);
        assert_eq!(copied_occ, b"setting=true\n");

        // 2. Gzip-compressed RPM
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &cpio_data).unwrap();
        let compressed_payload = gz.finish().unwrap();

        let rpm_gz_bytes = build_rpm(Some("gzip"), &compressed_payload);
        let rpm_gz_path = temp.path("sample_gz.rpm");
        fs::write(&rpm_gz_path, rpm_gz_bytes).unwrap();

        let entries_gz = list(&rpm_gz_path).unwrap();
        assert_eq!(entries_gz.len(), 1);
        assert_eq!(entries_gz[0].path, "etc/app.conf");

        let dest_gz = temp.path("out_gz");
        let report_gz = extract(&rpm_gz_path, &dest_gz, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(report_gz.entries, 1);
        assert_eq!(fs::read(dest_gz.join("etc/app.conf")).unwrap(), b"setting=true\n");
    }

    #[test]
    fn test_rpm_error_handling() {
        let temp = TestDir::new("rpm-backend-errors");
        let non_existent = temp.path("missing.rpm");
        assert!(list(&non_existent).is_err());
        assert!(test(&non_existent, &TestOptions::default()).is_err());
        assert!(extract(&non_existent, temp.path("out"), ExtractionPolicy::default(), None, None).is_err());
        assert!(copy(&non_existent, 0, &mut Vec::new()).is_err());

        // Short lead
        let short_lead = temp.path("short.rpm");
        fs::write(&short_lead, b"short").unwrap();
        assert!(list(&short_lead).is_err());

        // Invalid lead magic
        let mut bad_magic = [0_u8; 96];
        bad_magic[0..4].copy_from_slice(b"bad!");
        let bad_magic_path = temp.path("bad_magic.rpm");
        fs::write(&bad_magic_path, bad_magic).unwrap();
        assert!(list(&bad_magic_path).is_err());

        // Unsupported compressor
        let cpio_data = build_cpio(&[("f.txt", b"x")]);
        let unsupported_rpm = build_rpm(Some("unknown_algo"), &cpio_data);
        let unsupp_path = temp.path("unsupp.rpm");
        fs::write(&unsupp_path, unsupported_rpm).unwrap();
        assert!(list(&unsupp_path).is_err());

        // Error types & Display coverage
        let inv_err = RpmError::Invalid { path: PathBuf::from("a.rpm"), message: "corrupt".to_string() };
        assert!(inv_err.to_string().contains("invalid RPM"));
        assert!(std::error::Error::source(&inv_err).is_none());

        let io_err = RpmError::Io { path: PathBuf::from("b.rpm"), source: io::Error::new(io::ErrorKind::NotFound, "err") };
        assert!(io_err.to_string().contains("I/O failed"));
        assert!(std::error::Error::source(&io_err).is_some());
    }
}
