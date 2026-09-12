//! Bounded native CPIO reader for package and initramfs payloads.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, OverwriteResolver};
use filetime::FileTime;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";
const ODC_MAGIC: &[u8; 6] = b"070707";
const BINARY_MAGIC_BE: [u8; 2] = [0x71, 0xc7];
const BINARY_MAGIC_LE: [u8; 2] = [0xc7, 0x71];
const TRAILER_NAME: &str = "TRAILER!!!";
const MAX_NAME_BYTES: u64 = 16 * 1024 * 1024;

/// Supported CPIO wire encodings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CpioFormat {
    /// SVR4 portable ASCII format without checksums.
    Newc,
    /// SVR4 portable ASCII format with byte-sum checksums.
    Crc,
    /// POSIX portable character format.
    Odc,
    /// Binary format with big- or little-endian 16-bit fields.
    Binary { little_endian: bool },
}

/// One normalized CPIO entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CpioEntry {
    /// Archive-order index used as the retained engine entry ID.
    pub index: usize,
    /// Archive member path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Payload size in bytes.
    pub size: u64,
    /// Unix mode bits.
    pub mode: u32,
    /// Modification time in seconds since the Unix epoch.
    pub modified: Option<String>,
    /// Link target for symbolic and hard links.
    pub link_target: Option<String>,
}

/// Normalized CPIO operation report.
pub type CpioReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by native CPIO operations.
#[derive(Debug)]
pub enum CpioError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The CPIO structure is malformed or uses an unsupported encoding.
    Invalid { path: PathBuf, message: String },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl fmt::Display for CpioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid CPIO archive {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for CpioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

impl From<ExtractionSafetyError> for CpioError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Lists entries from a supported CPIO archive.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<CpioEntry>, CpioError> {
    Ok(parse(path.as_ref())?.entries.into_iter().map(|entry| entry.public).collect())
}

/// Verifies selected or all CPIO member payloads and CRC checksums.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<CpioReport, CpioError> {
    let path = path.as_ref();
    let parsed = parse(path)?;
    let mut file = open(path)?;
    let mut report = CpioReport::default();
    for entry in parsed.entries {
        if options.is_cancelled() {
            return Err(CpioError::Cancelled);
        }
        if !options.selects(&entry.public.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        verify_payload(&mut file, path, &entry)?;
        report.entries = report.entries.saturating_add(1);
        report.bytes = report.bytes.saturating_add(entry.public.size_for_bytes());
    }
    Ok(report)
}

/// Extracts all entries, or one retained entry by archive-order index.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_index: Option<usize>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<CpioReport, CpioError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let parsed = parse(path)?;
    let mut file = open(path)?;
    let mut planner = crate::safety::ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    let mut report = CpioReport::default();
    let mut deferred_directories = Vec::new();
    let mut deferred_hardlinks = Vec::new();

    for entry in parsed.entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(CpioError::Cancelled);
        }
        if selected_index.is_some_and(|selected| selected != entry.public.index) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let safety_entry = ExtractionEntry {
            archive_path: entry.public.path.clone(),
            kind: entry.extraction_kind(),
            uncompressed_size: Some(entry.public.size),
            compressed_size: Some(entry.public.size),
        };
        // `find . | cpio -o` - the canonical way to build a cpio archive -
        // records the root as a `.` entry. Its path normalizes to empty, which
        // safety planning rejects, so it has to be skipped before validation
        // exactly as the shared extraction loop does for the other formats.
        // The check requires a directory kind, so an empty-pathed file entry
        // is still rejected.
        if crate::extract_materialize::is_archive_root_directory(&safety_entry.archive_path, &safety_entry.kind) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            report.warnings.push("skipped archive root directory entry".to_owned());
            continue;
        }
        let decision = planner.validate_entry(&safety_entry)?;
        let crate::safety::ExtractionDecision::Write { destination_path, link_target_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        if matches!(safety_entry.kind, ExtractionEntryKind::Directory) {
            if replace_existing {
                crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            }
            std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
            deferred_directories.push((destination_path, entry.metadata()));
            report.entries = report.entries.saturating_add(1);
            continue;
        }
        if matches!(safety_entry.kind, ExtractionEntryKind::Hardlink { .. }) {
            let source = link_target_path.ok_or_else(|| invalid(path, "hardlink entry has no target"))?;
            deferred_hardlinks.push(crate::extract_materialize::DeferredHardlink { source_path: source, destination_path });
            continue;
        }
        if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
            crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
        }
        match safety_entry.kind {
            ExtractionEntryKind::File => {
                let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                let copied = copy_payload(&mut file, path, &entry, output.file_mut().map_err(|source| io_error(&destination_path, source))?)?;
                output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
                apply_metadata(&destination_path, entry.metadata())?;
                report.entries = report.entries.saturating_add(1);
                report.bytes = report.bytes.saturating_add(copied);
            }
            ExtractionEntryKind::Symlink { target } => {
                if crate::safety::should_skip_symlink_materialization(&ExtractionEntryKind::Symlink { target: target.clone() }) {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(crate::safety::unsupported_symlink_warning(&entry.public.path));
                } else {
                    crate::extract_materialize::write_symlink(&target, &destination_path).map_err(|source| io_error(&destination_path, source))?;
                    crate::extract_materialize::apply_symlink_mtime(&destination_path, entry.mtime()).map_err(|source| io_error(&destination_path, source))?;
                    report.entries = report.entries.saturating_add(1);
                }
            }
            ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                return Err(CpioError::Io {
                    path: destination_path,
                    source: io::Error::new(io::ErrorKind::Unsupported, "special CPIO entry reached materialization after safety planning"),
                });
            }
            ExtractionEntryKind::Directory | ExtractionEntryKind::Hardlink { .. } => unreachable!(),
        }
    }

    crate::extract_materialize::materialize_deferred_hardlinks(&deferred_hardlinks)
        .map_err(|source| io_error(deferred_hardlinks.first().map_or(destination, |link| link.destination_path.as_path()), source))?;
    for (path, metadata) in deferred_directories {
        apply_metadata(&path, metadata)?;
    }
    report.entries = report.entries.saturating_add(deferred_hardlinks.len());
    Ok(report)
}

/// Extracts one retained entry by its path and duplicate occurrence in the
/// session listing.
pub fn extract_by_path_occurrence(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    selected_path: &str,
    selected_occurrence: usize,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<CpioReport, CpioError> {
    let path = path.as_ref();
    let selected_index = find_path_occurrence(path, selected_path, selected_occurrence)?;
    extract(path, destination, policy, resolver, Some(selected_index), cancellation)
}

/// Copies one retained regular-file entry to a caller-owned writer.
pub fn copy(path: impl AsRef<Path>, entry_index: usize, writer: &mut dyn Write) -> Result<u64, CpioError> {
    let path = path.as_ref();
    let entry = parse(path)?
        .entries
        .into_iter()
        .find(|entry| entry.public.index == entry_index)
        .ok_or_else(|| io_error(path, io::Error::new(io::ErrorKind::NotFound, "retained CPIO entry ID is not present")))?;
    if !matches!(entry.public.kind, BrowserEntryKind::File) {
        return Err(io_error(Path::new(&entry.public.path), io::Error::new(io::ErrorKind::InvalidInput, "retained CPIO entry is not a regular file")));
    }
    let mut file = open(path)?;
    copy_payload(&mut file, path, &entry, writer)
}

/// Copies one retained regular-file entry by path and duplicate occurrence.
pub fn copy_by_path_occurrence(path: impl AsRef<Path>, selected_path: &str, selected_occurrence: usize, writer: &mut dyn Write) -> Result<u64, CpioError> {
    let path = path.as_ref();
    let entry_index = find_path_occurrence(path, selected_path, selected_occurrence)?;
    copy(path, entry_index, writer)
}

fn find_path_occurrence(path: &Path, selected_path: &str, selected_occurrence: usize) -> Result<usize, CpioError> {
    let mut occurrence = 0_usize;
    parse(path)?
        .entries
        .into_iter()
        .find_map(|entry| {
            if entry.public.path != selected_path {
                return None;
            }
            let matches = occurrence == selected_occurrence;
            occurrence = occurrence.saturating_add(1);
            matches.then_some(entry.public.index)
        })
        .ok_or_else(|| io_error(path, io::Error::new(io::ErrorKind::NotFound, "retained CPIO entry is not present")))
}

impl CpioEntry {
    fn size_for_bytes(&self) -> u64 {
        matches!(self.kind, BrowserEntryKind::File).then_some(self.size).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum WireFormat {
    Newc,
    Crc,
    Odc,
    Binary { little_endian: bool },
}

#[derive(Debug)]
struct ParsedEntry {
    public: CpioEntry,
    data_offset: u64,
    checksum: Option<u32>,
    inode: u64,
    device: (u64, u64),
    nlink: u64,
}

impl ParsedEntry {
    fn extraction_kind(&self) -> ExtractionEntryKind {
        match self.public.kind {
            BrowserEntryKind::File => {
                if let Some(target) = self.public.link_target.as_ref() {
                    ExtractionEntryKind::Hardlink { target: target.clone().into() }
                } else {
                    ExtractionEntryKind::File
                }
            }
            BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
            BrowserEntryKind::Symlink => ExtractionEntryKind::Symlink { target: self.public.link_target.clone().unwrap_or_default().into() },
            BrowserEntryKind::Hardlink => ExtractionEntryKind::Hardlink { target: self.public.link_target.clone().unwrap_or_default().into() },
            BrowserEntryKind::Special | BrowserEntryKind::FileCopy => ExtractionEntryKind::Special,
        }
    }

    fn metadata(&self) -> Metadata {
        Metadata { mode: Some(self.public.mode), mtime: self.mtime() }
    }

    fn mtime(&self) -> Option<FileTime> {
        self.public.modified.as_ref()?.parse::<i64>().ok().map(|seconds| FileTime::from_unix_time(seconds, 0))
    }
}

#[derive(Debug, Clone, Copy)]
struct Metadata {
    mode: Option<u32>,
    mtime: Option<FileTime>,
}

fn parse(path: &Path) -> Result<ParsedArchive, CpioError> {
    let mut file = open(path)?;
    let format = detect_format(&mut file, path)?;
    let mut entries = Vec::new();
    let mut link_candidates = Vec::new();
    loop {
        let Some(record) = read_record(&mut file, path, format)? else {
            return Err(invalid(path, "archive ended before TRAILER!!!"));
        };
        if record.name == TRAILER_NAME {
            break;
        }
        let index = entries.len();
        let kind = entry_kind(record.mode);
        let link_target = if kind == BrowserEntryKind::Symlink { Some(read_link_target(&mut file, path, record.data_offset, record.size)?) } else { None };
        skip_payload(&mut file, path, record.data_offset, record.size, format)?;
        let public = CpioEntry { index, path: record.name, kind, size: record.size, mode: record.mode, modified: Some(record.mtime.to_string()), link_target };
        let entry =
            ParsedEntry { public, data_offset: record.data_offset, checksum: record.checksum, inode: record.inode, device: record.device, nlink: record.nlink };
        if entry.public.kind == BrowserEntryKind::File && entry.nlink > 1 {
            link_candidates.push((entry.inode, entry.device, index));
        }
        entries.push(entry);
    }
    assign_hardlinks(&mut entries, link_candidates);
    Ok(ParsedArchive { entries })
}

#[derive(Debug)]
struct ParsedArchive {
    entries: Vec<ParsedEntry>,
}

#[derive(Debug)]
struct Record {
    name: String,
    mode: u32,
    mtime: u64,
    size: u64,
    data_offset: u64,
    checksum: Option<u32>,
    inode: u64,
    device: (u64, u64),
    nlink: u64,
}

fn detect_format(file: &mut File, path: &Path) -> Result<WireFormat, CpioError> {
    let mut magic = [0_u8; 6];
    file.read_exact(&mut magic).map_err(|source| io_error(path, source))?;
    file.seek(SeekFrom::Start(0)).map_err(|source| io_error(path, source))?;
    if &magic == NEWC_MAGIC {
        Ok(WireFormat::Newc)
    } else if &magic == CRC_MAGIC {
        Ok(WireFormat::Crc)
    } else if &magic == ODC_MAGIC {
        Ok(WireFormat::Odc)
    } else if magic[..2] == BINARY_MAGIC_BE {
        Ok(WireFormat::Binary { little_endian: false })
    } else if magic[..2] == BINARY_MAGIC_LE {
        Ok(WireFormat::Binary { little_endian: true })
    } else {
        Err(invalid(path, "unsupported CPIO magic; supported encodings are newc, crc, odc, and binary"))
    }
}

fn read_record(file: &mut File, path: &Path, format: WireFormat) -> Result<Option<Record>, CpioError> {
    match format {
        WireFormat::Newc | WireFormat::Crc => read_newc_record(file, path, format),
        WireFormat::Odc => read_odc_record(file, path),
        WireFormat::Binary { little_endian } => read_binary_record(file, path, little_endian),
    }
}

fn read_newc_record(file: &mut File, path: &Path, format: WireFormat) -> Result<Option<Record>, CpioError> {
    let mut header = [0_u8; 110];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::UnexpectedEof && file.stream_position().unwrap_or(0) == 0 => return Ok(None),
        Err(source) => return Err(io_error(path, source)),
    }
    let expected = match format {
        WireFormat::Newc => NEWC_MAGIC,
        WireFormat::Crc => CRC_MAGIC,
        _ => unreachable!(),
    };
    if &header[..6] != expected {
        return Err(invalid(path, "record magic does not match the archive encoding"));
    }
    let fields = (0..13).map(|index| parse_hex(path, &header[6 + index * 8..14 + index * 8])).collect::<Result<Vec<_>, _>>()?;
    let namesize = fields[11];
    let size = fields[6];
    let name = read_name(file, path, namesize, 4, 110)?;
    let data_offset = file.stream_position().map_err(|source| io_error(path, source))?;
    Ok(Some(Record {
        name,
        mode: u32::try_from(fields[1]).map_err(|_| invalid(path, "mode exceeds native width"))?,
        mtime: fields[5],
        size,
        data_offset,
        checksum: (format == WireFormat::Crc).then_some(u32::try_from(fields[12]).unwrap_or(u32::MAX)),
        inode: fields[0],
        device: (fields[2], fields[3]),
        nlink: fields[4],
    }))
}

fn read_odc_record(file: &mut File, path: &Path) -> Result<Option<Record>, CpioError> {
    let mut header = [0_u8; 76];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::UnexpectedEof && file.stream_position().unwrap_or(0) == 0 => return Ok(None),
        Err(source) => return Err(io_error(path, source)),
    }
    if &header[..6] != ODC_MAGIC {
        return Err(invalid(path, "record magic does not match the archive encoding"));
    }
    let dev = parse_octal(path, &header[6..12])?;
    let inode = parse_octal(path, &header[12..18])?;
    let mode = parse_octal(path, &header[18..24])?;
    let nlink = parse_octal(path, &header[36..42])?;
    let mtime = parse_octal(path, &header[48..59])?;
    let namesize = parse_octal(path, &header[59..65])?;
    let size = parse_octal(path, &header[65..76])?;
    let name = read_name(file, path, namesize, 1, 76)?;
    let data_offset = file.stream_position().map_err(|source| io_error(path, source))?;
    Ok(Some(Record {
        name,
        mode: u32::try_from(mode).map_err(|_| invalid(path, "mode exceeds native width"))?,
        mtime,
        size,
        data_offset,
        checksum: None,
        inode,
        device: (dev, 0),
        nlink,
    }))
}

fn read_binary_record(file: &mut File, path: &Path, little_endian: bool) -> Result<Option<Record>, CpioError> {
    let mut header = [0_u8; 26];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::UnexpectedEof && file.stream_position().unwrap_or(0) == 0 => return Ok(None),
        Err(source) => return Err(io_error(path, source)),
    }
    let endian = |bytes: &[u8]| -> u16 { if little_endian { u16::from_le_bytes([bytes[0], bytes[1]]) } else { u16::from_be_bytes([bytes[0], bytes[1]]) } };
    if endian(&header[..2]) != 0x71c7 {
        return Err(invalid(path, "record magic does not match the archive encoding"));
    }
    let fields = (0..13).map(|index| endian(&header[index * 2..index * 2 + 2])).collect::<Vec<_>>();
    let name = read_name(file, path, u64::from(fields[10]), 2, 26)?;
    let data_offset = file.stream_position().map_err(|source| io_error(path, source))?;
    Ok(Some(Record {
        name,
        mode: u32::from(fields[3]),
        mtime: (u64::from(fields[8]) << 16) | u64::from(fields[9]),
        size: (u64::from(fields[11]) << 16) | u64::from(fields[12]),
        data_offset,
        checksum: None,
        inode: u64::from(fields[2]),
        device: (u64::from(fields[1]), 0),
        nlink: u64::from(fields[6]),
    }))
}

fn read_name(file: &mut File, path: &Path, size: u64, alignment: u64, header_size: u64) -> Result<String, CpioError> {
    if size == 0 || size > MAX_NAME_BYTES {
        return Err(invalid(path, "CPIO pathname length is outside the supported bound"));
    }
    let length = usize::try_from(size).map_err(|_| invalid(path, "CPIO pathname length does not fit memory"))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes).map_err(|source| io_error(path, source))?;
    if bytes.last() != Some(&0) {
        return Err(invalid(path, "CPIO pathname is not NUL terminated"));
    }
    skip_padding(file, path, header_size.saturating_add(size), alignment)?;
    Ok(String::from_utf8_lossy(&bytes[..bytes.len() - 1]).into_owned())
}

fn read_link_target(file: &mut File, path: &Path, offset: u64, size: u64) -> Result<String, CpioError> {
    file.seek(SeekFrom::Start(offset)).map_err(|source| io_error(path, source))?;
    let length = usize::try_from(size).map_err(|_| invalid(path, "CPIO symlink target is too large"))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes).map_err(|source| io_error(path, source))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn skip_payload(file: &mut File, path: &Path, offset: u64, size: u64, format: WireFormat) -> Result<(), CpioError> {
    let end = offset.checked_add(size).ok_or_else(|| invalid(path, "CPIO payload offset overflows"))?;
    file.seek(SeekFrom::Start(end)).map_err(|source| io_error(path, source))?;
    let alignment = match format {
        WireFormat::Newc | WireFormat::Crc => 4,
        WireFormat::Odc => 1,
        WireFormat::Binary { .. } => 2,
    };
    skip_padding(file, path, size, alignment)
}

fn skip_padding(file: &mut File, path: &Path, size: u64, alignment: u64) -> Result<(), CpioError> {
    let padding = (alignment - (size % alignment)) % alignment;
    if padding != 0 {
        file.seek(SeekFrom::Current(i64::try_from(padding).map_err(|_| invalid(path, "CPIO padding is too large"))?))
            .map_err(|source| io_error(path, source))?;
    }
    Ok(())
}

fn assign_hardlinks(entries: &mut [ParsedEntry], candidates: Vec<(u64, (u64, u64), usize)>) {
    for (inode, device, index) in candidates {
        if entries[index].public.size != 0 {
            continue;
        }
        let Some(target) = entries
            .iter()
            .find(|entry| entry.public.kind == BrowserEntryKind::File && entry.public.size != 0 && entry.inode == inode && entry.device == device)
        else {
            continue;
        };
        let target_path = target.public.path.clone();
        entries[index].public.kind = BrowserEntryKind::Hardlink;
        entries[index].public.link_target = Some(target_path);
    }
}

fn verify_payload(file: &mut File, path: &Path, entry: &ParsedEntry) -> Result<(), CpioError> {
    if entry.public.kind != BrowserEntryKind::File && entry.public.kind != BrowserEntryKind::Symlink {
        return Ok(());
    }
    let mut sink = io::sink();
    let checksum = copy_payload(file, path, entry, &mut sink)?;
    if let Some(expected) = entry.checksum
        && checksum != u64::from(expected)
    {
        return Err(invalid(path, format!("CPIO CRC mismatch for {}", entry.public.path)));
    }
    Ok(())
}

fn copy_payload(file: &mut File, path: &Path, entry: &ParsedEntry, writer: &mut dyn Write) -> Result<u64, CpioError> {
    file.seek(SeekFrom::Start(entry.data_offset)).map_err(|source| io_error(path, source))?;
    let mut limited = (&mut *file).take(entry.public.size);
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut bytes = 0_u64;
    let mut checksum = 0_u64;
    loop {
        let read = limited.read(&mut buffer).map_err(|source| io_error(path, source))?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_err(|source| io_error(path, source))?;
        checksum = checksum.wrapping_add(buffer[..read].iter().map(|byte| u64::from(*byte)).sum::<u64>());
        bytes = bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    if bytes != entry.public.size {
        return Err(invalid(path, format!("CPIO payload is truncated for {}", entry.public.path)));
    }
    Ok(if entry.checksum.is_some() { checksum } else { bytes })
}

fn entry_kind(mode: u32) -> BrowserEntryKind {
    match mode & 0o170_000 {
        0o040_000 => BrowserEntryKind::Directory,
        0o120_000 => BrowserEntryKind::Symlink,
        0o100_000 => BrowserEntryKind::File,
        _ => BrowserEntryKind::Special,
    }
}

fn parse_hex(path: &Path, bytes: &[u8]) -> Result<u64, CpioError> {
    u64::from_str_radix(std::str::from_utf8(bytes).unwrap_or(""), 16).map_err(|_| invalid(path, "CPIO hexadecimal field is invalid"))
}

fn parse_octal(path: &Path, bytes: &[u8]) -> Result<u64, CpioError> {
    let text = std::str::from_utf8(bytes).unwrap_or("").trim();
    u64::from_str_radix(if text.is_empty() { "0" } else { text }, 8).map_err(|_| invalid(path, "CPIO octal field is invalid"))
}

fn apply_metadata(path: &Path, metadata: Metadata) -> Result<(), CpioError> {
    crate::extract_materialize::apply_metadata(path, metadata.mode, metadata.mtime).map_err(|source| io_error(path, source))
}

fn open(path: &Path) -> Result<File, CpioError> {
    File::open(path).map_err(|source| io_error(path, source))
}

fn invalid(path: &Path, message: impl Into<String>) -> CpioError {
    CpioError::Invalid { path: path.to_path_buf(), message: message.into() }
}

fn io_error(path: &Path, source: io::Error) -> CpioError {
    CpioError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
mod tests {
    use super::{BrowserEntryKind, CpioError, NEWC_MAGIC, extract, list, test};
    use crate::engine::types::TestOptions;
    use crate::safety::ExtractionPolicy;
    use crate::test_support::TestDir;
    use std::fs;

    #[test]
    fn newc_reader_lists_and_verifies_regular_payload() {
        let dir = TestDir::new("cpio-newc");
        let archive = dir.path("payload.cpio");
        let bytes = newc_record("hello.txt", 0o100_644, 7, b"hello").into_iter().chain(newc_record("TRAILER!!!", 0, 0, &[])).collect::<Vec<_>>();
        fs::write(&archive, bytes).unwrap();

        let entries = list(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, BrowserEntryKind::File);
        assert_eq!(entries[0].size, 5);
        let report = test(&archive, &TestOptions::default()).unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 5);
    }

    /// `find . | cpio -o` - the documented way to build a cpio archive - records
    /// the archive root as a `.` entry, whose path normalizes to empty. Failing
    /// the whole extraction over it made standard archives unextractable while
    /// both bsdtar and cpio skip it.
    #[test]
    fn archive_root_dot_entry_is_skipped_instead_of_failing_extraction() {
        let dir = TestDir::new("cpio-root-dot");
        let archive = dir.path("root.cpio");
        let bytes = newc_record(".", 0o040_755, 1, &[])
            .into_iter()
            .chain(newc_record("a.txt", 0o100_644, 2, b"hello"))
            .chain(newc_record("TRAILER!!!", 0, 0, &[]))
            .collect::<Vec<_>>();
        fs::write(&archive, bytes).unwrap();

        let destination = dir.path("out");
        let report = extract(&archive, &destination, ExtractionPolicy::default(), None, None, None).unwrap();

        assert_eq!(fs::read_to_string(destination.join("a.txt")).unwrap(), "hello", "the real entries must still extract");
        assert_eq!(report.skipped_entries, 1, "the root entry is skipped, not written");
        assert!(report.warnings.iter().any(|warning| warning == "skipped archive root directory entry"), "{:?}", report.warnings);
    }

    /// The root skip is gated on the directory kind: a *file* whose path
    /// normalizes to empty has no safe destination and must still be rejected.
    #[test]
    fn empty_pathed_file_entry_is_still_rejected() {
        let dir = TestDir::new("cpio-root-dot-file");
        let archive = dir.path("root-file.cpio");
        let bytes = newc_record(".", 0o100_644, 1, b"hello").into_iter().chain(newc_record("TRAILER!!!", 0, 0, &[])).collect::<Vec<_>>();
        fs::write(&archive, bytes).unwrap();

        let error = extract(&archive, dir.path("out"), ExtractionPolicy::default(), None, None, None).unwrap_err();
        assert!(matches!(error, CpioError::Safety(_)), "expected a safety rejection, got {error:?}");
    }

    #[test]
    fn binary_reader_accepts_little_endian_records() {
        let dir = TestDir::new("cpio-binary");
        let archive = dir.path("payload.cpio");
        let mut bytes = binary_record("hello.txt", 0o100_644, b"ok");
        bytes.extend(binary_record("TRAILER!!!", 0, &[]));
        fs::write(&archive, bytes).unwrap();

        let entries = list(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "hello.txt");
        assert_eq!(test(&archive, &TestOptions::default()).unwrap().bytes, 2);
    }

    fn newc_record(name: &str, mode: u32, inode: u64, data: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let fields = [inode, u64::from(mode), 0, 0, 1, 0, u64::try_from(data.len()).unwrap(), 0, 0, 0, 0, u64::try_from(name_bytes.len() + 1).unwrap(), 0];
        let mut output = Vec::from(NEWC_MAGIC.as_slice());
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

    fn binary_record(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let name_size = u16::try_from(name.len() + 1).unwrap();
        let data_size = u16::try_from(data.len()).unwrap();
        let fields = [0x71c7, 0, 1, u16::try_from(mode).unwrap(), 0, 0, 1, 0, 0, 0, name_size, 0, data_size];
        let mut output = Vec::with_capacity(26 + name.len() + data.len() + 4);
        for field in fields {
            output.extend_from_slice(&field.to_le_bytes());
        }
        output.extend_from_slice(name.as_bytes());
        output.push(0);
        pad(&mut output, 2);
        output.extend_from_slice(data);
        pad(&mut output, 2);
        output
    }

    fn pad(output: &mut Vec<u8>, alignment: usize) {
        while !output.len().is_multiple_of(alignment) {
            output.push(0);
        }
    }
}
