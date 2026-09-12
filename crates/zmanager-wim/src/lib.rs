#![allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]

//! Read-only parsing and decompression for Windows Imaging (WIM) files.
//!
//! This library owns WIM container parsing, split-set discovery, resource
//! decoding, metadata directory trees, and the WIM-specific XPRESS-Huffman and
//! LZX dialects. Filesystem extraction policy remains in zmanager-core.
//!
//! LZMS and solid resources are intentionally unsupported; this crate is not an
//! ESD decoder.

use sha1::{Digest as _, Sha1};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use lzx::{Lzxd, WindowSize};

mod lzx;

/// The portable kind of a WIM directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimEntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link or junction represented by an NTFS reparse point.
    Symlink,
}

/// One normalized WIM entry.
#[derive(Debug, Clone)]
pub struct WimEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Normalized archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: WimEntryKind,
    /// Uncompressed file size.
    pub size: u64,
    /// Relative target for a symbolic-link entry.
    pub link_target: Option<String>,
    /// SHA-1 hash for lookup table data resolution.
    pub sha1: [u8; 20],
    /// NTFS reparse tag, or 0 when the entry is not a reparse point. The tag
    /// selects the reparse payload layout, which is otherwise ambiguous.
    pub reparse_tag: u32,
}

/// Error returned when a WIM cannot be parsed or decoded.
#[derive(Debug)]
pub enum WimError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// WIM format or decompression error.
    Invalid { path: PathBuf, message: String },
    /// The WIM is well-formed but uses a feature this library does not decode.
    Unsupported { path: PathBuf, message: String },
}

impl fmt::Display for WimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid WIM {}: {message}", path.display()),
            Self::Unsupported { path, message } => write!(f, "unsupported WIM {}: {message}", path.display()),
        }
    }
}

impl std::error::Error for WimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Invalid { .. } | Self::Unsupported { .. } => None,
        }
    }
}

fn io_error(path: impl AsRef<Path>, source: io::Error) -> WimError {
    WimError::Io { path: path.as_ref().to_path_buf(), source }
}

fn invalid(path: impl AsRef<Path>, message: impl Into<String>) -> WimError {
    WimError::Invalid { path: path.as_ref().to_path_buf(), message: message.into() }
}

fn unsupported(path: impl AsRef<Path>, message: impl Into<String>) -> WimError {
    WimError::Unsupported { path: path.as_ref().to_path_buf(), message: message.into() }
}

const WIM_MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
const WIM_HEADER_SIZE: usize = 208;
const WIM_FLAG_COMPRESSION_XPRESS: u32 = 0x0002_0000;
const WIM_FLAG_COMPRESSION_LZX: u32 = 0x0004_0000;
const WIM_FLAG_COMPRESSION_LZMS: u32 = 0x0008_0000;

const WIM_RESHDR_FLAG_METADATA: u8 = 0x02;
const WIM_RESHDR_FLAG_COMPRESSED: u8 = 0x04;
const WIM_RESHDR_FLAG_SOLID: u8 = 0x10;

/// Size of one lookup-table entry on disk.
const WIM_LOOKUP_ENTRY_SIZE: usize = 50;

// Directory-entry field offsets, per the Windows Imaging File Format
// whitepaper (identical in wimlib's `wim_dentry_on_disk` and 7-Zip's
// `NArchive::NWim::CDatabase`). The fixed portion is 102 bytes; the UTF-16
// file name follows it immediately.
const DENTRY_FIXED_SIZE: usize = 102;
const DENTRY_OFF_LENGTH: usize = 0;
const DENTRY_OFF_ATTRIBUTES: usize = 8;
const DENTRY_OFF_SUBDIR_OFFSET: usize = 16;
const DENTRY_OFF_HASH: usize = 64;
const DENTRY_OFF_REPARSE_TAG: usize = 88;
const DENTRY_OFF_NUM_EXTRA_STREAMS: usize = 96;
const DENTRY_OFF_FILE_NAME_NBYTES: usize = 100;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// Fixed portion of an extra stream entry: `length`, a reserved `u64`, the
/// stream's SHA-1, and its name length. The UTF-16 name follows.
const STREAM_ENTRY_FIXED_SIZE: usize = 38;

/// Guard against a malicious dentry tree that nests without bound. Real WIM
/// trees are far shallower; NTFS itself caps paths well below this.
const MAX_DENTRY_DEPTH: usize = 512;

/// Smallest chunk size a WIM header may declare.
const MIN_CHUNK_SIZE: u32 = 4096;
/// Largest chunk size a WIM header may declare.
const MAX_CHUNK_SIZE: u32 = 1 << 30;

/// Upper bound on a single in-memory resource. WIM resources are read whole
/// because the chunk table is only meaningful for the complete resource; the
/// cap keeps a corrupt or hostile header from requesting an unbounded
/// allocation.
const MAX_RESOURCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Memory budget for retained decompressed resources.
///
/// WIM is single-instance storage: identical files share one SHA-1-keyed
/// resource, so a stream referenced by many entries would otherwise be decoded
/// once per entry, and decoding costs the whole resource. Retaining decoded
/// resources makes that cost proportional to distinct streams instead of to
/// entries. The budget bounds the retention; a resource larger than the whole
/// budget is simply never retained.
const RESOURCE_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Compression algorithm declared by a WIM header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimCompression {
    /// Resources are stored.
    None,
    /// LZX-compressed chunks.
    Lzx,
    /// XPRESS-compressed chunks.
    Xpress,
    /// LZMS-compressed chunks (not decoded by this backend).
    Lzms,
}

/// A WIM resource header (`offset`, sizes, and flags packed into 24 bytes).
#[derive(Debug, Clone, Copy)]
pub struct ResHdr {
    /// Resource flags (`METADATA`, `COMPRESSED`, `SOLID`).
    pub flags: u8,
    /// Byte offset of the resource in its part file.
    pub offset: u64,
    /// Uncompressed resource size.
    pub original_size: u64,
    /// Stored resource size.
    pub compressed_size: u64,
}

impl ResHdr {
    /// Decodes the 24-byte on-disk resource header.
    ///
    /// The layout is `size_in_wim[7] | flags | offset_in_wim | uncompressed_size`
    /// (wimlib's `wim_reshdr_disk`, and the same shape 7-Zip's WIM handler
    /// reads): the stored size occupies the *first* seven bytes and the flags
    /// byte sits directly after it, with the offset following in its own
    /// `u64`. Reading the first `u64` as "flags in the top byte, offset in the
    /// low 56 bits" transposes the offset with the stored size and the two
    /// size fields with each other, which happens to leave the flags byte in
    /// the right place — so the mistake survives until a real WIM is opened.
    fn read(buf: &[u8]) -> Self {
        let mut stored = [0_u8; 8];
        stored[..7].copy_from_slice(&buf[0..7]);
        let compressed_size = u64::from_le_bytes(stored);
        let flags = buf[7];
        let offset = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let original_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        Self { flags, offset, original_size, compressed_size }
    }

    const fn is_compressed(&self) -> bool {
        self.flags & WIM_RESHDR_FLAG_COMPRESSED != 0
    }

    const fn is_solid(&self) -> bool {
        self.flags & WIM_RESHDR_FLAG_SOLID != 0
    }

    const fn is_metadata(&self) -> bool {
        self.flags & WIM_RESHDR_FLAG_METADATA != 0
    }
}

/// Parsed WIM header.
#[derive(Debug, Clone)]
pub struct WimHeader {
    /// Raw header flags.
    pub flags: u32,
    /// Uncompressed chunk size for compressed resources.
    pub chunk_size: u32,
    /// Declared compression algorithm.
    pub compression: WimCompression,
    /// 1-based part number within a split set.
    pub part_number: u16,
    /// Number of parts in the split set (1 for a standalone WIM).
    pub total_parts: u16,
    /// Number of images described by the WIM.
    pub image_count: u32,
    /// Lookup-table resource header.
    pub offset_table_rh: ResHdr,
    /// XML data resource header.
    pub xml_data_rh: ResHdr,
    /// Boot metadata resource header.
    pub boot_metadata_rh: ResHdr,
}

impl WimHeader {
    fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < WIM_HEADER_SIZE || &buf[0..8] != WIM_MAGIC {
            return Err("invalid WIM magic".to_owned());
        }
        let flags = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let mut chunk_size = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        if chunk_size == 0 {
            chunk_size = 32768;
        }
        // A chunk table entry is bounded by the chunk size; reject values that
        // would make the per-chunk arithmetic below meaningless.
        if !chunk_size.is_power_of_two() || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(format!("unsupported WIM chunk size {chunk_size}"));
        }
        let compression = if flags & WIM_FLAG_COMPRESSION_LZX != 0 {
            WimCompression::Lzx
        } else if flags & WIM_FLAG_COMPRESSION_XPRESS != 0 {
            WimCompression::Xpress
        } else if flags & WIM_FLAG_COMPRESSION_LZMS != 0 {
            WimCompression::Lzms
        } else {
            WimCompression::None
        };
        let part_number = u16::from_le_bytes(buf[40..42].try_into().unwrap());
        let total_parts = u16::from_le_bytes(buf[42..44].try_into().unwrap());
        let image_count = u32::from_le_bytes(buf[44..48].try_into().unwrap());
        let offset_table_rh = ResHdr::read(&buf[48..72]);
        let xml_data_rh = ResHdr::read(&buf[72..96]);
        let boot_metadata_rh = ResHdr::read(&buf[96..120]);

        Ok(Self { flags, chunk_size, compression, part_number, total_parts, image_count, offset_table_rh, xml_data_rh, boot_metadata_rh })
    }
}

/// One lookup-table row: a stored stream keyed by its SHA-1.
#[derive(Debug, Clone)]
pub struct WimLookupEntry {
    /// Resource header for the stream.
    pub res: ResHdr,
    /// Part number holding the stream.
    pub part_number: u16,
    /// Reference count recorded in the table.
    pub ref_count: u32,
    /// SHA-1 of the uncompressed stream.
    pub sha1: [u8; 20],
    /// Index of the owning part in [`WimArchive::parts`].
    pub part_index: usize,
}

/// One opened file of a (possibly split) WIM set.
#[derive(Debug)]
struct WimPart {
    path: PathBuf,
    file: File,
    header: WimHeader,
    file_len: u64,
}

/// An opened WIM: every part file of the set, the merged lookup table, and the
/// per-image metadata resources.
#[derive(Debug)]
pub struct WimArchive {
    parts: Vec<WimPart>,
    /// Streams keyed by SHA-1, merged across every available part.
    pub lut: HashMap<[u8; 20], WimLookupEntry>,
    /// Metadata resources in lookup-table order, one per image.
    pub metadata_resources: Vec<WimLookupEntry>,
    /// Decompressed streams retained by SHA-1, bounded by
    /// [`RESOURCE_CACHE_BUDGET_BYTES`].
    resource_cache: HashMap<[u8; 20], Vec<u8>>,
    /// Bytes currently retained in `resource_cache`.
    resource_cache_bytes: usize,
}

impl WimArchive {
    /// Path of the first part of the set.
    #[must_use]
    fn path(&self) -> &Path {
        &self.parts[0].path
    }

    /// Opens `path`, together with every sibling part of a split (`.swm`) set.
    ///
    /// # Errors
    ///
    /// Returns [`WimError::Invalid`] for a malformed header or lookup
    /// table, [`WimError::Unsupported`] for LZMS or solid resources,
    /// and [`WimError::Io`] when a part cannot be read.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WimError> {
        let path = path.as_ref();
        let primary = open_part(path)?;
        let total_parts = primary.header.total_parts.max(1);

        let mut parts = vec![primary];
        let mut missing_parts = Vec::new();
        if total_parts > 1 {
            for part_number in 2..=total_parts {
                match split_part_path(path, part_number) {
                    Some(sibling) => match open_part(&sibling) {
                        Ok(part) => parts.push(part),
                        Err(error) => return Err(error),
                    },
                    None => missing_parts.push(part_number),
                }
            }
        }

        let mut lut: HashMap<[u8; 20], WimLookupEntry> = HashMap::new();
        let mut metadata_resources = Vec::new();
        for (part_index, part) in parts.iter_mut().enumerate() {
            let (rows, metadata) = read_lookup_table(part, part_index)?;
            metadata_resources.extend(metadata);
            for row in rows {
                lut.entry(row.sha1).or_insert(row);
            }
        }

        if !missing_parts.is_empty() {
            let names = missing_parts.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
            return Err(invalid(path, format!("split WIM set is incomplete: part(s) {names} of {total_parts} are missing next to the first part")));
        }

        Ok(Self { parts, lut, metadata_resources, resource_cache: HashMap::new(), resource_cache_bytes: 0 })
    }

    /// Reads the whole resource described by `entry` from its owning part.
    fn read_stream(&mut self, entry: &WimLookupEntry) -> Result<Vec<u8>, WimError> {
        let part = &mut self.parts[entry.part_index];
        read_resource(part, &entry.res)
    }

    /// Reads the metadata resource for one image and parses its dentry tree.
    fn read_image_entries(&mut self, image_index: usize, prefix: Option<&str>, next_index: &mut usize) -> Result<Vec<WimEntry>, WimError> {
        let metadata = self.metadata_resources[image_index].clone();
        let bytes = self.read_stream(&metadata)?;
        let part_path = self.parts[metadata.part_index].path.clone();
        let mut entries = parse_dentries(&bytes, prefix, next_index).map_err(|message| invalid(&part_path, message))?;
        self.resolve_entry_details(&mut entries)?;
        Ok(entries)
    }

    /// Fills in sizes from the lookup table and decodes reparse-point targets.
    fn resolve_entry_details(&mut self, entries: &mut [WimEntry]) -> Result<(), WimError> {
        for entry in entries.iter_mut() {
            if entry.sha1 == [0_u8; 20] {
                continue;
            }
            let Some(lookup) = self.lut.get(&entry.sha1).cloned() else { continue };
            match entry.kind {
                WimEntryKind::Symlink => {
                    let data = self.read_stream(&lookup)?;
                    entry.link_target = decode_reparse_target(&data, entry.reparse_tag);
                }
                _ => entry.size = lookup.res.original_size,
            }
        }
        Ok(())
    }

    /// Walks every image, producing one flat entry list.
    ///
    /// A WIM holding more than one image (a Windows `install.wim` carries one
    /// per edition) is flattened into a synthetic `imageN/` namespace so no
    /// image is silently invisible and paths from different images cannot
    /// collide.
    ///
    /// # Errors
    ///
    /// Returns [`WimError`] when a metadata resource cannot be read or its
    /// directory tree is invalid.
    pub fn entries(&mut self) -> Result<Vec<WimEntry>, WimError> {
        if self.metadata_resources.is_empty() {
            return Err(invalid(self.path(), "no image metadata resource found in WIM"));
        }
        let multi_image = self.metadata_resources.len() > 1;
        let mut entries = Vec::new();
        let mut next_index = 0;
        for image_index in 0..self.metadata_resources.len() {
            let prefix = multi_image.then(|| format!("image{}", image_index + 1));
            entries.extend(self.read_image_entries(image_index, prefix.as_deref(), &mut next_index)?);
        }
        Ok(entries)
    }
}

/// Opens one part file and validates the features it declares.
fn open_part(path: &Path) -> Result<WimPart, WimError> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let file_len = file.metadata().map_err(|source| io_error(path, source))?.len();
    let mut header_buf = [0_u8; WIM_HEADER_SIZE];
    file.read_exact(&mut header_buf).map_err(|source| io_error(path, source))?;
    let header = WimHeader::read(&header_buf).map_err(|message| invalid(path, message))?;

    if header.compression == WimCompression::Lzms {
        return Err(unsupported(
            path,
            "LZMS-compressed images (typically .esd distribution images) are not supported; convert the image with `dism /Export-Image /Compress:max` or `wimlib-imagex export` first",
        ));
    }

    Ok(WimPart { path: path.to_path_buf(), file, header, file_len })
}

/// Derives the file name of part `part_number` of a split WIM set.
///
/// `DISM /Split-Image` and `wimlib-imagex split` both name the parts
/// `base.swm`, `base2.swm`, `base3.swm`, …; part 1 is the file the caller
/// opened. Returns `None` when the sibling does not exist.
fn split_part_path(primary: &Path, part_number: u16) -> Option<PathBuf> {
    let stem = primary.file_stem()?.to_str()?;
    let extension = primary.extension().and_then(|extension| extension.to_str()).unwrap_or("swm");
    let parent = primary.parent()?;
    // `base2.swm` is the documented spelling; `base02.swm` is accepted because
    // some splitters zero-pad.
    for candidate_name in [format!("{stem}{part_number}.{extension}"), format!("{stem}{part_number:02}.{extension}")] {
        let candidate = parent.join(candidate_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Reads and decodes one part's lookup table.
fn read_lookup_table(part: &mut WimPart, part_index: usize) -> Result<(Vec<WimLookupEntry>, Vec<WimLookupEntry>), WimError> {
    let table_header = part.header.offset_table_rh;
    let bytes = read_resource(part, &table_header)?;

    let mut rows = Vec::with_capacity(bytes.len() / WIM_LOOKUP_ENTRY_SIZE);
    let mut metadata = Vec::new();
    let mut offset = 0;
    while offset + WIM_LOOKUP_ENTRY_SIZE <= bytes.len() {
        let res = ResHdr::read(&bytes[offset..offset + 24]);
        let part_number = u16::from_le_bytes(bytes[offset + 24..offset + 26].try_into().unwrap());
        let ref_count = u32::from_le_bytes(bytes[offset + 26..offset + 30].try_into().unwrap());
        let mut sha1 = [0_u8; 20];
        sha1.copy_from_slice(&bytes[offset + 30..offset + 50]);
        offset += WIM_LOOKUP_ENTRY_SIZE;

        if res.is_solid() {
            return Err(unsupported(
                &part.path,
                "solid (LZMS) resources are not supported; re-export the image with `dism /Export-Image /Compress:max` or `wimlib-imagex export --compress=LZX`",
            ));
        }

        let entry = WimLookupEntry { res, part_number, ref_count, sha1, part_index };
        if res.is_metadata() {
            metadata.push(entry.clone());
        }
        rows.push(entry);
    }
    Ok((rows, metadata))
}

/// Reads a complete resource from `part`, decompressing chunked resources.
fn read_resource(part: &mut WimPart, res: &ResHdr) -> Result<Vec<u8>, WimError> {
    if res.original_size == 0 {
        return Ok(Vec::new());
    }
    if res.original_size > MAX_RESOURCE_BYTES {
        return Err(invalid(&part.path, format!("resource declares {} uncompressed bytes, above the {MAX_RESOURCE_BYTES} byte limit", res.original_size)));
    }
    let stored_size = if res.is_compressed() { res.compressed_size } else { res.original_size };
    // The stored bytes must actually be inside the part file: reject the
    // header before allocating for it.
    if stored_size > part.file_len || res.offset > part.file_len - stored_size {
        return Err(invalid(
            &part.path,
            format!("resource at offset {} declares {stored_size} stored bytes, past the end of the {} byte file", res.offset, part.file_len),
        ));
    }

    part.file.seek(SeekFrom::Start(res.offset)).map_err(|source| io_error(&part.path, source))?;
    let mut stored = vec![0_u8; stored_size as usize];
    part.file.read_exact(&mut stored).map_err(|source| io_error(&part.path, source))?;

    if !res.is_compressed() || part.header.compression == WimCompression::None {
        stored.truncate(res.original_size as usize);
        return Ok(stored);
    }
    if part.header.compression == WimCompression::Lzx && part.header.chunk_size as usize > lzx::MAX_WIM_CHUNK_SIZE {
        return Err(unsupported(
            &part.path,
            format!("WIM LZX chunk size {} exceeds this decoder's {} byte limit", part.header.chunk_size, lzx::MAX_WIM_CHUNK_SIZE),
        ));
    }
    if !matches!(part.header.compression, WimCompression::None) && !decodes(part.header.compression) {
        return Err(unsupported(&part.path, undecodable_reason(part.header.compression)));
    }

    decompress_resource(&stored, res.original_size as usize, part.header.chunk_size as usize, part.header.compression)
        .map_err(|message| invalid(&part.path, message))
}

/// Decompresses one chunked WIM resource.
///
/// A compressed resource is a chunk table followed by the chunks themselves.
/// The table holds `chunk_count - 1` entries, each the end offset of the
/// preceding chunk relative to the first chunk's start; the final chunk runs
/// to the end of the stored data. A chunk whose stored size equals its
/// uncompressed size is stored verbatim.
fn decompress_resource(stored: &[u8], original_size: usize, chunk_size: usize, compression: WimCompression) -> Result<Vec<u8>, String> {
    if original_size <= chunk_size {
        // A single-chunk resource carries no chunk table.
        return decompress_chunk(stored, original_size, compression);
    }

    let chunk_count = original_size.div_ceil(chunk_size);
    let entry_size = if original_size as u64 > u64::from(u32::MAX) { 8 } else { 4 };
    let table_size = (chunk_count - 1).checked_mul(entry_size).ok_or_else(|| "chunk table size overflow".to_owned())?;
    if stored.len() < table_size {
        return Err(format!("stored resource is {} bytes, shorter than its {table_size} byte chunk table", stored.len()));
    }
    let (table, chunk_data) = stored.split_at(table_size);

    let mut output = Vec::with_capacity(original_size);
    let mut chunk_start = 0_usize;
    for chunk_index in 0..chunk_count {
        let chunk_end = if chunk_index + 1 == chunk_count {
            chunk_data.len()
        } else {
            let raw = &table[chunk_index * entry_size..(chunk_index + 1) * entry_size];
            let value = if entry_size == 8 { u64::from_le_bytes(raw.try_into().unwrap()) } else { u64::from(u32::from_le_bytes(raw.try_into().unwrap())) };
            usize::try_from(value).map_err(|_| "chunk offset does not fit in this address space".to_owned())?
        };
        if chunk_end < chunk_start || chunk_end > chunk_data.len() {
            return Err(format!("chunk {chunk_index} spans {chunk_start}..{chunk_end}, outside the {} byte chunk area", chunk_data.len()));
        }

        let expected = (original_size - output.len()).min(chunk_size);
        let chunk = &chunk_data[chunk_start..chunk_end];
        if chunk.len() == expected {
            output.extend_from_slice(chunk);
        } else {
            output.extend_from_slice(&decompress_chunk(chunk, expected, compression)?);
        }
        chunk_start = chunk_end;
    }

    if output.len() != original_size {
        return Err(format!("resource decoded to {} bytes, expected {original_size}", output.len()));
    }
    Ok(output)
}

/// Whether this build can decode `compression`.
const fn decodes(compression: WimCompression) -> bool {
    matches!(compression, WimCompression::None | WimCompression::Xpress | WimCompression::Lzx)
}

/// Explains why a compressed WIM cannot be read, and how to convert it.
fn undecodable_reason(compression: WimCompression) -> String {
    let detail = match compression {
        // WIM's LZX dialect omits the leading E8-translation header bit and
        // encodes block sizes in 16 bits where CAB/[MS-PATCH] LZX uses 24, so
        // a CAB decoder desynchronizes on the very first block header.
        WimCompression::Lzx => "LZX resources use WIM's LZX dialect, which differs from CAB/[MS-PATCH] LZX in its block header",
        // WIM uses XPRESS *with Huffman coding* ([MS-XCA] section 2.4): a
        // 256-byte table of 512 four-bit code lengths followed by a 16-bit-word
        // bitstream, not the plain LZ77 XPRESS of section 2.3.
        WimCompression::Xpress => "XPRESS resources use XPRESS with Huffman coding ([MS-XCA] 2.4), not plain LZ77 XPRESS",
        WimCompression::Lzms => "LZMS resources (typically .esd distribution images) use an undocumented Microsoft codec",
        WimCompression::None => "the image is uncompressed",
    };
    format!("{detail}; convert the image with `wimlib-imagex export <wim> all <out.wim> --compress=none`")
}

/// Decompresses one chunk of a resource.
fn decompress_chunk(compressed: &[u8], uncompressed_size: usize, compression: WimCompression) -> Result<Vec<u8>, String> {
    match compression {
        WimCompression::None => {
            let mut out = compressed.to_vec();
            out.truncate(uncompressed_size);
            Ok(out)
        }
        WimCompression::Lzx => {
            if uncompressed_size > lzx::MAX_WIM_CHUNK_SIZE {
                return Err(format!("WIM LZX chunk is {uncompressed_size} bytes; this decoder supports at most {} bytes", lzx::MAX_WIM_CHUNK_SIZE));
            }
            let mut decoder = Lzxd::new_wim(WindowSize::KB32);
            decoder.decompress_next(compressed, uncompressed_size).map(<[u8]>::to_vec).map_err(|error| format!("WIM LZX decompression failed: {error}"))
        }
        WimCompression::Xpress => xpress_huffman::decompress(compressed, uncompressed_size).map_err(|error| format!("XPRESS decompression failed: {error}")),
        WimCompression::Lzms => Err("LZMS decompression is not supported".to_owned()),
    }
}

/// One decoded directory entry: the fixed 102-byte portion plus its UTF-16 name.
struct Dentry {
    length: usize,
    attributes: u32,
    subdir_offset: usize,
    sha1: [u8; 20],
    reparse_tag: u32,
    num_extra_streams: usize,
    name: String,
}

impl Dentry {
    const fn is_directory(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    const fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    const fn is_link_reparse_point(&self) -> bool {
        self.is_reparse_point() && matches!(self.reparse_tag, IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_MOUNT_POINT)
    }
}

/// Reads one directory entry at `offset`.
///
/// Returns `Ok(None)` for the zero-length end-of-list marker.
fn read_dentry(buf: &[u8], offset: usize) -> Result<Option<Dentry>, String> {
    if offset + 8 > buf.len() {
        return Ok(None);
    }
    let length = u64::from_le_bytes(buf[offset + DENTRY_OFF_LENGTH..offset + 8].try_into().unwrap()) as usize;
    if length == 0 {
        return Ok(None);
    }
    if length < DENTRY_FIXED_SIZE || offset + length > buf.len() {
        return Err(format!("directory entry at offset {offset} declares {length} bytes, outside the metadata resource"));
    }
    let dentry = &buf[offset..offset + length];

    let attributes = u32::from_le_bytes(dentry[DENTRY_OFF_ATTRIBUTES..DENTRY_OFF_ATTRIBUTES + 4].try_into().unwrap());
    let subdir_offset = u64::from_le_bytes(dentry[DENTRY_OFF_SUBDIR_OFFSET..DENTRY_OFF_SUBDIR_OFFSET + 8].try_into().unwrap()) as usize;
    let mut sha1 = [0_u8; 20];
    sha1.copy_from_slice(&dentry[DENTRY_OFF_HASH..DENTRY_OFF_HASH + 20]);
    let reparse_tag = u32::from_le_bytes(dentry[DENTRY_OFF_REPARSE_TAG..DENTRY_OFF_REPARSE_TAG + 4].try_into().unwrap());
    let num_extra_streams = u16::from_le_bytes(dentry[DENTRY_OFF_NUM_EXTRA_STREAMS..DENTRY_OFF_NUM_EXTRA_STREAMS + 2].try_into().unwrap()) as usize;
    let file_name_nbytes = u16::from_le_bytes(dentry[DENTRY_OFF_FILE_NAME_NBYTES..DENTRY_OFF_FILE_NAME_NBYTES + 2].try_into().unwrap()) as usize;
    let name = read_utf16_name(dentry, DENTRY_FIXED_SIZE, file_name_nbytes);

    Ok(Some(Dentry { length, attributes, subdir_offset, sha1, reparse_tag, num_extra_streams, name }))
}

/// Reads the extra stream entries that follow a directory entry.
///
/// These sit *after* the dentry and are not covered by its `length` field, so
/// the sibling walk must step over them explicitly. An inode with extra
/// streams stores its unnamed data stream as one of them — with an empty name
/// — and leaves the dentry's own hash field zero, so the unnamed stream's hash
/// is the one that resolves the file's content in the lookup table.
///
/// Returns the offset of the next sibling and the unnamed stream's hash.
fn read_extra_streams(buf: &[u8], mut offset: usize, count: usize) -> Result<(usize, Option<[u8; 20]>), String> {
    let mut unnamed_hash = None;
    for index in 0..count {
        if offset + STREAM_ENTRY_FIXED_SIZE > buf.len() {
            return Err(format!("stream entry {index} at offset {offset} runs past the metadata resource"));
        }
        let length = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap()) as usize;
        if length < STREAM_ENTRY_FIXED_SIZE || offset + length > buf.len() {
            return Err(format!("stream entry {index} at offset {offset} declares {length} bytes, outside the metadata resource"));
        }
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(&buf[offset + 16..offset + 36]);
        let name_nbytes = u16::from_le_bytes(buf[offset + 36..offset + 38].try_into().unwrap()) as usize;
        if name_nbytes == 0 && unnamed_hash.is_none() && hash != [0_u8; 20] {
            unnamed_hash = Some(hash);
        }
        offset = offset.checked_add(align8(length)).ok_or_else(|| "stream entry offset overflow".to_owned())?;
    }
    Ok((offset, unnamed_hash))
}

/// Parses the dentry tree out of a decoded metadata resource.
///
/// The metadata resource begins with the security data block, whose first
/// `u32` is its total length; the root directory entry follows it, aligned to
/// 8 bytes. The root is a single nameless directory entry — not a sibling
/// list — so its children are reached through its subdirectory offset.
fn parse_dentries(metadata: &[u8], prefix: Option<&str>, next_index: &mut usize) -> Result<Vec<WimEntry>, String> {
    if metadata.len() < 8 {
        return Err("metadata resource is shorter than its security block header".to_owned());
    }
    let security_len = u32::from_le_bytes(metadata[0..4].try_into().unwrap()) as usize;
    let root_offset = align8(security_len.max(8));
    if root_offset >= metadata.len() {
        return Err(format!("security block ends at {root_offset}, past the {} byte metadata resource", metadata.len()));
    }

    let mut entries = Vec::new();
    let Some(root) = read_dentry(metadata, root_offset)? else {
        // An image whose root dentry is the end-of-list marker is an empty
        // image, not a malformed one.
        return Ok(entries);
    };

    let mut visited = HashSet::new();
    visited.insert(root_offset);
    if root.subdir_offset > 0 && root.subdir_offset < metadata.len() {
        walk_dentry_list(metadata, root.subdir_offset, prefix.unwrap_or(""), &mut entries, next_index, &mut visited, 0)?;
    }
    Ok(entries)
}

const fn align8(value: usize) -> usize {
    value.next_multiple_of(8)
}

/// Walks one sibling list of directory entries, recursing into subdirectories.
fn walk_dentry_list(
    buf: &[u8],
    offset: usize,
    current_path: &str,
    entries: &mut Vec<WimEntry>,
    next_index: &mut usize,
    visited: &mut HashSet<usize>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DENTRY_DEPTH {
        return Err(format!("directory tree nests deeper than {MAX_DENTRY_DEPTH} levels"));
    }
    // A sibling list reached twice means the subdirectory offsets form a
    // cycle; refuse rather than recurse until the stack is exhausted.
    if !visited.insert(offset) {
        return Err(format!("directory entry list at offset {offset} is reachable twice; the tree contains a cycle"));
    }

    let mut cursor = offset;
    while let Some(dentry) = read_dentry(buf, cursor)? {
        // Extra stream entries follow the dentry and are not covered by its
        // `length`, so the next sibling starts after them.
        let (next_cursor, unnamed_hash) = read_extra_streams(buf, cursor + align8(dentry.length), dentry.num_extra_streams)?;
        // When an inode carries extra streams its own hash field is left
        // zero and the unnamed stream holds the content hash.
        let data_hash = if dentry.sha1 == [0_u8; 20] { unnamed_hash.unwrap_or(dentry.sha1) } else { dentry.sha1 };

        // A dentry name is one NTFS path component; anything else — an empty
        // name, a separator, a dot entry, an embedded NUL — is dropped before
        // it can reach the safety planner.
        let usable_name = !dentry.name.is_empty()
            && dentry.name != "."
            && dentry.name != ".."
            && !dentry.name.contains('/')
            && !dentry.name.contains('\\')
            && !dentry.name.contains('\0');

        if usable_name {
            let full_path = if current_path.is_empty() { dentry.name.clone() } else { format!("{current_path}/{}", dentry.name) };
            let kind = if dentry.is_link_reparse_point() {
                WimEntryKind::Symlink
            } else if dentry.is_directory() {
                WimEntryKind::Directory
            } else {
                WimEntryKind::File
            };

            entries.push(WimEntry {
                index: *next_index,
                path: full_path.clone(),
                kind,
                size: 0,
                link_target: None,
                sha1: data_hash,
                reparse_tag: dentry.reparse_tag,
            });
            *next_index += 1;

            // A reparse point can carry the directory attribute while its
            // stream is the reparse data buffer rather than a child list.
            if dentry.is_directory() && !dentry.is_reparse_point() && dentry.subdir_offset > 0 && dentry.subdir_offset < buf.len() {
                walk_dentry_list(buf, dentry.subdir_offset, &full_path, entries, next_index, visited, depth + 1)?;
            }
        }

        cursor = next_cursor;
    }
    Ok(())
}

/// Decodes a UTF-16LE name field, stopping at the declared byte length.
fn read_utf16_name(dentry: &[u8], offset: usize, nbytes: usize) -> String {
    if nbytes == 0 || offset + nbytes > dentry.len() {
        return String::new();
    }
    let units: Vec<u16> = dentry[offset..offset + nbytes].chunks_exact(2).map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap())).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_owned()
}

/// Decodes a symlink or junction target from a WIM reparse data buffer.
///
/// WIM stores the reparse point *payload*, i.e. the bytes that follow the
/// 8-byte `REPARSE_DATA_BUFFER` header. The two layouts differ only in whether
/// a 4-byte flags field sits between the name offsets and the path buffer, and
/// the reparse tag is what tells them apart — so it is passed in rather than
/// inferred from the lengths, which can be ambiguous.
fn decode_reparse_target(payload: &[u8], reparse_tag: u32) -> Option<String> {
    if payload.len() < 8 {
        return None;
    }
    let substitute_offset = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    let substitute_len = u16::from_le_bytes(payload[2..4].try_into().unwrap()) as usize;
    let print_offset = u16::from_le_bytes(payload[4..6].try_into().unwrap()) as usize;
    let print_len = u16::from_le_bytes(payload[6..8].try_into().unwrap()) as usize;

    // A symlink payload prefixes the path buffer with a 4-byte flags field; a
    // junction (mount point) payload does not. An unrecognized tag tries both,
    // preferring the symlink layout.
    let candidate_offsets: &[usize] = match reparse_tag {
        IO_REPARSE_TAG_SYMLINK => &[12],
        IO_REPARSE_TAG_MOUNT_POINT => &[8],
        _ => &[12, 8],
    };

    for &path_buffer_offset in candidate_offsets {
        if path_buffer_offset > payload.len() {
            continue;
        }
        let buffer = &payload[path_buffer_offset..];
        // The print name is the human-readable spelling; fall back to the
        // substitute name (which carries the NT `\??\` prefix) when absent.
        let target =
            utf16_slice(buffer, print_offset, print_len).filter(|value| !value.is_empty()).or_else(|| utf16_slice(buffer, substitute_offset, substitute_len));
        let Some(target) = target else { continue };
        let normalized = normalize_reparse_target(&target);
        if !normalized.is_empty() {
            return Some(normalized);
        }
    }
    None
}

fn utf16_slice(buffer: &[u8], offset: usize, length: usize) -> Option<String> {
    if length == 0 || !length.is_multiple_of(2) {
        return None;
    }
    let end = offset.checked_add(length)?;
    if end > buffer.len() {
        return None;
    }
    let units: Vec<u16> = buffer[offset..end].chunks_exact(2).map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap())).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Converts an NTFS reparse target into a portable relative-or-absolute path.
fn normalize_reparse_target(target: &str) -> String {
    let stripped = target.strip_prefix(r"\??\").unwrap_or(target);
    stripped.replace('\\', "/")
}

impl WimArchive {
    /// Reads the stream backing one directory entry.
    ///
    /// A zero SHA-1 denotes an empty or metadata-only entry and returns
    /// Ok(None).
    ///
    /// # Errors
    ///
    /// Returns [`WimError`] when the entry has no corresponding resource or
    /// its resource cannot be read or decoded.
    pub fn read_entry_data(&mut self, entry: &WimEntry) -> Result<Option<Vec<u8>>, WimError> {
        if entry.sha1 == [0_u8; 20] {
            return Ok(None);
        }
        if let Some(retained) = self.resource_cache.get(&entry.sha1) {
            return Ok(Some(retained.clone()));
        }
        let Some(lookup) = self.lut.get(&entry.sha1).cloned() else {
            return Err(invalid(self.path(), format!("entry {} references stream {} which is not in the lookup table", entry.path, hex_sha1(entry.sha1))));
        };
        let data = self.read_stream(&lookup)?;
        self.retain_resource(entry.sha1, &data);
        Ok(Some(data))
    }

    /// Retains a decoded stream for reuse by other entries sharing its SHA-1.
    ///
    /// Streams too large to ever fit the budget are skipped rather than
    /// evicting everything for a single entry. When the budget would be
    /// exceeded the retained set is cleared outright: WIM entries are visited
    /// in lookup-table order, so the streams still to be shared are the recent
    /// ones, and a clear keeps the policy allocation-free.
    fn retain_resource(&mut self, sha1: [u8; 20], data: &[u8]) {
        if data.is_empty() || data.len() > RESOURCE_CACHE_BUDGET_BYTES {
            return;
        }
        if self.resource_cache_bytes + data.len() > RESOURCE_CACHE_BUDGET_BYTES {
            self.resource_cache.clear();
            self.resource_cache_bytes = 0;
        }
        if self.resource_cache.insert(sha1, data.to_vec()).is_none() {
            self.resource_cache_bytes += data.len();
        }
    }

    /// Verifies every regular-file stream against its recorded size and
    /// SHA-1, returning the number of verified bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WimError`] when an entry or resource cannot be read, or when
    /// a decoded stream does not match its recorded size or SHA-1.
    pub fn verify(&mut self) -> Result<u64, WimError> {
        let entries = self.entries()?;
        let mut verified = 0_u64;
        for entry in entries.iter().filter(|entry| entry.kind == WimEntryKind::File) {
            let Some(data) = self.read_entry_data(entry)? else {
                return Err(invalid(self.path(), format!("file entry {} has no data stream", entry.path)));
            };
            if data.len() as u64 != entry.size {
                return Err(invalid(self.path(), format!("WIM entry {} decoded to {} bytes, expected {}", entry.path, data.len(), entry.size)));
            }
            let digest: [u8; 20] = Sha1::digest(&data).into();
            if digest != entry.sha1 {
                return Err(invalid(
                    self.path(),
                    format!("WIM entry {} hashes to {}, but the lookup table records {}", entry.path, hex_sha1(digest), hex_sha1(entry.sha1)),
                ));
            }
            verified = verified.saturating_add(data.len() as u64);
        }
        Ok(verified)
    }
}

fn hex_sha1(value: [u8; 20]) -> String {
    hex::encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn first_file_entry(archive: &mut WimArchive) -> WimEntry {
        archive
            .entries()
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == WimEntryKind::File && entry.sha1 != [0_u8; 20])
            .expect("fixture should contain a regular file")
    }

    /// WIM is single-instance storage: one SHA-1-keyed stream backs every
    /// entry with the same content. Decoding costs the whole stream, so it
    /// must be decoded once and retained, not re-decoded per referencing
    /// entry.
    #[test]
    fn decoded_stream_is_retained_for_entries_sharing_a_sha1() {
        let mut archive = WimArchive::open(fixture("basic-LZX.wim")).unwrap();
        let entry = first_file_entry(&mut archive);

        assert!(archive.resource_cache.is_empty(), "nothing is retained before the first read");
        let first = archive.read_entry_data(&entry).unwrap().expect("entry has data");
        assert!(archive.resource_cache.contains_key(&entry.sha1), "the decoded stream must be retained under its SHA-1");

        let second = archive.read_entry_data(&entry).unwrap().expect("entry has data");
        assert_eq!(first, second, "a retained stream must return the same bytes as the decode that produced it");
    }

    /// The retention budget must bound memory: a stream too large to ever fit
    /// is skipped rather than clearing the retained set for no benefit.
    #[test]
    fn oversized_streams_are_not_retained() {
        let mut archive = WimArchive::open(fixture("basic-LZX.wim")).unwrap();

        archive.retain_resource([1_u8; 20], &[0_u8; 64]);
        assert_eq!(archive.resource_cache.len(), 1);
        assert_eq!(archive.resource_cache_bytes, 64);

        archive.retain_resource([2_u8; 20], &vec![0_u8; RESOURCE_CACHE_BUDGET_BYTES + 1]);
        assert_eq!(archive.resource_cache.len(), 1, "an unretainable stream must not disturb what is already retained");

        archive.retain_resource([3_u8; 20], &[]);
        assert_eq!(archive.resource_cache.len(), 1, "empty streams are not worth retaining");
    }

    /// Exceeding the budget must reset retention rather than grow unbounded.
    #[test]
    fn retention_stays_within_its_budget() {
        let mut archive = WimArchive::open(fixture("basic-LZX.wim")).unwrap();
        let half = RESOURCE_CACHE_BUDGET_BYTES / 2 + 1;

        archive.retain_resource([1_u8; 20], &vec![0_u8; half]);
        archive.retain_resource([2_u8; 20], &vec![0_u8; half]);

        assert!(archive.resource_cache_bytes <= RESOURCE_CACHE_BUDGET_BYTES, "retained bytes must never exceed the budget");
        assert_eq!(archive.resource_cache.len(), 1, "the second stream clears the first rather than exceeding the budget");
    }
}
