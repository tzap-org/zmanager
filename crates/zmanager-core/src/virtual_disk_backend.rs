//! Virtual disk image extraction backends (`.vhd`, `.vmdk`, `.udf`).
//!
//! `VHD` (Virtual PC/Hyper-V), `VMDK` (`VMware`), and `UDF` (optical) are block-device
//! formats: the files live inside an inner filesystem (NTFS, FAT/exFAT, ext4,
//! UDF), usually behind an MBR/GPT partition table. The `forensic-vfs-engine`
//! crate resolves the whole stack in one call — container → volume system →
//! filesystem — and exposes the result as a read-only `forensic_vfs::FileSystem`
//! (`Arc<dyn FileSystem>`), which this backend walks and streams out through the
//! standard extraction pipeline.
//!
//! All three formats share 100% of the pipeline; the public entry points only
//! differ by name so the CLI can route by detected kind.
//!
//! ## Non-disk-input guard
//!
//! The underlying VFS resolver also recognizes embedded archive containers, so
//! a plain zip renamed `foo.vhd` resolves as a browsable archive tree with
//! `fs: Some(...)`. [`mount_disk`] rejects those with
//! [`VirtualDiskBackendError::NotDiskImage`] (locator `Archive` layer check plus
//! a logical-container kind check).
//!
//! ## Known limitations
//!
//! - Only the default data stream is extracted (no NTFS ADS / resource forks).
//! - Symlinks are supported on NTFS (reparse-point buffers and the ntfs-3g
//!   `IntxLNK` form, patched in the ntfs-core fork) and UDF (`PATH_COMPONENT`
//!   decode, patched in the udf-forensic fork); FAT has no symlinks.
//! - NTFS system metadata files (`$MFT`, `$Bitmap`, …) are filtered from the
//!   volume root by exact name.
//! - Deleted/recovered entries (`Allocation::Deleted`/`Orphan`) are skipped with
//!   a warning when surfaced; the FAT adapter already hides them.
//! - Multi-volume disks resolve to the first *mountable* filesystem (the
//!   resolver skips unmountable slots such as MSR partitions); per-volume
//!   extraction into labeled directories is a future option via the engine's
//!   `open_all`.

use crate::engine::types::{TestOptions, TestReport};
use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use forensic_vfs::{Allocation, FsKind, ImageSource, Layer, NodeKind, StreamId};
use forensic_vfs_engine::{Evidence, Vfs};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(VirtualDiskBackendError);

/// Entry kind reported by the listing APIs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VirtualDiskEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symlink.
    Symlink,
}

/// Entry reported by [`list_vhd`] / [`list_vmdk`] / [`list_udf`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VirtualDiskListEntry {
    /// Path inside the disk image (the mounted filesystem's tree).
    pub path: String,
    /// Entry kind.
    pub kind: VirtualDiskEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Relative target for a symbolic-link entry.
    pub link_target: Option<String>,
}

/// Disk-image extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VirtualDiskExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for VirtualDiskExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// Disk-image backend error.
#[derive(Debug)]
pub enum VirtualDiskBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed (destination side).
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The engine failed to decode the image (corrupt/truncated container,
    /// unrecognized filesystem). The message carries the engine's layer/offset
    /// context.
    Vfs(String),
    /// The file is not a supported disk image: no filesystem was found inside,
    /// or it resolved to a non-disk (archive) tree.
    NotDiskImage(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for VirtualDiskBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Vfs(message) => write!(f, "disk image backend error: {message}"),
            Self::NotDiskImage(message) => write!(f, "not a supported disk image: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for VirtualDiskBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Vfs(_) | Self::NotDiskImage(_) | Self::Cancelled => None,
        }
    }
}

/// NTFS system metadata files surfaced by the ntfs-core vfs adapter at the
/// volume root. Filtered by exact name (never by `$` prefix — `$Recycle.Bin`
/// and `$WinREAgent` are legitimate user-visible directories).
const NTFS_METADATA_NAMES: &[&str] = &["$AttrDef", "$BadClus", "$Bitmap", "$Boot", "$Extend", "$LogFile", "$MFT", "$MFTMirr", "$Secure", "$UpCase", "$Volume"];

/// Reserved volume entries cannot exist as real paths (raw names containing
/// NUL bytes — the same rule the DMG backend applies to HFS+ Finder metadata).
fn is_reserved_volume_entry(path: &str) -> bool {
    path.contains('\0')
}

/// True when the path's first component is a known NTFS metadata file. Covers
/// both the root entries and everything under `$Extend/…`.
fn is_ntfs_metadata_path(path: &str) -> bool {
    path.split('/').next().is_some_and(|root| NTFS_METADATA_NAMES.contains(&root))
}

/// Plain archive kinds the VFS resolver can produce as fallbacks (zip/7z/tar).
/// A file that resolves to one of these is a loose archive fallback, not a dedicated
/// container or disk image.
fn is_plain_archive_fallback_kind(kind: FsKind) -> bool {
    matches!(kind.as_str(), "zip" | "7z" | "tar")
}

/// Logical-container kinds the VFS resolver can produce (dar/aff4/ad1).
fn is_logical_container_kind(kind: FsKind) -> bool {
    matches!(kind.as_str(), "dar" | "aff4" | "ad1")
}

/// `VDI_IMAGE_SIGNATURE` from `VirtualBox`'s `VDICore.h`, read as a little-endian
/// `u32` at offset 64. Spelling it byte-reversed makes every real image fall
/// through to the generic opener, which then reports the far less useful "no
/// supported filesystem found".
const VDI_SIGNATURE: u32 = 0xbeda_107f;

/// Minimum bytes of a VDI header needed to read every field below.
const VDI_HEADER_BYTES: usize = 512;

/// `VDI_IMAGE_BLOCK_FREE`: the block was never allocated.
const VDI_BLOCK_FREE: u32 = 0xFFFF_FFFF;
/// `VDI_IMAGE_BLOCK_ZERO`: the block is allocated but known to be all zeros.
/// `VirtualBox` writes this for discarded blocks; treating it as a block index
/// would seek terabytes past the end of the file.
const VDI_BLOCK_ZERO: u32 = 0xFFFF_FFFE;

/// `VDI_IMAGE_TYPE_DYNAMIC`: sparse image with a populated block map.
const VDI_TYPE_DYNAMIC: u32 = 1;
/// `VDI_IMAGE_TYPE_FIXED`: preallocated image, still block-mapped.
const VDI_TYPE_FIXED: u32 = 2;

/// Upper bound on a VDI block map, guarding against a hostile `cBlocks`.
/// 64 Mi entries covers a 64 TiB disk at the smallest 1 MiB block size.
const VDI_MAX_BLOCKS: u32 = 64 * 1024 * 1024;

fn is_vdi_image(archive_path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(archive_path) else { return false };
    let mut buf = [0_u8; 68];
    if file.read_exact(&mut buf).is_err() {
        return false;
    }
    u32::from_le_bytes(buf[64..68].try_into().unwrap()) == VDI_SIGNATURE
}

/// Parsed Oracle `VirtualBox` VDI header.
#[derive(Debug, Clone, Copy)]
pub struct VdiHeader {
    /// Image type (`VDI_IMAGE_TYPE_*`).
    pub image_type: u32,
    /// Offset of the block map.
    pub offset_bmap: u32,
    /// Offset of the first data block.
    pub offset_data: u32,
    /// Logical disk size in bytes.
    pub disk_size: u64,
    /// Bytes per data block.
    pub block_size: u32,
    /// Per-block metadata prefix size, normally zero.
    pub block_extra: u32,
    /// Number of entries in the block map.
    pub blocks_in_hdd: u32,
}

impl VdiHeader {
    /// Parses and validates a VDI header.
    ///
    /// # Errors
    ///
    /// Returns a message describing the first field that makes the image
    /// unreadable: a bad signature, an unusable geometry, or an image type
    /// (differencing/undo) whose data lives in a parent image.
    ///
    /// # Panics
    ///
    /// Never: the length check above guarantees every field read below is in
    /// bounds, so the slice conversions cannot fail.
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 400 {
            return Err("VDI header too short".to_owned());
        }
        let sig = u32::from_le_bytes(buf[64..68].try_into().unwrap());
        if sig != VDI_SIGNATURE {
            return Err("invalid VDI signature".to_owned());
        }
        let image_type = u32::from_le_bytes(buf[76..80].try_into().unwrap());
        let offset_bmap = u32::from_le_bytes(buf[340..344].try_into().unwrap());
        let offset_data = u32::from_le_bytes(buf[344..348].try_into().unwrap());
        let disk_size = u64::from_le_bytes(buf[368..376].try_into().unwrap());
        let block_size = u32::from_le_bytes(buf[376..380].try_into().unwrap());
        let block_extra = u32::from_le_bytes(buf[380..384].try_into().unwrap());
        let blocks_in_hdd = u32::from_le_bytes(buf[384..388].try_into().unwrap());

        // A differencing or undo image only stores blocks that changed
        // relative to a parent; reading one standalone silently yields zeros
        // where the parent's data belongs.
        if image_type != VDI_TYPE_DYNAMIC && image_type != VDI_TYPE_FIXED {
            return Err(format!(
                "VDI image type {image_type} is a differencing or undo image whose data lives in a parent image; merge it with `VBoxManage clonemedium` first"
            ));
        }
        if block_size == 0 || blocks_in_hdd == 0 {
            return Err("invalid VDI geometry".to_owned());
        }
        if blocks_in_hdd > VDI_MAX_BLOCKS {
            return Err(format!("VDI declares {blocks_in_hdd} blocks, above the {VDI_MAX_BLOCKS} block limit"));
        }
        // Per-block extra data shifts every payload address. Rather than
        // decode it wrongly, refuse an image that uses it.
        if block_extra != 0 {
            return Err(format!("VDI declares {block_extra} bytes of per-block extra data, which this reader does not decode"));
        }

        Ok(Self { image_type, offset_bmap, offset_data, disk_size, block_size, block_extra, blocks_in_hdd })
    }
}

struct VdiSource {
    file: std::sync::Mutex<std::fs::File>,
    offset_data: u64,
    disk_size: u64,
    block_size: u64,
    bat: Vec<u32>,
}

use std::io::{Read as _, Seek as _};

impl forensic_vfs::ImageSource for VdiSource {
    fn len(&self) -> u64 {
        self.disk_size
    }

    #[allow(clippy::cast_possible_truncation)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> forensic_vfs::VfsResult<usize> {
        if offset >= self.disk_size || buf.is_empty() {
            return Ok(0);
        }
        let mut total_read = 0;
        let mut cur_offset = offset;
        let mut cur_buf = buf;
        let mut file = self.file.lock().map_err(|_| forensic_vfs::VfsError::Io { op: "lock", source: io::Error::other("mutex poisoned") })?;

        while !cur_buf.is_empty() && cur_offset < self.disk_size {
            let block_idx = (cur_offset / self.block_size) as usize;
            let in_block_offset = cur_offset % self.block_size;
            let bytes_in_block = (self.block_size - in_block_offset).min(cur_buf.len() as u64).min(self.disk_size - cur_offset) as usize;

            let unallocated = block_idx >= self.bat.len() || matches!(self.bat[block_idx], VDI_BLOCK_FREE | VDI_BLOCK_ZERO);
            if unallocated {
                cur_buf[..bytes_in_block].fill(0);
            } else {
                let phys_offset = self.offset_data + u64::from(self.bat[block_idx]) * self.block_size + in_block_offset;
                file.seek(io::SeekFrom::Start(phys_offset)).map_err(|source| forensic_vfs::VfsError::Io { op: "seek", source })?;
                file.read_exact(&mut cur_buf[..bytes_in_block]).map_err(|source| forensic_vfs::VfsError::Io { op: "read", source })?;
            }

            total_read += bytes_in_block;
            cur_offset += bytes_in_block as u64;
            cur_buf = &mut cur_buf[bytes_in_block..];
        }

        Ok(total_read)
    }
}

/// Magic bytes for `UltraISO` Compressed ISO (`.isz`).
pub const ISZ_MAGIC: [u8; 4] = *b"IsZ!";

/// Chunk stored as all-zero bytes.
const ISZ_CHUNK_ZERO: u8 = 0;
/// Chunk stored verbatim.
const ISZ_CHUNK_DATA: u8 = 1;
/// Chunk compressed with zlib.
const ISZ_CHUNK_ZLIB: u8 = 2;
/// Chunk compressed with bzip2.
const ISZ_CHUNK_BZ2: u8 = 3;

/// One decoded ISZ chunk pointer.
#[derive(Debug, Clone, Copy)]
struct IszChunk {
    kind: u8,
    stored_length: u32,
}

/// Header descriptor for `UltraISO` Compressed ISO (`.isz`).
///
/// The on-disk header is a 48-byte packed structure. Every multi-byte field is
/// little-endian and *unaligned*: `sect_size` is a `u16` at offset 10 and
/// `segment_size` is a `u64` at offset 17, so the fields cannot be read at
/// 4-byte strides.
#[derive(Debug, Clone)]
pub struct IszHeader {
    /// Header length in bytes (48 for version 1).
    pub header_size: u8,
    /// Format version.
    pub version: u8,
    /// Logical sector size in bytes (2048 or 2352).
    pub sector_size: u16,
    /// Total logical sectors in the image.
    pub total_sectors: u32,
    /// Encryption algorithm (0 = none).
    pub encryption_type: u8,
    /// Bytes per segment for multi-file `.isz`/`.i01` sets (0 = single file).
    pub segment_size: u64,
    /// Number of chunk pointers in the table.
    pub num_blocks: u32,
    /// Uncompressed chunk size in bytes.
    pub block_size: u32,
    /// Bytes per chunk pointer (2 or 3 in practice).
    pub ptr_len: u8,
    /// Number of segments in the set.
    pub segment_count: u8,
    /// Offset of the chunk pointer table.
    pub ptr_offset: u32,
    /// Offset of the segment table.
    pub segment_table_offset: u32,
    /// Offset of the first chunk's stored bytes.
    pub data_offset: u32,
}

impl IszHeader {
    /// Parses an ISZ header from the first 48 bytes of the file.
    ///
    /// # Errors
    ///
    /// Returns an error when `buf` is short, does not begin with
    /// [`ISZ_MAGIC`], or declares encryption or a multi-segment set.
    ///
    /// # Panics
    ///
    /// Never: the 48-byte length check above guarantees every field read below
    /// is in bounds, so the slice conversions cannot fail.
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 48 || buf[0..4] != ISZ_MAGIC {
            return Err("not an ISZ image".to_owned());
        }
        let read_u16 = |offset: usize| u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap());
        let read_u32 = |offset: usize| u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        let read_u64 = |offset: usize| u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());

        let header = Self {
            header_size: buf[4],
            version: buf[5],
            sector_size: read_u16(10),
            total_sectors: read_u32(12),
            encryption_type: buf[16],
            segment_size: read_u64(17),
            num_blocks: read_u32(25),
            block_size: read_u32(29),
            ptr_len: buf[33],
            segment_count: buf[34],
            ptr_offset: read_u32(35),
            segment_table_offset: read_u32(39),
            data_offset: read_u32(43),
        };

        if header.encryption_type != 0 {
            return Err(format!("ISZ image is encrypted (encryption type {}); decrypt it with UltraISO first", header.encryption_type));
        }
        // `segment_size` alone only declares the split threshold; a set is
        // actually multi-file when it declares more than one segment.
        if header.segment_count > 1 {
            return Err(format!("ISZ image is split across {} segments (.i01, .i02, …), which this reader does not join", header.segment_count));
        }
        if header.block_size == 0 {
            return Err("ISZ declares a zero chunk size".to_owned());
        }
        if header.sector_size == 0 {
            return Err("ISZ declares a zero sector size".to_owned());
        }
        if !(1..=4).contains(&header.ptr_len) {
            return Err(format!("ISZ declares {} bytes per chunk pointer, outside the 1..=4 range", header.ptr_len));
        }
        if header.num_blocks == 0 {
            return Err("ISZ declares no chunks".to_owned());
        }
        Ok(header)
    }

    /// Decodes the chunk pointer table.
    ///
    /// Each pointer is `ptr_len` little-endian bytes whose top two bits carry
    /// the chunk type and whose remaining bits carry the chunk's *stored*
    /// length. Chunks sit back to back starting at `data_offset`.
    fn decode_chunk_table(&self, table: &[u8]) -> Result<Vec<IszChunk>, String> {
        let ptr_len = usize::from(self.ptr_len);
        let expected = (self.num_blocks as usize).checked_mul(ptr_len).ok_or_else(|| "ISZ chunk table size overflow".to_owned())?;
        if table.len() < expected {
            return Err(format!("ISZ chunk table is {} bytes, shorter than the {expected} bytes its header declares", table.len()));
        }
        let type_shift = ptr_len * 8 - 2;
        let length_mask = (1_u32 << type_shift) - 1;

        Ok(table[..expected]
            .chunks_exact(ptr_len)
            .map(|raw| {
                let mut value = 0_u32;
                for (index, byte) in raw.iter().enumerate() {
                    value |= u32::from(*byte) << (index * 8);
                }
                // The type occupies the top two bits, so it is always 0..=3.
                IszChunk { kind: u8::try_from(value >> type_shift).unwrap_or(u8::MAX), stored_length: value & length_mask }
            })
            .collect())
    }
}

/// Returns true if `path` begins with the `UltraISO` `.isz` magic signature.
#[must_use]
pub fn is_isz_image(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else { return false };
    let mut magic = [0_u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == ISZ_MAGIC
}

struct IszSource {
    file: std::sync::Mutex<std::fs::File>,
    total_size: u64,
    block_size: u64,
    /// Chunk descriptors paired with the absolute file offset of their bytes.
    chunks: Vec<(IszChunk, u64)>,
    cached_block: std::sync::Mutex<Option<(usize, std::sync::Arc<Vec<u8>>)>>,
}

impl IszSource {
    #[allow(clippy::cast_possible_truncation)]
    fn decode_chunk(&self, file: &mut std::fs::File, block_idx: usize) -> io::Result<Vec<u8>> {
        let Some((chunk, offset)) = self.chunks.get(block_idx).copied() else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ISZ chunk index out of range"));
        };
        let block_size = self.block_size as usize;
        if chunk.kind == ISZ_CHUNK_ZERO {
            return Ok(vec![0_u8; block_size]);
        }

        let mut stored = vec![0_u8; chunk.stored_length as usize];
        file.seek(io::SeekFrom::Start(offset))?;
        file.read_exact(&mut stored)?;

        let mut out = Vec::with_capacity(block_size);
        match chunk.kind {
            ISZ_CHUNK_DATA => out = stored,
            ISZ_CHUNK_ZLIB => {
                flate2::read::ZlibDecoder::new(&stored[..]).read_to_end(&mut out)?;
            }
            ISZ_CHUNK_BZ2 => {
                bzip2::read::BzDecoder::new(&stored[..]).read_to_end(&mut out)?;
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown ISZ chunk type {other}"))),
        }
        // A short final chunk is legal; a short interior chunk is not, but the
        // caller zero-fills rather than failing a whole image for one chunk.
        Ok(out)
    }
}

impl forensic_vfs::ImageSource for IszSource {
    fn len(&self) -> u64 {
        self.total_size
    }

    #[allow(clippy::cast_possible_truncation)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> forensic_vfs::VfsResult<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let mut total_read = 0;
        let mut cur_offset = offset;
        let mut cur_buf = buf;
        let mut file = self.file.lock().map_err(|_| forensic_vfs::VfsError::Io { op: "lock", source: io::Error::other("mutex poisoned") })?;

        while !cur_buf.is_empty() && cur_offset < self.total_size {
            let block_idx = (cur_offset / self.block_size) as usize;
            let in_block_offset = (cur_offset % self.block_size) as usize;
            let bytes_avail = (self.block_size - in_block_offset as u64).min(cur_buf.len() as u64).min(self.total_size - cur_offset) as usize;

            let mut cache = self.cached_block.lock().map_err(|_| forensic_vfs::VfsError::Io { op: "lock", source: io::Error::other("mutex poisoned") })?;
            let block_bytes = match cache.as_ref() {
                Some((cached_idx, data)) if *cached_idx == block_idx => std::sync::Arc::clone(data),
                _ => {
                    let decoded =
                        std::sync::Arc::new(self.decode_chunk(&mut file, block_idx).map_err(|source| forensic_vfs::VfsError::Io { op: "read", source })?);
                    *cache = Some((block_idx, std::sync::Arc::clone(&decoded)));
                    decoded
                }
            };
            drop(cache);

            if in_block_offset < block_bytes.len() {
                let copy_len = bytes_avail.min(block_bytes.len() - in_block_offset);
                cur_buf[..copy_len].copy_from_slice(&block_bytes[in_block_offset..in_block_offset + copy_len]);
                total_read += copy_len;
                cur_offset += copy_len as u64;
                cur_buf = &mut cur_buf[copy_len..];
            } else {
                cur_buf[..bytes_avail].fill(0);
                total_read += bytes_avail;
                cur_offset += bytes_avail as u64;
                cur_buf = &mut cur_buf[bytes_avail..];
            }
        }

        Ok(total_read)
    }
}

/// Optical disc track source that translates physical raw/sync sectors to 2048-byte logical sectors.
struct OpticalTrackSource {
    reader: std::sync::Mutex<SendReadSeek>,
    sector_mode: iso::SectorMode,
    total_logical_bytes: u64,
}

/// `iso9660-forensic` erases the concrete reader's auto traits from its
/// public `ReadSeek` object. Every reader this module wraps is in fact `Send`;
/// restore that fact at this boundary so the enclosing forensic `ImageSource`
/// can be shared safely between worker threads.
struct SendReadSeek(Box<dyn iso::ReadSeek>);

// SAFETY: this wrapper is constructed from exactly three sources, all `Send`:
//   * `iso::open`, whose path opener returns only file-backed readers
//     (`File`, `BufReader<File>`, and seekable offset wrappers around them);
//   * `iso::offset::OffsetReader<BufReader<File>>` built here for the `.cdi`
//     track window;
//   * `forensic_vfs::adapters::SourceCursor` over an `Arc<IszSource>`, whose
//     fields are a `Mutex<File>`, plain data, and a `Mutex` cache.
// None of them holds a non-`Send` value; the dependency's trait object simply
// omits the auto-trait bound. Adding a fourth construction site means
// re-checking this list.
#[allow(unsafe_code)]
unsafe impl Send for SendReadSeek {}

impl io::Read for SendReadSeek {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Seek for SendReadSeek {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}

impl forensic_vfs::ImageSource for OpticalTrackSource {
    fn len(&self) -> u64 {
        self.total_logical_bytes
    }

    #[allow(clippy::cast_possible_truncation)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> forensic_vfs::VfsResult<usize> {
        if offset >= self.total_logical_bytes || buf.is_empty() {
            return Ok(0);
        }
        let mut total_read = 0;
        let mut cur_offset = offset;
        let mut cur_buf = buf;
        let mut reader = self.reader.lock().map_err(|_| forensic_vfs::VfsError::Io { op: "lock", source: io::Error::other("mutex poisoned") })?;

        while !cur_buf.is_empty() && cur_offset < self.total_logical_bytes {
            let lba = cur_offset / 2048;
            let in_sector_offset = cur_offset % 2048;
            let bytes_in_sector = (2048 - in_sector_offset).min(cur_buf.len() as u64).min(self.total_logical_bytes - cur_offset) as usize;

            let phys_pos = self.sector_mode.user_data_pos(lba) + in_sector_offset;
            reader.seek(io::SeekFrom::Start(phys_pos)).map_err(|source| forensic_vfs::VfsError::Io { op: "seek", source })?;
            reader.read_exact(&mut cur_buf[..bytes_in_sector]).map_err(|source| forensic_vfs::VfsError::Io { op: "read", source })?;

            total_read += bytes_in_sector;
            cur_offset += bytes_in_sector as u64;
            cur_buf = &mut cur_buf[bytes_in_sector..];
        }

        Ok(total_read)
    }
}

/// Returns true if `path` names an optical disc image or sector dump.
///
/// The list is exactly the set of extensions that map to a registered
/// [`ArchiveFormatKind`](crate::archive_format::ArchiveFormatKind) plus the
/// data files a descriptor sheet points at (`.bin` for `.cue`, `.img` for
/// `.ccd`). Extensions with no registered kind are deliberately absent: they
/// could never be routed here, so listing them only implied support that does
/// not exist.
#[must_use]
pub fn is_optical_image(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase) else { return false };
    matches!(ext.as_str(), "iso" | "nrg" | "mds" | "mdf" | "cdi" | "ccd" | "cue" | "bin" | "img")
}

/// Resolves an Alcohol 120% `.mdf` to its sibling `.mds` descriptor.
///
/// The `.mds` carries the session and track table; the `.mdf` is raw sector
/// data whose first data track need not begin at byte 0. Opening the `.mdf`
/// directly would treat it as a flat image, so prefer the descriptor whenever
/// one sits next to it.
fn resolve_mdf_descriptor(archive_path: &Path) -> Option<PathBuf> {
    if !archive_path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("mdf")) {
        return None;
    }
    for candidate_extension in ["mds", "MDS"] {
        let candidate = archive_path.with_extension(candidate_extension);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Opens an optical image or sector dump into a unified `forensic_vfs::ImageSource`.
#[allow(clippy::cast_possible_truncation)]
fn open_optical_source(archive_path: &Path) -> Result<std::sync::Arc<dyn forensic_vfs::ImageSource>, VirtualDiskBackendError> {
    if is_isz_image(archive_path) {
        let io_err = |e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e };
        let mut file = std::fs::File::open(archive_path).map_err(io_err)?;
        let mut hdr_buf = [0_u8; 48];
        file.read_exact(&mut hdr_buf).map_err(io_err)?;
        let isz_hdr = IszHeader::read(&hdr_buf).map_err(|msg| VirtualDiskBackendError::NotDiskImage(format!("{}: {msg}", archive_path.display())))?;

        let mut table = vec![0_u8; (isz_hdr.num_blocks as usize) * usize::from(isz_hdr.ptr_len)];
        file.seek(io::SeekFrom::Start(u64::from(isz_hdr.ptr_offset))).map_err(io_err)?;
        file.read_exact(&mut table).map_err(io_err)?;
        let descriptors =
            isz_hdr.decode_chunk_table(&table).map_err(|msg| VirtualDiskBackendError::NotDiskImage(format!("{}: {msg}", archive_path.display())))?;

        // Chunks are stored back to back from `data_offset`; a zero-length
        // (all-zero) chunk occupies no bytes.
        let mut cursor = u64::from(isz_hdr.data_offset);
        let mut chunks = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            chunks.push((descriptor, cursor));
            cursor = cursor.saturating_add(u64::from(descriptor.stored_length));
        }
        let total_uncompressed = u64::from(isz_hdr.total_sectors).saturating_mul(u64::from(isz_hdr.sector_size));

        let isz_src = std::sync::Arc::new(IszSource {
            file: std::sync::Mutex::new(file),
            total_size: total_uncompressed,
            block_size: u64::from(isz_hdr.block_size),
            chunks,
            cached_block: std::sync::Mutex::new(None),
        });

        if isz_hdr.sector_size == 2352 {
            let len = isz_src.len();
            let cursor = forensic_vfs::adapters::SourceCursor::new(isz_src, 0, len);
            let mut reader = SendReadSeek(Box::new(cursor));
            let sector_mode = iso::SectorMode::detect(&mut reader).unwrap_or(iso::SectorMode::Raw2352);
            let total_logical_bytes = (len / sector_mode.physical_sector_size()) * 2048;
            return Ok(std::sync::Arc::new(OpticalTrackSource { reader: std::sync::Mutex::new(reader), sector_mode, total_logical_bytes }));
        }

        return Ok(isz_src);
    }

    let ext = archive_path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
    if ext.as_deref() == Some("cdi") {
        let mut file = std::fs::File::open(archive_path).map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
        if let Some(tracks) = iso::cdi::tracks(&mut file)
            && let Some(data_track) = tracks.into_iter().find(|t| t.kind != iso::cdi::CdiTrackKind::Audio)
        {
            let raw_sector_size = if data_track.raw_bytes_per_sector > 0 { u64::from(data_track.raw_bytes_per_sector) } else { 2048 };
            let start_offset = u64::from(data_track.start_sector) * raw_sector_size;
            let track_len = u64::from(data_track.length_sectors) * raw_sector_size;
            let offset_reader = iso::offset::OffsetReader::new(std::io::BufReader::new(file), start_offset, track_len)
                .map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
            let mut reader = SendReadSeek(Box::new(offset_reader));
            let sector_mode = iso::SectorMode::detect(&mut reader).unwrap_or(iso::SectorMode::Iso2048);
            let total_logical_bytes = (track_len / sector_mode.physical_sector_size()) * 2048;
            return Ok(std::sync::Arc::new(OpticalTrackSource { reader: std::sync::Mutex::new(reader), sector_mode, total_logical_bytes }));
        }
    }

    // `.mdf` carries no track table of its own; open the sibling `.mds` when
    // one exists so the data track is windowed at the right offset.
    let descriptor_path = resolve_mdf_descriptor(archive_path);
    let open_path = descriptor_path.as_deref().unwrap_or(archive_path);
    let mut reader = match iso::open(open_path) {
        Ok(r) => SendReadSeek(r),
        Err(e) => return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: {e}", open_path.display()))),
    };

    let sector_mode = iso::SectorMode::detect(&mut reader).unwrap_or(iso::SectorMode::Iso2048);
    let track_len = reader.seek(io::SeekFrom::End(0)).map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
    let total_logical_bytes = (track_len / sector_mode.physical_sector_size()) * 2048;

    Ok(std::sync::Arc::new(OpticalTrackSource { reader: std::sync::Mutex::new(reader), sector_mode, total_logical_bytes }))
}

/// Opens `archive_path` through the engine and returns the mounted read-only
/// filesystem and its locator.
///
/// `allow_logical` selects which resolutions count as success. With it clear the
/// input must be a disk or optical image, so a logical container (AD1/DAR/AFF4)
/// is rejected; with it set the logical containers are accepted too. A plain
/// archive tree (zip/7z/tar) is rejected either way — that is the resolver's
/// loose-archive fallback, not a container this backend owns.
#[allow(clippy::cast_possible_truncation)]
fn mount_entry(archive_path: &Path, allow_logical: bool) -> Result<(forensic_vfs::DynFs, forensic_vfs::Locator), VirtualDiskBackendError> {
    if is_vdi_image(archive_path) {
        let mut file = std::fs::File::open(archive_path).map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
        let mut header_buf = vec![0_u8; VDI_HEADER_BYTES];
        file.read_exact(&mut header_buf).map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
        let vdi_hdr = VdiHeader::read(&header_buf).map_err(|msg| VirtualDiskBackendError::NotDiskImage(format!("{}: {msg}", archive_path.display())))?;

        // `blocks_in_hdd` is bounded by `VdiHeader::read`, so this cannot
        // request an unbounded allocation from a hostile header.
        let bat_size = (vdi_hdr.blocks_in_hdd as usize) * 4;
        let mut bat_bytes = vec![0_u8; bat_size];
        file.seek(io::SeekFrom::Start(u64::from(vdi_hdr.offset_bmap)))
            .map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;
        file.read_exact(&mut bat_bytes).map_err(|e| VirtualDiskBackendError::Io { path: archive_path.to_path_buf(), source: e })?;

        let bat: Vec<u32> = bat_bytes.as_chunks::<4>().0.iter().map(|chunk| u32::from_le_bytes(*chunk)).collect();
        let vdi_src = std::sync::Arc::new(VdiSource {
            file: std::sync::Mutex::new(file),
            offset_data: u64::from(vdi_hdr.offset_data),
            disk_size: vdi_hdr.disk_size,
            block_size: u64::from(vdi_hdr.block_size),
            bat,
        });

        let fs = Vfs::new().open_source(vdi_src).map_err(|e| VirtualDiskBackendError::Vfs(e.to_string()))?;

        let Some(fs) = fs else {
            return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: no supported filesystem found in the VDI image", archive_path.display())));
        };

        return Ok((fs, forensic_vfs::Locator::file(archive_path)));
    }

    if (is_isz_image(archive_path) || is_optical_image(archive_path))
        && let Ok(src) = open_optical_source(archive_path)
        && let Ok(Some(fs)) = Vfs::new().open_source(src)
    {
        return Ok((fs, forensic_vfs::Locator::file(archive_path)));
    }

    let evidence: Evidence = Vfs::new().open(archive_path).map_err(|error| VirtualDiskBackendError::Vfs(error.to_string()))?;

    let Some(fs) = &evidence.fs else {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: no supported filesystem found in the image", archive_path.display())));
    };

    // An archive *wrapping* a nested image would mount the inner filesystem
    // through the packaging peel; that is a different extraction model.
    if evidence.root.layers().iter().any(|layer| matches!(layer, Layer::Archive { .. })) {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: resolved to an archive wrapper, not a disk image", archive_path.display())));
    }

    if is_plain_archive_fallback_kind(fs.kind()) {
        return Err(VirtualDiskBackendError::NotDiskImage(format!(
            "{}: resolved to a {} tree, not a disk image or container",
            archive_path.display(),
            fs.kind().as_str()
        )));
    }

    if !allow_logical && is_logical_container_kind(fs.kind()) {
        return Err(VirtualDiskBackendError::NotDiskImage(format!("{}: resolved to a {} tree, not a disk image", archive_path.display(), fs.kind().as_str())));
    }

    Ok((std::sync::Arc::clone(fs), evidence.root))
}

/// Maps one walked engine entry to the safety layer's entry kind.
fn map_entry_kind(fs: &forensic_vfs::DynFs, id: forensic_vfs::FileId, kind: NodeKind) -> Result<ExtractionEntryKind, VirtualDiskBackendError> {
    match kind {
        NodeKind::File => Ok(ExtractionEntryKind::File),
        NodeKind::Dir => Ok(ExtractionEntryKind::Directory),
        NodeKind::Symlink => {
            let target_bytes = fs.read_link(id, 4096).map_err(|error| VirtualDiskBackendError::Vfs(format!("read_link: {error}")))?;
            Ok(ExtractionEntryKind::Symlink { target: PathBuf::from(String::from_utf8_lossy(&target_bytes).into_owned()) })
        }
        // Devices and unknown nodes fall to the safety planner's
        // `UnsafeFilePolicy` (default `Reject`). `NodeKind` is
        // `#[non_exhaustive]`, so future kinds stay safe by default.
        NodeKind::Device | NodeKind::Other | _ => Ok(ExtractionEntryKind::Device),
    }
}

/// Walks the mounted filesystem and maps every entry to the safety layer's
/// shape, applying the deleted/reserved/metadata filters. Entries filtered by
/// the reserved/metadata rules are dropped; `skip_warning` receives a warning
/// message for each filtered entry when extraction runs (listing drops them
/// silently, mirroring `list_dmg`). The engine's `FileId` is carried alongside
/// each entry so file bytes can be streamed without re-walking the tree.
fn collect_entries_with_path_map(
    fs: &forensic_vfs::DynFs,
    skip_warning: &mut Option<&mut dyn FnMut(String)>,
    path_map: Option<&HashMap<u32, String>>,
) -> Result<Vec<(ExtractionEntry, forensic_vfs::FileId)>, VirtualDiskBackendError> {
    let walked = forensic_vfs_engine::walk(fs.as_ref()).map_err(|error| VirtualDiskBackendError::Vfs(error.to_string()))?;

    let mut entries = Vec::with_capacity(walked.len());
    for entry in walked {
        // Built into one exactly-sized String rather than
        // `map(into_owned).collect::<Vec<_>>().join("/")`, which allocates a
        // String per component plus a Vec to hold them and then throws both
        // away. `from_utf8_lossy` borrows for valid UTF-8, so the component
        // bytes are copied once, straight into the destination. The separator
        // is keyed on the index, not on the accumulator being non-empty, so an
        // empty leading component still yields `/b` rather than `b`.
        let mut walked_path = String::with_capacity(entry.path.iter().map(|component| component.len() + 1).sum());
        for (index, component) in entry.path.iter().enumerate() {
            if index > 0 {
                walked_path.push('/');
            }
            walked_path.push_str(&String::from_utf8_lossy(component));
        }
        let path = match (path_map, entry.id) {
            (Some(map), forensic_vfs::FileId::IsoExtent { block }) => map.get(&block).cloned().unwrap_or(walked_path),
            _ => walked_path,
        };
        if path.is_empty() {
            continue;
        }
        if is_reserved_volume_entry(&path) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: reserved filesystem entry"));
            }
            continue;
        }
        if is_ntfs_metadata_path(&path) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: NTFS system metadata file"));
            }
            continue;
        }
        if matches!(entry.meta.allocated, Allocation::Deleted | Allocation::Orphan) {
            if let Some(warn) = skip_warning.as_deref_mut() {
                warn(format!("skipped {path}: recovered deleted entry"));
            }
            continue;
        }

        let kind = map_entry_kind(fs, entry.id, entry.meta.kind)?;
        entries.push((ExtractionEntry { archive_path: path, kind, uncompressed_size: Some(entry.meta.size), compressed_size: None }, entry.id));
    }
    Ok(entries)
}

fn iso_path_map(archive_path: &Path) -> HashMap<u32, String> {
    if (is_isz_image(archive_path) || is_optical_image(archive_path))
        && let Ok(src) = open_optical_source(archive_path)
    {
        let len = src.len();
        let cursor = forensic_vfs::adapters::SourceCursor::new(src, 0, len);
        let mut reader = SendReadSeek(Box::new(cursor));
        if let Ok(mut r) = iso::IsoReader::open(&mut reader)
            && let Ok(walked) = r.walk()
        {
            return walked.into_iter().map(|entry| (entry.record.lba, entry.path)).collect();
        }
    }
    if let Ok(file) = std::fs::File::open(archive_path)
        && let Ok(mut reader) = iso::IsoReader::open(file)
        && let Ok(walked) = reader.walk()
    {
        return walked.into_iter().map(|entry| (entry.record.lba, entry.path)).collect();
    }
    HashMap::new()
}

fn path_map_for_filesystem(fs: &forensic_vfs::DynFs, archive_path: &Path) -> Option<HashMap<u32, String>> {
    if fs.kind().as_str() == "iso9660" { Some(iso_path_map(archive_path)) } else { None }
}

/// Lists the entries of a `.vhd` archive without extracting them.
pub fn list_vhd(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.vmdk` archive without extracting them.
pub fn list_vmdk(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.udf` archive without extracting them.
pub fn list_udf(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an Oracle `VirtualBox` `.vdi` image without extracting them.
pub fn list_vdi(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a Nero `.nrg` image without extracting them.
pub fn list_nrg(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an Alcohol 120% `.mdf`/`.mds` image without extracting them.
pub fn list_mdf(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an `UltraISO` Compressed ISO `.isz` image without extracting them.
pub fn list_isz(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `CloneCD` `.ccd`/`.img` image without extracting them.
pub fn list_ccd(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `CUE/BIN` sheet without extracting them.
pub fn list_cue(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.vhdx` virtual disk without extracting them.
pub fn list_vhdx(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of a `.qcow2` virtual disk without extracting them.
pub fn list_qcow2(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an Expert Witness (`.e01`/`.ex01`) image without extracting them.
pub fn list_ewf(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Lists the entries of an `AccessData` AD1 (`.ad1`) logical image without extracting them.
pub fn list_ad1(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_logical_container_inner(archive_path)
}

/// Lists the entries of a DAR (`.dar`) archive without extracting them.
pub fn list_dar(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_logical_container_inner(archive_path)
}

/// Lists the entries of an AFF4 (`.aff4`) container without extracting them.
pub fn list_aff4(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_logical_container_inner(archive_path)
}

/// Lists the entries of a raw sector disk dump (`.raw`/`.dd`/`.dsk`/`.img`) without extracting them.
pub fn list_raw_disk(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_virtual_disk_inner(archive_path)
}

/// Verifies selected optical image payloads through the forensic VFS reader.
pub fn test_optical(archive_path: impl AsRef<Path>, options: &TestOptions) -> Result<TestReport, VirtualDiskBackendError> {
    test_container_payloads(archive_path, options, false)
}

/// Verifies selected virtual-disk payloads (VHD, VMDK, UDF, VDI, VHDX, QCOW2, EWF, `RawDisk`) through the
/// forensic VFS reader.
///
/// # Errors
///
/// Propagates mount failures and reports any file whose decoded length
/// disagrees with the filesystem's declared size.
pub fn test_virtual_disk(archive_path: impl AsRef<Path>, options: &TestOptions) -> Result<TestReport, VirtualDiskBackendError> {
    test_container_payloads(archive_path, options, false)
}

/// Verifies selected logical container payloads (AD1, DAR, AFF4) through the
/// forensic VFS reader.
pub fn test_logical_container(archive_path: impl AsRef<Path>, options: &TestOptions) -> Result<TestReport, VirtualDiskBackendError> {
    test_container_payloads(archive_path, options, true)
}

pub(crate) fn test_container_payloads(
    archive_path: impl AsRef<Path>,
    options: &TestOptions,
    allow_logical: bool,
) -> Result<TestReport, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let (fs, _) = mount_entry(archive_path, allow_logical)?;
    let path_map = path_map_for_filesystem(&fs, archive_path);
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;
    let mut report = TestReport::default();
    for (entry, file_id) in entries {
        if options.is_cancelled() {
            return Err(VirtualDiskBackendError::Cancelled);
        }
        if !options.selects(&entry.archive_path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if matches!(entry.kind, ExtractionEntryKind::File) {
            let mut sink = io::sink();
            let bytes = stream_file(&fs, file_id, &entry.archive_path, &mut sink)?;
            if Some(bytes) != entry.uncompressed_size {
                return Err(VirtualDiskBackendError::Vfs(format!(
                    "test {}: filesystem declares {} bytes but yielded {bytes}",
                    entry.archive_path,
                    entry.uncompressed_size.unwrap_or(0)
                )));
            }
            report.tested_bytes = report.tested_bytes.saturating_add(bytes);
        }
        report.tested_entries = report.tested_entries.saturating_add(1);
    }
    Ok(report)
}

/// Resolves `selected_path` + `selected_occurrence` to an entry and copies it.
/// The occurrence counter advances only on entries whose path matches, so it
/// selects the Nth duplicate of that exact path rather than the Nth entry
/// overall.
///
/// The container is mounted and walked once. Resolving the selector through
/// `list_*` and then mounting it again would cost more than reading the file
/// itself for a compressed container (EWF, qcow2, VHDX).
pub(crate) fn copy_container_by_path_occurrence(
    archive_path: &Path,
    selected_path: &str,
    selected_occurrence: usize,
    writer: &mut dyn io::Write,
    allow_logical: bool,
    label: &str,
) -> Result<u64, VirtualDiskBackendError> {
    let (fs, _) = mount_entry(archive_path, allow_logical)?;
    let path_map = path_map_for_filesystem(&fs, archive_path);
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;

    let mut occurrence = 0_usize;
    let selected = entries.iter().find(|(entry, _)| {
        if entry.archive_path != selected_path {
            return false;
        }
        let matches = occurrence == selected_occurrence;
        occurrence = occurrence.saturating_add(1);
        matches
    });
    let (entry, file_id) = selected.ok_or_else(|| VirtualDiskBackendError::Io {
        path: archive_path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::NotFound, format!("retained {label} entry is not present")),
    })?;
    if !matches!(entry.kind, ExtractionEntryKind::File) {
        return Err(VirtualDiskBackendError::Vfs(format!("retained {label} entry is not a regular file")));
    }
    stream_file(&fs, *file_id, &entry.archive_path, writer)
}

/// Copies one retained VDI file by path and duplicate occurrence.
pub fn copy_vdi_by_path_occurrence(
    archive_path: impl AsRef<Path>,
    selected_path: &str,
    selected_occurrence: usize,
    writer: &mut dyn io::Write,
) -> Result<u64, VirtualDiskBackendError> {
    copy_virtual_disk_by_path_occurrence(archive_path, selected_path, selected_occurrence, writer)
}

/// Copies a retained virtual-disk file by its stable path/occurrence selector.
/// The native engine does not expose format-specific copy functions at its
/// selector boundary, so route through the matching listing backend here.
pub fn copy_virtual_disk_by_path_occurrence(
    archive_path: impl AsRef<Path>,
    selected_path: &str,
    selected_occurrence: usize,
    writer: &mut dyn io::Write,
) -> Result<u64, VirtualDiskBackendError> {
    copy_container_by_path_occurrence(archive_path.as_ref(), selected_path, selected_occurrence, writer, false, "virtual disk")
}

/// Copies a retained logical container file by its stable path/occurrence selector.
pub fn copy_logical_container_by_path_occurrence(
    archive_path: impl AsRef<Path>,
    selected_path: &str,
    selected_occurrence: usize,
    writer: &mut dyn io::Write,
) -> Result<u64, VirtualDiskBackendError> {
    copy_container_by_path_occurrence(archive_path.as_ref(), selected_path, selected_occurrence, writer, true, "logical container")
}

pub(crate) fn list_container_inner(archive_path: impl AsRef<Path>, allow_logical: bool) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let (fs, _) = mount_entry(archive_path, allow_logical)?;
    let path_map = path_map_for_filesystem(&fs, archive_path);
    let mut no_warning = None;
    let entries = collect_entries_with_path_map(&fs, &mut no_warning, path_map.as_ref())?;
    Ok(entries
        .into_iter()
        .map(|(entry, _)| {
            let link_target = match &entry.kind {
                ExtractionEntryKind::Symlink { target } => Some(target.to_string_lossy().into_owned()),
                _ => None,
            };
            VirtualDiskListEntry {
                path: entry.archive_path,
                kind: match entry.kind {
                    ExtractionEntryKind::Directory => VirtualDiskEntryKind::Directory,
                    ExtractionEntryKind::Symlink { .. } => VirtualDiskEntryKind::Symlink,
                    _ => VirtualDiskEntryKind::File,
                },
                size: entry.uncompressed_size.unwrap_or(0),
                link_target,
            }
        })
        .collect())
}

fn list_virtual_disk_inner(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_container_inner(archive_path, false)
}

fn list_logical_container_inner(archive_path: impl AsRef<Path>) -> Result<Vec<VirtualDiskListEntry>, VirtualDiskBackendError> {
    list_container_inner(archive_path, true)
}

/// Extracts a `.vhd` archive into `destination`.
pub fn extract_vhd_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.vmdk` archive into `destination`.
pub fn extract_vmdk_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.udf` archive into `destination`.
pub fn extract_udf_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.vdi` image into `destination`.
pub fn extract_vdi_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a Nero `.nrg` image into `destination`.
pub fn extract_nrg_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an Alcohol 120% `.mdf`/`.mds` image into `destination`.
pub fn extract_mdf_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an `UltraISO` Compressed ISO `.isz` image into `destination`.
pub fn extract_isz_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `CloneCD` `.ccd`/`.img` image into `destination`.
pub fn extract_ccd_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `CUE/BIN` sheet into `destination`.
pub fn extract_cue_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.vhdx` virtual disk into `destination`.
pub fn extract_vhdx_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.qcow2` virtual disk into `destination`.
pub fn extract_qcow2_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an Expert Witness (`.e01`/`.ex01`) image into `destination`.
pub fn extract_ewf_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an `AccessData` AD1 (`.ad1`) logical image into `destination`.
pub fn extract_ad1_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_logical_container_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a DAR (`.dar`) archive into `destination`.
pub fn extract_dar_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_logical_container_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an AFF4 (`.aff4`) container into `destination`.
pub fn extract_aff4_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_logical_container_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a raw sector disk dump (`.raw`/`.dd`/`.dsk`/`.img`) into `destination`.
pub fn extract_raw_disk_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_virtual_disk_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a logical container without job progress callbacks.
pub fn extract_logical_container(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_logical_container_inner(archive_path, destination, policy, None, None)
}

/// Streaming writer that checks cancellation and reports bytes through the
/// job context on every write (mirrors the MSI backend's `ProgressWriter`).
struct ProgressWriter<'a, 'b, W: io::Write> {
    inner: W,
    context: Option<&'a mut JobContext<'b>>,
    archive_path: &'a str,
}

impl<W: io::Write> io::Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(ctx) = self.context.as_deref_mut() {
            if ctx.check_cancelled().is_err() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
            }
            ctx.bytes_processed(Some(self.archive_path), written as u64);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn extract_virtual_disk_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_container_inner(archive_path, destination, policy, context, overwrite_resolver, false)
}

fn extract_logical_container_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    extract_container_inner(archive_path, destination, policy, context, overwrite_resolver, true)
}

pub(crate) fn extract_container_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    allow_logical: bool,
) -> Result<VirtualDiskExtractReport, VirtualDiskBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| VirtualDiskBackendError::Io { path: destination.to_path_buf(), source })?;

    let (fs, _) = mount_entry(archive_path, allow_logical)?;

    let mut warnings = Vec::new();
    let path_map = path_map_for_filesystem(&fs, archive_path);
    let mut warning_sink = |warning| warnings.push(warning);
    let mut warning_callback: Option<&mut dyn FnMut(String)> = Some(&mut warning_sink);
    let entries = collect_entries_with_path_map(&fs, &mut warning_callback, path_map.as_ref())?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = VirtualDiskExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings };

    for (safety_entry, file_id) in entries {
        if let Some(ctx) = context.as_deref_mut() {
            ctx.check_cancelled()?;
        }

        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, mut context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, VirtualDiskBackendError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    let replace_existing = decision.replace_existing;
                    let destination_path = decision.destination_path;

                    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(destination_path)
                            .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                    }

                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            std::fs::create_dir_all(destination_path)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            Ok::<u64, VirtualDiskBackendError>(0)
                        }
                        ExtractionEntryKind::File => {
                            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            let file = output.file_mut().map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            // The engine exposes byte-range reads, not a stream;
                            // loop in fixed-size chunks through the progress
                            // writer when a context is present.
                            let expected = safety_entry.uncompressed_size.unwrap_or(0);
                            let written_bytes = if context.is_some() {
                                let mut writer = ProgressWriter { inner: file, context: context.as_deref_mut(), archive_path: &safety_entry.archive_path };
                                stream_file(&fs, file_id, &safety_entry.archive_path, &mut writer)?
                            } else {
                                let mut file = file;
                                stream_file(&fs, file_id, &safety_entry.archive_path, &mut file)?
                            };

                            output
                                .commit_with_replace(replace_existing)
                                .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            report.written_entries += 1;
                            report.written_bytes += written_bytes;
                            if written_bytes != expected {
                                // The filesystem's declared size was a lie; the
                                // file is materialized as-is, so warn.
                                report
                                    .warnings
                                    .push(format!("{}: extracted {} bytes, filesystem declares {}", safety_entry.archive_path, written_bytes, expected));
                            }
                            Ok(written_bytes)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            // The engine exposes symlink targets through
                            // read_link; skip rather than materialize a broken
                            // empty symlink if a target is still missing.
                            if target.as_os_str().is_empty() {
                                crate::extract_loop::skip_entry(
                                    report,
                                    context,
                                    format!("symlink {} skipped: disk image does not expose the symlink target", safety_entry.archive_path),
                                );
                                return Ok(0);
                            }
                            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                                return Ok(0);
                            }

                            #[cfg(unix)]
                            {
                                crate::extract_materialize::write_symlink(Path::new(target), destination_path)
                                    .map_err(|source| VirtualDiskBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = target;
                            }
                            report.written_entries += 1;
                            Ok::<u64, VirtualDiskBackendError>(0)
                        }
                        _ => Ok::<u64, VirtualDiskBackendError>(0),
                    }
                }
            }
        })?;
    }

    Ok(report)
}

/// Streams one file's bytes from the engine into `writer` via chunked
/// `read_at` calls on the walked `FileId`.
fn stream_file<W: io::Write + ?Sized>(
    fs: &forensic_vfs::DynFs,
    file_id: forensic_vfs::FileId,
    archive_path: &str,
    writer: &mut W,
) -> Result<u64, VirtualDiskBackendError> {
    let mut written: u64 = 0;
    let mut buf = vec![0u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut offset: u64 = 0;
    loop {
        let n =
            fs.read_at(file_id, StreamId::Default, offset, &mut buf).map_err(|error| VirtualDiskBackendError::Vfs(format!("read {archive_path}: {error}")))?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(|source| VirtualDiskBackendError::Io { path: PathBuf::from(archive_path), source })?;
        written += n as u64;
        offset += n as u64;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::{
        ISZ_MAGIC, IszHeader, VDI_BLOCK_FREE, VDI_BLOCK_ZERO, VDI_SIGNATURE, VdiHeader, VdiSource, VirtualDiskBackendError, VirtualDiskEntryKind,
        copy_vdi_by_path_occurrence, extract_ccd_with_overwrite_resolver, extract_cue_with_overwrite_resolver, extract_isz_with_overwrite_resolver,
        extract_mdf_with_overwrite_resolver, extract_nrg_with_overwrite_resolver, extract_udf_with_overwrite_resolver, extract_vdi_with_overwrite_resolver,
        extract_vhd_with_overwrite_resolver, extract_vmdk_with_overwrite_resolver, is_isz_image, is_logical_container_kind, is_ntfs_metadata_path,
        is_optical_image, is_plain_archive_fallback_kind, is_reserved_volume_entry, is_vdi_image, list_ccd, list_cue, list_isz, list_mdf, list_nrg, list_udf,
        list_vdi, list_vhd, list_vmdk, open_optical_source, resolve_mdf_descriptor, test_optical, test_virtual_disk,
    };
    use crate::safety::{ExtractionPolicy, OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver};
    use crate::test_support::TestDir;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    struct AlwaysReplace;
    impl OverwriteResolver for AlwaysReplace {
        fn decide(&mut self, _conflict: &OverwriteConflict) -> OverwriteDecision {
            OverwriteDecision::Replace
        }
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn disk_format_of(name: &str) -> DiskFixtureFormat {
        match Path::new(name).extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("vhd") => DiskFixtureFormat::Vhd,
            Some("vmdk") => DiskFixtureFormat::Vmdk,
            _ => DiskFixtureFormat::Udf,
        }
    }

    fn extract_all(archive: &Path, name: &str, out: &Path) -> crate::virtual_disk_backend::VirtualDiskExtractReport {
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let result = match disk_format_of(name) {
            DiskFixtureFormat::Vhd => extract_vhd_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
            DiskFixtureFormat::Vmdk => extract_vmdk_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
            DiskFixtureFormat::Udf => extract_udf_with_overwrite_resolver(archive, out, policy, &mut AlwaysReplace),
        };
        result.unwrap_or_else(|error| panic!("extract {archive:?} failed: {error}"))
    }

    fn list_all(archive: &Path, name: &str) -> Result<Vec<crate::virtual_disk_backend::VirtualDiskListEntry>, VirtualDiskBackendError> {
        match disk_format_of(name) {
            DiskFixtureFormat::Vhd => list_vhd(archive),
            DiskFixtureFormat::Vmdk => list_vmdk(archive),
            DiskFixtureFormat::Udf => list_udf(archive),
        }
    }

    #[derive(Clone, Copy)]
    enum DiskFixtureFormat {
        Vhd,
        Vmdk,
        Udf,
    }

    #[test]
    fn checked_in_vhd_vmdk_udf_fixtures_list_with_normalized_paths() {
        for name in ["basic.vhd", "basic.vmdk", "basic.udf"] {
            let archive = fixture(name);
            assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
            let listing = list_all(&archive, name).unwrap_or_else(|error| panic!("list {name} failed: {error}"));
            let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
            assert!(paths.contains(&"payload/README.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/nested/file.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/unicode/こんにちは.txt"), "{name}: {paths:?}");
            assert!(paths.contains(&"payload/nested/empty-dir"), "{name}: {paths:?}");
            assert!(listing.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "{name} paths must be normalized: {paths:?}");
            assert!(
                listing.iter().all(|entry| entry.size > 0 || entry.kind == VirtualDiskEntryKind::Directory),
                "{name}: non-directory entries must declare sizes"
            );
            // NTFS system metadata must never surface (the vhd fixture is MBR+NTFS).
            assert!(!listing.iter().any(|entry| entry.path.starts_with('$')), "{name}: NTFS metadata leaked: {paths:?}");
        }
    }

    #[test]
    fn checked_in_vhd_vmdk_udf_fixtures_extract_with_byte_accurate_report() {
        for name in ["basic.vhd", "basic.vmdk", "basic.udf"] {
            let archive = fixture(name);
            assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
            let listing = list_all(&archive, name).unwrap();
            let temp = TestDir::new(&format!("virtual-disk-{name}"));
            let out = temp.path("out");
            let report = extract_all(&archive, name, &out);

            // The NTFS/UDF fixtures carry one symlink: materialized on unix,
            // skipped with a warning elsewhere (the FAT vmdk has none). The
            // NTFS-metadata filter warns but does not count toward
            // skipped_entries.
            let skipped_symlink = usize::from(!cfg!(unix) && name != "basic.vmdk");
            assert_eq!(report.skipped_entries, skipped_symlink, "{name}: warnings: {:?}", report.warnings);
            assert_eq!(
                report.written_entries,
                listing.iter().filter(|entry| entry.kind != VirtualDiskEntryKind::Directory).count() - skipped_symlink,
                "{name}"
            );
            let declared_file_bytes: u64 = listing.iter().filter(|entry| entry.kind == VirtualDiskEntryKind::File).map(|entry| entry.size).sum();
            assert_eq!(report.written_bytes, declared_file_bytes, "{name}: written bytes must sum the declared sizes of all listed files");

            assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n", "{name}");
            assert_eq!(fs::read_to_string(out.join("payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n", "{name}");
            assert!(out.join("payload/nested/empty-dir").is_dir(), "{name}");
            // The NTFS and UDF fixtures carry the symlink (patched adapters
            // decode reparse/IntxLNK and PATH_COMPONENT targets); FAT strips it.
            if matches!(name, "basic.vhd" | "basic.udf") {
                #[cfg(unix)]
                {
                    assert_eq!(fs::read_link(out.join("payload/nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"), "{name}");
                }
            } else {
                assert!(!out.join("payload/nested/readme-link.txt").exists(), "{name}");
            }
        }
    }

    #[test]
    fn empty_file_is_rejected_as_not_a_disk_image() {
        let temp = TestDir::new("virtual-disk-empty");
        fs::write(temp.path("empty.vhd"), b"").unwrap();
        let error = list_vhd(temp.path("empty.vhd")).unwrap_err();
        assert!(matches!(error, VirtualDiskBackendError::NotDiskImage(_)), "{error}");
    }

    #[test]
    fn garbage_bytes_are_rejected_as_not_a_disk_image() {
        let temp = TestDir::new("virtual-disk-garbage");
        fs::write(temp.path("garbage.vmdk"), b"this is not a disk image at all, just some junk bytes").unwrap();
        let error = list_vhd(temp.path("garbage.vmdk")).unwrap_err();
        assert!(matches!(error, VirtualDiskBackendError::NotDiskImage(_)), "{error}");
    }

    #[test]
    fn truncated_vhd_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let bytes = fs::read(&archive).unwrap();
        let temp = TestDir::new("virtual-disk-truncated");
        fs::write(temp.path("truncated.vhd"), &bytes[..bytes.len() / 2]).unwrap();
        assert!(list_vhd(temp.path("truncated.vhd")).is_err());
    }

    #[test]
    fn vhd_with_corrupt_footer_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let mut bytes = fs::read(&archive).unwrap();
        // The VHD footer (last 512 bytes) carries the "conectix" cookie at its start.
        let footer_start = bytes.len() - 512;
        bytes[footer_start..footer_start + 8].copy_from_slice(b"XXXXXXIX");
        let temp = TestDir::new("virtual-disk-corrupt-footer");
        fs::write(temp.path("corrupt.vhd"), &bytes).unwrap();
        assert!(list_vhd(temp.path("corrupt.vhd")).is_err());
    }

    #[test]
    fn zeroed_ntfs_boot_sector_inside_vhd_errors() {
        let archive = fixture("basic.vhd");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");
        let bytes = fs::read(&archive).unwrap();
        // The NTFS boot sector OEM id is the 8 bytes "NTFS    " (4 + 4 spaces).
        let oem = b"NTFS    ";
        let offset = bytes.windows(oem.len()).position(|window| window == oem).expect("NTFS boot sector must be present in the fixture");
        let mut patched = bytes;
        patched[offset..offset + oem.len()].fill(0);
        let temp = TestDir::new("virtual-disk-zeroed-boot");
        fs::write(temp.path("boot.vhd"), &patched).unwrap();
        assert!(list_vhd(temp.path("boot.vhd")).is_err());
    }

    #[test]
    fn zip_named_vhd_is_rejected_by_the_disk_guard() {
        let temp = TestDir::new("virtual-disk-zip-guard");
        let zip_path = temp.path("fake.vhd");
        let file = fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer.start_file("payload/README.txt", zip::write::SimpleFileOptions::default()).unwrap();
        writer.write_all(b"ZManager fixture payload\n").unwrap();
        writer.finish().unwrap();

        let error = list_vhd(&zip_path).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("not a disk image"), "{message}");
    }

    #[test]
    fn reserved_metadata_and_logical_filters_are_pure_functions() {
        assert!(is_reserved_volume_entry("payload/\0secret"));
        assert!(!is_reserved_volume_entry("payload/README.txt"));
        assert!(is_ntfs_metadata_path("$MFT"));
        assert!(is_ntfs_metadata_path("$Extend/$ObjId"));
        assert!(!is_ntfs_metadata_path("$Recycle.Bin"));
        assert!(!is_ntfs_metadata_path("payload/README.txt"));
        for (name, expected) in [
            ("dar", true),
            ("aff4", true),
            ("ad1", true),
            ("zip", false),
            ("7z", false),
            ("tar", false),
            ("ntfs", false),
            ("fat", false),
            ("udf", false),
            ("ext", false),
        ] {
            assert_eq!(is_logical_container_kind(forensic_vfs::FsKind::from_name(name)), expected, "is_logical_container_kind({name})");
        }
        for (name, expected) in [("zip", true), ("7z", true), ("tar", true), ("dar", false), ("aff4", false), ("ad1", false), ("ntfs", false), ("fat", false)] {
            assert_eq!(is_plain_archive_fallback_kind(forensic_vfs::FsKind::from_name(name)), expected, "is_plain_archive_fallback_kind({name})");
        }
    }

    // ---- VDI -------------------------------------------------------------

    /// Writes a VDI header with the documented field offsets.
    fn vdi_header(image_type: u32, block_extra: u32, blocks: u32) -> Vec<u8> {
        let mut buf = vec![0_u8; 512];
        buf[64..68].copy_from_slice(&VDI_SIGNATURE.to_le_bytes());
        buf[76..80].copy_from_slice(&image_type.to_le_bytes());
        buf[340..344].copy_from_slice(&512_u32.to_le_bytes()); // offset_bmap
        buf[344..348].copy_from_slice(&1024_u32.to_le_bytes()); // offset_data
        buf[368..376].copy_from_slice(&10_485_760_u64.to_le_bytes()); // 10 MiB
        buf[376..380].copy_from_slice(&1_048_576_u32.to_le_bytes()); // 1 MiB blocks
        buf[380..384].copy_from_slice(&block_extra.to_le_bytes());
        buf[384..388].copy_from_slice(&blocks.to_le_bytes());
        buf
    }

    #[test]
    fn vdi_header_reads_the_documented_offsets() {
        let header = VdiHeader::read(&vdi_header(1, 0, 10)).expect("valid VDI header");
        assert_eq!(header.image_type, 1);
        assert_eq!(header.offset_bmap, 512);
        assert_eq!(header.offset_data, 1024);
        assert_eq!(header.disk_size, 10_485_760);
        assert_eq!(header.block_size, 1_048_576);
        assert_eq!(header.block_extra, 0);
        assert_eq!(header.blocks_in_hdd, 10);

        let temp = TestDir::new("vdi-detect");
        let vdi_path = temp.path("test.vdi");
        fs::write(&vdi_path, vdi_header(1, 0, 10)).unwrap();
        assert!(is_vdi_image(&vdi_path));

        let non_vdi = temp.path("other.vdi");
        fs::write(&non_vdi, b"not a vdi").unwrap();
        assert!(!is_vdi_image(&non_vdi));
    }

    #[test]
    fn vdi_headers_this_reader_cannot_honour_are_rejected_with_a_reason() {
        // A differencing image's data lives in a parent; reading it alone
        // would silently yield zeros where the parent's blocks belong.
        for differencing_type in [3_u32, 4] {
            let error = VdiHeader::read(&vdi_header(differencing_type, 0, 10)).unwrap_err();
            assert!(error.contains("parent image"), "type {differencing_type}: {error}");
            assert!(error.contains("clonemedium"), "the error must name a remedy: {error}");
        }

        // Per-block extra data shifts every payload address.
        let error = VdiHeader::read(&vdi_header(1, 64, 10)).unwrap_err();
        assert!(error.contains("per-block extra data"), "{error}");

        // A hostile block count must be refused before it becomes an allocation.
        let error = VdiHeader::read(&vdi_header(1, 0, u32::MAX)).unwrap_err();
        assert!(error.contains("block limit"), "{error}");

        assert!(VdiHeader::read(&vdi_header(1, 0, 0)).unwrap_err().contains("geometry"));
        assert!(VdiHeader::read(&[0_u8; 16]).unwrap_err().contains("too short"));
        assert!(VdiHeader::read(&[0_u8; 512]).unwrap_err().contains("signature"));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn vdi_block_map_sentinels_read_as_zeros() {
        use forensic_vfs::ImageSource as _;

        // VirtualBox writes BLOCK_FREE for never-allocated blocks and
        // BLOCK_ZERO for discarded ones. Treating either as a block index
        // seeks terabytes past the end of the file.
        let temp = TestDir::new("vdi-sentinels");
        let backing = temp.path("blocks.bin");
        let block_size = 4096_u64;
        // One real block of 0xAB, at block index 0 of the data area.
        fs::write(&backing, vec![0xAB_u8; block_size as usize]).unwrap();

        let source = VdiSource {
            file: std::sync::Mutex::new(fs::File::open(&backing).unwrap()),
            offset_data: 0,
            disk_size: block_size * 4,
            block_size,
            bat: vec![0, VDI_BLOCK_FREE, VDI_BLOCK_ZERO, VDI_BLOCK_FREE],
        };

        let mut buf = vec![0xFF_u8; (block_size * 4) as usize];
        let read = source.read_at(0, &mut buf).expect("sentinel blocks must not error");
        assert_eq!(read, buf.len());
        assert!(buf[..block_size as usize].iter().all(|byte| *byte == 0xAB), "the allocated block must come from the file");
        assert!(buf[block_size as usize..].iter().all(|byte| *byte == 0), "BLOCK_FREE and BLOCK_ZERO must both read as zeros");
    }

    #[test]
    fn checked_in_vdi_fixture_lists_and_extracts() {
        let archive = fixture("basic.vdi");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let listing = list_vdi(&archive).unwrap_or_else(|error| panic!("list basic.vdi failed: {error}"));
        let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
        assert!(paths.contains(&"payload/README.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/file.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/unicode/こんにちは.txt"), "{paths:?}");
        assert!(listing.iter().all(|entry| !entry.path.starts_with('/')), "paths must be normalized: {paths:?}");

        let temp = TestDir::new("vdi-extract");
        let out = temp.path("out");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let report = extract_vdi_with_overwrite_resolver(&archive, &out, policy, &mut AlwaysReplace).unwrap();
        assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(out.join("payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");

        let declared: u64 = listing.iter().filter(|entry| entry.kind == VirtualDiskEntryKind::File).map(|entry| entry.size).sum();
        assert_eq!(report.written_bytes, declared, "written bytes must sum the declared sizes of all listed files");

        // The sparse fixture has 64 blocks with only a couple allocated, so a
        // successful walk proves the unallocated-block path works end to end.
        let test_report = test_virtual_disk(&archive, &crate::engine::types::TestOptions::default()).unwrap();
        assert!(test_report.tested_entries > 0);

        let mut copied = Vec::new();
        copy_vdi_by_path_occurrence(&archive, "payload/README.txt", 0, &mut copied).unwrap();
        assert_eq!(copied, b"ZManager fixture payload\n");
    }

    #[test]
    fn non_vdi_bytes_named_vdi_are_rejected() {
        let temp = TestDir::new("vdi-garbage");
        fs::write(temp.path("garbage.vdi"), vec![0x41_u8; 4096]).unwrap();
        assert!(list_vdi(temp.path("garbage.vdi")).is_err());

        // A valid signature with an unreadable geometry must name the reason.
        let mut header = vdi_header(4, 0, 10);
        header.truncate(512);
        fs::write(temp.path("diff.vdi"), &header).unwrap();
        let error = list_vdi(temp.path("diff.vdi")).unwrap_err();
        assert!(error.to_string().contains("parent image"), "{error}");
    }

    // ---- ISZ -------------------------------------------------------------

    /// Builds an ISZ image at the documented 48-byte packed header layout.
    ///
    /// Every field is placed at its real, unaligned offset: `sect_size` is a
    /// `u16` at 10, `block_size` a `u32` at 29, `ptr_offs` a `u32` at 35. The
    /// chunk pointers are `ptr_len` bytes each, carrying the chunk type in the
    /// top two bits and the stored length in the rest.
    fn build_isz(payload: &[u8], sector_size: u16, block_size: u32, ptr_len: u8) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        let total_sectors = (payload.len() / usize::from(sector_size)) as u32;

        let mut chunk_types = Vec::new();
        let mut chunk_bytes = Vec::new();
        for block in payload.chunks(block_size as usize) {
            if block.iter().all(|byte| *byte == 0) {
                // A zero chunk stores nothing at all.
                chunk_types.push((0_u8, Vec::new()));
                continue;
            }
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(block).unwrap();
            let compressed = encoder.finish().unwrap();
            if compressed.len() < block.len() {
                chunk_types.push((2_u8, compressed));
            } else {
                chunk_types.push((1_u8, block.to_vec()));
            }
        }
        for (_, bytes) in &chunk_types {
            chunk_bytes.extend_from_slice(bytes);
        }

        let ptr_offset = 48_u32;
        #[allow(clippy::cast_possible_truncation)]
        let data_offset = ptr_offset + (chunk_types.len() as u32) * u32::from(ptr_len);

        let mut header = vec![0_u8; 48];
        header[0..4].copy_from_slice(&ISZ_MAGIC);
        header[4] = 48; // header_size
        header[5] = 1; // version
        header[6..10].copy_from_slice(&0x1234_5678_u32.to_le_bytes()); // vol_sn
        header[10..12].copy_from_slice(&sector_size.to_le_bytes()); // u16 at 10
        header[12..16].copy_from_slice(&total_sectors.to_le_bytes());
        header[16] = 0; // encryption_type: none
        header[17..25].copy_from_slice(&0_u64.to_le_bytes()); // segment_size: single file
        #[allow(clippy::cast_possible_truncation)]
        let num_blocks = chunk_types.len() as u32;
        header[25..29].copy_from_slice(&num_blocks.to_le_bytes());
        header[29..33].copy_from_slice(&block_size.to_le_bytes()); // u32 at 29
        header[33] = ptr_len;
        header[34] = 1; // segment count
        header[35..39].copy_from_slice(&ptr_offset.to_le_bytes()); // u32 at 35
        header[39..43].copy_from_slice(&0_u32.to_le_bytes()); // seg_offs
        header[43..47].copy_from_slice(&data_offset.to_le_bytes());

        let type_shift = u32::from(ptr_len) * 8 - 2;
        let mut table = Vec::new();
        for (kind, bytes) in &chunk_types {
            #[allow(clippy::cast_possible_truncation)]
            let value = (u32::from(*kind) << type_shift) | (bytes.len() as u32);
            table.extend_from_slice(&value.to_le_bytes()[..usize::from(ptr_len)]);
        }

        let mut out = header;
        out.extend_from_slice(&table);
        out.extend_from_slice(&chunk_bytes);
        out
    }

    #[test]
    fn isz_header_reads_the_documented_packed_layout() {
        let payload = fs::read(fixture("basic.iso")).expect("read basic.iso fixture");
        let bytes = build_isz(&payload, 2048, 65536, 3);
        let header = IszHeader::read(&bytes[..48]).expect("valid ISZ header");

        assert_eq!(header.header_size, 48);
        assert_eq!(header.version, 1);
        assert_eq!(header.sector_size, 2048, "sect_size is a u16 at offset 10");
        assert_eq!(header.block_size, 65536, "block_size is a u32 at offset 29");
        assert_eq!(header.ptr_len, 3);
        assert_eq!(header.ptr_offset, 48, "ptr_offs is a u32 at offset 35");
        assert_eq!(header.encryption_type, 0);
        #[allow(clippy::cast_possible_truncation)]
        let expected_sectors = (payload.len() / 2048) as u32;
        assert_eq!(header.total_sectors, expected_sectors);
    }

    #[test]
    fn isz_chunk_pointers_split_type_and_length_at_the_top_two_bits() {
        let payload = fs::read(fixture("basic.iso")).expect("read basic.iso fixture");
        let bytes = build_isz(&payload, 2048, 65536, 3);
        let header = IszHeader::read(&bytes[..48]).unwrap();
        let table_start = header.ptr_offset as usize;
        let table_end = table_start + (header.num_blocks as usize) * usize::from(header.ptr_len);
        let chunks = header.decode_chunk_table(&bytes[table_start..table_end]).unwrap();

        assert_eq!(chunks.len(), header.num_blocks as usize);
        assert!(chunks.iter().all(|chunk| chunk.kind <= 3), "chunk types must decode into the documented 0..=3 range");
        assert!(chunks.iter().any(|chunk| chunk.kind == 2), "the fixture must contain at least one zlib chunk");
        // The stored lengths must add up to the bytes that follow the table.
        let stored: u64 = chunks.iter().map(|chunk| u64::from(chunk.stored_length)).sum();
        assert_eq!(stored, (bytes.len() - header.data_offset as usize) as u64);
    }

    #[test]
    fn isz_headers_this_reader_cannot_honour_are_rejected_with_a_reason() {
        let payload = fs::read(fixture("basic.iso")).expect("read basic.iso fixture");
        let base = build_isz(&payload, 2048, 65536, 3);

        let mut encrypted = base.clone();
        encrypted[16] = 2; // AES128
        let error = IszHeader::read(&encrypted[..48]).unwrap_err();
        assert!(error.contains("encrypted"), "{error}");

        let mut segmented = base.clone();
        segmented[34] = 3; // three segments
        let error = IszHeader::read(&segmented[..48]).unwrap_err();
        assert!(error.contains("segments"), "{error}");

        let mut bad_ptr_len = base.clone();
        bad_ptr_len[33] = 9;
        assert!(IszHeader::read(&bad_ptr_len[..48]).unwrap_err().contains("chunk pointer"));

        let mut zero_block = base;
        zero_block[29..33].copy_from_slice(&0_u32.to_le_bytes());
        assert!(IszHeader::read(&zero_block[..48]).unwrap_err().contains("zero chunk size"));

        assert!(IszHeader::read(b"nope").unwrap_err().contains("not an ISZ"));
    }

    #[test]
    fn isz_roundtrip_list_test_and_extract() {
        let payload = fs::read(fixture("basic.iso")).expect("read basic.iso fixture");
        let temp = TestDir::new("isz-roundtrip");

        // Both pointer widths seen in the wild.
        for ptr_len in [2_u8, 3] {
            let isz_path = temp.path(format!("test-{ptr_len}.isz"));
            fs::write(&isz_path, build_isz(&payload, 2048, 65536, ptr_len)).unwrap();
            assert!(is_isz_image(&isz_path));

            let entries = list_isz(&isz_path).unwrap_or_else(|error| panic!("ptr_len {ptr_len}: list failed: {error}"));
            let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
            assert!(paths.contains(&"README.TXT"), "ptr_len {ptr_len}: {paths:?}");
            assert!(paths.contains(&"NESTED/FILE.TXT"), "ptr_len {ptr_len}: {paths:?}");

            let report = test_optical(&isz_path, &crate::engine::types::TestOptions::default()).unwrap();
            assert!(report.tested_entries > 0, "ptr_len {ptr_len}");

            let out_dir = temp.path(format!("out-{ptr_len}"));
            let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
            let extracted = extract_isz_with_overwrite_resolver(&isz_path, &out_dir, policy, &mut AlwaysReplace).unwrap();
            assert!(extracted.written_entries > 0, "ptr_len {ptr_len}");
            assert!(out_dir.join("README.TXT").is_file(), "ptr_len {ptr_len}");
        }
    }

    #[test]
    fn isz_decodes_byte_identically_to_the_source_image() {
        // The strongest statement available: every logical byte the ISZ
        // source yields must equal the ISO it was built from.
        let payload = fs::read(fixture("basic.iso")).expect("read basic.iso fixture");
        let temp = TestDir::new("isz-byte-identical");
        let isz_path = temp.path("identical.isz");
        fs::write(&isz_path, build_isz(&payload, 2048, 32768, 3)).unwrap();

        let source = open_optical_source(&isz_path).expect("open isz source");
        let aligned_len = (payload.len() / 2048) * 2048;
        assert_eq!(source.len(), aligned_len as u64);

        let mut decoded = vec![0_u8; aligned_len];
        let mut offset = 0;
        while offset < decoded.len() {
            let read = source.read_at(offset as u64, &mut decoded[offset..]).unwrap();
            assert!(read > 0, "read stalled at {offset}");
            offset += read;
        }
        assert_eq!(decoded, payload[..aligned_len], "decoded ISZ bytes must match the source ISO");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn optical_nrg_roundtrip_list_and_extract() {
        let iso_path = fixture("basic.iso");
        let iso_bytes = fs::read(&iso_path).expect("read basic.iso fixture");
        let iso_len = iso_bytes.len() as u32;

        let temp = TestDir::new("nrg-test");
        let nrg_path = temp.path("test.nrg");

        let mut nrg_bytes = iso_bytes.clone();
        // ETNF chunk: 4-byte chunk ID + 4-byte size (20) + 20-byte subblock
        nrg_bytes.extend_from_slice(b"ETNF");
        nrg_bytes.extend_from_slice(&20_u32.to_be_bytes());
        nrg_bytes.extend_from_slice(&0_u32.to_be_bytes()); // start offset
        nrg_bytes.extend_from_slice(&iso_len.to_be_bytes()); // size
        nrg_bytes.extend_from_slice(&[0, 0, 0, 5]); // mode 5 = Mode 1 Data 2048
        nrg_bytes.extend_from_slice(&0_u32.to_be_bytes()); // start LBA

        // END! chunk: 4-byte chunk ID + 4-byte size (0)
        nrg_bytes.extend_from_slice(b"END!");
        nrg_bytes.extend_from_slice(&0_u32.to_be_bytes());

        // Trailer: NERO + 4-byte offset pointing to ETNF chunk (iso_len)
        nrg_bytes.extend_from_slice(b"NERO");
        nrg_bytes.extend_from_slice(&iso_len.to_be_bytes());

        fs::write(&nrg_path, &nrg_bytes).unwrap();
        assert!(is_optical_image(&nrg_path));

        let entries = list_nrg(&nrg_path).expect("list nrg");
        assert!(!entries.is_empty());
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"README.TXT"), "paths: {paths:?}");
        assert!(paths.contains(&"NESTED/FILE.TXT"), "paths: {paths:?}");

        let out_dir = temp.path("out");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let report = extract_nrg_with_overwrite_resolver(&nrg_path, &out_dir, policy, &mut AlwaysReplace).expect("extract nrg");
        assert!(report.written_entries > 0);
        assert!(out_dir.join("README.TXT").is_file());
    }

    #[test]
    fn mdf_prefers_its_sibling_mds_descriptor() {
        let temp = TestDir::new("mdf-descriptor");
        let mdf = temp.path("disc.mdf");
        fs::write(&mdf, b"raw sector data").unwrap();

        // With no descriptor next to it, the `.mdf` is opened directly.
        assert_eq!(resolve_mdf_descriptor(&mdf), None);

        // With one present, the descriptor wins: it carries the session and
        // track table, and the data track need not begin at byte 0.
        let mds = temp.path("disc.mds");
        fs::write(&mds, b"descriptor").unwrap();
        assert_eq!(resolve_mdf_descriptor(&mdf), Some(mds));

        // Only `.mdf` inputs are redirected.
        assert_eq!(resolve_mdf_descriptor(&temp.path("disc.iso")), None);
    }

    #[test]
    fn optical_extension_set_matches_the_registered_format_kinds() {
        // Every extension here must be reachable: either it maps to a
        // registered format kind, or it is the data file a descriptor sheet
        // points at. Listing anything else implies support that cannot exist.
        for reachable in ["disc.iso", "disc.nrg", "disc.mds", "disc.mdf", "disc.cdi", "disc.ccd", "disc.cue", "disc.bin", "disc.img"] {
            assert!(is_optical_image(Path::new(reachable)), "{reachable}");
        }
        for unreachable in ["disc.b5t", "disc.b5i", "disc.toc", "archive.zip", "noextension"] {
            assert!(!is_optical_image(Path::new(unreachable)), "{unreachable} has no registered format kind and must not be claimed");
        }
    }

    #[test]
    fn optical_ccd_cue_mdf_roundtrip_list_and_extract() {
        let iso_path = fixture("basic.iso");
        let iso_bytes = fs::read(&iso_path).expect("read basic.iso fixture");

        let temp = TestDir::new("ccd-cue-mdf-test");

        // CCD/IMG
        let img_path = temp.path("disc.img");
        let ccd_path = temp.path("disc.ccd");
        fs::write(&img_path, &iso_bytes).unwrap();
        fs::write(&ccd_path, "[CloneCD]\r\nVersion=3\r\n[Disc]\r\nTracks=1\r\n[Track 1]\r\nMode=1\r\n").unwrap();

        let entries = list_ccd(&ccd_path).expect("list ccd");
        assert!(!entries.is_empty());
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"README.TXT"), "paths: {paths:?}");
        assert!(paths.contains(&"NESTED/FILE.TXT"), "paths: {paths:?}");

        let out_dir_ccd = temp.path("out_ccd");
        let policy = ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() };
        let report = extract_ccd_with_overwrite_resolver(&ccd_path, &out_dir_ccd, policy.clone(), &mut AlwaysReplace).expect("extract ccd");
        assert!(report.written_entries > 0);
        assert!(out_dir_ccd.join("README.TXT").is_file());

        // CUE/BIN
        let bin_path = temp.path("disc.bin");
        let cue_path = temp.path("disc.cue");
        fs::write(&bin_path, &iso_bytes).unwrap();
        fs::write(&cue_path, "FILE \"disc.bin\" BINARY\r\n  TRACK 01 MODE1/2048\r\n    INDEX 01 00:00:00\r\n").unwrap();

        let entries_cue = list_cue(&cue_path).expect("list cue");
        assert!(!entries_cue.is_empty());

        let out_dir_cue = temp.path("out_cue");
        let report_cue = extract_cue_with_overwrite_resolver(&cue_path, &out_dir_cue, policy.clone(), &mut AlwaysReplace).expect("extract cue");
        assert!(report_cue.written_entries > 0);
        assert!(out_dir_cue.join("README.TXT").is_file());

        // MDF
        let mdf_path = temp.path("disc.mdf");
        fs::write(&mdf_path, &iso_bytes).unwrap();

        let entries_mdf = list_mdf(&mdf_path).expect("list mdf");
        assert!(!entries_mdf.is_empty());

        let out_dir_mdf = temp.path("out_mdf");
        let report_mdf = extract_mdf_with_overwrite_resolver(&mdf_path, &out_dir_mdf, policy, &mut AlwaysReplace).expect("extract mdf");
        assert!(report_mdf.written_entries > 0);
        assert!(out_dir_mdf.join("README.TXT").is_file());
    }
}
