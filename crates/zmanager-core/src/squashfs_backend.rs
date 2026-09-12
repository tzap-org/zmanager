#![allow(clippy::doc_markdown, clippy::cast_possible_truncation, clippy::trivially_copy_pass_by_ref)]

//! Read-only SquashFS and AppImage backend.
//!
//! Handles both standalone SquashFS images and the SquashFS payload embedded
//! in a type-2 Linux AppImage. The AppImage payload offset is read from the
//! ELF section headers rather than scanned for, so a `hsqs` byte sequence
//! appearing inside the runtime cannot be mistaken for the filesystem.
//!
//! Compression coverage is deliberately complete for real-world images:
//! gzip, LZ4, zstd and LZO come from `backhand`'s default compressor, and XZ —
//! the dominant choice for distribution root filesystems — is decoded by
//! [`XzCapableCompressor`] through the pure-Rust `lzma-rust2` already used
//! elsewhere in this crate. See the `backhand` dependency comment in
//! `Cargo.toml` for why `liblzma` cannot be linked here.

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use backhand::FilesystemReader;
use backhand::kind::Kind;
use backhand::traits::CompressionAction;
use backhand::v4::compressor::{Compressor, DefaultCompressor};
use backhand::v4::filesystem::writer::FilesystemCompressor;
use backhand::v4::squashfs::SuperBlock;
use filetime::FileTime;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(SquashfsBackendError);

/// One normalized SquashFS entry.
#[derive(Debug, Clone)]
pub struct SquashfsEntry {
    /// Retained archive-order entry ID.
    pub index: usize,
    /// Normalized archive path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Uncompressed file size.
    pub size: u64,
    /// Relative target for a symbolic link entry.
    pub link_target: Option<String>,
    /// Unix mode bits recorded in the image.
    pub mode: u32,
    /// Modification time recorded in the image.
    pub mtime: u32,
    /// Position of the backing node in the image's node list.
    pub node_index: usize,
}

/// Normalized SquashFS operation report.
pub type SquashfsReport = crate::backend_impl::backend_report::BackendReport;

/// Error returned by native SquashFS operations.
#[derive(Debug)]
pub enum SquashfsBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Underlying backhand error.
    Backhand(String),
    /// Format error (not a valid SquashFS or AppImage).
    Invalid { path: PathBuf, message: String },
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for SquashfsBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Backhand(message) => write!(f, "squashfs error: {message}"),
            Self::Invalid { path, message } => write!(f, "invalid squashfs {}: {message}", path.display()),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for SquashfsBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Backhand(_) | Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

fn io_error(path: impl AsRef<Path>, source: io::Error) -> SquashfsBackendError {
    SquashfsBackendError::Io { path: path.as_ref().to_path_buf(), source }
}

fn invalid(path: impl AsRef<Path>, message: impl Into<String>) -> SquashfsBackendError {
    SquashfsBackendError::Invalid { path: path.as_ref().to_path_buf(), message: message.into() }
}

/// Little-endian SquashFS superblock magic.
const SQUASHFS_MAGIC: [u8; 4] = *b"hsqs";
/// Big-endian SquashFS superblock magic (recognized so the failure names the
/// real cause; `backhand` reads little-endian v4 images only).
const SQUASHFS_MAGIC_BE: [u8; 4] = *b"sqsh";
/// Bytes of ELF header needed to locate the section-header table.
const ELF_PROBE_BYTES: usize = 64;
/// Memory limit handed to the LZMA decoder, in KiB. SquashFS blocks are at
/// most 1 MiB, so a 256 MiB dictionary ceiling is generous while still
/// bounding a hostile `props` byte.
const LZMA_MEM_LIMIT_KIB: u32 = 256 * 1024;

/// A `backhand` compression backend that adds XZ (and legacy LZMA) on top of
/// the default compressor.
///
/// `backhand`'s own `xz` feature links `liblzma`, whose `links = "lzma"` key
/// collides with the `lzma-sys` already in this workspace's dependency graph.
/// Routing XZ through `lzma-rust2` keeps the reader pure-Rust and keeps a
/// single native `lzma` in the final binary.
#[derive(Debug, Default, Clone, Copy)]
pub struct XzCapableCompressor;

static XZ_CAPABLE_COMPRESSOR: XzCapableCompressor = XzCapableCompressor;

impl CompressionAction for XzCapableCompressor {
    type Error = backhand::BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    fn decompress(&self, bytes: &[u8], out: &mut Vec<u8>, compressor: Self::Compressor) -> Result<(), Self::Error> {
        match compressor {
            Compressor::Xz => {
                // SquashFS stores each XZ block as a complete single-stream
                // `.xz` container.
                let mut reader = lzma_rust2::XzReader::new(bytes, false);
                reader.read_to_end(out).map_err(|error| backhand::BackhandError::UnsupportedCompression(format!("xz block: {error}")))?;
                Ok(())
            }
            Compressor::Lzma => {
                // Legacy alone-format LZMA; rare in v4 images but cheap to
                // support now that a pure-Rust decoder is wired in.
                let mut reader = lzma_rust2::LzmaReader::new_mem_limit(bytes, LZMA_MEM_LIMIT_KIB, None)
                    .map_err(|error| backhand::BackhandError::UnsupportedCompression(format!("lzma block: {error}")))?;
                reader.read_to_end(out).map_err(|error| backhand::BackhandError::UnsupportedCompression(format!("lzma block: {error}")))?;
                Ok(())
            }
            Compressor::Lzo => {
                // Raw LZO1X block decode via the Apache-2.0 `lzo` crate.
                let uncompressed =
                    lzo::decompress(bytes, out.capacity()).map_err(|error| backhand::BackhandError::UnsupportedCompression(format!("lzo block: {error}")))?;
                out.extend_from_slice(&uncompressed);
                Ok(())
            }
            other => DefaultCompressor.decompress(bytes, out, other),
        }
    }

    fn compress(&self, bytes: &[u8], fc: Self::FilesystemCompressor, block_size: u32) -> Result<Vec<u8>, Self::Error> {
        // This backend never writes; `FilesystemCompressor` does not expose
        // its compressor id, so there is nothing to dispatch on even if it did.
        DefaultCompressor.compress(bytes, fc, block_size)
    }

    fn compression_options(
        &self,
        superblock: &mut Self::SuperBlock,
        kind: &Kind,
        fs_compressor: Self::FilesystemCompressor,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        DefaultCompressor.compression_options(superblock, kind, fs_compressor)
    }
}

/// The `Kind` used for every image opened by this backend.
fn squashfs_kind() -> Kind {
    Kind::new_v4(&XZ_CAPABLE_COMPRESSOR)
}

/// Locates the byte offset where the SquashFS superblock begins.
///
/// A standalone `.squashfs` starts at 0. A type-2 AppImage is an ELF whose
/// payload is appended after the section-header table, so the offset is
/// `e_shoff + e_shentsize * e_shnum` — the same computation `appimagetool`
/// uses when it appends the image.
///
/// # Errors
///
/// Returns [`SquashfsBackendError::Invalid`] when neither shape is present.
pub fn find_squashfs_offset(path: impl AsRef<Path>) -> Result<u64, SquashfsBackendError> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let file_len = file.metadata().map_err(|source| io_error(path, source))?.len();

    let mut probe = [0_u8; ELF_PROBE_BYTES];
    let probe_len = read_up_to(&mut file, &mut probe).map_err(|source| io_error(path, source))?;
    let probe = &probe[..probe_len];

    if probe.len() >= 4 && probe[..4] == SQUASHFS_MAGIC {
        return Ok(0);
    }
    if probe.len() >= 4 && probe[..4] == SQUASHFS_MAGIC_BE {
        return Err(invalid(path, "big-endian SquashFS images ('sqsh' magic) are not supported"));
    }

    if let Some(offset) = elf_payload_offset(probe)
        && offset < file_len
        && read_magic_at(&mut file, offset).map_err(|source| io_error(path, source))? == Some(SQUASHFS_MAGIC)
    {
        return Ok(offset);
    }

    Err(invalid(path, "no SquashFS superblock ('hsqs') found at offset 0 or at the ELF payload offset"))
}

/// Reads as much as the buffer holds, tolerating short reads.
fn read_up_to(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// Reads the 4 magic bytes at `offset`, if the file reaches that far.
fn read_magic_at(file: &mut File, offset: u64) -> io::Result<Option<[u8; 4]>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut magic = [0_u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(Some(magic)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

/// Computes the end of an ELF file's section-header table, which is where an
/// AppImage's SquashFS payload is appended.
///
/// Returns `None` when `header` is not an ELF header this can interpret.
fn elf_payload_offset(header: &[u8]) -> Option<u64> {
    if header.len() < ELF_PROBE_BYTES || !header.starts_with(b"\x7fELF") {
        return None;
    }
    let class = header[4];
    let little_endian = match header[5] {
        1 => true,
        2 => false,
        _ => return None,
    };

    let read_u16 = |offset: usize| -> u16 {
        let raw: [u8; 2] = header[offset..offset + 2].try_into().unwrap();
        if little_endian { u16::from_le_bytes(raw) } else { u16::from_be_bytes(raw) }
    };
    let read_u32 = |offset: usize| -> u64 {
        let raw: [u8; 4] = header[offset..offset + 4].try_into().unwrap();
        u64::from(if little_endian { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) })
    };
    let read_u64 = |offset: usize| -> u64 {
        let raw: [u8; 8] = header[offset..offset + 8].try_into().unwrap();
        if little_endian { u64::from_le_bytes(raw) } else { u64::from_be_bytes(raw) }
    };

    // ELFCLASS32 = 1 places e_shoff at 0x20 with 32-bit offsets;
    // ELFCLASS64 = 2 places it at 0x28 with 64-bit offsets.
    let (section_header_offset, section_entry_size, section_count) = match class {
        1 => (read_u32(0x20), read_u16(0x2E), read_u16(0x30)),
        2 => (read_u64(0x28), read_u16(0x3A), read_u16(0x3C)),
        _ => return None,
    };

    section_header_offset.checked_add(u64::from(section_entry_size).checked_mul(u64::from(section_count))?)
}

/// Opens a SquashFS filesystem reader at its detected offset.
fn open(path: &Path) -> Result<FilesystemReader<'static>, SquashfsBackendError> {
    let offset = find_squashfs_offset(path)?;
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let reader = BufReader::new(file);
    FilesystemReader::from_reader_with_offset_and_kind(reader, offset, squashfs_kind()).map_err(|error| SquashfsBackendError::Backhand(error.to_string()))
}

fn normalize_squashfs_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.trim_start_matches('/').replace('\\', "/")
}

/// Walks the image once, producing the normalized entry list.
///
/// Each entry carries the index of its backing node so later passes can index
/// straight into the node list instead of rescanning it per entry.
fn collect_entries(fs: &FilesystemReader<'_>, warnings: &mut Vec<String>) -> Vec<SquashfsEntry> {
    let mut entries = Vec::new();

    for (node_index, node) in fs.files().enumerate() {
        let normalized = normalize_squashfs_path(&node.fullpath);
        if normalized.is_empty() {
            continue;
        }
        let header = node.header;
        let (kind, size, link_target) = match &node.inner {
            backhand::InnerNode::File(file) => (BrowserEntryKind::File, file.file_len() as u64, None),
            backhand::InnerNode::Dir(_) => (BrowserEntryKind::Directory, 0, None),
            backhand::InnerNode::Symlink(symlink) => (BrowserEntryKind::Symlink, 0, Some(symlink.link.to_string_lossy().into_owned())),
            backhand::InnerNode::CharacterDevice(_) | backhand::InnerNode::BlockDevice(_) => {
                warnings.push(format!("skipped {normalized}: device nodes are not materialized"));
                continue;
            }
            backhand::InnerNode::NamedPipe => {
                warnings.push(format!("skipped {normalized}: named pipes are not materialized"));
                continue;
            }
            backhand::InnerNode::Socket => {
                warnings.push(format!("skipped {normalized}: sockets are not materialized"));
                continue;
            }
        };

        entries.push(SquashfsEntry {
            index: entries.len(),
            path: normalized,
            kind,
            size,
            link_target,
            mode: u32::from(header.permissions),
            mtime: header.mtime,
            node_index,
        });
    }
    entries
}

/// Returns the file reader for the node backing `entry`.
fn file_reader<'a, 'b>(
    fs: &'a FilesystemReader<'b>,
    entry: &SquashfsEntry,
    path: &Path,
) -> Result<backhand::FilesystemReaderFile<'a, 'b>, SquashfsBackendError> {
    let node = fs.files().nth(entry.node_index).ok_or_else(|| invalid(path, format!("node backing {} is no longer present", entry.path)))?;
    let backhand::InnerNode::File(file) = &node.inner else {
        return Err(invalid(path, format!("entry {} is not a regular file", entry.path)));
    };
    Ok(fs.file(file))
}

/// Restores the mode and modification time recorded in the image.
///
/// A SquashFS carries real Unix modes; dropping them would strip the
/// executable bit from every binary in an AppImage or root filesystem.
fn restore_metadata(entry: &SquashfsEntry, destination_path: &Path) -> Result<(), SquashfsBackendError> {
    crate::extract_materialize::apply_metadata(destination_path, Some(entry.mode), Some(FileTime::from_unix_time(i64::from(entry.mtime), 0)))
        .map_err(|source| io_error(destination_path, source))
}

/// Lists files in a SquashFS or AppImage archive.
///
/// # Errors
///
/// Propagates superblock detection and `backhand` decoding failures.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<SquashfsEntry>, SquashfsBackendError> {
    let path = path.as_ref();
    let fs = open(path)?;
    let mut warnings = Vec::new();
    Ok(collect_entries(&fs, &mut warnings))
}

/// Verifies selected or all SquashFS files.
///
/// # Errors
///
/// Returns [`SquashfsBackendError::Invalid`] when a file decodes to a length
/// other than the one the inode declares.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<SquashfsReport, SquashfsBackendError> {
    let path = path.as_ref();
    let fs = open(path)?;
    let mut report = SquashfsReport::default();
    let entries = collect_entries(&fs, &mut report.warnings);

    for entry in entries {
        if options.is_cancelled() {
            return Err(SquashfsBackendError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        if entry.kind == BrowserEntryKind::File {
            let mut reader = file_reader(&fs, &entry, path)?.reader();
            let bytes = io::copy(&mut reader, &mut io::sink()).map_err(|source| io_error(path, source))?;
            if bytes != entry.size {
                return Err(invalid(path, format!("file {} decoded to {bytes} bytes, expected {}", entry.path, entry.size)));
            }
            report.bytes = report.bytes.saturating_add(bytes);
        }
        report.entries = report.entries.saturating_add(1);
    }
    Ok(report)
}

/// Extracts all SquashFS files through the shared safety planner and atomic output.
///
/// # Errors
///
/// Propagates decoding failures, safety rejections, and destination I/O errors.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    resolver: Option<&mut dyn OverwriteResolver>,
    cancellation: Option<&crate::jobs::CancellationToken>,
) -> Result<SquashfsReport, SquashfsBackendError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    let root = crate::safety::prepare_destination_root(destination).map_err(|source| io_error(destination, source))?;
    let fs = open(path)?;
    let mut report = SquashfsReport::default();
    let entries = collect_entries(&fs, &mut report.warnings);
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&root, policy, resolver);
    // Directory modes are restored only after every child has been written,
    // so a read-only directory in the image cannot block its own contents.
    let mut deferred_directories: Vec<(SquashfsEntry, PathBuf)> = Vec::new();

    for entry in entries {
        if cancellation.is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(SquashfsBackendError::Cancelled);
        }
        let kind = match entry.kind {
            BrowserEntryKind::File => ExtractionEntryKind::File,
            BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
            BrowserEntryKind::Symlink => ExtractionEntryKind::Symlink { target: PathBuf::from(entry.link_target.clone().unwrap_or_default()) },
            _ => continue,
        };
        let safety_entry = ExtractionEntry { archive_path: entry.path.clone(), kind, uncompressed_size: Some(entry.size), compressed_size: None };
        let decision = planner.validate_entry(&safety_entry)?;
        let ExtractionDecision::Write { destination_path, replace_existing, .. } = decision else {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        };
        match &safety_entry.kind {
            ExtractionEntryKind::Directory => {
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                std::fs::create_dir_all(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                deferred_directories.push((entry, destination_path));
                report.entries = report.entries.saturating_add(1);
            }
            ExtractionEntryKind::File => {
                let mut reader = file_reader(&fs, &entry, path)?.reader();
                let mut output = crate::atomic_file::AtomicOutputFile::create(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                let file_out = output.file_mut().map_err(|source| io_error(&destination_path, source))?;
                let bytes = io::copy(&mut reader, file_out).map_err(|source| io_error(&destination_path, source))?;
                output.commit_with_replace(replace_existing).map_err(|source| io_error(&destination_path, source))?;
                restore_metadata(&entry, &destination_path)?;
                report.entries = report.entries.saturating_add(1);
                report.bytes = report.bytes.saturating_add(bytes);
            }
            ExtractionEntryKind::Symlink { target } => {
                if target.as_os_str().is_empty() {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(format!("skipped symlink {}: symlink target is empty", entry.path));
                    continue;
                }
                if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    report.warnings.push(crate::safety::unsupported_symlink_warning(&entry.path));
                    continue;
                }
                if replace_existing {
                    crate::safety::remove_destination_for_replace(&destination_path).map_err(|source| io_error(&destination_path, source))?;
                }
                crate::extract_materialize::write_symlink(target, &destination_path).map_err(|source| io_error(&destination_path, source))?;
                crate::extract_materialize::apply_symlink_mtime(&destination_path, Some(FileTime::from_unix_time(i64::from(entry.mtime), 0)))
                    .map_err(|source| io_error(&destination_path, source))?;
                report.entries = report.entries.saturating_add(1);
            }
            _ => unreachable!("SquashFS entries map only to files, directories, and symlinks"),
        }
    }

    // Deepest first, so a parent's mode is applied after its children.
    deferred_directories.sort_by_key(|(_, path)| std::cmp::Reverse(path.components().count()));
    for (entry, destination_path) in deferred_directories {
        restore_metadata(&entry, &destination_path)?;
    }

    Ok(report)
}

/// Copies one file entry to the writer.
///
/// # Errors
///
/// Returns [`SquashfsBackendError::Invalid`] when `target_path` is absent or
/// is not a regular file.
pub fn copy_to_writer(path: impl AsRef<Path>, target_path: &str, writer: &mut dyn Write) -> Result<u64, SquashfsBackendError> {
    let path = path.as_ref();
    let fs = open(path)?;
    let mut warnings = Vec::new();
    let entries = collect_entries(&fs, &mut warnings);
    let Some(entry) = entries.iter().find(|entry| entry.path == target_path && entry.kind == BrowserEntryKind::File) else {
        return Err(invalid(path, format!("file '{target_path}' not found in squashfs")));
    };
    let mut reader = file_reader(&fs, entry, path)?.reader();
    io::copy(&mut reader, writer).map_err(|source| io_error(path, source))
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use backhand::compression::Compressor as CompressorId;
    use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
    use std::fs;
    use std::io::Cursor;

    /// The checked-in images are produced by `mksquashfs`, the reference
    /// implementation, not by this crate's own encoder. That matters most for
    /// XZ: both sides of an in-repo round trip would be our code, so the test
    /// could pass while disagreeing with every real image.
    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    fn require_fixture(name: &str) -> PathBuf {
        let path = fixture(name);
        assert!(path.is_file(), "missing fixture {name}; run scripts/generate_fixtures.sh");
        path
    }

    fn paths_of(entries: &[SquashfsEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.path.as_str()).collect()
    }

    /// Builds a small image in-process for shapes the checked-in fixtures do
    /// not carry (device nodes, a read-only directory).
    fn build_squashfs(build: impl FnOnce(&mut FilesystemWriter<'_, '_, '_>)) -> Vec<u8> {
        let mut writer = FilesystemWriter::default();
        writer.set_kind(squashfs_kind());
        writer.set_compressor(FilesystemCompressor::new(CompressorId::Gzip, None).expect("compressor"));
        build(&mut writer);
        let mut out = Cursor::new(Vec::new());
        writer.write(&mut out).expect("write squashfs");
        out.into_inner()
    }

    #[test]
    fn reference_images_list_and_extract_for_every_compressor() {
        // XZ is the reason this loop exists: it is the dominant compressor for
        // distribution root filesystems and is served by
        // `XzCapableCompressor`, not by backhand's own `xz` feature.
        for name in ["basic-xz.squashfs", "basic-gzip.squashfs", "basic-zstd.squashfs"] {
            let archive = require_fixture(name);

            let entries = list(&archive).unwrap_or_else(|error| panic!("{name}: list failed: {error}"));
            let paths = paths_of(&entries);
            for expected in
                ["README.txt", "run.sh", "nested", "nested/file.txt", "nested/empty-dir", "dir with spaces/file with spaces.txt", "unicode/こんにちは.txt"]
            {
                assert!(paths.contains(&expected), "{name}: missing {expected} in {paths:?}");
            }
            assert!(entries.iter().all(|entry| !entry.path.starts_with('/')), "{name}: paths must be normalized: {paths:?}");

            let temp = TestDir::new(&format!("squashfs-{name}"));
            let dest = temp.path("out");
            extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap_or_else(|error| panic!("{name}: extract failed: {error}"));
            assert_eq!(fs::read_to_string(dest.join("README.txt")).unwrap(), "ZManager fixture payload\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("nested/file.txt")).unwrap(), "nested fixture file\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n", "{name}");
            assert_eq!(fs::read_to_string(dest.join("unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n", "{name}");
            assert!(dest.join("nested/empty-dir").is_dir(), "{name}");

            let report = test(&archive, &TestOptions::default()).unwrap_or_else(|error| panic!("{name}: test failed: {error}"));
            let declared: u64 = entries.iter().filter(|entry| entry.kind == BrowserEntryKind::File).map(|entry| entry.size).sum();
            assert_eq!(report.bytes, declared, "{name}: verified bytes must sum the declared file sizes");
        }
    }

    #[test]
    fn xz_reference_image_decodes_through_the_pure_rust_compressor() {
        // A standalone assertion so a regression in the custom
        // `CompressionAction` cannot hide behind the loop above.
        let archive = require_fixture("basic-xz.squashfs");
        let mut copied = Vec::new();
        let written = copy_to_writer(&archive, "nested/file.txt", &mut copied).unwrap();
        assert_eq!(copied, b"nested fixture file\n");
        assert_eq!(written, copied.len() as u64);
    }

    #[test]
    #[cfg(unix)]
    fn extraction_restores_unix_modes_and_mtimes() {
        use std::os::unix::fs::PermissionsExt as _;

        let archive = require_fixture("basic-gzip.squashfs");
        let temp = TestDir::new("squashfs-modes");
        let dest = temp.path("out");
        extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap();

        // Losing the executable bit is the failure mode this guards: an
        // AppImage or root filesystem extracted without modes has no runnable
        // binaries left in it.
        assert_eq!(fs::metadata(dest.join("run.sh")).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(dest.join("README.txt")).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(fs::metadata(dest.join("nested")).unwrap().permissions().mode() & 0o111 != 0, "directories must stay traversable");

        let entries = list(&archive).unwrap();
        let readme = entries.iter().find(|entry| entry.path == "README.txt").unwrap();
        let restored = filetime::FileTime::from_last_modification_time(&fs::metadata(dest.join("README.txt")).unwrap());
        assert_eq!(restored.unix_seconds(), i64::from(readme.mtime));
    }

    #[test]
    #[cfg(unix)]
    fn a_read_only_directory_still_receives_its_children() {
        use std::os::unix::fs::PermissionsExt as _;

        // Directory modes are applied after the tree is written; applying
        // 0o500 up front would make the directory unwritable for its own
        // contents.
        let temp = TestDir::new("squashfs-ro-dir");
        let archive = temp.path("locked.squashfs");
        let bytes = build_squashfs(|writer| {
            writer.push_dir("locked", NodeHeader::new(0o500, 0, 0, 0)).unwrap();
            writer.push_file(Cursor::new(b"inside\n"), "locked/inner.txt", NodeHeader::new(0o644, 0, 0, 0)).unwrap();
        });
        fs::write(&archive, bytes).unwrap();

        let dest = temp.path("out");
        extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(fs::read_to_string(dest.join("locked/inner.txt")).unwrap(), "inside\n");
        assert_eq!(fs::metadata(dest.join("locked")).unwrap().permissions().mode() & 0o777, 0o500);

        // Leave the tree writable so the temp directory can be cleaned up.
        fs::set_permissions(dest.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn appimage_payload_offset_comes_from_the_elf_section_table() {
        let archive = require_fixture("basic.AppImage");
        let payload = require_fixture("basic-gzip.squashfs");
        let expected_offset = fs::metadata(&archive).unwrap().len() - fs::metadata(&payload).unwrap().len();

        // The fixture plants a decoy `hsqs` at offset 2048; a reader that
        // scans for the magic instead of computing the offset locks onto it.
        assert_eq!(find_squashfs_offset(&archive).unwrap(), expected_offset);
        assert!(expected_offset > 2052, "the fixture's decoy must precede the real payload");

        let entries = list(&archive).unwrap();
        assert!(paths_of(&entries).contains(&"README.txt"));

        let temp = TestDir::new("appimage-extract");
        let dest = temp.path("out");
        extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap();
        assert_eq!(fs::read_to_string(dest.join("README.txt")).unwrap(), "ZManager fixture payload\n");
    }

    #[test]
    fn elf_payload_offset_handles_both_elf_classes_and_endiannesses() {
        let mut elf64 = vec![0_u8; ELF_PROBE_BYTES];
        elf64[0..4].copy_from_slice(b"\x7fELF");
        elf64[4] = 2;
        elf64[5] = 1;
        elf64[0x28..0x30].copy_from_slice(&1000_u64.to_le_bytes());
        elf64[0x3A..0x3C].copy_from_slice(&64_u16.to_le_bytes());
        elf64[0x3C..0x3E].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(elf_payload_offset(&elf64), Some(1000 + 128));

        let mut elf32 = vec![0_u8; ELF_PROBE_BYTES];
        elf32[0..4].copy_from_slice(b"\x7fELF");
        elf32[4] = 1;
        elf32[5] = 1;
        elf32[0x20..0x24].copy_from_slice(&500_u32.to_le_bytes());
        elf32[0x2E..0x30].copy_from_slice(&40_u16.to_le_bytes());
        elf32[0x30..0x32].copy_from_slice(&3_u16.to_le_bytes());
        assert_eq!(elf_payload_offset(&elf32), Some(500 + 120));

        let mut elf64_be = vec![0_u8; ELF_PROBE_BYTES];
        elf64_be[0..4].copy_from_slice(b"\x7fELF");
        elf64_be[4] = 2;
        elf64_be[5] = 2;
        elf64_be[0x28..0x30].copy_from_slice(&1000_u64.to_be_bytes());
        elf64_be[0x3A..0x3C].copy_from_slice(&64_u16.to_be_bytes());
        elf64_be[0x3C..0x3E].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(elf_payload_offset(&elf64_be), Some(1000 + 128));

        assert_eq!(elf_payload_offset(b"not an elf"), None);
        let mut bad_class = elf64.clone();
        bad_class[4] = 9;
        assert_eq!(elf_payload_offset(&bad_class), None, "an unknown ELF class must not be guessed at");
    }

    #[test]
    fn non_squashfs_inputs_are_rejected_with_a_specific_message() {
        let temp = TestDir::new("squashfs-reject");

        fs::write(temp.path("empty.squashfs"), b"").unwrap();
        assert!(find_squashfs_offset(temp.path("empty.squashfs")).is_err());

        // A file that merely contains `hsqs` somewhere is not a SquashFS.
        let mut junk = vec![0x5A_u8; 65536];
        junk[30000..30004].copy_from_slice(b"hsqs");
        fs::write(temp.path("junk.squashfs"), &junk).unwrap();
        let error = find_squashfs_offset(temp.path("junk.squashfs")).unwrap_err();
        assert!(error.to_string().contains("no SquashFS superblock"), "{error}");

        // Big-endian images name their own cause instead of failing obscurely.
        let mut big_endian = vec![0_u8; 1024];
        big_endian[0..4].copy_from_slice(b"sqsh");
        fs::write(temp.path("be.squashfs"), &big_endian).unwrap();
        let error = find_squashfs_offset(temp.path("be.squashfs")).unwrap_err();
        assert!(error.to_string().contains("big-endian"), "{error}");

        // A real image cut off below its metadata tables must fail rather
        // than list garbage. `mksquashfs` pads the file to a 4 KiB boundary,
        // so the cut is taken against `bytes_used` from the superblock rather
        // than against the file length, which is mostly padding.
        let bytes = fs::read(require_fixture("basic-gzip.squashfs")).unwrap();
        let bytes_used = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        assert!(bytes_used > 96, "superblock must report a plausible used length");
        fs::write(temp.path("truncated.squashfs"), &bytes[..bytes_used / 2]).unwrap();
        assert!(list(temp.path("truncated.squashfs")).is_err(), "an image cut below its metadata tables must not list");
    }

    #[test]
    fn special_files_are_reported_rather_than_dropped_silently() {
        let temp = TestDir::new("squashfs-special");
        let archive = temp.path("special.squashfs");
        let bytes = build_squashfs(|writer| {
            writer.push_file(Cursor::new(b"real\n"), "real.txt", NodeHeader::new(0o644, 0, 0, 0)).unwrap();
            writer.push_dir("dev", NodeHeader::new(0o755, 0, 0, 0)).unwrap();
            writer.push_char_device(1, "dev/null", NodeHeader::new(0o666, 0, 0, 0)).unwrap();
        });
        fs::write(&archive, bytes).unwrap();

        let report = test(&archive, &TestOptions::default()).unwrap();
        assert!(report.warnings.iter().any(|warning| warning.contains("dev/null") && warning.contains("device")), "warnings: {:?}", report.warnings);
        assert!(!paths_of(&list(&archive).unwrap()).contains(&"dev/null"));
    }

    #[test]
    fn symlinks_are_materialized_with_their_targets() {
        let archive = require_fixture("basic-gzip.squashfs");
        let entries = list(&archive).unwrap();
        let link = entries.iter().find(|entry| entry.path == "nested/readme-link.txt").expect("fixture carries a symlink");
        assert_eq!(link.kind, BrowserEntryKind::Symlink);
        assert_eq!(link.link_target.as_deref(), Some("../README.txt"));

        let temp = TestDir::new("squashfs-symlink");
        let dest = temp.path("out");
        let report = extract(&archive, &dest, ExtractionPolicy::default(), None, None).unwrap();
        #[cfg(unix)]
        assert_eq!(fs::read_link(dest.join("nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"), "warnings: {:?}", report.warnings);
        #[cfg(not(unix))]
        assert!(report.warnings.iter().any(|warning| warning.contains("readme-link.txt")));
    }

    #[test]
    fn entry_lookup_uses_the_recorded_node_index() {
        // `node_index` is what keeps list/test/extract linear rather than
        // rescanning the whole node list once per entry.
        let archive = require_fixture("basic-gzip.squashfs");
        let fs_reader = open(&archive).unwrap();
        let mut warnings = Vec::new();
        let entries = collect_entries(&fs_reader, &mut warnings);
        assert!(!entries.is_empty());

        for entry in &entries {
            let node = fs_reader.files().nth(entry.node_index).expect("node index resolves");
            assert_eq!(normalize_squashfs_path(&node.fullpath), entry.path);
        }
    }

    #[test]
    fn test_honours_selection_and_cancellation() {
        let archive = require_fixture("basic-gzip.squashfs");

        let options = TestOptions { selected_paths: vec!["README.txt".to_owned()], ..TestOptions::default() };
        let report = test(&archive, &options).unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, "ZManager fixture payload\n".len() as u64);
        assert!(report.skipped_entries > 0);

        let cancelled = TestOptions { cancellation: Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true))), ..TestOptions::default() };
        assert!(matches!(test(&archive, &cancelled), Err(SquashfsBackendError::Cancelled)));
    }
}
