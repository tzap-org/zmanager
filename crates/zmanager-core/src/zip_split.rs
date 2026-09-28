//! Split-ZIP volume machinery for the ZIP backend.
//!
//! The zip crate writes a single seekable archive; splitting it into
//! `.z01`/`.z02`/.../`.zip` volumes requires post-processing the finished
//! archive: byte-splitting the file, rewriting central-directory disk fields,
//! and synthesizing a multi-disk EOCD. All of that lives here.

use crate::segmented_reader::SegmentedReader;
use crate::zip_backend::ZipBackendError;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const ZIP_SPLIT_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_EOCD_MIN_SIZE: usize = 22;
const ZIP_EOCD_MAX_COMMENT_SIZE: u64 = 65_535;
pub(crate) const MIN_ZIP_VOLUME_SIZE_BYTES: u64 = 65_536;
const ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH: usize = 2;

pub(crate) fn split_zip_temp_archive(archive_path: &Path, destination: &Path, volume_size: u64, replace_existing: bool) -> Result<usize, ZipBackendError> {
    let archive_size = fs::metadata(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?.len();
    let eocd = read_zip_eocd(archive_path, archive_size)?;

    if archive_size <= volume_size {
        let volume_paths = vec![destination.to_path_buf()];
        let existing_volume_paths = existing_split_zip_volume_paths(destination)?;
        ensure_split_destinations_available(destination, &volume_paths, &existing_volume_paths, replace_existing)?;
        let mut archive = File::open(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
        let mut writer = ZipSplitVolumeWriter::new(&volume_paths, archive_size.max(1))?;
        writer.copy_from(&mut archive, archive_size, destination)?;
        writer.finish(destination, &existing_volume_paths, replace_existing)?;
        return Ok(1);
    }

    let logical_size = archive_size.checked_add(4u64).ok_or_else(|| unsupported_split_zip("archive is too large to split"))?;
    let volume_count = crate::archive_split::split_volume_count(logical_size, volume_size).ok_or_else(|| unsupported_split_zip("too many ZIP volumes"))?;
    let layout = ZipSplitLayout::new(logical_size, volume_size, &eocd)?;
    let volume_paths = split_zip_volume_paths(destination, volume_count)?;
    let existing_volume_paths = existing_split_zip_volume_paths(destination)?;
    ensure_split_destinations_available(destination, &volume_paths, &existing_volume_paths, replace_existing)?;

    let mut central_directory = read_zip_central_directory(archive_path, &eocd)?;
    let entries_on_last_disk =
        patch_split_zip_central_directory(&mut central_directory, volume_size, layout.central_directory_logical_offset, layout.last_disk)?;
    let mut eocd_bytes = eocd.bytes.clone();
    patch_split_zip_eocd(&mut eocd_bytes, &layout, eocd.total_entries, entries_on_last_disk)?;

    let mut archive = BufReader::new(File::open(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?);
    let mut writer = ZipSplitVolumeWriter::new(&volume_paths, volume_size)?;
    writer.write_all(&ZIP_SPLIT_SIGNATURE)?;
    writer.copy_from(&mut archive, eocd.central_directory_offset, archive_path)?;
    writer.write_all(&central_directory)?;
    writer.write_all(&eocd_bytes)?;
    writer.finish(destination, &existing_volume_paths, replace_existing)?;

    Ok(volume_count)
}

/// A seekable ZIP input. Split ZIP volumes are exposed as one logical stream
/// with the multi-disk fields normalized to a single-disk archive so the
/// `zip` crate can perform all metadata, decompression, encryption, and CRC
/// handling. The volume payload is read on demand; it is never concatenated
/// into memory or a temporary file.
pub(crate) trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

pub(crate) fn open_zip_reader(path: &Path) -> Result<Box<dyn ReadSeek>, ZipBackendError> {
    let paths = crate::engine::source::discover_split_zip_volumes(path).unwrap_or_else(|| vec![path.to_path_buf()]);
    open_zip_reader_from_paths(&paths)
}

/// Opens a ZIP reader from the caller-owned, already resolved volume set.
///
/// The engine uses this entry point after `ArchiveSource` has captured the
/// source shape. It must not rediscover sidecars from a final path.
pub(crate) fn open_zip_reader_from_paths(paths: &[PathBuf]) -> Result<Box<dyn ReadSeek>, ZipBackendError> {
    if paths.len() <= 1 {
        let path = paths.first().cloned().unwrap_or_else(|| PathBuf::from("<ZIP source>"));
        return File::open(&path).map(|file| Box::new(file) as Box<dyn ReadSeek>).map_err(|source| ZipBackendError::Io { path, source });
    }
    let Some(first_path) = paths.first() else {
        return Err(unsupported_split_zip("split ZIP volume set is incomplete"));
    };
    let mut header = [0_u8; ZIP_SPLIT_SIGNATURE.len()];
    let mut first = File::open(first_path).map_err(|source| ZipBackendError::Io { path: first_path.clone(), source })?;
    let read = first.read(&mut header).map_err(|source| ZipBackendError::Io { path: paths[0].clone(), source })?;
    if read == header.len() && header == ZIP_SPLIT_SIGNATURE {
        Ok(Box::new(SplitZipReader::open(paths)?))
    } else {
        // 7-Zip's `-v` ZIP output is a raw contiguous stream split across
        // numbered `.zip.001` volumes rather than a disk-spanned ZIP with
        // PK\x07\x08 markers. Present the ordered segments directly.
        Ok(Box::new(
            SegmentedReader::open(paths.to_vec())
                .map_err(|source| ZipBackendError::Io { path: paths.first().cloned().unwrap_or_else(|| PathBuf::from("<split ZIP>")), source })?,
        ))
    }
}

struct SplitZipReader {
    source: SegmentedReader,
    lengths: Vec<u64>,
    starts: Vec<u64>,
    len: u64,
    position: u64,
    patches: Vec<(u64, Vec<u8>)>,
}

impl SplitZipReader {
    fn open(paths: &[PathBuf]) -> Result<Self, ZipBackendError> {
        let source = SegmentedReader::open(paths.to_vec())
            .map_err(|source| ZipBackendError::Io { path: paths.first().cloned().unwrap_or_else(|| PathBuf::from("<split ZIP>")), source })?;
        let layout = source.part_layout();
        if layout.first().map_or(0, |(_, length)| *length) < 4 {
            return Err(unsupported_split_zip("first ZIP volume is missing the split signature"));
        }
        let mut signature = [0_u8; 4];
        let mut source = source;
        source.read_exact(&mut signature).map_err(|source| ZipBackendError::Io { path: paths[0].clone(), source })?;
        if signature != ZIP_SPLIT_SIGNATURE {
            return Err(unsupported_split_zip("first ZIP volume has an invalid split signature"));
        }

        let len = source.total_len().checked_sub(4).ok_or_else(|| unsupported_split_zip("ZIP volume size underflow"))?;
        let (starts, lengths): (Vec<_>, Vec<_>) = layout.into_iter().unzip();
        let mut reader = Self { source, lengths, starts, len, position: 0, patches: Vec::new() };
        reader.build_normalization_patches()?;
        Ok(reader)
    }

    fn build_normalization_patches(&mut self) -> Result<(), ZipBackendError> {
        let tail_size = self.len.min((ZIP_EOCD_MIN_SIZE as u64) + ZIP_EOCD_MAX_COMMENT_SIZE);
        if tail_size < ZIP_EOCD_MIN_SIZE as u64 {
            return Err(unsupported_split_zip("ZIP end record is missing"));
        }
        let tail_start = self.len - tail_size;
        let mut tail = vec![0_u8; usize::try_from(tail_size).map_err(|_| unsupported_split_zip("ZIP end record tail is too large"))?];
        self.read_raw_at(tail_start, &mut tail)?;
        let mut eocd_offset = None;
        let mut eocd_bytes = None;
        for offset in (0..=tail.len() - ZIP_EOCD_MIN_SIZE).rev() {
            if read_u32(&tail[offset..offset + 4]) != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
                continue;
            }
            let comment_len = usize::from(read_u16(&tail[offset + 20..offset + 22]));
            let end = offset.checked_add(ZIP_EOCD_MIN_SIZE).and_then(|end| end.checked_add(comment_len));
            if end == Some(tail.len()) {
                eocd_offset = Some(tail_start + u64::try_from(offset).unwrap_or(0));
                eocd_bytes = Some(tail[offset..end.unwrap_or(offset)].to_vec());
                break;
            }
        }
        let eocd_offset = eocd_offset.ok_or_else(|| unsupported_split_zip("ZIP end record is missing"))?;
        let mut eocd = eocd_bytes.ok_or_else(|| unsupported_split_zip("ZIP end record is missing"))?;
        if eocd.len() < ZIP_EOCD_MIN_SIZE {
            return Err(unsupported_split_zip("ZIP end record is truncated"));
        }
        if read_u16(&eocd[4..6]) == u16::MAX || read_u16(&eocd[6..8]) == u16::MAX || read_u32(&eocd[12..16]) == u32::MAX || read_u32(&eocd[16..20]) == u32::MAX
        {
            return Err(unsupported_split_zip("ZIP64 split metadata is not implemented"));
        }
        let cd_disk = read_u16(&eocd[6..8]);
        let cd_offset_on_disk = u64::from(read_u32(&eocd[16..20]));
        let cd_size = u64::from(read_u32(&eocd[12..16]));
        let total_entries = read_u16(&eocd[10..12]);
        let cd_start = self.disk_offset(cd_disk, cd_offset_on_disk)?;
        let cd_end = cd_start.checked_add(cd_size).ok_or_else(|| unsupported_split_zip("central directory range overflow"))?;
        if cd_end > self.len || cd_end > eocd_offset {
            return Err(unsupported_split_zip("central directory lies outside the ZIP stream"));
        }

        let mut central = vec![0_u8; usize::try_from(cd_size).map_err(|_| unsupported_split_zip("central directory is too large"))?];
        self.read_raw_at(cd_start, &mut central)?;
        let mut offset = 0usize;
        let mut entries = 0_u16;
        while offset < central.len() {
            if offset + 46 > central.len() || read_u32(&central[offset..offset + 4]) != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
                return Err(unsupported_split_zip("central directory is malformed"));
            }
            let name_len = usize::from(read_u16(&central[offset + 28..offset + 30]));
            let extra_len = usize::from(read_u16(&central[offset + 30..offset + 32]));
            let comment_len = usize::from(read_u16(&central[offset + 32..offset + 34]));
            let disk_start = read_u16(&central[offset + 34..offset + 36]);
            let local_offset = u64::from(read_u32(&central[offset + 42..offset + 46]));
            let local_absolute = self.disk_offset(disk_start, local_offset)?;
            let local_absolute_u32 = u32::try_from(local_absolute).map_err(|_| unsupported_split_zip("logical ZIP offset exceeds ZIP32"))?;
            central[offset + 34..offset + 36].copy_from_slice(&0_u16.to_le_bytes());
            central[offset + 42..offset + 46].copy_from_slice(&local_absolute_u32.to_le_bytes());
            let next = offset
                .checked_add(46)
                .and_then(|value| value.checked_add(name_len))
                .and_then(|value| value.checked_add(extra_len))
                .and_then(|value| value.checked_add(comment_len))
                .ok_or_else(|| unsupported_split_zip("central directory entry overflow"))?;
            if next > central.len() {
                return Err(unsupported_split_zip("central directory entry is truncated"));
            }
            offset = next;
            entries = entries.checked_add(1).ok_or_else(|| unsupported_split_zip("too many ZIP entries"))?;
        }
        if entries != total_entries {
            return Err(unsupported_split_zip("central directory entry count is inconsistent"));
        }
        self.patches.push((cd_start, central));

        let eocd_virtual = eocd_offset;
        eocd[4..6].copy_from_slice(&0_u16.to_le_bytes());
        eocd[6..8].copy_from_slice(&0_u16.to_le_bytes());
        eocd[8..10].copy_from_slice(&total_entries.to_le_bytes());
        eocd[10..12].copy_from_slice(&total_entries.to_le_bytes());
        eocd[12..16].copy_from_slice(&u32::try_from(cd_size).map_err(|_| unsupported_split_zip("central directory exceeds ZIP32"))?.to_le_bytes());
        eocd[16..20].copy_from_slice(&u32::try_from(cd_start).map_err(|_| unsupported_split_zip("central directory offset exceeds ZIP32"))?.to_le_bytes());
        self.patches.push((eocd_virtual, eocd));
        Ok(())
    }

    fn disk_offset(&self, disk: u16, offset: u64) -> Result<u64, ZipBackendError> {
        let disk = usize::from(disk);
        if disk >= self.lengths.len() {
            return Err(unsupported_split_zip("ZIP entry references a missing volume"));
        }
        if disk == 0 {
            if offset < 4 || offset >= self.lengths[0] {
                return Err(unsupported_split_zip("ZIP disk-relative offset is outside volume 0"));
            }
            Ok(offset - 4)
        } else if offset >= self.lengths[disk] {
            Err(unsupported_split_zip("ZIP disk-relative offset is outside its volume"))
        } else {
            Ok(self.starts[disk] - 4 + offset)
        }
    }

    fn read_raw_at(&mut self, position: u64, output: &mut [u8]) -> Result<(), ZipBackendError> {
        let mut copied = 0usize;
        while copied < output.len() {
            let physical = position.checked_add(u64::try_from(copied).unwrap_or(0)).ok_or_else(|| unsupported_split_zip("ZIP read offset overflow"))? + 4;
            let disk = self.starts.partition_point(|start| *start <= physical).saturating_sub(1);
            let within = physical - self.starts[disk];
            let available = usize::try_from(self.lengths[disk] - within).unwrap_or(usize::MAX);
            let count = available.min(output.len() - copied);
            self.source.seek(SeekFrom::Start(physical)).map_err(|source| ZipBackendError::Io { path: PathBuf::from("<split ZIP>"), source })?;
            self.source.read_exact(&mut output[copied..copied + count]).map_err(|source| ZipBackendError::Io { path: PathBuf::from("<split ZIP>"), source })?;
            copied += count;
        }
        Ok(())
    }
}

impl Read for SplitZipReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.len || output.is_empty() {
            return Ok(0);
        }
        let count = output.len().min(usize::try_from(self.len - self.position).unwrap_or(usize::MAX));
        self.read_raw_at(self.position, &mut output[..count]).map_err(|error| match error {
            ZipBackendError::Io { source, .. } => source,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        })?;
        for (patch_start, patch) in &self.patches {
            let patch_end = patch_start.saturating_add(u64::try_from(patch.len()).unwrap_or(u64::MAX));
            let read_end = self.position + u64::try_from(count).unwrap_or(0);
            if *patch_start < read_end && patch_end > self.position {
                let start = (*patch_start).max(self.position);
                let end = patch_end.min(read_end);
                let output_start = usize::try_from(start - self.position).unwrap_or(0);
                let patch_start_index = usize::try_from(start - *patch_start).unwrap_or(0);
                let patch_end_index = patch_start_index + usize::try_from(end - start).unwrap_or(0);
                output[output_start..output_start + (patch_end_index - patch_start_index)].copy_from_slice(&patch[patch_start_index..patch_end_index]);
            }
        }
        self.position += u64::try_from(count).unwrap_or(0);
        Ok(count)
    }
}

impl Seek for SplitZipReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.len) + i128::from(value),
        };
        if !(0..=i128::from(self.len)).contains(&next) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ZIP seek outside logical stream"));
        }
        self.position = u64::try_from(next).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ZIP seek overflow"))?;
        Ok(self.position)
    }
}

#[derive(Debug)]
struct ZipEndOfCentralDirectory {
    central_directory_offset: u64,
    central_directory_size: u64,
    total_entries: u16,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ZipSplitLayout {
    central_directory_logical_offset: u64,
    central_directory_disk: u16,
    central_directory_offset_on_disk: u32,
    last_disk: u16,
}

impl ZipSplitLayout {
    fn new(logical_size: u64, volume_size: u64, eocd: &ZipEndOfCentralDirectory) -> Result<Self, ZipBackendError> {
        let central_directory_logical_offset =
            eocd.central_directory_offset.checked_add(4u64).ok_or_else(|| unsupported_split_zip("central directory offset overflow"))?;
        let (central_directory_disk, central_directory_offset_on_disk) = split_zip_location(central_directory_logical_offset, volume_size)?;
        let (last_disk, _) = split_zip_location(logical_size.saturating_sub(1), volume_size)?;
        Ok(Self { central_directory_logical_offset, central_directory_disk, central_directory_offset_on_disk, last_disk })
    }
}

fn read_zip_eocd(archive_path: &Path, archive_size: u64) -> Result<ZipEndOfCentralDirectory, ZipBackendError> {
    if archive_size < ZIP_EOCD_MIN_SIZE as u64 {
        return Err(unsupported_split_zip("archive is missing ZIP end record"));
    }

    let tail_size = archive_size.min(ZIP_EOCD_MIN_SIZE as u64 + ZIP_EOCD_MAX_COMMENT_SIZE);
    let mut file = File::open(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
    file.seek(SeekFrom::Start(archive_size - tail_size)).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
    let mut tail = vec![0; usize::try_from(tail_size).map_err(|_| { unsupported_split_zip("ZIP end record tail is too large for this platform") })?];
    file.read_exact(&mut tail).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;

    for offset in (0..=tail.len() - ZIP_EOCD_MIN_SIZE).rev() {
        if read_u32(&tail[offset..offset + 4]) != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            continue;
        }
        let comment_len = usize::from(read_u16(&tail[offset + 20..offset + 22]));
        let eocd_len = ZIP_EOCD_MIN_SIZE + comment_len;
        if offset + eocd_len != tail.len() {
            continue;
        }
        let eocd_offset = archive_size - tail_size + u64::try_from(offset).unwrap_or(0);
        if eocd_offset >= 20 {
            let locator_start = eocd_offset - 20;
            if locator_start >= archive_size - tail_size {
                let relative =
                    usize::try_from(locator_start - (archive_size - tail_size)).map_err(|_| unsupported_split_zip("ZIP64 locator offset overflow"))?;
                if relative + 4 <= tail.len() && read_u32(&tail[relative..relative + 4]) == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE {
                    return Err(unsupported_split_zip("ZIP64 split metadata is not implemented"));
                }
            }
        }

        let disk_number = read_u16(&tail[offset + 4..offset + 6]);
        let central_directory_disk = read_u16(&tail[offset + 6..offset + 8]);
        if disk_number != 0 || central_directory_disk != 0 {
            return Err(unsupported_split_zip("archive is already a multi-disk ZIP"));
        }
        let entries_on_disk = read_u16(&tail[offset + 8..offset + 10]);
        let total_entries = read_u16(&tail[offset + 10..offset + 12]);
        let central_directory_size = read_u32(&tail[offset + 12..offset + 16]);
        let central_directory_offset = read_u32(&tail[offset + 16..offset + 20]);
        if entries_on_disk == u16::MAX || total_entries == u16::MAX || central_directory_size == u32::MAX || central_directory_offset == u32::MAX {
            return Err(unsupported_split_zip("ZIP64 central directory markers are not supported for split output"));
        }
        if entries_on_disk != total_entries {
            return Err(unsupported_split_zip("central directory entry counts are inconsistent"));
        }
        let central_directory_offset = u64::from(central_directory_offset);
        let central_directory_size = u64::from(central_directory_size);
        let central_directory_end =
            central_directory_offset.checked_add(central_directory_size).ok_or_else(|| unsupported_split_zip("central directory offset overflow"))?;
        if central_directory_end != eocd_offset {
            return Err(unsupported_split_zip("unexpected data between central directory and ZIP end record"));
        }

        return Ok(ZipEndOfCentralDirectory {
            central_directory_offset,
            central_directory_size,
            total_entries,
            bytes: tail[offset..offset + eocd_len].to_vec(),
        });
    }

    Err(unsupported_split_zip("archive is missing ZIP end record"))
}

fn read_zip_central_directory(archive_path: &Path, eocd: &ZipEndOfCentralDirectory) -> Result<Vec<u8>, ZipBackendError> {
    let mut file = File::open(archive_path).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
    file.seek(SeekFrom::Start(eocd.central_directory_offset)).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
    let mut central_directory =
        vec![0; usize::try_from(eocd.central_directory_size).map_err(|_| { unsupported_split_zip("central directory is too large for this platform") })?];
    file.read_exact(&mut central_directory).map_err(|source| ZipBackendError::Io { path: archive_path.to_path_buf(), source })?;
    Ok(central_directory)
}

fn patch_split_zip_central_directory(
    central_directory: &mut [u8],
    volume_size: u64,
    central_directory_logical_offset: u64,
    eocd_disk: u16,
) -> Result<u16, ZipBackendError> {
    let mut offset = 0usize;
    let mut entries_on_eocd_disk = 0u16;
    while offset < central_directory.len() {
        if offset + 46 > central_directory.len() || read_u32(&central_directory[offset..offset + 4]) != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
            return Err(unsupported_split_zip("central directory is malformed"));
        }
        let file_name_len = usize::from(read_u16(&central_directory[offset + 28..offset + 30]));
        let extra_len = usize::from(read_u16(&central_directory[offset + 30..offset + 32]));
        let comment_len = usize::from(read_u16(&central_directory[offset + 32..offset + 34]));
        let disk_start = read_u16(&central_directory[offset + 34..offset + 36]);
        let local_header_offset = read_u32(&central_directory[offset + 42..offset + 46]);
        if disk_start != 0 {
            return Err(unsupported_split_zip("archive is already a multi-disk ZIP"));
        }
        if local_header_offset == u32::MAX {
            return Err(unsupported_split_zip("ZIP64 local header offsets are not supported for split output"));
        }
        let logical_header_offset = u64::from(local_header_offset).checked_add(4u64).ok_or_else(|| unsupported_split_zip("local header offset overflow"))?;
        let (disk, relative_offset) = split_zip_location(logical_header_offset, volume_size)?;
        central_directory[offset + 34..offset + 36].copy_from_slice(&disk.to_le_bytes());
        central_directory[offset + 42..offset + 46].copy_from_slice(&relative_offset.to_le_bytes());
        let central_directory_entry_offset = central_directory_logical_offset
            .checked_add(u64::try_from(offset).unwrap_or(0))
            .ok_or_else(|| unsupported_split_zip("central directory entry offset overflow"))?;
        let (central_directory_entry_disk, _) = split_zip_location(central_directory_entry_offset, volume_size)?;
        if central_directory_entry_disk == eocd_disk {
            entries_on_eocd_disk = entries_on_eocd_disk.saturating_add(1);
        }
        let next_offset = offset
            .checked_add(46)
            .and_then(|value| value.checked_add(file_name_len))
            .and_then(|value| value.checked_add(extra_len))
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| unsupported_split_zip("central directory entry overflow"))?;
        if next_offset > central_directory.len() {
            return Err(unsupported_split_zip("central directory entry is truncated"));
        }
        offset = next_offset;
    }
    Ok(entries_on_eocd_disk)
}

fn patch_split_zip_eocd(eocd: &mut [u8], layout: &ZipSplitLayout, total_entries: u16, entries_on_last_disk: u16) -> Result<(), ZipBackendError> {
    if eocd.len() < ZIP_EOCD_MIN_SIZE || read_u32(&eocd[0..4]) != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
        return Err(unsupported_split_zip("ZIP end record is malformed"));
    }
    eocd[4..6].copy_from_slice(&layout.last_disk.to_le_bytes());
    eocd[6..8].copy_from_slice(&layout.central_directory_disk.to_le_bytes());
    eocd[8..10].copy_from_slice(&entries_on_last_disk.to_le_bytes());
    eocd[10..12].copy_from_slice(&total_entries.to_le_bytes());
    eocd[16..20].copy_from_slice(&layout.central_directory_offset_on_disk.to_le_bytes());
    Ok(())
}

fn split_zip_location(logical_offset: u64, volume_size: u64) -> Result<(u16, u32), ZipBackendError> {
    let disk = logical_offset / volume_size;
    if disk >= u64::from(u16::MAX) {
        return Err(unsupported_split_zip("too many ZIP volumes"));
    }
    let offset = logical_offset % volume_size;
    let disk = u16::try_from(disk).map_err(|_| unsupported_split_zip("ZIP disk number overflow"))?;
    let offset = u32::try_from(offset).map_err(|_| unsupported_split_zip("ZIP disk-relative offset overflow"))?;
    Ok((disk, offset))
}

fn split_zip_volume_paths(destination: &Path, count: usize) -> Result<Vec<PathBuf>, ZipBackendError> {
    if count <= 1 {
        return Ok(vec![destination.to_path_buf()]);
    }
    let base = split_zip_base_path(destination)?;
    let mut paths = Vec::with_capacity(count);
    for index in 1..count {
        let extension = format!("z{index:0ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH$}");
        paths.push(base.with_extension(extension));
    }
    paths.push(destination.to_path_buf());
    Ok(paths)
}

fn split_zip_base_path(destination: &Path) -> Result<PathBuf, ZipBackendError> {
    if destination.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case("zip")) {
        return Ok(destination.with_extension(""));
    }
    Err(unsupported_split_zip("split ZIP output path must use a .zip extension"))
}

fn ensure_split_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), ZipBackendError> {
    ensure_file_destination_available(destination, replace_existing)?;
    for path in crate::archive_split::unique_paths(volume_paths, existing_volume_paths) {
        ensure_file_destination_available(path, replace_existing)?;
    }
    Ok(())
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), ZipBackendError> {
    crate::archive_split::ensure_file_destination_available(path, replace_existing).map_err(|source| ZipBackendError::Io { path: path.to_path_buf(), source })
}

fn remove_split_destinations_for_replace(destination: &Path, existing_volume_paths: &[PathBuf], replace_existing: bool) -> Result<(), ZipBackendError> {
    crate::archive_split::remove_split_destinations_for_replace(destination, existing_volume_paths, replace_existing)
        .map_err(|source| ZipBackendError::Io { path: destination.to_path_buf(), source })
}

fn existing_split_zip_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, ZipBackendError> {
    let base = split_zip_base_path(destination)?;
    let Some(base_name) = base.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let directory = destination.parent().unwrap_or_else(|| Path::new("."));
    crate::archive_split::existing_volume_paths(directory, &mut |candidate_name| {
        parse_split_zip_sidecar_name(candidate_name).filter(|(candidate_base, _)| candidate_base.eq_ignore_ascii_case(base_name)).map(|(_, part)| part)
    })
    .map_err(|source| ZipBackendError::Io { path: directory.to_path_buf(), source })
}

fn parse_split_zip_sidecar_name(name: &str) -> Option<(&str, u32)> {
    let (base, extension) = name.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();
    let number = extension.strip_prefix('z')?;
    if number.len() < ZIP_SPLIT_SIDE_CAR_EXTENSION_WIDTH || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

struct ZipSplitVolumeWriter<'a> {
    paths: &'a [PathBuf],
    volume_size: u64,
    next_index: usize,
    current: Option<crate::atomic_file::AtomicOutputFile>,
    current_written: u64,
    completed: Vec<crate::atomic_file::AtomicOutputFile>,
}

impl<'a> ZipSplitVolumeWriter<'a> {
    fn new(paths: &'a [PathBuf], volume_size: u64) -> Result<Self, ZipBackendError> {
        let mut writer = Self { paths, volume_size, next_index: 0, current: None, current_written: 0, completed: Vec::with_capacity(paths.len()) };
        writer.start_next_volume()?;
        Ok(writer)
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), ZipBackendError> {
        while !bytes.is_empty() {
            if self.current_written == self.volume_size {
                self.finish_current_volume();
                self.start_next_volume()?;
            }
            let remaining = usize::try_from(self.volume_size - self.current_written).unwrap_or(usize::MAX);
            let to_write = remaining.min(bytes.len());
            let path = self.current_path().to_path_buf();
            let output = self
                .current
                .as_mut()
                .ok_or_else(|| unsupported_split_zip("missing ZIP volume output"))?
                .file_mut()
                .map_err(|source| ZipBackendError::Io { path: path.clone(), source })?;
            output.write_all(&bytes[..to_write]).map_err(|source| ZipBackendError::Io { path, source })?;
            self.current_written += u64::try_from(to_write).unwrap_or(0);
            bytes = &bytes[to_write..];
        }
        Ok(())
    }

    fn copy_from<R: Read>(&mut self, reader: &mut R, mut bytes_to_copy: u64, source_path: &Path) -> Result<(), ZipBackendError> {
        let mut buffer = vec![0; 64 * 1024];
        while bytes_to_copy > 0 {
            let chunk_len = usize::try_from(bytes_to_copy.min(buffer.len() as u64)).unwrap_or(buffer.len());
            reader.read_exact(&mut buffer[..chunk_len]).map_err(|source| ZipBackendError::Io { path: source_path.to_path_buf(), source })?;
            self.write_all(&buffer[..chunk_len])?;
            bytes_to_copy -= u64::try_from(chunk_len).unwrap_or(0);
        }
        Ok(())
    }

    fn finish(mut self, destination: &Path, existing_volume_paths: &[PathBuf], replace_existing: bool) -> Result<(), ZipBackendError> {
        self.finish_current_volume();
        if self.completed.len() != self.paths.len() {
            return Err(unsupported_split_zip("ZIP split writer did not fill all volumes"));
        }
        remove_split_destinations_for_replace(destination, existing_volume_paths, replace_existing)?;
        for (output, path) in self.completed.into_iter().zip(self.paths) {
            output.commit_with_file_replace(replace_existing).map_err(|source| ZipBackendError::Io { path: path.clone(), source })?;
        }
        Ok(())
    }

    fn start_next_volume(&mut self) -> Result<(), ZipBackendError> {
        let Some(path) = self.paths.get(self.next_index) else {
            return Err(unsupported_split_zip("ZIP split produced too many volumes"));
        };
        let output = crate::atomic_file::AtomicOutputFile::create(path).map_err(|source| ZipBackendError::Io { path: path.clone(), source })?;
        self.current = Some(output);
        self.current_written = 0;
        self.next_index += 1;
        Ok(())
    }

    fn finish_current_volume(&mut self) {
        if let Some(mut output) = self.current.take() {
            output.close();
            self.completed.push(output);
        }
    }

    fn current_path(&self) -> &Path {
        let current_index = self.next_index.saturating_sub(1);
        self.paths.get(current_index).map_or_else(|| Path::new("archive.zip"), PathBuf::as_path)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn unsupported_split_zip(reason: impl Into<String>) -> ZipBackendError {
    ZipBackendError::UnsupportedSplitZip { reason: reason.into() }
}

#[cfg(test)]
mod tests {
    use super::{MIN_ZIP_VOLUME_SIZE_BYTES, ZIP_SPLIT_SIGNATURE};
    use crate::safety::ExtractionPolicy;
    use crate::secrets::SecretString;
    use crate::test_support::TestDir;
    use crate::test_support::create_zip_fixture;
    use crate::zip_backend::{ZipBackendError, ZipCompression, ZipCreateOptions};
    use std::fs;

    #[test]
    fn split_zip_round_trips_through_native_engine() {
        let temp = TestDir::new("split_zip_round_trips_through_native_engine");
        let payload = deterministic_bytes(200_000);
        temp.write_file("project/blob.bin", &payload);
        let archive = temp.path("archive.zip");

        let report = create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions { compression: ZipCompression::Store, volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES), ..ZipCreateOptions::default() },
        )
        .unwrap();

        assert_eq!(report.volume_size, Some(MIN_ZIP_VOLUME_SIZE_BYTES));
        assert!(report.volume_count > 1);
        assert_eq!(fs::metadata(temp.path("archive.z01")).unwrap().len(), MIN_ZIP_VOLUME_SIZE_BYTES);
        assert_eq!(&fs::read(temp.path("archive.z01")).unwrap()[..ZIP_SPLIT_SIGNATURE.len()], ZIP_SPLIT_SIGNATURE.as_slice());
        assert!(archive.is_file());

        let native_listing = crate::zip_backend::list_zip(&archive).unwrap();
        assert!(native_listing.entries.iter().any(|entry| entry.name == "project/blob.bin"));
        crate::zip_backend::test_zip_with_password_filter(&archive, None, |_| true).unwrap();
        let native_out = temp.path("native-out");
        let token = crate::jobs::CancellationToken::new();
        let mut sink = |_event: crate::jobs::JobEvent| {};
        let mut context = crate::jobs::JobContext::new(&token, &mut sink);
        crate::zip_backend::extract_zip_with_context_and_password(&archive, &native_out, ExtractionPolicy::default(), None, &mut context).unwrap();
        assert_eq!(fs::read(native_out.join("project/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn split_zip_round_trip_keeps_entry_mtime() {
        let temp = TestDir::new("split_zip_keeps_mtime");
        temp.write_file("project/blob.bin", &deterministic_bytes(200_000));
        filetime::set_file_mtime(temp.path("project/blob.bin"), filetime::FileTime::from_unix_time(1_700_000_001, 0)).unwrap();
        let archive = temp.path("archive.zip");
        create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES),
                preserve_metadata: true,
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();
        assert!(temp.path("archive.z01").is_file());

        let listing = crate::zip_backend::list_zip(&archive).unwrap();
        let listed = listing.entries.iter().find(|entry| entry.name == "project/blob.bin").unwrap();
        assert_eq!(listed.modified.as_deref(), Some("1700000001"));

        let native_out = temp.path("native-out");
        let token = crate::jobs::CancellationToken::new();
        let mut sink = |_event: crate::jobs::JobEvent| {};
        let mut context = crate::jobs::JobContext::new(&token, &mut sink);
        crate::zip_backend::extract_zip_with_context_and_password(&archive, &native_out, ExtractionPolicy::default(), None, &mut context).unwrap();
        let extracted = filetime::FileTime::from_last_modification_time(&fs::metadata(native_out.join("project/blob.bin")).unwrap());
        assert_eq!(extracted.unix_seconds(), 1_700_000_001);
    }

    /// Split ZIP round-trip through the native reader across the compression range.
    ///
    #[test]
    fn split_zip_compression_range_round_trips_through_native_reader() {
        // Deflate levels below 1 are rejected by the zip crate.
        let cases = [
            ("store", ZipCompression::Store, None),
            ("deflate-1", ZipCompression::Deflate, Some(1)),
            ("deflate-3", ZipCompression::Deflate, Some(3)),
            ("deflate-6", ZipCompression::Deflate, Some(6)),
            ("deflate-9", ZipCompression::Deflate, Some(9)),
        ];
        for (name, compression, level) in cases {
            let temp = TestDir::new(&format!("split_zip_{name}"));
            let payload = deterministic_bytes(200_000);
            temp.write_file("project/blob.bin", &payload);
            let archive = temp.path("archive.zip");

            let report = create_zip_fixture(
                temp.path("project"),
                &archive,
                &ZipCreateOptions { compression, level, volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES), ..ZipCreateOptions::default() },
            )
            .unwrap_or_else(|error| panic!("{name}: split create failed: {error}"));
            assert!(report.volume_count > 1, "{name}: expected multiple volumes");

            let token = crate::jobs::CancellationToken::new();
            let mut sink = |_event: crate::jobs::JobEvent| {};
            let mut context = crate::jobs::JobContext::new(&token, &mut sink);
            let destination = temp.path("out");
            let report = crate::zip_backend::extract_zip_with_context_and_password(&archive, &destination, ExtractionPolicy::default(), None, &mut context)
                .unwrap_or_else(|error| panic!("{name}: native extract failed: {error}"));

            assert_eq!(report.written_bytes, payload.len() as u64, "{name}");
            assert_eq!(fs::read(destination.join("project/blob.bin")).unwrap(), payload, "{name}");
        }
    }

    #[test]
    fn passworded_split_zip_extracts_through_native_reader() {
        let temp = TestDir::new("passworded_split_zip_extracts_through_native_reader");
        let payload = deterministic_bytes(200_000);
        temp.write_file("project/blob.bin", &payload);
        let archive = temp.path("secret.zip");

        let report = create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                password: Some(SecretString::from("correct horse")),
                volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(report.volume_count > 1);

        let token = crate::jobs::CancellationToken::new();
        let mut sink = |_event: crate::jobs::JobEvent| {};
        let mut context = crate::jobs::JobContext::new(&token, &mut sink);
        crate::zip_backend::extract_zip_with_context_and_password(
            &archive,
            temp.path("native-out"),
            ExtractionPolicy::default(),
            Some("correct horse"),
            &mut context,
        )
        .unwrap();

        assert_eq!(fs::read(temp.path("native-out/project/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn split_zip_refuses_and_replaces_existing_sidecars() {
        let temp = TestDir::new("split_zip_refuses_and_replaces_existing_sidecars");
        temp.write_file("project/blob.bin", &deterministic_bytes(200_000));
        temp.write_file("archive.z01", b"stale");
        let archive = temp.path("archive.zip");

        let error = create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions { compression: ZipCompression::Store, volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES), ..ZipCreateOptions::default() },
        )
        .unwrap_err();

        assert!(matches!(error, ZipBackendError::Io { .. }));
        assert_eq!(fs::read(temp.path("archive.z01")).unwrap(), b"stale");

        temp.write_file("archive.z09", b"stale tail");
        create_zip_fixture(
            temp.path("project"),
            &archive,
            &ZipCreateOptions {
                compression: ZipCompression::Store,
                replace_existing: true,
                volume_size: Some(MIN_ZIP_VOLUME_SIZE_BYTES),
                ..ZipCreateOptions::default()
            },
        )
        .unwrap();

        assert!(temp.path("archive.z01").is_file());
        assert!(!temp.path("archive.z09").exists());
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        crate::test_support::deterministic_bytes(len)
    }
}
