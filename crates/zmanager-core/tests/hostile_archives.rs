mod common;

use common::TestDir;

use std::fs::{self, File};
use std::io::{Cursor, Seek, Write};
use std::path::{Path, PathBuf};

use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};
use zmanager_core::backend_test_support::sevenz_backend::extract_7z;
use zmanager_core::backend_test_support::zip_backend::{ZipBackendError, ZipExtractReport, extract_zip_with_context_and_password, list_zip};
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent};
use zmanager_core::safety::{ExtractionLimits, ExtractionPolicy, ExtractionSafetyError};

fn extract_zip_default(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy) -> Result<ZipExtractReport, ZipBackendError> {
    let token = CancellationToken::new();
    let mut sink = |_event: JobEvent| {};
    let mut context = JobContext::new(&token, &mut sink);
    extract_zip_with_context_and_password(archive_path, destination, policy, None, &mut context)
}

/// Extracts a `.tar.zst` hostile fixture through the engine seam.
fn extract_tar_zst_via_engine(archive: &Path, destination: &Path) -> Result<(), zmanager_core::engine::ArchiveError> {
    let mut handle = zmanager_core::engine::create_default_engine()
        .unwrap()
        .open(zmanager_core::engine::ArchiveSource::Path(archive.to_path_buf()), zmanager_core::engine::OpenOptions::default())
        .unwrap();
    let mut options = zmanager_core::engine::ExtractOptions { destination: destination.to_path_buf(), ..zmanager_core::engine::ExtractOptions::default() };
    handle.extract(&mut options).map(|_| ())
}

#[test]
fn zip_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("zip_hostile_fixtures_are_rejected");
    let cases = [
        ("traversal.zip", zip_file_case(temp.path("traversal.zip"), "../escape.txt", b"owned")),
        ("absolute.zip", zip_file_case(temp.path("absolute.zip"), "/tmp/zmanager-escape.txt", b"owned")),
        ("duplicate.zip", zip_two_file_case(temp.path("duplicate.zip"), "dup/./file.txt", "dup/file.txt")),
        ("case-collision.zip", zip_two_file_case(temp.path("case-collision.zip"), "Readme.txt", "README.txt")),
        ("symlink-escape.zip", zip_raw_symlink_case(temp.path("symlink-escape.zip"), "link.txt", "../outside.txt")),
    ];

    for (name, archive) in cases {
        let error = extract_zip_default(&archive, temp.path(format!("out-{name}")), ExtractionPolicy::default());
        assert!(error.is_err(), "{name} should be rejected");
    }

    assert!(!temp.path("escape.txt").exists());
}

#[test]
#[cfg(unix)]
fn symlink_chains_cannot_escape_fresh_extraction_roots() {
    use zmanager_core::engine::{ArchiveSource, ExtractOptions, OpenOptions, create_default_engine};

    let temp = TestDir::new("symlink-chain-escape");
    for reverse in [false, true] {
        let mut links = [("a", "."), ("b", "a/..")];
        if reverse {
            links.reverse();
        }
        for format in ["tar", "zip"] {
            let archive = temp.path(format!("chain-{reverse}.{format}"));
            if format == "tar" {
                raw_tar_case(
                    archive.clone(),
                    &[
                        RawTarEntry::symlink(links[0].0, links[0].1),
                        RawTarEntry::symlink(links[1].0, links[1].1),
                        RawTarEntry::file("b/escaped.txt", b"marker"),
                    ],
                );
            } else {
                let mut writer = ZipWriter::new(File::create(&archive).unwrap());
                for (name, target) in links {
                    writer.add_symlink(name, target, SimpleFileOptions::default()).unwrap();
                }
                writer.start_file("b/escaped.txt", SimpleFileOptions::default()).unwrap();
                writer.write_all(b"marker").unwrap();
                writer.finish().unwrap();
            }
            let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(archive), OpenOptions::default()).unwrap();
            let mut options = ExtractOptions { destination: temp.path(format!("out-{reverse}-{format}")), ..Default::default() };

            let result = handle.extract(&mut options);

            assert!(!temp.path("escaped.txt").exists(), "{format} wrote outside a fresh destination");
            assert!(result.is_err(), "{format} must reject traversal through a symlink");
        }
    }
}

#[test]
#[cfg(unix)]
fn extraction_refuses_preexisting_symlink_ancestors_even_with_replace() {
    use zmanager_core::engine::{ArchiveSource, ExtractOptions, OpenOptions, create_default_engine};
    use zmanager_core::safety::OverwritePolicy;

    let temp = TestDir::new("existing-symlink-ancestor");
    temp.create_dir("outside");
    let archive = zip_file_case(temp.path("payload.zip"), "redirect/escaped.txt", b"marker");
    for overwrite in [OverwritePolicy::Refuse, OverwritePolicy::Replace] {
        let destination = temp.path(format!("out-{overwrite:?}"));
        fs::create_dir(&destination).unwrap();
        std::os::unix::fs::symlink(temp.path("outside"), destination.join("redirect")).unwrap();
        let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(archive.clone()), OpenOptions::default()).unwrap();
        let mut options = ExtractOptions { destination, policy: ExtractionPolicy { overwrite, ..Default::default() }, ..Default::default() };

        assert!(handle.extract(&mut options).is_err());
        assert!(!temp.path("outside/escaped.txt").exists());
    }
}

#[test]
fn tar_zst_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("tar_zst_hostile_fixtures_are_rejected");
    let cases = [
        raw_tar_zst_case(temp.path("traversal.tar.zst"), &[RawTarEntry::file("../escape.txt", b"owned")]),
        raw_tar_zst_case(temp.path("absolute.tar.zst"), &[RawTarEntry::file("/tmp/zmanager-escape.txt", b"owned")]),
        raw_tar_zst_case(temp.path("symlink.tar.zst"), &[RawTarEntry::symlink("link.txt", "../outside.txt")]),
        raw_tar_zst_case(temp.path("hardlink.tar.zst"), &[RawTarEntry::hardlink("link.txt", "../outside.txt")]),
        raw_tar_zst_case(temp.path("case.tar.zst"), &[RawTarEntry::file("Readme.txt", b"one"), RawTarEntry::file("README.txt", b"two")]),
    ];

    for archive in cases {
        let error = extract_tar_zst_via_engine(&archive, &temp.path("out"));
        assert!(error.is_err(), "{} should be rejected", archive.display());
    }

    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn sevenz_hostile_fixture_is_rejected() {
    let temp = TestDir::new("sevenz_hostile_fixture_is_rejected");
    let archive = temp.path("traversal.7z");
    let output = File::create(&archive).unwrap();
    let mut writer = ArchiveWriter::new(output).unwrap();
    writer.push_archive_entry(ArchiveEntry::new_file("../escape.txt"), Some(&b"owned"[..])).unwrap();
    writer.finish().unwrap();

    let error = extract_7z(&archive, temp.path("out"), None, ExtractionPolicy::default());

    assert!(error.is_err());
    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn lzma_high_memory_exhaustion_is_rejected() {
    let temp = TestDir::new("lzma_high_memory_exhaustion_is_rejected");
    let archive = temp.path("hostile.7z");
    let output = File::create(&archive).unwrap();
    let mut writer = ArchiveWriter::new(output).unwrap();
    let payload = vec![0_u8; 10 * 1024]; // 10KB payload
    writer.push_archive_entry(ArchiveEntry::new_file("bomb.bin"), Some(&payload[..])).unwrap();
    writer.finish().unwrap();

    let policy = ExtractionPolicy {
        limits: ExtractionLimits { max_expanded_bytes: Some(10), max_entry_expansion_ratio: None, max_entries: None },
        ..ExtractionPolicy::default()
    };

    let error = extract_7z(&archive, temp.path("out"), None, policy).unwrap_err();

    assert!(matches!(error, zmanager_core::backend_test_support::sevenz_backend::SevenZError::Safety(ExtractionSafetyError::ExpandedSizeLimitExceeded { .. })));
    assert!(!temp.path("out/bomb.bin").exists());
}

#[test]
fn native_tar_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("native_tar_hostile_fixtures_are_rejected");
    let cases = [
        raw_tar_case(temp.path("traversal.tar"), &[RawTarEntry::file("../escape.txt", b"owned")]),
        raw_tar_case(temp.path("absolute.tar"), &[RawTarEntry::file("/tmp/zmanager-escape.txt", b"owned")]),
        raw_tar_case(temp.path("symlink.tar"), &[RawTarEntry::symlink("link.txt", "../outside.txt")]),
        raw_tar_case(temp.path("hardlink.tar"), &[RawTarEntry::hardlink("link.txt", "../outside.txt")]),
        raw_tar_case(temp.path("case.tar"), &[RawTarEntry::file("Readme.txt", b"one"), RawTarEntry::file("README.txt", b"two")]),
    ];

    for archive in cases {
        let engine = zmanager_core::engine::create_default_engine().unwrap();
        let source = zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive);
        let mut handle = engine.open(source, zmanager_core::engine::OpenOptions::default()).unwrap();
        let mut options = zmanager_core::engine::ExtractOptions { destination: temp.path("out"), policy: ExtractionPolicy::default(), ..Default::default() };
        let error = handle.extract(&mut options);
        assert!(error.is_err(), "{} should be rejected", archive.display());
    }

    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn squashfs_hostile_fixtures_are_rejected() {
    use backhand::compression::Compressor as CompressorId;
    use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};

    let temp = TestDir::new("squashfs_hostile");
    let mut writer = FilesystemWriter::default();
    writer.set_compressor(FilesystemCompressor::new(CompressorId::Gzip, None).unwrap());
    writer.push_symlink("../escape.txt", "sym_escape", NodeHeader::new(0o777, 0, 0, 0)).unwrap();
    let mut out_bytes = std::io::Cursor::new(Vec::new());
    writer.write(&mut out_bytes).unwrap();

    let archive = temp.path("traversal.squashfs");
    fs::write(&archive, out_bytes.into_inner()).unwrap();

    let engine = zmanager_core::engine::create_default_engine().unwrap();
    let source = zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive);
    let mut handle = engine.open(source, zmanager_core::engine::OpenOptions::default()).unwrap();
    let mut options = zmanager_core::engine::ExtractOptions { destination: temp.path("out"), policy: ExtractionPolicy::default(), ..Default::default() };
    let error = handle.extract(&mut options);
    assert!(error.is_err(), "traversal in squashfs must be rejected");
    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn wim_hostile_size_and_limits_are_enforced() {
    let temp = TestDir::new("wim_limits");
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.wim");
    if !archive.exists() {
        return;
    }

    let policy = ExtractionPolicy {
        limits: ExtractionLimits { max_expanded_bytes: Some(5), max_entry_expansion_ratio: None, max_entries: None },
        ..ExtractionPolicy::default()
    };

    let engine = zmanager_core::engine::create_default_engine().unwrap();
    let source = zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive);
    let mut handle = engine.open(source, zmanager_core::engine::OpenOptions::default()).unwrap();
    let mut options = zmanager_core::engine::ExtractOptions { destination: temp.path("out"), policy, ..Default::default() };
    let error = handle.extract(&mut options);
    assert!(error.is_err(), "exceeding max_expanded_bytes in WIM must be rejected");
}

#[test]
fn truncated_and_corrupt_archives_fail_closed() {
    let temp = TestDir::new("truncated_and_corrupt_archives_fail_closed");
    let zip = zip_file_case(temp.path("valid.zip"), "payload/file.txt", b"hello");
    let truncated_zip = temp.path("truncated.zip");
    let bytes = fs::read(zip).unwrap();
    fs::write(&truncated_zip, &bytes[..bytes.len() / 2]).unwrap();

    fs::write(temp.path("corrupt.tar.zst"), b"not a zstd tar").unwrap();
    fs::write(temp.path("corrupt.7z"), b"not a 7z archive").unwrap();
    fs::write(temp.path("corrupt.tar"), b"not a tar archive").unwrap();

    assert!(extract_zip_default(&truncated_zip, temp.path("zip-out"), ExtractionPolicy::default()).is_err());
    assert!(extract_tar_zst_via_engine(&temp.path("corrupt.tar.zst"), &temp.path("tar-zst-out")).is_err());
    assert!(extract_7z(temp.path("corrupt.7z"), temp.path("seven-out"), None, ExtractionPolicy::default()).is_err());
    let engine = zmanager_core::engine::create_default_engine().unwrap();
    let mut handle = engine
        .open(zmanager_core::engine::ArchiveSource::from_path_autodetect(temp.path("corrupt.tar")), zmanager_core::engine::OpenOptions::default())
        .unwrap();
    let mut options = zmanager_core::engine::ExtractOptions { destination: temp.path("tar-out"), policy: ExtractionPolicy::default(), ..Default::default() };
    assert!(handle.extract(&mut options).is_err());
}

#[test]
fn zip_bomb_and_nested_archive_fixtures_are_listed_without_extraction() {
    let temp = TestDir::new("zip_bomb_and_nested_archive_fixtures_are_listed_without_extraction");
    let archive = temp.path("hostile.zip");
    let inner_zip = nested_zip_bytes();
    let repeated = vec![0_u8; 2 * 1024 * 1024];
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer.start_file("bomb.bin", SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)).unwrap();
    writer.write_all(&repeated).unwrap();
    writer.start_file("nested/inner.zip", SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
    writer.write_all(&inner_zip).unwrap();
    writer.finish().unwrap();

    let listing = list_zip(&archive).unwrap();
    let bomb = listing.entries.iter().find(|entry| entry.name == "bomb.bin").unwrap();

    assert!(bomb.size >= u64::try_from(repeated.len()).unwrap());
    assert!(bomb.compressed_size < bomb.size / 10);
    assert!(listing.entries.iter().any(|entry| entry.name == "nested/inner.zip"));
}

#[test]
fn zip_extraction_rejects_entries_above_expansion_ratio_limit() {
    let temp = TestDir::new("zip_extraction_rejects_entries_above_expansion_ratio_limit");
    let archive = temp.path("hostile.zip");
    let repeated = vec![0_u8; 2 * 1024 * 1024];
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer.start_file("bomb.bin", SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)).unwrap();
    writer.write_all(&repeated).unwrap();
    writer.finish().unwrap();
    let policy = ExtractionPolicy {
        limits: ExtractionLimits { max_expanded_bytes: None, max_entry_expansion_ratio: Some(10), max_entries: None },
        ..ExtractionPolicy::default()
    };

    let error = extract_zip_default(&archive, temp.path("out"), policy).unwrap_err();

    assert!(matches!(error, ZipBackendError::Safety(ExtractionSafetyError::ExpansionRatioLimitExceeded { .. })));
    assert!(!temp.path("out/bomb.bin").exists());
}

#[test]
fn batch_selected_extraction_enforces_aggregate_expansion_limit() {
    let temp = TestDir::new("batch_selected_extraction_enforces_aggregate_expansion_limit");
    let archive = temp.path("multi.zip");
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    for name in ["file1.txt", "file2.txt", "file3.txt", "file4.txt"] {
        writer.start_file(name, SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
        writer.write_all(&[0x42_u8; 100]).unwrap();
    }
    writer.finish().unwrap();

    let mut handle = zmanager_core::engine::create_default_engine()
        .unwrap()
        .open(zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive), zmanager_core::engine::OpenOptions::default())
        .unwrap();

    // 4 files x 100 bytes = 400 bytes. Cap at 250 bytes.
    let options = zmanager_core::archive_browser::BrowserExtractOptions {
        limits: Some(ExtractionLimits { max_expanded_bytes: Some(250), ..ExtractionLimits::default() }),
        ..zmanager_core::archive_browser::BrowserExtractOptions::default()
    };
    let entry_paths = vec!["file1.txt".to_string(), "file2.txt".to_string(), "file3.txt".to_string(), "file4.txt".to_string()];

    let error = zmanager_core::archive_browser::extract_selected_entries_from_engine_handle(&mut handle, &entry_paths, temp.path("out"), options).unwrap_err();

    assert!(matches!(
        error,
        zmanager_core::archive_browser::ArchiveBrowserError::Safety(ExtractionSafetyError::ExpandedSizeLimitExceeded { limit_bytes: 250, .. })
    ));
}

fn zip_file_case(archive: PathBuf, entry_path: &str, contents: &[u8]) -> PathBuf {
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer.start_file(entry_path, SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap();
    archive
}

fn zip_two_file_case(archive: PathBuf, first: &str, second: &str) -> PathBuf {
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    for entry in [first, second] {
        writer.start_file(entry, SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
        writer.write_all(b"duplicate").unwrap();
    }
    writer.finish().unwrap();
    archive
}

fn zip_raw_symlink_case(archive: PathBuf, entry_path: &str, target: &str) -> PathBuf {
    let mut file = File::create(&archive).unwrap();
    let name = entry_path.as_bytes();
    let contents = target.as_bytes();
    let crc = crc32(contents);
    let size = u32::try_from(contents.len()).unwrap();

    write_zip_local_file(&mut file, name, contents, crc, size);
    let central_directory_offset = u32::try_from(file.stream_position().unwrap()).unwrap();
    write_zip_central_file(&mut file, name, crc, size, 0, 0o120_777 << 16);
    let central_directory_size = u32::try_from(file.stream_position().unwrap()).unwrap() - central_directory_offset;
    write_zip_end_of_central_directory(&mut file, 1, central_directory_size, central_directory_offset);
    archive
}

fn write_zip_local_file(file: &mut File, name: &[u8], contents: &[u8], crc: u32, size: u32) {
    write_le_u32(file, 0x0403_4b50);
    write_le_u16(file, 20);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u32(file, crc);
    write_le_u32(file, size);
    write_le_u32(file, size);
    write_le_u16(file, u16::try_from(name.len()).unwrap());
    write_le_u16(file, 0);
    file.write_all(name).unwrap();
    file.write_all(contents).unwrap();
}

fn write_zip_central_file(file: &mut File, name: &[u8], crc: u32, size: u32, local_header_offset: u32, external_attributes: u32) {
    write_le_u32(file, 0x0201_4b50);
    write_le_u16(file, 0x031E);
    write_le_u16(file, 20);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u32(file, crc);
    write_le_u32(file, size);
    write_le_u32(file, size);
    write_le_u16(file, u16::try_from(name.len()).unwrap());
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u32(file, external_attributes);
    write_le_u32(file, local_header_offset);
    file.write_all(name).unwrap();
}

fn write_zip_end_of_central_directory(file: &mut File, entry_count: u16, central_directory_size: u32, central_directory_offset: u32) {
    write_le_u32(file, 0x0605_4b50);
    write_le_u16(file, 0);
    write_le_u16(file, 0);
    write_le_u16(file, entry_count);
    write_le_u16(file, entry_count);
    write_le_u32(file, central_directory_size);
    write_le_u32(file, central_directory_offset);
    write_le_u16(file, 0);
}

fn write_le_u16(file: &mut File, value: u16) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

fn write_le_u32(file: &mut File, value: u32) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn nested_zip_bytes() -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    writer.start_file("inner.txt", SimpleFileOptions::default()).unwrap();
    writer.write_all(b"nested").unwrap();
    writer.finish().unwrap().into_inner()
}

fn raw_tar_case(path: PathBuf, entries: &[RawTarEntry<'_>]) -> PathBuf {
    let mut file = File::create(&path).unwrap();
    write_raw_tar(&mut file, entries);
    path
}

fn raw_tar_zst_case(path: PathBuf, entries: &[RawTarEntry<'_>]) -> PathBuf {
    let file = File::create(&path).unwrap();
    let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
    write_raw_tar(&mut encoder, entries);
    encoder.finish().unwrap();
    path
}

fn write_raw_tar(writer: &mut dyn Write, entries: &[RawTarEntry<'_>]) {
    for entry in entries {
        let header = raw_tar_header(entry);
        writer.write_all(&header).unwrap();
        if let RawTarEntryKind::File(contents) = entry.kind {
            writer.write_all(contents).unwrap();
            let padding_len = (512 - (contents.len() % 512)) % 512;
            writer.write_all(&vec![0; padding_len]).unwrap();
        }
    }
    writer.write_all(&[0; 1024]).unwrap();
}

fn raw_tar_header(entry: &RawTarEntry<'_>) -> [u8; 512] {
    let mut header = [0_u8; 512];
    let (entry_type, size, link_name) = match entry.kind {
        RawTarEntryKind::File(contents) => (b'0', u64::try_from(contents.len()).unwrap(), None),
        RawTarEntryKind::Symlink(target) => (b'2', 0, Some(target)),
        RawTarEntryKind::Hardlink(target) => (b'1', 0, Some(target)),
    };

    write_bytes(&mut header[0..100], entry.path.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = entry_type;
    if let Some(link_name) = link_name {
        write_bytes(&mut header[157..257], link_name.as_bytes());
    }
    write_bytes(&mut header[257..263], b"ustar\0");
    write_bytes(&mut header[263..265], b"00");

    let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    write_checksum(&mut header[148..156], checksum);

    header
}

fn write_bytes(destination: &mut [u8], source: &[u8]) {
    let len = destination.len().min(source.len());
    destination[..len].copy_from_slice(&source[..len]);
}

fn write_octal(destination: &mut [u8], value: u64) {
    let encoded = format!("{value:0width$o}\0", width = destination.len() - 1);
    write_bytes(destination, encoded.as_bytes());
}

fn write_checksum(destination: &mut [u8], value: u32) {
    let encoded = format!("{value:06o}\0 ");
    write_bytes(destination, encoded.as_bytes());
}

struct RawTarEntry<'a> {
    path: &'a str,
    kind: RawTarEntryKind<'a>,
}

impl<'a> RawTarEntry<'a> {
    fn file(path: &'a str, contents: &'a [u8]) -> Self {
        Self { path, kind: RawTarEntryKind::File(contents) }
    }

    fn symlink(path: &'a str, target: &'a str) -> Self {
        Self { path, kind: RawTarEntryKind::Symlink(target) }
    }

    fn hardlink(path: &'a str, target: &'a str) -> Self {
        Self { path, kind: RawTarEntryKind::Hardlink(target) }
    }
}

#[derive(Clone, Copy)]
enum RawTarEntryKind<'a> {
    File(&'a [u8]),
    Symlink(&'a str),
    Hardlink(&'a str),
}
