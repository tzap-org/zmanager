use std::fs::{self, File};
use std::io::{Cursor, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};
use zmanager_core::libarchive_backend::extract_archive;
use zmanager_core::safety::{ExtractionLimits, ExtractionPolicy, ExtractionSafetyError};
use zmanager_core::sevenz_backend::extract_7z;
use zmanager_core::tar_zst_backend::extract_tar_zst;
use zmanager_core::zip_backend::{ZipBackendError, extract_zip, list_zip};

#[test]
fn zip_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("zip_hostile_fixtures_are_rejected");
    let cases = [
        (
            "traversal.zip",
            zip_file_case(temp.path("traversal.zip"), "../escape.txt", b"owned"),
        ),
        (
            "absolute.zip",
            zip_file_case(
                temp.path("absolute.zip"),
                "/tmp/zmanager-escape.txt",
                b"owned",
            ),
        ),
        (
            "duplicate.zip",
            zip_two_file_case(temp.path("duplicate.zip"), "dup/./file.txt", "dup/file.txt"),
        ),
        (
            "case-collision.zip",
            zip_two_file_case(temp.path("case-collision.zip"), "Readme.txt", "README.txt"),
        ),
        (
            "symlink-escape.zip",
            zip_raw_symlink_case(
                temp.path("symlink-escape.zip"),
                "link.txt",
                "../outside.txt",
            ),
        ),
    ];

    for (name, archive) in cases {
        let error = extract_zip(
            &archive,
            temp.path(format!("out-{name}")),
            ExtractionPolicy::default(),
        );
        assert!(error.is_err(), "{name} should be rejected");
    }

    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn tar_zst_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("tar_zst_hostile_fixtures_are_rejected");
    let cases = [
        raw_tar_zst_case(
            temp.path("traversal.tar.zst"),
            &[RawTarEntry::file("../escape.txt", b"owned")],
        ),
        raw_tar_zst_case(
            temp.path("absolute.tar.zst"),
            &[RawTarEntry::file("/tmp/zmanager-escape.txt", b"owned")],
        ),
        raw_tar_zst_case(
            temp.path("symlink.tar.zst"),
            &[RawTarEntry::symlink("link.txt", "../outside.txt")],
        ),
        raw_tar_zst_case(
            temp.path("hardlink.tar.zst"),
            &[RawTarEntry::hardlink("link.txt", "../outside.txt")],
        ),
        raw_tar_zst_case(
            temp.path("case.tar.zst"),
            &[
                RawTarEntry::file("Readme.txt", b"one"),
                RawTarEntry::file("README.txt", b"two"),
            ],
        ),
    ];

    for archive in cases {
        let error = extract_tar_zst(&archive, temp.path("out"), ExtractionPolicy::default());
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
    writer
        .push_archive_entry(ArchiveEntry::new_file("../escape.txt"), Some(&b"owned"[..]))
        .unwrap();
    writer.finish().unwrap();

    let error = extract_7z(
        &archive,
        temp.path("out"),
        None,
        ExtractionPolicy::default(),
    );

    assert!(error.is_err());
    assert!(!temp.path("escape.txt").exists());
}

#[test]
fn libarchive_tar_hostile_fixtures_are_rejected() {
    let temp = TestDir::new("libarchive_tar_hostile_fixtures_are_rejected");
    let cases = [
        raw_tar_case(
            temp.path("traversal.tar"),
            &[RawTarEntry::file("../escape.txt", b"owned")],
        ),
        raw_tar_case(
            temp.path("absolute.tar"),
            &[RawTarEntry::file("/tmp/zmanager-escape.txt", b"owned")],
        ),
        raw_tar_case(
            temp.path("symlink.tar"),
            &[RawTarEntry::symlink("link.txt", "../outside.txt")],
        ),
        raw_tar_case(
            temp.path("hardlink.tar"),
            &[RawTarEntry::hardlink("link.txt", "../outside.txt")],
        ),
        raw_tar_case(
            temp.path("case.tar"),
            &[
                RawTarEntry::file("Readme.txt", b"one"),
                RawTarEntry::file("README.txt", b"two"),
            ],
        ),
    ];

    for archive in cases {
        let error = extract_archive(&archive, temp.path("out"), ExtractionPolicy::default());
        assert!(error.is_err(), "{} should be rejected", archive.display());
    }

    assert!(!temp.path("escape.txt").exists());
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

    assert!(
        extract_zip(
            &truncated_zip,
            temp.path("zip-out"),
            ExtractionPolicy::default()
        )
        .is_err()
    );
    assert!(
        extract_tar_zst(
            temp.path("corrupt.tar.zst"),
            temp.path("tar-zst-out"),
            ExtractionPolicy::default()
        )
        .is_err()
    );
    assert!(
        extract_7z(
            temp.path("corrupt.7z"),
            temp.path("seven-out"),
            None,
            ExtractionPolicy::default()
        )
        .is_err()
    );
    assert!(
        extract_archive(
            temp.path("corrupt.tar"),
            temp.path("tar-out"),
            ExtractionPolicy::default()
        )
        .is_err()
    );
}

#[test]
fn zip_bomb_and_nested_archive_fixtures_are_listed_without_extraction() {
    let temp = TestDir::new("zip_bomb_and_nested_archive_fixtures_are_listed_without_extraction");
    let archive = temp.path("hostile.zip");
    let inner_zip = nested_zip_bytes();
    let repeated = vec![0_u8; 2 * 1024 * 1024];
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file(
            "bomb.bin",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&repeated).unwrap();
    writer
        .start_file(
            "nested/inner.zip",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(&inner_zip).unwrap();
    writer.finish().unwrap();

    let listing = list_zip(&archive).unwrap();
    let bomb = listing
        .entries
        .iter()
        .find(|entry| entry.name == "bomb.bin")
        .unwrap();

    assert!(bomb.size >= u64::try_from(repeated.len()).unwrap());
    assert!(bomb.compressed_size < bomb.size / 10);
    assert!(
        listing
            .entries
            .iter()
            .any(|entry| entry.name == "nested/inner.zip")
    );
}

#[test]
fn zip_extraction_rejects_entries_above_expansion_ratio_limit() {
    let temp = TestDir::new("zip_extraction_rejects_entries_above_expansion_ratio_limit");
    let archive = temp.path("hostile.zip");
    let repeated = vec![0_u8; 2 * 1024 * 1024];
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file(
            "bomb.bin",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&repeated).unwrap();
    writer.finish().unwrap();
    let policy = ExtractionPolicy {
        limits: ExtractionLimits {
            max_expanded_bytes: None,
            max_entry_expansion_ratio: Some(10),
        },
        ..ExtractionPolicy::default()
    };

    let error = extract_zip(&archive, temp.path("out"), policy).unwrap_err();

    assert!(matches!(
        error,
        ZipBackendError::Safety(ExtractionSafetyError::ExpansionRatioLimitExceeded { .. })
    ));
    assert!(!temp.path("out/bomb.bin").exists());
}

fn zip_file_case(archive: PathBuf, entry_path: &str, contents: &[u8]) -> PathBuf {
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    writer
        .start_file(
            entry_path,
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap();
    archive
}

fn zip_two_file_case(archive: PathBuf, first: &str, second: &str) -> PathBuf {
    let file = File::create(&archive).unwrap();
    let mut writer = ZipWriter::new(file);
    for entry in [first, second] {
        writer
            .start_file(
                entry,
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
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
    let central_directory_size =
        u32::try_from(file.stream_position().unwrap()).unwrap() - central_directory_offset;
    write_zip_end_of_central_directory(
        &mut file,
        1,
        central_directory_size,
        central_directory_offset,
    );
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

fn write_zip_central_file(
    file: &mut File,
    name: &[u8],
    crc: u32,
    size: u32,
    local_header_offset: u32,
    external_attributes: u32,
) {
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

fn write_zip_end_of_central_directory(
    file: &mut File,
    entry_count: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
) {
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
    writer
        .start_file("inner.txt", SimpleFileOptions::default())
        .unwrap();
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
        Self {
            path,
            kind: RawTarEntryKind::File(contents),
        }
    }

    fn symlink(path: &'a str, target: &'a str) -> Self {
        Self {
            path,
            kind: RawTarEntryKind::Symlink(target),
        }
    }

    fn hardlink(path: &'a str, target: &'a str) -> Self {
        Self {
            path,
            kind: RawTarEntryKind::Hardlink(target),
        }
    }
}

#[derive(Clone, Copy)]
enum RawTarEntryKind<'a> {
    File(&'a [u8]),
    Symlink(&'a str),
    Hardlink(&'a str),
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
