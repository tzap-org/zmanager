//! End-to-end portable metadata coverage for the manager extraction surface.

mod common;

use common::TestDir;
use filetime::FileTime;
use std::fs;
use std::path::{Path, PathBuf};

use zmanager_core::archive_browser::{BrowserExtractOptions, extract_entry_with_options};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use zmanager_core::backend_test_support::apple_archive_backend::{AppleArchiveCompression, AppleArchiveCreateOptions, create_apple_archive_from_path};
use zmanager_core::backend_test_support::sevenz_backend::{SevenZCreateOptions, create_7z_from_path};
use zmanager_core::backend_test_support::tar_gz_backend::{TarGzCreateOptions, create_tar_gz_from_path};
use zmanager_core::backend_test_support::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_path};
use zmanager_core::backend_test_support::tzap::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};
use zmanager_core::backend_test_support::zip_backend::{ZipCompression, ZipCreateOptions, create_zip_from_manifest};
use zmanager_core::jobs::{CancellationToken, JobContext};
use zmanager_core::manifest::{PlanOptions, plan_archive};
use zmanager_core::safety::OverwritePolicy;

const SPLIT_ZIP_VOLUME_SIZE_BYTES: u64 = 65_536;

struct MetadataFixture {
    temp: TestDir,
    source: PathBuf,
    file: PathBuf,
    file_mtime: FileTime,
    directory_mtime: FileTime,
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(mode & 0o222 == 0);
        fs::set_permissions(path, permissions).unwrap();
    }
}

#[cfg(unix)]
fn observed_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn observed_mtime(path: &Path) -> FileTime {
    FileTime::from_last_modification_time(&fs::metadata(path).unwrap())
}

fn metadata_fixture() -> MetadataFixture {
    let temp = TestDir::new("metadata_round_trip");
    let source = temp.path("src");
    let directory = source.join("folder");
    let file = source.join("data.bin");

    fs::create_dir_all(&directory).unwrap();
    fs::write(&file, b"metadata payload\n").unwrap();
    fs::write(directory.join("child.txt"), b"child payload\n").unwrap();

    let file_mtime = FileTime::from_unix_time(1_500_000_000, 0);
    let directory_mtime = FileTime::from_unix_time(1_500_000_100, 0);
    filetime::set_file_mtime(&file, file_mtime).unwrap();
    set_mode(&file, 0o444);
    filetime::set_file_mtime(&directory, directory_mtime).unwrap();
    set_mode(&directory, 0o755);

    MetadataFixture { temp, source, file, file_mtime, directory_mtime }
}

fn assert_metadata_round_trip(fixture: &mut MetadataFixture, archive: &Path) {
    let output = fixture.temp.path("out");
    let options = BrowserExtractOptions { overwrite: OverwritePolicy::Replace, ..Default::default() };

    let first = extract_entry_with_options(archive, "src", &output, options).unwrap();
    assert!(first.written_bytes > 0);
    assert_eq!(fs::read(output.join("src/data.bin")).unwrap(), b"metadata payload\n");
    assert_eq!(observed_mtime(&output.join("src/data.bin")), fixture.file_mtime, "file mtime");
    assert_eq!(observed_mtime(&output.join("src/folder")), fixture.directory_mtime, "directory mtime");

    #[cfg(unix)]
    {
        assert_eq!(observed_mode(&output.join("src/data.bin")), 0o444, "file mode");
        assert_eq!(observed_mode(&output.join("src/folder")), 0o755, "directory mode");
    }
    #[cfg(not(unix))]
    {
        assert!(fs::metadata(output.join("src/data.bin")).unwrap().permissions().readonly(), "read-only mode projection");
        assert!(!fs::metadata(output.join("src/folder")).unwrap().permissions().readonly(), "writable directory mode projection");
    }

    // The second pass covers replacement of a destination whose archived mode
    // made the first pass read-only on Windows.
    let second = extract_entry_with_options(archive, "src", &output, options).unwrap();
    assert!(second.written_bytes > 0);
    assert_eq!(observed_mtime(&output.join("src/data.bin")), fixture.file_mtime, "overwritten file mtime");
    assert_eq!(observed_mtime(&output.join("src/folder")), fixture.directory_mtime, "overwritten directory mtime");

    // Keep the temporary test tree removable on Windows after asserting the
    // archived read-only projection.
    set_mode(&fixture.file, 0o644);
    set_mode(&output.join("src/data.bin"), 0o644);
}

#[test]
fn tar_zst_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.tzst");
    create_tar_zst_from_path(&fixture.source, &archive, &TarZstdCreateOptions::default()).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[test]
fn zip_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.zip");
    let manifest = plan_archive(&fixture.source, &PlanOptions::default()).unwrap();
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default()).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[test]
fn split_zip_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    // Make the archive larger than the minimum ZIP volume size while keeping
    // the metadata assertions focused on the same small file and directory.
    let large_payload = vec![0_u8; 131_072];
    fs::write(fixture.source.join("large.bin"), large_payload).unwrap();

    let archive = fixture.temp.path("metadata.zip");
    let manifest = plan_archive(&fixture.source, &PlanOptions::default()).unwrap();
    let options = ZipCreateOptions { compression: ZipCompression::Store, volume_size: Some(SPLIT_ZIP_VOLUME_SIZE_BYTES), ..Default::default() };
    let report = create_zip_from_manifest(&manifest, &archive, &options).unwrap();
    assert!(report.volume_count > 1, "fixture should exercise split ZIP extraction");
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[test]
fn tar_gz_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.tgz");
    create_tar_gz_from_path(&fixture.source, &archive, &TarGzCreateOptions::default()).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[test]
fn sevenz_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.7z");
    let options = SevenZCreateOptions { encrypt_file_names: false, ..Default::default() };
    create_7z_from_path(&fixture.source, &archive, &options).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[test]
fn tzap_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.tzap");
    let manifest = plan_archive(&fixture.source, &PlanOptions::default()).unwrap();
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn apple_archive_manager_round_trip_restores_portable_metadata() {
    let mut fixture = metadata_fixture();
    let archive = fixture.temp.path("metadata.aar");
    let options = AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, ..Default::default() };
    create_apple_archive_from_path(&fixture.source, &archive, &options).unwrap();
    assert_metadata_round_trip(&mut fixture, &archive);
}
