//! Core archive engine adapter conformance test suite (ARC-109, ARC-110).

mod common;

use common::TestDir;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::engine::{
    AdapterDescriptor, ArchiveEngineBuilder, ArchiveError, ArchiveListing, ArchiveOperation, ArchivePlugin, ArchivePluginRole, ArchiveSource, CreateOptions,
    CreateRequest, CredentialRequirement, EngineEntry, ExtractOptions, FormatId, NavigationMode, OpenLimits, OpenOptions, ReadAdapterFactory,
    ReadAdapterSession, SelectedExtractOptions, SevenZCreateOptions, SourceAccess, TarGzCreateOptions, TarZstdCreateOptions, TzapCreateOptions, TzapKeySource,
    ZipCreateOptions, create_default_engine, is_split_zip_archive_path,
};

struct NoopSink;

impl zmanager_core::jobs::JobEventSink for NoopSink {
    fn emit(&mut self, _event: zmanager_core::jobs::JobEvent) {}
}

#[test]
#[allow(clippy::too_many_lines)]
fn default_engine_registers_every_phase_two_native_listing_adapter() {
    let engine = create_default_engine().unwrap();
    let expected = [
        (FormatId::SEVEN_Z, SourceAccess::Seekable),
        (FormatId::TAR_ZST, SourceAccess::Seekable),
        (FormatId::TZAP, SourceAccess::Seekable),
        (FormatId::RAR, SourceAccess::Seekable),
        (FormatId::RAW_STREAM, SourceAccess::Seekable),
        (FormatId::APPLE_ARCHIVE, SourceAccess::Seekable),
        (FormatId::DMG, SourceAccess::Seekable),
        (FormatId::PKG, SourceAccess::Seekable),
        (FormatId::MSI, SourceAccess::Seekable),
        (FormatId::VHD, SourceAccess::Seekable),
        (FormatId::VMDK, SourceAccess::Seekable),
        (FormatId::UDF, SourceAccess::Seekable),
        (FormatId::ISO, SourceAccess::Seekable),
        (FormatId::TAR_LZ, SourceAccess::Seekable),
        (FormatId::TAR_LZO, SourceAccess::Seekable),
        (FormatId::TAR_COMPRESS, SourceAccess::Seekable),
        (FormatId::TAR_LZ4, SourceAccess::Seekable),
        (FormatId::TAR_UU, SourceAccess::Seekable),
        (FormatId::LHA, SourceAccess::Seekable),
        (FormatId::WARC, SourceAccess::Seekable),
        (FormatId::SQUASHFS, SourceAccess::Seekable),
        (FormatId::APPIMAGE, SourceAccess::Seekable),
        (FormatId::WIM, SourceAccess::Seekable),
        (FormatId::VDI, SourceAccess::Seekable),
        (FormatId::NRG, SourceAccess::Seekable),
        (FormatId::MDF, SourceAccess::Seekable),
        (FormatId::CDI, SourceAccess::Seekable),
        (FormatId::ISZ, SourceAccess::Seekable),
        (FormatId::CCD, SourceAccess::Seekable),
        (FormatId::CUE, SourceAccess::Seekable),
        (FormatId::VHDX, SourceAccess::Seekable),
        (FormatId::QCOW2, SourceAccess::Seekable),
        (FormatId::EWF, SourceAccess::Seekable),
        (FormatId::AD1, SourceAccess::Seekable),
        (FormatId::DAR, SourceAccess::Seekable),
        (FormatId::AFF4, SourceAccess::Seekable),
        (FormatId::RAW_DISK, SourceAccess::Seekable),
        (FormatId::AR, SourceAccess::Seekable),
        (FormatId::CPIO, SourceAccess::Seekable),
        (FormatId::DEB, SourceAccess::Seekable),
        (FormatId::RPM, SourceAccess::Seekable),
        (FormatId::CAB, SourceAccess::Seekable),
        (FormatId::XAR, SourceAccess::Seekable),
    ];

    for (format, source_access) in expected {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::List), "{format} must claim listing");
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
        assert_eq!(capabilities.source_access, source_access, "{format} advertised the wrong source access");
    }

    // Formats removed from the supported list are absent from the registry:
    // detection reports them as unknown and the engine rejects them with the
    // explicit unrecognized-format error instead of probing.
    for format in ["tar.lrz", "tar.grz"] {
        assert!(engine.registry().capabilities_for_format(FormatId(format)).is_none(), "{format} must not be registered");
    }
    #[cfg(unix)]
    {
        let mtree = engine.registry().capabilities_for_format(FormatId::MTREE).expect("missing MTREE capabilities");
        assert!(mtree.operations.contains(&ArchiveOperation::List));
        assert!(mtree.operations.contains(&ArchiveOperation::Test));
        assert!(mtree.operations.contains(&ArchiveOperation::Extract));
    }
    for format in [
        FormatId::ZIP,
        FormatId::SPLIT_ZIP,
        FormatId::SEVEN_Z,
        FormatId::TAR_ZST,
        FormatId::TZAP,
        FormatId::RAR,
        FormatId::RAW_STREAM,
        FormatId::APPLE_ARCHIVE,
        FormatId::SQUASHFS,
        FormatId::APPIMAGE,
        FormatId::WIM,
        FormatId::VDI,
        FormatId::ISO,
        FormatId::NRG,
        FormatId::MDF,
        FormatId::CDI,
        FormatId::ISZ,
        FormatId::CCD,
        FormatId::CUE,
    ] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::Test), "{format} must claim data testing");
    }
    for format in [
        FormatId::ZIP,
        FormatId::SPLIT_ZIP,
        FormatId::SEVEN_Z,
        FormatId::TAR_ZST,
        FormatId::TAR_GZ,
        FormatId::TZAP,
        FormatId::RAR,
        FormatId::RAW_STREAM,
        FormatId::APPLE_ARCHIVE,
        FormatId::ISO,
        FormatId::TAR_LZ,
        FormatId::TAR_LZO,
        FormatId::TAR_COMPRESS,
        FormatId::TAR_LZ4,
        FormatId::TAR_UU,
        FormatId::SQUASHFS,
        FormatId::APPIMAGE,
        FormatId::WIM,
        FormatId::VHD,
        FormatId::VMDK,
        FormatId::UDF,
        FormatId::VDI,
        FormatId::NRG,
        FormatId::MDF,
        FormatId::CDI,
        FormatId::ISZ,
        FormatId::CCD,
        FormatId::CUE,
        FormatId::AR,
        FormatId::CPIO,
        FormatId::DEB,
        FormatId::RPM,
        FormatId::CAB,
        FormatId::XAR,
        FormatId::PKG,
        FormatId::DMG,
        FormatId::MSI,
        FormatId::LHA,
        FormatId::WARC,
    ] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert!(capabilities.operations.contains(&ArchiveOperation::Extract), "{format} must claim full extraction");
    }

    let zip = engine.registry().capabilities_for_format(FormatId::ZIP).unwrap();
    assert_eq!(zip.navigation, NavigationMode::RandomAccess);
    for format in [FormatId::TAR_GZ, FormatId::TAR_ZST, FormatId::SEVEN_Z, FormatId::TZAP, FormatId::RAR, FormatId::RAW_STREAM] {
        let capabilities = engine.registry().capabilities_for_format(format).unwrap_or_else(|| panic!("missing capabilities for {format}"));
        assert_eq!(capabilities.navigation, NavigationMode::SequentialScan, "{format} must advertise its cursor-scan navigation");
    }
    assert_eq!(zip.credential_requirement, CredentialRequirement::Password);
    let tzap = engine.registry().capabilities_for_format(FormatId::TZAP).unwrap();
    assert_eq!(tzap.credential_requirement, CredentialRequirement::PasswordOrRecipientKey);
}

#[test]
fn capability_snapshot_reports_registration_and_platform_state() {
    let engine = create_default_engine().unwrap();
    let snapshot = engine.capability_snapshot();

    let zip = snapshot.iter().find(|capability| capability.format == FormatId::ZIP).expect("ZIP capability should be present");
    assert!(zip.recognized);
    assert!(zip.platform_available);
    assert!(zip.unavailable_reason.is_none());
    assert!(zip.operations.contains(&ArchiveOperation::List));
    assert!(zip.operations.contains(&ArchiveOperation::Test));
    assert!(zip.operations.contains(&ArchiveOperation::Create));
    assert_eq!(zip.role, Some(ArchivePluginRole::Both));
    assert_eq!(zip.source_access, Some(SourceAccess::Seekable));
    assert!(zip.encryption_supported);

    let apple_archive = snapshot.iter().find(|capability| capability.format == FormatId::APPLE_ARCHIVE).expect("Apple Archive capability should be present");
    assert!(apple_archive.recognized);
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        assert!(apple_archive.platform_available);
        assert!(apple_archive.unavailable_reason.is_none());
    } else {
        assert!(!apple_archive.platform_available);
        assert_eq!(apple_archive.unavailable_reason.as_deref(), Some("unsupported platform"));
    }

    let package = snapshot.iter().find(|capability| capability.format == FormatId::PKG).expect("PKG capability should be present");
    assert_eq!(package.role, Some(ArchivePluginRole::Extraction));
}

#[test]
fn engine_creates_zip_through_one_shot_contract_and_commits_before_returning() {
    let temp = TestDir::new("engine-conformance-create-zip");
    let source = temp.path("source.txt");
    let archive = temp.path("created.zip");
    fs::write(&source, b"created through engine").unwrap();
    let manifest = zmanager_core::manifest::plan_archive(&source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, &archive, CreateOptions::Zip(ZipCreateOptions::default()));
    let engine = create_default_engine().unwrap();
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);

    let report = engine.create(&request, &mut context).unwrap();
    assert_eq!(report.format, FormatId::ZIP);
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, b"created through engine".len() as u64);
    assert!(archive.is_file());
    assert!(!temp.path("created.zip.tmp").exists());

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    assert_eq!(handle.list().unwrap().entries.len(), 1);
    handle.close().unwrap();
}

fn create_engine_fixture(
    engine: &zmanager_core::engine::ArchiveEngine,
    source: &std::path::Path,
    destination: &std::path::Path,
    options: CreateOptions,
) -> zmanager_core::engine::CreateReport {
    let manifest = zmanager_core::manifest::plan_archive(source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, destination, options);
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);
    engine.create(&request, &mut context).unwrap()
}

#[test]
fn engine_creation_adapters_round_trip_portable_formats() {
    let temp = TestDir::new("engine-conformance-create-matrix");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"portable create matrix").unwrap();
    let engine = create_default_engine().unwrap();

    let cases = [
        ("created.tar.gz", CreateOptions::TarGz(TarGzCreateOptions::default())),
        ("created.tar.zst", CreateOptions::TarZstd(TarZstdCreateOptions::default())),
        ("created.7z", CreateOptions::SevenZ(SevenZCreateOptions { encrypt_file_names: false, ..Default::default() })),
        (
            "created.tzap",
            CreateOptions::Tzap(TzapCreateOptions {
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
            }),
        ),
    ];

    for (name, options) in cases {
        let archive = temp.path(name);
        let report = create_engine_fixture(&engine, &source, &archive, options);
        assert_eq!(report.written_entries, 2, "{name} should include the project directory and file");
        assert!(archive.is_file(), "{name} should be committed before create returns");
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
        let listing = handle.list().unwrap();
        assert!(listing.entries.iter().any(|entry| entry.path == "project/file.txt"), "{name} should reopen through the engine");
        let destination = temp.path(format!("out-{name}"));
        let mut extract = ExtractOptions { destination, ..Default::default() };
        assert_eq!(handle.extract(&mut extract).unwrap().written_bytes, b"portable create matrix".len() as u64);
    }
}

#[test]
fn native_tar_family_uses_shared_reader_for_all_read_operations() {
    let temp = TestDir::new("engine-conformance-shared-tar");
    let source = temp.path("payload.txt");
    fs::write(&source, b"shared tar payload").unwrap();

    let plain_tar = temp.path("payload.tar");
    let file = File::create(&plain_tar).unwrap();
    let mut builder = tar::Builder::new(file);
    builder.append_path_with_name(&source, "payload.txt").unwrap();
    builder.finish().unwrap();

    let gzip_tar = temp.path("payload.tar.gz");
    zmanager_core::backend_test_support::tar_gz_backend::create_tar_gz_from_path(
        &source,
        &gzip_tar,
        &zmanager_core::backend_test_support::tar_gz_backend::TarGzCreateOptions::default(),
    )
    .unwrap();

    let bzip_tar = temp.path("payload.tar.bz2");
    let file = File::create(&bzip_tar).unwrap();
    let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder.append_path_with_name(&source, "payload.txt").unwrap();
    builder.into_inner().unwrap().finish().unwrap();

    let mut archives = vec![plain_tar, gzip_tar, bzip_tar];
    for (tool, suffix) in [("xz", "xz"), ("lzma", "lzma")] {
        let Ok(output) = std::process::Command::new(tool).arg("-c").arg(archives[0].as_path()).output() else {
            continue;
        };
        if output.status.success() {
            let archive = temp.path(format!("payload.tar.{suffix}"));
            fs::write(&archive, output.stdout).unwrap();
            archives.push(archive);
        }
    }

    let engine = create_default_engine().unwrap();
    for (index, archive) in archives.iter().enumerate() {
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(archive), OpenOptions::default()).unwrap();
        let listing = handle.list().unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
        let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
        assert_eq!(test.tested_entries, 1);
        assert_eq!(test.tested_bytes, b"shared tar payload".len() as u64);
        let mut copied = Vec::new();
        let copy = handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
        assert_eq!(copy.written_bytes, b"shared tar payload".len() as u64);
        assert_eq!(copied, b"shared tar payload");
        handle.close().unwrap();

        let destination = temp.path(format!("out-{index}"));
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(archive), OpenOptions::default()).unwrap();
        let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
        let report = handle.extract(&mut options).unwrap();
        assert_eq!(report.written_entries, 1);
        assert_eq!(fs::read(destination.join("payload.txt")).unwrap(), b"shared tar payload");
        handle.close().unwrap();
    }
}

#[test]
fn native_tar_read_operations_honor_open_options_temp_root() {
    let temp = TestDir::new("engine-conformance-tar-temp-root");
    let source = temp.path("payload.txt");
    fs::write(&source, b"shared tar payload").unwrap();
    let archive = temp.path("payload.tar.gz");
    zmanager_core::backend_test_support::tar_gz_backend::create_tar_gz_from_path(
        &source,
        &archive,
        &zmanager_core::backend_test_support::tar_gz_backend::TarGzCreateOptions::default(),
    )
    .unwrap();

    let temp_root_file = temp.path("app-cache");
    fs::write(&temp_root_file, b"not a directory").unwrap();
    let engine = create_default_engine().unwrap();
    let mut handle =
        engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { temp_root: Some(temp_root_file.clone()), ..Default::default() }).unwrap();

    let error = handle.list().expect_err("a file cannot be used as the archive temp root");
    assert!(error.to_string().contains(temp_root_file.to_string_lossy().as_ref()));
}

#[test]
fn native_cpio_adapter_uses_bounded_operations_for_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.cpio");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert!(!listing.entries.is_empty());
    assert!(listing.entries.iter().any(|entry| entry.path.ends_with("README.txt")));

    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert!(test.tested_bytes > 0);

    let file_entry = listing
        .entries
        .iter()
        .find(|entry| entry.kind == BrowserEntryKind::File && entry.size == Some(12))
        .unwrap_or_else(|| listing.entries.iter().find(|entry| entry.kind == BrowserEntryKind::File).expect("fixture should contain a regular file"));
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert!(!copied.is_empty());

    let destination = TestDir::new("engine-conformance-cpio");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert!(destination.path("out").join("payload/README.txt").is_file());
    handle.close().unwrap();
}

#[test]
fn native_deb_adapter_composes_ar_and_shared_payload_readers() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.deb");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), ["debian-binary", "control.tar.gz", "data.tar.xz"]);

    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, 3);
    assert!(test.tested_bytes > 0);

    let destination = TestDir::new("engine-conformance-deb");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.path("out/data/usr/share/zmanager-fixture/README.txt")).unwrap(), b"ZManager fixture payload\n");
    handle.close().unwrap();
}

#[test]
fn native_rpm_adapter_composes_header_and_cpio_when_rpmbuild_available() {
    let Some(rpmbuild) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("rpmbuild")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-rpm");
    let topdir = temp.path("rpmbuild");
    for directory in ["BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"] {
        fs::create_dir_all(topdir.join(directory)).unwrap();
    }
    let spec = topdir.join("SPECS/zmanager-engine.spec");
    fs::write(
        &spec,
        "Name: zmanager-engine\nVersion: 1.0\nRelease: 1\nSummary: ZManager engine fixture\nLicense: Apache-2.0\nBuildArch: noarch\n\n%description\nZManager engine fixture\n\n%install\nmkdir -p %{buildroot}/usr/share/zmanager-engine\nprintf 'rpm engine payload\\n' > %{buildroot}/usr/share/zmanager-engine/file.txt\n\n%files\n/usr/share/zmanager-engine/file.txt\n",
    )
    .unwrap();
    let build = std::process::Command::new(rpmbuild)
        .arg("--define")
        .arg(format!("_topdir {}", topdir.display()))
        .arg("--define")
        .arg("_build_id_links none")
        .arg("-bb")
        .arg(&spec)
        .output()
        .unwrap();
    assert!(build.status.success(), "rpmbuild failed: {}", String::from_utf8_lossy(&build.stderr));
    let archive = topdir.join("RPMS/noarch/zmanager-engine-1.0-1.noarch.rpm");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry =
        listing.entries.iter().find(|entry| entry.path.ends_with("usr/share/zmanager-engine/file.txt")).expect("RPM payload file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"rpm engine payload\n");

    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("usr/share/zmanager-engine/file.txt")).unwrap(), b"rpm engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_cab_adapter_composes_shared_safety_and_atomic_output() {
    let temp = TestDir::new("engine-conformance-cab");
    let archive = temp.path("payload.cab");
    let mut builder = cab::CabinetBuilder::new();
    let folder = builder.add_folder(cab::CompressionType::MsZip);
    folder.add_file("project/file.txt");
    let mut writer = builder.build(File::create(&archive).unwrap()).unwrap();
    writer.next_file().unwrap().unwrap().write_all(b"cab engine payload\n").unwrap();
    writer.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries[0].path, "project/file.txt");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, 1);
    let mut copied = Vec::new();
    handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
    assert_eq!(copied, b"cab engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    assert_eq!(handle.extract(&mut options).unwrap().written_entries, 1);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"cab engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_xar_adapter_uses_standalone_reader_when_xar_available() {
    let Some(xar) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("xar")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-xar");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"xar engine payload\n").unwrap();
    let archive = temp.path("payload.xar");
    let create = std::process::Command::new(xar).current_dir(temp.root()).arg("-cf").arg(&archive).arg("project").output().unwrap();
    assert!(create.status.success(), "xar failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path.ends_with("project/file.txt")).expect("XAR file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"xar engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"xar engine payload\n");
    handle.close().unwrap();
}

#[test]
fn native_lha_adapter_uses_delharc_when_lha_available() {
    let temp = TestDir::new("engine-conformance-lha");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"lha engine payload\n").unwrap();
    let archive = temp.path("payload.lzh");

    let created_by_native_lha = if let Some(lha) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("lha")).find(|candidate| candidate.is_file()))
    {
        let create = std::process::Command::new(lha).current_dir(temp.root()).arg("a").arg(&archive).arg("project").output();
        create.is_ok_and(|o| o.status.success())
    } else {
        false
    };

    if !created_by_native_lha {
        let entries: [(&str, &[u8], bool); 1] = [("project/file.txt", b"lha engine payload\n", false)];
        let bytes = build_lha_level0_bytes(&entries);
        fs::write(&archive, bytes).unwrap();
    }

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path.ends_with("project/file.txt")).expect("LHA file should be listed");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test.tested_entries > 0);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"lha engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"lha engine payload\n");
    handle.close().unwrap();
}

#[allow(clippy::cast_possible_truncation)]
fn lha_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[allow(clippy::cast_possible_truncation)]
fn build_lha_level0_bytes(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut archive = Vec::new();
    for &(name, data, is_dir) in entries {
        let name_bytes = name.as_bytes();
        let header_size = (22 + name_bytes.len()) as u8;
        let mut header = Vec::with_capacity(header_size as usize + 2);
        header.push(header_size);
        header.push(0); // placeholder for checksum
        let method = if is_dir { b"-lhd-" } else { b"-lh0-" };
        header.extend_from_slice(method);
        let comp_size = if is_dir { 0_u32 } else { data.len() as u32 };
        let uncomp_size = comp_size;
        header.extend_from_slice(&comp_size.to_le_bytes());
        header.extend_from_slice(&uncomp_size.to_le_bytes());
        let dos_time: u32 = ((2026 - 1980) << 25) | (1 << 21) | (1 << 16) | (12 << 11);
        header.extend_from_slice(&dos_time.to_le_bytes());
        header.push(if is_dir { 0x10 } else { 0x20 });
        header.push(0); // Level 0
        header.push(name_bytes.len() as u8);
        header.extend_from_slice(name_bytes);
        let crc = if is_dir { 0_u16 } else { lha_crc16(data) };
        header.extend_from_slice(&crc.to_le_bytes());

        let sum: u8 = header[2..].iter().fold(0_u8, |acc, &b| acc.wrapping_add(b));
        header[1] = sum;

        archive.extend_from_slice(&header);
        if !is_dir {
            archive.extend_from_slice(data);
        }
    }
    archive
}

#[test]
fn native_warc_adapter_materializes_record_bodies_when_bsdtar_available() {
    let Some(bsdtar) = std::env::var("PATH")
        .ok()
        .and_then(|path| path.split(':').map(std::path::PathBuf::from).map(|directory| directory.join("bsdtar")).find(|candidate| candidate.is_file()))
    else {
        return;
    };
    let temp = TestDir::new("engine-conformance-warc");
    let source = temp.path("project");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"warc engine payload\n").unwrap();
    let archive = temp.path("payload.warc");
    let create = std::process::Command::new(bsdtar)
        .current_dir(temp.root())
        .arg("--format")
        .arg("warc")
        .arg("-cf")
        .arg(&archive)
        .arg("project/file.txt")
        .output()
        .unwrap();
    assert!(create.status.success(), "bsdtar failed: {}", String::from_utf8_lossy(&create.stderr));

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_entry = listing.entries.iter().find(|entry| entry.path == "project/file.txt").expect("WARC target URI should become the entry path");
    assert!(listing.entries.iter().any(|entry| entry.path.starts_with("records/")), "WARC info record should retain a stable record path");
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    let mut copied = Vec::new();
    let copy = handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(copy.written_bytes, copied.len() as u64);
    assert_eq!(copied, b"warc engine payload\n");
    let destination = temp.path("out");
    let mut options = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, listing.entries.len() as u64);
    assert_eq!(fs::read(destination.join("project/file.txt")).unwrap(), b"warc engine payload\n");
    handle.close().unwrap();
}

/// Unix-only because the fixture manifest declares a `type=link` record and
/// extraction materializes it; `extract_materialize::write_symlink` reports
/// symlinks as unsupported off Unix. Listing and validation are portable and
/// covered by the reader's own corpus in `mtree_backend`.
#[test]
#[cfg(unix)]
fn native_mtree_adapter_lists_verifies_and_extracts_manifest_shape() {
    let temp = TestDir::new("engine-conformance-mtree");
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.mtree");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|entry| entry.path == "payload/README.txt"));
    assert!(listing.entries.iter().any(|entry| entry.path == "payload/nested/readme-link.txt"));
    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert_eq!(test.tested_bytes, 45);
    let mut options = ExtractOptions { destination: temp.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert!(report.written_entries > 0);
    assert_eq!(fs::metadata(temp.path("out/payload/README.txt")).unwrap().len(), 25);
    assert_eq!(fs::metadata(temp.path("out/payload/nested/file.txt")).unwrap().len(), 20);
    assert_eq!(fs::read_link(temp.path("out/payload/nested/readme-link.txt")).unwrap(), std::path::PathBuf::from("../README.txt"));
    handle.close().unwrap();
}

/// `/unset` used to be rejected up front because the previous `mtree` crate
/// reached `unimplemented!()` on it — the manifest was refused so the panic
/// could not be triggered. The in-tree reader implements the directive, so the
/// same manifest now lists cleanly; the "does not panic" half of the original
/// contract is still what this test guards.
#[test]
fn native_mtree_adapter_applies_unset_directives_without_panicking() {
    let temp = TestDir::new("engine-conformance-mtree-unset");
    let archive = temp.path("unset.mtree");
    fs::write(&archive, b"/set type=file\n/unset type\n./file.txt size=1\n").unwrap();
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "file.txt");
    // `/unset type` cleared the `/set` default, so the record carries no type
    // of its own and falls back to the reader's regular-file default.
    assert_eq!(listing.entries[0].kind, BrowserEntryKind::File);
    assert_eq!(listing.entries[0].size, Some(1));
    handle.close().unwrap();
}

#[test]
fn native_iso_adapter_handles_hybrid_iso_for_list_test_copy_and_extract() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.iso");

    // This fixture is deliberately a hybrid ISO 9660/Joliet image. Keep the
    // assertion here so the regression test cannot silently be replaced with
    // a plain ISO and lose coverage of supplementary-volume handling.
    let mut iso_reader = iso::IsoReader::open(File::open(&archive).unwrap()).unwrap();
    assert!(iso_reader.has_joliet(), "the ISO regression fixture must contain a Joliet supplementary volume");
    assert!(
        iso_reader.walk_joliet().unwrap().iter().any(|entry| !entry.record.joliet_name().is_ascii()),
        "the hybrid fixture must exercise a non-ASCII Joliet filename"
    );

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();

    // The adapter exposes the active primary tree once; it must not surface a
    // second copy of every entry from the Joliet tree.
    let expected_entries = [
        ("DIR WITH SPACES", true, 2048),
        ("NESTED", true, 2048),
        ("README.TXT", false, 25),
        ("UNICODE", true, 2048),
        ("UNICODE/_.TXT", false, 21),
        ("NESTED/EMPTY-DIR", true, 2048),
        ("NESTED/FILE.TXT", false, 20),
        ("DIR WITH SPACES/FILE WITH SPACES.TXT", false, 15),
    ];
    assert_eq!(listing.entries.len(), expected_entries.len());
    for (path, is_directory, size) in expected_entries {
        let entry = listing.entries.iter().find(|entry| entry.path == path).unwrap_or_else(|| panic!("ISO fixture entry should be listed: {path}"));
        assert_eq!(matches!(entry.kind, BrowserEntryKind::Directory), is_directory, "wrong kind for {path}");
        assert_eq!(entry.size, Some(size), "wrong size for {path}");
    }

    let selected_test = handle.test(&zmanager_core::engine::TestOptions { selected_paths: vec!["NESTED/FILE.TXT".to_owned()], ..Default::default() }).unwrap();
    assert_eq!(selected_test.tested_entries, 1);
    assert_eq!(selected_test.skipped_entries, (listing.entries.len() - 1) as u64);
    assert_eq!(selected_test.tested_bytes, b"nested fixture file\n".len() as u64);

    let test = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert_eq!(test.tested_entries, listing.entries.len() as u64);
    assert_eq!(test.tested_bytes, 25 + 20 + 15 + 21);

    for (path, expected) in [
        ("README.TXT", b"ZManager fixture payload\n".as_slice()),
        ("NESTED/FILE.TXT", b"nested fixture file\n".as_slice()),
        ("DIR WITH SPACES/FILE WITH SPACES.TXT", b"spaces in path\n".as_slice()),
        ("UNICODE/_.TXT", b"unicode path fixture\n".as_slice()),
    ] {
        let entry = listing.entries.iter().find(|entry| entry.path == path).unwrap_or_else(|| panic!("ISO fixture file should be listed: {path}"));
        let mut copied = Vec::new();
        let copy = handle.copy_entry(entry.id, &mut copied).unwrap();
        assert_eq!(copy.written_bytes, expected.len() as u64, "wrong copied byte count for {path}");
        assert_eq!(copied, expected, "wrong copied contents for {path}");
    }

    let destination = TestDir::new("engine-conformance-iso");
    let mut options = ExtractOptions { destination: destination.path("out"), ..ExtractOptions::default() };
    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, 4);
    assert_eq!(report.written_bytes, 25 + 20 + 15 + 21);
    assert_eq!(fs::read(destination.path("out/README.TXT")).unwrap(), b"ZManager fixture payload\n");
    assert_eq!(fs::read(destination.path("out/NESTED/FILE.TXT")).unwrap(), b"nested fixture file\n");
    assert_eq!(fs::read(destination.path("out/DIR WITH SPACES/FILE WITH SPACES.TXT")).unwrap(), b"spaces in path\n");
    assert_eq!(fs::read(destination.path("out/UNICODE/_.TXT")).unwrap(), b"unicode path fixture\n");
    handle.close().unwrap();
}

#[test]
fn native_iso_adapter_marks_corrupt_images_terminal() {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.iso");
    let bytes = fs::read(&source).unwrap();
    let temp = TestDir::new("engine-conformance-corrupt-iso");
    let archive = temp.path("corrupt.iso");
    fs::write(&archive, &bytes[..24 * 2048]).unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(error.disposition, zmanager_core::engine::SessionDisposition::Unusable);
    let second = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(second.kind, zmanager_core::engine::ErrorKind::CorruptData);
}

#[test]
fn engine_creation_cancellation_does_not_commit_output() {
    let temp = TestDir::new("engine-conformance-create-cancel");
    let source = temp.path("source.txt");
    let archive = temp.path("cancelled.tar.zst");
    fs::write(&source, b"cancelled create").unwrap();
    let manifest = zmanager_core::manifest::plan_archive(&source, &zmanager_core::manifest::PlanOptions::default()).unwrap();
    let request = CreateRequest::new(manifest, &archive, CreateOptions::TarZstd(TarZstdCreateOptions::default()));
    let engine = create_default_engine().unwrap();
    let token = zmanager_core::jobs::CancellationToken::new();
    token.cancel();
    let mut sink = NoopSink;
    let mut context = zmanager_core::jobs::JobContext::new(&token, &mut sink);
    let error = engine.create(&request, &mut context).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
    assert!(!archive.exists());
}

#[test]
fn engine_lists_native_zip_fixture() {
    let temp = TestDir::new("engine-conformance-zip");
    let zip_path = temp.path("test.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"Hello world!").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::from_path_autodetect(&zip_path);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::ZIP);
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "hello.txt");
    assert_eq!(listing.entries[0].kind, BrowserEntryKind::File);
    assert_eq!(listing.entries[0].size, Some(12));

    handle.close().unwrap();
}

#[test]
fn engine_tests_native_zip_payload_and_honors_selection() {
    let temp = TestDir::new("engine-conformance-test-zip");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("selected.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.start_file("skipped.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"other").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let report = handle.test(&zmanager_core::engine::TestOptions { selected_paths: vec!["selected.txt".to_owned()], ..Default::default() }).unwrap();
    assert_eq!(report.tested_entries, 1);
    assert_eq!(report.skipped_entries, 1);
    assert_eq!(report.tested_bytes, 7);
}

#[test]
fn engine_extracts_native_zip_with_normalized_report() {
    let temp = TestDir::new("engine-conformance-extract-zip");
    let zip_path = temp.path("test.zip");
    let destination = temp.path("out");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"Hello world!").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination: destination.clone(), ..Default::default() };
    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, 12);
    assert_eq!(fs::read(destination.join("hello.txt")).unwrap(), b"Hello world!");
}

#[test]
fn engine_extracts_and_copies_zip_entries_by_retained_id() {
    let temp = TestDir::new("engine-conformance-selected-zip");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("first.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"first").unwrap();
    zip.start_file("second.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"second").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let second_id = listing.entries[1].id;
    let mut selected = zmanager_core::engine::SelectedExtractOptions { destination: temp.path("out"), ..Default::default() };
    let report = handle.extract_selected(second_id, &mut selected).unwrap();
    assert_eq!(report.written_entries, 1);
    assert_eq!(fs::read(temp.path("out/second.txt")).unwrap(), b"second");

    let mut copied = Vec::new();
    let copy_report = handle.copy_entry(listing.entries[0].id, &mut copied).unwrap();
    assert_eq!(copy_report.written_bytes, 5);
    assert_eq!(copied, b"first");
}

#[test]
fn engine_rejects_unknown_input_during_open() {
    let temp = TestDir::new("engine-conformance-unknown-open");
    let path = temp.path("payload.unknown");
    fs::write(&path, b"not an archive format").unwrap();

    let error = create_default_engine().unwrap().open(ArchiveSource::Path(path), OpenOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::InvalidFormat);
}

#[test]
fn engine_rejects_source_changes_before_using_retained_entry_id() {
    let temp = TestDir::new("engine-conformance-source-change");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"original").unwrap();
    zip.finish().unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(zip_path.clone()), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    fs::write(&zip_path, b"replacement archive with different bytes").unwrap();

    let error = handle.copy_entry(listing.entries[0].id, &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn engine_entry_ids_are_scoped_to_the_handle_that_listed_them() {
    let temp = TestDir::new("engine-conformance-entry-id-scope");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut first = engine.open(ArchiveSource::Path(zip_path.clone()), OpenOptions::default()).unwrap();
    let mut second = engine.open(ArchiveSource::Path(zip_path), OpenOptions::default()).unwrap();
    let first_id = first.list().unwrap().entries[0].id;
    second.list().unwrap();

    let error = second.copy_entry(first_id, &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::InvalidFormat);
}

#[test]
fn engine_extract_cancellation_is_reported_before_adapter_work() {
    let temp = TestDir::new("engine-conformance-extract-cancelled");
    let zip_path = temp.path("test.zip");
    fs::write(&zip_path, b"not used").unwrap();
    let cancellation = zmanager_core::jobs::CancellationToken::new();
    cancellation.cancel();
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination: temp.path("out"), cancellation: Some(cancellation), ..Default::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
}

#[test]
fn engine_extract_zip_cancellation_is_honored_by_adapter() {
    let temp = TestDir::new("engine-conformance-zip-cancel-adapter");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for name in ["first.txt", "second.txt", "third.txt"] {
        zip.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"sample payload").unwrap();
    }
    zip.finish().unwrap();

    let cancellation = zmanager_core::jobs::CancellationToken::new();
    cancellation.cancel();
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination: temp.path("out"), cancellation: Some(cancellation), ..Default::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
}

#[test]
fn engine_extract_enforces_entry_count_budget() {
    let temp = TestDir::new("engine-conformance-extract-entry-budget");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for name in ["first.txt", "second.txt"] {
        zip.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"payload").unwrap();
    }
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions {
        destination: temp.path("out"),
        policy: zmanager_core::safety::ExtractionPolicy {
            limits: zmanager_core::safety::ExtractionLimits { max_entries: Some(1), ..zmanager_core::safety::ExtractionLimits::default() },
            ..zmanager_core::safety::ExtractionPolicy::default()
        },
        ..Default::default()
    };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);
}

#[test]
fn engine_extract_rejects_traversal_before_writing_outside_destination() {
    let temp = TestDir::new("engine-conformance-extract-traversal");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("../outside.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"must not escape").unwrap();
    zip.finish().unwrap();

    let destination = temp.path("out");
    let outside = temp.path("outside.txt");
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let mut options = ExtractOptions { destination, ..Default::default() };
    let error = handle.extract(&mut options).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SafetyViolation);
    assert!(!outside.exists());
}

#[test]
fn engine_test_cancellation_is_reported_before_adapter_work() {
    let temp = TestDir::new("engine-conformance-test-cancelled");
    let zip_path = temp.path("test.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("payload.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();

    let cancellation = Arc::new(AtomicBool::new(true));
    let mut handle = create_default_engine().unwrap().open(ArchiveSource::from_path_autodetect(&zip_path), OpenOptions::default()).unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions { cancellation: Some(Arc::clone(&cancellation)), ..Default::default() }).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::Cancelled);
    assert!(cancellation.load(Ordering::Relaxed));
}

#[test]
fn engine_rejects_ambiguous_registrations_at_build_time() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "duplicate-registration-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct DuplicateFactory;

    impl ReadAdapterFactory for DuplicateFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    struct DummyPlugin;
    impl ArchivePlugin for DummyPlugin {
        fn name(&self) -> &'static str {
            "dummy_duplicate"
        }
        fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError> {
            let factory = std::sync::Arc::new(DuplicateFactory);
            builder.register_read_adapter(factory.clone())?;
            builder.register_read_adapter(factory)
        }
    }

    let result = zmanager_core::engine::build_engine_with_plugins(&[&DummyPlugin]);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.message.contains("Ambiguous registration"));
}

#[test]
fn engine_rejects_disjoint_factories_for_one_format() {
    static LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "disjoint-factory-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };
    static TEST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "disjoint-factory-test-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::Test],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct ListOnlyFactory;
    impl ReadAdapterFactory for ListOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &LIST_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    struct TestOnlyFactory;
    impl ReadAdapterFactory for TestOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &TEST_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    static DUPLICATE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "duplicate-operation-test-adapter",
        format: FormatId::TAR,
        operations: &[ArchiveOperation::List, ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };
    struct DuplicateOperationFactory;
    impl ReadAdapterFactory for DuplicateOperationFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DUPLICATE_DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "test factory is not opened"))
        }
    }

    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(ListOnlyFactory)).unwrap();
    let error = builder.register_read_adapter(Arc::new(TestOnlyFactory)).unwrap_err();
    assert!(error.message.contains("one factory instance"));

    let mut duplicate_builder = ArchiveEngineBuilder::new();
    let error = duplicate_builder.register_read_adapter(Arc::new(DuplicateOperationFactory)).unwrap_err();
    assert!(error.message.contains("more than once"));
}

#[test]
fn engine_handles_split_zip_sidecar_detection_without_compatibility_fallback() {
    let temp = TestDir::new("engine-conformance-split-zip");
    let z01 = temp.path("split_test.z01");
    let zip = temp.path("split_test.zip");

    fs::write(&z01, b"sidecar data").unwrap();
    fs::write(&zip, b"zip data").unwrap();

    assert!(is_split_zip_archive_path(&zip));
    assert!(is_split_zip_archive_path(&z01));

    let source = ArchiveSource::from_path_autodetect(&zip);
    match source {
        ArchiveSource::VolumeSet(volumes) => {
            assert_eq!(volumes.len(), 2);
            assert_eq!(volumes[0], z01);
            assert_eq!(volumes[1], zip);
        }
        ArchiveSource::Path(_) => panic!("Expected VolumeSet for split ZIP"),
    }
}

#[test]
fn engine_rejects_explicit_volume_sets_for_single_file_adapters() {
    let temp = TestDir::new("engine-conformance-source-access");
    let source = temp.path("archive.zip");
    fs::write(&source, b"not a split archive").unwrap();

    let error = create_default_engine().unwrap().open(ArchiveSource::VolumeSet(vec![source]), OpenOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::UnsupportedOperation);
    assert!(error.message.contains("MultiVolumeSet"));
    assert!(error.message.contains("Seekable"));
}

#[test]
fn engine_enforces_configured_source_size_limit_before_adapter_open() {
    let temp = TestDir::new("engine-conformance-source-limit");
    let archive = temp.path("archive.zip");
    fs::write(&archive, b"not a zip archive").unwrap();

    let error = create_default_engine()
        .unwrap()
        .open(ArchiveSource::Path(archive), OpenOptions { limits: OpenLimits { max_source_bytes: Some(1) }, ..Default::default() })
        .unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);
}

#[test]
fn engine_rejects_tzap_sibling_mutation_after_open() {
    let temp = TestDir::new("engine-conformance-tzap-source-integrity");
    let source = temp.path("payload.bin");
    let mut state = 0x1234_5678_9abc_def0_u64;
    let payload: Vec<u8> = (0..(3 * 1024 * 1024))
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    fs::write(&source, payload).unwrap();

    let engine = create_default_engine().unwrap();
    let archive = temp.path("split.tzap");
    let report = create_engine_fixture(
        &engine,
        &source,
        &archive,
        CreateOptions::Tzap(TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: Some(1024 * 1024),
            volume_count: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
            emit_bootstrap_sidecar: false,
        }),
    );
    assert!(report.volume_count > 1, "fixture must contain format-owned sibling volumes");

    // A split TZAP archive has numbered volume files and no base `.tzap` file.
    // Opening the requested base path must still use the same format-owned
    // volume discovery path as opening one of its physical volumes.
    let limited = engine
        .open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { limits: OpenLimits { max_source_bytes: Some(1) }, ..Default::default() })
        .unwrap_err();
    assert_eq!(limited.kind, zmanager_core::engine::ErrorKind::ResourceLimitExceeded);

    let mut base_handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    assert!(!base_handle.list().unwrap().entries.is_empty());

    let first_volume = temp.path("split.vol000.tzap");
    let second_volume = temp.path("split.vol001.tzap");
    assert!(first_volume.is_file());
    assert!(second_volume.is_file());

    let logical_source = ArchiveSource::from_path_autodetect(&archive);
    let plan_fingerprint = engine.capture_source_fingerprint(&logical_source).unwrap();

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&second_volume), OpenOptions::default()).unwrap();
    let mut mutated = fs::read(&first_volume).unwrap();
    mutated.push(0);
    fs::write(&first_volume, mutated).unwrap();
    assert_ne!(engine.capture_source_fingerprint(&logical_source).unwrap(), plan_fingerprint);

    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&second_volume), OpenOptions::default()).unwrap();
    fs::write(temp.path("split.vol999.tzap"), b"unexpected volume").unwrap();
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn engine_unusable_session_prevents_subsequent_operations() {
    let temp = TestDir::new("engine-conformance-corrupt");
    let corrupt_zip = temp.path("corrupt.zip");
    fs::write(&corrupt_zip, b"this is not a valid zip archive").unwrap();

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::Path(corrupt_zip);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();

    // Corruption surfaced by the first operation — even list — must mark the
    // session unusable, per the single adapter disposition policy.
    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);

    // Second call should report session unusable
    let res2 = handle.list();
    assert!(res2.is_err());
}

#[test]
fn engine_test_corruption_invalidates_the_session() {
    let temp = TestDir::new("engine-conformance-test-corrupt");
    let corrupt_zip = temp.path("corrupt.zip");
    fs::write(&corrupt_zip, b"this is not a valid zip archive").unwrap();

    let mut handle = create_default_engine().unwrap().open(ArchiveSource::Path(corrupt_zip), OpenOptions::default()).unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::CorruptData);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
    assert!(handle.test(&zmanager_core::engine::TestOptions::default()).is_err());
}

#[test]
fn engine_opens_one_read_session_and_reuses_the_listing_snapshot() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "counting-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct CountingFactory {
        opens: Arc<std::sync::atomic::AtomicUsize>,
    }

    struct CountingSession {
        lists: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ReadAdapterFactory for CountingFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(CountingSession { lists: Arc::new(std::sync::atomic::AtomicUsize::new(0)) }))
        }
    }

    impl ReadAdapterSession for CountingSession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &mut zmanager_core::engine::SelectedExtractOptions<'_>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    let temp = TestDir::new("engine-conformance-session-reuse");
    let source = temp.path("source.zip");
    fs::write(&source, b"placeholder").unwrap();
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(CountingFactory { opens: Arc::clone(&opens) })).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    assert_eq!(handle.list().unwrap().entries[0].path, "payload.txt");
    assert_eq!(handle.list().unwrap().entries[0].path, "payload.txt");
    assert_eq!(opens.load(Ordering::Relaxed), 1);
}

#[test]
fn engine_rejects_source_mutation_detected_after_an_operation() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "mutating-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct MutatingFactory;
    struct MutatingSession {
        source: PathBuf,
    }

    impl ReadAdapterSession for MutatingSession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            fs::write(&self.source, b"replacement archive written during listing").unwrap();
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &mut zmanager_core::engine::SelectedExtractOptions<'_>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    impl ReadAdapterFactory for MutatingFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Ok(Box::new(MutatingSession { source: archive.source.primary_path().to_path_buf() }))
        }
    }

    let temp = TestDir::new("engine-conformance-post-operation-source-change");
    let source = temp.path("source.zip");
    fs::write(&source, b"original archive bytes").unwrap();
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(MutatingFactory)).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    let error = handle.list().unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::SourceChanged);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Unusable);
}

#[test]
fn engine_rejects_unclaimed_operations_at_the_registry_seam_after_open() {
    static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
        name: "list-only-read-adapter",
        format: FormatId::ZIP,
        operations: &[ArchiveOperation::List],
        required_source_access: SourceAccess::Seekable,
        supports_encryption: false,
    };

    struct ListOnlyFactory;
    struct ListOnlySession;

    impl ReadAdapterSession for ListOnlySession {
        fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
            Ok(ArchiveListing { entries: vec![EngineEntry { path: "payload.txt".to_owned(), ..EngineEntry::default() }] })
        }

        fn test(&mut self, _options: &zmanager_core::engine::TestOptions) -> Result<zmanager_core::engine::TestReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn extract<'a>(&mut self, _options: &'a mut ExtractOptions<'a>) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn selected_extract(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _options: &mut zmanager_core::engine::SelectedExtractOptions<'_>,
        ) -> Result<zmanager_core::engine::ExtractReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }

        fn copy_to_writer(
            &mut self,
            _entry_id: zmanager_core::engine::EntryId,
            _writer: &mut dyn std::io::Write,
        ) -> Result<zmanager_core::engine::CopyReport, ArchiveError> {
            Err(ArchiveError::usable(zmanager_core::engine::ErrorKind::UnsupportedOperation, "not claimed"))
        }
    }

    impl ReadAdapterFactory for ListOnlyFactory {
        fn descriptor(&self) -> &'static AdapterDescriptor {
            &DESCRIPTOR
        }

        fn open(self: Arc<Self>, _archive: zmanager_core::engine::DetectedArchive, _options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
            Ok(Box::new(ListOnlySession))
        }
    }

    let temp = TestDir::new("engine-conformance-unclaimed-operation");
    let source = temp.path("source.zip");
    fs::write(&source, b"placeholder").unwrap();
    let mut builder = ArchiveEngineBuilder::new();
    builder.register_read_adapter(Arc::new(ListOnlyFactory)).unwrap();
    let engine = zmanager_core::engine::ArchiveEngine::new(builder.build());
    let mut handle = engine.open(ArchiveSource::Path(source), OpenOptions::default()).unwrap();

    handle.list().unwrap();
    let error = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap_err();
    assert_eq!(error.kind, zmanager_core::engine::ErrorKind::UnsupportedOperation);
    assert_eq!(handle.disposition(), zmanager_core::engine::SessionDisposition::Usable);
}

#[test]
fn engine_extract_progress_sink_receives_live_events() {
    let temp = TestDir::new("engine-progress-sink");
    let zip_path = temp.path("archive.zip");
    let out_dir = temp.path("out");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("sample.txt", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"Hello world from live progress test!").unwrap();
    zip.finish().unwrap();

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::from_path_autodetect(&zip_path);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();

    let mut events = Vec::new();
    let mut sink = |event: zmanager_core::jobs::JobEvent| {
        events.push(event);
    };

    let mut options = ExtractOptions { destination: out_dir.clone(), event_sink: Some(&mut sink), ..Default::default() };

    let report = handle.extract(&mut options).unwrap();
    assert_eq!(report.written_entries, 1);
    assert!(out_dir.join("sample.txt").exists());

    // Verify events recorded EntryStarted or BytesProcessed
    let has_entry_event = events.iter().any(|ev| {
        matches!(
            ev,
            zmanager_core::jobs::JobEvent::EntryStarted { .. }
                | zmanager_core::jobs::JobEvent::BytesProcessed { .. }
                | zmanager_core::jobs::JobEvent::EntryFinished { .. }
        )
    });
    assert!(has_entry_event, "Extraction event sink must receive entry progress events");
}

#[test]
fn engine_batch_selected_extract_executes_in_one_pass() {
    let temp = TestDir::new("engine-batch-selected-extract");
    let archive_path = temp.path("multi.tar.gz");
    let out_dir = temp.path("out");

    {
        let file = File::create(&archive_path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(enc);
        let mut header1 = tar::Header::new_gnu();
        header1.set_path("first.txt").unwrap();
        header1.set_size(5);
        header1.set_cksum();
        tar.append(&header1, b"first".as_slice()).unwrap();

        let mut header2 = tar::Header::new_gnu();
        header2.set_path("second.txt").unwrap();
        header2.set_size(6);
        header2.set_cksum();
        tar.append(&header2, b"second".as_slice()).unwrap();

        let mut header3 = tar::Header::new_gnu();
        header3.set_path("third.txt").unwrap();
        header3.set_size(5);
        header3.set_cksum();
        tar.append(&header3, b"third".as_slice()).unwrap();
        tar.finish().unwrap();
    }

    let engine = create_default_engine().unwrap();
    let source = ArchiveSource::from_path_autodetect(&archive_path);
    let mut handle = engine.open(source, OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 3);

    let first_id = listing.entries[0].id;
    let third_id = listing.entries[2].id;

    let mut selected_options = SelectedExtractOptions { destination: out_dir.clone(), ..Default::default() };

    let report = handle.extract_selected_many(&[first_id, third_id], &mut selected_options).unwrap();
    assert_eq!(report.written_entries, 2);
    assert!(out_dir.join("first.txt").exists());
    assert!(!out_dir.join("second.txt").exists());
    assert!(out_dir.join("third.txt").exists());
}

/// RAR archives may be solid, where decoding one member requires decoding
/// every member before it. Selecting entries one at a time therefore repeats
/// that work per entry, so the adapter must hand the whole selection to
/// `UnRAR` in a single pass.
#[test]
fn engine_batch_selected_extract_covers_rar() {
    let archive = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.rar");
    let temp = TestDir::new("engine-batch-selected-extract-rar");
    let out_dir = temp.path("out");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();

    let readme = listing.entries.iter().find(|entry| entry.path.ends_with("README.txt")).expect("fixture has README.txt");
    let nested = listing.entries.iter().find(|entry| entry.path.ends_with("nested/file.txt")).expect("fixture has nested/file.txt");
    let skipped = listing
        .entries
        .iter()
        .find(|entry| entry.kind == BrowserEntryKind::File && entry.id != readme.id && entry.id != nested.id)
        .expect("fixture has a third regular file");
    let skipped_path = skipped.path.clone();
    let (readme_id, nested_id) = (readme.id, nested.id);

    let mut selected_options = SelectedExtractOptions { destination: out_dir.clone(), ..Default::default() };
    let report = handle.extract_selected_many(&[readme_id, nested_id], &mut selected_options).unwrap();

    assert_eq!(report.written_entries, 2, "exactly the selected entries are written");
    assert_eq!(fs::read_to_string(out_dir.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n");
    assert_eq!(fs::read_to_string(out_dir.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n");
    assert!(!out_dir.join(&skipped_path).exists(), "unselected entry {skipped_path} must not be written");
}

#[test]
fn engine_batch_selected_extract_covers_seven_z() {
    let temp = TestDir::new("engine-batch-selected-extract-7z");
    let source = temp.path("project");
    let archive_path = temp.path("multi.7z");
    let out_dir = temp.path("out");

    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("first.txt"), b"first").unwrap();
    fs::write(source.join("second.txt"), b"second").unwrap();
    fs::write(source.join("third.txt"), b"third").unwrap();

    let engine = create_default_engine().unwrap();
    create_engine_fixture(&engine, &source, &archive_path, CreateOptions::SevenZ(SevenZCreateOptions { encrypt_file_names: false, ..Default::default() }));

    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive_path), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let entry_id = |suffix: &str| listing.entries.iter().find(|entry| entry.path.ends_with(suffix)).expect("entry present").id;
    let selected = [entry_id("first.txt"), entry_id("third.txt")];

    let mut selected_options = SelectedExtractOptions { destination: out_dir.clone(), ..Default::default() };
    let report = handle.extract_selected_many(&selected, &mut selected_options).unwrap();

    assert_eq!(report.written_entries, 2);

    // Every archive entry is accounted for exactly once. A per-entry loop
    // rescans the whole archive per selector and counts the unselected entries
    // again on each pass, so this equality only holds for a single pass.
    let accounted = report.written_entries.saturating_add(report.skipped_entries);
    assert_eq!(accounted, u64::try_from(listing.entries.len()).unwrap(), "batch 7z extraction should visit each entry once");

    let written = |name: &str| {
        let mut matches = walk_files(&out_dir).into_iter().filter(|path| path.ends_with(name));
        matches.next()
    };
    assert!(written("first.txt").is_some(), "selected first.txt should be written");
    assert!(written("third.txt").is_some(), "selected third.txt should be written");
    assert!(written("second.txt").is_none(), "unselected second.txt must not be written");
}

#[test]
fn engine_lists_tests_and_extracts_squashfs_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.squashfs");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::SQUASHFS);
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|e| e.path == "README.txt"));
    assert!(listing.entries.iter().any(|e| e.path == "nested/file.txt"));

    let test_report = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test_report.tested_entries > 0);
    assert!(test_report.tested_bytes > 0);

    let temp = TestDir::new("engine-conformance-squashfs");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap();
    assert!(extract_report.written_entries > 0);
    assert_eq!(fs::read(out.join("README.txt")).unwrap(), b"ZManager fixture payload\n");

    let readme_id = listing.entries.iter().find(|e| e.path == "README.txt").unwrap().id;
    let mut writer = Vec::new();
    let copy_report = handle.copy_entry(readme_id, &mut writer).unwrap();
    assert_eq!(writer, b"ZManager fixture payload\n");
    assert_eq!(copy_report.written_bytes, writer.len() as u64);
}

#[test]
fn engine_lists_tests_and_extracts_appimage_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.AppImage");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::APPIMAGE);
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|e| e.path == "README.txt"));

    let test_report = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test_report.tested_entries > 0);

    let temp = TestDir::new("engine-conformance-appimage");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap();
    assert!(extract_report.written_entries > 0);
    assert_eq!(fs::read(out.join("README.txt")).unwrap(), b"ZManager fixture payload\n");
}

#[test]
fn engine_lists_tests_and_extracts_wim_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.wim");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::WIM);
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|e| e.path == "README.txt"));
    assert!(listing.entries.iter().any(|e| e.path == "nested/file.txt"));

    let test_report = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test_report.tested_entries > 0);
    assert!(test_report.tested_bytes > 0);

    let temp = TestDir::new("engine-conformance-wim");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap();
    assert!(extract_report.written_entries > 0);
    assert_eq!(fs::read(out.join("README.txt")).unwrap(), b"ZManager fixture payload\n");

    let readme_id = listing.entries.iter().find(|e| e.path == "README.txt").unwrap().id;
    let mut writer = Vec::new();
    let copy_report = handle.copy_entry(readme_id, &mut writer).unwrap();
    assert_eq!(writer, b"ZManager fixture payload\n");
    assert_eq!(copy_report.written_bytes, writer.len() as u64);
}

#[test]
fn engine_lists_tests_and_extracts_vdi_fixture() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.vdi");
    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();

    assert_eq!(handle.detected().format, FormatId::VDI);
    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|e| e.path == "payload/README.txt"));
    assert!(listing.entries.iter().any(|e| e.path == "payload/nested/file.txt"));

    let test_report = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test_report.tested_entries > 0);

    let temp = TestDir::new("engine-conformance-vdi");
    let out = temp.path("out");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap();
    assert!(extract_report.written_entries > 0);
    assert_eq!(fs::read(out.join("payload/README.txt")).unwrap(), b"ZManager fixture payload\n");

    let readme_id = listing.entries.iter().find(|e| e.path == "payload/README.txt").unwrap().id;
    let mut writer = Vec::new();
    let copy_report = handle.copy_entry(readme_id, &mut writer).unwrap();
    assert_eq!(writer, b"ZManager fixture payload\n");
    assert_eq!(copy_report.written_bytes, writer.len() as u64);
}

#[test]
fn engine_lists_tests_and_extracts_optical_images() {
    let iso_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.iso");
    let iso_bytes = fs::read(&iso_path).unwrap();
    let temp = TestDir::new("engine-conformance-optical");

    // Test CUE sheet through engine
    let bin_path = temp.path("disc.bin");
    let cue_path = temp.path("disc.cue");
    fs::write(&bin_path, &iso_bytes).unwrap();
    fs::write(&cue_path, "FILE \"disc.bin\" BINARY\r\n  TRACK 01 MODE1/2048\r\n    INDEX 01 00:00:00\r\n").unwrap();

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&cue_path), OpenOptions::default()).unwrap();
    assert_eq!(handle.detected().format, FormatId::CUE);

    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|e| e.path == "README.TXT"));

    let test_report = handle.test(&zmanager_core::engine::TestOptions::default()).unwrap();
    assert!(test_report.tested_entries > 0);

    let out = temp.path("out_cue");
    let mut options = ExtractOptions { destination: out.clone(), ..Default::default() };
    let extract_report = handle.extract(&mut options).unwrap();
    assert!(extract_report.written_entries > 0);
    assert_eq!(fs::read(out.join("README.TXT")).unwrap(), b"ZManager fixture payload\n");
}

/// Collects every regular file below `root`, so a test can assert on extraction
/// output without depending on how a format nests its entries.
fn walk_files(root: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path) } else { found.push(path) }
        }
    }
    found
}

/// A compressed cpio container has no seekable member index, so the adapter
/// decodes it to a temporary file. That decode costs the whole archive, so it
/// must happen once per session and be reused, not repeated per operation.
#[test]
fn compressed_cpio_session_decodes_its_payload_once() {
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.cpio.gz");
    let scratch = TestDir::new("engine-conformance-cpio-gz-decode");
    let temp_root = scratch.path("temp-root");
    fs::create_dir_all(&temp_root).unwrap();

    let decode_dirs =
        || fs::read_dir(&temp_root).unwrap().filter_map(Result::ok).filter(|entry| entry.file_name().to_string_lossy().contains("cpio-decode")).count();

    let engine = create_default_engine().unwrap();
    let mut handle =
        engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { temp_root: Some(temp_root.clone()), ..Default::default() }).unwrap();

    let listing = handle.list().unwrap();
    assert!(listing.entries.iter().any(|entry| entry.path.ends_with("README.txt")));
    // The decode is retained on the session: it survives the operation that
    // produced it, so later operations reuse it instead of decoding again.
    assert_eq!(decode_dirs(), 1, "listing should leave exactly one retained decode");

    let mut options = ExtractOptions { destination: scratch.path("out"), ..ExtractOptions::default() };
    assert!(handle.extract(&mut options).unwrap().written_entries > 0);
    assert_eq!(decode_dirs(), 1, "extraction should reuse the retained decode rather than add another");

    let file_entry = listing.entries.iter().find(|entry| entry.kind == BrowserEntryKind::File).expect("fixture should contain a regular file");
    let mut copied = Vec::new();
    handle.copy_entry(file_entry.id, &mut copied).unwrap();
    assert_eq!(decode_dirs(), 1, "copy should reuse the retained decode rather than add another");

    handle.close().unwrap();
    assert_eq!(decode_dirs(), 0, "closing the session must remove the decoded payload");
}

/// Formats without a batched selected-extract fall back to extracting each
/// entry in turn. That fallback must still route the caller's overwrite
/// resolver through, or every `Ask` conflict in a batch fails closed with
/// `OverwritePromptUnavailable` instead of reaching the prompt.
#[test]
fn batched_selected_extract_consults_the_caller_overwrite_resolver() {
    #[derive(Default)]
    struct CountingResolver {
        calls: usize,
    }

    impl zmanager_core::safety::OverwriteResolver for CountingResolver {
        fn decide(&mut self, _conflict: &zmanager_core::safety::OverwriteConflict) -> zmanager_core::safety::OverwriteDecision {
            self.calls += 1;
            zmanager_core::safety::OverwriteDecision::Skip
        }
    }

    // `basic.cpio` has no batched selected-extract override, so it exercises
    // the per-entry fallback in `selected_extract_many`.
    let archive = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.cpio");
    let scratch = TestDir::new("engine-conformance-cpio-batch-resolver");
    let destination = scratch.path("out");

    let engine = create_default_engine().unwrap();
    let mut handle = engine.open(ArchiveSource::from_path_autodetect(&archive), OpenOptions::default()).unwrap();
    let listing = handle.list().unwrap();
    let file_ids: Vec<_> = listing.entries.iter().filter(|entry| entry.kind == BrowserEntryKind::File).map(|entry| entry.id).collect();
    assert!(file_ids.len() >= 2, "fixture should contain at least two regular files");

    // Populate the destination so every selected entry conflicts.
    let mut seed = ExtractOptions { destination: destination.clone(), ..ExtractOptions::default() };
    assert!(handle.extract(&mut seed).unwrap().written_entries > 0);

    let mut resolver = CountingResolver::default();
    let report = {
        let mut options = SelectedExtractOptions {
            destination: destination.clone(),
            policy: zmanager_core::safety::ExtractionPolicy {
                overwrite: zmanager_core::safety::OverwritePolicy::Ask,
                ..zmanager_core::safety::ExtractionPolicy::default()
            },
            overwrite_resolver: Some(&mut resolver),
            ..Default::default()
        };
        handle.extract_selected_many(&file_ids, &mut options).expect("the batch must reach the resolver, not fail closed")
    };

    assert_eq!(resolver.calls, file_ids.len(), "every conflicting entry in the batch should reach the resolver");
    assert_eq!(report.written_entries, 0, "the resolver skipped every entry");
    handle.close().unwrap();
}
