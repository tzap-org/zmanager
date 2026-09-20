//! Cross-platform creation and extraction contracts for every manifest entry type.

mod common;

use common::TestDir;
use std::fs;
use std::path::{Path, PathBuf};

use zmanager_core::archive_browser::{BrowserEntryKind, BrowserExtractOptions, extract_entry_with_options, list_entries};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use zmanager_core::backend_test_support::apple_archive_backend::{AppleArchiveCompression, AppleArchiveCreateOptions, create_apple_archive_from_manifest};
use zmanager_core::backend_test_support::sevenz_backend::{SevenZCreateOptions, create_7z_from_manifest};
use zmanager_core::backend_test_support::tar_gz_backend::{TarGzCreateOptions, create_tar_gz_from_manifest};
use zmanager_core::backend_test_support::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_manifest};
use zmanager_core::backend_test_support::tzap::{
    TzapCreateOptions, TzapExtractKeySource, TzapExtractRequest, TzapKeySource, TzapRestoreOptions, create_tzap_from_manifest_with_context, extract_tzap,
};
use zmanager_core::backend_test_support::zip_backend::{ZipCreateOptions, create_zip_from_manifest};
use zmanager_core::jobs::{CancellationToken, JobContext};
use zmanager_core::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot, PlanOptions, plan_archive};
use zmanager_core::safety::{ExtractionPolicy, OverwritePolicy};

struct EntryTypeFixture {
    temp: TestDir,
    manifest: ArchiveManifest,
}

fn entry_type_fixture() -> EntryTypeFixture {
    let temp = TestDir::new("entry_type_contracts");
    let source = temp.path("types");
    fs::create_dir_all(source.join("empty")).unwrap();
    fs::write(source.join("file.txt"), b"entry type payload\n").unwrap();

    let mut manifest = plan_archive(&source, &PlanOptions::default()).unwrap();
    manifest.entries.push(ManifestEntry {
        archive_path: "types/link.txt".to_owned(),
        source_path: temp.path("synthetic-link-source"),
        file_type: ManifestFileType::Symlink,
        size: 0,
        modified: None,
        permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o777) },
        symlink_target: Some(PathBuf::from("file.txt")),
    });
    manifest.entries.push(ManifestEntry {
        archive_path: "types/service.sock".to_owned(),
        source_path: temp.path("synthetic-special-source"),
        file_type: ManifestFileType::Other,
        size: 0,
        modified: None,
        permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
        symlink_target: None,
    });

    EntryTypeFixture { temp, manifest }
}

fn assert_creation_warnings(warnings: &[String], expects_symlink_skip: bool) {
    assert!(warnings.iter().any(|warning| warning.contains("service.sock")), "missing special-entry warning: {warnings:?}");
    assert_eq!(warnings.iter().any(|warning| warning.contains("link.txt")), expects_symlink_skip, "unexpected symlink warning set: {warnings:?}");
}

fn assert_entry_type_lifecycle(
    archive: &Path,
    fixture: &EntryTypeFixture,
    archives_symlink: bool,
    listing_exposes_symlink_target: bool,
    selected_extract_materializes_symlink: bool,
) {
    let listing = list_entries(archive).unwrap();
    for (path, expected_kind) in
        [("types", BrowserEntryKind::Directory), ("types/empty", BrowserEntryKind::Directory), ("types/file.txt", BrowserEntryKind::File)]
    {
        let entry = listing.entries.iter().find(|entry| entry.path == path).unwrap_or_else(|| panic!("missing {path} in {listing:?}"));
        assert_eq!(entry.kind, expected_kind, "wrong kind for {path}");
    }

    let link = listing.entries.iter().find(|entry| entry.path == "types/link.txt");
    if archives_symlink {
        let link = link.expect("archive should contain the symlink entry");
        assert_eq!(link.kind, BrowserEntryKind::Symlink);
        if listing_exposes_symlink_target {
            assert_eq!(link.link_target.as_deref(), Some("file.txt"));
        } else {
            assert!(link.link_target.is_none(), "backend unexpectedly exposed a link target: {link:?}");
        }
    } else {
        assert!(link.is_none(), "backend promised to skip symlinks: {listing:?}");
    }
    assert!(!listing.entries.iter().any(|entry| entry.path == "types/service.sock"), "special entry must not be archived");

    let output = fixture.temp.path(format!("out-{}", archive.extension().and_then(|extension| extension.to_str()).unwrap_or("archive")));
    let options = BrowserExtractOptions { overwrite: OverwritePolicy::Replace, ..Default::default() };
    let extract_report = extract_entry_with_options(archive, "types", &output, options).unwrap();
    assert_eq!(fs::read(output.join("types/file.txt")).unwrap(), b"entry type payload\n");
    assert!(output.join("types/empty").is_dir());
    assert!(!output.join("types/service.sock").exists());

    if archives_symlink && selected_extract_materializes_symlink && cfg!(unix) {
        assert!(fs::symlink_metadata(output.join("types/link.txt")).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(output.join("types/link.txt")).unwrap(), PathBuf::from("file.txt"));
    } else {
        assert!(!output.join("types/link.txt").exists(), "symlink should be skipped on this platform/backend");
        if archives_symlink && !selected_extract_materializes_symlink {
            assert!(
                extract_report.metadata_diagnostics.iter().any(|warning| warning.contains("link.txt")),
                "missing selected-extraction symlink diagnostic: {:?}",
                extract_report.metadata_diagnostics
            );
        }
    }
}

#[test]
fn zip_covers_every_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.zip");
    let options = ZipCreateOptions { preserve_metadata: false, ..Default::default() };
    let report = create_zip_from_manifest(&fixture.manifest, &archive, &options).unwrap();

    assert_eq!(report.written_entries, 4);
    assert_creation_warnings(&report.warnings, false);
    assert_entry_type_lifecycle(&archive, &fixture, true, false, true);
}

#[test]
fn tar_zst_covers_every_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.tar.zst");
    let options = TarZstdCreateOptions { preserve_metadata: false, ..Default::default() };
    let report = create_tar_zst_from_manifest(&fixture.manifest, &archive, &options).unwrap();

    assert_eq!(report.written_entries, 4);
    assert_creation_warnings(&report.warnings, false);
    assert_entry_type_lifecycle(&archive, &fixture, true, true, true);
}

#[test]
fn tar_gz_covers_every_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.tar.gz");
    let options = TarGzCreateOptions { preserve_metadata: false, ..Default::default() };
    let report = create_tar_gz_from_manifest(&fixture.manifest, &archive, &options).unwrap();

    assert_eq!(report.written_entries, 4);
    assert_creation_warnings(&report.warnings, false);
    assert_entry_type_lifecycle(&archive, &fixture, true, true, true);
}

#[test]
fn sevenz_covers_every_supported_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.7z");
    let options = SevenZCreateOptions { preserve_metadata: false, encrypt_file_names: false, ..Default::default() };
    let report = create_7z_from_manifest(&fixture.manifest, &archive, &options).unwrap();

    assert_eq!(report.written_entries, 3);
    assert_creation_warnings(&report.warnings, true);
    assert_entry_type_lifecycle(&archive, &fixture, false, false, false);
}

#[test]
fn tzap_covers_every_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.tzap");
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: false,
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
    let report = create_tzap_from_manifest_with_context(&fixture.manifest, &archive, &options, &mut context).unwrap();

    assert_eq!(report.written_entries, 4);
    assert_creation_warnings(&report.warnings, false);
    assert_entry_type_lifecycle(&archive, &fixture, true, true, false);

    let full_output = fixture.temp.path("out-tzap-full");
    let _full_report = extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::None,
            policy: ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..Default::default() },
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: None,
            fast: false,
        },
        &archive,
        &full_output,
    )
    .unwrap();
    let link = full_output.join("types/link.txt");
    let metadata = fs::symlink_metadata(&link).unwrap_or_else(|error| panic!("full TZAP extraction did not restore {link:?}: {error}"));
    assert!(metadata.file_type().is_symlink(), "full TZAP extraction restored {link:?} as {metadata:?}, not a symlink");
    assert_eq!(fs::read_link(link).unwrap(), PathBuf::from("file.txt"));
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn apple_archive_covers_every_manifest_entry_type() {
    let fixture = entry_type_fixture();
    let archive = fixture.temp.path("types.aar");
    let options = AppleArchiveCreateOptions { compression: AppleArchiveCompression::None, preserve_metadata: false, ..Default::default() };
    let report = create_apple_archive_from_manifest(&fixture.manifest, &archive, &options).unwrap();

    assert_eq!(report.written_entries, 4);
    assert_creation_warnings(&report.warnings, false);
    assert_entry_type_lifecycle(&archive, &fixture, true, true, true);
}
