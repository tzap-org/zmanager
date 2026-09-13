use super::error::{ERROR_DAMAGED_ARCHIVE, ERROR_INVALID_REQUEST, ERROR_NOT_FOUND, WARNING_LAUNCH_GATED_FORMAT};
use super::util::{classify_archive_path, format_capabilities, password_ref};
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "localsend")]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::backend_test_support::zip_backend::{ZipCreateOptions, create_zip_from_manifest};
use zmanager_core::manifest::{PlanOptions, plan_archive};

#[cfg(feature = "localsend")]
static LOCALSEND_FFI_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(feature = "localsend")]
#[test]
fn localsend_ffi_conversions_preserve_device_events_and_decisions() {
    let ffi_device = DeviceInfoDto {
        alias: "peer".to_owned(),
        fingerprint: "sha256:peer".to_owned(),
        port: 53317,
        protocol: "http".to_owned(),
        ip: Some("192.0.2.10".to_owned()),
        device_model: Some("test".to_owned()),
        last_seen_unix_seconds: Some(42),
    };
    let native_device: zmanager_localsend::DeviceInfoDto = ffi_device.clone().into();
    let round_trip = DeviceInfoDto::from(native_device.clone());
    assert_eq!(round_trip.alias, ffi_device.alias);
    assert_eq!(round_trip.fingerprint, ffi_device.fingerprint);
    assert_eq!(round_trip.port, ffi_device.port);
    assert_eq!(round_trip.protocol, ffi_device.protocol);
    assert_eq!(round_trip.ip, ffi_device.ip);
    assert_eq!(round_trip.device_model, ffi_device.device_model);
    assert_eq!(round_trip.last_seen_unix_seconds, ffi_device.last_seen_unix_seconds);

    let event = zmanager_localsend::QueuedEvent::PeerRegistered { device: native_device };
    assert!(matches!(QueuedEvent::from(event), QueuedEvent::PeerRegistered { device } if device.alias == "peer"));

    for decision in [TransferDecisionKind::Accept, TransferDecisionKind::AcceptFiles, TransferDecisionKind::Decline, TransferDecisionKind::Refuse] {
        let native: zmanager_localsend::TransferDecisionKind = decision.into();
        assert!(matches!(
            native,
            zmanager_localsend::TransferDecisionKind::Accept
                | zmanager_localsend::TransferDecisionKind::AcceptFiles
                | zmanager_localsend::TransferDecisionKind::Decline
                | zmanager_localsend::TransferDecisionKind::Refuse
        ));
    }
}

#[cfg(feature = "localsend")]
#[test]
fn localsend_ffi_receiver_lifecycle_is_wired_to_the_shared_registry() {
    let _guard = LOCALSEND_FFI_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = TestDir::new("ffi-localsend");
    localsendStartReceiver(StartReceiverRequest {
        alias: "ffi-test-receiver".to_owned(),
        port: 0,
        https: false,
        save_dir: fixture.root.to_string_lossy().into_owned(),
        auto_accept: false,
        pin: None,
    })
    .expect("FFI receiver start should reach the shared registry");

    let events = localsendPollEvents();
    assert!(events.events.is_empty(), "starting a receiver should not manufacture transfer events");
    localsendStopReceiver().expect("FFI receiver stop should reach the shared registry");
}

#[cfg(feature = "localsend")]
#[test]
fn localsend_ffi_error_paths_return_typed_bridge_errors() {
    let _guard = LOCALSEND_FFI_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let devices = localsendDiscover(DiscoverRequest {
        alias: "ffi-discovery".to_owned(),
        port: 0,
        https: false,
        timeout_ms: 25,
        interface_ips: vec!["127.0.0.1".to_owned()],
    })
    .expect("FFI discovery should use the bounded no-peer path");
    assert!(devices.is_empty());

    let error = localsendRespondToTransfer(RespondToTransferRequest {
        request_id: "missing-request".to_owned(),
        decision: TransferDecisionKind::Decline,
        file_ids: Vec::new(),
        reason: None,
    })
    .expect_err("an unknown transfer request must be rejected");
    assert!(matches!(error, ZmanagerGuiError::Bridge { code, .. } if code == "localsend_unknown_request"));

    let error = localsendSendFile(SendFileRequest {
        send_id: "missing-file".to_owned(),
        alias: "ffi-sender".to_owned(),
        self_port: 0,
        https: false,
        target: DeviceInfoDto {
            alias: "peer".to_owned(),
            fingerprint: String::new(),
            port: 53317,
            protocol: "http".to_owned(),
            ip: Some("127.0.0.1".to_owned()),
            device_model: None,
            last_seen_unix_seconds: None,
        },
        file_path: "/definitely/missing/localsend-file".to_owned(),
        pin: None,
    })
    .expect_err("a missing file must be rejected before spawning a send");
    assert!(matches!(error, ZmanagerGuiError::Bridge { code, .. } if code == "invalid_request"));

    let error = localsendCancelSend(CancelSendRequest { send_id: "missing-send".to_owned() }).expect_err("an unknown send must be rejected");
    assert!(matches!(error, ZmanagerGuiError::Bridge { code, .. } if code == "localsend_unknown_send"));
}

#[cfg(feature = "tzap-online")]
use tzap_core::format::FormatError;
#[cfg(feature = "tzap-online")]
use tzap_core::{MasterKey, RegularFile, RootAuthWriterConfig, WriterOptions, write_archive_with_root_auth};
#[cfg(feature = "tzap-online")]
use tzap_plugin_signing::x509_chain::X509RootAuthSigner;

#[test]
fn healthcheck_reports_real_core() {
    let result = healthcheck();

    assert_eq!(result.engine, "zmanager-core");
    assert!(result.ready);
    assert_eq!(result.status, "ready");
    assert!(result.summary.contains("zmanager-core"));
}

#[cfg(not(feature = "tzap-online"))]
#[test]
fn offline_profile_keeps_local_tzap_contract_and_blocks_hosted_auth() {
    let ZmanagerGuiError::Bridge { user_message, .. } = tzapAuthLogin(TzapAuthLoginRequest {
        state_dir: String::new(),
        account_key: String::new(),
        client_id: String::new(),
        redirect_uri: String::new(),
        auth_base_url: String::new(),
        account_base_url: String::new(),
    })
    .expect_err("tzapAuthLogin should be unavailable without the tzap-online feature");
    assert!(user_message.contains("not enabled in this build"));

    // Document verification stays available offline (see tzap_offline.rs):
    // a failure here must be for a different reason than the feature being
    // disabled.
    if let Err(ZmanagerGuiError::Bridge { user_message, .. }) =
        tzapDocumentVerify(TzapDocumentVerifyRequest { envelope_json: "{}".to_owned(), custom_trust_root_cert_paths: vec![], verifier_time_unix_seconds: 0 })
    {
        assert!(!user_message.contains("not enabled in this build"));
    }
}

#[test]
fn classify_archive_path_supports_launch_extensions() {
    let cases = [
        ("ARCHIVE.ZIP", ArchiveFormat::Zip),
        ("archive.z01", ArchiveFormat::SplitZip),
        ("archive.part01.rar", ArchiveFormat::MultipartRar),
        ("archive.r02", ArchiveFormat::MultipartRar),
        ("archive.7z", ArchiveFormat::SevenZ),
        ("archive.tar", ArchiveFormat::Tar),
        ("archive.tar.gz", ArchiveFormat::TarGz),
        ("archive.tbz2", ArchiveFormat::TarBz2),
        ("archive.txz", ArchiveFormat::TarXz),
        ("archive.tar.zst", ArchiveFormat::TarZst),
        ("archive.tar.lzma", ArchiveFormat::TarLzma),
        ("archive.tar.lz", ArchiveFormat::TarLz),
        ("archive.tar.lzo", ArchiveFormat::TarLzo),
        ("archive.tar.z", ArchiveFormat::TarCompress),
        ("archive.tar.lz4", ArchiveFormat::TarLz4),
        ("archive.tar.uu", ArchiveFormat::TarUu),
        ("archive.iso", ArchiveFormat::Iso),
        ("archive.cab", ArchiveFormat::Cab),
        ("archive.cpio", ArchiveFormat::Cpio),
        ("archive.rpm", ArchiveFormat::Rpm),
        ("archive.xar", ArchiveFormat::Xar),
        ("archive.pkg", ArchiveFormat::Pkg),
        ("archive.dmg", ArchiveFormat::Dmg),
        ("archive.lha", ArchiveFormat::Lha),
        ("archive.ar", ArchiveFormat::Ar),
        ("archive.warc", ArchiveFormat::Warc),
        ("archive.mtree", ArchiveFormat::Mtree),
        ("archive.deb", ArchiveFormat::Deb),
        ("archive.msi", ArchiveFormat::Msi),
        ("archive.vhd", ArchiveFormat::Vhd),
        ("archive.vmdk", ArchiveFormat::Vmdk),
        ("archive.udf", ArchiveFormat::Udf),
        ("archive.vhdx", ArchiveFormat::Vhdx),
        ("archive.qcow2", ArchiveFormat::Qcow2),
        ("archive.e01", ArchiveFormat::Ewf),
        ("archive.ad1", ArchiveFormat::Ad1),
        ("archive.dar", ArchiveFormat::Dar),
        ("archive.aff4", ArchiveFormat::Aff4),
        ("archive.raw", ArchiveFormat::RawDisk),
        ("archive.dd", ArchiveFormat::RawDisk),
        ("archive.dsk", ArchiveFormat::RawDisk),
        ("archive.img", ArchiveFormat::RawDisk),
        ("archive.ex01", ArchiveFormat::Ewf),
        ("archive.qcow", ArchiveFormat::Qcow2),
        ("archive.gz", ArchiveFormat::Gzip),
        ("archive.bz2", ArchiveFormat::Bzip2),
        ("archive.xz", ArchiveFormat::Xz),
        ("archive.zst", ArchiveFormat::Zstd),
        ("archive.tzap", ArchiveFormat::Tzap),
        ("archive.aar", ArchiveFormat::AppleArchive),
        ("archive.aea", ArchiveFormat::AppleArchive),
        ("archive.cbz", ArchiveFormat::Zip),
        ("archive.epub", ArchiveFormat::Zip),
        ("archive.cb7", ArchiveFormat::SevenZ),
        ("archive.cbr", ArchiveFormat::Rar),
        ("archive.cbt", ArchiveFormat::Tar),
        ("archive.xip", ArchiveFormat::Xip),
    ];

    for (path, expected) in cases {
        assert_eq!(classify_archive_path(Path::new(path)).0, expected, "{path}");
    }
}

#[test]
fn every_registered_core_format_has_a_dedicated_mobile_classification() {
    let cases = [
        ("tar.lzma", ArchiveFormat::TarLzma),
        ("tar.lz", ArchiveFormat::TarLz),
        ("tar.lzo", ArchiveFormat::TarLzo),
        ("tar.z", ArchiveFormat::TarCompress),
        ("tar.lz4", ArchiveFormat::TarLz4),
        ("tar.uu", ArchiveFormat::TarUu),
        ("iso", ArchiveFormat::Iso),
        ("cab", ArchiveFormat::Cab),
        ("cpio", ArchiveFormat::Cpio),
        ("rpm", ArchiveFormat::Rpm),
        ("xar", ArchiveFormat::Xar),
        ("pkg", ArchiveFormat::Pkg),
        ("dmg", ArchiveFormat::Dmg),
        ("lha", ArchiveFormat::Lha),
        ("ar", ArchiveFormat::Ar),
        ("warc", ArchiveFormat::Warc),
        ("mtree", ArchiveFormat::Mtree),
        ("deb", ArchiveFormat::Deb),
        ("msi", ArchiveFormat::Msi),
        ("vhd", ArchiveFormat::Vhd),
        ("vmdk", ArchiveFormat::Vmdk),
        ("udf", ArchiveFormat::Udf),
        ("vhdx", ArchiveFormat::Vhdx),
        ("qcow2", ArchiveFormat::Qcow2),
        ("e01", ArchiveFormat::Ewf),
        ("ad1", ArchiveFormat::Ad1),
        ("dar", ArchiveFormat::Dar),
        ("aff4", ArchiveFormat::Aff4),
        ("raw", ArchiveFormat::RawDisk),
        ("dd", ArchiveFormat::RawDisk),
        ("dsk", ArchiveFormat::RawDisk),
        ("img", ArchiveFormat::RawDisk),
        ("ex01", ArchiveFormat::Ewf),
        ("qcow", ArchiveFormat::Qcow2),
    ];

    for (extension, expected) in cases {
        let detected = classify_archive_path(Path::new(&format!("fixture.{extension}"))).0;
        assert_eq!(detected, expected, "fixture.{extension}");
        // MTREE used to be special-cased here on both counts: its backend was
        // `cfg(unix)`-gated, so off Unix it advertised neither capability. The
        // reader is portable now, so it is asserted like every other format.
        assert!(format_capabilities(expected).0, "{extension} must expose list support");
        assert!(format_capabilities(expected).1, "{extension} must expose extract support");
    }
}

#[test]
fn list_formats_returns_full_registry() {
    let result = listFormats();
    // One row per core format kind plus the product-facing Unknown result.
    assert_eq!(result.formats.len(), zmanager_core::archive_format::FORMAT_CAPABILITIES.len() + 1);
    assert!(result.formats.len() >= 26);

    let by_kind: std::collections::HashMap<&str, &FormatDescriptor> = result.formats.iter().map(|format| (format.kind.as_str(), format)).collect();

    let apple_archive = by_kind.get("AppleArchive").expect("Apple Archive row");
    assert_eq!(apple_archive.label, "AppleArchive / AAR");
    assert_eq!(apple_archive.extensions, vec![".aar".to_string(), ".aea".to_string()]);
    let apple_capabilities = zmanager_core::engine::create_default_engine()
        .unwrap()
        .capability_snapshot()
        .into_iter()
        .find(|snapshot| snapshot.format == zmanager_core::engine::FormatId::APPLE_ARCHIVE)
        .expect("Apple Archive capability row");
    assert_eq!(apple_archive.can_list, apple_capabilities.operations.contains(&zmanager_core::engine::ArchiveOperation::List));
    assert_eq!(apple_archive.can_create, apple_capabilities.operations.contains(&zmanager_core::engine::ArchiveOperation::Create));

    let zip = by_kind.get("Zip").expect("Zip row");
    assert!(zip.extensions.contains(&".zip".to_string()));
    assert!(zip.can_list && zip.can_extract && zip.can_create);
    assert!(zip.recognized && zip.platform_available);
    assert_eq!(zip.source_access.as_deref(), Some("seekable"));
    assert!(zip.encryption_supported);
    assert!(zip.unavailable_reason.is_none());

    // Predicate-detected kinds carry no extension list.
    for kind in ["SplitZip", "Tzap", "Unknown"] {
        assert_eq!(by_kind.get(kind).expect(kind).extensions, Vec::<String>::new(), "{kind} extensions");
    }
    assert!(!by_kind.get("Unknown").expect("Unknown row").recognized);
    // RawStream is recognized by suffixes (not predicates).
    assert!(by_kind.get("RawStream").expect("RawStream row").extensions.contains(&".zst".to_string()));

    // The FFI-level capability semantics are preserved alongside the registry.
    assert_eq!(format_capabilities(ArchiveFormat::Xip), (false, false, false));
    assert_eq!(format_capabilities(ArchiveFormat::Other), (false, false, false));
    assert_eq!(format_capabilities(ArchiveFormat::MultipartRar), (true, true, false));
}

#[test]
fn classify_archive_path_identifies_the_final_volume_of_a_split_zip() {
    let temp = TestDir::new("classify-split-zip");
    temp.write_file("archive.z01", b"first volume");
    temp.write_file("archive.zip", b"final volume");

    assert_eq!(classify_archive_path(&temp.path("archive.zip")).0, ArchiveFormat::SplitZip);
}

#[test]
fn classify_archive_path_identifies_the_first_volume_of_a_split_7z() {
    assert_eq!(classify_archive_path(Path::new("archive.7z.001")).0, ArchiveFormat::SevenZ);
}

#[test]
fn detect_archive_rejects_platform_uri_objects() {
    let error = detectArchive(DetectArchiveRequest { archive_path: "content://downloads/archive.zip".to_string() }).unwrap_err();

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
}

#[test]
fn detect_archive_classifies_existing_app_controlled_file() {
    let temp = TestDir::new("detect-existing-file");
    temp.write_file("ARCHIVE.ZIP", b"not parsed during detection");

    let result = detectArchive(DetectArchiveRequest { archive_path: temp.path("ARCHIVE.ZIP").to_string_lossy().to_string() })
        .expect("detection should classify an existing app-controlled path");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert_eq!(result.format_label, "ZIP");
    assert!(result.exists);
    assert!(result.is_file);
    assert!(result.can_list);
    assert!(result.can_extract);
    assert!(result.can_create);
}

#[test]
fn detect_archive_returns_normalized_launch_gated_warning() {
    let temp = TestDir::new("detect-launch-gated-warning");
    temp.write_file("archive.xip", b"not parsed during detection");

    let result = detectArchive(DetectArchiveRequest { archive_path: temp.path("archive.xip").to_string_lossy().to_string() })
        .expect("detection should classify launch-gated app-controlled path");

    assert_eq!(result.format, ArchiveFormat::Xip);
    assert!(!result.can_list);
    assert!(!result.can_extract);
    assert!(!result.can_create);
    assert_eq!(result.warnings.len(), 1);
    let warning = &result.warnings[0];
    assert_eq!(warning.code, WARNING_LAUNCH_GATED_FORMAT);
    assert!(matches!(warning.severity, BridgeSeverity::Warning));
    assert!(!warning.retryable);
}

#[test]
fn list_archive_rejects_missing_path() {
    let error = listArchive(ListArchiveRequest { archive_path: "/definitely/missing/archive.zip".to_string(), password: None }).unwrap_err();

    assert_bridge_error_code(error, ERROR_NOT_FOUND);
}

#[test]
fn list_archive_reads_real_zip_through_core() {
    let temp = TestDir::new("list-archive-real-zip");
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default()).expect("fixture zip should be created through zmanager-core");

    let result =
        listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None }).expect("core-backed listing should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.entry_count >= 1);
    assert!(result.entries.iter().any(|entry| entry.path.ends_with("readme.txt")));
    assert!(result.total_size.is_some());
}

#[test]
fn test_archive_reads_real_zip_through_core() {
    let fixture = create_test_zip("test-archive-real-zip");

    let result = testArchive(TestArchiveRequest { archive_path: fixture.archive.to_string_lossy().to_string(), password: None, selected_paths: Vec::new() })
        .expect("core-backed archive test should succeed");

    assert_eq!(result.format, ArchiveFormat::Zip);
    assert!(result.verified);
    assert!(result.tested_entries >= 1);
    assert_eq!(result.total_entries, result.tested_entries + result.skipped_entries);
    assert!(result.tested_bytes > 0);
}

#[test]
fn test_archive_honors_selected_entry_filter() {
    let fixture = create_test_zip("test-archive-selected-filter");

    let result = testArchive(TestArchiveRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        password: None,
        selected_paths: vec!["missing.txt".to_string()],
    })
    .expect("skipping all entries is still a successful filtered test");

    assert_eq!(result.tested_entries, 0);
    assert!(result.skipped_entries >= 1);
    assert_eq!(result.total_entries, result.skipped_entries);
    assert_eq!(result.tested_bytes, 0);
}

#[test]
fn test_archive_reports_corrupt_zip_as_damaged_archive() {
    let temp = TestDir::new("test-archive-corrupt-zip");
    temp.write_file("broken.zip", b"this is not a zip archive");

    let error =
        testArchive(TestArchiveRequest { archive_path: temp.path("broken.zip").to_string_lossy().to_string(), password: None, selected_paths: Vec::new() })
            .unwrap_err();

    assert_bridge_error_code(error, ERROR_DAMAGED_ARCHIVE);
}

#[test]
fn password_ref_preserves_boundary_whitespace() {
    let password = Some(" secret ".to_string());

    assert_eq!(password_ref(&password), Some(" secret "));
}

#[test]
fn materialize_preview_extracts_one_entry_to_cleanup_root() {
    let fixture = create_test_zip("materialize-preview-real-zip");
    let entry_path = readme_entry_path(&fixture.archive);

    let result = materializePreview(MaterializePreviewRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        entry_path: entry_path.clone(),
        password: None,
        strip_components: 0,
    })
    .expect("preview should materialize through zmanager-core");

    let cleanup_root = PathBuf::from(&result.cleanup_root);
    let preview_path = PathBuf::from(&result.preview_path);
    let canonical_cleanup_root = fs::canonicalize(&cleanup_root).expect("cleanup root should exist");
    let canonical_preview_path = fs::canonicalize(&preview_path).expect("preview path should exist");
    assert_eq!(result.entry_path, entry_path);
    assert!(canonical_preview_path.starts_with(&canonical_cleanup_root));
    assert_eq!(fs::read_to_string(&preview_path).expect("preview file should be readable"), "hello mobile bridge\n");
    assert!(result.written_bytes > 0);

    fs::remove_dir_all(cleanup_root).expect("preview cleanup root should be removable");
}

#[test]
fn materialize_preview_rejects_empty_entry_path() {
    let fixture = create_test_zip("materialize-preview-empty-entry");

    let error = materializePreview(MaterializePreviewRequest {
        archive_path: fixture.archive.to_string_lossy().to_string(),
        entry_path: String::new(),
        password: None,
        strip_components: 0,
    })
    .unwrap_err();

    assert_bridge_error_code(error, ERROR_INVALID_REQUEST);
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_service_endpoints_return_validation_error_instead_of_continuing() {
    let temp = TestDir::new("tzap-service-validation");

    // Regression: the validation failure used to be passed to the core
    // service as the archive path, which then reported its own secondary
    // error. The caller must see the validation message instead.
    let result = tzapPublicMetadataSummary(temp.path("missing.tzap").to_string_lossy().to_string());
    assert!(result.contains("archivePath does not exist"), "expected the validation error envelope, got: {result}");
    assert!(result.starts_with("{\"ok\":false"));

    let display = tzapPublicMetadataDisplaySummary(temp.path("missing.tzap").to_string_lossy().to_string());
    assert!(display.contains("archivePath does not exist"), "expected the validation error envelope, got: {display}");
    assert!(display.starts_with("{\"ok\":false"));
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_public_metadata_display_summary_reports_unsigned_archive() {
    use zmanager_core::backend_test_support::tzap::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};
    use zmanager_core::jobs::JobContext;
    use zmanager_core::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot};

    let temp = TestDir::new("tzap-display-summary");
    let source = temp.path("payload.txt");
    let archive = temp.path("unsigned.tzap");
    fs::write(&source, b"display payload").unwrap();

    let manifest = ArchiveManifest {
        root: temp.path("."),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: b"display payload".len() as u64,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: b"display payload".len() as u64,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
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
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"unsigned\""), "got: {result}");
    assert!(result.contains("\"key_derivation\":\"none\""), "got: {result}");
}

// X.509 fixtures for the signed display-summary tests: a self-signed RSA-2048
// leaf with the `digitalSignature` key usage and a 100-year validity, so the
// fixtures stay usable without regeneration. To regenerate:
//
//   openssl req -x509 -newkey rsa:2048 -keyout ffi_signer.key -out ffi_signer.pem \
//     -days 36500 -nodes -subj "/CN=ZManager FFI Test Signer" \
//     -addext "keyUsage=critical,digitalSignature"
#[cfg(feature = "tzap-online")]
const TEST_LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIUKpN56sqVOMaPXsi55AM0RNv2od8wDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYWk1hbmFnZXIgRkZJIFRlc3QgU2lnbmVyMCAXDTI2MDgw
ODEyNTMzNloYDzIxMjYwNzE1MTI1MzM2WjAjMSEwHwYDVQQDDBhaTWFuYWdlciBG
RkkgVGVzdCBTaWduZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
Dlev5I2sPsnEIx5QlgRH/F6UnLSPTqMxvNZUz9r95DiHB5K3Rec/vWDgR7OuZ3Kn
oeoYBpKWI9aSiMJKtSndFPfBPr8LOCkfcXW5oYp+Ru5VGOsHrDGzphM7Gp80PRGs
qYPLiH4Vdr9jT6NTqLQu+RmhmB/odV23SUhhYfsMpbqAxOr6H+pTr0BImbtaUmZN
2nwLsdU0vn63KifJXyZ3cnLVZ+H/Mc/gPo0icET1pRRMzYE2jTFMvEEjTWfS/rkb
vudLqMJMi0ouRSo6yvfw7jRpGTmrO+K8TLxX1duzpbFBkDgsO+ZOwwpQhlnbX5Eq
mLdS3oa29tAbKkB3iTpBAgMBAAGjYzBhMB0GA1UdDgQWBBRCSGa9lfCggdmisR/N
REo9GuZnDjAfBgNVHSMEGDAWgBRCSGa9lfCggdmisR/NREo9GuZnDjAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAdYKi
/AMDB1opwH7MoaFVPAgs32Q3fddYX9qVq91orG61EuXk1bdl+ByGKT0A07I1YsfF
yS1IWF/IMcvCy9/vOlOWEfN95szohp1qS3+wZEu6+rmjTBIys7ExzSMx1iZknuoy
3X+eRiY66pNtRWod0ffm86SW3O+UGoDHsffJwtRQs5swnFGKVeaP70BOgsu4riG3
5VzgF/6RF7Qv29U27W36u0NNCoe4nRahWZhGI6iE+ZtJA0U9FhYr8Mdr17iN1lUO
M1+kurEbOjjg6QKMUdlrlhj8k4FM5uHoHRpnS2Qlwx89VntwsWkjQq33OwJ9LJ9G
ZZxolvHTPjCTdshjwQ==
-----END CERTIFICATE-----";
#[cfg(feature = "tzap-online")]
const TEST_LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7Dlev5I2sPsnE
Ix5QlgRH/F6UnLSPTqMxvNZUz9r95DiHB5K3Rec/vWDgR7OuZ3KnoeoYBpKWI9aS
iMJKtSndFPfBPr8LOCkfcXW5oYp+Ru5VGOsHrDGzphM7Gp80PRGsqYPLiH4Vdr9j
T6NTqLQu+RmhmB/odV23SUhhYfsMpbqAxOr6H+pTr0BImbtaUmZN2nwLsdU0vn63
KifJXyZ3cnLVZ+H/Mc/gPo0icET1pRRMzYE2jTFMvEEjTWfS/rkbvudLqMJMi0ou
RSo6yvfw7jRpGTmrO+K8TLxX1duzpbFBkDgsO+ZOwwpQhlnbX5EqmLdS3oa29tAb
KkB3iTpBAgMBAAECggEAF6DnrbXSuZPS295NyYMxtkAoWGB1JHccAT/n2R3KfXDT
PSdVPqZrYC9Vae9UwK6bmpZG4lMOOD39sFPrKxG4YI9x/mylKE8nTqv/4XuI6Yuf
NounwLfdLWLIohoqSyh9r5BYMCElQCPYaDyalopEfHyF4tY7DZupw2nT5U1Br6aW
N7K1Idef3KlolvGx7GJ0LVHzx1rVcm6WwLq3QxaTkFRGS6wKDm9EZYRgMyDHQfAs
E35Hllcxbgw6taGSPa9OCFF4jp5ym3+nOpPl3yuAZTa1B0qPo84Rhr/gFpls9Moe
72HuYSi3/ll4zNpU2tF/hS+f44QY3z+NBxReGzibuQKBgQDr/eJjpeqJGZaXAvQY
0O8CGWBUMe1jsgl1WICE6ET1AQaRi5RXBgcuB23lvR+cazm17Fy2E+zd+r3Jyn4z
v/M2fWgatO9w1mooZwZBQFA/Uyy4tTzrei421w/gzCvUFPKDolSwnVQkXA+7ccou
NUCjWkjEToQFITryrLyCHhfXrQKBgQDK6lODRsOq+Hfl0yTfp4rdA7jpbBAWnkY7
aNpXSv1CdTxgsdunOQN1F4T6OWOSVLkUM58ZUlErILZoEzUZqGdoeApMYJOle3Cw
5oVa9dRN8GVHAk+HR86AAVWxtPZJDB7I81VD5RYDsHKsY1im/36Etu9jb1llevDn
2TnlBDYPZQKBgGcB1JVmUG8zahXURjOmzwx9gxx9Bn9jsNk1njNlJuRCZFmXMVKi
4PNobsG+wVOHQhN0bitTmypxTfIMnvV7rW91YcF2hKUeEgw8m/BTYDOj3HtrMIIg
PJfXW6jltaPG2Ow4KPtGUPnl7UAGNRfiSqqCuAxnsRyEGrTeTRIGjKWpAoGBAJxX
pZbtLA+MN90lLTEBxxV5K7z13QOAWX6m0CwYBEBzUdzyzNnwLMDIKVYeZ6C0lJGD
IJ+C9DU1lDVmLzCgt2QfsVedxcTn8jDqvG8UH8sZYP8wQZRq+ClaXet5EZXAt+t+
yQBx/t9C0WgPd5vcGWAqDxJfFdMBwaHxlhDliL2dAoGBAI5T5py8nbfR6Ma88p7i
jVNycLtmEw9Zf4El3KhVrKJkmC7cbDoJ4D5Q9Mv8qHmcXeG+RfAIGpe8XUtYZCYH
XzuI4HQvxWLbhYYyE57ijUfokL0DQHo08feGLtPki+AdJZ5pqIzVoQebz88KFpoS
VfwBjNLu/eSndu5yGiwpZ+3g
-----END PRIVATE KEY-----";

/// Writes a stripe-N archive whose volumes carry an X.509 `RootAuth` footer
/// produced by the fixture signer.
#[cfg(feature = "tzap-online")]
fn write_x509_signed_archive(stripe_width: u32) -> tzap_core::writer::WrittenArchive {
    let signer = X509RootAuthSigner::from_pem_or_der(TEST_LEAF_CERT_PEM.as_bytes(), TEST_LEAF_KEY_PEM.as_bytes(), Vec::new(), 1_700_000_000).unwrap();
    write_archive_with_root_auth(
        &[RegularFile::new("payload.txt", b"signed payload")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width, volume_loss_tolerance: 0, ..WriterOptions::default() },
        signer.root_auth_writer_config().unwrap(),
        |request| signer.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed")),
    )
    .unwrap()
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_public_metadata_display_summary_reports_signed_x509_footer() {
    let temp = TestDir::new("tzap-display-signed");
    let archive = temp.path("signed.tzap");
    fs::write(&archive, write_x509_signed_archive(1).bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"signed\""), "got: {result}");
    assert!(result.contains("\"verification_scope\":\"footer-only\""), "got: {result}");
    assert!(result.contains("\"content_verified\":false"), "got: {result}");
    assert!(result.contains("\"status\":\"root_auth_signer_inspected\""), "got: {result}");
    assert!(result.contains("\"subject\":\"CN=ZManager FFI Test Signer\""), "got: {result}");
    assert!(result.contains("\"signature_verified\":true"), "got: {result}");
    assert!(result.contains("\"trust_validated\":false"), "got: {result}");
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_public_metadata_display_summary_reports_not_authentic_for_tampered_signature() {
    let temp = TestDir::new("tzap-display-not-authentic");
    let archive = temp.path("tampered.tzap");
    let signer = X509RootAuthSigner::from_pem_or_der(TEST_LEAF_CERT_PEM.as_bytes(), TEST_LEAF_KEY_PEM.as_bytes(), Vec::new(), 1_700_000_000).unwrap();
    // A real signature with one flipped byte in the signature region: the
    // footer parses but the signature no longer verifies.
    let written = write_archive_with_root_auth(
        &[RegularFile::new("payload.txt", b"tampered payload")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        signer.root_auth_writer_config().unwrap(),
        |request| {
            let mut value = signer.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed"))?;
            let last = value.len() - 1;
            value[last] ^= 0x01;
            Ok(value)
        },
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"not_authentic\""), "got: {result}");
    assert!(result.contains("\"message\":\"X.509 RootAuth signature failed\""), "got: {result}");
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_public_metadata_display_summary_reports_unavailable_for_non_x509_footer() {
    let temp = TestDir::new("tzap-display-non-x509");
    let archive = temp.path("signed.tzap");
    let written = write_archive_with_root_auth(
        &[RegularFile::new("plain.txt", b"generic signing profile")],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig { authenticator_id: 0x7777, signer_identity_type: 1, signer_identity: b"test signer", authenticator_value_length: 32 },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let result = tzapPublicMetadataDisplaySummary(archive.to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"unavailable\""), "got: {result}");
    assert!(result.contains("non-X.509 root-auth profile"), "got: {result}");
}

#[test]
// TZAP online surface; only present in the full (auth) build.
#[cfg(feature = "tzap-online")]
fn tzap_public_metadata_display_summary_accepts_multi_volume_base_path() {
    let temp = TestDir::new("tzap-display-multi-volume");
    let written = write_x509_signed_archive(4);
    for (index, volume) in written.volumes.iter().enumerate() {
        fs::write(temp.path(&format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    // The volume set exists only under numbered sibling names; the
    // non-existent base path must still resolve to the set and verify every
    // volume's footer.
    let result = tzapPublicMetadataDisplaySummary(temp.path("sample.tzap").to_string_lossy().to_string());
    assert!(result.contains("\"ok\":true"), "got: {result}");
    assert!(result.contains("\"status\":\"signed\""), "got: {result}");
    assert!(result.contains("\"expected_volume_count\":4"), "got: {result}");
    assert!(result.contains("\"present_volume_count\":4"), "got: {result}");
    assert!(result.contains("\"subject\":\"CN=ZManager FFI Test Signer\""), "got: {result}");
}

fn assert_bridge_error_code(error: ZmanagerGuiError, expected: &str) {
    match error {
        ZmanagerGuiError::Bridge { code, .. } => assert_eq!(code, expected),
    }
}

fn readme_entry_path(archive: &Path) -> String {
    listArchive(ListArchiveRequest { archive_path: archive.to_string_lossy().to_string(), password: None })
        .expect("fixture archive should list")
        .entries
        .into_iter()
        .find(|entry| entry.path.ends_with("readme.txt"))
        .expect("fixture archive should contain readme.txt")
        .path
}

fn create_test_zip(name: &str) -> TestArchiveFixture {
    let temp = TestDir::new(name);
    temp.create_dir("project");
    temp.write_file("project/readme.txt", b"hello mobile bridge\n");
    let archive = temp.path("archive.zip");
    let manifest = plan_archive(temp.path("project"), &PlanOptions::default()).expect("fixture manifest should be planned");
    create_zip_from_manifest(&manifest, &archive, &ZipCreateOptions::default()).expect("fixture zip should be created through zmanager-core");
    TestArchiveFixture { temp, archive }
}

struct TestArchiveFixture {
    // Never read directly; kept alive so `TestDir`'s `Drop` cleans up the
    // fixture directory for the lifetime of the archive path below.
    #[allow(dead_code)]
    temp: TestDir,
    archive: PathBuf,
}

struct TestDir {
    root: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("zmanager-mobile-{name}-{}-{now}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test temp root should be created");
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn create_dir(&self, relative: &str) {
        fs::create_dir_all(self.path(relative)).expect("test directory should be created");
    }

    fn write_file(&self, relative: &str, contents: &[u8]) {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("test parent should be created");
        }
        fs::write(path, contents).expect("test file should be written");
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod disk_and_filesystem_formats {
    use crate::ffi::types::ArchiveFormat;
    use crate::ffi::util::{classify_archive_path, format_capabilities, format_label, kind_for_format};
    use std::path::Path;

    /// Every format kind added for the disk-image and filesystem backends,
    /// paired with a path that must classify as it.
    const CASES: &[(&str, ArchiveFormat)] = &[
        ("image.squashfs", ArchiveFormat::Squashfs),
        ("image.sqfs", ArchiveFormat::Squashfs),
        ("Tool-x86_64.AppImage", ArchiveFormat::AppImage),
        ("install.wim", ArchiveFormat::Wim),
        ("install.swm", ArchiveFormat::Wim),
        ("disk.vdi", ArchiveFormat::Vdi),
        ("disc.nrg", ArchiveFormat::Nrg),
        ("disc.mdf", ArchiveFormat::Mdf),
        ("disc.mds", ArchiveFormat::Mdf),
        ("disc.cdi", ArchiveFormat::Cdi),
        ("disc.isz", ArchiveFormat::Isz),
        ("disc.ccd", ArchiveFormat::Ccd),
        ("disc.cue", ArchiveFormat::Cue),
    ];

    #[test]
    fn new_formats_classify_as_themselves_rather_than_other() {
        // Before the bridge learned these variants they all fell through to
        // `ArchiveFormat::Other`, which reports `can_list: false` — so the
        // formats existed in the CLI and were invisible to every FFI caller.
        for (name, expected) in CASES {
            let (format, warnings) = classify_archive_path(Path::new(name));
            assert_eq!(format, *expected, "{name} classified as {format:?}");
            assert!(warnings.is_empty(), "{name}: {warnings:?}");
        }
    }

    #[test]
    fn new_formats_report_list_and_extract_capability() {
        for (name, format) in CASES {
            let (can_list, can_extract, can_create) = format_capabilities(*format);
            assert!(can_list, "{name}: the bridge must report list support");
            assert!(can_extract, "{name}: the bridge must report extract support");
            assert!(!can_create, "{name}: these backends are read-only");
        }
    }

    #[test]
    fn format_and_kind_mappings_are_round_trip_consistent() {
        for (_, format) in CASES {
            let kind = kind_for_format(*format);
            assert_ne!(kind, zmanager_core::archive_format::ArchiveFormatKind::Unknown, "{format:?} must map to a core kind");
            assert!(!format_label(*format).is_empty(), "{format:?} must have a label");
        }
    }

    #[test]
    fn generic_and_unimplemented_extensions_stay_unclaimed() {
        // `.img` is a generic raw-image extension: SD-card, floppy and disk
        // dumps all use it, which is exactly `RawDisk` -- never CloneCD, whose
        // sets are entered through the `.ccd` control file.
        for name in ["raspios.img", "sdcard.img"] {
            let (format, _) = classify_archive_path(Path::new(name));
            assert_eq!(format, ArchiveFormat::RawDisk, "{name} must classify as a raw disk dump");
        }

        // `.esd` images are LZMS solid WIMs this build cannot decode, and the
        // logical/SMART EWF variants have no reader, so none are advertised.
        for name in ["install.esd", "evidence.s01", "evidence.l01", "evidence.lx01"] {
            let (format, _) = classify_archive_path(Path::new(name));
            assert_eq!(format, ArchiveFormat::Other, "{name} must not be claimed");
        }
    }
}
