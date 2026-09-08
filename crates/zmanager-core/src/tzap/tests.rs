//! Integration-style tests for the TZAP backend. Unit tests that exercise
//! private module internals live inside the module they belong to.

use super::{
    TzapCreateOptions, TzapExtractKeySource, TzapExtractRequest, TzapKeySource, TzapPublicSignatureStatus, TzapRestoreOptions, TzapRestorePolicy,
    TzapX509SigningOptions, TzapX509TrustOptions, copy_tzap_file_to_writer, copy_tzap_files_to_writer, create_tzap_from_manifest_with_context, extract_tzap,
    extract_tzap_file_to_destination, inspect_tzap_x509_public_no_key_signer, list_tzap_index_with_optional_password, list_tzap_with_optional_password,
    list_tzap_with_password, list_tzap_with_recipient_key, summarize_tzap_public_display, summarize_tzap_public_metadata,
    test_tzap_with_password_filter_and_x509_trust, test_tzap_with_recipient_key_filter_and_x509_trust, verify_tzap_x509_public_no_key,
};
use crate::jobs::{CancellationToken, JobContext};
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PermissionSnapshot};
use crate::safety::ExtractionPolicy;
use crate::secrets::SecretBytes;
use crate::secrets::SecretString;
use crate::test_support::TestDir;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509NameBuilder, X509Ref};
use std::fs;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

#[cfg(unix)]
#[allow(unsafe_code)]
fn unix_process_is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn create_windows_relative_symlink(path: &Path, target: &str) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

    fs::write(path, []).unwrap();
    let target = target.encode_utf16().collect::<Vec<_>>();
    let target_bytes = target.len() * 2;
    let mut path_units = target.clone();
    path_units.push(0);
    path_units.extend_from_slice(&target);
    path_units.push(0);
    let payload_len = 12 + path_units.len() * 2;
    let mut reparse = Vec::with_capacity(8 + payload_len);
    reparse.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
    reparse.extend_from_slice(&u16::try_from(payload_len).expect("reparse payload length fits u16").to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&u16::try_from(target_bytes).expect("reparse target length fits u16").to_le_bytes());
    reparse.extend_from_slice(&u16::try_from(target_bytes + 2).expect("reparse target offset fits u16").to_le_bytes());
    reparse.extend_from_slice(&u16::try_from(target_bytes).expect("reparse target length fits u16").to_le_bytes());
    reparse.extend_from_slice(&1u32.to_le_bytes());
    for unit in path_units {
        reparse.extend_from_slice(&unit.to_le_bytes());
    }

    let file = fs::OpenOptions::new().access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path).unwrap();
    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_SET_REPARSE_POINT,
            reparse.as_ptr().cast(),
            u32::try_from(reparse.len()).expect("reparse buffer length fits u32"),
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_basic_info(path: &Path, directory: bool, reparse_point: bool) -> windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO {
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FileBasicInfo, GetFileInformationByHandleEx,
    };

    let mut flags = if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
    if reparse_point {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(flags)
        .open(path)
        .unwrap_or_else(|error| panic!("failed to open {} for basic-info read: {error}", path.display()));
    let mut info = FILE_BASIC_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FileBasicInfo,
                (&raw mut info).cast(),
                u32::try_from(size_of::<FILE_BASIC_INFO>()).expect("FILE_BASIC_INFO size fits u32"),
            )
        },
        0,
        "failed to read basic info for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    info
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn set_windows_basic_info(path: &Path, directory: bool, reparse_point: bool, info: windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO) {
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES, FileBasicInfo, SetFileInformationByHandle,
    };

    let mut flags = if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
    if reparse_point {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let file = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(flags)
        .open(path)
        .unwrap_or_else(|error| panic!("failed to open {} for basic-info write: {error}", path.display()));
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle().cast(),
                FileBasicInfo,
                (&raw const info).cast(),
                u32::try_from(size_of::<FILE_BASIC_INFO>()).expect("FILE_BASIC_INFO size fits u32"),
            )
        },
        0,
        "failed to set basic info for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_process_is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size fits u32"),
            &raw mut returned,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    result != 0 && elevation.TokenIsElevated != 0
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_security_descriptor(path: &Path, directory: bool) -> Vec<u8> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 })
        .open(path)
        .unwrap();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(status, 0, "failed to read security descriptor for {}: {status}", path.display());
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    assert!(length >= 20, "security descriptor is too short");
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec();
    unsafe {
        LocalFree(descriptor);
    }
    bytes
}

#[cfg(windows)]
fn windows_security_descriptors_equivalent(expected: &[u8], actual: &[u8]) -> bool {
    const DACL_PRESENT: u16 = 0x0004;
    const SACL_PRESENT: u16 = 0x0010;
    const DACL_PROTECTED: u16 = 0x1000;
    const SACL_PROTECTED: u16 = 0x2000;

    if expected.len() < 20 || actual.len() < 20 || expected[..2] != actual[..2] {
        return false;
    }
    let expected_control = u16::from_le_bytes([expected[2], expected[3]]);
    let actual_control = u16::from_le_bytes([actual[2], actual[3]]);
    let mut ignorable = 0u16;
    if expected_control & DACL_PRESENT == 0 && actual_control & DACL_PRESENT == 0 {
        ignorable |= DACL_PROTECTED;
    }
    if expected_control & SACL_PRESENT == 0 && actual_control & SACL_PRESENT == 0 {
        ignorable |= SACL_PROTECTED;
    }
    if (expected_control ^ actual_control) & !ignorable != 0 {
        return false;
    }
    for (offset_field, acl, represented) in
        [(4usize, false, true), (8, false, true), (12, true, expected_control & SACL_PRESENT != 0), (16, true, expected_control & DACL_PRESENT != 0)]
    {
        if represented && security_descriptor_component(expected, offset_field, acl) != security_descriptor_component(actual, offset_field, acl) {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn security_descriptor_component(descriptor: &[u8], offset_field: usize, acl: bool) -> Option<&[u8]> {
    let offset_bytes = descriptor.get(offset_field..offset_field.checked_add(4)?)?;
    let offset = u32::from_le_bytes(offset_bytes.try_into().ok()?) as usize;
    if offset == 0 {
        return Some(&[]);
    }
    let length = if acl {
        let header = descriptor.get(offset..offset.checked_add(4)?)?;
        u16::from_le_bytes([header[2], header[3]]) as usize
    } else {
        let header = descriptor.get(offset..offset.checked_add(8)?)?;
        8usize.checked_add(usize::from(header[1]).checked_mul(4)?)?
    };
    descriptor.get(offset..offset.checked_add(length)?)
}

use tzap_core::format::{CRITICAL_METADATA_RECOVERY_HEADER_LEN, CRITICAL_RECOVERY_LOCATOR_LEN, FormatError};
use tzap_core::wire::CriticalRecoveryLocator;
use tzap_core::{KdfParams, MasterKey, RegularFile, RootAuthWriterConfig, WriterOptions, write_archive_with_kdf, write_archive_with_root_auth};
use tzap_plugin_signing::x509_chain::{X509_AUTHENTICATOR_ID, X509_SIGNER_IDENTITY_TYPE_DER_CERT, X509RootAuthSigner};

#[test]
fn selected_extract_uses_seekable_core_for_numbered_volumes() {
    let temp = TestDir::new("tzap_seekable_selected");
    let large = vec![7u8; 1024 * 1024];
    let archive = create_test_tzap_archive(&[RegularFile::new("large.bin", &large), RegularFile::new("nested/small.txt", b"small target")]);
    for (index, volume) in archive.volumes.iter().enumerate() {
        fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    let selected_volume_path = temp.path("sample.vol001.tzap");
    let listing = list_tzap_with_password(&selected_volume_path, "secret").unwrap();
    assert!(listing.entries.iter().any(|entry| entry.path == "nested/small.txt"));

    let destination = temp.path("out/selected.txt");
    let written = extract_tzap_file_to_destination(
        &selected_volume_path,
        TzapExtractKeySource::Password("secret"),
        "nested/small.txt",
        &destination,
        false,
        TzapRestoreOptions::default(),
    )
    .unwrap()
    .map(|report| report.written_bytes);

    assert_eq!(written, Some(12));
    assert_eq!(fs::read(&destination).unwrap(), b"small target");
}

#[test]
fn public_metadata_summary_reads_numbered_volume_headers_without_password() {
    let temp = TestDir::new("tzap_public_metadata");
    let base_path = temp.path("sample.tzap");
    let archive = create_test_tzap_archive(&[RegularFile::new("hello.txt", b"hello")]);
    for (index, volume) in archive.volumes.iter().enumerate() {
        fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    let summary = summarize_tzap_public_metadata(&base_path).unwrap();

    assert_eq!(summary.expected_volume_count, 4);
    assert_eq!(summary.present_volume_count, 4);
    assert_eq!(summary.missing_volume_indices, Vec::<usize>::new());
    assert_eq!(summary.volumes.len(), 4);
    assert!(summary.format.password_required);
    assert_eq!(summary.format.volume_loss_tolerance, 0);
    assert_eq!(summary.format.bit_rot_buffer_percentage, 0);
    assert_eq!(summary.total_size, archive.volumes.iter().map(Vec::len).sum::<usize>() as u64);
}

#[test]
fn create_tzap_without_password_uses_unencrypted_mode() {
    let temp = TestDir::new("tzap_unencrypted_create");
    let source = temp.path("payload.txt");
    let archive = temp.path("public.tzap");
    fs::write(&source, b"public payload").unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 14,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 14,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = public_metadata_create_options();
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    let report = create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_tzap_with_optional_password(&archive, None).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, fs::metadata(&archive).unwrap().len());
    assert_ne!(report.written_bytes, manifest.total_bytes);

    let summary = summarize_tzap_public_metadata(&archive).unwrap();
    assert_eq!(summary.format.encryption_algorithm, "none");
    assert_eq!(summary.format.key_derivation, "none");
    assert!(!summary.format.password_required);
}

#[test]
fn index_listing_matches_full_paths_kinds_and_sizes_and_exact_copy_skips_full_enumeration() {
    let temp = TestDir::new("tzap_index_listing");
    let empty_directory = temp.path("empty-dir");
    let folder = temp.path("folder");
    let empty_file = temp.path("empty.txt");
    let payload = temp.path("folder/payload.txt");
    let archive = temp.path("public.tzap");
    fs::create_dir(&empty_directory).unwrap();
    fs::create_dir(&folder).unwrap();
    fs::write(&empty_file, []).unwrap();
    fs::write(&payload, b"payload").unwrap();

    let directory_permissions = PermissionSnapshot { readonly: false, unix_mode: Some(0o755) };
    let file_permissions = PermissionSnapshot { readonly: false, unix_mode: Some(0o644) };
    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![
            ManifestEntry {
                archive_path: "empty-dir".to_owned(),
                source_path: empty_directory,
                file_type: ManifestFileType::Directory,
                size: 0,
                modified: None,
                permissions: directory_permissions,
                symlink_target: None,
            },
            ManifestEntry {
                archive_path: "empty.txt".to_owned(),
                source_path: empty_file,
                file_type: ManifestFileType::File,
                size: 0,
                modified: None,
                permissions: file_permissions,
                symlink_target: None,
            },
            ManifestEntry {
                archive_path: "folder".to_owned(),
                source_path: folder,
                file_type: ManifestFileType::Directory,
                size: 0,
                modified: None,
                permissions: directory_permissions,
                symlink_target: None,
            },
            ManifestEntry {
                archive_path: "folder/payload.txt".to_owned(),
                source_path: payload,
                file_type: ManifestFileType::File,
                size: 7,
                modified: None,
                permissions: file_permissions,
                symlink_target: None,
            },
        ],
        total_bytes: 7,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &public_metadata_create_options(), &mut context).unwrap();

    let full = list_tzap_with_optional_password(&archive, None).unwrap();
    let indexed = list_tzap_index_with_optional_password(&archive, None).unwrap();
    let mut full_facts = full.entries.into_iter().map(|entry| (entry.path, entry.kind, entry.size)).collect::<Vec<_>>();
    let mut indexed_facts = indexed.entries.iter().map(|entry| (entry.path.clone(), entry.kind, entry.size)).collect::<Vec<_>>();
    full_facts.sort_by(|left, right| left.0.cmp(&right.0));
    indexed_facts.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(indexed_facts, full_facts);
    assert!(indexed.entries.iter().all(|entry| { if entry.kind == super::TzapEntryKind::File && entry.size > 0 { entry.compressed_size > 0 } else { true } }));

    let mut copied = Vec::new();
    let report = copy_tzap_file_to_writer(&archive, TzapExtractKeySource::None, "folder/payload.txt", &mut copied).unwrap();
    assert_eq!(copied, b"payload");
    assert_eq!(report.written_entries, 1);
    assert_eq!(report.written_bytes, 7);
}

#[test]
#[ignore = "performance characterization harness; set ZMANAGER_PERF_ARCHIVE"]
fn characterize_full_and_index_tzap_listing() {
    let archive = std::env::var_os("ZMANAGER_PERF_ARCHIVE").map(PathBuf::from).expect("set ZMANAGER_PERF_ARCHIVE to a local .tzap fixture");

    let full_started = std::time::Instant::now();
    let full = list_tzap_with_optional_password(&archive, None).unwrap();
    let full_elapsed = full_started.elapsed();

    let index_started = std::time::Instant::now();
    let indexed = list_tzap_index_with_optional_password(&archive, None).unwrap();
    let index_elapsed = index_started.elapsed();

    assert_eq!(indexed.entries.len(), full.entries.len());
    let copy_path = indexed
        .entries
        .iter()
        .filter(|entry| entry.kind == super::TzapEntryKind::File && entry.size > 0)
        .min_by_key(|entry| entry.size)
        .map(|entry| entry.path.clone())
        .expect("fixture should contain a non-empty regular file");
    let old_copy_started = std::time::Instant::now();
    let old_copy = copy_tzap_files_to_writer(&archive, TzapExtractKeySource::None, |path| path == copy_path, &mut std::io::sink()).unwrap();
    let old_copy_elapsed = old_copy_started.elapsed();
    let exact_copy_started = std::time::Instant::now();
    let exact_copy = copy_tzap_file_to_writer(&archive, TzapExtractKeySource::None, &copy_path, &mut std::io::sink()).unwrap();
    let exact_copy_elapsed = exact_copy_started.elapsed();
    assert_eq!(exact_copy.written_bytes, old_copy.written_bytes);
    eprintln!(
        "tzap-listing-baseline entries={} full_ms={} index_ms={} old_copy_ms={} exact_copy_ms={}",
        full.entries.len(),
        full_elapsed.as_millis(),
        index_elapsed.as_millis(),
        old_copy_elapsed.as_millis(),
        exact_copy_elapsed.as_millis(),
    );
}

#[test]
fn list_tzap_with_optional_password_includes_precise_portable_metadata() {
    let temp = TestDir::new("tzap_list_with_optional_password_includes_mtime");
    let source = temp.path("payload.txt");
    let archive = temp.path("public.tzap");
    fs::write(&source, b"payload").unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 7,
            // Windows `SystemTime` has 100-nanosecond precision, so use a
            // timestamp that every supported platform can represent.
            modified: Some(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700)),
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 7,
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
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_tzap_with_optional_password(&archive, None).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");
    assert_eq!(listing.entries[0].mode, 0o644);
    assert_eq!(listing.entries[0].mtime, 1_700_000_000);
    assert_eq!(listing.entries[0].mtime_nanoseconds, 123_456_700);
    assert!(listing.entries[0].metadata_diagnostics.is_empty());
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn fast_extract_restores_portable_mode_and_precise_mtime() {
    use std::os::unix::fs::MetadataExt;

    let temp = TestDir::new("tzap_fast_extract_restores_metadata");
    let source = temp.path("payload.txt");
    let archive = temp.path("public.tzap");
    fs::write(&source, b"payload").unwrap();
    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 7,
            modified: Some(UNIX_EPOCH + Duration::new(1_700_000_000, 234_567_890)),
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o6751) },
            symlink_target: None,
        }],
        total_bytes: 7,
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
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let extract_token = CancellationToken::new();
    let mut extract_events = |_| {};
    let mut extract_context = JobContext::new(&extract_token, &mut extract_events);
    let report = extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::None,
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: Some(&mut extract_context),
            fast: true,
        },
        &archive,
        temp.path("out"),
    )
    .unwrap();

    let metadata = fs::metadata(temp.path("out/payload.txt")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o751);
    assert_eq!(metadata.mtime(), 1_700_000_000);
    assert_eq!(metadata.mtime_nsec(), 234_567_890);
    assert!(report.warnings.iter().any(|warning| warning.contains("setid-mode")));

    let content_token = CancellationToken::new();
    let mut content_events = |_| {};
    let mut content_context = JobContext::new(&content_token, &mut content_events);
    extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::None,
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions { policy: TzapRestorePolicy::Content, allow_degraded: false, ..Default::default() },
            overwrite_resolver: None,
            context: Some(&mut content_context),
            fast: true,
        },
        &archive,
        temp.path("content-out"),
    )
    .unwrap();
    let content_metadata = fs::metadata(temp.path("content-out/payload.txt")).unwrap();
    assert_ne!(content_metadata.mode() & 0o7777, 0o751);
    assert_ne!(content_metadata.mtime(), 1_700_000_000);

    if unix_process_is_elevated() {
        let system_token = CancellationToken::new();
        let mut system_events = |_| {};
        let mut system_context = JobContext::new(&system_token, &mut system_events);
        extract_tzap(
            TzapExtractRequest {
                key: TzapExtractKeySource::None,
                policy: ExtractionPolicy::default(),
                restore_options: TzapRestoreOptions {
                    policy: TzapRestorePolicy::System,
                    // Linux birth time is observable but has no general restoration API.
                    allow_degraded: cfg!(target_os = "linux"),
                    ..Default::default()
                },
                overwrite_resolver: None,
                context: Some(&mut system_context),
                fast: true,
            },
            &archive,
            temp.path("system-out"),
        )
        .unwrap();
        let source_metadata = fs::metadata(temp.path("payload.txt")).unwrap();
        let system_metadata = fs::metadata(temp.path("system-out/payload.txt")).unwrap();
        assert_eq!(system_metadata.mode() & 0o7777, 0o6751);
        assert_eq!(system_metadata.uid(), source_metadata.uid());
        assert_eq!(system_metadata.gid(), source_metadata.gid());
    }
}

#[cfg(unix)]
#[test]
fn fast_extract_restores_directory_metadata_after_children() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let temp = TestDir::new("tzap_fast_extract_restores_directory_metadata");
    let source_dir = temp.path("payload");
    let source_file = temp.path("payload/file.txt");
    let source_link = temp.path("payload/link.txt");
    fs::create_dir(&source_dir).unwrap();
    fs::write(&source_file, b"payload").unwrap();
    symlink("file.txt", &source_link).unwrap();
    filetime::set_symlink_file_times(
        &source_link,
        filetime::FileTime::from_unix_time(1_675_000_000, 456_789_012),
        filetime::FileTime::from_unix_time(1_675_000_000, 456_789_012),
    )
    .unwrap();
    let directory_time = UNIX_EPOCH + Duration::new(1_650_000_000, 345_678_901);
    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![
            ManifestEntry {
                archive_path: "payload".to_owned(),
                source_path: source_dir,
                file_type: ManifestFileType::Directory,
                size: 0,
                modified: Some(directory_time),
                permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o1750) },
                symlink_target: None,
            },
            ManifestEntry {
                archive_path: "payload/link.txt".to_owned(),
                source_path: source_link,
                file_type: ManifestFileType::Symlink,
                size: 0,
                modified: Some(UNIX_EPOCH + Duration::new(1_675_000_000, 456_789_012)),
                permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o777) },
                symlink_target: Some(PathBuf::from("file.txt")),
            },
            ManifestEntry {
                archive_path: "payload/file.txt".to_owned(),
                source_path: source_file,
                file_type: ManifestFileType::File,
                size: 7,
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
                permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o640) },
                symlink_target: None,
            },
        ],
        total_bytes: 7,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let archive = temp.path("public.tzap");
    let options = public_metadata_create_options();
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let extract_token = CancellationToken::new();
    let mut extract_events = |_| {};
    let mut extract_context = JobContext::new(&extract_token, &mut extract_events);
    extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::None,
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: Some(&mut extract_context),
            fast: true,
        },
        &archive,
        temp.path("out"),
    )
    .unwrap();

    let metadata = fs::metadata(temp.path("out/payload")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o1750);
    assert_eq!(metadata.mtime(), 1_650_000_000);
    assert_eq!(metadata.mtime_nsec(), 345_678_901);
    let link_path = temp.path("out/payload/link.txt");
    let link_metadata = fs::symlink_metadata(&link_path).unwrap();
    assert!(link_metadata.file_type().is_symlink());
    assert_eq!(fs::read_link(&link_path).unwrap(), PathBuf::from("file.txt"));
    assert_eq!(link_metadata.mtime(), 1_675_000_000);
    assert_eq!(link_metadata.mtime_nsec(), 456_789_012);
    let listing = list_tzap_with_optional_password(&archive, None).unwrap();
    assert_eq!(listing.entries.len(), 3);
    assert!(listing.entries.iter().any(|entry| { entry.path == "payload" && entry.kind == super::TzapEntryKind::Directory }));
    assert!(listing.entries.iter().any(|entry| { entry.path == "payload/link.txt" && entry.kind == super::TzapEntryKind::Symlink }));
}

#[test]
fn create_tzap_with_recipient_certificate_opens_with_private_key() {
    let temp = TestDir::new("tzap_recipient_wrap_create");
    let source = temp.path("payload.txt");
    let archive = temp.path("sealed.tzap");
    let recipient_cert_path = temp.path("recipient.pem");
    let recipient_key_path = temp.path("recipient.key");
    fs::write(&source, b"sealed payload").unwrap();

    let (recipient_cert, recipient_key) = test_p256_recipient_cert("ZManager Test Recipient");
    fs::write(&recipient_cert_path, recipient_cert.to_pem().unwrap()).unwrap();
    fs::write(&recipient_key_path, recipient_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Test Signer", root_cert.as_ref(), root_key.as_ref());

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 14,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 14,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientCertificate(recipient_cert_path),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::InMemory {
            signing_certificate: signer_cert.to_pem().unwrap(),
            signing_private_key: SecretBytes::from(signer_key.private_key_to_pem_pkcs8().unwrap()),
            signing_chain: vec![root_cert.to_der().unwrap()],
        }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let summary = summarize_tzap_public_metadata(&archive).unwrap();
    assert_eq!(summary.format.key_derivation, "recipient-wrap");
    assert_eq!(summary.format.encryption_algorithm, "aes-gcm-siv-256");
    assert!(!summary.format.password_required);

    let no_key_error = list_tzap_with_optional_password(&archive, None).unwrap_err();
    assert!(no_key_error.to_string().contains("recipient private key"));

    let listing = list_tzap_with_recipient_key(&archive, &recipient_key_path).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");

    let report = test_tzap_with_recipient_key_filter_and_x509_trust(&archive, &recipient_key_path, |_| true, None).unwrap();
    assert_eq!(report.tested_entries, 1);
    assert_eq!(report.tested_bytes, 14);

    let out = temp.path("out");
    let extract_report = extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::RecipientKeyPath(&recipient_key_path),
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: None,
            fast: false,
        },
        &archive,
        &out,
    )
    .unwrap();
    assert_eq!(extract_report.written_entries, 1);
    assert_eq!(fs::read(out.join("payload.txt")).unwrap(), b"sealed payload");

    let out_from_secure_store = temp.path("out-from-secure-store");
    let extract_report = extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::RecipientKeyPath(&recipient_key_path),
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: None,
            fast: false,
        },
        &archive,
        &out_from_secure_store,
    )
    .unwrap();
    assert_eq!(extract_report.written_entries, 1);
    assert_eq!(fs::read(out_from_secure_store.join("payload.txt")).unwrap(), b"sealed payload");
}

#[test]
fn multi_recipient_public_keys_can_open_same_archive() {
    let temp = TestDir::new("tzap_multi_recipient_wrap_create");
    let source = temp.path("payload.txt");
    let archive = temp.path("sealed.tzap");
    let recipient_one_key_path = temp.path("recipient-one.key");
    let recipient_two_key_path = temp.path("recipient-two.key");
    let outsider_key_path = temp.path("outsider.key");
    fs::write(&source, b"shared payload").unwrap();

    let (_recipient_one_cert, recipient_one_key) = test_p256_recipient_cert("ZManager Test Recipient One");
    let (_recipient_two_cert, recipient_two_key) = test_p256_recipient_cert("ZManager Test Recipient Two");
    let (_outsider_cert, outsider_key) = test_p256_recipient_cert("ZManager Test Outsider");
    fs::write(&recipient_one_key_path, recipient_one_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    fs::write(&recipient_two_key_path, recipient_two_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    fs::write(&outsider_key_path, outsider_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let manifest = single_file_manifest(&temp, source, 14);
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientPublicKeys(vec![recipient_one_key.public_key_to_der().unwrap(), recipient_two_key.public_key_to_der().unwrap()]),
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

    for recipient_key_path in [&recipient_one_key_path, &recipient_two_key_path] {
        let listing = list_tzap_with_recipient_key(&archive, recipient_key_path).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, "payload.txt");
    }

    let outsider_error = list_tzap_with_recipient_key(&archive, outsider_key_path).unwrap_err();
    assert!(outsider_error.to_string().contains("no matching recipient private key"));
}

#[test]
fn signed_tzap_with_recipient_public_keys_opens_with_the_matching_key() {
    let temp = TestDir::new("tzap_signed_recipient_public_key");
    let source = temp.path("payload.txt");
    let archive = temp.path("sealed.tzap");
    let recipient_key_path = temp.path("recipient.key");
    fs::write(&source, b"sealed payload").unwrap();

    let (_recipient_cert, recipient_key) = test_p256_recipient_cert("ZManager Test Recipient");
    fs::write(&recipient_key_path, recipient_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Test Signer", root_cert.as_ref(), root_key.as_ref());

    let manifest = single_file_manifest(&temp, source, 14);
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientPublicKeys(vec![recipient_key.public_key_to_der().unwrap()]),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::InMemory {
            signing_certificate: signer_cert.to_pem().unwrap(),
            signing_private_key: SecretBytes::from(signer_key.private_key_to_pem_pkcs8().unwrap()),
            signing_chain: vec![root_cert.to_der().unwrap()],
        }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_tzap_with_recipient_key(&archive, &recipient_key_path).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");
}

/// The engine's `OpenOptions`/`BrowserListOptions`/`ExtractOptions` accept a
/// recipient private key as either a file path or in-memory bytes, so callers
/// backed by a platform-sealed secret store never have to write the key to
/// disk. This proves the bytes path end to end through the public engine
/// surface: open, list, test, and extract, all with no key file on disk.
#[test]
fn recipient_wrapped_tzap_opens_lists_tests_and_extracts_with_in_memory_key_bytes() {
    use crate::engine::{ArchiveSource, ExtractOptions, OpenOptions, TestOptions};
    use crate::safety::ExtractionPolicy;

    let temp = TestDir::new("tzap_recipient_key_bytes");
    let source = temp.path("payload.txt");
    let archive = temp.path("sealed.tzap");
    fs::write(&source, b"sealed payload").unwrap();

    let (_recipient_cert, recipient_key) = test_p256_recipient_cert("ZManager Test Recipient");
    let recipient_key_bytes = recipient_key.private_key_to_pem_pkcs8().unwrap();

    let manifest = single_file_manifest(&temp, source, 14);
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientPublicKeys(vec![recipient_key.public_key_to_der().unwrap()]),
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

    let engine = crate::engine::create_default_engine().unwrap();

    // Wrong bytes must not open it.
    let (_wrong_cert, wrong_key) = test_p256_recipient_cert("ZManager Wrong Recipient");
    let wrong_bytes = wrong_key.private_key_to_pem_pkcs8().unwrap();
    let open_err = engine
        .open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { recipient_key_bytes: Some(vec![wrong_bytes]), ..Default::default() })
        .and_then(|mut handle| handle.list());
    assert!(open_err.is_err(), "the wrong recipient key must not open a recipient-wrapped archive");

    // The matching key, supplied only as in-memory bytes, opens and lists it.
    let mut handle = engine
        .open(ArchiveSource::from_path_autodetect(&archive), OpenOptions { recipient_key_bytes: Some(vec![recipient_key_bytes.clone()]), ..Default::default() })
        .unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");

    // Integrity test with only the session-bound bytes (no per-call key).
    let test_report = handle.test(&TestOptions::default()).unwrap();
    assert_eq!(test_report.tested_entries, 1);

    // Extraction inherits the session-bound bytes without being told again.
    let destination = temp.path("extracted");
    let mut extract_options = ExtractOptions { destination: destination.clone(), policy: ExtractionPolicy::default(), ..ExtractOptions::default() };
    let report = handle.extract(&mut extract_options).unwrap();
    assert_eq!(report.written_entries, 1);
    assert_eq!(fs::read(destination.join("payload.txt")).unwrap(), b"sealed payload");
}

/// A device that has rotated its recipient key holds several private-key
/// candidates at once (design §9.4): the retired key that encrypted an old
/// archive, and the active key it now advertises. Opening must pick whichever
/// candidate's SPKI matches the archive's keywrap record, regardless of
/// position in the candidate list, and a lookup with no matching candidate
/// must fail rather than silently succeed with the wrong key.
#[test]
fn recipient_wrapped_tzap_opens_with_a_non_active_key_from_a_multi_key_candidate_list() {
    use crate::engine::{ArchiveSource, OpenOptions};

    let temp = TestDir::new("tzap_multi_key_candidates");
    let source = temp.path("payload.txt");
    let archive = temp.path("sealed.tzap");
    fs::write(&source, b"sealed payload").unwrap();

    let (_retired_cert, retired_key) = test_p256_recipient_cert("ZManager Retired Recipient");
    let (_active_cert, active_key) = test_p256_recipient_cert("ZManager Active Recipient");
    let (_unrelated_cert, unrelated_key) = test_p256_recipient_cert("ZManager Unrelated Recipient");
    let retired_key_bytes = retired_key.private_key_to_pem_pkcs8().unwrap();
    let active_key_bytes = active_key.private_key_to_pem_pkcs8().unwrap();
    let unrelated_key_bytes = unrelated_key.private_key_to_pem_pkcs8().unwrap();

    // The archive is addressed to the retired key only, as an old archive
    // encrypted before a key rotation would be.
    let manifest = single_file_manifest(&temp, source, 14);
    let options = TzapCreateOptions {
        key_source: TzapKeySource::RecipientPublicKeys(vec![retired_key.public_key_to_der().unwrap()]),
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

    let engine = crate::engine::create_default_engine().unwrap();

    // The device now holds the active key first and the retired key second;
    // the record only matches the retired key, so it must still be found.
    let mut handle = engine
        .open(
            ArchiveSource::from_path_autodetect(&archive),
            OpenOptions { recipient_key_bytes: Some(vec![active_key_bytes.clone(), retired_key_bytes.clone()]), ..Default::default() },
        )
        .unwrap();
    let listing = handle.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");

    // A candidate list holding none of the archive's matching keys reports
    // the same "no matching private key" outcome as the single-key path,
    // rather than a misleading error.
    let open_err = engine
        .open(
            ArchiveSource::from_path_autodetect(&archive),
            OpenOptions { recipient_key_bytes: Some(vec![active_key_bytes, unrelated_key_bytes]), ..Default::default() },
        )
        .and_then(|mut handle| handle.list());
    assert!(open_err.is_err(), "a candidate list with no matching key must not open a recipient-wrapped archive");
}

#[test]
fn create_split_tzap_uses_os_friendly_volume_names() {
    let temp = TestDir::new("tzap_split_volume_names");
    let source = temp.path("payload.bin");
    let archive = temp.path("public.tzap");
    let payload = deterministic_bytes(3 * 1024 * 1024);
    fs::write(&source, &payload).unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.bin".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: payload.len() as u64,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: payload.len() as u64,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: Some(1024 * 1024),
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 1,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    let report = create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    assert!(report.volume_count > 1);
    assert!(!archive.exists());
    assert!(temp.path("public.vol000.tzap").exists());
    assert!(temp.path("public.vol001.tzap").exists());

    let selected_volume = temp.path("public.vol001.tzap");
    let listing = list_tzap_with_optional_password(&selected_volume, None).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.bin");
}

/// `volume_count` is a second, independent split mode from `volume_size`: it
/// requests an exact number of output volumes (round-robin striped) rather
/// than targeting a byte size per volume.
#[test]
fn create_tzap_with_volume_count_produces_exactly_that_many_volumes() {
    let temp = TestDir::new("tzap_volume_count");
    let source = temp.path("payload.bin");
    let archive = temp.path("public.tzap");
    // Incompressible content: `deterministic_bytes`'s short repeating cycle
    // compresses away to almost nothing under round-robin striping, which
    // starves the archive-size-scaled extraction cap below the logical size.
    let payload = pseudo_random_bytes(3 * 1024 * 1024, 0xC0FF_EE13);
    fs::write(&source, &payload).unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.bin".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: payload.len() as u64,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: payload.len() as u64,
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
        volume_count: Some(4),
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    let report = create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    assert_eq!(report.volume_count, 4);
    assert!(!archive.exists());
    for index in 0..4 {
        assert!(temp.path(format!("public.vol{index:03}.tzap")).exists());
    }

    let listing = list_tzap_with_optional_password(&archive, None).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.bin");
}

/// `volume_size` and `volume_count` are alternate split modes and cannot both
/// be requested at once.
#[test]
fn create_tzap_rejects_both_volume_size_and_volume_count() {
    let temp = TestDir::new("tzap_volume_count_conflict");
    let source = temp.path("payload.txt");
    let archive = temp.path("conflict.tzap");
    fs::write(&source, b"payload").unwrap();

    let manifest = single_file_manifest(&temp, source, 7);
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: Some(1024),
        volume_count: Some(2),
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);

    let error = create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap_err();
    assert!(matches!(error, super::TzapError::Format(_)));
}

#[test]
fn create_and_test_tzap_with_x509_root_auth() {
    let temp = TestDir::new("tzap_x509_root_auth");
    let source = temp.path("payload.txt");
    let archive = temp.path("signed.tzap");
    let root_ca_path = temp.path("root-ca.pem");
    fs::write(&source, b"signed payload").unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Test Signer", root_cert.as_ref(), root_key.as_ref());
    fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
    let signer_certificate = signer_cert.to_pem().unwrap();
    let signer_private_key = signer_key.private_key_to_pem_pkcs8().unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 14,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 14,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::InMemory {
            signing_certificate: signer_certificate,
            signing_private_key: SecretBytes::from(signer_private_key),
            signing_chain: Vec::new(),
        }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let trust = TzapX509TrustOptions { trusted_ca_certificates: vec![root_ca_path], trusted_system_roots: false, include_official_tzap_root: false };
    let report = test_tzap_with_password_filter_and_x509_trust(&archive, "secret", |_| true, Some(&trust)).unwrap();
    let root_auth = report.x509_root_auth.unwrap();

    assert_eq!(report.tested_entries, 1);
    assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
    assert_eq!(root_auth.issuer, "CN=ZManager Test Root CA");
    assert_eq!(root_auth.trust_anchor_subject.as_deref(), Some("CN=ZManager Test Root CA"));
    assert!(root_auth.diagnostics.iter().any(|diagnostic| diagnostic == "root_auth_content_verified"));

    let public_report = verify_tzap_x509_public_no_key(&archive, &trust).unwrap();
    assert_eq!(public_report.archive_root, root_auth.archive_root);
    assert_eq!(public_report.subject, "CN=ZManager Test Signer");
    assert_eq!(public_report.trust_anchor_subject.as_deref(), Some("CN=ZManager Test Root CA"));
    assert_eq!(public_report.diagnostics.first().map(String::as_str), Some("public_data_block_commitment_verified"));

    // Z4: both public no-key paths now verify through File-backed
    // ArchiveReadAt readers rather than reading every volume into memory
    // first; this is the same archive exercising the signer-inspection path.
    let signer_inspection = inspect_tzap_x509_public_no_key_signer(&archive).unwrap();
    assert_eq!(signer_inspection.archive_root, root_auth.archive_root);
    assert_eq!(signer_inspection.subject, "CN=ZManager Test Signer");

    // Z7: unified archive verification model
    let now = i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap();
    let archive_verification = super::verify_tzap_archive_public_no_key(&archive, &trust, now).unwrap();
    assert_eq!(archive_verification.signature, super::TzapArchiveSignatureCheck::Ok);
    // Custom test root without official root classifies as Untrusted under Z2 -> Failed
    assert_eq!(archive_verification.trust, super::TzapArchiveTrustCheck::Untrusted);
    assert_eq!(archive_verification.certificate_time, super::TzapArchiveTimeCheck::ValidAtSigning);
    assert_eq!(archive_verification.outcome, super::TzapArchiveVerificationOutcome::Failed);
    assert_eq!(archive_verification.headline_label(), "Signer Not Trusted");
    let signer = archive_verification.signer.unwrap();
    assert_eq!(signer.subject, "CN=ZManager Test Signer");
    assert_eq!(signer.display_name.as_deref(), Some("ZManager Test Signer"));
    assert_eq!(signer.certificate_sha256, root_auth.certificate_sha256);

    let own_verification =
        super::verify_tzap_archive_public_no_key_with_signer_predicate(&archive, &trust, now, |fp| *fp == root_auth.certificate_sha256).unwrap();
    assert!(own_verification.signer_is_this_device);
}

#[test]
fn public_display_summary_reports_signed_authentic_footer() {
    let temp = TestDir::new("tzap_display_signed");
    let source = temp.path("payload.txt");
    let archive = temp.path("signed.tzap");
    let root_ca_path = temp.path("root-ca.pem");
    fs::write(&source, b"signed display payload").unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Display Root CA");
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Display Signer", root_cert.as_ref(), root_key.as_ref());
    let options = TzapCreateOptions {
        key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::InMemory {
            signing_certificate: signer_cert.to_pem().unwrap(),
            signing_private_key: SecretBytes::from(signer_key.private_key_to_pem_pkcs8().unwrap()),
            signing_chain: Vec::new(),
        }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&single_file_manifest(&temp, source, b"signed display payload".len() as u64), &archive, &options, &mut context)
        .unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert_eq!(summary.metadata.present_volume_count, 1);
    let TzapPublicSignatureStatus::Signed { signer } = &summary.signature else {
        panic!("expected signed status, got {:?}", summary.signature);
    };
    assert_eq!(signer.subject, "CN=ZManager Display Signer");
    assert_eq!(signer.issuer, "CN=ZManager Display Root CA");

    // Cross-check the footer-only inspection against the full no-key
    // verification: both must agree on the signed payload's root commitment
    // and the data blocks it covers.
    fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
    let trust = TzapX509TrustOptions { trusted_ca_certificates: vec![root_ca_path], trusted_system_roots: false, include_official_tzap_root: false };
    let report = verify_tzap_x509_public_no_key(&archive, &trust).unwrap();
    assert_eq!(report.archive_root, signer.archive_root);
    assert_eq!(report.total_data_block_count, signer.total_data_block_count);
    assert_eq!(report.subject, signer.subject);
}

#[test]
fn public_display_summary_reports_unsigned_archive() {
    let temp = TestDir::new("tzap_display_unsigned");
    let base_path = temp.path("sample.tzap");
    let written = create_test_tzap_archive(&[RegularFile::new("plain.txt", b"no signature")]);
    for (index, volume) in written.volumes.iter().enumerate() {
        fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    // Summarize through the non-existent base name: discovery must resolve
    // the complete volume set and the footer pass must report Unsigned for
    // every present volume — never Unavailable for "missing volume 0".
    let summary = summarize_tzap_public_display(&base_path).unwrap();
    assert_eq!(summary.metadata.expected_volume_count, 4);
    assert_eq!(summary.metadata.present_volume_count, 4);
    assert!(summary.metadata.missing_volume_indices.is_empty());
    assert_eq!(summary.signature, TzapPublicSignatureStatus::Unsigned);
}

/// A footer whose authenticator value is a byte blob no real signature
/// scheme produces (all-zero "signature" over a real RSA-2048 identity).
/// The plugin fails while parsing the authenticator value; inspection must
/// report the footer not authentic rather than treat it as signed. A footer
/// signed by a real but mismatched key is covered by
/// `public_display_summary_reports_not_authentic_for_forged_signature`.
#[test]
fn public_display_summary_reports_not_authentic_for_parse_failed_footer() {
    let temp = TestDir::new("tzap_display_forged");
    let archive = temp.path("forged.tzap");
    let (root_cert, root_key) = test_ca_cert("ZManager Forged Root CA");
    let (signer_cert, _signer_key) = test_leaf_cert("ZManager Forged Signer", root_cert.as_ref(), root_key.as_ref());
    let written = write_archive_with_root_auth(
        &[RegularFile::new("forged.txt", b"forged payload")],
        &crate::tzap::write::placeholder_master_key().unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig {
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity: &signer_cert.to_der().unwrap(),
            authenticator_value_length: 256,
        },
        // A signature no real key ever produced; inspection must report the
        // footer not authentic rather than treat it as signed.
        |_| Ok(vec![0u8; 256]),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert!(matches!(summary.signature, TzapPublicSignatureStatus::NotAuthentic { .. }), "expected not-authentic status, got {:?}", summary.signature);
}

#[test]
fn public_display_summary_reports_unavailable_for_non_x509_footer() {
    let temp = TestDir::new("tzap_display_non_x509");
    let archive = temp.path("signed.tzap");
    let written = write_archive_with_root_auth(
        &[RegularFile::new("plain.txt", b"generic signing profile")],
        &crate::tzap::write::placeholder_master_key().unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig { authenticator_id: 0x7777, signer_identity_type: 1, signer_identity: b"test signer", authenticator_value_length: 32 },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert!(matches!(summary.signature, TzapPublicSignatureStatus::Unavailable { .. }), "expected unavailable status, got {:?}", summary.signature);
}

#[test]
fn public_display_summary_reports_unavailable_for_unsupported_signer_identity_type() {
    let temp = TestDir::new("tzap_display_identity_type");
    let archive = temp.path("signed.tzap");
    let written = write_archive_with_root_auth(
        &[RegularFile::new("plain.txt", b"unsupported identity profile")],
        &crate::tzap::write::placeholder_master_key().unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig {
            authenticator_id: X509_AUTHENTICATOR_ID,
            // X.509 authenticator with a signer identity type the X.509
            // profile does not define; a validly signed footer must be
            // reported unavailable (not an X.509 profile), never not-authentic
            // (implying forgery). `DER_CERT` is type 2; use a type outside
            // the profile.
            signer_identity_type: 3,
            signer_identity: b"not a der certificate",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    let TzapPublicSignatureStatus::Unavailable { reason } = &summary.signature else {
        panic!("expected unavailable status, got {:?}", summary.signature);
    };
    assert!(reason.contains("identity type"), "expected identity-type reason, got {reason:?}");
}

#[test]
fn public_display_summary_reports_unavailable_for_corrupt_terminal() {
    let temp = TestDir::new("tzap_display_corrupt");
    let archive = temp.path("corrupt.tzap");
    let written = create_test_tzap_archive(&[RegularFile::new("plain.txt", b"corrupt terminal")]);
    let mut bytes = written.volumes[0].clone();
    // Destroy the CMRA image body beyond GF16 repair capacity (parity + 1
    // shards), mirroring the tzap-core tampered-terminal fixture. The header,
    // boundary magic, and locators stay intact so every recovery path is
    // attempted — and must fail. `cmra_length` is the serialized shard region
    // length; `cmra_image_length` is only the unsharded image and would cap
    // the corruption short of the last shards on small fixtures.
    let locator = CriticalRecoveryLocator::parse(&bytes[bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN..]).unwrap();
    let locator_offset = usize::try_from(locator.cmra_offset).expect("CMRA offset fits usize");
    let kill_shards = usize::from(locator.cmra_parity_shard_count) + 1;
    let start = locator_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN;
    let end = (start + kill_shards * locator.cmra_shard_size as usize).min(locator_offset + locator.cmra_length as usize);
    for byte in &mut bytes[start..end] {
        *byte ^= 0x55;
    }
    fs::write(&archive, bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert!(matches!(summary.signature, TzapPublicSignatureStatus::Unavailable { .. }), "expected unavailable status, got {:?}", summary.signature);
}

/// The footer embeds cert A's DER while the authenticator value is a real
/// signature from an unrelated key (cert B). The signature is internally
/// valid; verification must fail because the embedded certificate and the
/// signing key do not match.
#[test]
fn public_display_summary_reports_not_authentic_for_forged_signature() {
    let temp = TestDir::new("tzap_display_forged_signature");
    let archive = temp.path("forged.tzap");
    let (root_cert, root_key) = test_ca_cert("ZManager Forged Root CA");
    let (embedded_cert, _embedded_key) = test_leaf_cert("ZManager Embedded Signer", root_cert.as_ref(), root_key.as_ref());
    let (forger_cert, forger_key) = test_leaf_cert("ZManager Forger", root_cert.as_ref(), root_key.as_ref());
    let forger =
        X509RootAuthSigner::from_pem_or_der(&forger_cert.to_pem().unwrap(), &forger_key.private_key_to_pem_pkcs8().unwrap(), Vec::new(), 1_700_000_000)
            .unwrap();
    let written = write_archive_with_root_auth(
        &[RegularFile::new("forged.txt", b"forged payload")],
        &crate::tzap::write::placeholder_master_key().unwrap(),
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() },
        RootAuthWriterConfig {
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity: &embedded_cert.to_der().unwrap(),
            authenticator_value_length: forger.authenticator_value_length().unwrap(),
        },
        |request| forger.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed")),
    )
    .unwrap();
    fs::write(&archive, written.bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    let TzapPublicSignatureStatus::NotAuthentic { reason } = &summary.signature else {
        panic!("expected not-authentic status, got {:?}", summary.signature);
    };
    assert_eq!(reason, "X.509 RootAuth signature failed");
}

#[test]
fn public_display_summary_reports_unavailable_for_missing_volume() {
    let temp = TestDir::new("tzap_display_missing_volume");
    let signer = test_x509_root_auth_signer("ZManager Missing Volume Signer");
    let written = write_signed_test_archive(&[RegularFile::new("payload.txt", b"stripe payload")], 4, &signer);
    for index in [0usize, 1, 3] {
        fs::write(temp.path(format!("sample.vol{index:03}.tzap")), &written.volumes[index]).unwrap();
    }

    let summary = summarize_tzap_public_display(&temp.path("sample.vol000.tzap")).unwrap();
    assert_eq!(summary.metadata.present_volume_count, 3);
    assert_eq!(summary.metadata.missing_volume_indices, vec![2]);
    let TzapPublicSignatureStatus::Unavailable { reason } = &summary.signature else {
        panic!("expected unavailable status, got {:?}", summary.signature);
    };
    assert!(reason.contains("missing volume 2"), "unexpected reason: {reason}");
}

#[test]
fn public_display_summary_reports_signed_for_complete_multi_volume_set() {
    let temp = TestDir::new("tzap_display_multi_volume");
    let signer = test_x509_root_auth_signer("ZManager Multi Volume Signer");
    let written = write_signed_test_archive(&[RegularFile::new("payload.txt", b"stripe payload")], 4, &signer);
    for (index, volume) in written.volumes.iter().enumerate() {
        fs::write(temp.path(format!("sample.vol{index:03}.tzap")), volume).unwrap();
    }

    // Summarize through the non-existent base name: discovery must resolve
    // the volume set from the destination pattern, as the Finder plugin does.
    let summary = summarize_tzap_public_display(&temp.path("sample.tzap")).unwrap();
    assert_eq!(summary.metadata.expected_volume_count, 4);
    assert_eq!(summary.metadata.present_volume_count, 4);
    let TzapPublicSignatureStatus::Signed { signer } = &summary.signature else {
        panic!("expected signed status, got {:?}", summary.signature);
    };
    assert_eq!(signer.subject, "CN=ZManager Multi Volume Signer");
}

/// Corrupting vol000's CMRA region (parity + 1 shards, beyond GF16 repair
/// capacity) destroys the terminal on one volume of a two-volume set. The
/// display must report the status unavailable rather than claim `Signed`
/// from the surviving volume.
#[test]
fn public_display_summary_reports_unavailable_for_tampered_volume_footer() {
    let temp = TestDir::new("tzap_display_tampered_footer");
    let signer = test_x509_root_auth_signer("ZManager Tampered Signer");
    let written = write_signed_test_archive(&[RegularFile::new("payload.txt", b"stripe payload")], 2, &signer);
    let mut volume = written.volumes[0].clone();
    let locator = CriticalRecoveryLocator::parse(&volume[volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN..]).unwrap();
    let locator_offset = usize::try_from(locator.cmra_offset).expect("CMRA offset fits usize");
    let kill_shards = usize::from(locator.cmra_parity_shard_count) + 1;
    let start = locator_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN;
    let end = (start + kill_shards * locator.cmra_shard_size as usize).min(locator_offset + locator.cmra_length as usize);
    for byte in &mut volume[start..end] {
        *byte ^= 0x55;
    }
    fs::write(temp.path("sample.vol000.tzap"), &volume).unwrap();
    fs::write(temp.path("sample.vol001.tzap"), &written.volumes[1]).unwrap();

    let summary = summarize_tzap_public_display(&temp.path("sample.vol000.tzap")).unwrap();
    assert_eq!(summary.metadata.present_volume_count, 2);
    let TzapPublicSignatureStatus::Unavailable { reason } = &summary.signature else {
        panic!("expected unavailable status, got {:?}", summary.signature);
    };
    assert!(!reason.is_empty());
}

#[test]
fn public_display_summary_reports_unsigned_for_pre_v45_archive() {
    let temp = TestDir::new("tzap_display_pre_v45");
    let archive = temp.path("old.tzap");
    let signer = test_x509_root_auth_signer("ZManager Old Signer");
    let written = write_signed_test_archive(&[RegularFile::new("payload.txt", b"old format")], 1, &signer);
    let mut bytes = written.bytes;
    // Downgrade the volume format revision to 44 (pre-RootAuth) and fix the
    // volume header CRC. The footer pass must report Unsigned — a revision
    // predating RootAuth — not Unavailable.
    bytes[6..8].copy_from_slice(&44u16.to_le_bytes());
    let header_checksum = crc32c::crc32c(&bytes[..124]);
    bytes[124..128].copy_from_slice(&header_checksum.to_le_bytes());
    fs::write(&archive, &bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert_eq!(summary.metadata.format.volume_format_revision, 44);
    assert_eq!(summary.signature, TzapPublicSignatureStatus::Unsigned);
}

#[test]
fn public_display_summary_reports_unavailable_for_future_revision() {
    let temp = TestDir::new("tzap_display_future_revision");
    let archive = temp.path("future.tzap");
    let signer = test_x509_root_auth_signer("ZManager Future Signer");
    let written = write_signed_test_archive(&[RegularFile::new("payload.txt", b"future format")], 1, &signer);
    let mut bytes = written.bytes;
    // Bump the volume format revision past this build's supported maximum;
    // the footer cannot be located, so the status must be Unavailable with a
    // revision-aware reason — never Unsigned.
    bytes[6..8].copy_from_slice(&46u16.to_le_bytes());
    let header_checksum = crc32c::crc32c(&bytes[..124]);
    bytes[124..128].copy_from_slice(&header_checksum.to_le_bytes());
    fs::write(&archive, &bytes).unwrap();

    let summary = summarize_tzap_public_display(&archive).unwrap();
    assert_eq!(summary.metadata.format.volume_format_revision, 46);
    let TzapPublicSignatureStatus::Unavailable { reason } = &summary.signature else {
        panic!("expected unavailable status, got {:?}", summary.signature);
    };
    assert!(reason.contains("newer"), "unexpected reason: {reason}");
    assert!(reason.contains("46"), "unexpected reason: {reason}");
}

#[test]
fn create_tzap_embeds_chain_from_signing_certificate_bundle() {
    let temp = TestDir::new("tzap_x509_root_auth_bundle");
    let source = temp.path("payload.txt");
    let archive = temp.path("signed.tzap");
    let root_ca_path = temp.path("root-ca.pem");
    let signer_bundle_path = temp.path("signer-fullchain.pem");
    let signer_key_path = temp.path("signer.key");
    fs::write(&source, b"signed payload").unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (intermediate_cert, intermediate_key) = test_child_ca_cert("ZManager Test Intermediate CA", root_cert.as_ref(), root_key.as_ref());
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Test Signer", intermediate_cert.as_ref(), intermediate_key.as_ref());
    fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
    let mut signer_bundle = signer_cert.to_pem().unwrap();
    signer_bundle.extend(intermediate_cert.to_pem().unwrap());
    fs::write(&signer_bundle_path, signer_bundle).unwrap();
    fs::write(&signer_key_path, signer_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 14,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 14,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::CertificateAndKey {
            signing_certificate: signer_bundle_path,
            signing_private_key: signer_key_path,
            signing_chain: Vec::new(),
        }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let trust = TzapX509TrustOptions { trusted_ca_certificates: vec![root_ca_path], trusted_system_roots: false, include_official_tzap_root: false };
    let report = test_tzap_with_password_filter_and_x509_trust(&archive, "secret", |_| true, Some(&trust)).unwrap();
    let root_auth = report.x509_root_auth.unwrap();

    assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
    assert_eq!(root_auth.issuer, "CN=ZManager Test Intermediate CA");
    assert_eq!(
        root_auth.verified_chain_subjects,
        vec!["CN=ZManager Test Signer".to_owned(), "CN=ZManager Test Intermediate CA".to_owned(), "CN=ZManager Test Root CA".to_owned(),]
    );
    assert_eq!(root_auth.trust_anchor_subject.as_deref(), Some("CN=ZManager Test Root CA"));
}

#[test]
fn create_tzap_signs_with_pkcs12_identity() {
    let temp = TestDir::new("tzap_x509_root_auth_p12");
    let source = temp.path("payload.txt");
    let archive = temp.path("signed.tzap");
    let root_ca_path = temp.path("root-ca.pem");
    let identity_path = temp.path("signer.p12");
    fs::write(&source, b"signed payload").unwrap();

    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (intermediate_cert, intermediate_key) = test_child_ca_cert("ZManager Test Intermediate CA", root_cert.as_ref(), root_key.as_ref());
    let (signer_cert, signer_key) = test_leaf_cert("ZManager Test Signer", intermediate_cert.as_ref(), intermediate_key.as_ref());
    fs::write(&root_ca_path, root_cert.to_pem().unwrap()).unwrap();
    let mut chain = Stack::new().unwrap();
    chain.push(intermediate_cert).unwrap();
    let identity = Pkcs12::builder().name("ZManager Test Signer").pkey(&signer_key).cert(&signer_cert).ca(chain).build2("identity-password").unwrap();
    fs::write(&identity_path, identity.to_der().unwrap()).unwrap();

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size: 14,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: 14,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let options = TzapCreateOptions {
        key_source: TzapKeySource::Passphrase(SecretString::from("secret")),
        level: 1,
        preserve_metadata: true,
        replace_existing: false,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        x509_signing: Some(TzapX509SigningOptions::Pkcs12 { identity: identity_path, password: SecretString::from("identity-password") }),
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let trust = TzapX509TrustOptions { trusted_ca_certificates: vec![root_ca_path], trusted_system_roots: false, include_official_tzap_root: false };
    let report = test_tzap_with_password_filter_and_x509_trust(&archive, "secret", |_| true, Some(&trust)).unwrap();
    let root_auth = report.x509_root_auth.unwrap();

    assert_eq!(root_auth.subject, "CN=ZManager Test Signer");
    assert_eq!(root_auth.issuer, "CN=ZManager Test Intermediate CA");
    assert_eq!(root_auth.trust_anchor_subject.as_deref(), Some("CN=ZManager Test Root CA"));
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn preserves_windows_file_directory_and_symlink_metadata_through_core() {
    use crate::archive_browser::{BrowserEntryKind, list_entries};

    const READONLY: u32 = 0x0000_0001;
    const HIDDEN: u32 = 0x0000_0002;
    const SYSTEM: u32 = 0x0000_0004;
    const ARCHIVE: u32 = 0x0000_0020;
    const MUTABLE_ATTRIBUTES: u32 = READONLY | HIDDEN | SYSTEM | ARCHIVE;
    const WINDOWS_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

    let temp = TestDir::new("tzap-windows-core-metadata");
    let source_root = temp.path("project");
    let source_directory = temp.path("project/scripts");
    let source_file = temp.path("project/scripts/payload.txt");
    let source_link = temp.path("project/current.txt");
    fs::create_dir_all(&source_directory).unwrap();
    fs::write(&source_file, b"windows core metadata").unwrap();
    if let Err(error) = create_windows_relative_symlink(&source_link, r"scripts\payload.txt") {
        eprintln!("skipping Windows symlink metadata test: {error}");
        return;
    }
    fs::write(PathBuf::from(format!("{}:zmanager-core", source_file.display())), b"file alternate data").unwrap();
    fs::write(PathBuf::from(format!("{}:zmanager-core", source_directory.display())), b"directory alternate data").unwrap();

    let mut file_basic = windows_basic_info(&source_file, false, false);
    file_basic.CreationTime = WINDOWS_EPOCH_OFFSET - 40_000_000_000;
    file_basic.LastAccessTime = WINDOWS_EPOCH_OFFSET - 30_000_000_000;
    file_basic.LastWriteTime = WINDOWS_EPOCH_OFFSET - 20_000_000_000;
    file_basic.ChangeTime = WINDOWS_EPOCH_OFFSET - 10_000_000_000;
    file_basic.FileAttributes |= READONLY | HIDDEN | SYSTEM | ARCHIVE;
    set_windows_basic_info(&source_file, false, false, file_basic);

    let mut directory_basic = windows_basic_info(&source_directory, true, false);
    directory_basic.CreationTime = WINDOWS_EPOCH_OFFSET - 80_000_000_000;
    directory_basic.LastAccessTime = WINDOWS_EPOCH_OFFSET - 70_000_000_000;
    directory_basic.LastWriteTime = WINDOWS_EPOCH_OFFSET - 60_000_000_000;
    directory_basic.ChangeTime = WINDOWS_EPOCH_OFFSET - 50_000_000_000;
    directory_basic.FileAttributes |= HIDDEN | SYSTEM;
    set_windows_basic_info(&source_directory, true, false, directory_basic);

    let mut link_basic = windows_basic_info(&source_link, false, true);
    link_basic.CreationTime = WINDOWS_EPOCH_OFFSET - 120_000_000_000;
    link_basic.LastAccessTime = WINDOWS_EPOCH_OFFSET - 110_000_000_000;
    link_basic.LastWriteTime = WINDOWS_EPOCH_OFFSET - 100_000_000_000;
    link_basic.ChangeTime = WINDOWS_EPOCH_OFFSET - 90_000_000_000;
    link_basic.FileAttributes |= HIDDEN;
    set_windows_basic_info(&source_link, false, true, link_basic);

    let source_file_security = windows_security_descriptor(&source_file, false);
    let source_directory_security = windows_security_descriptor(&source_directory, true);
    let source_link_security = windows_security_descriptor(&source_link, false);

    let entries = vec![
        ManifestEntry {
            archive_path: "project".to_owned(),
            source_path: source_root.clone(),
            file_type: ManifestFileType::Directory,
            size: 0,
            modified: fs::symlink_metadata(&source_root).unwrap().modified().ok(),
            permissions: PermissionSnapshot { readonly: false, unix_mode: None },
            symlink_target: None,
        },
        ManifestEntry {
            archive_path: "project/scripts".to_owned(),
            source_path: source_directory.clone(),
            file_type: ManifestFileType::Directory,
            size: 0,
            modified: fs::symlink_metadata(&source_directory).unwrap().modified().ok(),
            permissions: PermissionSnapshot { readonly: false, unix_mode: None },
            symlink_target: None,
        },
        ManifestEntry {
            archive_path: "project/scripts/payload.txt".to_owned(),
            source_path: source_file.clone(),
            file_type: ManifestFileType::File,
            size: b"windows core metadata".len() as u64,
            modified: fs::symlink_metadata(&source_file).unwrap().modified().ok(),
            permissions: PermissionSnapshot { readonly: true, unix_mode: None },
            symlink_target: None,
        },
        ManifestEntry {
            archive_path: "project/current.txt".to_owned(),
            source_path: source_link.clone(),
            file_type: ManifestFileType::Symlink,
            size: 0,
            modified: fs::symlink_metadata(&source_link).unwrap().modified().ok(),
            permissions: PermissionSnapshot { readonly: false, unix_mode: None },
            symlink_target: Some(PathBuf::from(r"scripts\payload.txt")),
        },
    ];
    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries,
        total_bytes: b"windows core metadata".len() as u64,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };
    let archive = temp.path("metadata.tzap");
    let options = public_metadata_create_options();
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_entries(&archive).unwrap();
    let listed_file = listing.entries.iter().find(|entry| entry.path == "project/scripts/payload.txt").unwrap();
    assert_eq!(listed_file.kind, BrowserEntryKind::File);
    assert!(listed_file.created.is_some());
    assert!(listed_file.accessed.is_some());
    assert!(listed_file.attributes.is_some());
    let listed_directory = listing.entries.iter().find(|entry| entry.path == "project/scripts").unwrap();
    assert_eq!(listed_directory.kind, BrowserEntryKind::Directory);
    assert!(listed_directory.created.is_some());
    assert!(listed_directory.accessed.is_some());
    assert!(listed_directory.attributes.is_some());
    let listed_link = listing.entries.iter().find(|entry| entry.path == "project/current.txt").unwrap();
    assert_eq!(listed_link.kind, BrowserEntryKind::Symlink);
    assert_eq!(listed_link.link_target.as_deref(), Some("scripts/payload.txt"));

    let policies: &[TzapRestorePolicy] = if windows_process_is_elevated() {
        &[TzapRestorePolicy::Portable, TzapRestorePolicy::SameOs, TzapRestorePolicy::System]
    } else {
        &[TzapRestorePolicy::Portable, TzapRestorePolicy::SameOs]
    };
    for &policy in policies {
        let policy_name = match policy {
            TzapRestorePolicy::Portable => "portable",
            TzapRestorePolicy::SameOs => "same-os",
            TzapRestorePolicy::System => "system",
            TzapRestorePolicy::Content => unreachable!(),
        };
        let destination = temp.path(format!("restore-{policy_name}"));
        extract_tzap(
            TzapExtractRequest {
                key: TzapExtractKeySource::None,
                policy: ExtractionPolicy::default(),
                restore_options: TzapRestoreOptions {
                    policy,
                    // Portable metadata intentionally excludes Windows
                    // HIDDEN/SYSTEM/ARCHIVE attributes.
                    allow_degraded: policy == TzapRestorePolicy::Portable,
                    allow_absolute_symlinks: false,
                },
                overwrite_resolver: None,
                context: None,
                fast: false,
            },
            &archive,
            &destination,
        )
        .unwrap();

        let restored_file = destination.join("project/scripts/payload.txt");
        let restored_directory = destination.join("project/scripts");
        let restored_link = destination.join("project/current.txt");
        let actual_file_basic = windows_basic_info(&restored_file, false, false);
        let actual_directory_basic = windows_basic_info(&restored_directory, true, false);
        let actual_link_basic = windows_basic_info(&restored_link, false, true);
        assert_eq!(fs::read(&restored_file).unwrap(), b"windows core metadata");
        assert_eq!(fs::read_link(&restored_link).unwrap(), PathBuf::from("scripts/payload.txt"));
        let expected_attribute_mask = if policy == TzapRestorePolicy::Portable { READONLY } else { MUTABLE_ATTRIBUTES };
        assert_eq!(actual_file_basic.FileAttributes & expected_attribute_mask, file_basic.FileAttributes & expected_attribute_mask);
        assert_eq!(actual_directory_basic.FileAttributes & expected_attribute_mask, directory_basic.FileAttributes & expected_attribute_mask);
        assert_eq!(actual_file_basic.LastWriteTime, file_basic.LastWriteTime);
        assert_eq!(actual_directory_basic.LastWriteTime, directory_basic.LastWriteTime);
        assert_eq!(actual_link_basic.LastWriteTime, link_basic.LastWriteTime);

        let restored_file_ads = PathBuf::from(format!("{}:zmanager-core", restored_file.display()));
        let restored_directory_ads = PathBuf::from(format!("{}:zmanager-core", restored_directory.display()));
        if policy == TzapRestorePolicy::Portable {
            assert!(fs::read(&restored_file_ads).is_err());
            assert!(fs::read(&restored_directory_ads).is_err());
        } else {
            assert_eq!(fs::read(&restored_file_ads).unwrap(), b"file alternate data");
            assert_eq!(fs::read(&restored_directory_ads).unwrap(), b"directory alternate data");
            for (actual, expected) in [(actual_file_basic, file_basic), (actual_directory_basic, directory_basic), (actual_link_basic, link_basic)] {
                assert_eq!(actual.CreationTime, expected.CreationTime);
                assert_eq!(actual.LastAccessTime, expected.LastAccessTime);
                assert_eq!(actual.LastWriteTime, expected.LastWriteTime);
                assert_eq!(actual.ChangeTime, expected.ChangeTime);
            }
        }
        if policy == TzapRestorePolicy::System {
            for (actual_path, directory, expected) in [
                (&restored_file, false, &source_file_security),
                (&restored_directory, true, &source_directory_security),
                (&restored_link, false, &source_link_security),
            ] {
                let actual = windows_security_descriptor(actual_path, directory);
                assert!(windows_security_descriptors_equivalent(expected, &actual), "security descriptor mismatch for {}", actual_path.display());
            }
        }

        let mut cleanup_file_basic = actual_file_basic;
        cleanup_file_basic.FileAttributes &= !READONLY;
        set_windows_basic_info(&restored_file, false, false, cleanup_file_basic);
    }

    file_basic.FileAttributes &= !READONLY;
    set_windows_basic_info(&source_file, false, false, file_basic);
}

#[test]
#[allow(clippy::too_many_lines)]
fn preserves_all_metadata_in_tzap_round_trip() {
    use crate::archive_browser::list_entries;

    let temp = TestDir::new("tzap_metadata_roundtrip");

    let file_path = temp.path("data.bin");
    let directory_path = temp.path("folder");
    let payload = b"round-trip payload";
    fs::write(&file_path, payload).unwrap();
    fs::create_dir(&directory_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&directory_path, fs::Permissions::from_mode(0o750)).unwrap();
    }

    #[cfg(target_os = "macos")]
    {
        xattr::set(&file_path, "com.tzap.test", b"zmanager metadata").unwrap();
        xattr::set(&directory_path, "com.tzap.test", b"zmanager directory metadata").unwrap();
        xattr::set(&file_path, "com.apple.FinderInfo", &[0x5a; 32]).unwrap();
        xattr::set(&directory_path, "com.apple.FinderInfo", &[0x5b; 32]).unwrap();
        fs::write(file_path.join("..namedfork/rsrc"), vec![0x6b; 2 * 1024 * 1024 + 31]).unwrap();
        let acl_status = std::process::Command::new("/bin/chmod").args(["+a", "everyone deny delete"]).arg(&file_path).status().expect("failed to set ACL");
        assert!(acl_status.success(), "chmod +a failed");
        let directory_acl_status =
            std::process::Command::new("/bin/chmod").args(["+a", "everyone deny delete"]).arg(&directory_path).status().expect("failed to set directory ACL");
        assert!(directory_acl_status.success(), "directory chmod +a failed");
        let status = std::process::Command::new("/usr/bin/chflags").arg("hidden").arg(&file_path).status().expect("failed to run chflags");
        assert!(status.success(), "chflags failed");
        let directory_status =
            std::process::Command::new("/usr/bin/chflags").arg("hidden").arg(&directory_path).status().expect("failed to run directory chflags");
        assert!(directory_status.success(), "directory chflags failed");
    }

    #[cfg(target_os = "linux")]
    let (expected_file_acl, expected_directory_acl) = {
        let file_acl = [
            2, 0, 0, 0, // POSIX ACL xattr version
            1, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // owning user
            2, 0, 4, 0, 0x39, 0x30, 0, 0, // named user 12345
            4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // owning group
            0x10, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // mask
            0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // other
        ];
        let mut directory_acl = file_acl;
        directory_acl[6] = 7;
        directory_acl[14] = 5;
        directory_acl[22] = 5;
        directory_acl[30] = 5;
        xattr::set(&file_path, "user.zmanager.test", b"file metadata").unwrap();
        xattr::set(&directory_path, "user.zmanager.test", b"directory metadata").unwrap();
        xattr::set(&file_path, "system.posix_acl_access", &file_acl).unwrap();
        xattr::set(&directory_path, "system.posix_acl_access", &directory_acl).unwrap();
        (xattr::get(&file_path, "system.posix_acl_access").unwrap().unwrap(), xattr::get(&directory_path, "system.posix_acl_access").unwrap().unwrap())
    };

    #[cfg(unix)]
    let symlink_target = "data.bin";
    #[cfg(unix)]
    let symlink_path = {
        let p = temp.path("link.txt");
        std::os::unix::fs::symlink(symlink_target, &p).unwrap();
        #[cfg(target_os = "macos")]
        {
            xattr::set(&p, "com.tzap.link", b"zmanager link metadata").unwrap();
            assert!(std::process::Command::new("/bin/chmod").args(["-h", "+a", "everyone deny delete"]).arg(&p).status().unwrap().success());
            assert!(std::process::Command::new("/usr/bin/chflags").args(["-h", "hidden"]).arg(&p).status().unwrap().success());
        }
        p
    };

    let file_modified = fs::metadata(&file_path).unwrap().modified().ok();

    let mut entries = vec![ManifestEntry {
        archive_path: "data.bin".to_owned(),
        source_path: file_path.clone(),
        file_type: ManifestFileType::File,
        size: payload.len() as u64,
        modified: file_modified,
        permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o640) },
        symlink_target: None,
    }];
    entries.push(ManifestEntry {
        archive_path: "folder".to_owned(),
        source_path: directory_path.clone(),
        file_type: ManifestFileType::Directory,
        size: 0,
        modified: fs::symlink_metadata(&directory_path).unwrap().modified().ok(),
        permissions: PermissionSnapshot {
            readonly: false,
            #[cfg(unix)]
            unix_mode: Some(0o750),
            #[cfg(not(unix))]
            unix_mode: None,
        },
        symlink_target: None,
    });
    #[cfg(unix)]
    entries.push({
        let sym_modified = fs::symlink_metadata(&symlink_path).unwrap().modified().ok();
        ManifestEntry {
            archive_path: "link.txt".to_owned(),
            source_path: symlink_path.clone(),
            file_type: ManifestFileType::Symlink,
            size: 0,
            modified: sym_modified,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o777) },
            symlink_target: Some(symlink_target.into()),
        }
    });

    let manifest = ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries,
        total_bytes: payload.len() as u64,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    };

    let archive = temp.path("metadata.tzap");
    let options = TzapCreateOptions {
        level: 1,
        volume_size: None,
        volume_count: None,
        recovery_percentage: 0,
        volume_loss_tolerance: 0,
        preserve_metadata: true,
        replace_existing: true,
        key_source: TzapKeySource::NoPassword,
        x509_signing: None,
        emit_bootstrap_sidecar: false,
    };
    let token = CancellationToken::new();
    let mut events = |_| {};
    let mut context = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive, &options, &mut context).unwrap();

    let listing = list_entries(&archive).unwrap();
    let file_entry = listing.entries.iter().find(|e| e.path == "data.bin").unwrap();

    // --- name ---
    assert_eq!(file_entry.path, "data.bin");

    // --- kind ---
    assert_eq!(file_entry.kind, crate::archive_browser::BrowserEntryKind::File);

    // --- size ---
    assert_eq!(file_entry.size, Some(payload.len() as u64));

    // --- modified ---
    assert!(file_entry.modified.is_some(), "modified timestamp");

    // --- created ---
    // Always present: the writer falls back to ctime when the platform
    // cannot expose the birth time (musl).
    assert!(file_entry.created.is_some(), "created timestamp");

    // --- accessed ---
    assert!(file_entry.accessed.is_some(), "accessed timestamp");

    // --- Unix metadata ---
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        // mode
        assert_eq!(file_entry.mode, Some(0o640), "file mode");

        // uid / gid
        let source_file_metadata = fs::symlink_metadata(&file_path).unwrap();
        assert_eq!(file_entry.uid, Some(source_file_metadata.uid()));
        assert_eq!(file_entry.gid, Some(source_file_metadata.gid()));

        // owner / group — name resolution
        assert!(file_entry.owner.is_some(), "owner name should be resolved from uid");
        assert!(file_entry.group.is_some(), "group name should be resolved from gid");

        let directory = listing.entries.iter().find(|entry| entry.path == "folder").unwrap();
        assert_eq!(directory.kind, crate::archive_browser::BrowserEntryKind::Directory);
        assert_eq!(directory.mode, Some(0o750));
        assert_eq!(directory.uid, file_entry.uid);
        assert_eq!(directory.gid, file_entry.gid);
        assert_eq!(directory.owner, file_entry.owner);
        assert_eq!(directory.group, file_entry.group);

        // symlink
        let sym = listing.entries.iter().find(|e| e.path == "link.txt").unwrap();
        assert_eq!(sym.kind, crate::archive_browser::BrowserEntryKind::Symlink, "symlink kind");
        assert_eq!(sym.mode, Some(0o777), "symlink mode");
        assert_eq!(sym.link_target.as_deref(), Some(symlink_target), "link target");
        assert!(sym.uid.is_some(), "symlink uid");
        assert!(sym.gid.is_some(), "symlink gid");
    }

    // --- exact platform attributes ---
    #[cfg(target_os = "macos")]
    if let Some(ref attrs_hex) = file_entry.attributes {
        let hex = attrs_hex.strip_prefix("0x").unwrap_or(attrs_hex);
        let attrs = u32::from_str_radix(hex, 16).expect("valid hex");
        {
            use std::os::macos::fs::MetadataExt as _;
            assert_eq!(attrs, fs::metadata(&file_path).unwrap().st_flags());
        }
    }

    let portable_destination = temp.path("portable-extract");
    extract_tzap(
        TzapExtractRequest {
            key: TzapExtractKeySource::None,
            policy: ExtractionPolicy::default(),
            restore_options: TzapRestoreOptions::default(),
            overwrite_resolver: None,
            context: None,
            fast: false,
        },
        &archive,
        &portable_destination,
    )
    .expect("portable extraction must not reject native flags");
    assert_eq!(fs::read(portable_destination.join("data.bin")).unwrap(), payload);
    assert!(portable_destination.join("folder").is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        assert_eq!(fs::symlink_metadata(portable_destination.join("data.bin")).unwrap().permissions().mode() & 0o7777, 0o640);
        assert_eq!(fs::symlink_metadata(portable_destination.join("folder")).unwrap().permissions().mode() & 0o7777, 0o750);
        assert_eq!(fs::read_link(portable_destination.join("link.txt")).unwrap(), std::path::Path::new(symlink_target));
        let restored = fs::symlink_metadata(portable_destination.join("data.bin")).unwrap();
        let source = fs::symlink_metadata(&file_path).unwrap();
        assert_eq!((restored.mtime(), restored.mtime_nsec()), (source.mtime(), source.mtime_nsec()));
    }
    #[cfg(target_os = "macos")]
    {
        assert_eq!(xattr::get(portable_destination.join("data.bin"), "com.tzap.test").unwrap(), None);
        assert_eq!(xattr::get(portable_destination.join("folder"), "com.tzap.test").unwrap(), None);
        assert_eq!(xattr::get(portable_destination.join("link.txt"), "com.tzap.link").unwrap(), None);
    }
    #[cfg(target_os = "linux")]
    {
        assert_eq!(xattr::get(portable_destination.join("data.bin"), "user.zmanager.test").unwrap(), None);
        assert_eq!(xattr::get(portable_destination.join("folder"), "user.zmanager.test").unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as _;

        let native_destination = temp.path("native-extract");
        extract_tzap(
            TzapExtractRequest {
                key: TzapExtractKeySource::None,
                policy: ExtractionPolicy::default(),
                restore_options: TzapRestoreOptions { policy: TzapRestorePolicy::SameOs, allow_degraded: false, allow_absolute_symlinks: false },
                overwrite_resolver: None,
                context: None,
                fast: false,
            },
            &archive,
            &native_destination,
        )
        .expect("same-OS extraction");

        let restored = native_destination.join("data.bin");
        let restored_directory = native_destination.join("folder");
        let restored_link = native_destination.join("link.txt");
        assert_eq!(fs::metadata(&restored).unwrap().st_flags(), fs::metadata(&file_path).unwrap().st_flags());
        assert_eq!(fs::symlink_metadata(&restored_directory).unwrap().st_flags(), fs::symlink_metadata(&directory_path).unwrap().st_flags());
        assert_eq!(fs::symlink_metadata(&restored_link).unwrap().st_flags(), fs::symlink_metadata(&symlink_path).unwrap().st_flags());
        assert_eq!(
            (fs::metadata(&restored).unwrap().st_birthtime(), fs::metadata(&restored).unwrap().st_birthtime_nsec(),),
            (fs::metadata(&file_path).unwrap().st_birthtime(), fs::metadata(&file_path).unwrap().st_birthtime_nsec(),)
        );
        assert_eq!(xattr::get(&restored, "com.tzap.test").unwrap().as_deref(), Some(b"zmanager metadata".as_slice()));
        assert_eq!(xattr::get(&restored_directory, "com.tzap.test").unwrap().as_deref(), Some(b"zmanager directory metadata".as_slice()));
        assert_eq!(xattr::get(&restored_link, "com.tzap.link").unwrap().as_deref(), Some(b"zmanager link metadata".as_slice()));
        assert_eq!(xattr::get(&restored, "com.apple.FinderInfo").unwrap().as_deref(), Some([0x5a; 32].as_slice()));
        assert_eq!(xattr::get(&restored_directory, "com.apple.FinderInfo").unwrap().as_deref(), Some([0x5b; 32].as_slice()));
        assert_eq!(fs::read(restored.join("..namedfork/rsrc")).unwrap(), vec![0x6b; 2 * 1024 * 1024 + 31]);
        for restored_path in [&restored, &restored_directory, &restored_link] {
            let acl = std::process::Command::new("/bin/ls").args(["-lde"]).arg(restored_path).output().unwrap();
            assert!(acl.status.success());
            assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
        }

        if unix_process_is_elevated() {
            let system_destination = temp.path("system-extract");
            extract_tzap(
                TzapExtractRequest {
                    key: TzapExtractKeySource::None,
                    policy: ExtractionPolicy::default(),
                    restore_options: TzapRestoreOptions { policy: TzapRestorePolicy::System, allow_degraded: false, allow_absolute_symlinks: false },
                    overwrite_resolver: None,
                    context: None,
                    fast: false,
                },
                &archive,
                &system_destination,
            )
            .expect("system extraction");
            for (relative, source) in [("data.bin", &file_path), ("folder", &directory_path), ("link.txt", &symlink_path)] {
                use std::os::unix::fs::MetadataExt as _;
                let actual = fs::symlink_metadata(system_destination.join(relative)).unwrap();
                let expected = fs::symlink_metadata(source).unwrap();
                assert_eq!(actual.uid(), expected.uid());
                assert_eq!(actual.gid(), expected.gid());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let policies: &[TzapRestorePolicy] =
            if unix_process_is_elevated() { &[TzapRestorePolicy::SameOs, TzapRestorePolicy::System] } else { &[TzapRestorePolicy::SameOs] };
        for &policy in policies {
            let destination = temp.path(match policy {
                TzapRestorePolicy::SameOs => "linux-same-os-extract",
                TzapRestorePolicy::System => "linux-system-extract",
                _ => unreachable!(),
            });
            extract_tzap(
                TzapExtractRequest {
                    key: TzapExtractKeySource::None,
                    policy: ExtractionPolicy::default(),
                    restore_options: TzapRestoreOptions {
                        policy,
                        // Linux birth time is captured when available but is
                        // not generally assignable by the kernel.
                        allow_degraded: true,
                        allow_absolute_symlinks: false,
                    },
                    overwrite_resolver: None,
                    context: None,
                    fast: false,
                },
                &archive,
                &destination,
            )
            .unwrap();
            let restored_file = fs::symlink_metadata(destination.join("data.bin")).unwrap();
            let restored_directory = fs::symlink_metadata(destination.join("folder")).unwrap();
            let restored_link = fs::symlink_metadata(destination.join("link.txt")).unwrap();
            assert_eq!(restored_file.permissions().mode() & 0o7777, 0o640);
            assert_eq!(restored_directory.permissions().mode() & 0o7777, 0o750);
            assert!(restored_link.file_type().is_symlink());
            assert_eq!(fs::read_link(destination.join("link.txt")).unwrap(), std::path::Path::new(symlink_target));
            assert_eq!(xattr::get(destination.join("data.bin"), "user.zmanager.test").unwrap().as_deref(), Some(b"file metadata".as_slice()));
            assert_eq!(xattr::get(destination.join("folder"), "user.zmanager.test").unwrap().as_deref(), Some(b"directory metadata".as_slice()));
            assert_eq!(xattr::get(destination.join("data.bin"), "system.posix_acl_access").unwrap().as_deref(), Some(expected_file_acl.as_slice()));
            assert_eq!(xattr::get(destination.join("folder"), "system.posix_acl_access").unwrap().as_deref(), Some(expected_directory_acl.as_slice()));
            if policy == TzapRestorePolicy::System {
                for (actual, source) in [
                    (restored_file, fs::symlink_metadata(&file_path).unwrap()),
                    (restored_directory, fs::symlink_metadata(&directory_path).unwrap()),
                    (restored_link, fs::symlink_metadata(&symlink_path).unwrap()),
                ] {
                    assert_eq!(actual.uid(), source.uid());
                    assert_eq!(actual.gid(), source.gid());
                }
            }
        }
    }
}

fn create_test_tzap_archive(files: &[RegularFile<'_>]) -> tzap_core::writer::WrittenArchive {
    let kdf = KdfParams::Argon2id { t_cost: 1, m_cost_kib: 8, parallelism: 1, salt: b"12345678".to_vec() };
    let key = MasterKey::derive_from_passphrase(&kdf, "secret").unwrap();
    let options = WriterOptions { stripe_width: 4, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, zstd_level: 1, ..WriterOptions::default() };
    write_archive_with_kdf(files, &key, options, &kdf).unwrap()
}

/// Builds a throwaway root CA + leaf signer pair and returns the leaf signer,
/// whose `signer_identity()` embeds the leaf certificate DER.
fn test_x509_root_auth_signer(signer_name: &str) -> X509RootAuthSigner {
    let (root_cert, root_key) = test_ca_cert("ZManager Test Root CA");
    let (leaf_cert, leaf_key) = test_leaf_cert(signer_name, root_cert.as_ref(), root_key.as_ref());
    X509RootAuthSigner::from_pem_or_der(&leaf_cert.to_pem().unwrap(), &leaf_key.private_key_to_pem_pkcs8().unwrap(), Vec::new(), 1_700_000_000).unwrap()
}

/// Writes a stripe-N archive whose volumes carry an X.509 `RootAuth` footer
/// produced by `signer`.
fn write_signed_test_archive(files: &[RegularFile<'_>], stripe_width: u32, signer: &X509RootAuthSigner) -> tzap_core::writer::WrittenArchive {
    let options = WriterOptions { stripe_width, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, zstd_level: 1, ..WriterOptions::default() };
    write_archive_with_root_auth(files, &crate::tzap::write::placeholder_master_key().unwrap(), options, signer.root_auth_writer_config().unwrap(), |request| {
        signer.authenticator_value_for_request(request).map_err(|_| FormatError::InvalidArchive("X.509 RootAuth signer failed"))
    })
    .unwrap()
}

fn single_file_manifest(temp: &TestDir, source: PathBuf, size: u64) -> ArchiveManifest {
    ArchiveManifest {
        root: temp.root().to_path_buf(),
        entries: vec![ManifestEntry {
            archive_path: "payload.txt".to_owned(),
            source_path: source,
            file_type: ManifestFileType::File,
            size,
            modified: None,
            permissions: PermissionSnapshot { readonly: false, unix_mode: Some(0o644) },
            symlink_target: None,
        }],
        total_bytes: size,
        excluded_entries: Vec::new(),
        excluded_bytes: 0,
        warnings: Vec::new(),
    }
}

fn test_ca_cert(common_name: &str) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn test_child_ca_cert(common_name: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn test_leaf_cert(common_name: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn test_p256_recipient_cert(common_name: &str) -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_agreement().digital_signature().build().unwrap()).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

fn random_serial_number() -> openssl::asn1::Asn1Integer {
    let mut serial = BigNum::new().unwrap();
    serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
    serial.to_asn1_integer().unwrap()
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index.wrapping_mul(31).wrapping_add(17)) % 251).expect("deterministic byte is reduced below u8::MAX")).collect()
}

/// Deterministic but effectively incompressible byte content (xorshift64),
/// for tests that need the compressed archive size to stay close to the
/// logical payload size.
fn pseudo_random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn public_metadata_create_options() -> TzapCreateOptions {
    TzapCreateOptions {
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
    }
}

#[test]
fn tzap_create_sidecar_toggle_behavior() {
    let temp = TestDir::new("tzap_sidecar_toggle");
    let source = temp.path("payload.txt");
    fs::write(&source, b"test content").unwrap();

    // 1. Without sidecar
    let archive_no_sidecar = temp.path("no_sidecar.tzap");
    let sidecar_no_sidecar = temp.path("no_sidecar.sidecar");
    let manifest = single_file_manifest(&temp, source.clone(), 12);
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
    create_tzap_from_manifest_with_context(&manifest, &archive_no_sidecar, &options, &mut context).unwrap();

    assert!(archive_no_sidecar.exists());
    assert!(!sidecar_no_sidecar.exists(), "sidecar should NOT be created when emit_bootstrap_sidecar is false");

    // Verify it still opens and reads properly
    let listing = list_tzap_with_optional_password(&archive_no_sidecar, None).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, "payload.txt");

    // 2. With sidecar
    let archive_with_sidecar = temp.path("with_sidecar.tzap");
    let sidecar_with_sidecar = temp.path("with_sidecar.sidecar");
    let options_with_sidecar = TzapCreateOptions { emit_bootstrap_sidecar: true, ..options };
    let mut context_sidecar = JobContext::new(&token, &mut events);
    create_tzap_from_manifest_with_context(&manifest, &archive_with_sidecar, &options_with_sidecar, &mut context_sidecar).unwrap();

    assert!(archive_with_sidecar.exists());
    assert!(sidecar_with_sidecar.exists(), "sidecar SHOULD be created when emit_bootstrap_sidecar is true");
    assert!(fs::metadata(&sidecar_with_sidecar).unwrap().len() > 0);
}
