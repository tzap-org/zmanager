mod common;

use common::*;

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest as _, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const ANSI_PROGRESS_PREFIX: &str = "\x1b[36mprogress\x1b[0m:";

/// Extensions whose full lifecycle fixtures are constructed in this test
/// binary instead of being stored in `fixtures/archives/manifest.tsv`.
const RUNTIME_GENERATED_LIFECYCLE_EXTENSIONS: &[&str] = &[".nrg", ".isz", ".cue"];

const RUNTIME_GENERATED_LIFECYCLE_FORMATS: &[zmanager_core::archive_format::ArchiveFormatKind] = &[
    zmanager_core::archive_format::ArchiveFormatKind::SplitZip,
    zmanager_core::archive_format::ArchiveFormatKind::Nrg,
    zmanager_core::archive_format::ArchiveFormatKind::Isz,
    zmanager_core::archive_format::ArchiveFormatKind::Cue,
];

/// Formats whose primary detection path cannot be audited by enumerating
/// registered extensions. Their lifecycle coverage is exercised explicitly by
/// the split-ZIP and TZAP tests in this binary.
const PREDICATE_LIFECYCLE_FORMATS: &[zmanager_core::archive_format::ArchiveFormatKind] =
    &[zmanager_core::archive_format::ArchiveFormatKind::SplitZip, zmanager_core::archive_format::ArchiveFormatKind::Tzap];

#[cfg(unix)]
#[allow(unsafe_code)]
fn unix_process_is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn try_create_windows_relative_symlink(path: &Path, target: &str) -> bool {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

    if fs::write(path, []).is_err() {
        return false;
    }
    let target = target.encode_utf16().collect::<Vec<_>>();
    let target_bytes = target.len() * 2;
    let mut path_units = target.clone();
    path_units.push(0);
    path_units.extend_from_slice(&target);
    path_units.push(0);
    let payload_len = 12 + path_units.len() * 2;
    let mut reparse = Vec::with_capacity(8 + payload_len);
    let Ok(payload_len) = u16::try_from(payload_len) else {
        return false;
    };
    let Ok(target_bytes) = u16::try_from(target_bytes) else {
        return false;
    };
    let Some(target_bytes_with_nul) = target_bytes.checked_add(2) else {
        return false;
    };
    reparse.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
    reparse.extend_from_slice(&payload_len.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&target_bytes.to_le_bytes());
    reparse.extend_from_slice(&target_bytes_with_nul.to_le_bytes());
    reparse.extend_from_slice(&target_bytes.to_le_bytes());
    reparse.extend_from_slice(&1u32.to_le_bytes());
    for unit in path_units {
        reparse.extend_from_slice(&unit.to_le_bytes());
    }

    let Ok(file) = fs::OpenOptions::new().access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path) else {
        return false;
    };
    let mut returned = 0u32;
    let Ok(reparse_len) = u32::try_from(reparse.len()) else {
        return false;
    };
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_SET_REPARSE_POINT,
            reparse.as_ptr().cast(),
            reparse_len,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    result != 0
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
    let elevation_size = u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size fits in u32");
    let result = unsafe { GetTokenInformation(token, TokenElevation, (&raw mut elevation).cast(), elevation_size, &raw mut returned) };
    unsafe {
        CloseHandle(token);
    }
    result != 0 && elevation.TokenIsElevated != 0
}

fn assert_same_file_identity(first: &Path, second: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let first = fs::metadata(first).unwrap();
        let second = fs::metadata(second).unwrap();
        assert_eq!((first.dev(), first.ino()), (second.dev(), second.ino()));
    }

    let probe = b"hardlink identity probe\n";
    fs::write(first, probe).unwrap();
    assert_eq!(fs::read(second).unwrap(), probe, "writing one hardlink name must update the other");
}

#[test]
fn cli_lists_all_fixture_archives() {
    for fixture in fixture_manifest() {
        if !fixture_supported_on_target(&fixture) {
            continue;
        }
        let output = Command::new(cli_path()).arg("list").arg(fixture.path()).output().unwrap();

        assert!(
            output.status.success(),
            "failed to list {} ({})\nstdout:\n{}\nstderr:\n{}",
            fixture.filename,
            fixture.format,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "list output was empty for {} ({})", fixture.filename, fixture.format);
    }
}

#[test]
fn every_registered_format_and_extension_has_a_committed_or_generated_lifecycle_fixture() {
    let fixtures = fixture_manifest();

    for capability in zmanager_core::archive_format::FORMAT_CAPABILITIES {
        assert!(
            fixtures.iter().any(|fixture| fixture.extract && zmanager_core::archive_format::detect_archive_format(fixture.path()) == capability.kind)
                || RUNTIME_GENERATED_LIFECYCLE_FORMATS.contains(&capability.kind),
            "registered format {:?} has no committed or runtime-generated lifecycle fixture",
            capability.kind
        );
    }

    for extension in zmanager_core::archive_format::FORMAT_CAPABILITIES.iter().flat_map(|capability| capability.extensions) {
        let extension = extension.to_ascii_lowercase();
        assert!(
            fixtures.iter().any(|fixture| fixture.filename.to_ascii_lowercase().ends_with(&extension))
                || RUNTIME_GENERATED_LIFECYCLE_EXTENSIONS.contains(&extension.as_str()),
            "no committed or runtime-generated lifecycle fixture exercises registered extension {extension}"
        );
    }

    for capability in zmanager_core::archive_format::FORMAT_CAPABILITIES.iter().filter(|capability| capability.extensions.is_empty()) {
        assert!(
            PREDICATE_LIFECYCLE_FORMATS.contains(&capability.kind),
            "predicate-only format {:?} has no explicit lifecycle coverage declaration",
            capability.kind
        );
    }
    for kind in PREDICATE_LIFECYCLE_FORMATS {
        assert!(
            zmanager_core::archive_format::FORMAT_CAPABILITIES.iter().any(|capability| capability.kind == *kind && capability.extensions.is_empty()),
            "stale predicate-only lifecycle coverage declaration for {kind:?}"
        );
    }
}

#[test]
fn committed_optical_descriptor_sidecars_are_present_and_pinned() {
    // `manifest.tsv` pins every archive entry point. The CloneCD `.img` is a
    // required data sidecar rather than a separately openable fixture, so pin
    // it here as well to keep the independently authored pair reproducible.
    let sidecars = [("aaru-optical.img", "b9c6ec1e6b3adb6942053fe16393d8ddad3e4dedaf0cc37ef701f5c28c40d463")];
    for (filename, expected_sha256) in sidecars {
        let path = archives_dir().join(filename);
        assert!(path.is_file(), "missing optical fixture sidecar: {}", path.display());
        assert_eq!(sha256_hex(&path), expected_sha256, "optical fixture sidecar checksum drifted: {filename}");
    }
}

/// Members of the shared `payload/` fixture tree that every container format
/// carries, excluding the symlink. See `fixtures/archives/README.md` for how
/// the tree is generated.
///
/// The symlink is deliberately not listed here: formats disagree on whether
/// they can represent one, so each case supplies its own symlink expectation
/// through [`payload_tree_with_symlink`].
const PAYLOAD_TREE_WITHOUT_SYMLINK: &[(&str, &str)] = &[
    ("payload", "directory"),
    ("payload/README.txt", "file"),
    ("payload/nested", "directory"),
    ("payload/nested/file.txt", "file"),
    ("payload/nested/empty-dir", "directory"),
    ("payload/dir with spaces", "directory"),
    ("payload/dir with spaces/file with spaces.txt", "file"),
    ("payload/unicode", "directory"),
    ("payload/unicode/こんにちは.txt", "file"),
];

/// The full shared payload tree, with the symlink entry recorded as the kind
/// the given format is expected to produce: `"symlink"` where the format
/// preserves it, `"file"` where the writer materializes it instead.
fn payload_tree_with_symlink(symlink_kind: &'static str) -> Vec<(&'static str, &'static str)> {
    let mut tree = PAYLOAD_TREE_WITHOUT_SYMLINK.to_vec();
    tree.push(("payload/nested/readme-link.txt", symlink_kind));
    tree
}

/// Entries the fixture corpus is allowed to carry beyond the documented tree.
///
/// Every `bsdtar`-generated fixture is built with `COPYFILE_DISABLE=1` and
/// carries no `AppleDouble` sidecars. `basic.pkg` is the sole documented
/// exception: `pkgbuild`'s payload cpio embeds `._` entries regardless (see
/// `fixtures/archives/README.md`), so this stays scoped to that one fixture
/// rather than a blanket allowance — otherwise a future macOS regeneration
/// could silently regrow `._` pollution in the rest of the corpus.
fn is_generation_artifact(archive_filename: &str, name: &str) -> bool {
    archive_filename == "basic.pkg" && name.split('/').next_back().is_some_and(|leaf| leaf.starts_with("._"))
}

fn assert_listing_kinds(archive: &Path, expected: &[(&str, &str)]) {
    let output = Command::new(cli_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    assert_success(&format!("zm list {} --json", archive.display()), &output);
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = listing["entries"].as_array().expect("JSON listing entries array");

    for &(path, expected_kind) in expected {
        let entry = entries
            .iter()
            .find(|entry| entry["name"].as_str() == Some(path))
            .unwrap_or_else(|| panic!("missing JSON listing entry {path} in {}: {listing}", archive.display()));
        assert_eq!(entry["kind"].as_str(), Some(expected_kind), "wrong kind for {path} in {}", archive.display());
    }
}

/// Asserts the listing is exactly `expected` — every expected entry present
/// with the right kind, and no unexpected entries beyond known generation
/// artifacts. Subset assertions let a format silently drop payload members, so
/// formats that carry the whole tree are held to the stricter check.
fn assert_listing_is_exactly(archive: &Path, expected: &[(&str, &str)]) {
    assert_listing_kinds(archive, expected);

    let output = Command::new(cli_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = listing["entries"].as_array().expect("JSON listing entries array");

    let archive_filename = archive.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let unexpected = entries
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .filter(|name| !name.is_empty() && !is_generation_artifact(archive_filename, name))
        .filter(|name| !expected.iter().any(|&(path, _)| path == *name))
        .collect::<Vec<_>>();

    assert!(unexpected.is_empty(), "unexpected listing entries in {}: {unexpected:?}", archive.display());
}

/// Formats that carry the complete shared payload tree. Each is held to an
/// exact listing so a regression that drops the empty directory, the
/// spaces-in-name file, or the Unicode file fails here rather than surviving a
/// subset check.
///
/// The second field is the kind the format is expected to report for the
/// symlink member.
const FULL_PAYLOAD_TREE_FIXTURES: &[(&str, &str)] = &[
    // The ZIP and 7z v1 writers materialize the symlink as a regular file.
    ("basic.zip", "file"),
    ("basic.7z", "file"),
    ("basic.tzap", "file"),
    // TAR-family and the remaining container formats preserve it. Every
    // distinct bsdtar-produced byte stream is listed here (not just its alias
    // spellings, which are byte-identical copies) so a regression that
    // reintroduces AppleDouble `._` pollution into any one of them is caught
    // rather than passing silently.
    ("basic.tar", "symlink"),
    ("basic.tar.gz", "symlink"),
    ("basic.tar.bz2", "symlink"),
    ("basic.tar.xz", "symlink"),
    ("basic.tar.lzma", "symlink"),
    ("basic.tar.lz", "symlink"),
    ("basic.tar.lzo", "symlink"),
    ("basic.tar.Z", "symlink"),
    ("basic.tar.lz4", "symlink"),
    ("basic.tar.zst", "symlink"),
    ("basic.cpio", "symlink"),
    ("basic.pkg", "symlink"),
    ("basic.xar", "symlink"),
];

#[test]
fn cli_fixture_listings_carry_the_whole_payload_tree() {
    for &(filename, symlink_kind) in FULL_PAYLOAD_TREE_FIXTURES {
        let archive = archives_dir().join(filename);
        assert!(archive.is_file(), "committed fixture is missing: {}", archive.display());
        assert_listing_is_exactly(&archive, &payload_tree_with_symlink(symlink_kind));
    }
}

/// The shared payload tree for formats whose writer roots the tree directly
/// at the archive root, rather than nesting it under `payload/`: `SquashFS`,
/// `AppImage`, and WIM.
const ROOT_PAYLOAD_TREE_WITHOUT_SYMLINK: &[(&str, &str)] = &[
    ("README.txt", "file"),
    ("nested", "directory"),
    ("nested/file.txt", "file"),
    ("nested/empty-dir", "directory"),
    ("dir with spaces", "directory"),
    ("dir with spaces/file with spaces.txt", "file"),
    ("unicode", "directory"),
    ("unicode/こんにちは.txt", "file"),
];

/// [`ROOT_PAYLOAD_TREE_WITHOUT_SYMLINK`] plus the symlink entry and any
/// format-specific extras (SquashFS/AppImage additionally carry an executable
/// `run.sh`, added by `scripts/generate_fixtures.sh` specifically for these
/// two formats to check that the mode bit round-trips).
fn root_payload_tree(symlink_kind: &'static str, extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut tree = ROOT_PAYLOAD_TREE_WITHOUT_SYMLINK.to_vec();
    tree.push(("nested/readme-link.txt", symlink_kind));
    tree.extend_from_slice(extra);
    tree
}

#[test]
fn cli_fixture_listings_carry_the_whole_payload_tree_root_rooted() {
    // SquashFS (every compression variant and extension alias), AppImage, and
    // every WIM variant (including the split set) carry the complete shared
    // tree with no `payload/` prefix. Held to the same exact-match discipline
    // as `cli_fixture_listings_carry_the_whole_payload_tree` above, so a
    // regression that drops the empty directory, the symlink, or silently
    // stops carrying `run.sh` fails here instead of surviving a subset check.
    let run_sh = &[("run.sh", "file")][..];

    for filename in ["basic.squashfs", "basic-xz.squashfs", "basic-gzip.squashfs", "basic-zstd.squashfs", "basic.sqfs", "basic.AppImage"] {
        let archive = archives_dir().join(filename);
        assert!(archive.is_file(), "committed fixture is missing: {}", archive.display());
        assert_listing_is_exactly(&archive, &root_payload_tree("symlink", run_sh));
    }

    for filename in ["basic.wim", "basic-none.wim", "basic-LZX.wim", "basic-XPRESS.wim", "split.swm"] {
        let archive = archives_dir().join(filename);
        assert!(archive.is_file(), "committed fixture is missing: {}", archive.display());
        assert_listing_is_exactly(&archive, &root_payload_tree("symlink", &[]));
    }
}

#[test]
fn cli_fixture_listings_preserve_entry_kinds_across_formats() {
    // Formats whose listing legitimately deviates from the shared payload tree.
    // Every deviation here is documented in `fixtures/archives/README.md`;
    // these stay subset assertions because the deviations are format-inherent.
    let cases: &[(&str, &[(&str, &str)])] = &[
        // ISO 9660/Joliet upcases names and is generated without the symlink.
        ("basic.iso", &[("NESTED", "directory"), ("README.TXT", "file"), ("NESTED/FILE.TXT", "file")]),
        // Package containers expose their members, not the payload tree.
        ("basic.deb", &[("debian-binary", "file"), ("control.tar.gz", "file"), ("data.tar.xz", "file")]),
        ("basic.ar", &[("README.md", "file")]),
        (
            "basic.dmg",
            &[("payload", "directory"), ("payload/nested", "directory"), ("payload/README.txt", "file"), ("payload/nested/readme-link.txt", "symlink")],
        ),
        // MSI has no symlink entries and `wixl` cannot encode the Unicode name.
        ("basic.msi", &[("payload/README.txt", "file"), ("payload/nested/file.txt", "file"), ("payload/dir with spaces/file with spaces.txt", "file")]),
        (
            "basic.vhd",
            &[("payload", "directory"), ("payload/nested", "directory"), ("payload/README.txt", "file"), ("payload/nested/readme-link.txt", "symlink")],
        ),
        // FAT32 has no symlinks.
        ("basic.vmdk", &[("payload", "directory"), ("payload/nested", "directory"), ("payload/README.txt", "file"), ("payload/nested/file.txt", "file")]),
        (
            "basic.udf",
            &[("payload", "directory"), ("payload/nested", "directory"), ("payload/README.txt", "file"), ("payload/nested/readme-link.txt", "symlink")],
        ),
        (
            "basic.vdi",
            &[
                ("payload", "directory"),
                ("payload/nested", "directory"),
                ("payload/README.txt", "file"),
                ("payload/nested/file.txt", "file"),
                ("payload/dir with spaces/file with spaces.txt", "file"),
                ("payload/unicode/こんにちは.txt", "file"),
            ],
        ),
    ];

    for &(filename, expected) in cases {
        let archive = archives_dir().join(filename);
        assert!(archive.is_file(), "committed fixture is missing: {}", archive.display());
        assert_listing_kinds(&archive, expected);
    }

    let rar = archives_dir().join("rar5-multipart.part1.rar");
    assert!(rar.is_file(), "committed fixture is missing: {}", rar.display());
    assert_listing_kinds(&rar, &[("rar-fixture", "directory"), ("rar-fixture/docs/readme.txt", "file")]);

    assert_listing_kinds(
        &archives_dir().join("basic.mtree"),
        &[
            ("payload", "directory"),
            ("payload/nested", "directory"),
            ("payload/README.txt", "file"),
            ("payload/nested/file.txt", "file"),
            ("payload/nested/readme-link.txt", "symlink"),
        ],
    );
}

#[test]
fn committed_optical_fixtures_expose_the_expected_complete_trees() {
    let aaru_tree = &[
        ("DIR WITH SPACES", "directory"),
        ("NESTED", "directory"),
        ("README.TXT", "file"),
        ("UNICODE", "directory"),
        ("UNICODE/_.TXT", "file"),
        ("NESTED/EMPTY-DIR", "directory"),
        ("NESTED/FILE.TXT", "file"),
        ("DIR WITH SPACES/FILE WITH SPACES.TXT", "file"),
    ];
    for filename in ["aaru-optical.mds", "aaru-optical.mdf", "aaru-optical.ccd"] {
        assert_listing_is_exactly(&archives_dir().join(filename), aaru_tree);
    }

    assert_listing_is_exactly(
        &archives_dir().join("mkdcdisc-basic.cdi"),
        &[("1ST_READ.BIN", "file"), ("nested", "directory"), ("README.txt", "file"), ("nested/file.txt", "file")],
    );
}

#[test]
fn cli_extracts_extractable_fixture_archives() {
    for fixture in fixture_manifest().into_iter().filter(|fixture| fixture.extract && fixture_supported_on_target(fixture)) {
        let temp = TestDir::new("fixture_cli_extracts");
        let mut command = Command::new(cli_path());
        command.arg("extract").arg(fixture.path()).arg(temp.path("out"));
        #[cfg(windows)]
        if fixture.format == "TZAP" {
            command.arg("--allow-degraded");
        }
        let output = command.output().unwrap();

        if cfg!(windows) && (fixture.format == "MTREE" || fixture.filename == "rar5-links.rar") {
            assert_failure(&format!("zm extract {} on Windows", fixture.filename), &output);
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("symlink extraction is not supported on this platform"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            continue;
        }

        assert!(
            output.status.success(),
            "failed to extract {} ({})\nstdout:\n{}\nstderr:\n{}",
            fixture.filename,
            fixture.format,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!collect_tree_entries(&temp.path("out")).is_empty(), "extraction produced no entries for {} ({})", fixture.filename, fixture.format);
    }
}

#[test]
fn cli_tests_all_fixture_archives() {
    for fixture in fixture_manifest().into_iter().filter(fixture_supported_on_target) {
        let output = Command::new(cli_path()).arg("test").arg(fixture.path()).output().unwrap();
        assert_success(&format!("zm test {}", fixture.filename), &output);
    }
}

/// Drives the selective-operation contract through one committed fixture for
/// every format kind represented by the corpus. Extension aliases and codec
/// variants are already covered by the list/test/full-extract sweeps above;
/// repeating this slower matrix once per backend keeps the scenario coverage
/// exhaustive without multiplying the test runtime by every alias.
#[test]
fn every_committed_format_supports_its_selective_operation_contract() {
    let mut exercised = Vec::new();

    for fixture in fixture_manifest().into_iter().filter(fixture_supported_on_target) {
        let kind = zmanager_core::archive_format::detect_archive_format(fixture.path());
        if exercised.contains(&kind) {
            continue;
        }
        exercised.push(kind);

        let list = Command::new(cli_path()).arg("list").arg(fixture.path()).arg("--json").output().unwrap();
        assert_success(&format!("zm list {} --json", fixture.filename), &list);
        let listing: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
        let entries = listing["entries"].as_array().expect("JSON listing entries array");
        let selected_path = entries
            .iter()
            .find(|entry| entry["kind"].as_str() == Some("file"))
            .and_then(|entry| entry["name"].as_str())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| panic!("{} ({kind:?}) has no selectable regular file: {listing}", fixture.filename));

        let temp = TestDir::new("fixture-selective-contract");
        let selected_output = temp.path("selected");
        let mut selected = Command::new(cli_path());
        selected.arg("extract").arg(fixture.path()).arg("-C").arg(&selected_output).arg("--include").arg(selected_path);
        configure_fixture_extract_command(&mut selected, &fixture);
        let selected = selected.output().unwrap();
        assert_success(&format!("zm extract {} --include {selected_path}", fixture.filename), &selected);

        let selected_file = selected_output.join(selected_path);
        assert!(selected_file.is_file(), "{} ({kind:?}) did not materialize selected file {selected_path}", fixture.filename);
        let selected_bytes = fs::read(&selected_file).unwrap();

        if let Some((parent, _)) = selected_path.rsplit_once('/').filter(|(parent, _)| !parent.is_empty()) {
            let directory_output = temp.path("directory");
            let mut directory = Command::new(cli_path());
            directory.arg("extract").arg(fixture.path()).arg("-C").arg(&directory_output).arg("--include").arg(parent);
            configure_fixture_extract_command(&mut directory, &fixture);
            let directory = directory.output().unwrap();
            if cfg!(windows) && fixture.format == "MTREE" {
                assert_failure(&format!("zm extract {} --include {parent}", fixture.filename), &directory);
                assert!(
                    String::from_utf8_lossy(&directory.stderr).contains("symlink extraction is not supported on this platform"),
                    "{}",
                    String::from_utf8_lossy(&directory.stderr)
                );
            } else {
                assert_success(&format!("zm extract {} --include {parent}", fixture.filename), &directory);
                assert_eq!(
                    fs::read(directory_output.join(selected_path)).unwrap(),
                    selected_bytes,
                    "{} ({kind:?}) directory selection changed {selected_path}",
                    fixture.filename
                );
            }
        }

        let mut stdout = Command::new(cli_path());
        stdout.arg("extract").arg(fixture.path()).arg("--include").arg(selected_path).arg("--to-stdout");
        configure_fixture_extract_command(&mut stdout, &fixture);
        let stdout = stdout.output().unwrap();
        if matches!(fixture.format.as_str(), "DMG" | "PKG" | "MSI" | "MTREE") {
            assert_failure(&format!("zm extract {} --include {selected_path} --to-stdout", fixture.filename), &stdout);
            assert!(!stdout.stderr.is_empty(), "{} ({kind:?}) rejected stdout extraction without a diagnostic", fixture.filename);
        } else {
            assert_success(&format!("zm extract {} --include {selected_path} --to-stdout", fixture.filename), &stdout);
            assert_eq!(stdout.stdout, selected_bytes, "{} ({kind:?}) stdout bytes differ for {selected_path}", fixture.filename);
        }
    }
}

fn configure_fixture_extract_command(command: &mut Command, fixture: &Fixture) {
    #[cfg(windows)]
    if fixture.format == "TZAP" {
        command.arg("--allow-degraded");
    }

    #[cfg(not(windows))]
    let _ = (command, fixture);
}

#[test]
fn cli_lists_tests_and_extracts_msi_fixture() {
    let fixture = archives_dir().join("basic.msi");
    if !fixture.exists() {
        return;
    }
    let temp = TestDir::new("fixture-cli-msi");

    let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
    assert_success("zm list basic.msi", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("payload/README.txt"), "{list_stdout}");
    assert!(list_stdout.contains("payload/nested/file.txt"), "{list_stdout}");
    assert!(list_stdout.contains("payload/dir with spaces/file with spaces.txt"), "{list_stdout}");
    assert!(!list_stdout.contains("payload/./"), "entries must not carry ./ prefixes: {list_stdout}");

    let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
    assert_success("zm test basic.msi", &test);

    let out = temp.path("out");
    let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract basic.msi", &extract);
    assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n");
    assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n");
    assert_eq!(fs::read_to_string(out.join("payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");

    // Selective extraction exercises pattern matching against the resolved paths.
    let out_sel = temp.path("out-sel");
    let selective =
        Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_sel).arg("--include").arg("payload/nested/file.txt").output().unwrap();
    assert_success("zm extract basic.msi --include", &selective);
    assert!(out_sel.join("payload/nested/file.txt").is_file());
    assert!(!out_sel.join("payload/README.txt").exists());

    // --to-stdout is explicitly unsupported for MSI.
    let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("payload/README.txt").arg("--to-stdout").output().unwrap();
    assert_failure("zm extract basic.msi --to-stdout", &stdout);
    assert!(
        String::from_utf8_lossy(&stdout.stderr).contains("do not currently support extracting to stdout"),
        "stderr:\n{}",
        String::from_utf8_lossy(&stdout.stderr)
    );
}

#[test]
fn cli_lists_tests_and_extracts_virtual_disk_fixtures() {
    for filename in ["basic.vhd", "basic.vmdk", "basic.udf", "basic.vdi"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let temp = TestDir::new("fixture-cli-virtual-disk");

        let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
        assert_success(&format!("zm list {filename}"), &list);
        let list_stdout = String::from_utf8_lossy(&list.stdout);
        assert!(list_stdout.contains("payload/README.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/nested/file.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/dir with spaces/file with spaces.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/unicode/こんにちは.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/nested/empty-dir"), "{list_stdout}");
        assert!(!list_stdout.contains("payload/./"), "entries must not carry ./ prefixes: {list_stdout}");
        // The NTFS vhd fixture must not surface $MFT-style system metadata.
        assert!(!list_stdout.contains("$MFT"), "NTFS metadata leaked: {list_stdout}");
        // The UDF fixture carries a symlink; the NTFS/FAT fixtures do not.
        assert_eq!(list_stdout.contains("payload/nested/readme-link.txt"), matches!(filename, "basic.vhd" | "basic.udf"), "{list_stdout}");

        let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
        assert_success(&format!("zm test {filename}"), &test);

        let out = temp.path("out");
        let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
        assert_success(&format!("zm extract {filename}"), &extract);
        assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(out.join("payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");
        assert_eq!(fs::read_to_string(out.join("payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");
        assert!(out.join("payload/nested/empty-dir").is_dir());
        // The patched NTFS and UDF adapters decode symlinks (reparse/
        // IntxLNK and PATH_COMPONENT), so those fixtures carry the symlink;
        // the FAT fixture strips it (FAT has no symlinks).
        if matches!(filename, "basic.vhd" | "basic.udf") {
            #[cfg(unix)]
            {
                assert_eq!(fs::read_link(out.join("payload/nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"), "{filename}");
            }
        } else {
            assert!(!out.join("payload/nested/readme-link.txt").exists(), "{filename}");
        }

        // Selective extraction exercises pattern matching against the resolved paths.
        let out_sel = temp.path("out-sel");
        let selective =
            Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_sel).arg("--include").arg("payload/nested/file.txt").output().unwrap();
        assert_success(&format!("zm extract {filename} --include"), &selective);
        assert!(out_sel.join("payload/nested/file.txt").is_file());
        assert!(!out_sel.join("payload/README.txt").exists());

        // Selecting a whole subfolder must pull every entry beneath it
        // (including the empty directory) and nothing outside it.
        let out_subdir = temp.path("out-subdir");
        let subdir_extract =
            Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_subdir).arg("--include").arg("payload/nested").output().unwrap();
        assert_success(&format!("zm extract {filename} --include payload/nested"), &subdir_extract);
        assert!(out_subdir.join("payload/nested/file.txt").is_file(), "{filename}");
        assert!(out_subdir.join("payload/nested/empty-dir").is_dir(), "{filename}");
        assert!(!out_subdir.join("payload/README.txt").exists(), "{filename}");
        assert!(!out_subdir.join("payload/unicode").exists(), "{filename}");

        // The disk formats copy a single entry through the shared
        // path/occurrence selector, so --to-stdout works for them.
        let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("payload/README.txt").arg("--to-stdout").output().unwrap();
        assert_success(&format!("zm extract {filename} --to-stdout"), &stdout);
        assert_eq!(stdout.stdout, b"ZManager fixture payload\n", "{filename}");
    }
}

#[test]
fn cli_lists_tests_and_extracts_hybrid_iso_fixture() {
    let fixture = archives_dir().join("basic.iso");
    if !fixture.exists() {
        return;
    }
    let temp = TestDir::new("fixture-cli-hybrid-iso");

    let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
    assert_success("zm list basic.iso", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    for path in
        ["DIR WITH SPACES", "NESTED", "README.TXT", "UNICODE", "UNICODE/_.TXT", "NESTED/EMPTY-DIR", "NESTED/FILE.TXT", "DIR WITH SPACES/FILE WITH SPACES.TXT"]
    {
        assert!(list_stdout.contains(path), "basic.iso list is missing {path}:\n{list_stdout}");
    }
    assert_eq!(list_stdout.matches("README.TXT").count(), 1, "hybrid ISO trees must not be listed twice:\n{list_stdout}");

    let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
    assert_success("zm test basic.iso", &test);

    let out = temp.path("out");
    let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract basic.iso", &extract);
    assert_eq!(fs::read(out.join("README.TXT")).unwrap(), b"ZManager fixture payload\n");
    assert_eq!(fs::read(out.join("NESTED/FILE.TXT")).unwrap(), b"nested fixture file\n");
    assert_eq!(fs::read(out.join("DIR WITH SPACES/FILE WITH SPACES.TXT")).unwrap(), b"spaces in path\n");
    assert_eq!(fs::read(out.join("UNICODE/_.TXT")).unwrap(), b"unicode path fixture\n");

    let selected_out = temp.path("selected");
    let selected = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&selected_out).arg("--include").arg("NESTED/FILE.TXT").output().unwrap();
    assert_success("zm extract basic.iso --include", &selected);
    assert_eq!(fs::read(selected_out.join("NESTED/FILE.TXT")).unwrap(), b"nested fixture file\n");
    assert!(!selected_out.join("README.TXT").exists());

    // Open one and extract subfolder: basic.iso carries the same upcased
    // README.TXT / NESTED/FILE.TXT shape every synthesized optical fixture
    // wraps it in, so the shared matrix helper applies directly.
    assert_optical_open_extract_matrix("basic.iso", &fixture, &temp);
}

#[test]
fn cli_lists_tests_and_extracts_squashfs_fixtures() {
    for filename in ["basic.squashfs", "basic-xz.squashfs", "basic-gzip.squashfs", "basic-zstd.squashfs", "basic.sqfs"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let temp = TestDir::new("fixture-cli-squashfs");

        let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
        assert_success(&format!("zm list {filename}"), &list);
        let list_stdout = String::from_utf8_lossy(&list.stdout);
        assert!(list_stdout.contains("README.txt"), "{list_stdout}");
        assert!(list_stdout.contains("nested/file.txt"), "{list_stdout}");
        assert!(list_stdout.contains("dir with spaces/file with spaces.txt"), "{list_stdout}");
        assert!(list_stdout.contains("unicode/こんにちは.txt"), "{list_stdout}");
        assert!(list_stdout.contains("nested/empty-dir"), "{list_stdout}");

        let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
        assert_success(&format!("zm test {filename}"), &test);

        let out = temp.path("out");
        let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
        assert_success(&format!("zm extract {filename}"), &extract);
        assert_eq!(fs::read_to_string(out.join("README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(out.join("nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(out.join("dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");
        assert_eq!(fs::read_to_string(out.join("unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");
        assert!(out.join("nested/empty-dir").is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(out.join("run.sh")).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{filename}: run.sh must extract as executable, got mode {mode:o}");
        }

        // Selecting one file must write only that file to the destination.
        let out_one = temp.path("out-one");
        let one_extract =
            Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_one).arg("--include").arg("nested/file.txt").output().unwrap();
        assert_success(&format!("zm extract {filename} --include nested/file.txt"), &one_extract);
        assert_eq!(fs::read_to_string(out_one.join("nested/file.txt")).unwrap(), "nested fixture file\n", "{filename}");
        assert!(!out_one.join("README.txt").exists(), "{filename}");

        // Selecting a subfolder must pull every entry beneath it (including
        // the empty directory) and nothing outside it.
        let out_subdir = temp.path("out-subdir");
        let subdir_extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_subdir).arg("--include").arg("nested").output().unwrap();
        assert_success(&format!("zm extract {filename} --include nested"), &subdir_extract);
        assert!(out_subdir.join("nested/file.txt").is_file(), "{filename}");
        assert!(out_subdir.join("nested/empty-dir").is_dir(), "{filename}");
        assert!(!out_subdir.join("README.txt").exists(), "{filename}");
        assert!(!out_subdir.join("unicode").exists(), "{filename}");

        let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("README.txt").arg("--to-stdout").output().unwrap();
        assert_success(&format!("zm extract {filename} --to-stdout"), &stdout);
        assert_eq!(stdout.stdout, b"ZManager fixture payload\n", "{filename}");
    }
}

#[test]
fn cli_lists_tests_and_extracts_appimage_fixture() {
    let fixture = archives_dir().join("basic.AppImage");
    if !fixture.exists() {
        return;
    }
    let temp = TestDir::new("fixture-cli-appimage");

    let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
    assert_success("zm list basic.AppImage", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("README.txt"), "{list_stdout}");
    assert!(list_stdout.contains("nested/file.txt"), "{list_stdout}");
    assert!(list_stdout.contains("dir with spaces/file with spaces.txt"), "{list_stdout}");
    assert!(list_stdout.contains("unicode/こんにちは.txt"), "{list_stdout}");

    let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
    assert_success("zm test basic.AppImage", &test);

    let out = temp.path("out");
    let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract basic.AppImage", &extract);
    assert_eq!(fs::read_to_string(out.join("README.txt")).unwrap(), "ZManager fixture payload\n");
    assert_eq!(fs::read_to_string(out.join("nested/file.txt")).unwrap(), "nested fixture file\n");
    assert!(out.join("nested/empty-dir").is_dir());

    let out_one = temp.path("out-one");
    let one_extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_one).arg("--include").arg("nested/file.txt").output().unwrap();
    assert_success("zm extract basic.AppImage --include nested/file.txt", &one_extract);
    assert_eq!(fs::read_to_string(out_one.join("nested/file.txt")).unwrap(), "nested fixture file\n");
    assert!(!out_one.join("README.txt").exists());

    let out_subdir = temp.path("out-subdir");
    let subdir_extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_subdir).arg("--include").arg("nested").output().unwrap();
    assert_success("zm extract basic.AppImage --include nested", &subdir_extract);
    assert!(out_subdir.join("nested/file.txt").is_file());
    assert!(out_subdir.join("nested/empty-dir").is_dir());
    assert!(!out_subdir.join("README.txt").exists());

    let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("README.txt").arg("--to-stdout").output().unwrap();
    assert_success("zm extract basic.AppImage --to-stdout", &stdout);
    assert_eq!(stdout.stdout, b"ZManager fixture payload\n");
}

#[test]
fn cli_lists_tests_and_extracts_wim_fixtures() {
    for filename in ["basic.wim", "basic-none.wim", "basic-LZX.wim", "basic-XPRESS.wim", "multi-image.wim", "split.swm"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let temp = TestDir::new("fixture-cli-wim");

        let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
        assert_success(&format!("zm list {filename}"), &list);
        let list_stdout = String::from_utf8_lossy(&list.stdout);
        assert!(list_stdout.contains("README.txt"), "{list_stdout}");

        let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
        assert_success(&format!("zm test {filename}"), &test);

        let out = temp.path("out");
        let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
        assert_success(&format!("zm extract {filename}"), &extract);
        if filename == "multi-image.wim" {
            // The two images carry genuinely different content (see
            // scripts/generate_fixtures.sh): image1 has `unicode/` and no
            // marker file, image2 has the marker and no `unicode/`. Asserting
            // both directions catches a backend that emits one image twice
            // under both `imageN/` prefixes, which a same-content fixture
            // could not.
            assert!(out.join("image1/README.txt").is_file());
            assert!(out.join("image1/unicode/こんにちは.txt").is_file());
            assert!(!out.join("image1/second-image-only.txt").exists());
            assert!(out.join("image2/README.txt").is_file());
            assert!(out.join("image2/second-image-only.txt").is_file());
            assert_eq!(fs::read_to_string(out.join("image2/second-image-only.txt")).unwrap(), "second image marker\n");
            assert!(!out.join("image2/unicode").exists());

            // Selecting one image's subfolder must not pull the other image's
            // entries.
            let out_image2 = temp.path("out-image2");
            let image2_extract =
                Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_image2).arg("--include").arg("image2").output().unwrap();
            assert_success("zm extract multi-image.wim --include image2", &image2_extract);
            assert!(out_image2.join("image2/second-image-only.txt").is_file());
            assert!(!out_image2.join("image1").exists());

            // Selecting one file inside one specific image, by both open
            // (stdout preview) and extract (directory write), must resolve
            // against that image and not the other one -- image1 has no
            // `second-image-only.txt`, so a resolver that ignored the image
            // prefix would either fail or silently pick the wrong image.
            let stdout_one_image =
                Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("image2/second-image-only.txt").arg("--to-stdout").output().unwrap();
            assert_success("zm extract multi-image.wim --include image2/second-image-only.txt --to-stdout", &stdout_one_image);
            assert_eq!(stdout_one_image.stdout, b"second image marker\n");

            let out_one_image = temp.path("out-one-image");
            let one_image_extract = Command::new(cli_path())
                .arg("extract")
                .arg(&fixture)
                .arg("-C")
                .arg(&out_one_image)
                .arg("--include")
                .arg("image2/second-image-only.txt")
                .output()
                .unwrap();
            assert_success("zm extract multi-image.wim --include image2/second-image-only.txt", &one_image_extract);
            assert_eq!(fs::read_to_string(out_one_image.join("image2/second-image-only.txt")).unwrap(), "second image marker\n");
            assert!(!out_one_image.join("image1").exists());
        } else {
            assert_eq!(fs::read_to_string(out.join("README.txt")).unwrap(), "ZManager fixture payload\n");
            assert_eq!(fs::read_to_string(out.join("nested/file.txt")).unwrap(), "nested fixture file\n");
            assert!(out.join("nested/empty-dir").is_dir(), "{filename}");
            #[cfg(unix)]
            {
                assert_eq!(fs::read_link(out.join("nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"), "{filename}");
            }

            // Selecting one file must write only that file to the destination.
            let out_one = temp.path("out-one");
            let one_extract =
                Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_one).arg("--include").arg("nested/file.txt").output().unwrap();
            assert_success(&format!("zm extract {filename} --include nested/file.txt"), &one_extract);
            assert_eq!(fs::read_to_string(out_one.join("nested/file.txt")).unwrap(), "nested fixture file\n", "{filename}");
            assert!(!out_one.join("README.txt").exists(), "{filename}");

            // Selecting a subfolder must pull every entry beneath it
            // (including the empty directory and the symlink) and nothing
            // outside it.
            let out_subdir = temp.path("out-subdir");
            let subdir_extract =
                Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_subdir).arg("--include").arg("nested").output().unwrap();
            assert_success(&format!("zm extract {filename} --include nested"), &subdir_extract);
            assert!(out_subdir.join("nested/file.txt").is_file(), "{filename}");
            assert!(out_subdir.join("nested/empty-dir").is_dir(), "{filename}");
            assert!(!out_subdir.join("README.txt").exists(), "{filename}");
        }

        if filename != "multi-image.wim" {
            let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("README.txt").arg("--to-stdout").output().unwrap();
            assert_success(&format!("zm extract {filename} --to-stdout"), &stdout);
            assert_eq!(stdout.stdout, b"ZManager fixture payload\n", "{filename}");
        }
    }
}

/// `split.swm` alone (without its sibling `split2.swm`) must fail rather than
/// silently list/extract a truncated tree: this is the only thing that proves
/// the second part is actually consumed rather than merely present on disk
/// beside the first.
#[test]
fn cli_rejects_a_split_wim_missing_its_second_part() {
    let split = archives_dir().join("split.swm");
    let split2 = archives_dir().join("split2.swm");
    if !split.exists() || !split2.exists() {
        return;
    }
    let temp = TestDir::new("fixture-cli-wim-split-incomplete");
    // Copy only the first part into an isolated directory so wimlib's sibling
    // resolution (which scans the part's own directory) cannot find part 2.
    fs::write(temp.path("split.swm"), fs::read(&split).unwrap()).unwrap();

    let list = Command::new(cli_path()).arg("list").arg(temp.path("split.swm")).output().unwrap();
    assert!(!list.status.success(), "listing split.swm without split2.swm must fail:\n{}", String::from_utf8_lossy(&list.stdout));
    assert!(!String::from_utf8_lossy(&list.stderr).trim().is_empty(), "failed without a diagnostic");
}

/// Builds an `UltraISO` `.isz` image at the documented 48-byte packed header
/// layout, byte-for-byte the same recipe as `zmanager-core`'s own internal
/// `build_isz` test encoder (`crates/zmanager-core/src/virtual_disk_backend.rs`,
/// `sect_size` a `u16` at offset 10, `block_size` a `u32` at offset 29,
/// `ptr_offs` a `u32` at offset 35, chunk pointers carrying the chunk type in
/// their top two bits). Kept here rather than imported because the encoder is
/// `#[cfg(test)]`-private to that crate; this is a second, independent
/// construction against the same documented wire shape, not a shortcut that
/// trusts the original encoder's own output.
fn build_isz(payload: &[u8], sector_size: u16, block_size: u32, ptr_len: u8) -> Vec<u8> {
    let total_sectors = u32::try_from(payload.len() / usize::from(sector_size)).unwrap();

    let mut chunk_types = Vec::new();
    let mut chunk_bytes = Vec::new();
    for block in payload.chunks(block_size as usize) {
        if block.iter().all(|byte| *byte == 0) {
            chunk_types.push((0_u8, Vec::new()));
            continue;
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::fast());
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
    let data_offset = ptr_offset + u32::try_from(chunk_types.len()).unwrap() * u32::from(ptr_len);

    let mut header = vec![0_u8; 48];
    header[0..4].copy_from_slice(b"IsZ!");
    header[4] = 48; // header_size
    header[5] = 1; // version
    header[6..10].copy_from_slice(&0x1234_5678_u32.to_le_bytes()); // vol_sn
    header[10..12].copy_from_slice(&sector_size.to_le_bytes());
    header[12..16].copy_from_slice(&total_sectors.to_le_bytes());
    header[16] = 0; // encryption_type: none
    header[17..25].copy_from_slice(&0_u64.to_le_bytes()); // segment_size: single file
    let num_blocks = u32::try_from(chunk_types.len()).unwrap();
    header[25..29].copy_from_slice(&num_blocks.to_le_bytes());
    header[29..33].copy_from_slice(&block_size.to_le_bytes());
    header[33] = ptr_len;
    header[34] = 1; // segment count
    header[35..39].copy_from_slice(&ptr_offset.to_le_bytes());
    header[39..43].copy_from_slice(&0_u32.to_le_bytes()); // seg_offs
    header[43..47].copy_from_slice(&data_offset.to_le_bytes());

    let type_shift = u32::from(ptr_len) * 8 - 2;
    let mut table = Vec::new();
    for (kind, bytes) in &chunk_types {
        let value = (u32::from(*kind) << type_shift) | u32::try_from(bytes.len()).unwrap();
        table.extend_from_slice(&value.to_le_bytes()[..usize::from(ptr_len)]);
    }

    let mut out = header;
    out.extend_from_slice(&table);
    out.extend_from_slice(&chunk_bytes);
    out
}

/// Builds a minimal one-session Alcohol 120% MDS descriptor for a sibling
/// `.mdf`. The layout follows the independently implemented libmirage/Aaru
/// wire format: header at 0, session block at 88, track block at 112, and the
/// track-length extra block at 192.
fn build_mds(sector_size: u16, start_offset: u64, num_sectors: u32) -> Vec<u8> {
    let mut descriptor = vec![0_u8; 200];
    descriptor[0..16].copy_from_slice(b"MEDIA DESCRIPTOR");
    descriptor[16] = 0x01;
    descriptor[18..20].copy_from_slice(&0_u16.to_le_bytes());
    descriptor[20..22].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[80..84].copy_from_slice(&88_u32.to_le_bytes());

    let session = 88;
    descriptor[session + 8..session + 10].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[session + 10] = 1;
    descriptor[session + 12..session + 14].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[session + 14..session + 16].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[session + 20..session + 24].copy_from_slice(&112_u32.to_le_bytes());

    let track = 112;
    descriptor[track] = 0x02;
    descriptor[track + 4] = 1;
    descriptor[track + 12..track + 16].copy_from_slice(&192_u32.to_le_bytes());
    descriptor[track + 16..track + 18].copy_from_slice(&sector_size.to_le_bytes());
    descriptor[track + 40..track + 48].copy_from_slice(&start_offset.to_le_bytes());

    let extra = 192;
    descriptor[extra + 4..extra + 8].copy_from_slice(&num_sectors.to_le_bytes());
    descriptor
}

/// Open one (preview without writing to disk), extract one, and extract
/// subfolder against an ISO-9660-shaped fixture that carries the canonical
/// tree upcased: `README.TXT` at the root and `NESTED/FILE.TXT` +
/// `NESTED/EMPTY-DIR/` beneath a subfolder.
fn assert_optical_open_extract_matrix(label: &str, path: &Path, temp: &TestDir) {
    let stdout = Command::new(cli_path()).arg("extract").arg(path).arg("--include").arg("README.TXT").arg("--to-stdout").output().unwrap();
    assert_success(&format!("zm extract {label} --to-stdout"), &stdout);
    assert_eq!(stdout.stdout, b"ZManager fixture payload\n", "{label}");

    let out_one = temp.path(format!("{label}-one"));
    let extract_one = Command::new(cli_path()).arg("extract").arg(path).arg("-C").arg(&out_one).arg("--include").arg("README.TXT").output().unwrap();
    assert_success(&format!("zm extract {label} --include README.TXT"), &extract_one);
    assert!(out_one.join("README.TXT").is_file(), "{label}");
    assert!(!out_one.join("NESTED").exists(), "{label}");

    let out_sub = temp.path(format!("{label}-sub"));
    let extract_sub = Command::new(cli_path()).arg("extract").arg(path).arg("-C").arg(&out_sub).arg("--include").arg("NESTED").output().unwrap();
    assert_success(&format!("zm extract {label} --include NESTED"), &extract_sub);
    assert!(out_sub.join("NESTED/FILE.TXT").is_file(), "{label}");
    assert!(out_sub.join("NESTED/EMPTY-DIR").is_dir(), "{label}");
    assert!(!out_sub.join("README.TXT").exists(), "{label}");
}

#[test]
fn cli_exercises_the_complete_authentic_cdi_operation_matrix() {
    let archive = archives_dir().join("mkdcdisc-basic.cdi");
    let temp = TestDir::new("fixture-cli-authentic-cdi");

    let list = Command::new(cli_path()).arg("list").arg(&archive).output().unwrap();
    assert_success("zm list mkdcdisc-basic.cdi", &list);
    let test = Command::new(cli_path()).arg("test").arg(&archive).output().unwrap();
    assert_success("zm test mkdcdisc-basic.cdi", &test);

    let all_output = temp.path("all");
    let extract_all = Command::new(cli_path()).arg("extract").arg(&archive).arg("-C").arg(&all_output).output().unwrap();
    assert_success("zm extract mkdcdisc-basic.cdi", &extract_all);
    assert_eq!(fs::read(all_output.join("README.txt")).unwrap(), b"ZManager free-tool CDI fixture\n");
    assert_eq!(fs::read(all_output.join("nested/file.txt")).unwrap(), b"nested CDI payload\n");

    let stdout = Command::new(cli_path()).arg("extract").arg(&archive).arg("--include").arg("README.txt").arg("--to-stdout").output().unwrap();
    assert_success("zm extract mkdcdisc-basic.cdi --to-stdout", &stdout);
    assert_eq!(stdout.stdout, b"ZManager free-tool CDI fixture\n");

    let file_output = temp.path("one");
    let extract_file =
        Command::new(cli_path()).arg("extract").arg(&archive).arg("-C").arg(&file_output).arg("--include").arg("nested/file.txt").output().unwrap();
    assert_success("zm extract mkdcdisc-basic.cdi --include nested/file.txt", &extract_file);
    assert_eq!(fs::read(file_output.join("nested/file.txt")).unwrap(), b"nested CDI payload\n");
    assert!(!file_output.join("README.txt").exists());

    let directory_output = temp.path("directory");
    let extract_directory =
        Command::new(cli_path()).arg("extract").arg(&archive).arg("-C").arg(&directory_output).arg("--include").arg("nested").output().unwrap();
    assert_success("zm extract mkdcdisc-basic.cdi --include nested", &extract_directory);
    assert_eq!(fs::read(directory_output.join("nested/file.txt")).unwrap(), b"nested CDI payload\n");
    assert!(!directory_output.join("README.txt").exists());
}

#[test]
fn cli_lists_tests_and_extracts_optical_disc_fixtures() {
    let iso_path = archives_dir().join("basic.iso");
    if !iso_path.exists() {
        return;
    }
    let iso_bytes = fs::read(&iso_path).unwrap();
    let iso_len = u32::try_from(iso_bytes.len()).unwrap();
    let temp = TestDir::new("fixture-cli-optical");

    // 1. NRG
    let nrg_path = temp.path("disc.nrg");
    let mut nrg_bytes = iso_bytes.clone();
    nrg_bytes.extend_from_slice(b"ETNF");
    nrg_bytes.extend_from_slice(&20_u32.to_be_bytes());
    nrg_bytes.extend_from_slice(&0_u32.to_be_bytes());
    nrg_bytes.extend_from_slice(&iso_len.to_be_bytes());
    nrg_bytes.extend_from_slice(&[0, 0, 0, 5]);
    nrg_bytes.extend_from_slice(&0_u32.to_be_bytes());
    nrg_bytes.extend_from_slice(b"END!");
    nrg_bytes.extend_from_slice(&0_u32.to_be_bytes());
    nrg_bytes.extend_from_slice(b"NERO");
    nrg_bytes.extend_from_slice(&iso_len.to_be_bytes());
    fs::write(&nrg_path, &nrg_bytes).unwrap();

    let list_nrg = Command::new(cli_path()).arg("list").arg(&nrg_path).output().unwrap();
    assert_success("zm list disc.nrg", &list_nrg);
    let test_nrg = Command::new(cli_path()).arg("test").arg(&nrg_path).output().unwrap();
    assert_success("zm test disc.nrg", &test_nrg);
    let out_nrg = temp.path("out_nrg");
    let extract_nrg = Command::new(cli_path()).arg("extract").arg(&nrg_path).arg("-C").arg(&out_nrg).output().unwrap();
    assert_success("zm extract disc.nrg", &extract_nrg);
    assert!(out_nrg.join("README.TXT").is_file());
    assert_optical_open_extract_matrix("disc.nrg", &nrg_path, &temp);

    // 2. CUE/BIN
    let bin_path = temp.path("disc.bin");
    let cue_path = temp.path("disc.cue");
    fs::write(&bin_path, &iso_bytes).unwrap();
    fs::write(&cue_path, "FILE \"disc.bin\" BINARY\r\n  TRACK 01 MODE1/2048\r\n    INDEX 01 00:00:00\r\n").unwrap();

    let list_cue = Command::new(cli_path()).arg("list").arg(&cue_path).output().unwrap();
    assert_success("zm list disc.cue", &list_cue);
    let test_cue = Command::new(cli_path()).arg("test").arg(&cue_path).output().unwrap();
    assert_success("zm test disc.cue", &test_cue);
    let out_cue = temp.path("out_cue");
    let extract_cue = Command::new(cli_path()).arg("extract").arg(&cue_path).arg("-C").arg(&out_cue).output().unwrap();
    assert_success("zm extract disc.cue", &extract_cue);
    assert!(out_cue.join("README.TXT").is_file());
    assert_optical_open_extract_matrix("disc.cue", &cue_path, &temp);

    // 3. CCD/IMG
    let img_path = temp.path("disc.img");
    let ccd_path = temp.path("disc.ccd");
    fs::write(&img_path, &iso_bytes).unwrap();
    fs::write(&ccd_path, "[CloneCD]\r\nVersion=3\r\n[Disc]\r\nTracks=1\r\n[Track 1]\r\nMode=1\r\n").unwrap();

    let list_ccd = Command::new(cli_path()).arg("list").arg(&ccd_path).output().unwrap();
    assert_success("zm list disc.ccd", &list_ccd);
    let test_ccd = Command::new(cli_path()).arg("test").arg(&ccd_path).output().unwrap();
    assert_success("zm test disc.ccd", &test_ccd);
    let out_ccd = temp.path("out_ccd");
    let extract_ccd = Command::new(cli_path()).arg("extract").arg(&ccd_path).arg("-C").arg(&out_ccd).output().unwrap();
    assert_success("zm extract disc.ccd", &extract_ccd);
    assert!(out_ccd.join("README.TXT").is_file());
    assert_optical_open_extract_matrix("disc.ccd", &ccd_path, &temp);

    // 4. MDS/MDF. Enter through both supported suffixes: `.mds` exercises the
    // descriptor directly, while `.mdf` proves sibling descriptor discovery.
    let mdf_path = temp.path("disc.mdf");
    let mds_path = temp.path("disc.mds");
    fs::write(&mdf_path, &iso_bytes).unwrap();
    let sector_count = u32::try_from(iso_bytes.len() / 2048).unwrap();
    fs::write(&mds_path, build_mds(2048, 0, sector_count)).unwrap();

    for (label, path) in [("disc.mdf", &mdf_path), ("disc.mds", &mds_path)] {
        let list = Command::new(cli_path()).arg("list").arg(path).output().unwrap();
        assert_success(&format!("zm list {label}"), &list);
        let test = Command::new(cli_path()).arg("test").arg(path).output().unwrap();
        assert_success(&format!("zm test {label}"), &test);
        let out = temp.path(format!("out_{label}"));
        let extract = Command::new(cli_path()).arg("extract").arg(path).arg("-C").arg(&out).output().unwrap();
        assert_success(&format!("zm extract {label}"), &extract);
        assert!(out.join("README.TXT").is_file(), "{label}");
        assert_optical_open_extract_matrix(label, path, &temp);
    }

    // 5. ISZ (UltraISO). ISZ has a real compressed-chunk
    // container format, so `build_isz` above constructs a genuine ISZ byte
    // stream (2 pointer widths and all 4 chunk types are exercised by
    // `zmanager-core`'s own unit tests against this exact recipe) rather than
    // wrapping the raw ISO bytes under the extension.
    let isz_path = temp.path("disc.isz");
    fs::write(&isz_path, build_isz(&iso_bytes, 2048, 65536, 3)).unwrap();

    let list_isz = Command::new(cli_path()).arg("list").arg(&isz_path).output().unwrap();
    assert_success("zm list disc.isz", &list_isz);
    let list_isz_stdout = String::from_utf8_lossy(&list_isz.stdout);
    assert!(list_isz_stdout.contains("README.TXT"), "{list_isz_stdout}");
    let test_isz = Command::new(cli_path()).arg("test").arg(&isz_path).output().unwrap();
    assert_success("zm test disc.isz", &test_isz);
    let out_isz = temp.path("out_isz");
    let extract_isz = Command::new(cli_path()).arg("extract").arg(&isz_path).arg("-C").arg(&out_isz).output().unwrap();
    assert_success("zm extract disc.isz", &extract_isz);
    assert!(out_isz.join("README.TXT").is_file());
    assert_eq!(fs::read(out_isz.join("NESTED/FILE.TXT")).unwrap(), b"nested fixture file\n");
    assert_optical_open_extract_matrix("disc.isz", &isz_path, &temp);
}

/// Extracts the VHD and VMDK fixtures with 7-Zip (which reads VPC and VMDK
/// containers natively) and compares the payload tree entry-for-entry against
/// zmanager's extraction. The UDF fixture is excluded: 7-Zip 26.02 fails to
/// list mkudffs-authored images, so hdiutil is the UDF oracle instead.
#[test]
fn optional_7zz_compares_vhd_vmdk_extraction_when_available() {
    let Some(seven_zip) = find_on_path("7zz") else {
        return;
    };
    for filename in ["basic.vhd", "basic.vmdk"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let temp = TestDir::new("fixture-cli-7zz-compare");
        let reference = temp.path("reference");
        let expand = Command::new(&seven_zip).arg("x").arg("-y").arg(format!("-o{}", reference.display())).arg(&fixture).output().unwrap();
        assert_success(&format!("7zz x {filename}"), &expand);

        let out = temp.path("zm");
        let extract = Command::new(zm_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).output().unwrap();
        assert_success(&format!("zm extract {filename}"), &extract);

        // Divergence filter: 7-Zip extracts the NTFS IntxLNK symlink as a
        // regular file (the raw 34-byte record) while zm materializes the
        // symlink itself (patched ntfs-core adapter) — documented, so the
        // entry is skipped on both sides for the VHD comparison. The FAT32
        // VMDK carries no symlink and the filter is a no-op there.
        assert_trees_match_filtered(&format!("7zz reference vs zm ({filename})"), &reference.join("payload"), &out.join("payload"), |rel| {
            rel.file_name().is_some_and(|name| name == "readme-link.txt")
        });
    }
}

/// The VHD/VMDK containers must satisfy qemu-img's own integrity check.
#[test]
fn optional_qemu_img_info_validates_virtual_disk_fixtures_when_available() {
    let Some(qemu_img) = find_on_path("qemu-img") else {
        return;
    };
    for filename in ["basic.vhd", "basic.vmdk"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let info = Command::new(&qemu_img).arg("info").arg(&fixture).output().unwrap();
        assert_success(&format!("qemu-img info {filename}"), &info);
        let stdout = String::from_utf8_lossy(&info.stdout);
        assert!(stdout.contains("file format:"), "{stdout}");
    }
}

/// macOS mounts UDF natively; attach the fixture read-only and compare the
/// mounted tree entry-for-entry against zmanager's extraction.
#[test]
fn optional_hdiutil_attach_compares_udf_fixture_when_available() {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    let fixture = archives_dir().join("basic.udf");
    if !fixture.exists() {
        return;
    }
    let temp = TestDir::new("fixture-cli-hdiutil-udf-compare");
    let mountpoint = temp.path("mount");
    let attach = Command::new("hdiutil").arg("attach").arg("-readonly").arg("-nobrowse").arg("-mountpoint").arg(&mountpoint).arg(&fixture).output().unwrap();
    if !attach.status.success() {
        eprintln!("skipping hdiutil UDF compare: attach failed: {}", String::from_utf8_lossy(&attach.stderr));
        return;
    }
    let out = temp.path("zm");
    let extract = Command::new(zm_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).output().unwrap();
    assert_success("zm extract basic.udf", &extract);

    let detach = Command::new("hdiutil").arg("detach").arg(&mountpoint).output().unwrap();
    assert_success("hdiutil detach", &detach);

    assert_trees_match("hdiutil reference vs zm (UDF)", &mountpoint.join("payload"), &out.join("payload"));
}

#[test]
fn cli_lists_tests_and_extracts_apple_dmg_pkg_fixtures() {
    for filename in ["basic.dmg", "basic.pkg"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let temp = TestDir::new("fixture-cli-apple");

        let list = Command::new(cli_path()).arg("list").arg(&fixture).output().unwrap();
        assert_success(&format!("zm list {filename}"), &list);
        let list_stdout = String::from_utf8_lossy(&list.stdout);
        assert!(list_stdout.contains("payload/README.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/nested/file.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/dir with spaces/file with spaces.txt"), "{list_stdout}");
        assert!(list_stdout.contains("payload/unicode/こんにちは.txt"), "{list_stdout}");
        assert!(!list_stdout.contains("payload/./"), "entries must not carry ./ prefixes: {list_stdout}");

        let json_list = Command::new(cli_path()).arg("list").arg(&fixture).arg("--json").output().unwrap();
        assert_success(&format!("zm list {filename} --json"), &json_list);
        let listing: serde_json::Value = serde_json::from_slice(&json_list.stdout).unwrap();
        let entries = listing["entries"].as_array().expect("JSON listing entries array");
        let kind_for = |path: &str| {
            entries
                .iter()
                .find(|entry| entry["name"].as_str() == Some(path))
                .and_then(|entry| entry["kind"].as_str())
                .unwrap_or_else(|| panic!("missing JSON listing entry {path} in {listing}"))
        };
        assert_eq!(kind_for("payload/README.txt"), "file", "regular file kind for {filename}");
        assert_eq!(kind_for("payload/nested"), "directory", "directory kind for {filename}");
        assert_eq!(kind_for("payload/nested/readme-link.txt"), "symlink", "symlink kind for {filename}");

        let test = Command::new(cli_path()).arg("test").arg(&fixture).output().unwrap();
        assert_success(&format!("zm test {filename}"), &test);

        let out = temp.path("out");
        let extract = Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).arg("--overwrite").arg("always").output().unwrap();
        assert_success(&format!("zm extract {filename}"), &extract);
        assert_eq!(fs::read_to_string(out.join("payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(out.join("payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(out.join("payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");
        assert_eq!(fs::read_to_string(out.join("payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");
        assert!(out.join("payload/nested/empty-dir").is_dir());
        #[cfg(unix)]
        {
            // The symlink target must be materialized, not skipped (APFS DMGs
            // store it in a catalog xattr; PKGs carry it in the cpio payload).
            let link = fs::read_link(out.join("payload/nested/readme-link.txt")).unwrap();
            assert_eq!(link, PathBuf::from("../README.txt"), "symlink target for {filename}");
        }

        // Selective extraction exercises pattern matching against the normalized paths.
        let out_sel = temp.path("out-sel");
        let selective =
            Command::new(cli_path()).arg("extract").arg(&fixture).arg("-C").arg(&out_sel).arg("--include").arg("payload/nested/file.txt").output().unwrap();
        assert_success(&format!("zm extract {filename} --include"), &selective);
        assert!(out_sel.join("payload/nested/file.txt").is_file());
        assert!(!out_sel.join("payload/README.txt").exists());

        // --to-stdout is explicitly unsupported for DMG and PKG.
        let stdout = Command::new(cli_path()).arg("extract").arg(&fixture).arg("--include").arg("payload/README.txt").arg("--to-stdout").output().unwrap();
        assert_failure(&format!("zm extract {filename} --to-stdout"), &stdout);
        assert!(
            String::from_utf8_lossy(&stdout.stderr).contains("do not currently support extracting to stdout"),
            "stderr:\n{}",
            String::from_utf8_lossy(&stdout.stderr)
        );
    }
}

#[test]
fn cli_lists_tests_and_extracts_checked_in_multipart_rar_fixtures() {
    let password = "zmanager-rar-fixture-password";

    for (filename, fixture_password) in [("rar5-multipart.part1.rar", None), ("rar5-passworded-multipart.part1.rar", Some(password))] {
        let archive = archives_dir().join(filename);
        let temp = TestDir::new("fixture-cli-multipart-rar");
        let mut list = Command::new(cli_path());
        list.arg("list").arg(&archive).arg("--json");
        let list = run_with_optional_password(list, fixture_password);
        assert_success(&format!("zm list {filename}"), &list);
        let list_stdout = String::from_utf8_lossy(&list.stdout);
        let listing: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
        let normalized_names: Vec<String> =
            listing["entries"].as_array().into_iter().flatten().filter_map(|entry| entry["name"].as_str().map(|name| name.replace('\\', "/"))).collect();
        assert_eq!(normalized_names.iter().filter(|name| name.as_str() == "rar-fixture/data/stream.bin").count(), 1, "{list_stdout}");

        let mut test = Command::new(cli_path());
        test.arg("test").arg(&archive).arg("--json");
        let test = run_with_optional_password(test, fixture_password);
        assert_success(&format!("zm test {filename}"), &test);
        let test_stdout = String::from_utf8_lossy(&test.stdout);
        assert!(test_stdout.contains("\"tested_entries\":6"), "{test_stdout}");

        let output = temp.path("out");
        let mut extract = Command::new(cli_path());
        extract.arg("extract").arg(&archive).arg("-C").arg(&output).arg("--overwrite").arg("always");
        let extract = run_with_optional_password(extract, fixture_password);
        assert_success(&format!("zm extract {filename}"), &extract);
        assert_eq!(fs::read(output.join("rar-fixture/data/stream.bin")).unwrap(), vec![0; 196_608]);
        assert_eq!(fs::read_to_string(output.join("rar-fixture/docs/readme.txt")).unwrap(), "RAR multipart fixture\n");
    }
}

#[test]
fn cli_preserves_rar_link_records_on_every_supported_platform() {
    let archive = archives_dir().join("rar5-links.rar");
    let list = Command::new(cli_path()).arg("list").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm list rar5-links.rar --json", &list);
    let listing: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let entries = listing["entries"].as_array().unwrap();
    for (path, kind, target) in [
        ("rar-links/target.txt", "file", None),
        ("rar-links/link.txt", "symlink", Some("target.txt")),
        ("rar-links/hard.txt", "hardlink", Some("rar-links/target.txt")),
        ("rar-links", "directory", None),
    ] {
        let entry = entries.iter().find(|entry| entry["name"].as_str() == Some(path)).unwrap_or_else(|| panic!("missing {path}: {listing}"));
        assert_eq!(entry["kind"].as_str(), Some(kind), "{path}");
        assert_eq!(entry["link_target"].as_str(), target, "{path}");
    }

    let tested = Command::new(cli_path()).arg("test").arg(&archive).output().unwrap();
    assert_success("zm test rar5-links.rar", &tested);

    #[cfg(unix)]
    {
        let temp = TestDir::new("fixture-cli-rar-links");
        let output = Command::new(cli_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
        assert_success("zm extract rar5-links.rar", &output);
        let target = temp.path("out/rar-links/target.txt");
        let hardlink = temp.path("out/rar-links/hard.txt");
        assert_same_file_identity(&target, &hardlink);

        let symlink = temp.path("out/rar-links/link.txt");
        assert!(fs::symlink_metadata(&symlink).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&symlink).unwrap(), PathBuf::from("target.txt"));
    }
    #[cfg(windows)]
    {
        let temp = TestDir::new("fixture-cli-rar-links-windows");
        let full = Command::new(cli_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("full")).output().unwrap();
        assert_failure("zm extract rar5-links.rar on Windows", &full);
        assert!(
            String::from_utf8_lossy(&full.stderr).contains("symlink extraction is not supported on this platform"),
            "{}",
            String::from_utf8_lossy(&full.stderr)
        );

        let selected = Command::new(cli_path())
            .arg("extract")
            .arg(&archive)
            .arg("-C")
            .arg(temp.path("selected"))
            .arg("--include")
            .arg("rar-links/target.txt")
            .arg("--include")
            .arg("rar-links/hard.txt")
            .output()
            .unwrap();
        assert_success("zm extract RAR target and hardlink on Windows", &selected);
        assert_same_file_identity(&temp.path("selected/rar-links/target.txt"), &temp.path("selected/rar-links/hard.txt"));
    }
}

#[test]
fn optional_unzip_validates_zip_fixture_when_available() {
    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let fixture = archives_dir().join("basic.zip");
    if !fixture.exists() {
        return;
    }

    let output = Command::new(unzip).arg("-t").arg(&fixture).output().unwrap();

    assert!(
        output.status.success(),
        "unzip failed for {}\nstdout:\n{}\nstderr:\n{}",
        fixture.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn optional_bsdtar_lists_common_archive_fixtures_when_available() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };

    for filename in ["basic.tar.gz", "basic.tar.xz", "basic.tar.zst", "basic.cpio"] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let output = Command::new(&bsdtar).arg("-tf").arg(&fixture).output().unwrap();

        assert!(
            output.status.success(),
            "bsdtar failed for {}\nstdout:\n{}\nstderr:\n{}",
            fixture.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn optional_xar_lists_xar_fixture_when_available() {
    let Some(xar) = find_on_path("xar") else {
        return;
    };
    let fixture = archives_dir().join("basic.xar");
    if !fixture.exists() {
        return;
    }

    let output = Command::new(xar).arg("-tf").arg(&fixture).output().unwrap();

    assert!(
        output.status.success(),
        "xar failed for {}\nstdout:\n{}\nstderr:\n{}",
        fixture.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The DMG fixture must pass Apple's own integrity check.
#[test]
fn optional_hdiutil_verifies_dmg_fixture_when_available() {
    let Some(hdiutil) = find_on_path("hdiutil") else {
        return;
    };
    let fixture = archives_dir().join("basic.dmg");
    if !fixture.exists() {
        return;
    }

    let output = Command::new(hdiutil).arg("verify").arg(&fixture).output().unwrap();

    assert!(
        output.status.success(),
        "hdiutil verify failed for {}\nstdout:\n{}\nstderr:\n{}",
        fixture.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Attaches the DMG with Apple's tools, copies the volume tree out, and
/// compares it entry-for-entry against zmanager's own extraction: the two
/// must agree on tree shape, file contents, and symlink targets.
#[test]
fn optional_hdiutil_attach_compares_dmg_extraction_when_available() {
    let Some(hdiutil) = find_on_path("hdiutil") else {
        return;
    };
    let fixture = archives_dir().join("basic.dmg");
    if !fixture.exists() {
        return;
    }

    let temp = TestDir::new("fixture-cli-hdiutil-compare");
    let mountpoint = temp.path("mnt");
    fs::create_dir_all(&mountpoint).unwrap();

    let attach = Command::new(&hdiutil).arg("attach").arg("-readonly").arg("-nobrowse").arg("-mountpoint").arg(&mountpoint).arg(&fixture).output().unwrap();
    assert_success("hdiutil attach", &attach);

    let reference = temp.path("reference");
    // ditto preserves symlinks and copies the whole volume root.
    let copy = Command::new("ditto").arg(&mountpoint).arg(&reference).output().unwrap();
    assert_success("ditto copy of attached volume", &copy);
    let detach = Command::new(hdiutil).arg("detach").arg(&mountpoint).output().unwrap();
    assert_success("hdiutil detach", &detach);

    let out = temp.path("zm");
    let extract = Command::new(zm_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).output().unwrap();
    assert_success("zm extract basic.dmg", &extract);

    // Compare the payload subtree only: the volume root may carry
    // filesystem-level metadata that ditto copies but that is not part of
    // the archived payload tree.
    assert!(reference.join("payload").is_dir(), "reference payload missing: {}", reference.display());
    assert_trees_match("hdiutil reference vs zm", &reference.join("payload"), &out.join("payload"));
}

/// Expands the PKG with Apple's own installer tools (`pkgutil --expand-full`)
/// and compares the payload tree entry-for-entry against zmanager's
/// extraction: same tree shape, file contents, and symlink targets.
#[test]
fn optional_pkgutil_compares_pkg_extraction_when_available() {
    let Some(pkgutil) = find_on_path("pkgutil") else {
        return;
    };
    let fixture = archives_dir().join("basic.pkg");
    if !fixture.exists() {
        return;
    }

    let temp = TestDir::new("fixture-cli-pkgutil-compare");
    let expanded = temp.path("expanded");
    let expand = Command::new(pkgutil).arg("--expand-full").arg(&fixture).arg(&expanded).output().unwrap();
    assert_success("pkgutil --expand-full", &expand);

    // Flat pkgbuild packages expand to Payload/payload/...; accept the
    // common layouts in case the component directory is named differently.
    let reference = ["Payload/payload", "payload"]
        .iter()
        .map(|rel| expanded.join(rel))
        .find(|path| path.is_dir())
        .unwrap_or_else(|| panic!("expanded payload missing under {}", expanded.display()));

    let out = temp.path("zm");
    let extract = Command::new(zm_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).output().unwrap();
    assert_success("zm extract basic.pkg", &extract);

    assert_trees_match("pkgutil reference vs zm", &reference, &out.join("payload"));
}

/// Extracts the MSI fixture with msitools' `msiextract` (the reference
/// Windows-Installer extraction tool) and compares the payload tree
/// entry-for-entry against zmanager's extraction.
#[test]
fn optional_msiextract_compares_msi_extraction_when_available() {
    let Some(msiextract) = find_on_path("msiextract") else {
        return;
    };
    let fixture = archives_dir().join("basic.msi");
    if !fixture.exists() {
        return;
    }

    let temp = TestDir::new("fixture-cli-msiextract-compare");
    let reference = temp.path("reference");
    let expand = Command::new(msiextract).arg("-C").arg(&reference).arg(&fixture).output().unwrap();
    assert_success("msiextract basic.msi", &expand);

    let out = temp.path("zm");
    let extract = Command::new(zm_path()).arg("extract").arg(&fixture).arg("-C").arg(&out).output().unwrap();
    assert_success("zm extract basic.msi", &extract);

    // msiextract resolves the Directory table the same way the backend does:
    // TARGETDIR -> payload -> nested / dir with spaces.
    assert_trees_match("msiextract reference vs zm", &reference.join("payload"), &out.join("payload"));
}

#[test]
fn zm_doctor_accepts_command_local_json_flag() {
    let output = Command::new(zm_path()).arg("doctor").arg("--json").output().unwrap();
    assert_success("zm doctor --json", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"engine\":\"zmanager-core\""), "{stdout}");
    assert!(stdout.contains("\"ready\":true"), "{stdout}");
}

#[test]
fn zm_creates_lists_tests_and_extracts_zip_folder() {
    let temp = TestDir::new("zm_zip_folder");
    fs::create_dir_all(temp.path("project/src")).unwrap();
    fs::write(temp.path("project/README.md"), "hello").unwrap();
    fs::write(temp.path("project/src/main.rs"), "fn main() {}\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf", &create);

    let list = Command::new(zm_path()).arg("-tf").arg(&archive).output().unwrap();
    assert_success("zm -tf", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("README.md"), "{list_stdout}");
    assert!(list_stdout.contains("src/main.rs"), "{list_stdout}");

    let test = Command::new(zm_path()).arg("-Tf").arg(&archive).output().unwrap();
    assert_success("zm -Tf", &test);

    let extract = Command::new(zm_path()).arg("-xf").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm -xf", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/project/README.md")).unwrap(), "hello");
}

#[cfg(target_os = "macos")]
#[test]
fn zm_creates_lists_tests_and_extracts_apple_archive_folder() {
    let temp = TestDir::new("zm_aar_folder");
    fs::create_dir_all(temp.path("project/src")).unwrap();
    fs::create_dir_all(temp.path("project/empty dir")).unwrap();
    fs::write(temp.path("project/README.md"), "hello aar").unwrap();
    fs::write(temp.path("project/src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(temp.path("project/space name.txt"), "safe odd name").unwrap();
    let archive = temp.path("project.aar");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create aar", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list aar", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("project/README.md"), "{list_stdout}");
    assert!(list_stdout.contains("project/src/main.rs"), "{list_stdout}");
    assert!(list_stdout.contains("project/space name.txt"), "{list_stdout}");
    assert!(list_stdout.contains("project/empty dir"), "{list_stdout}");

    let test = Command::new(zm_path()).arg("test").arg(&archive).output().unwrap();
    assert_success("zm test aar", &test);

    let stdout = Command::new(zm_path()).arg("extract").arg(&archive).arg("--include").arg("project/README.md").arg("--to-stdout").output().unwrap();
    assert_success("zm extract aar to stdout", &stdout);
    assert_eq!(stdout.stdout, b"hello aar");

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract aar", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/project/README.md")).unwrap(), "hello aar");
    assert_eq!(fs::read_to_string(temp.path("out/project/space name.txt")).unwrap(), "safe odd name");
    assert!(temp.path("out/project/empty dir").is_dir());
}

#[test]
fn zm_create_accepts_multiple_explicit_sources() {
    let temp = TestDir::new("zm_multiple_sources");
    fs::write(temp.path("README.md"), "readme").unwrap();
    fs::write(temp.path("LICENSE"), "license").unwrap();
    let archive = temp.path("release.zip");

    let output = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("README.md")).arg(temp.path("LICENSE")).output().unwrap();
    assert_success("zm create multiple sources", &output);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list --name-only", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("README.md"), "{stdout}");
    assert!(stdout.contains("LICENSE"), "{stdout}");
}

#[test]
fn zm_create_no_hidden_excludes_nested_hidden_entries() {
    let temp = TestDir::new("zm_no_hidden");
    fs::create_dir_all(temp.path("project/src/.hidden")).unwrap();
    fs::write(temp.path("project/src/lib.rs"), "pub fn f() {}\n").unwrap();
    fs::write(temp.path("project/src/.hidden/secret.txt"), "secret").unwrap();
    fs::write(temp.path("project/.config"), "hidden config").unwrap();
    fs::write(temp.path("project/README.md"), "readme").unwrap();
    let archive = temp.path("nohidden.zip");

    let output = Command::new(zm_path()).arg("create").arg(&archive).arg("--no-hidden").arg(temp.path("project")).output().unwrap();
    assert_success("zm create --no-hidden", &output);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list --name-only", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("lib.rs"), "{stdout}");
    assert!(stdout.contains("README.md"), "{stdout}");
    assert!(!stdout.contains(".config"), "{stdout}");
    assert!(!stdout.contains(".hidden"), "{stdout}");
    assert!(!stdout.contains("secret.txt"), "{stdout}");
}

#[test]
fn zm_create_accepts_long_create_file_form() {
    let temp = TestDir::new("zm_long_create_file");
    fs::write(temp.path("file.txt"), "content").unwrap();
    let archive = temp.path("long.zip");

    let output = Command::new(zm_path()).arg("--create").arg("--file").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert_success("zm --create --file", &output);

    let list = Command::new(zm_path()).arg("--list").arg("--file").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm --list --file", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("file.txt"), "{stdout}");
}

#[test]
fn zm_create_directory_base_uses_relative_archive_paths() {
    let temp = TestDir::new("zm_create_c");
    fs::create_dir_all(temp.path("project/src")).unwrap();
    fs::write(temp.path("project/src/lib.rs"), "pub fn f() {}\n").unwrap();
    fs::write(temp.path("project/README.md"), "readme").unwrap();
    let archive = temp.path("base.zip");

    let output = Command::new(zm_path()).arg("-cf").arg(&archive).arg("-C").arg(temp.path("project")).arg("src").arg("README.md").output().unwrap();
    assert_success("zm -cf -C", &output);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list -C archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("src/lib.rs"), "{stdout}");
    assert!(stdout.contains("README.md"), "{stdout}");
    assert!(!stdout.contains("project/src/lib.rs"), "{stdout}");
}

#[test]
fn zm_create_reads_newline_paths_from_stdin_with_at() {
    let temp = TestDir::new("zm_stdin_paths");
    fs::write(temp.path("a.txt"), "a").unwrap();
    fs::write(temp.path("b.txt"), "b").unwrap();
    let archive = temp.path("stdin.zip");

    let mut child = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg("-@")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", temp.path("a.txt").display()).unwrap();
        writeln!(stdin, "{}", temp.path("b.txt").display()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_success("zm -cf -@", &output);

    let list = Command::new(zm_path()).arg("-tf").arg(&archive).output().unwrap();
    assert_success("zm -tf stdin archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("a.txt"), "{stdout}");
    assert!(stdout.contains("b.txt"), "{stdout}");
}

#[test]
fn zm_create_reads_nul_paths_from_files_from_stdin() {
    let temp = TestDir::new("zm_null_paths");
    fs::write(temp.path("a space.txt"), "a").unwrap();
    fs::write(temp.path("b.txt"), "b").unwrap();
    let archive = temp.path("nul.zip");

    let mut child = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg("--files-from")
        .arg("-")
        .arg("--null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "{}\0{}\0", temp.path("a space.txt").display(), temp.path("b.txt").display()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_success("zm --files-from - --null", &output);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list null archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("a space.txt"), "{stdout}");
    assert!(stdout.contains("b.txt"), "{stdout}");
}

#[test]
fn zm_create_refuses_existing_destination_without_force() {
    let temp = TestDir::new("zm_force");
    fs::write(temp.path("file.txt"), "one").unwrap();
    let archive = temp.path("force.zip");

    let first = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert_success("first zm -cf", &first);

    let second = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert!(
        !second.status.success(),
        "second create unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    let forced = Command::new(zm_path()).arg("-cf").arg(&archive).arg("--force").arg(temp.path("file.txt")).output().unwrap();
    assert_success("forced zm -cf", &forced);
}

#[test]
fn zm_create_junk_paths_flattens_names_and_unzip_accepts_archive() {
    let temp = TestDir::new("zm_junk_paths");
    fs::create_dir_all(temp.path("src")).unwrap();
    fs::create_dir_all(temp.path("docs")).unwrap();
    fs::write(temp.path("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(temp.path("docs/guide.md"), "# Guide\n").unwrap();
    let archive = temp.path("junk.zip");

    let create = Command::new(zm_path()).arg("-jcf").arg(&archive).arg(temp.path("src/main.rs")).arg(temp.path("docs/guide.md")).output().unwrap();
    assert_success("zm -jcf", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list junk archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("main.rs"), "{stdout}");
    assert!(stdout.contains("guide.md"), "{stdout}");
    assert!(!stdout.contains("src/main.rs"), "{stdout}");
    assert!(!stdout.contains("docs/guide.md"), "{stdout}");

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_test = Command::new(unzip).arg("-t").arg(&archive).output().unwrap();
    assert_success("unzip -t zm junk archive", &unzip_test);
}

#[test]
fn zm_create_junk_paths_rejects_duplicate_flattened_names() {
    let temp = TestDir::new("zm_junk_paths_duplicate");
    fs::create_dir_all(temp.path("src")).unwrap();
    fs::create_dir_all(temp.path("test")).unwrap();
    fs::write(temp.path("src/config.json"), "{}").unwrap();
    fs::write(temp.path("test/config.json"), "{}").unwrap();
    let archive = temp.path("dup.zip");

    let output = Command::new(zm_path()).arg("-jcf").arg(&archive).arg(temp.path("src/config.json")).arg(temp.path("test/config.json")).output().unwrap();

    assert!(
        !output.status.success(),
        "duplicate junk paths unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate junk path"), "stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("src/config.json"), "stderr:\n{stderr}");
    assert!(stderr.contains("test/config.json"), "stderr:\n{stderr}");
    assert!(!archive.exists(), "failed create should not leave final archive");
}

#[test]
fn zm_lists_zip_created_with_competitor_junk_paths() {
    let Some(zip) = find_on_path("zip") else {
        return;
    };
    let temp = TestDir::new("zm_reads_zip_junk_paths");
    fs::create_dir_all(temp.path("src")).unwrap();
    fs::create_dir_all(temp.path("docs")).unwrap();
    fs::write(temp.path("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(temp.path("docs/guide.md"), "# Guide\n").unwrap();
    let archive = temp.path("competitor-junk.zip");

    let zip_output = Command::new(zip).current_dir(temp.root()).arg("-jq").arg(&archive).arg("src/main.rs").arg("docs/guide.md").output().unwrap();
    assert_success("zip -j", &zip_output);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list competitor junk archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("main.rs"), "{stdout}");
    assert!(stdout.contains("guide.md"), "{stdout}");
    assert!(!stdout.contains("src/main.rs"), "{stdout}");
}

#[test]
fn zm_create_zip_level_is_accepted_and_unzip_validates_archive() {
    let temp = TestDir::new("zm_zip_level");
    fs::write(temp.path("file.txt"), "repeat repeat repeat repeat\n").unwrap();
    let archive = temp.path("level.zip");

    let create = Command::new(zm_path()).arg("-9cf").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert_success("zm -9cf", &create);

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_test = Command::new(unzip).arg("-t").arg(&archive).output().unwrap();
    assert_success("unzip -t zm -9 archive", &unzip_test);
}

#[test]
fn zm_create_and_extract_zip_preserves_unicode_paths() {
    let temp = TestDir::new("zm_unicode_zip_roundtrip");
    fs::create_dir_all(temp.path("project/数据")).unwrap();
    fs::write(temp.path("project/数据/emoji-😀.txt"), "unicode\n").unwrap();
    let archive = temp.path("unicode.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create unicode zip", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list unicode zip", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("project/数据/emoji-😀.txt"), "{stdout}");

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract unicode zip", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/project/数据/emoji-😀.txt")).unwrap(), "unicode\n");
}

#[test]
fn zm_extract_zip_rejects_unicode_case_collision() {
    let temp = TestDir::new("zm_zip_unicode_case_collision");
    let archive = temp.path("unicode-collision.zip");
    write_zip_entries(&archive, CompressionMethod::Stored, &[("Über.txt", b"upper\n"), ("über.txt", b"lower\n")]);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();

    assert_failure("zm extract unicode collision zip", &extract);
    let stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(stderr.contains("collides with previous entry"), "{stderr}");
}

#[test]
fn zm_extract_zip_rejects_high_expansion_ratio_before_writing() {
    let temp = TestDir::new("zm_zip_expansion_ratio");
    let archive = temp.path("bomb.zip");
    let repeated = vec![0_u8; 8 * 1024 * 1024];
    write_zip_entries(&archive, CompressionMethod::Deflated, &[("bomb.bin", repeated.as_slice())]);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();

    assert_failure("zm extract high-ratio zip", &extract);
    let stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(stderr.contains("ratio limit"), "expected expansion-ratio failure\nstderr:\n{stderr}");
    assert!(!temp.path("out/bomb.bin").exists());
    assert_no_zmanager_temp_files(&temp.path("out"));
}

#[test]
fn zm_extract_nested_rejects_non_deb_and_default_zip_extraction_is_not_recursive() {
    let temp = TestDir::new("zm_nested_zip_not_recursive");
    let inner = temp.path("inner.zip");
    write_zip_entries(&inner, CompressionMethod::Stored, &[("inner.txt", b"inner\n")]);
    let inner_bytes = fs::read(&inner).unwrap();
    let archive = temp.path("outer.zip");
    write_zip_entries(&archive, CompressionMethod::Stored, &[("project/inner.zip", inner_bytes.as_slice())]);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract zip containing nested zip", &extract);
    assert!(temp.path("out/project/inner.zip").is_file());
    assert!(!temp.path("out/project/inner.txt").exists(), "plain extraction should not recursively expand nested archives");

    let nested = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("nested-out")).arg("--extract-nested").output().unwrap();
    assert_failure("zm extract --extract-nested non-deb", &nested);
    assert!(String::from_utf8_lossy(&nested.stderr).contains("only for .deb packages"), "{}", String::from_utf8_lossy(&nested.stderr));
}

#[test]
fn zm_extract_nested_deb_handles_gzip_and_zstd_payload_members() {
    let temp = TestDir::new("zm_deb_payload_variants");
    let control_tar = tar_bytes(&[("control", b"Package: zmanager-compat\n")]);
    let data_tar = tar_bytes(&[("usr/share/zmanager-compat/file.txt", b"deb payload\n")]);
    let control_gz = gzip_bytes(&control_tar);

    let variants = [("gzip", "data.tar.gz", gzip_bytes(&data_tar)), ("zstd", "data.tar.zst", zstd_bytes(&data_tar))];

    for (label, data_member_name, data_member) in variants {
        let archive = temp.path(format!("payload-{label}.deb"));
        write_deb_ar_archive(&archive, "control.tar.gz", &control_gz, data_member_name, &data_member);

        let out = temp.path(format!("out-{label}"));
        let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(&out).arg("--extract-nested").output().unwrap();
        assert_success(&format!("zm extract --extract-nested deb {label}"), &extract);
        assert_eq!(fs::read_to_string(out.join("control/control")).unwrap(), "Package: zmanager-compat\n");
        assert_eq!(fs::read_to_string(out.join("data/usr/share/zmanager-compat/file.txt")).unwrap(), "deb payload\n");

        let debian_binary_meta = fs::metadata(out.join("debian-binary")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(debian_binary_meta.permissions().mode() & 0o777, 0o644);
        }
        let modified = debian_binary_meta.modified().unwrap();
        let duration = modified.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(duration.as_secs(), 0);
    }
}

#[test]
fn zm_create_tar_zst_level_round_trips_and_bsdtar_extracts_when_available() {
    let temp = TestDir::new("zm_tar_zst_level");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "zstd level\n").unwrap();
    let archive = temp.path("project.tar.zst");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).arg("--level").arg("1").output().unwrap();
    assert_success("zm create tar.zst --level 1", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-zm")).output().unwrap();
    assert_success("zm extract tar.zst level archive", &extract);
    assert_eq!(fs::read_to_string(temp.path("out-zm/project/file.txt")).unwrap(), "zstd level\n");

    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    fs::create_dir_all(temp.path("out-bsdtar")).unwrap();
    let bsdtar_extract = Command::new(bsdtar).arg("-xf").arg(&archive).arg("-C").arg(temp.path("out-bsdtar")).output().unwrap();
    assert_success("bsdtar -xf zm tar.zst level archive", &bsdtar_extract);
    assert_eq!(fs::read_to_string(temp.path("out-bsdtar/project/file.txt")).unwrap(), "zstd level\n");
}

#[test]
fn zm_create_tgz_level_round_trips_and_bsdtar_extracts_when_available() {
    let temp = TestDir::new("zm_tgz_level");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "gzip level\n").unwrap();
    let archive = temp.path("project.tar.gz");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).arg("--level").arg("1").output().unwrap();
    assert_success("zm create tgz --level 1", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-zm")).output().unwrap();
    assert_success("zm extract tgz level archive", &extract);
    assert_eq!(fs::read_to_string(temp.path("out-zm/project/file.txt")).unwrap(), "gzip level\n");

    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    fs::create_dir_all(temp.path("out-bsdtar")).unwrap();
    let bsdtar_extract = Command::new(bsdtar).arg("-xf").arg(&archive).arg("-C").arg(temp.path("out-bsdtar")).output().unwrap();
    assert_success("bsdtar -xf zm tgz level archive", &bsdtar_extract);
    assert_eq!(fs::read_to_string(temp.path("out-bsdtar/project/file.txt")).unwrap(), "gzip level\n");
}

#[test]
fn zm_create_tgz_alias_round_trips_with_inferred_format() {
    let temp = TestDir::new("zm_tgz_alias");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "tgz alias\n").unwrap();
    let archive = temp.path("project.tgz");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create tgz", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract tgz alias archive", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "tgz alias\n");
}

#[test]
fn zm_create_tzst_alias_round_trips_with_inferred_format() {
    let temp = TestDir::new("zm_tzst_alias");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "tzst alias\n").unwrap();
    let archive = temp.path("project.tzst");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create .tzst alias", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract .tzst alias", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "tzst alias\n");
}

#[test]
fn zm_create_tzap_round_trips_with_password_stdin() {
    let temp = TestDir::new("zm_tzap_roundtrip");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/nested/file.txt"), "tzap payload\n").unwrap();
    let archive = temp.path("project.tzap");

    let mut create = Command::new(zm_path());
    create.arg("create").arg(&archive).arg(temp.path("project")).arg("--password-stdin").arg("--level").arg("1");
    let create = run_with_stdin(create, "correct horse\n");
    assert_success("zm create tzap --password-stdin", &create);

    let mut list = Command::new(zm_path());
    list.arg("list").arg(&archive).arg("--password-stdin").arg("--json");
    let list = run_with_stdin(list, "correct horse\n");
    assert_success("zm list tzap --password-stdin --json", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("\"name\":\"project/nested/file.txt\""));
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let listed_entry = &list_json["entries"][0];
    assert!(listed_entry["mode"].is_u64());
    assert!(listed_entry["modified"].is_string());
    assert!(listed_entry["metadata_diagnostics"].is_array());

    let mut long_list = Command::new(zm_path());
    long_list.arg("list").arg(&archive).arg("--password-stdin").arg("--long");
    let long_list = run_with_stdin(long_list, "correct horse\n");
    assert_success("zm list tzap --password-stdin --long", &long_list);
    let long_stdout = String::from_utf8_lossy(&long_list.stdout);
    assert!(long_stdout.contains("TYPE\tMODE\tSIZE\tCOMPRESSED\tMODIFIED\tPATH"));

    let mut test = Command::new(zm_path());
    test.arg("test").arg(&archive).arg("--password-stdin").arg("--include").arg("project/nested/**").arg("--json");
    let test = run_with_stdin(test, "correct horse\n");
    assert_success("zm test tzap --password-stdin --json", &test);
    let test_stdout = String::from_utf8_lossy(&test.stdout);
    assert!(test_stdout.contains("\"format\":\"tzap\""), "{test_stdout}");

    let mut extract = Command::new(zm_path());
    extract.arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).arg("--password-stdin").arg("--strip-components").arg("1");
    let extract = run_with_stdin(extract, "correct horse\n");
    assert_success("zm extract tzap --password-stdin", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/nested/file.txt")).unwrap(), "tzap payload\n");

    let mut stdout = Command::new(zm_path());
    stdout.arg("extract").arg(&archive).arg("--password-stdin").arg("--to-stdout").arg("--include").arg("project/nested/file.txt");
    let stdout = run_with_stdin(stdout, "correct horse\n");
    assert_success("zm extract tzap --to-stdout", &stdout);
    assert_eq!(stdout.stdout, b"tzap payload\n");
}

#[test]
fn zm_create_tzap_without_password_uses_unencrypted_mode() {
    let temp = TestDir::new("zm_tzap_unencrypted");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "public\n").unwrap();
    let archive = temp.path("project.tzap");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create tzap without password", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm list unencrypted tzap", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("\"name\":\"project/file.txt\""));

    let test = Command::new(zm_path()).arg("test").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm test unencrypted tzap", &test);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).arg("--strip-components").arg("1").output().unwrap();
    assert_success("zm extract unencrypted tzap", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/file.txt")).unwrap(), "public\n");
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn zm_extract_tzap_honors_metadata_restore_policy() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let temp = TestDir::new("zm_tzap_restore_policy");
    let source_root = temp.path("project");
    let source_directory = temp.path("project/scripts");
    let source_file = temp.path("project/scripts/executable.sh");
    let source_link = temp.path("project/current");
    fs::create_dir_all(&source_directory).unwrap();
    fs::write(&source_file, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&source_file, fs::Permissions::from_mode(0o751)).unwrap();
    fs::set_permissions(&source_directory, fs::Permissions::from_mode(0o750)).unwrap();
    symlink("scripts/executable.sh", &source_link).unwrap();

    #[cfg(target_os = "macos")]
    {
        xattr::set(&source_file, "com.tzap.zm", b"file metadata").unwrap();
        xattr::set(&source_directory, "com.tzap.zm", b"directory metadata").unwrap();
        xattr::set(&source_link, "com.tzap.zm", b"link metadata").unwrap();
        for source in [&source_file, &source_directory] {
            assert!(Command::new("/bin/chmod").args(["+a", "everyone deny delete"]).arg(source).status().unwrap().success());
        }
        assert!(Command::new("/bin/chmod").args(["-h", "+a", "everyone deny delete"]).arg(&source_link).status().unwrap().success());
        for source in [&source_file, &source_directory] {
            assert!(Command::new("/usr/bin/chflags").arg("hidden").arg(source).status().unwrap().success());
        }
        assert!(Command::new("/usr/bin/chflags").args(["-h", "hidden"]).arg(&source_link).status().unwrap().success());
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
        xattr::set(&source_file, "user.zmanager.cli", b"file metadata").unwrap();
        xattr::set(&source_directory, "user.zmanager.cli", b"directory metadata").unwrap();
        xattr::set(&source_file, "system.posix_acl_access", &file_acl).unwrap();
        xattr::set(&source_directory, "system.posix_acl_access", &directory_acl).unwrap();
        (xattr::get(&source_file, "system.posix_acl_access").unwrap().unwrap(), xattr::get(&source_directory, "system.posix_acl_access").unwrap().unwrap())
    };

    let source_file_metadata = fs::symlink_metadata(&source_file).unwrap();
    let source_directory_metadata = fs::symlink_metadata(&source_directory).unwrap();
    let archive = temp.path("metadata.tzap");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg("-y").arg(&source_root).output().unwrap();
    assert_success("zm create metadata tzap", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm list metadata tzap", &list);
    let listing: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let entries = listing["entries"].as_array().unwrap();
    let listed_file = entries.iter().find(|entry| entry["name"] == "project/scripts/executable.sh").unwrap();
    for field in ["modified", "accessed", "encrypted", "method", "solid", "uid", "gid", "owner", "group"] {
        assert!(!listed_file[field].is_null(), "{field}");
    }
    #[cfg(target_os = "macos")]
    assert!(!listed_file["created"].is_null(), "APFS creation time should be listed");
    #[cfg(windows)]
    assert!(!listed_file["attributes"].is_null());
    #[cfg(target_os = "macos")]
    {
        // Fast index listing for .tzap on macOS exposes null for portable attributes
        // because native BSD flags are stored in PAX header extensions (TZAP.macos.st-flags).
        // Restored BSD flags on extraction are verified below.
        assert!(listed_file["attributes"].is_null());
    }
    let listed_link = entries.iter().find(|entry| entry["name"] == "project/current").unwrap();
    assert_eq!(listed_link["link_target"], "scripts/executable.sh");

    let policies: &[&str] = if unix_process_is_elevated() { &["portable", "same-os", "system"] } else { &["portable", "same-os"] };
    for &policy in policies {
        let destination = temp.path(format!("restore-{policy}"));
        let mut restore_command = Command::new(zm_path());
        restore_command.arg("extract").arg(&archive).arg("-C").arg(&destination).arg("--restore").arg(policy);
        #[cfg(target_os = "macos")]
        if policy == "portable" {
            restore_command.arg("--allow-degraded");
        }
        #[cfg(target_os = "linux")]
        if policy != "portable" {
            restore_command.arg("--allow-degraded");
        }
        let restore = restore_command.output().unwrap();
        assert_success(&format!("zm extract tzap {policy} metadata"), &restore);

        let restored_file = destination.join("project/scripts/executable.sh");
        let restored_directory = destination.join("project/scripts");
        let restored_link = destination.join("project/current");
        let restored_file_metadata = fs::symlink_metadata(&restored_file).unwrap();
        let restored_directory_metadata = fs::symlink_metadata(&restored_directory).unwrap();
        assert_eq!(restored_file_metadata.permissions().mode() & 0o7777, source_file_metadata.permissions().mode() & 0o7777);
        assert_eq!(restored_directory_metadata.permissions().mode() & 0o7777, source_directory_metadata.permissions().mode() & 0o7777);
        assert_eq!(fs::read_link(&restored_link).unwrap(), Path::new("scripts/executable.sh"));
        assert_eq!((restored_file_metadata.mtime(), restored_file_metadata.mtime_nsec()), (source_file_metadata.mtime(), source_file_metadata.mtime_nsec()));

        #[cfg(target_os = "macos")]
        {
            use std::os::macos::fs::MetadataExt as _;

            if policy == "portable" {
                assert_eq!(xattr::get(&restored_file, "com.tzap.zm").unwrap(), None);
                continue;
            }
            assert_eq!(fs::symlink_metadata(&restored_file).unwrap().st_flags(), source_file_metadata.st_flags());
            assert_eq!(fs::symlink_metadata(&restored_directory).unwrap().st_flags(), source_directory_metadata.st_flags());
            assert_eq!(fs::symlink_metadata(&restored_link).unwrap().st_flags(), fs::symlink_metadata(&source_link).unwrap().st_flags());
            assert_eq!(xattr::get(&restored_file, "com.tzap.zm").unwrap().as_deref(), Some(b"file metadata".as_slice()));
            assert_eq!(xattr::get(&restored_directory, "com.tzap.zm").unwrap().as_deref(), Some(b"directory metadata".as_slice()));
            assert_eq!(xattr::get(&restored_link, "com.tzap.zm").unwrap().as_deref(), Some(b"link metadata".as_slice()));
            for restored_path in [&restored_file, &restored_directory, &restored_link] {
                let acl = Command::new("/bin/ls").args(["-lde"]).arg(restored_path).output().unwrap();
                assert!(acl.status.success());
                assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
            }
        }

        #[cfg(target_os = "linux")]
        {
            if policy == "portable" {
                assert_eq!(xattr::get(&restored_file, "user.zmanager.cli").unwrap(), None);
                assert_eq!(xattr::get(&restored_directory, "user.zmanager.cli").unwrap(), None);
                continue;
            }
            assert_eq!(xattr::get(&restored_file, "user.zmanager.cli").unwrap().as_deref(), Some(b"file metadata".as_slice()));
            assert_eq!(xattr::get(&restored_directory, "user.zmanager.cli").unwrap().as_deref(), Some(b"directory metadata".as_slice()));
            assert_eq!(xattr::get(&restored_file, "system.posix_acl_access").unwrap().as_deref(), Some(expected_file_acl.as_slice()));
            assert_eq!(xattr::get(&restored_directory, "system.posix_acl_access").unwrap().as_deref(), Some(expected_directory_acl.as_slice()));
        }
    }

    let content = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("content"))
        .arg("--restore")
        .arg("content")
        .arg("--allow-degraded")
        .output()
        .unwrap();
    assert_success("zm extract tzap content only", &content);
    assert_ne!(fs::metadata(temp.path("content/project/scripts/executable.sh")).unwrap().permissions().mode() & 0o777, 0o751);
}

#[cfg(windows)]
#[test]
fn zm_extract_tzap_preserves_windows_entry_metadata() {
    use std::os::windows::fs::MetadataExt as _;

    let temp = TestDir::new("zm_tzap_windows_restore_policy");
    let source_root = temp.path("project");
    let source_directory = temp.path("project/scripts");
    let source_file = temp.path("project/scripts/payload.txt");
    let source_link = temp.path("project/current.txt");
    fs::create_dir_all(&source_directory).unwrap();
    fs::write(&source_file, b"windows metadata").unwrap();
    if !try_create_windows_relative_symlink(&source_link, r"scripts\payload.txt") {
        eprintln!("skipping zm_extract_tzap_preserves_windows_entry_metadata: symlink privilege not held");
        return;
    }
    fs::write(PathBuf::from(format!("{}:zmanager-cli", source_file.display())), b"file alternate data").unwrap();
    fs::write(PathBuf::from(format!("{}:zmanager-cli", source_directory.display())), b"directory alternate data").unwrap();
    assert!(Command::new("attrib").args(["+H", source_file.to_str().unwrap()]).status().unwrap().success());
    let mut permissions = fs::metadata(&source_file).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&source_file, permissions).unwrap();
    let source_file_metadata = fs::symlink_metadata(&source_file).unwrap();
    let source_directory_metadata = fs::symlink_metadata(&source_directory).unwrap();
    let archive = temp.path("metadata.tzap");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg("-y").arg(&source_root).output().unwrap();
    assert_success("zm create Windows metadata tzap", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm list Windows metadata tzap", &list);
    let listing: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let entries = listing["entries"].as_array().unwrap();
    let file_entry = entries.iter().find(|entry| entry["name"] == "project/scripts/payload.txt").unwrap();
    assert!(file_entry["created"].is_string());
    assert!(file_entry["accessed"].is_string());
    assert!(file_entry["attributes"].is_string());
    let link_entry = entries.iter().find(|entry| entry["name"] == "project/current.txt").unwrap();
    assert_eq!(link_entry["link_target"], "scripts/payload.txt");

    let policies: &[&str] = if windows_process_is_elevated() { &["portable", "same-os", "system"] } else { &["portable", "same-os"] };
    for &policy in policies {
        let destination = temp.path(format!("restore-{policy}"));
        let mut restore_command = Command::new(zm_path());
        restore_command.arg("extract").arg(&archive).arg("-C").arg(&destination).arg("--restore").arg(policy);
        if policy == "portable" {
            restore_command.arg("--allow-degraded");
        }
        let restore = restore_command.output().unwrap();
        assert_success(&format!("zm extract Windows tzap {policy}"), &restore);

        let restored_file = destination.join("project/scripts/payload.txt");
        let restored_directory = destination.join("project/scripts");
        let restored_link = destination.join("project/current.txt");
        let restored_file_ads = PathBuf::from(format!("{}:zmanager-cli", restored_file.display()));
        let restored_directory_ads = PathBuf::from(format!("{}:zmanager-cli", restored_directory.display()));
        let restored_file_metadata = fs::symlink_metadata(&restored_file).unwrap();
        let restored_directory_metadata = fs::symlink_metadata(&restored_directory).unwrap();
        assert_eq!(fs::read(&restored_file).unwrap(), b"windows metadata");
        assert_eq!(fs::read_link(&restored_link).unwrap(), Path::new("scripts/payload.txt"));
        if policy == "portable" {
            assert!(fs::read(&restored_file_ads).is_err());
            assert!(fs::read(&restored_directory_ads).is_err());
        } else {
            assert_eq!(fs::read(&restored_file_ads).unwrap(), b"file alternate data");
            assert_eq!(fs::read(&restored_directory_ads).unwrap(), b"directory alternate data");
        }
        let attribute_mask = if policy == "portable" { 0x1 } else { 0x23 };
        assert_eq!(restored_file_metadata.file_attributes() & attribute_mask, source_file_metadata.file_attributes() & attribute_mask);
        assert_eq!(restored_file_metadata.last_write_time(), source_file_metadata.last_write_time());
        if policy != "portable" {
            assert_eq!(restored_file_metadata.creation_time(), source_file_metadata.creation_time());
            assert_eq!(restored_file_metadata.last_access_time(), source_file_metadata.last_access_time());
            assert_eq!(restored_directory_metadata.creation_time(), source_directory_metadata.creation_time());
        }
    }

    let mut permissions = fs::metadata(&source_file).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&source_file, permissions).unwrap();
}

#[test]
fn zm_create_tzap_accepts_bare_relative_archive_path() {
    let temp = TestDir::new("zm_tzap_bare_relative_output");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "relative output\n").unwrap();

    let create = Command::new(zm_path()).current_dir(temp.root()).arg("create").arg("project.tzap").arg("project").output().unwrap();
    assert_success("zm create with bare relative tzap output", &create);
    assert!(temp.path("project.tzap").is_file());

    let list = Command::new(zm_path()).current_dir(temp.root()).arg("list").arg("project.tzap").arg("--name-only").output().unwrap();
    assert_success("zm list bare relative tzap output", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("project/file.txt"));
}

#[test]
fn zm_create_7z_level_round_trips_with_backend() {
    let temp = TestDir::new("zm_7z_level");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "7z level\n").unwrap();
    let archive = temp.path("project.7z");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).arg("--level").arg("1").output().unwrap();
    assert_success("zm create 7z --level 1", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list 7z level archive", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("project/file.txt"), "{}", String::from_utf8_lossy(&list.stdout));

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract 7z level archive", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "7z level\n");
}

#[test]
fn optional_7zip_validates_zm_created_7z_when_available() {
    let Some(sevenzip) = find_7zip() else {
        return;
    };
    let temp = TestDir::new("zm_7zip_validates_zm_archive");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "7zip validation\n").unwrap();
    let archive = temp.path("project.7z");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf 7z for external 7zip", &create);

    let test = Command::new(sevenzip).arg("t").arg("-bd").arg(&archive).output().unwrap();
    assert_success("7zz t zm-created 7z archive", &test);
}

#[test]
fn optional_zm_extracts_7zip_created_archive_when_available() {
    let Some(sevenzip) = find_7zip() else {
        return;
    };
    let temp = TestDir::new("zm_extract_7zip_archive");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "created by 7zip\n").unwrap();
    let archive = temp.path("competitor.7z");

    let create = Command::new(sevenzip).current_dir(temp.root()).arg("a").arg("-t7z").arg("-bd").arg(&archive).arg("project").output().unwrap();
    assert_success("7zz a competitor 7z archive", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract 7zz-created archive", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "created by 7zip\n");
}

#[test]
fn zm_create_split_zip_lists_extracts_and_7zip_tests_when_available() {
    let temp = TestDir::new("zm_split_zip");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/blob.bin"), deterministic_bytes(200_000)).unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("project"))
        .arg("--format")
        .arg("zip")
        .arg("--store")
        .arg("--volume-size")
        .arg("64k")
        .arg("--json")
        .output()
        .unwrap();
    assert_success("zm create split zip", &create);
    let stdout = String::from_utf8_lossy(&create.stdout);
    assert!(stdout.contains("\"volume_size\":65536"), "{stdout}");
    assert!(stdout.contains("\"volume_count\":"), "{stdout}");
    assert_eq!(fs::metadata(temp.path("project.z01")).unwrap().len(), 65_536);
    assert!(archive.is_file());

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list split zip", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("project/blob.bin"), "{}", String::from_utf8_lossy(&list.stdout));

    let zm_test = Command::new(zm_path()).arg("test").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm test split zip", &zm_test);
    assert!(String::from_utf8_lossy(&zm_test.stdout).contains("\"format\":\"zip\""), "{}", String::from_utf8_lossy(&zm_test.stdout));
    assert!(String::from_utf8_lossy(&zm_test.stdout).contains("\"bytes\":200000"), "{}", String::from_utf8_lossy(&zm_test.stdout));

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract split zip", &extract);
    let expected = fs::read(temp.path("project/blob.bin")).unwrap();
    assert_eq!(fs::read(temp.path("out/project/blob.bin")).unwrap(), expected);
    assert_split_archive_selective_matrix("split-zip", &archive, &temp, &expected);

    if let Some(sevenzip) = find_7zip() {
        let test = Command::new(sevenzip).arg("t").arg(&archive).output().unwrap();
        assert_success("7zz test zm split zip", &test);
    }
}

#[test]
fn zm_create_split_7z_lists_extracts_and_7zip_tests_when_available() {
    let temp = TestDir::new("zm_split_7z");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/blob.bin"), deterministic_bytes(3_200_000)).unwrap();
    let archive = temp.path("project.7z");
    let first_volume = temp.path("project.7z.001");

    let create = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("project"))
        .arg("--format")
        .arg("7z")
        .arg("--volume-size")
        .arg("1m")
        .output()
        .unwrap();
    assert_success("zm create split 7z", &create);
    assert!(!archive.exists());
    assert_eq!(fs::metadata(&first_volume).unwrap().len(), 1_048_576);
    assert!(temp.path("project.7z.002").is_file());

    let list = Command::new(zm_path()).arg("list").arg(&first_volume).arg("--name-only").output().unwrap();
    assert_success("zm list split 7z", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("project/blob.bin"), "{}", String::from_utf8_lossy(&list.stdout));

    let zm_test = Command::new(zm_path()).arg("test").arg(&first_volume).arg("--json").output().unwrap();
    assert_success("zm test split 7z", &zm_test);
    assert!(String::from_utf8_lossy(&zm_test.stdout).contains("\"format\":\"7z\""), "{}", String::from_utf8_lossy(&zm_test.stdout));

    let extract = Command::new(zm_path()).arg("extract").arg(&first_volume).arg("-C").arg(temp.path("out")).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract split 7z", &extract);
    let expected = fs::read(temp.path("project/blob.bin")).unwrap();
    assert_eq!(fs::read(temp.path("out/project/blob.bin")).unwrap(), expected);
    assert_split_archive_selective_matrix("split-7z", &first_volume, &temp, &expected);

    if let Some(sevenzip) = find_7zip() {
        let test = Command::new(sevenzip).arg("t").arg(&first_volume).output().unwrap();
        assert_success("7zz test zm split 7z", &test);
    }
}

fn assert_split_archive_selective_matrix(label: &str, archive: &Path, temp: &TestDir, expected: &[u8]) {
    let one_output = temp.path(format!("out-{label}-one"));
    let one = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&one_output).arg("--include").arg("project/blob.bin").output().unwrap();
    assert_success(&format!("zm extract {label} selected file"), &one);
    assert_eq!(fs::read(one_output.join("project/blob.bin")).unwrap(), expected);

    let directory_output = temp.path(format!("out-{label}-directory"));
    let directory = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&directory_output).arg("--include").arg("project").output().unwrap();
    assert_success(&format!("zm extract {label} selected directory"), &directory);
    assert_eq!(fs::read(directory_output.join("project/blob.bin")).unwrap(), expected);

    let stdout = Command::new(zm_path()).arg("extract").arg(archive).arg("--include").arg("project/blob.bin").arg("--to-stdout").output().unwrap();
    assert_success(&format!("zm extract {label} selected file to stdout"), &stdout);
    assert_eq!(stdout.stdout, expected);
}

#[test]
fn zm_create_single_volume_split_7z_lists_base_archive_path() {
    let temp = TestDir::new("zm_single_volume_split_7z_base");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "small payload\n").unwrap();
    let archive = temp.path("project.7z");

    let create = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("project"))
        .arg("--format")
        .arg("7z")
        .arg("--volume-size")
        .arg("1m")
        .output()
        .unwrap();
    assert_success("zm create single-volume split 7z", &create);
    assert!(!archive.exists());
    assert!(temp.path("project.7z.001").is_file());

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--name-only").output().unwrap();
    assert_success("zm list base path for single-volume split 7z", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("project/file.txt"), "{}", String::from_utf8_lossy(&list.stdout));
}

#[test]
fn zm_create_passworded_split_archives_extract_with_password_stdin() {
    let temp = TestDir::new("zm_passworded_split_archives");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/blob.bin"), deterministic_bytes(3_200_000)).unwrap();

    let zip_archive = temp.path("secret.zip");
    let mut create_zip = Command::new(zm_path());
    create_zip
        .arg("create")
        .arg(&zip_archive)
        .arg(temp.path("project"))
        .arg("--format")
        .arg("zip")
        .arg("--store")
        .arg("--volume-size")
        .arg("64k")
        .arg("--encrypt")
        .arg("--password-stdin");
    let zip_create = run_with_stdin(create_zip, "correct horse\n");
    assert_success("zm create passworded split zip", &zip_create);
    assert!(temp.path("secret.z01").is_file());

    let mut extract_zip = Command::new(zm_path());
    extract_zip.arg("extract").arg(&zip_archive).arg("-C").arg(temp.path("out-zip")).arg("--overwrite").arg("always").arg("--password-stdin");
    let zip_extract = run_with_stdin(extract_zip, "correct horse\n");
    assert_success("zm extract passworded split zip", &zip_extract);
    assert_eq!(fs::read(temp.path("out-zip/project/blob.bin")).unwrap(), fs::read(temp.path("project/blob.bin")).unwrap());

    let mut test_zip = Command::new(zm_path());
    test_zip.arg("test").arg(&zip_archive).arg("--json").arg("--password-stdin");
    let zip_test = run_with_stdin(test_zip, "correct horse\n");
    assert_success("zm test passworded split zip", &zip_test);
    assert!(String::from_utf8_lossy(&zip_test.stdout).contains("\"format\":\"zip\""), "{}", String::from_utf8_lossy(&zip_test.stdout));

    let sevenz_archive = temp.path("secret.7z");
    let first_7z_volume = temp.path("secret.7z.001");
    let mut create_7z = Command::new(zm_path());
    create_7z
        .arg("create")
        .arg(&sevenz_archive)
        .arg(temp.path("project"))
        .arg("--format")
        .arg("7z")
        .arg("--volume-size")
        .arg("1m")
        .arg("--encrypt")
        .arg("--password-stdin");
    let sevenz_create = run_with_stdin(create_7z, "correct horse\n");
    assert_success("zm create passworded split 7z", &sevenz_create);
    assert!(first_7z_volume.is_file());

    let mut extract_7z = Command::new(zm_path());
    extract_7z.arg("extract").arg(&first_7z_volume).arg("-C").arg(temp.path("out-7z")).arg("--overwrite").arg("always").arg("--password-stdin");
    let sevenz_extract = run_with_stdin(extract_7z, "correct horse\n");
    assert_success("zm extract passworded split 7z", &sevenz_extract);
    assert_eq!(fs::read(temp.path("out-7z/project/blob.bin")).unwrap(), fs::read(temp.path("project/blob.bin")).unwrap());

    let mut test_7z = Command::new(zm_path());
    test_7z.arg("test").arg(&first_7z_volume).arg("--json").arg("--password-stdin");
    let sevenz_test = run_with_stdin(test_7z, "correct horse\n");
    assert_success("zm test passworded split 7z", &sevenz_test);
    let stdout = String::from_utf8_lossy(&sevenz_test.stdout);
    assert!(stdout.contains("\"format\":\"7z\""), "{stdout}");
    assert!(stdout.contains("\"tested_entries\":"), "{stdout}");
}

#[test]
fn zm_volume_size_rejects_tar_zst_and_stdout_output() {
    let temp = TestDir::new("zm_volume_size_rejections");
    fs::write(temp.path("file.txt"), "payload").unwrap();

    let tar =
        Command::new(zm_path()).arg("create").arg(temp.path("archive.tar.zst")).arg(temp.path("file.txt")).arg("--volume-size").arg("64k").output().unwrap();
    assert_failure("zm create tar.zst --volume-size", &tar);
    assert!(String::from_utf8_lossy(&tar.stderr).contains("supported only for ZIP, TZAP, and 7z"), "{}", String::from_utf8_lossy(&tar.stderr));

    let stdout_archive =
        Command::new(zm_path()).arg("create").arg("-").arg(temp.path("file.txt")).arg("--format").arg("zip").arg("--volume-size").arg("64k").output().unwrap();
    assert_failure("zm create stdout --volume-size", &stdout_archive);
    assert!(String::from_utf8_lossy(&stdout_archive.stderr).contains("stdout archive output"), "{}", String::from_utf8_lossy(&stdout_archive.stderr));
}

#[test]
fn optional_zm_reads_infozip_and_7zip_split_zip_sets_when_available() {
    let temp = TestDir::new("zm_reads_external_split_zip");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/blob.bin"), deterministic_bytes(200_000)).unwrap();

    if let Some(zip) = find_on_path("zip") {
        let archive = temp.path("infozip.zip");
        let create =
            Command::new(zip).arg("-0").arg("-q").arg("-s").arg("64k").arg(&archive).arg("project/blob.bin").current_dir(temp.root()).output().unwrap();
        assert_success("zip create split zip", &create);

        let extract =
            Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-infozip")).arg("--overwrite").arg("always").output().unwrap();
        assert_success("zm extract Info-ZIP split zip", &extract);
        assert_eq!(fs::read(temp.path("out-infozip/project/blob.bin")).unwrap(), fs::read(temp.path("project/blob.bin")).unwrap());
    }

    if let Some(sevenzip) = find_7zip() {
        let create = Command::new(sevenzip)
            .arg("a")
            .arg("-tzip")
            .arg("-mx=0")
            .arg("-v64k")
            .arg("sevenzip.zip")
            .arg("project/blob.bin")
            .current_dir(temp.root())
            .output()
            .unwrap();
        assert_success("7zz create split zip stream", &create);

        let extract = Command::new(zm_path())
            .arg("extract")
            .arg(temp.path("sevenzip.zip.001"))
            .arg("-C")
            .arg(temp.path("out-sevenzip"))
            .arg("--overwrite")
            .arg("always")
            .output()
            .unwrap();
        assert_success("zm extract 7zz split zip stream", &extract);
        assert_eq!(fs::read(temp.path("out-sevenzip/project/blob.bin")).unwrap(), fs::read(temp.path("project/blob.bin")).unwrap());
    }
}

#[test]
fn optional_zm_reads_7zip_created_split_7z_when_available() {
    let Some(sevenzip) = find_7zip() else {
        return;
    };
    let temp = TestDir::new("zm_reads_external_split_7z");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/blob.bin"), deterministic_bytes(3_200_000)).unwrap();

    let create = Command::new(sevenzip).arg("a").arg("-t7z").arg("-v1m").arg("external.7z").arg("project/blob.bin").current_dir(temp.root()).output().unwrap();
    assert_success("7zz create split 7z", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(temp.path("external.7z.001"))
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--overwrite")
        .arg("always")
        .output()
        .unwrap();
    assert_success("zm extract 7zz split 7z", &extract);
    assert_eq!(fs::read(temp.path("out/project/blob.bin")).unwrap(), fs::read(temp.path("project/blob.bin")).unwrap());
}

#[test]
fn optional_zm_extracts_7zip_created_tar_family_archives_when_available() {
    let Some(sevenzip) = find_7zip() else {
        return;
    };
    let temp = TestDir::new("zm_extract_7zip_tar_family");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "created by 7zip tar\n").unwrap();

    let tar_archive = temp.path("project.tar");
    let create_tar = Command::new(&sevenzip).current_dir(temp.root()).arg("a").arg("-ttar").arg("-bd").arg(&tar_archive).arg("project").output().unwrap();
    assert_success("7zz a -ttar archive", &create_tar);

    assert_zm_extracts_7zip_tar_family_archive("7zz-created tar", &tar_archive, &temp);

    for (format, archive_name) in [("gzip", "project.tar.gz"), ("xz", "project.tar.xz")] {
        let compressed_archive = temp.path(archive_name);
        let create_compressed = Command::new(&sevenzip)
            .current_dir(temp.root())
            .arg("a")
            .arg(format!("-t{format}"))
            .arg("-bd")
            .arg(&compressed_archive)
            .arg(&tar_archive)
            .output()
            .unwrap();
        assert_success(&format!("7zz a -t{format} archive"), &create_compressed);

        assert_zm_extracts_7zip_tar_family_archive(&format!("7zz-created {archive_name}"), &compressed_archive, &temp);
    }
}

#[cfg(unix)]
#[test]
fn zm_create_zip_follows_symlink_by_default() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_zip_follow_symlink");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), "target\n").unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    let archive = temp.path("follow.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf follows symlink", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract followed symlink archive", &extract);

    let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
    assert!(metadata.is_file(), "followed symlink should extract as file");
    assert_eq!(fs::read_to_string(temp.path("out/project/link.txt")).unwrap(), "target\n");
}

#[cfg(unix)]
#[test]
fn zm_create_zip_preserves_symlink_with_y() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_zip_preserve_symlink");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), "target\n").unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    let archive = temp.path("preserve.zip");

    let create = Command::new(zm_path()).arg("-ycf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -ycf preserves symlink", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--long").output().unwrap();
    assert_success("zm list preserved symlink", &list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("symlink"), "{}", String::from_utf8_lossy(&list.stdout));

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract preserved symlink archive", &extract);

    let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
    assert!(metadata.file_type().is_symlink(), "expected extracted symlink");
    assert_eq!(fs::read_link(temp.path("out/project/link.txt")).unwrap(), PathBuf::from("target.txt"));
}

#[cfg(unix)]
#[test]
fn zm_extracts_zip_symlink_created_by_competitor() {
    use std::os::unix::fs::symlink;

    let Some(zip) = find_on_path("zip") else {
        return;
    };
    let temp = TestDir::new("zm_extract_competitor_zip_symlink");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), "target\n").unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    let archive = temp.path("competitor-preserve.zip");

    let zip_output = Command::new(zip).current_dir(temp.root()).arg("-qry").arg(&archive).arg("project").output().unwrap();
    assert_success("zip -qry", &zip_output);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract competitor symlink zip", &extract);
    assert!(fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap().file_type().is_symlink(), "expected competitor symlink to extract as symlink");
}

#[cfg(unix)]
#[test]
fn zm_create_tar_zst_preserves_symlink_with_y() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_tar_zst_preserve_symlink");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), "target\n").unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    let archive = temp.path("preserve.tar.zst");

    let create = Command::new(zm_path()).arg("-ycf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -ycf tar.zst preserves symlink", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract tar.zst preserved symlink archive", &extract);
    assert!(fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap().file_type().is_symlink(), "expected tar.zst symlink to extract as symlink");
}

#[test]
fn zm_extract_tar_zst_materializes_safe_hardlink_entries() {
    let temp = TestDir::new("zm_tar_zst_hardlink_extract");
    let archive = temp.path("hardlink.tar.zst");
    write_tar_zst_with_hardlink(&archive, "project/target.txt", "project/hard.txt", b"hardlink payload\n");

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract tar.zst hardlink", &extract);

    let target = temp.path("out/project/target.txt");
    let hardlink = temp.path("out/project/hard.txt");
    assert_eq!(fs::read(&hardlink).unwrap(), b"hardlink payload\n");
    assert_same_file_identity(&target, &hardlink);
}

#[test]
fn zm_extract_native_tar_materializes_safe_hardlink_entries() {
    let temp = TestDir::new("zm_tar_hardlink_extract");
    let archive = temp.path("hardlink.tar");
    write_tar_with_hardlink(&archive, "project/target.txt", "project/hard.txt", b"hardlink payload\n");

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract tar hardlink", &extract);

    let target = temp.path("out/project/target.txt");
    let hardlink = temp.path("out/project/hard.txt");
    assert_eq!(fs::read(&hardlink).unwrap(), b"hardlink payload\n");
    assert_same_file_identity(&target, &hardlink);
}

#[cfg(unix)]
#[test]
fn zm_create_7z_rejects_preserve_symlinks() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_7z_preserve_symlink");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), "target\n").unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    let archive = temp.path("preserve.7z");

    let output = Command::new(zm_path()).arg("-ycf").arg(&archive).arg(temp.path("project")).output().unwrap();

    assert!(
        !output.status.success(),
        "7z preserve symlink unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("7z symlink preservation is not supported"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn zm_create_no_metadata_archives_remain_readable_across_formats() {
    let temp = TestDir::new("zm_no_metadata");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "metadata\n").unwrap();

    let zip_archive = temp.path("project.zip");
    let zip_create = Command::new(zm_path()).arg("-Xcf").arg(&zip_archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -Xcf zip", &zip_create);
    if let Some(unzip) = find_on_path("unzip") {
        let unzip_test = Command::new(unzip).arg("-t").arg(&zip_archive).output().unwrap();
        assert_success("unzip -t zm -X zip", &unzip_test);
    }

    let tar_zst_archive = temp.path("project.tar.zst");
    let tar_zst_create = Command::new(zm_path()).arg("-Xcf").arg(&tar_zst_archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -Xcf tar.zst", &tar_zst_create);
    let tar_zst_extract = Command::new(zm_path()).arg("extract").arg(&tar_zst_archive).arg("-C").arg(temp.path("out-tar-zst")).output().unwrap();
    assert_success("zm extract -X tar.zst", &tar_zst_extract);
    assert_eq!(fs::read_to_string(temp.path("out-tar-zst/project/file.txt")).unwrap(), "metadata\n");

    let sevenz_archive = temp.path("project.7z");
    let sevenz_create = Command::new(zm_path()).arg("-Xcf").arg(&sevenz_archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -Xcf 7z", &sevenz_create);
    let sevenz_extract = Command::new(zm_path()).arg("extract").arg(&sevenz_archive).arg("-C").arg(temp.path("out-7z")).output().unwrap();
    assert_success("zm extract -X 7z", &sevenz_extract);
    assert_eq!(fs::read_to_string(temp.path("out-7z/project/file.txt")).unwrap(), "metadata\n");

    let tgz_archive = temp.path("project.tar.gz");
    let tgz_create = Command::new(zm_path()).arg("-Xcf").arg(&tgz_archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -Xcf tgz", &tgz_create);
    let tgz_extract = Command::new(zm_path()).arg("extract").arg(&tgz_archive).arg("-C").arg(temp.path("out-tgz")).output().unwrap();
    assert_success("zm extract -X tgz", &tgz_extract);
    assert_eq!(fs::read_to_string(temp.path("out-tgz/project/file.txt")).unwrap(), "metadata\n");
}

#[test]
fn zm_extracts_selected_zip_entries_created_by_competitor() {
    let Some(zip) = find_on_path("zip") else {
        return;
    };
    let temp = TestDir::new("zm_extract_competitor_zip_filters");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    fs::write(temp.path("project/nested/deep.txt"), "deep\n").unwrap();
    let archive = temp.path("competitor.zip");

    let zip_output = Command::new(zip).current_dir(temp.root()).arg("-qr").arg(&archive).arg("project").output().unwrap();
    assert_success("zip -qr competitor filter archive", &zip_output);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--include")
        .arg("project/keep.txt")
        .arg("--strip-components")
        .arg("1")
        .output()
        .unwrap();
    assert_success("zm extract zip --include --strip-components", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/keep.txt")).unwrap(), "keep\n");
    assert!(!temp.path("out/drop.txt").exists());
    assert!(!temp.path("out/nested/deep.txt").exists());
}

#[test]
fn zm_extract_zip_honors_overwrite_policies() {
    let temp = TestDir::new("zm_extract_zip_overwrite");
    fs::write(temp.path("file.txt"), "archive\n").unwrap();
    let archive = temp.path("file.zip");
    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert_success("zm -cf overwrite fixture", &create);

    fs::create_dir_all(temp.path("out-never")).unwrap();
    fs::write(temp.path("out-never/file.txt"), "old\n").unwrap();
    let never = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-never")).output().unwrap();
    assert_failure("zm extract default overwrite refusal", &never);
    assert_eq!(fs::read_to_string(temp.path("out-never/file.txt")).unwrap(), "old\n");

    fs::create_dir_all(temp.path("out-always")).unwrap();
    fs::write(temp.path("out-always/file.txt"), "old\n").unwrap();
    let always = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-always")).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract --overwrite always", &always);
    assert_eq!(fs::read_to_string(temp.path("out-always/file.txt")).unwrap(), "archive\n");

    fs::create_dir_all(temp.path("out-rename")).unwrap();
    fs::write(temp.path("out-rename/file.txt"), "old\n").unwrap();
    let rename = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-rename")).arg("--overwrite").arg("rename").output().unwrap();
    assert_success("zm extract --overwrite rename", &rename);
    assert_eq!(fs::read_to_string(temp.path("out-rename/file.txt")).unwrap(), "old\n");
    assert_eq!(fs::read_to_string(temp.path("out-rename/file 2.txt")).unwrap(), "archive\n");

    let ask = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out-ask")).arg("--overwrite").arg("ask").output().unwrap();
    assert_failure("zm extract --overwrite ask without terminal", &ask);
}

#[cfg(unix)]
#[test]
fn zm_extract_overwrite_always_replaces_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_extract_zip_overwrite_symlink");
    fs::write(temp.path("file.txt"), "archive\n").unwrap();
    let archive = temp.path("file.zip");
    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("file.txt")).output().unwrap();
    assert_success("zm -cf symlink overwrite fixture", &create);

    fs::create_dir_all(temp.path("out")).unwrap();
    fs::write(temp.path("outside.txt"), "outside\n").unwrap();
    symlink(temp.path("outside.txt"), temp.path("out/file.txt")).unwrap();

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).arg("--overwrite").arg("always").output().unwrap();
    assert_success("zm extract --overwrite always over symlink", &extract);

    assert!(fs::symlink_metadata(temp.path("out/file.txt")).unwrap().file_type().is_file(), "expected symlink path to become a regular file");
    assert_eq!(fs::read_to_string(temp.path("out/file.txt")).unwrap(), "archive\n");
    assert_eq!(fs::read_to_string(temp.path("outside.txt")).unwrap(), "outside\n");
}

#[test]
fn zm_extract_tar_zst_honors_filters_and_strip_components() {
    let temp = TestDir::new("zm_extract_tar_zst_filters");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    fs::write(temp.path("project/nested/deep.txt"), "deep\n").unwrap();
    let archive = temp.path("project.tar.zst");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf tar.zst filter fixture", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--include")
        .arg("project/nested/deep.txt")
        .arg("--strip-components")
        .arg("2")
        .output()
        .unwrap();
    assert_success("zm extract tar.zst --include --strip-components", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/deep.txt")).unwrap(), "deep\n");
    assert!(!temp.path("out/project/keep.txt").exists());
    assert!(!temp.path("out/drop.txt").exists());
}

#[test]
fn zm_extract_7z_honors_filters_and_strip_components() {
    let temp = TestDir::new("zm_extract_7z_filters");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    fs::write(temp.path("project/nested/deep.txt"), "deep\n").unwrap();
    let archive = temp.path("project.7z");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf 7z filter fixture", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--include")
        .arg("project/nested/deep.txt")
        .arg("--strip-components")
        .arg("2")
        .output()
        .unwrap();
    assert_success("zm extract 7z --include --strip-components", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/deep.txt")).unwrap(), "deep\n");
    assert!(!temp.path("out/project/keep.txt").exists());
    assert!(!temp.path("out/drop.txt").exists());
}

#[test]
fn zm_extract_native_tar_honors_filters_and_strip_components() {
    let temp = TestDir::new("zm_extract_native_tar_filters");
    let archive = temp.path("project.tar");
    write_tar_entries(&archive, &[("project/keep.txt", b"keep\n"), ("project/drop.txt", b"drop\n"), ("project/nested/deep.txt", b"deep\n")]);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--include")
        .arg("project/nested/deep.txt")
        .arg("--strip-components")
        .arg("2")
        .output()
        .unwrap();
    assert_success("zm extract native tar --include --strip-components", &extract);

    assert_eq!(fs::read_to_string(temp.path("out/deep.txt")).unwrap(), "deep\n");
    assert!(!temp.path("out/project/keep.txt").exists());
    assert!(!temp.path("out/drop.txt").exists());
}

#[test]
fn zm_test_zip_honors_filters_and_reports_skipped_entries() {
    let temp = TestDir::new("zm_test_zip_filters");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf zip test filter fixture", &create);

    let test = Command::new(zm_path()).arg("test").arg(&archive).arg("--include").arg("project/keep.txt").arg("--json").output().unwrap();
    assert_success("zm test zip --include --json", &test);
    let stdout = String::from_utf8_lossy(&test.stdout);
    assert!(stdout.contains("\"tested_entries\":1"), "{stdout}");
    assert!(stdout.contains("\"skipped_entries\":"), "{stdout}");
}

#[test]
fn zm_test_tar_zst_and_7z_honor_filters() {
    let temp = TestDir::new("zm_test_non_zip_filters");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();

    for archive in [temp.path("project.tar.zst"), temp.path("project.7z")] {
        let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
        assert_success("zm -cf non-zip test filter fixture", &create);

        let test = Command::new(zm_path()).arg("test").arg(&archive).arg("--include").arg("project/keep.txt").arg("--json").output().unwrap();
        assert_success("zm test non-zip --include --json", &test);
        let stdout = String::from_utf8_lossy(&test.stdout);
        assert!(stdout.contains("\"bytes\":5"), "{stdout}");
        assert!(stdout.contains("\"tested_entries\":1"), "{stdout}");
        assert!(stdout.contains("\"skipped_entries\":"), "{stdout}");
    }
}

#[test]
fn zm_extract_zip_to_stdout_matches_selected_file_bytes() {
    let temp = TestDir::new("zm_zip_to_stdout");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf zip stdout fixture", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("--to-stdout").arg("--include").arg("project/keep.txt").output().unwrap();
    assert_success("zm extract zip --to-stdout", &extract);
    assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
    assert!(extract.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&extract.stderr));

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_output = Command::new(unzip).arg("-p").arg(&archive).arg("project/keep.txt").output().unwrap();
    assert_success("unzip -p zip stdout fixture", &unzip_output);
    assert_eq!(extract.stdout, unzip_output.stdout);
}

#[test]
fn zm_extract_tar_zst_and_7z_to_stdout_match_selected_file_bytes() {
    let temp = TestDir::new("zm_non_zip_to_stdout");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();

    for archive in [temp.path("project.tar.zst"), temp.path("project.7z")] {
        let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
        assert_success("zm -cf non-zip stdout fixture", &create);

        let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("--to-stdout").arg("--include").arg("project/keep.txt").output().unwrap();
        assert_success("zm extract non-zip --to-stdout", &extract);
        assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
        assert!(extract.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&extract.stderr));
    }
}

#[test]
fn zm_extract_native_tar_to_stdout_requires_one_selected_regular_file() {
    let temp = TestDir::new("zm_native_tar_to_stdout");
    let archive = temp.path("project.tar");
    write_tar_entries(&archive, &[("project/keep.txt", b"keep\n"), ("project/drop.txt", b"drop\n")]);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("--to-stdout").arg("--include").arg("project/keep.txt").output().unwrap();
    assert_success("zm extract native tar --to-stdout", &extract);
    assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
    assert!(extract.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&extract.stderr));

    let multiple = Command::new(zm_path()).arg("extract").arg(&archive).arg("--to-stdout").arg("--include").arg("project/**").output().unwrap();
    assert_failure("zm extract native tar --to-stdout multiple", &multiple);
    assert!(multiple.stdout.is_empty(), "failed stdout extraction must not write partial bytes:\n{}", String::from_utf8_lossy(&multiple.stdout));
    assert!(
        String::from_utf8_lossy(&multiple.stderr).contains("exactly one selected regular file"),
        "expected single-file selection error:\n{}",
        String::from_utf8_lossy(&multiple.stderr)
    );
}

#[test]
fn zm_list_tree_prints_hierarchical_archive_paths() {
    let temp = TestDir::new("zm_list_tree");
    fs::create_dir_all(temp.path("project/src")).unwrap();
    fs::write(temp.path("project/README.md"), "readme\n").unwrap();
    fs::write(temp.path("project/src/main.rs"), "fn main() {}\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("-cf").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm -cf tree fixture", &create);

    let list = Command::new(zm_path()).arg("list").arg(&archive).arg("--tree").output().unwrap();
    assert_success("zm list --tree", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("project/"), "{stdout}");
    assert!(stdout.contains("  README.md"), "{stdout}");
    assert!(stdout.contains("  src/"), "{stdout}");
    assert!(stdout.contains("    main.rs"), "{stdout}");
}

#[test]
fn zm_global_modes_validate_values_and_do_not_break_json() {
    let valid = Command::new(zm_path()).arg("--color").arg("never").arg("--progress").arg("never").arg("doctor").arg("--json").output().unwrap();
    assert_success("zm global color/progress modes", &valid);
    assert!(String::from_utf8_lossy(&valid.stdout).contains("\"ready\":true"), "{}", String::from_utf8_lossy(&valid.stdout));

    let invalid = Command::new(zm_path()).arg("--color").arg("sometimes").arg("doctor").output().unwrap();
    assert_failure("zm --color invalid value", &invalid);
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid value for --color"), "{}", String::from_utf8_lossy(&invalid.stderr));
}

#[test]
fn zm_progress_always_writes_create_and_extract_progress_to_stderr() {
    let temp = TestDir::new("zm_progress_always");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/README.md"), "readme\n").unwrap();
    fs::write(temp.path("project/nested/data.bin"), vec![b'x'; 16 * 1024]).unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("--progress").arg("always").arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create --progress always", &create);
    let create_stdout = String::from_utf8_lossy(&create.stdout);
    let create_stderr = String::from_utf8_lossy(&create.stderr);
    assert!(create_stdout.contains("created zip:"), "{create_stdout}");
    assert!(!create_stdout.contains("progress:"), "progress must stay off stdout:\n{create_stdout}");
    assert!(create_stderr.contains("progress: zip create started"), "{create_stderr}");
    assert!(create_stderr.contains("progress: 100%"), "{create_stderr}");
    assert!(create_stderr.contains("progress: complete"), "{create_stderr}");

    let extract = Command::new(zm_path()).arg("--progress").arg("always").arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).output().unwrap();
    assert_success("zm extract --progress always", &extract);
    let extract_stdout = String::from_utf8_lossy(&extract.stdout);
    let extract_stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(extract_stdout.contains("zip extract ok:"), "{extract_stdout}");
    assert!(!extract_stdout.contains("progress:"), "progress must stay off stdout:\n{extract_stdout}");
    assert!(extract_stderr.contains("progress: zip extract started"), "{extract_stderr}");
    assert!(extract_stderr.contains("progress:"), "{extract_stderr}");
    assert!(extract_stderr.contains("bytes"), "{extract_stderr}");
    assert!(extract_stderr.contains("progress: complete"), "{extract_stderr}");
}

#[test]
fn zm_progress_never_suppresses_progress() {
    let temp = TestDir::new("zm_progress_never");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "payload\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("--progress").arg("never").arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create --progress never", &create);
    assert!(!String::from_utf8_lossy(&create.stderr).contains("progress:"), "{}", String::from_utf8_lossy(&create.stderr));
}

#[test]
fn zm_color_always_styles_human_summary_and_progress() {
    let temp = TestDir::new("zm_color_progress");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "payload\n").unwrap();

    let colored_archive = temp.path("colored.zip");
    let colored = Command::new(zm_path())
        .arg("--color")
        .arg("always")
        .arg("--progress")
        .arg("always")
        .arg("create")
        .arg(&colored_archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm create --color always --progress always", &colored);
    let colored_stdout = String::from_utf8_lossy(&colored.stdout);
    let colored_stderr = String::from_utf8_lossy(&colored.stderr);
    assert!(colored_stdout.contains("\x1b["), "{colored_stdout}");
    assert!(strip_ansi(&colored_stdout).contains("created zip:"), "{colored_stdout}");
    assert!(colored_stderr.contains(ANSI_PROGRESS_PREFIX), "{colored_stderr}");

    let plain_archive = temp.path("plain.zip");
    let plain = Command::new(zm_path())
        .arg("--color")
        .arg("never")
        .arg("--progress")
        .arg("always")
        .arg("create")
        .arg(&plain_archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm create --color never --progress always", &plain);
    let plain_stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(plain_stderr.contains("progress: zip create started"), "{plain_stderr}");
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("\x1b["));
    assert!(!plain_stderr.contains("\x1b["), "{plain_stderr}");
}

#[test]
fn zm_color_always_does_not_color_json_or_archive_stdout() {
    let temp = TestDir::new("zm_color_machine_output");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create color fixture", &create);

    let json = Command::new(zm_path()).arg("--color").arg("always").arg("list").arg(&archive).arg("--json").output().unwrap();
    assert_success("zm --color always list --json", &json);
    let json_stdout = String::from_utf8_lossy(&json.stdout);
    assert_json_object(&json_stdout);
    assert!(!json_stdout.contains("\x1b["), "{json_stdout}");

    let extract = Command::new(zm_path())
        .arg("--color")
        .arg("always")
        .arg("extract")
        .arg(&archive)
        .arg("--to-stdout")
        .arg("--include")
        .arg("project/keep.txt")
        .output()
        .unwrap();
    assert_success("zm --color always extract --to-stdout", &extract);
    assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
    assert!(extract.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&extract.stderr));
}

#[test]
fn zm_create_json_summary_is_machine_readable() {
    let temp = TestDir::new("zm_create_json_summary");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "payload\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).arg("--json").output().unwrap();
    assert_success("zm create --json", &create);
    assert!(create.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&create.stderr));
    let stdout = String::from_utf8_lossy(&create.stdout);
    assert_json_object(&stdout);
    assert!(stdout.contains("\"operation\":\"create\""), "{stdout}");
    assert!(stdout.contains("\"archive\":\""), "{stdout}");
    assert!(stdout.contains("\"format\":\"zip\""), "{stdout}");
    assert!(stdout.contains("\"backend\":\"zip\""), "{stdout}");
    assert!(stdout.contains("\"written_entries\":"), "{stdout}");
    assert!(stdout.contains("\"written_bytes\":"), "{stdout}");

    let refused = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).arg("--json").output().unwrap();
    assert_failure("zm create --json refuses existing destination", &refused);
    assert!(refused.stdout.is_empty(), "failed create must not emit partial success JSON:\n{}", String::from_utf8_lossy(&refused.stdout));
}

#[test]
fn zm_extract_json_summary_is_machine_readable() {
    let temp = TestDir::new("zm_extract_json_summary");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "payload\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path()).arg("create").arg(&archive).arg(temp.path("project")).output().unwrap();
    assert_success("zm create json extract fixture", &create);

    let extract = Command::new(zm_path()).arg("extract").arg(&archive).arg("-C").arg(temp.path("out")).arg("--json").output().unwrap();
    assert_success("zm extract --json", &extract);
    assert!(extract.stderr.is_empty(), "stderr should stay quiet unless verbose/error:\n{}", String::from_utf8_lossy(&extract.stderr));
    let stdout = String::from_utf8_lossy(&extract.stdout);
    assert_json_object(&stdout);
    assert!(stdout.contains("\"operation\":\"extract\""), "{stdout}");
    assert!(stdout.contains("\"archive\":\""), "{stdout}");
    assert!(stdout.contains("\"destination\":\""), "{stdout}");
    assert!(stdout.contains("\"format\":\"zip\""), "{stdout}");
    assert!(stdout.contains("\"backend\":\"zip\""), "{stdout}");
    assert!(stdout.contains("\"written_entries\":"), "{stdout}");
    assert!(stdout.contains("\"skipped_entries\":"), "{stdout}");
    assert!(stdout.contains("\"written_bytes\":"), "{stdout}");
    assert_eq!(fs::read_to_string(temp.path("out/project/file.txt")).unwrap(), "payload\n");
}

#[test]
fn zm_no_password_prompt_fails_instead_of_prompting() {
    let temp = TestDir::new("zm_no_password_prompt");
    fs::write(temp.path("secret.txt"), "secret\n").unwrap();
    let archive = temp.path("secret.zip");

    let mut child = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("secret.txt"))
        .arg("--encrypt")
        .arg("--password-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "correct horse").unwrap();
    }
    let create = child.wait_with_output().unwrap();
    assert_success("zm create encrypted zip", &create);

    let mut extract_child = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--password-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let stdin = extract_child.stdin.as_mut().unwrap();
        writeln!(stdin, "correct horse").unwrap();
    }
    let extract = extract_child.wait_with_output().unwrap();
    assert_success("zm extract encrypted zip with password stdin", &extract);
    assert_eq!(fs::read_to_string(temp.path("out/secret.txt")).unwrap(), "secret\n");

    let test = Command::new(zm_path()).arg("--no-password-prompt").arg("test").arg(&archive).output().unwrap();
    assert_failure("zm --no-password-prompt test encrypted zip", &test);
    assert!(String::from_utf8_lossy(&test.stderr).contains("prompts are disabled"), "{}", String::from_utf8_lossy(&test.stderr));
}

#[derive(Debug)]
struct Fixture {
    filename: String,
    format: String,
    extract: bool,
    password: Option<String>,
    sha256: String,
}

impl Fixture {
    fn path(&self) -> PathBuf {
        archives_dir().join(&self.filename)
    }
}

fn fixture_manifest() -> Vec<Fixture> {
    let manifest_path = archives_dir().join("manifest.tsv");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let fixtures = manifest
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert!(fields.len() >= 6, "invalid fixture manifest line: {line:?}");
            Fixture {
                filename: fields[0].to_owned(),
                format: fields[1].to_owned(),
                extract: fields[2] == "true",
                password: (!fields[3].is_empty()).then(|| fields[3].to_owned()),
                sha256: fields[4].to_owned(),
            }
        })
        .collect::<Vec<_>>();

    assert!(!fixtures.is_empty(), "fixture manifest is empty: {}", manifest_path.display());
    for fixture in &fixtures {
        assert!(fixture.path().exists(), "missing fixture archive: {}", fixture.path().display());
        assert_eq!(sha256_hex(&fixture.path()), fixture.sha256, "fixture checksum drifted: {}", fixture.filename);
        assert!(fixture.password.is_none(), "password-protected fixtures are not wired into generic CLI tests yet: {}", fixture.filename);
    }

    fixtures
}

fn fixture_supported_on_target(fixture: &Fixture) -> bool {
    fixture.format != "AAR" || cfg!(any(target_os = "macos", target_os = "ios"))
}

fn sha256_hex(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}

fn cli_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zmanager-cli"))
}

fn assert_json_object(stdout: &str) {
    assert!(stdout.starts_with('{') && stdout.trim_end().ends_with('}'), "stdout is not a single JSON object:\n{stdout}");
}

fn write_zip_entries(path: &Path, method: CompressionMethod, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(method);

    for (entry_path, contents) in entries {
        writer.start_file(*entry_path, options).unwrap();
        writer.write_all(contents).unwrap();
    }

    writer.finish().unwrap();
}

fn write_tar_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut builder = tar::Builder::new(file);
    append_tar_entries(&mut builder, entries);
}

fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    append_tar_entries(&mut builder, entries);
    builder.into_inner().unwrap()
}

fn append_tar_entries<W: std::io::Write>(builder: &mut tar::Builder<W>, entries: &[(&str, &[u8])]) {
    for (entry_path, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(contents.len().try_into().unwrap());
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, *entry_path, *contents).unwrap();
    }

    builder.finish().unwrap();
}

fn gzip_bytes(contents: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn zstd_bytes(contents: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut counter = 0u64;
    while bytes.len() < len {
        let digest = Sha256::digest(counter.to_le_bytes());
        bytes.extend_from_slice(&digest);
        counter += 1;
    }
    bytes.truncate(len);
    bytes
}

fn run_with_stdin(mut command: Command, input: &str) -> std::process::Output {
    let mut child = command.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn run_with_optional_password(mut command: Command, password: Option<&str>) -> std::process::Output {
    match password {
        Some(password) => {
            command.arg("--password-stdin");
            run_with_stdin(command, &format!("{password}\n"))
        }
        None => command.output().unwrap(),
    }
}

fn write_deb_ar_archive(path: &Path, control_member_name: &str, control_member: &[u8], data_member_name: &str, data_member: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(b"!<arch>\n").unwrap();
    write_ar_member(&mut file, "debian-binary", b"2.0\n");
    write_ar_member(&mut file, control_member_name, control_member);
    write_ar_member(&mut file, data_member_name, data_member);
}

fn write_ar_member(file: &mut File, name: &str, contents: &[u8]) {
    assert!(name.len() <= 15, "ar fixture member name is too long: {name}");
    let identifier = format!("{name}/");
    writeln!(file, "{identifier:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`", 0, 0, 0, "100644", contents.len()).unwrap();
    file.write_all(contents).unwrap();
    if !contents.len().is_multiple_of(2) {
        file.write_all(b"\n").unwrap();
    }
}

fn write_tar_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
    let file = File::create(path).unwrap();
    write_tar_hardlink_entries(file, target_path, link_path, contents);
}

fn write_tar_zst_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
    let file = File::create(path).unwrap();
    let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
    let encoder = write_tar_hardlink_entries(encoder, target_path, link_path, contents);
    encoder.finish().unwrap();
}

fn write_tar_hardlink_entries<W: std::io::Write>(writer: W, target_path: &str, link_path: &str, contents: &[u8]) -> W {
    let mut builder = tar::Builder::new(writer);

    let mut file_header = tar::Header::new_gnu();
    file_header.set_entry_type(tar::EntryType::Regular);
    file_header.set_size(contents.len().try_into().unwrap());
    file_header.set_mode(0o644);
    file_header.set_mtime(0);
    file_header.set_cksum();
    builder.append_data(&mut file_header, target_path, contents).unwrap();

    let mut link_header = tar::Header::new_gnu();
    link_header.set_entry_type(tar::EntryType::Link);
    link_header.set_size(0);
    link_header.set_mode(0o644);
    link_header.set_mtime(0);
    link_header.set_cksum();
    builder.append_link(&mut link_header, link_path, Path::new(target_path)).unwrap();

    builder.into_inner().unwrap()
}

fn assert_no_zmanager_temp_files(root: &Path) {
    if !root.exists() {
        return;
    }

    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = entry.file_name();
        assert!(!name.to_string_lossy().starts_with(".zmanager-"), "temporary output file was left behind: {}", path.display());
        if path.is_dir() {
            assert_no_zmanager_temp_files(&path);
        }
    }
}

fn archives_dir() -> PathBuf {
    repo_root().join("fixtures/archives")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn find_7zip() -> Option<PathBuf> {
    find_on_path("7zz").or_else(|| find_on_path("7z"))
}

fn assert_zm_extracts_7zip_tar_family_archive(label: &str, archive: &Path, temp: &TestDir) {
    let output_dir_name = format!("out-{}", archive.file_name().and_then(|name| name.to_str()).unwrap_or("archive").replace('.', "-"));
    let extract = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(temp.path(output_dir_name)).output().unwrap();
    assert_success(&format!("zm extract {label}"), &extract);
    assert_eq!(
        fs::read_to_string(
            temp.path(format!("out-{}/project/file.txt", archive.file_name().and_then(|name| name.to_str()).unwrap_or("archive").replace('.', "-")))
        )
        .unwrap(),
        "created by 7zip tar\n"
    );
}
