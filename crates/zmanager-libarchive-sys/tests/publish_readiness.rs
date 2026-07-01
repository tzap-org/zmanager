use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const EXPECTED_LIBARCHIVE_VERSION_TEXT: &str = "3.8.8";
const EXPECTED_LIBARCHIVE_VERSION_NUMBER: i32 = 3_008_008;
const EXPECTED_SOURCE_DIR: &str = "libarchive-3.8.8";
const PUBLISH_SOURCE_PATH: &str = "vendor/libarchive/libarchive-3.8.8";
const WORKSPACE_SOURCE_PATH: &str = "../../vendor/libarchive/libarchive-3.8.8";
const PUBLISH_SOURCE_ROOT: &str = "vendor/libarchive";
const WORKSPACE_SOURCE_ROOT: &str = "../../vendor/libarchive";

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn assert_has_libarchive_files(source_root: &Path) {
    let source_dir = source_root.join(EXPECTED_SOURCE_DIR);
    assert!(
        source_dir.is_dir(),
        "expected versioned vendored source directory: {}",
        source_dir.display(),
    );
    assert!(
        source_dir.join("NEWS").is_file(),
        "expected NEWS in versioned libarchive source"
    );
    assert!(
        source_dir.join("CMakeLists.txt").is_file(),
        "expected CMakeLists.txt in versioned libarchive source"
    );
}

#[test]
fn vendored_libarchive_tree_is_present_for_package_and_workspace() {
    let manifest_dir = Path::new(manifest_dir());
    let publish_root = manifest_dir.join(PUBLISH_SOURCE_ROOT);
    let workspace_root = manifest_dir.join(WORKSPACE_SOURCE_ROOT);

    assert_has_libarchive_files(&publish_root);

    assert!(
        publish_root.join(EXPECTED_SOURCE_DIR).is_dir(),
        "publishable libarchive source should include {PUBLISH_SOURCE_PATH}, got: {}",
        publish_root.display(),
    );

    if workspace_root.is_dir() {
        assert_has_libarchive_files(&workspace_root);
    }
}

#[test]
fn crate_build_script_version_metadata_is_consistent() {
    let manifest_dir = Path::new(manifest_dir());
    let build_script = fs::read_to_string(manifest_dir.join("build.rs")).expect("read build.rs");
    let ffi_lib = fs::read_to_string(manifest_dir.join("src/lib.rs")).expect("read src/lib.rs");
    let readme = fs::read_to_string(manifest_dir.join("vendor/libarchive/README.zmanager.md"))
        .or_else(|_| {
            fs::read_to_string(manifest_dir.join("../../vendor/libarchive/README.zmanager.md"))
        })
        .expect("read vendored libarchive README");

    assert!(
        build_script.contains(PUBLISH_SOURCE_PATH),
        "build.rs should include the crates.io-ready vendored source path {PUBLISH_SOURCE_PATH}"
    );
    assert!(
        build_script.contains(WORKSPACE_SOURCE_PATH),
        "build.rs should include the workspace fallback path {WORKSPACE_SOURCE_PATH}"
    );
    assert!(
        build_script.find(PUBLISH_SOURCE_PATH).unwrap()
            < build_script.find(WORKSPACE_SOURCE_PATH).unwrap(),
        "build.rs should resolve crate-local vendored source before workspace fallback"
    );
    assert!(
        build_script.contains("3.8.8"),
        "build.rs must target libarchive 3.8.8"
    );
    assert!(
        ffi_lib.contains("3_008_008"),
        "src/lib.rs must expose ARCHIVE_VERSION_NUMBER for 3.8.8",
    );
    assert!(
        readme.contains("Release: v3.8.8"),
        "vendor README must declare v3.8.8",
    );
}

#[test]
fn package_list_contains_packaged_libarchive_source() {
    let manifest_dir = PathBuf::from(manifest_dir());
    let output = Command::new("cargo")
        .current_dir(&manifest_dir)
        .arg("package")
        .arg("--list")
        .arg("--allow-dirty")
        .arg("--no-verify")
        .output()
        .expect("run cargo package --list");

    assert!(
        output.status.success(),
        "cargo package --list should succeed for publish readiness check. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let listing = String::from_utf8(output.stdout).expect("cargo package output should be utf-8");
    let expected_markers = [
        format!("{PUBLISH_SOURCE_PATH}/NEWS"),
        format!("{PUBLISH_SOURCE_PATH}/CMakeLists.txt"),
        format!("{PUBLISH_SOURCE_PATH}/COPYING"),
        format!("{PUBLISH_SOURCE_PATH}/cat/CMakeLists.txt"),
    ];

    for marker in expected_markers {
        assert!(
            listing.contains(&marker),
            "published package should include vendored path {marker}"
        );
    }
}

#[test]
fn libarchive_version_number_matches_versioned_build_output() {
    let version_number = zmanager_libarchive_sys::ARCHIVE_VERSION_NUMBER;
    let major = version_number / 1_000_000;
    let minor = (version_number / 1_000) % 1_000;
    let patch = version_number % 1_000;

    assert_eq!(major, 3);
    assert_eq!(minor, 8);
    assert_eq!(patch, 8);
    assert_eq!(
        format!("{major}.{minor}.{patch}"),
        EXPECTED_LIBARCHIVE_VERSION_TEXT,
        "ARCHIVE_VERSION_NUMBER should decode to {}",
        EXPECTED_LIBARCHIVE_VERSION_TEXT
    );
    assert!(
        version_number >= EXPECTED_LIBARCHIVE_VERSION_NUMBER,
        "ARCHIVE_VERSION_NUMBER should be at least {EXPECTED_LIBARCHIVE_VERSION_NUMBER}"
    );
}
