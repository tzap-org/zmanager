use std::env;
use std::path::{Path, PathBuf};

const BUNDLED_SOURCE_PATH: &str = "../../vendor/libarchive/libarchive-3.8.7";

fn main() {
    println!("cargo:rerun-if-env-changed=ZMANAGER_LIBARCHIVE_SYSTEM");
    println!("cargo:rerun-if-env-changed=LIBARCHIVE_DIR");
    println!("cargo:rerun-if-env-changed=VCPKG_INSTALLATION_ROOT");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");
    println!("cargo:rerun-if-env-changed=VCPKG_TARGET_TRIPLET");
    println!("cargo:rerun-if-changed={BUNDLED_SOURCE_PATH}");

    if env::var_os("ZMANAGER_LIBARCHIVE_SYSTEM").is_some() {
        link_system_libarchive();
    } else {
        build_bundled_libarchive();
    }
}

fn link_system_libarchive() {
    if let Some(root) = env::var_os("LIBARCHIVE_DIR") {
        let root = PathBuf::from(root);
        println!(
            "cargo:rustc-link-search=native={}",
            root.join("lib").display()
        );
        println!("cargo:rustc-link-lib=archive");
        return;
    }

    pkg_config::Config::new()
        .atleast_version("3.8.7")
        .probe("libarchive")
        .expect("system libarchive >= 3.8.7 was not found");
}

fn build_bundled_libarchive() {
    let target = env::var("TARGET").expect("TARGET is set by Cargo");
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"));
    let source = manifest_dir.join(BUNDLED_SOURCE_PATH);

    let mut config = cmake::Config::new(&source);
    configure_common_libarchive_options(&mut config);
    configure_target_options(&mut config, &target);
    configure_vcpkg(&mut config);

    config.build_target("archive_static");
    let _install_root = config.build();

    link_bundled_archive_library(&target);
    link_bundled_archive_dependencies(&target);
}

fn configure_common_libarchive_options(config: &mut cmake::Config) {
    config
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("ENABLE_INSTALL", "OFF")
        .define("ENABLE_TEST", "OFF")
        .define("ENABLE_TAR", "OFF")
        .define("ENABLE_CPIO", "OFF")
        .define("ENABLE_CAT", "OFF")
        .define("ENABLE_UNZIP", "OFF")
        .define("ENABLE_WERROR", "OFF")
        .define("ENABLE_LZO", "OFF")
        .define("ENABLE_PCREPOSIX", "OFF")
        .define("ENABLE_PCRE2POSIX", "OFF")
        .define("ENABLE_LIBB2", "OFF")
        .define("ENABLE_ZLIB", "ON")
        .define("ENABLE_BZip2", "ON")
        .define("ENABLE_LZMA", "ON")
        .define("ENABLE_ZSTD", "ON")
        .define("ENABLE_LZ4", "ON")
        .define("ENABLE_OPENSSL", "ON");
}

fn configure_target_options(config: &mut cmake::Config, target: &str) {
    if target.contains("windows") {
        config
            .define("ENABLE_ACL", "ON")
            .define("ENABLE_XATTR", "ON")
            .define("MSVC_USE_STATIC_CRT", "ON")
            .define(
                "CMAKE_MSVC_RUNTIME_LIBRARY",
                "MultiThreaded$<$<CONFIG:Debug>:Debug>",
            )
            .define("ENABLE_ICONV", "OFF")
            .define("ENABLE_LIBXML2", "OFF")
            .define("ENABLE_EXPAT", "OFF")
            .define("ENABLE_WIN32_XMLLITE", "ON")
            .define("ENABLE_CNG", "ON");
    } else {
        config
            .define("ENABLE_ACL", "ON")
            .define("ENABLE_XATTR", "ON")
            .define("ENABLE_ICONV", "ON")
            .define("ENABLE_LIBXML2", "ON")
            .define("ENABLE_EXPAT", "ON")
            .define("ENABLE_WIN32_XMLLITE", "OFF");
    }
}

fn configure_vcpkg(config: &mut cmake::Config) {
    let Some(vcpkg_root) = vcpkg_root() else {
        return;
    };
    let toolchain = vcpkg_root.join("scripts/buildsystems/vcpkg.cmake");
    if toolchain.exists() {
        config.define("CMAKE_TOOLCHAIN_FILE", toolchain);
    }
    if let Ok(triplet) = env::var("VCPKG_TARGET_TRIPLET") {
        config.define("VCPKG_TARGET_TRIPLET", triplet);
    }
}

fn vcpkg_root() -> Option<PathBuf> {
    env::var_os("VCPKG_INSTALLATION_ROOT")
        .or_else(|| env::var_os("VCPKG_ROOT"))
        .map(PathBuf::from)
}

fn link_bundled_archive_library(target: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let build_dir = out_dir.join("build");

    if target.contains("windows") && target.contains("msvc") {
        print_link_search(build_dir.join("libarchive/Debug"));
        print_link_search(build_dir.join("libarchive/Release"));
    }
    print_link_search(build_dir.join("libarchive"));
    println!("cargo:rustc-link-lib=static=archive");
}

fn link_bundled_archive_dependencies(target: &str) {
    if target.contains("apple-darwin") {
        print_link_search("/opt/homebrew/lib");
        print_link_search("/usr/local/lib");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        link_common_unix_libraries();
        println!("cargo:rustc-link-lib=iconv");
        println!("cargo:rustc-link-lib=xml2");
    } else if target.contains("linux") {
        link_common_unix_libraries();
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=xml2");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=acl");
    } else if target.contains("windows") && target.contains("msvc") {
        let vcpkg_lib_dir = link_vcpkg_libraries();
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["zlib", "z"]);
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["bz2"]);
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["lzma"]);
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["zstd"]);
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["lz4"]);
        link_windows_vcpkg_library(&vcpkg_lib_dir, &["libcrypto"]);
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=xmllite");
        println!("cargo:rustc-link-lib=ole32");
    } else if target.contains("windows") {
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=bz2");
        println!("cargo:rustc-link-lib=lzma");
        println!("cargo:rustc-link-lib=zstd");
        println!("cargo:rustc-link-lib=lz4");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=xmllite");
        println!("cargo:rustc-link-lib=ole32");
    }
}

fn link_common_unix_libraries() {
    println!("cargo:rustc-link-lib=z");
    println!("cargo:rustc-link-lib=bz2");
    println!("cargo:rustc-link-lib=lzma");
    println!("cargo:rustc-link-lib=zstd");
    println!("cargo:rustc-link-lib=lz4");
}

fn link_vcpkg_libraries() -> Option<PathBuf> {
    let Some(vcpkg_root) = vcpkg_root() else {
        return None;
    };
    let triplet = env::var("VCPKG_TARGET_TRIPLET")
        .or_else(|_| env::var("VCPKG_DEFAULT_TRIPLET"))
        .unwrap_or_else(|_| default_vcpkg_triplet());
    let lib_dir = vcpkg_root.join("installed").join(triplet).join("lib");
    print_link_search(&lib_dir);
    Some(lib_dir)
}

fn link_windows_vcpkg_library(vcpkg_lib_dir: &Option<PathBuf>, candidates: &[&str]) {
    let Some(lib_dir) = vcpkg_lib_dir else {
        println!("cargo:rustc-link-lib={}", candidates[0]);
        return;
    };

    for candidate in candidates {
        if lib_dir.join(format!("{candidate}.lib")).exists() {
            println!("cargo:rustc-link-lib={candidate}");
            return;
        }
    }

    println!("cargo:rustc-link-lib={}", candidates[0]);
}

fn default_vcpkg_triplet() -> String {
    let target = env::var("TARGET").unwrap_or_default();
    if target.starts_with("aarch64") {
        "arm64-windows".to_owned()
    } else {
        "x64-windows".to_owned()
    }
}

fn print_link_search(path: impl AsRef<Path>) {
    let path = path.as_ref();
    if path.exists() {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
}
