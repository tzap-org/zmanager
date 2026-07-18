use std::env;
use std::path::{Path, PathBuf};

const BUNDLED_SOURCE_PATHS: [&str; 2] = [
    "vendor/libarchive/libarchive-3.8.8",
    "../../vendor/libarchive/libarchive-3.8.8",
];
const ENV_CMAKE_TOOLCHAIN_FILE: &str = "CMAKE_TOOLCHAIN_FILE";
const ENV_VCPKG_DEFAULT_TRIPLET: &str = "VCPKG_DEFAULT_TRIPLET";
const ENV_VCPKG_INSTALLATION_ROOT: &str = "VCPKG_INSTALLATION_ROOT";
const ENV_VCPKG_ROOT: &str = "VCPKG_ROOT";
const ENV_VCPKG_TARGET_TRIPLET: &str = "VCPKG_TARGET_TRIPLET";
const VCPKG_TRIPLET_ARM64_WINDOWS_STATIC_MD: &str = "arm64-windows-static-md";
const VCPKG_TRIPLET_X64_WINDOWS_STATIC_MD: &str = "x64-windows-static-md";
const CMAKE_LZMA_API_STATIC: &str = "LZMA_API_STATIC";
const CMAKE_USE_BZIP2_DLL: &str = "USE_BZIP2_DLL";
const CMAKE_USE_BZIP2_STATIC: &str = "USE_BZIP2_STATIC";
const CMAKE_WITHOUT_LZMA_API_STATIC: &str = "WITHOUT_LZMA_API_STATIC";
const CMAKE_WITHOUT_ZLIB_DLL: &str = "WITHOUT_ZLIB_DLL";
const CMAKE_ZLIB_DLL: &str = "ZLIB_DLL";
const MSVC_DISABLE_BZIP2_DLL_IMPORT: &str = "/UUSE_BZIP2_DLL";
const MSVC_DISABLE_LZ4_DLL_IMPORT: &str = "/DLZ4_DLL_IMPORT=0";
const MSVC_DISABLE_ZSTD_DLL_IMPORT: &str = "/DZSTD_DLL_IMPORT=0";
const MSVC_DISABLE_ZLIB_DLL_IMPORT: &str = "/UZLIB_DLL";
const MSVC_ENABLE_BZIP2_STATIC: &str = "/DUSE_BZIP2_STATIC";
const MSVC_ENABLE_LIBLZMA_STATIC: &str = "/DLZMA_API_STATIC";
const VCPKG_BZIP2_LIB_NAMES: &[&str] = &["bz2", "bz2d"];
const VCPKG_LIBCRYPTO_LIB_NAMES: &[&str] = &["libcrypto", "libcryptod"];
const VCPKG_LIBLZMA_LIB_NAMES: &[&str] = &["lzma", "lzmad"];
const VCPKG_LZ4_LIB_NAMES: &[&str] = &["lz4", "lz4d"];
const VCPKG_PROFILE_DEBUG: &str = "debug";
const VCPKG_ZLIB_LIB_NAMES: &[&str] = &[
    "zlib",
    "zlibd",
    "zlibstatic",
    "zlibstaticd",
    "zs",
    "zsd",
    "z",
];
const VCPKG_ZSTD_LIB_NAMES: &[&str] = &["zstd", "zstdd"];

struct VcpkgLinkSearch {
    triplet: String,
    lib_dirs: Vec<PathBuf>,
}

fn main() {
    println!("cargo:rerun-if-env-changed=ZMANAGER_LIBARCHIVE_SYSTEM");
    println!("cargo:rerun-if-env-changed=LIBARCHIVE_DIR");
    println!("cargo:rerun-if-env-changed={ENV_CMAKE_TOOLCHAIN_FILE}");
    println!("cargo:rerun-if-env-changed={ENV_VCPKG_INSTALLATION_ROOT}");
    println!("cargo:rerun-if-env-changed={ENV_VCPKG_ROOT}");
    println!("cargo:rerun-if-env-changed={ENV_VCPKG_DEFAULT_TRIPLET}");
    println!("cargo:rerun-if-env-changed={ENV_VCPKG_TARGET_TRIPLET}");

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
        .atleast_version("3.8.8")
        .probe("libarchive")
        .expect("system libarchive >= 3.8.8 was not found");
}

fn build_bundled_libarchive() {
    let target = env::var("TARGET").expect("TARGET is set by Cargo");
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"));
    let source = locate_bundled_libarchive_source(&manifest_dir);

    let mut config = cmake::Config::new(&source);
    configure_common_libarchive_options(&mut config);
    configure_target_options(&mut config, &target);
    configure_vcpkg(&mut config, &target);

    config.build_target("archive_static");
    let _install_root = config.build();

    link_bundled_archive_library(&target);
    link_bundled_archive_dependencies(&target);
}

fn locate_bundled_libarchive_source(manifest_dir: &Path) -> PathBuf {
    for path in BUNDLED_SOURCE_PATHS {
        let source = manifest_dir.join(path);
        println!("cargo:rerun-if-changed={path}");
        if source.is_dir() {
            return source;
        }
    }

    panic!(
        "Could not find bundled libarchive source. Checked: {} and {}.",
        BUNDLED_SOURCE_PATHS[0], BUNDLED_SOURCE_PATHS[1]
    )
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
        let static_crt = windows_msvc_uses_static_crt();
        let runtime_library = if static_crt {
            "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        } else {
            "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        };
        config
            .define("ENABLE_ACL", "ON")
            .define("ENABLE_XATTR", "ON")
            .define("MSVC_USE_STATIC_CRT", if static_crt { "ON" } else { "OFF" })
            .define("CMAKE_MSVC_RUNTIME_LIBRARY", runtime_library)
            .define("ENABLE_ICONV", "OFF")
            .define("ENABLE_LIBXML2", "OFF")
            .define("ENABLE_EXPAT", "OFF")
            .define("ENABLE_WIN32_XMLLITE", "ON")
            .define("ENABLE_CNG", "ON");
        configure_windows_static_vcpkg_dependencies(config);
    } else if target.contains("linux") && target.contains("musl") {
        config
            .define("ENABLE_ACL", "OFF")
            .define("ENABLE_XATTR", "OFF")
            .define("ENABLE_ICONV", "OFF")
            .define("ENABLE_LIBXML2", "OFF")
            .define("ENABLE_EXPAT", "OFF")
            .define("ENABLE_OPENSSL", "OFF")
            .define("ENABLE_MBEDTLS", "OFF")
            .define("ENABLE_NETTLE", "OFF")
            .define("ENABLE_ZLIB", "OFF")
            .define("ENABLE_BZip2", "OFF")
            .define("ENABLE_LZMA", "OFF")
            .define("ENABLE_ZSTD", "OFF")
            .define("ENABLE_LZ4", "OFF");
    } else if target.contains("apple-darwin") {
        config
            .define("ENABLE_ACL", "ON")
            .define("ENABLE_XATTR", "ON")
            .define("ENABLE_ICONV", "ON")
            .define("ENABLE_LIBXML2", "ON")
            .define("ENABLE_EXPAT", "ON")
            .define("ENABLE_WIN32_XMLLITE", "OFF");

        let lz4_include = find_include_dir("DEP_LZ4_INCLUDE", "DEP_LZ4_ROOT");
        let lz4_lib = find_static_library("DEP_LZ4_ROOT", "liblz4.a");

        let lzma_include = find_include_dir("DEP_LZMA_INCLUDE", "DEP_LZMA_ROOT");
        let lzma_lib = find_static_library("DEP_LZMA_ROOT", "liblzma.a");

        let zstd_include = find_include_dir("DEP_ZSTD_INCLUDE", "DEP_ZSTD_ROOT");
        let zstd_lib = find_static_library("DEP_ZSTD_ROOT", "libzstd.a");

        config
            .define("LZ4_INCLUDE_DIR", &lz4_include)
            .define("LZ4_LIBRARY", &lz4_lib)
            .define("LIBLZMA_INCLUDE_DIR", &lzma_include)
            .define("LIBLZMA_INCLUDE_DIRS", &lzma_include)
            .define("LIBLZMA_LIBRARY", &lzma_lib)
            .define("LIBLZMA_LIBRARIES", &lzma_lib)
            .define("ZSTD_INCLUDE_DIR", &zstd_include)
            .define("ZSTD_LIBRARY", &zstd_lib);
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

fn configure_windows_static_vcpkg_dependencies(config: &mut cmake::Config) {
    if !vcpkg_triplet_uses_static_libraries() {
        return;
    }

    config
        .define(CMAKE_ZLIB_DLL, "OFF")
        .define(CMAKE_WITHOUT_ZLIB_DLL, "ON")
        .define(CMAKE_USE_BZIP2_DLL, "OFF")
        .define(CMAKE_USE_BZIP2_STATIC, "ON")
        .define(CMAKE_WITHOUT_LZMA_API_STATIC, "OFF")
        .define(CMAKE_LZMA_API_STATIC, "ON")
        .cflag(MSVC_DISABLE_ZLIB_DLL_IMPORT)
        .cflag(MSVC_DISABLE_BZIP2_DLL_IMPORT)
        .cflag(MSVC_ENABLE_BZIP2_STATIC)
        .cflag(MSVC_ENABLE_LIBLZMA_STATIC)
        .cflag(MSVC_DISABLE_LZ4_DLL_IMPORT)
        .cflag(MSVC_DISABLE_ZSTD_DLL_IMPORT);
}

fn configure_vcpkg(config: &mut cmake::Config, target: &str) {
    if !target_uses_vcpkg(target) {
        return;
    }

    let Some(vcpkg_root) = vcpkg_root() else {
        panic!(
            "Windows MSVC builds require a configured vcpkg root. Set \
             {ENV_VCPKG_INSTALLATION_ROOT} or {ENV_VCPKG_ROOT}, or set \
             {ENV_CMAKE_TOOLCHAIN_FILE} to vcpkg.cmake. The CI entry point \
             scripts/ci-windows.ps1 configures this automatically."
        );
    };
    let toolchain = vcpkg_root.join("scripts/buildsystems/vcpkg.cmake");
    if toolchain.exists() {
        config.define("CMAKE_TOOLCHAIN_FILE", toolchain);
    }
    if let Ok(triplet) = env::var(ENV_VCPKG_TARGET_TRIPLET) {
        config.define("VCPKG_TARGET_TRIPLET", triplet);
    }
}

fn target_uses_vcpkg(target: &str) -> bool {
    target.contains("windows") && target.contains("msvc")
}

fn vcpkg_root() -> Option<PathBuf> {
    env::var_os(ENV_VCPKG_INSTALLATION_ROOT)
        .or_else(|| env::var_os(ENV_VCPKG_ROOT))
        .map(PathBuf::from)
        .or_else(vcpkg_root_from_toolchain_file)
}

fn vcpkg_root_from_toolchain_file() -> Option<PathBuf> {
    let toolchain = PathBuf::from(env::var_os(ENV_CMAKE_TOOLCHAIN_FILE)?);
    if toolchain.file_name()?.to_string_lossy() != "vcpkg.cmake" {
        return None;
    }

    let buildsystems_dir = toolchain.parent()?;
    let scripts_dir = buildsystems_dir.parent()?;
    if scripts_dir.file_name()?.to_string_lossy() != "scripts" {
        return None;
    }

    Some(scripts_dir.parent()?.to_path_buf())
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
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        // Link system compression libraries dynamically
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=bz2");
        println!("cargo:rustc-link-lib=iconv");
        println!("cargo:rustc-link-lib=xml2");

        // Link static dependencies from sys crates
        let lz4_out_dir = env::var("DEP_LZ4_ROOT").expect("DEP_LZ4_ROOT not found");
        println!("cargo:rustc-link-search=native={lz4_out_dir}");
        println!("cargo:rustc-link-search=native={lz4_out_dir}/lib");
        println!("cargo:rustc-link-lib=static=lz4");

        let lzma_out_dir = env::var("DEP_LZMA_ROOT").expect("DEP_LZMA_ROOT not found");
        println!("cargo:rustc-link-search=native={lzma_out_dir}");
        println!("cargo:rustc-link-search=native={lzma_out_dir}/lib");
        println!("cargo:rustc-link-lib=static=lzma");

        let zstd_out_dir = env::var("DEP_ZSTD_ROOT").expect("DEP_ZSTD_ROOT not found");
        println!("cargo:rustc-link-search=native={zstd_out_dir}");
        println!("cargo:rustc-link-search=native={zstd_out_dir}/lib");
        println!("cargo:rustc-link-lib=static=zstd");
    } else if target.contains("linux") && target.contains("musl") {
        println!("cargo:rustc-link-lib=pthread");
    } else if target.contains("linux") {
        link_common_unix_libraries();
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=xml2");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=acl");
    } else if target.contains("windows") && target.contains("msvc") {
        let vcpkg_lib_dir = link_vcpkg_libraries();
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_ZLIB_LIB_NAMES);
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_BZIP2_LIB_NAMES);
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_LIBLZMA_LIB_NAMES);
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_ZSTD_LIB_NAMES);
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_LZ4_LIB_NAMES);
        link_windows_vcpkg_library(vcpkg_lib_dir.as_ref(), VCPKG_LIBCRYPTO_LIB_NAMES);
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=gdi32");
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

fn link_vcpkg_libraries() -> Option<VcpkgLinkSearch> {
    let vcpkg_root = vcpkg_root()?;
    let triplet = configured_vcpkg_triplet();
    let installed_dir = vcpkg_root.join("installed").join(&triplet);
    let mut lib_dirs = Vec::new();

    if env::var("PROFILE").as_deref() == Ok(VCPKG_PROFILE_DEBUG) {
        let debug_lib_dir = installed_dir.join("debug").join("lib");
        lib_dirs.push(debug_lib_dir.clone());
        lib_dirs.push(debug_lib_dir.join("manual-link"));
    }
    let release_lib_dir = installed_dir.join("lib");
    lib_dirs.push(release_lib_dir.clone());
    lib_dirs.push(release_lib_dir.join("manual-link"));

    for lib_dir in &lib_dirs {
        print_link_search(lib_dir);
    }

    Some(VcpkgLinkSearch { triplet, lib_dirs })
}

fn link_windows_vcpkg_library(search: Option<&VcpkgLinkSearch>, candidates: &[&str]) {
    let Some(search) = search else {
        println!("cargo:rustc-link-lib={}", candidates[0]);
        return;
    };

    for lib_dir in &search.lib_dirs {
        for candidate in candidates {
            if lib_dir.join(format!("{candidate}.lib")).exists() {
                println!("cargo:rustc-link-lib={candidate}");
                return;
            }
        }
    }

    let searched = search
        .lib_dirs
        .iter()
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    panic!(
        "vcpkg library not found for triplet {}. Looked in {} for one of: {}",
        search.triplet,
        searched,
        candidates.join(", ")
    );
}

fn default_vcpkg_triplet() -> String {
    let target = env::var("TARGET").unwrap_or_default();
    if target.starts_with("aarch64") {
        VCPKG_TRIPLET_ARM64_WINDOWS_STATIC_MD.to_owned()
    } else {
        VCPKG_TRIPLET_X64_WINDOWS_STATIC_MD.to_owned()
    }
}

fn configured_vcpkg_triplet() -> String {
    env::var(ENV_VCPKG_TARGET_TRIPLET)
        .or_else(|_| env::var(ENV_VCPKG_DEFAULT_TRIPLET))
        .unwrap_or_else(|_| default_vcpkg_triplet())
}

fn windows_msvc_uses_static_crt() -> bool {
    let triplet = configured_vcpkg_triplet();
    triplet.ends_with("-static") && !triplet.ends_with("-static-md")
}

fn vcpkg_triplet_uses_static_libraries() -> bool {
    configured_vcpkg_triplet().contains("-static")
}

fn print_link_search(path: impl AsRef<Path>) {
    let path = path.as_ref();
    if path.exists() {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
}

fn find_static_library(root_var: &str, lib_name: &str) -> PathBuf {
    let root = env::var(root_var).unwrap_or_else(|_| panic!("{root_var} not found"));
    let root_path = Path::new(&root);
    let candidates = [
        root_path.join(lib_name),
        root_path.join("lib").join(lib_name),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }
    panic!(
        "Could not find static library {lib_name} under {root}: searched {candidates:?}"
    );
}

fn find_include_dir(var_name: &str, root_var_name: &str) -> PathBuf {
    if let Ok(inc) = env::var(var_name) {
        let p = PathBuf::from(inc);
        if p.exists() {
            return p;
        }
    }
    if let Ok(root) = env::var(root_var_name) {
        let p = Path::new(&root).join("include");
        if p.exists() {
            return p;
        }
    }
    panic!("Could not find include directory for {var_name}");
}
