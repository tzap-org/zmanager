use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const UNRAR_SOURCES: &[&str] = &[
    "rar.cpp",
    "strlist.cpp",
    "strfn.cpp",
    "pathfn.cpp",
    "smallfn.cpp",
    "global.cpp",
    "file.cpp",
    "filefn.cpp",
    "filcreat.cpp",
    "archive.cpp",
    "arcread.cpp",
    "unicode.cpp",
    "system.cpp",
    "crypt.cpp",
    "crc.cpp",
    "rawread.cpp",
    "encname.cpp",
    "resource.cpp",
    "match.cpp",
    "timefn.cpp",
    "rdwrfn.cpp",
    "consio.cpp",
    "options.cpp",
    "errhnd.cpp",
    "rarvm.cpp",
    "secpassword.cpp",
    "rijndael.cpp",
    "getbits.cpp",
    "sha1.cpp",
    "sha256.cpp",
    "blake2s.cpp",
    "hash.cpp",
    "extinfo.cpp",
    "extract.cpp",
    "volume.cpp",
    "list.cpp",
    "find.cpp",
    "unpack.cpp",
    "headers.cpp",
    "threadpool.cpp",
    "rs16.cpp",
    "cmddata.cpp",
    "ui.cpp",
    "largepage.cpp",
    "filestr.cpp",
    "scantree.cpp",
    "dll.cpp",
    "qopen.cpp",
];

const WINDOWS_UNRAR_SOURCES: &[&str] = &["isnt.cpp", "motw.cpp"];

const WINDOWS_SYSTEM_LIBS: &[&str] = &["advapi32", "shell32", "shlwapi", "powrprof", "psapi"];

const SYSTEM_CPU_FEATURE_NEEDLE: &str =
    "#elif defined(__GNUC__)\n  if (__builtin_cpu_supports(\"avx2\"))";
const SYSTEM_CPU_FEATURE_REPLACEMENT: &str = concat!(
    "#elif defined(__APPLE__)\n",
    "  // Apple clang can emit a reference to GCC's ___cpu_model runtime\n",
    "  // symbol through __builtin_cpu_supports. Disable optional UnRAR SSE\n",
    "  // dispatch in this embedded build and keep the portable code path.\n",
    "  return SSE_NONE;\n",
    "#elif defined(__GNUC__)\n",
    "  if (__builtin_cpu_supports(\"avx2\"))",
);

const RIJNDAEL_CPU_FEATURE_NEEDLE: &str =
    "#elif defined(__GNUC__)\n  AES_NI=__builtin_cpu_supports(\"aes\");";
const RIJNDAEL_CPU_FEATURE_REPLACEMENT: &str = concat!(
    "#elif defined(__APPLE__)\n",
    "  // See crates/zmanager-unrar/README.md. Avoid depending on GCC's\n",
    "  // ___cpu_model runtime symbol when this source is compiled by Apple clang.\n",
    "  AES_NI=false;\n",
    "#elif defined(__GNUC__)\n",
    "  AES_NI=__builtin_cpu_supports(\"aes\");",
);

const MACOS_X86_64_UNRAR_PATCHES: &[SourcePatch] = &[
    SourcePatch {
        file_name: "system.cpp",
        needle: SYSTEM_CPU_FEATURE_NEEDLE,
        replacement: SYSTEM_CPU_FEATURE_REPLACEMENT,
    },
    SourcePatch {
        file_name: "rijndael.cpp",
        needle: RIJNDAEL_CPU_FEATURE_NEEDLE,
        replacement: RIJNDAEL_CPU_FEATURE_REPLACEMENT,
    },
];

struct SourcePatch {
    file_name: &'static str,
    needle: &'static str,
    replacement: &'static str,
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let unrar_dir = manifest_dir.join("../../vendor/unrar");
    let build_source_dir = out_dir.join("unrar-src");
    fs::create_dir_all(&build_source_dir).expect("create copied UnRAR source directory");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .warnings(false)
        .include(&unrar_dir)
        .include(manifest_dir.join("cpp"))
        .define("_FILE_OFFSET_BITS", "64")
        .define("_LARGEFILE_SOURCE", None)
        .define("RAR_SMP", None)
        .define("RARDLL", None)
        .flag_if_supported("-std=c++11")
        .flag_if_supported("-Wno-logical-op-parentheses")
        .flag_if_supported("-Wno-switch")
        .flag_if_supported("-Wno-dangling-else")
        .flag_if_supported("-Wno-nontrivial-memcall");

    let target_os = target_os();
    let apply_macos_x86_64_patch = target_os == "macos" && target_arch() == "x86_64";
    for source in UNRAR_SOURCES {
        let build_source = copy_build_source(
            &unrar_dir,
            &build_source_dir,
            source,
            apply_macos_x86_64_patch,
        );
        build.file(build_source);
        println!(
            "cargo:rerun-if-changed={}",
            unrar_dir.join(source).display()
        );
    }
    if target_os == "windows" {
        for source in WINDOWS_UNRAR_SOURCES {
            let build_source = copy_build_source(
                &unrar_dir,
                &build_source_dir,
                source,
                apply_macos_x86_64_patch,
            );
            build.file(build_source);
            println!(
                "cargo:rerun-if-changed={}",
                unrar_dir.join(source).display()
            );
        }
    }
    build.file(manifest_dir.join("cpp/zmanager_unrar_bridge.cpp"));
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("cpp/zmanager_unrar_bridge.cpp").display()
    );

    build.compile("zmanager_unrar");

    if std::env::var("CARGO_CFG_UNIX").is_ok() {
        println!("cargo:rustc-link-lib=pthread");
    }
    if target_os == "windows" {
        for library in WINDOWS_SYSTEM_LIBS {
            println!("cargo:rustc-link-lib={library}");
        }
    }
}

fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS is set by Cargo")
}

fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is set by Cargo")
}

fn copy_build_source(
    unrar_dir: &Path,
    build_source_dir: &Path,
    source: &str,
    apply_macos_x86_64_patch: bool,
) -> PathBuf {
    let original = unrar_dir.join(source);
    let copied = build_source_dir.join(source);

    if apply_macos_x86_64_patch {
        let mut contents = None;
        for patch in MACOS_X86_64_UNRAR_PATCHES
            .iter()
            .filter(|patch| patch.file_name == source)
        {
            let patched = contents
                .take()
                .unwrap_or_else(|| fs::read_to_string(&original).expect("read UnRAR source"));
            contents = Some(apply_source_patch(source, &patched, patch));
        }

        if let Some(contents) = contents {
            fs::write(&copied, contents).expect("write patched UnRAR build source");
            return copied;
        }
    }

    fs::copy(&original, &copied).expect("copy UnRAR build source");
    copied
}

fn apply_source_patch(source: &str, contents: &str, patch: &SourcePatch) -> String {
    assert!(
        contents.contains(patch.needle),
        "UnRAR source patch no longer applies to {source}; review crates/zmanager-unrar/README.md"
    );
    contents.replace(patch.needle, patch.replacement)
}
