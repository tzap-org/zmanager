use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let unrar_dir = manifest_dir.join("../../vendor/unrar");

    let sources = [
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

    for source in sources {
        build.file(unrar_dir.join(source));
        println!(
            "cargo:rerun-if-changed={}",
            unrar_dir.join(source).display()
        );
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
}
