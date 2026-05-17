use std::env;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PAYLOAD: &[u8] = b"zmanager compatibility payload\n";

#[test]
fn competitor_zip_family_formats_extract_with_zm() {
    let Some(zip) = find_on_path("zip") else {
        return;
    };
    let temp = TestDir::new("compat_zip_family");
    create_project_payload(&temp);

    for extension in ["zip", "zipx", "jar", "war", "ipa", "apk", "appx", "xpi"] {
        let archive = temp.path(format!("payload.{extension}"));
        let create = Command::new(&zip)
            .current_dir(&temp.root)
            .arg("-qr")
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        assert_success(&format!("zip creates .{extension}"), &create);

        assert_zm_extracts_payload(&format!("zip-created .{extension}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_zipx_advanced_methods_extract_with_zm() {
    let Some(sevenzz) = find_on_path("7zz") else {
        return;
    };
    let temp = TestDir::new("compat_zipx_methods");
    create_project_payload(&temp);

    for (label, method) in [
        ("store", "Copy"),
        ("deflate", "Deflate"),
        ("deflate64", "Deflate64"),
        ("bzip2", "BZip2"),
        ("lzma", "LZMA"),
        ("ppmd", "PPMd"),
        ("xz", "XZ"),
    ] {
        let archive = temp.path(format!("payload-{label}.zipx"));
        let create = Command::new(&sevenzz)
            .current_dir(&temp.root)
            .arg("a")
            .arg("-tzip")
            .arg(format!("-mm={method}"))
            .arg("-bd")
            .arg("-bso0")
            .arg("-bsp0")
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        assert_success(&format!("7zz creates ZIPX with {method}"), &create);

        assert_zm_tests_archive(&format!("7zz-created ZIPX {method}"), &archive);
        assert_zm_extracts_payload(&format!("7zz-created ZIPX {method}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_zip_sfx_style_exe_extracts_with_zm() {
    let Some(zip) = find_on_path("zip") else {
        return;
    };
    let temp = TestDir::new("compat_zip_exe");
    create_project_payload(&temp);
    let archive = temp.path("payload.exe");

    let create = Command::new(zip)
        .current_dir(&temp.root)
        .arg("-qr")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("zip creates .exe-shaped archive", &create);

    assert_zm_extracts_payload("zip-created .exe-shaped archive", &archive, PAYLOAD);
}

#[test]
fn competitor_rar_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar");
    create_project_payload(&temp);

    for (label, switch, filename) in [
        ("rar5", "-ma5", "payload-rar5.rar"),
        ("rar4", "-ma4", "payload-rar4.rar"),
    ] {
        let archive = temp.path(filename);
        let create = Command::new(&rar)
            .current_dir(&temp.root)
            .arg("a")
            .arg("-idq")
            .arg(switch)
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        if !create.status.success() && label == "rar4" {
            continue;
        }
        assert_success(&format!("rar creates {label}"), &create);

        assert_zm_extracts_payload(&format!("rar-created {label}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_rar_multipart_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_multipart");
    create_project_payload(&temp);
    write_deterministic_blob(&temp.path("project/big.bin"), 384 * 1024);

    for (label, switch, filename) in [
        ("rar5 multipart", "-ma5", "payload-rar5.rar"),
        ("rar4 multipart", "-ma4", "payload-rar4.rar"),
    ] {
        let archive = temp.path(filename);
        let create = Command::new(&rar)
            .current_dir(&temp.root)
            .arg("a")
            .arg("-idq")
            .arg(switch)
            .arg("-m0")
            .arg("-v100k")
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        if !create.status.success() && label.starts_with("rar4") {
            continue;
        }
        assert_success(&format!("rar creates {label}"), &create);

        let first_volume = archive.with_file_name(
            archive
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
                .replace(".rar", ".part1.rar"),
        );
        let second_volume = archive.with_file_name(
            archive
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
                .replace(".rar", ".part2.rar"),
        );
        assert!(
            first_volume.exists() && second_volume.exists(),
            "{label} did not produce split .partN.rar volumes"
        );

        assert_zm_extracts_payload(label, &first_volume, PAYLOAD);
    }
}

#[test]
fn competitor_rar_passworded_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_gap");
    create_project_payload(&temp);

    for (label, password_switch, filename) in [
        (
            "rar5 encrypted data",
            "-psecret",
            "payload-rar5-password.rar",
        ),
        (
            "rar5 encrypted headers",
            "-hpsecret",
            "payload-rar5-header-password.rar",
        ),
    ] {
        let archive = temp.path(filename);
        let create = Command::new(&rar)
            .current_dir(&temp.root)
            .arg("a")
            .arg("-idq")
            .arg("-ma5")
            .arg(password_switch)
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        assert_success(&format!("rar creates {label}"), &create);

        let list = run_zm_with_password(["list", archive.to_str().unwrap()], "secret");
        assert_success(&format!("zm list {label}"), &list);
        assert!(
            String::from_utf8_lossy(&list.stdout).contains("project/file.txt"),
            "zm list did not include payload for {label}; stdout:\n{}",
            String::from_utf8_lossy(&list.stdout)
        );
        assert_zm_extracts_payload_with_password(label, &archive, PAYLOAD, "secret");
    }
}

#[cfg(unix)]
#[test]
fn competitor_rar_passworded_links_extract_safely_with_zm() {
    use std::os::unix::fs::{MetadataExt as _, symlink};

    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_links");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), PAYLOAD).unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    fs::hard_link(
        temp.path("project/target.txt"),
        temp.path("project/hard.txt"),
    )
    .unwrap();

    let archive = temp.path("payload-rar5-links.rar");
    let create = Command::new(&rar)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-idq")
        .arg("-ma5")
        .arg("-hpsecret")
        .arg("-ol")
        .arg("-oh")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("rar creates passworded link fixture", &create);

    let output = run_zm_extract_with_password(&archive, "secret");
    assert_success("zm extracts passworded RAR links", &output);

    let out = extraction_output_dir(&archive);
    let target = out.join("project/target.txt");
    let symlink_path = out.join("project/link.txt");
    let hardlink = out.join("project/hard.txt");

    assert_eq!(fs::read(&target).unwrap(), PAYLOAD);
    assert!(
        fs::symlink_metadata(&symlink_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(&symlink_path).unwrap(),
        PathBuf::from("target.txt")
    );
    assert_eq!(fs::read(&symlink_path).unwrap(), PAYLOAD);
    assert_eq!(
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&hardlink).unwrap().ino()
    );
}

#[test]
fn competitor_rar_passworded_file_references_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_file_references");
    fs::create_dir_all(temp.path("project")).unwrap();
    let duplicate_payload = vec![0_u8; 1024 * 1024];
    fs::write(temp.path("project/a.bin"), &duplicate_payload).unwrap();
    fs::write(temp.path("project/b.bin"), &duplicate_payload).unwrap();

    let archive = temp.path("payload-rar5-file-reference.rar");
    let create = Command::new(&rar)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-idq")
        .arg("-ma5")
        .arg("-hpsecret")
        .arg("-oi")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("rar creates passworded file-reference fixture", &create);

    let technical_list = run_rar_with_password(&rar, ["vt", archive.to_str().unwrap()], "secret");
    assert_success(
        "rar lists passworded file-reference fixture",
        &technical_list,
    );
    assert!(
        String::from_utf8_lossy(&technical_list.stdout).contains("Type: File reference"),
        "rar did not create a file-reference entry\nstdout:\n{}",
        String::from_utf8_lossy(&technical_list.stdout)
    );

    let list = run_zm_with_password(["list", archive.to_str().unwrap()], "secret");
    assert_success("zm lists passworded file-reference RAR", &list);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("filecopy"),
        "zm list did not expose the RAR file reference as filecopy\nstdout:\n{}",
        String::from_utf8_lossy(&list.stdout)
    );

    let output = run_zm_extract_with_password(&archive, "secret");
    assert_success("zm extracts passworded RAR file reference", &output);
    let out = extraction_output_dir(&archive);
    assert_eq!(
        fs::read(out.join("project/a.bin")).unwrap(),
        duplicate_payload
    );
    assert_eq!(
        fs::read(out.join("project/b.bin")).unwrap(),
        duplicate_payload
    );
}

#[cfg(unix)]
#[test]
fn competitor_rar_passworded_unsafe_link_is_rejected_by_zm() {
    use std::os::unix::fs::symlink;

    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_unsafe_link");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), PAYLOAD).unwrap();
    let outside = temp.path("outside.txt");
    fs::write(&outside, b"outside sentinel").unwrap();
    symlink("../../outside.txt", temp.path("project/escape.txt")).unwrap();

    let archive = temp.path("payload-rar5-unsafe-link.rar");
    let create = Command::new(&rar)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-idq")
        .arg("-ma5")
        .arg("-hpsecret")
        .arg("-ol")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("rar creates unsafe passworded link fixture", &create);

    let output = run_zm_extract_with_password(&archive, "secret");
    assert!(
        !output.status.success(),
        "zm unexpectedly extracted unsafe RAR link\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("link target escapes extraction root"),
        "unsafe link failure did not explain the rejected target\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel");
    assert!(
        fs::symlink_metadata(extraction_output_dir(&archive).join("project/escape.txt")).is_err(),
        "unsafe symlink should not be materialized under the extraction root"
    );
}

#[test]
fn competitor_rar_passworded_unicode_paths_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_unicode");
    let unicode_dir = temp.path("project/数据");
    let unicode_file_name = "emoji-😀.txt";
    fs::create_dir_all(&unicode_dir).unwrap();
    fs::write(unicode_dir.join(unicode_file_name), PAYLOAD).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        symlink(unicode_file_name, unicode_dir.join("链接.txt")).unwrap();
    }

    let archive = temp.path("payload-rar5-unicode.rar");
    let create = Command::new(&rar)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-idq")
        .arg("-ma5")
        .arg("-hpsecret")
        .arg("-ol")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("rar creates unicode passworded fixture", &create);

    let list = run_zm_with_password(["list", archive.to_str().unwrap()], "secret");
    assert_success("zm lists unicode passworded RAR", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("project/数据/emoji-😀.txt"),
        "unicode RAR listing missed the unicode path\nstdout:\n{list_stdout}"
    );

    let output = run_zm_extract_with_password(&archive, "secret");
    assert_success("zm extracts unicode passworded RAR", &output);
    let out = extraction_output_dir(&archive);
    assert_eq!(
        fs::read(out.join("project/数据").join(unicode_file_name)).unwrap(),
        PAYLOAD
    );
    #[cfg(unix)]
    {
        let unicode_link = out.join("project/数据/链接.txt");
        assert!(
            fs::symlink_metadata(&unicode_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&unicode_link).unwrap(),
            PathBuf::from(unicode_file_name)
        );
        assert_eq!(fs::read(&unicode_link).unwrap(), PAYLOAD);
    }
}

#[test]
fn competitor_rar_passworded_large_dictionary_is_rejected_by_zm() {
    let Some(rar) = find_on_path("rar") else {
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_large_dictionary");
    let large_file = temp.path("large.bin");
    File::create(&large_file)
        .unwrap()
        .set_len(600 * 1024 * 1024)
        .unwrap();

    let archive = temp.path("payload-rar5-large-dict.rar");
    let create = Command::new(&rar)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-idq")
        .arg("-ma5")
        .arg("-m5")
        .arg("-s")
        .arg("-hpsecret")
        .arg("-md1g")
        .arg(&archive)
        .arg("large.bin")
        .output()
        .unwrap();
    assert_success("rar creates passworded large-dictionary fixture", &create);

    let technical_list = run_rar_with_password(&rar, ["vt", archive.to_str().unwrap()], "secret");
    assert_success(
        "rar lists passworded large-dictionary fixture",
        &technical_list,
    );
    assert!(
        String::from_utf8_lossy(&technical_list.stdout).contains("-md=1g"),
        "rar did not create a 1 GiB dictionary fixture\nstdout:\n{}",
        String::from_utf8_lossy(&technical_list.stdout)
    );

    let output = run_zm_extract_with_password(&archive, "secret");
    assert!(
        !output.status.success(),
        "zm unexpectedly extracted a RAR dictionary over the limit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("dictionary exceeds 512 MiB limit"),
        "large-dictionary failure did not explain the limit\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !extraction_output_dir(&archive).join("large.bin").exists(),
        "large dictionary rejection should happen before writing output"
    );
}

#[test]
fn competitor_tar_cpio_pax_formats_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    let temp = TestDir::new("compat_tar_cpio_pax_shar");
    create_project_payload(&temp);

    for (label, format, filename) in [
        ("tar", None, "payload.tar"),
        ("ustar", Some("ustar"), "payload.ustar"),
        ("pax", Some("pax"), "payload.pax"),
        ("cpio", Some("cpio"), "payload.cpio"),
    ] {
        let archive = temp.path(filename);
        let mut command = Command::new(&bsdtar);
        command.arg("-cf").arg(&archive);
        if let Some(format) = format {
            command.arg("--format").arg(format);
        }
        let create = command
            .arg("-C")
            .arg(&temp.root)
            .arg("project")
            .output()
            .unwrap();
        assert_success(&format!("bsdtar creates {label}"), &create);

        assert_zm_extracts_payload(&format!("bsdtar-created {label}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_keka_style_cpgz_and_spk_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    let temp = TestDir::new("compat_cpgz_spk");
    create_project_payload(&temp);

    let cpio_archive = temp.path("payload.cpio");
    let create_cpio = Command::new(&bsdtar)
        .arg("--format")
        .arg("cpio")
        .arg("-cf")
        .arg(&cpio_archive)
        .arg("-C")
        .arg(&temp.root)
        .arg("project")
        .output()
        .unwrap();
    assert_success("bsdtar creates cpio for cpgz", &create_cpio);
    create_stdout_archive(
        "gzip creates cpgz",
        Command::new(require_tool("gzip"))
            .arg("-c")
            .arg(&cpio_archive),
        &temp.path("payload.cpgz"),
    );
    assert_zm_extracts_payload(
        "gzip-compressed cpio .cpgz",
        &temp.path("payload.cpgz"),
        PAYLOAD,
    );

    let spk_archive = temp.path("payload.spk");
    let create_spk = Command::new(&bsdtar)
        .arg("-cf")
        .arg(&spk_archive)
        .arg("-C")
        .arg(&temp.root)
        .arg("project")
        .output()
        .unwrap();
    assert_success("bsdtar creates spk-shaped tar", &create_spk);
    assert_zm_extracts_payload("tar-shaped .spk", &spk_archive, PAYLOAD);
}

#[test]
#[allow(clippy::too_many_lines)]
fn competitor_compressed_tar_filters_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    let temp = TestDir::new("compat_compressed_tar");
    create_project_payload(&temp);
    let mut archives = Vec::new();

    let tar_archive = temp.path("payload.tar");
    let create_tar = Command::new(&bsdtar)
        .arg("-cf")
        .arg(&tar_archive)
        .arg("-C")
        .arg(&temp.root)
        .arg("project")
        .output()
        .unwrap();
    assert_success("bsdtar creates source tar", &create_tar);

    if create_stdout_archive_with_optional_tool(
        "gzip",
        "gzip compresses tar",
        |command| {
            command.arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.gz"),
    ) {
        archives.push(("payload.tar.gz".to_owned(), temp.path("payload.tar.gz")));
    }
    if create_stdout_archive_with_optional_tool(
        "bzip2",
        "bzip2 compresses tar",
        |command| {
            command.arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.bz2"),
    ) {
        archives.push(("payload.tar.bz2".to_owned(), temp.path("payload.tar.bz2")));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz compresses tar",
        |command| {
            command.arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.xz"),
    ) {
        archives.push(("payload.tar.xz".to_owned(), temp.path("payload.tar.xz")));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz lzma compresses tar",
        |command| {
            command.arg("--format=lzma").arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.lzma"),
    ) {
        archives.push(("payload.tar.lzma".to_owned(), temp.path("payload.tar.lzma")));
    }
    if create_stdout_archive_with_optional_tool(
        "zstd",
        "zstd compresses tar",
        |command| {
            command.arg("-q").arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.zst"),
    ) {
        archives.push(("payload.tar.zst".to_owned(), temp.path("payload.tar.zst")));
    }
    if create_stdout_archive_with_optional_tool(
        "lzip",
        "lzip compresses tar",
        |command| {
            command.arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.lz"),
    ) {
        archives.push(("payload.tar.lz".to_owned(), temp.path("payload.tar.lz")));
    }
    if create_stdout_archive_with_optional_tool(
        "lzop",
        "lzop compresses tar",
        |command| {
            command.arg("-c").arg(&tar_archive);
        },
        &temp.path("payload.tar.lzo"),
    ) {
        archives.push(("payload.tar.lzo".to_owned(), temp.path("payload.tar.lzo")));
    }
    let compress_input = temp.path("payload-compress.tar");
    fs::copy(&tar_archive, &compress_input).unwrap();
    if run_optional_tool("compress", "compress creates tar.Z", |command| {
        command.arg("-f").arg(&compress_input);
    }) {
        archives.push((
            "payload-compress.tar.Z".to_owned(),
            temp.path("payload-compress.tar.Z"),
        ));
    }

    let lz4_archive = temp.path("payload.tar.lz4");
    if run_optional_tool("lz4", "lz4 compresses tar", |command| {
        command
            .arg("-q")
            .arg("-f")
            .arg(&tar_archive)
            .arg(&lz4_archive);
    }) {
        archives.push(("payload.tar.lz4".to_owned(), lz4_archive));
    }

    let lrzip_archive = temp.path("payload.tar.lrz");
    if run_optional_tool("lrzip", "lrzip compresses tar", |command| {
        command
            .arg("-q")
            .arg("-o")
            .arg(&lrzip_archive)
            .arg(&tar_archive);
    }) {
        archives.push(("payload.tar.lrz".to_owned(), lrzip_archive));
    }

    assert!(
        !archives.is_empty(),
        "no compressed tar creator tools were available"
    );
    for (label, archive) in archives {
        assert_zm_extracts_payload(&label, &archive, PAYLOAD);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn competitor_raw_single_file_streams_extract_with_zm() {
    let temp = TestDir::new("compat_raw_streams");
    fs::write(temp.path("payload.txt"), PAYLOAD).unwrap();
    let mut archives = Vec::new();

    let zstd_archive = temp.path("payload.txt.zst");
    if create_stdout_archive_with_optional_tool(
        "zstd",
        "zstd compresses raw file",
        |command| {
            command.arg("-q").arg("-c").arg(temp.path("payload.txt"));
        },
        &zstd_archive,
    ) {
        archives.push((
            "payload.txt.zst".to_owned(),
            zstd_archive.clone(),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "gzip",
        "gzip compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.gz"),
    ) {
        archives.push((
            "payload.txt.gz".to_owned(),
            temp.path("payload.txt.gz"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "bzip2",
        "bzip2 compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.bz2"),
    ) {
        archives.push((
            "payload.txt.bz2".to_owned(),
            temp.path("payload.txt.bz2"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.xz"),
    ) {
        archives.push((
            "payload.txt.xz".to_owned(),
            temp.path("payload.txt.xz"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz lzma compresses raw file",
        |command| {
            command
                .arg("--format=lzma")
                .arg("-c")
                .arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lzma"),
    ) {
        archives.push((
            "payload.txt.lzma".to_owned(),
            temp.path("payload.txt.lzma"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "lzip",
        "lzip compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lz"),
    ) {
        archives.push((
            "payload.txt.lz".to_owned(),
            temp.path("payload.txt.lz"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "brotli",
        "brotli compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.br"),
    ) {
        archives.push((
            "payload.txt.br".to_owned(),
            temp.path("payload.txt.br"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "lz4",
        "lz4 compresses raw file",
        |command| {
            command.arg("-q").arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lz4"),
    ) {
        archives.push((
            "payload.txt.lz4".to_owned(),
            temp.path("payload.txt.lz4"),
            "payload.txt",
        ));
    }
    if create_stdout_archive_with_optional_tool(
        "lzop",
        "lzop compresses raw file",
        |command| {
            command.arg("-q").arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lzo"),
    ) {
        archives.push((
            "payload.txt.lzo".to_owned(),
            temp.path("payload.txt.lzo"),
            "payload.txt",
        ));
    }
    let compress_dir = temp.path("compress-raw");
    fs::create_dir_all(&compress_dir).unwrap();
    fs::write(compress_dir.join("payload.txt"), PAYLOAD).unwrap();
    let compress_archive = compress_dir.join("payload.txt.Z");
    if run_optional_tool("compress", "compress creates raw .Z", |command| {
        command.arg("-f").arg(compress_dir.join("payload.txt"));
    }) {
        archives.push((
            "payload.txt.Z".to_owned(),
            compress_archive.clone(),
            "payload.txt",
        ));
    }
    let lrzip_archive = temp.path("payload.txt.lrz");
    if run_optional_tool("lrzip", "lrzip compresses raw file", |command| {
        command
            .arg("-q")
            .arg("-o")
            .arg(&lrzip_archive)
            .arg(temp.path("payload.txt"));
    }) {
        archives.push((
            "payload.txt.lrz".to_owned(),
            lrzip_archive.clone(),
            "payload.txt",
        ));
    }

    assert!(
        !archives.is_empty(),
        "no raw stream creator tools were available"
    );
    for (label, archive, output_name) in archives {
        assert_zm_extracts_raw_file(&label, &archive, output_name, PAYLOAD);
    }

    if zstd_archive.exists() {
        let stdout = Command::new(zm_path())
            .arg("extract")
            .arg(&zstd_archive)
            .arg("--to-stdout")
            .output()
            .unwrap();
        assert_success("zm extract raw zst to stdout", &stdout);
        assert_eq!(stdout.stdout, PAYLOAD);

        let list = Command::new(zm_path())
            .arg("list")
            .arg(&zstd_archive)
            .output()
            .unwrap();
        assert_success("zm list raw zst", &list);
        assert!(
            String::from_utf8_lossy(&list.stdout).contains("payload.txt"),
            "raw stream listing did not include payload.txt\nstdout:\n{}",
            String::from_utf8_lossy(&list.stdout)
        );

        let test = Command::new(zm_path())
            .arg("test")
            .arg(&zstd_archive)
            .output()
            .unwrap();
        assert_success("zm test raw zst", &test);
    }
    if lrzip_archive.exists() {
        let lrzip_stdout = Command::new(zm_path())
            .arg("extract")
            .arg(&lrzip_archive)
            .arg("--to-stdout")
            .output()
            .unwrap();
        assert_success("zm extract raw lrz to stdout", &lrzip_stdout);
        assert_eq!(lrzip_stdout.stdout, PAYLOAD);
    }
}

#[test]
fn raw_stream_extract_without_directory_writes_next_to_archive() {
    let temp = TestDir::new("raw_stream_default_destination");
    let source = temp.path("standalone.txt");
    let archive = temp.path("standalone.txt.zst");
    fs::write(&source, PAYLOAD).unwrap();
    write_zstd_file(&archive, PAYLOAD);
    fs::remove_file(&source).unwrap();

    let output = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .output()
        .unwrap();
    assert_success("zm extract raw zst without -C", &output);
    assert_eq!(fs::read(source).unwrap(), PAYLOAD);
}

#[test]
fn competitor_iso_xar_cab_formats_extract_with_zm() {
    let temp = TestDir::new("compat_images_packages");
    create_project_payload(&temp);

    if let Some(mkisofs) = find_on_path("mkisofs") {
        let archive = temp.path("payload.iso");
        let create = Command::new(mkisofs)
            .arg("-quiet")
            .arg("-o")
            .arg(&archive)
            .arg(temp.path("project"))
            .output()
            .unwrap();
        assert_success("mkisofs creates iso", &create);
        assert_zm_extracts_payload("mkisofs-created iso", &archive, PAYLOAD);
    }

    if let Some(xar) = find_on_path("xar") {
        let archive = temp.path("payload.xar");
        let create = Command::new(xar)
            .current_dir(&temp.root)
            .arg("-cf")
            .arg(&archive)
            .arg("project")
            .output()
            .unwrap();
        assert_success("xar creates xar", &create);
        assert_zm_extracts_payload("xar-created xar", &archive, PAYLOAD);
    }

    if let Some(gcab) = find_on_path("gcab") {
        let archive = temp.path("payload.cab");
        let create = Command::new(gcab)
            .current_dir(&temp.root)
            .arg("-c")
            .arg(&archive)
            .arg("project/file.txt")
            .output()
            .unwrap();
        assert_success("gcab creates cab", &create);
        assert_zm_extracts_payload("gcab-created cab", &archive, PAYLOAD);
    }
}

#[test]
fn competitor_unix_package_wrappers_extract_with_zm() {
    let temp = TestDir::new("compat_unix_packages");
    create_project_payload(&temp);

    if let Some(ar) = find_on_path("ar") {
        let archive = temp.path("payload.ar");
        let create = Command::new(ar)
            .current_dir(temp.path("project"))
            .arg("-qcS")
            .arg(&archive)
            .arg("file.txt")
            .output()
            .unwrap();
        assert_success("ar creates ar archive", &create);
        assert_zm_extracts_payload("ar-created archive", &archive, PAYLOAD);
    }

    if let Some(dpkg_deb) = find_on_path("dpkg-deb") {
        let package_root = temp.path("deb-root");
        fs::create_dir_all(package_root.join("DEBIAN")).unwrap();
        fs::create_dir_all(package_root.join("usr/share/zmanager-compat")).unwrap();
        fs::write(
            package_root.join("DEBIAN/control"),
            "Package: zmanager-compat\nVersion: 1.0\nArchitecture: all\nMaintainer: ZManager <test@example.invalid>\nDescription: ZManager compatibility fixture\n",
        )
        .unwrap();
        fs::write(
            package_root.join("usr/share/zmanager-compat/file.txt"),
            PAYLOAD,
        )
        .unwrap();
        let archive = temp.path("payload.deb");
        let create = Command::new(dpkg_deb)
            .arg("--build")
            .arg("--root-owner-group")
            .arg(&package_root)
            .arg(&archive)
            .output()
            .unwrap();
        assert_success("dpkg-deb creates deb", &create);
        assert_zm_extracts_any_file("dpkg-deb-created deb", &archive);
        assert_zm_extracts_deb_payload("dpkg-deb-created deb nested payload", &archive);
    }

    if let Some(rpmbuild) = find_on_path("rpmbuild") {
        let topdir = temp.path("rpmbuild");
        for dir in ["BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"] {
            fs::create_dir_all(topdir.join(dir)).unwrap();
        }
        let spec = topdir.join("SPECS/zmanager-compat.spec");
        fs::write(
            &spec,
            "Name: zmanager-compat\nVersion: 1.0\nRelease: 1\nSummary: ZManager compatibility fixture\nLicense: MIT\nBuildArch: noarch\n\n%description\nZManager compatibility fixture\n\n%install\nmkdir -p %{buildroot}/usr/share/zmanager-compat\nprintf 'zmanager compatibility payload\\n' > %{buildroot}/usr/share/zmanager-compat/file.txt\n\n%files\n/usr/share/zmanager-compat/file.txt\n",
        )
        .unwrap();
        let create = Command::new(rpmbuild)
            .arg("--define")
            .arg(format!("_topdir {}", topdir.display()))
            .arg("--define")
            .arg("_build_id_links none")
            .arg("-bb")
            .arg(&spec)
            .output()
            .unwrap();
        if create.status.success() {
            let archive = topdir.join("RPMS/noarch/zmanager-compat-1.0-1.noarch.rpm");
            assert_zm_extracts_payload("rpmbuild-created rpm", &archive, PAYLOAD);
        }
    }
}

fn create_project_payload(temp: &TestDir) {
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), PAYLOAD).unwrap();
}

fn write_deterministic_blob(path: &Path, bytes: usize) {
    let mut state = 0x9e37_79b9_u32;
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 24) as u8);
    }
    fs::write(path, data).unwrap();
}

fn create_stdout_archive(label: &str, command: &mut Command, archive: &Path) {
    let output_file = File::create(archive).unwrap();
    let output = command.stdout(Stdio::from(output_file)).output().unwrap();
    assert_success(label, &output);
}

fn create_stdout_archive_with_optional_tool(
    binary: &str,
    label: &str,
    configure: impl FnOnce(&mut Command),
    archive: &Path,
) -> bool {
    let Some(mut command) = optional_tool_command(binary, label) else {
        return false;
    };
    configure(&mut command);
    create_stdout_archive(label, &mut command, archive);
    true
}

fn run_optional_tool(binary: &str, label: &str, configure: impl FnOnce(&mut Command)) -> bool {
    let Some(mut command) = optional_tool_command(binary, label) else {
        return false;
    };
    configure(&mut command);
    let output = command.output().unwrap();
    assert_success(label, &output);
    true
}

fn optional_tool_command(binary: &str, label: &str) -> Option<Command> {
    let Some(path) = find_on_path(binary) else {
        eprintln!("skipping {label}: {binary} is not installed");
        return None;
    };
    Some(Command::new(path))
}

fn write_zstd_file(path: &Path, contents: &[u8]) {
    let file = File::create(path).unwrap();
    let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap();
}

fn require_tool(binary: &str) -> PathBuf {
    find_on_path(binary)
        .unwrap_or_else(|| panic!("{binary} is required for this compatibility test"))
}

fn assert_zm_extracts_payload(label: &str, archive: &Path, expected: &[u8]) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path())
        .arg("extract")
        .arg(archive)
        .arg("-C")
        .arg(&out)
        .output()
        .unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert!(
        tree_contains_file_with_contents(&out, expected),
        "extracted tree for {label} did not contain expected payload under {}",
        out.display()
    );
}

fn assert_zm_tests_archive(label: &str, archive: &Path) {
    let output = Command::new(zm_path())
        .arg("test")
        .arg(archive)
        .output()
        .unwrap();
    assert_success(&format!("zm test {label}"), &output);
}

fn run_zm_extract_with_password(archive: &Path, password: &str) -> std::process::Output {
    let out = extraction_output_dir(archive);
    run_zm_with_password(
        [
            "extract",
            archive.to_str().unwrap(),
            "-C",
            out.to_str().unwrap(),
        ],
        password,
    )
}

fn run_zm_with_password<const N: usize>(args: [&str; N], password: &str) -> std::process::Output {
    let mut command = Command::new(zm_path());
    command.args(args).arg("--password-stdin");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{password}\n").as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn run_rar_with_password<const N: usize>(
    rar: &Path,
    args: [&str; N],
    password: &str,
) -> std::process::Output {
    let mut command = Command::new(rar);
    command.args(args).arg(format!("-p{password}"));
    command.output().unwrap()
}

fn assert_zm_extracts_payload_with_password(
    label: &str,
    archive: &Path,
    expected: &[u8],
    password: &str,
) {
    let out = extraction_output_dir(archive);
    let output = run_zm_extract_with_password(archive, password);
    assert_success(&format!("zm extract {label}"), &output);
    assert!(
        tree_contains_file_with_contents(&out, expected),
        "extracted tree for {label} did not contain expected payload under {}",
        out.display()
    );
}

fn assert_zm_extracts_raw_file(label: &str, archive: &Path, output_name: &str, expected: &[u8]) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path())
        .arg("extract")
        .arg(archive)
        .arg("-C")
        .arg(&out)
        .output()
        .unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert_eq!(fs::read(out.join(output_name)).unwrap(), expected);
}

fn assert_zm_extracts_any_file(label: &str, archive: &Path) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path())
        .arg("extract")
        .arg(archive)
        .arg("-C")
        .arg(&out)
        .output()
        .unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert!(
        tree_contains_any_file(&out),
        "extracted tree for {label} did not contain any files under {}",
        out.display()
    );
}

fn assert_zm_extracts_deb_payload(label: &str, archive: &Path) {
    let out = extraction_output_dir(archive).with_file_name("out-deb-nested");
    let output = Command::new(zm_path())
        .arg("extract")
        .arg(archive)
        .arg("-C")
        .arg(&out)
        .arg("--extract-nested")
        .output()
        .unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert_eq!(
        fs::read(out.join("data/usr/share/zmanager-compat/file.txt")).unwrap(),
        PAYLOAD
    );
    assert!(
        fs::read_to_string(out.join("control/control"))
            .unwrap()
            .contains("Package: zmanager-compat")
    );
}

fn extraction_output_dir(archive: &Path) -> PathBuf {
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("archive")
        .replace(['.', '/'], "-");
    archive
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("out-{name}"))
}

fn tree_contains_file_with_contents(root: &Path, expected: &[u8]) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && tree_contains_file_with_contents(&path, expected) {
            return true;
        }
        if path.is_file()
            && let Ok(contents) = fs::read(&path)
            && contents == expected
        {
            return true;
        }
    }

    false
}

fn tree_contains_any_file(root: &Path) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && tree_contains_any_file(&path) {
            return true;
        }
        if path.is_file() {
            return true;
        }
    }

    false
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

fn zm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zm"))
}

struct TestDir {
    root: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("zmanager-{name}-{}-{now}", std::process::id()));
        fs::create_dir_all(&root).unwrap();

        Self { root }
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
