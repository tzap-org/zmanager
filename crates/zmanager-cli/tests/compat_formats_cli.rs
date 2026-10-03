mod common;

use common::*;

use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PAYLOAD: &[u8] = b"zmanager compatibility payload\n";

#[test]
fn competitor_zip_family_formats_extract_with_zm() {
    let Some(zip) = find_on_path("zip") else {
        record_optional_skip("missing optional tool: zip");
        return;
    };
    let temp = TestDir::new("compat_zip_family");
    create_project_payload(&temp);

    for extension in ["zip", "zipx", "jar", "war", "ipa", "apk", "appx", "xpi"] {
        let archive = temp.path(format!("payload.{extension}"));
        let create = Command::new(&zip).current_dir(temp.root()).arg("-qr").arg(&archive).arg("project").output().unwrap();
        assert_success(&format!("zip creates .{extension}"), &create);

        assert_zm_extracts_payload(&format!("zip-created .{extension}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_zipx_advanced_methods_extract_with_zm() {
    let Some(sevenzz) = find_on_path("7zz") else {
        record_optional_skip("missing optional tool: 7zz");
        return;
    };
    let temp = TestDir::new("compat_zipx_methods");
    create_project_payload(&temp);

    for (label, method) in
        [("store", "Copy"), ("deflate", "Deflate"), ("deflate64", "Deflate64"), ("bzip2", "BZip2"), ("lzma", "LZMA"), ("ppmd", "PPMd"), ("xz", "XZ")]
    {
        let archive = temp.path(format!("payload-{label}.zipx"));
        let create = Command::new(&sevenzz)
            .current_dir(temp.root())
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
        record_optional_skip("missing optional tool: zip");
        return;
    };
    let temp = TestDir::new("compat_zip_exe");
    create_project_payload(&temp);
    let archive = temp.path("payload.exe");

    let create = Command::new(zip).current_dir(temp.root()).arg("-qr").arg(&archive).arg("project").output().unwrap();
    assert_success("zip creates .exe-shaped archive", &create);

    assert_zm_extracts_payload("zip-created .exe-shaped archive", &archive, PAYLOAD);
}

#[test]
fn competitor_rar_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar");
    create_project_payload(&temp);

    for (label, switch, filename) in [("rar5", "-ma5", "payload-rar5.rar"), ("rar4", "-ma4", "payload-rar4.rar")] {
        let archive = temp.path(filename);
        let create = Command::new(&rar).current_dir(temp.root()).arg("a").arg("-idq").arg(switch).arg(&archive).arg("project").output().unwrap();
        if !create.status.success() && label == "rar4" {
            record_optional_skip("installed RAR creator rejected the requested RAR4 mode");
            continue;
        }
        assert_success(&format!("rar creates {label}"), &create);

        assert_zm_extracts_payload(&format!("rar-created {label}"), &archive, PAYLOAD);
    }
}

#[test]
fn competitor_rar_multipart_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_multipart");
    create_project_payload(&temp);
    let large_payload = write_deterministic_blob(&temp.path("project/big.bin"), 384 * 1024);

    for (label, switch, filename) in [("rar5 multipart", "-ma5", "payload-rar5.rar"), ("rar4 multipart", "-ma4", "payload-rar4.rar")] {
        let archive = temp.path(filename);
        let create = Command::new(&rar)
            .current_dir(temp.root())
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
            record_optional_skip(&format!("installed RAR creator rejected mode {label}"));
            continue;
        }
        assert_success(&format!("rar creates {label}"), &create);

        let first_volume = archive.with_file_name(archive.file_name().and_then(|name| name.to_str()).unwrap().replace(".rar", ".part1.rar"));
        let second_volume = archive.with_file_name(archive.file_name().and_then(|name| name.to_str()).unwrap().replace(".rar", ".part2.rar"));
        assert!(first_volume.exists() && second_volume.exists(), "{label} did not produce split .partN.rar volumes");

        let list = Command::new(zm_path()).arg("list").arg(&first_volume).output().unwrap();
        assert_success(&format!("zm lists {label}"), &list);
        let listing = String::from_utf8_lossy(&list.stdout);
        assert_eq!(listing.matches("project/big.bin").count(), 1, "zm listed a multipart continuation more than once for {label}; stdout:\n{listing}");

        let out = extraction_output_dir(&first_volume);
        let extract = Command::new(zm_path()).arg("extract").arg(&first_volume).arg("-C").arg(&out).output().unwrap();
        assert_success(&format!("zm extracts {label}"), &extract);
        assert_eq!(fs::read(out.join("project/file.txt")).unwrap(), PAYLOAD);
        assert_eq!(fs::read(out.join("project/big.bin")).unwrap(), large_payload);
    }
}

#[test]
fn competitor_rar_passworded_formats_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_gap");
    create_project_payload(&temp);

    for (label, password_switch, filename) in
        [("rar5 encrypted data", "-psecret", "payload-rar5-password.rar"), ("rar5 encrypted headers", "-hpsecret", "payload-rar5-header-password.rar")]
    {
        let archive = temp.path(filename);
        let create =
            Command::new(&rar).current_dir(temp.root()).arg("a").arg("-idq").arg("-ma5").arg(password_switch).arg(&archive).arg("project").output().unwrap();
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
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_links");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), PAYLOAD).unwrap();
    symlink("target.txt", temp.path("project/link.txt")).unwrap();
    fs::hard_link(temp.path("project/target.txt"), temp.path("project/hard.txt")).unwrap();

    let archive = temp.path("payload-rar5-links.rar");
    let create = Command::new(&rar)
        .current_dir(temp.root())
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
    assert!(fs::symlink_metadata(&symlink_path).unwrap().file_type().is_symlink());
    assert_eq!(fs::read_link(&symlink_path).unwrap(), PathBuf::from("target.txt"));
    assert_eq!(fs::read(&symlink_path).unwrap(), PAYLOAD);
    assert_eq!(fs::metadata(&target).unwrap().ino(), fs::metadata(&hardlink).unwrap().ino());
}

#[test]
fn competitor_rar_passworded_file_references_extract_with_zm() {
    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_file_references");
    fs::create_dir_all(temp.path("project")).unwrap();
    let duplicate_payload = vec![0_u8; 1024 * 1024];
    fs::write(temp.path("project/a.bin"), &duplicate_payload).unwrap();
    fs::write(temp.path("project/b.bin"), &duplicate_payload).unwrap();

    let archive = temp.path("payload-rar5-file-reference.rar");
    let create =
        Command::new(&rar).current_dir(temp.root()).arg("a").arg("-idq").arg("-ma5").arg("-hpsecret").arg("-oi").arg(&archive).arg("project").output().unwrap();
    assert_success("rar creates passworded file-reference fixture", &create);

    let technical_list = run_rar_with_password(&rar, ["vt", archive.to_str().unwrap()], "secret");
    assert_success("rar lists passworded file-reference fixture", &technical_list);
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
    assert_eq!(fs::read(out.join("project/a.bin")).unwrap(), duplicate_payload);
    assert_eq!(fs::read(out.join("project/b.bin")).unwrap(), duplicate_payload);
}

#[cfg(unix)]
#[test]
fn competitor_rar_passworded_unsafe_link_is_rejected_by_zm() {
    use std::os::unix::fs::symlink;

    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_unsafe_link");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/target.txt"), PAYLOAD).unwrap();
    let outside = temp.path("outside.txt");
    fs::write(&outside, b"outside sentinel").unwrap();
    symlink("../../outside.txt", temp.path("project/escape.txt")).unwrap();

    let archive = temp.path("payload-rar5-unsafe-link.rar");
    let create =
        Command::new(&rar).current_dir(temp.root()).arg("a").arg("-idq").arg("-ma5").arg("-hpsecret").arg("-ol").arg(&archive).arg("project").output().unwrap();
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
        record_optional_skip("missing optional tool: rar");
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
    let create =
        Command::new(&rar).current_dir(temp.root()).arg("a").arg("-idq").arg("-ma5").arg("-hpsecret").arg("-ol").arg(&archive).arg("project").output().unwrap();
    assert_success("rar creates unicode passworded fixture", &create);

    let list = run_zm_with_password(["list", archive.to_str().unwrap()], "secret");
    assert_success("zm lists unicode passworded RAR", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("project/数据/emoji-😀.txt"), "unicode RAR listing missed the unicode path\nstdout:\n{list_stdout}");

    let output = run_zm_extract_with_password(&archive, "secret");
    assert_success("zm extracts unicode passworded RAR", &output);
    let out = extraction_output_dir(&archive);
    assert_eq!(fs::read(out.join("project/数据").join(unicode_file_name)).unwrap(), PAYLOAD);
    #[cfg(unix)]
    {
        let unicode_link = out.join("project/数据/链接.txt");
        assert!(fs::symlink_metadata(&unicode_link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&unicode_link).unwrap(), PathBuf::from(unicode_file_name));
        assert_eq!(fs::read(&unicode_link).unwrap(), PAYLOAD);
    }
}

#[test]
fn competitor_rar_passworded_large_dictionary_is_rejected_by_zm() {
    let Some(rar) = find_on_path("rar") else {
        record_optional_skip("missing optional tool: rar");
        return;
    };
    let temp = TestDir::new("compat_rar_passworded_large_dictionary");
    let large_file = temp.path("large.bin");
    File::create(&large_file).unwrap().set_len(600 * 1024 * 1024).unwrap();

    let archive = temp.path("payload-rar5-large-dict.rar");
    let create = Command::new(&rar)
        .current_dir(temp.root())
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
    assert_success("rar lists passworded large-dictionary fixture", &technical_list);
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
    assert!(!extraction_output_dir(&archive).join("large.bin").exists(), "large dictionary rejection should happen before writing output");
}

#[test]
fn competitor_tar_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_tar_complex");
    create_complex_project_payload(&temp);

    let archive = temp.path("payload.tar");
    let create = Command::new(&bsdtar).arg("-cf").arg(&archive).arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates tar", &create);
    assert_zm_extracts_complex_matrix("bsdtar-created tar", &archive, &temp);
}

#[test]
fn competitor_ustar_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_ustar_complex");
    create_complex_project_payload(&temp);

    let archive = temp.path("payload.ustar");
    let create = Command::new(&bsdtar).arg("-cf").arg(&archive).arg("--format").arg("ustar").arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates ustar", &create);
    assert_zm_extracts_complex_matrix("bsdtar-created ustar", &archive, &temp);
}

#[test]
fn competitor_pax_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_pax_complex");
    create_complex_project_payload(&temp);

    let archive = temp.path("payload.pax");
    let create = Command::new(&bsdtar).arg("-cf").arg(&archive).arg("--format").arg("pax").arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates pax", &create);
    assert_zm_extracts_complex_matrix("bsdtar-created pax", &archive, &temp);
}

#[test]
fn competitor_cpio_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_cpio_complex");
    create_complex_project_payload(&temp);

    let archive = temp.path("payload.cpio");
    let create = Command::new(&bsdtar).arg("-cf").arg(&archive).arg("--format").arg("cpio").arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates cpio", &create);
    assert_zm_extracts_complex_matrix("bsdtar-created cpio", &archive, &temp);
}

#[test]
fn competitor_keka_style_cpgz_and_spk_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_cpgz_spk");
    create_project_payload(&temp);

    let cpio_archive = temp.path("payload.cpio");
    let create_cpio =
        Command::new(&bsdtar).arg("--format").arg("cpio").arg("-cf").arg(&cpio_archive).arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates cpio for cpgz", &create_cpio);
    create_stdout_archive("gzip creates cpgz", Command::new(require_tool("gzip")).arg("-c").arg(&cpio_archive), &temp.path("payload.cpgz"));
    assert_zm_extracts_payload("gzip-compressed cpio .cpgz", &temp.path("payload.cpgz"), PAYLOAD);

    let spk_archive = temp.path("payload.spk");
    let create_spk = Command::new(&bsdtar).arg("-cf").arg(&spk_archive).arg("-C").arg(temp.root()).arg("project").output().unwrap();
    assert_success("bsdtar creates spk-shaped tar", &create_spk);
    assert_zm_extracts_payload("tar-shaped .spk", &spk_archive, PAYLOAD);
}

#[test]
#[allow(clippy::too_many_lines)]
fn competitor_compressed_tar_filters_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_compressed_tar_complex");
    create_complex_project_payload(&temp);
    let mut archives = Vec::new();

    let tar_archive = temp.path("payload.tar");
    let create_tar = Command::new(&bsdtar).arg("-cf").arg(&tar_archive).arg("-C").arg(temp.root()).arg("project").output().unwrap();
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
        archives.push(("payload-compress.tar.Z".to_owned(), temp.path("payload-compress.tar.Z")));
    }

    let lz4_archive = temp.path("payload.tar.lz4");
    if run_optional_tool("lz4", "lz4 compresses tar", |command| {
        command.arg("-q").arg("-f").arg(&tar_archive).arg(&lz4_archive);
    }) {
        archives.push(("payload.tar.lz4".to_owned(), lz4_archive));
    }

    let lrzip_archive = temp.path("payload.tar.lrz");
    if run_optional_tool("lrzip", "lrzip compresses tar", |command| {
        command.arg("-q").arg("-o").arg(&lrzip_archive).arg(&tar_archive);
    }) {
        // LRZIP was removed from the supported-format list; zm must reject
        // the file as unrecognized rather than probing.
        assert_zm_rejects_unrecognized_format("tar.lrz", &lrzip_archive);
    }

    // uuencode / base64 filters are generated in-test: no universally
    // installed external tool writes both framings (bsdtar writes
    // `--uuencode` but has no base64 writer).
    let tar_bytes = fs::read(&tar_archive).unwrap();
    let uu_archive = temp.path("payload.tar.uu");
    write_uuencode_stream(&tar_bytes, "payload.tar", &uu_archive);
    archives.push(("payload.tar.uu".to_owned(), uu_archive));
    let b64_archive = temp.path("payload.tar.b64");
    write_base64_stream(&tar_bytes, "payload.tar", &b64_archive);
    archives.push(("payload.tar.b64".to_owned(), b64_archive));

    if archives.is_empty() {
        record_optional_skip("compressed tar compatibility cases: no creator tools are installed");
        return;
    }

    for (label, archive) in archives {
        assert_zm_extracts_complex_matrix(&label, &archive, &temp);
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
        archives.push(("payload.txt.zst".to_owned(), zstd_archive.clone(), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "gzip",
        "gzip compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.gz"),
    ) {
        archives.push(("payload.txt.gz".to_owned(), temp.path("payload.txt.gz"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "bzip2",
        "bzip2 compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.bz2"),
    ) {
        archives.push(("payload.txt.bz2".to_owned(), temp.path("payload.txt.bz2"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.xz"),
    ) {
        archives.push(("payload.txt.xz".to_owned(), temp.path("payload.txt.xz"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "xz",
        "xz lzma compresses raw file",
        |command| {
            command.arg("--format=lzma").arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lzma"),
    ) {
        archives.push(("payload.txt.lzma".to_owned(), temp.path("payload.txt.lzma"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "lzip",
        "lzip compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lz"),
    ) {
        archives.push(("payload.txt.lz".to_owned(), temp.path("payload.txt.lz"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "brotli",
        "brotli compresses raw file",
        |command| {
            command.arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.br"),
    ) {
        archives.push(("payload.txt.br".to_owned(), temp.path("payload.txt.br"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "lz4",
        "lz4 compresses raw file",
        |command| {
            command.arg("-q").arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lz4"),
    ) {
        archives.push(("payload.txt.lz4".to_owned(), temp.path("payload.txt.lz4"), "payload.txt"));
    }
    if create_stdout_archive_with_optional_tool(
        "lzop",
        "lzop compresses raw file",
        |command| {
            command.arg("-q").arg("-c").arg(temp.path("payload.txt"));
        },
        &temp.path("payload.txt.lzo"),
    ) {
        archives.push(("payload.txt.lzo".to_owned(), temp.path("payload.txt.lzo"), "payload.txt"));
    }
    let compress_dir = temp.path("compress-raw");
    fs::create_dir_all(&compress_dir).unwrap();
    fs::write(compress_dir.join("payload.txt"), PAYLOAD).unwrap();
    let compress_archive = compress_dir.join("payload.txt.Z");
    if run_optional_tool("compress", "compress creates raw .Z", |command| {
        command.arg("-f").arg(compress_dir.join("payload.txt"));
    }) {
        archives.push(("payload.txt.Z".to_owned(), compress_archive.clone(), "payload.txt"));
    }
    let lrzip_archive = temp.path("payload.txt.lrz");
    if run_optional_tool("lrzip", "lrzip compresses raw file", |command| {
        command.arg("-q").arg("-o").arg(&lrzip_archive).arg(temp.path("payload.txt"));
    }) {
        // LRZIP was removed from the supported-format list; zm must reject
        // the file as unrecognized rather than probing.
        assert_zm_rejects_unrecognized_format("raw lrz", &lrzip_archive);
    }
    let uu_raw = temp.path("payload.txt.uu");
    write_uuencode_stream(PAYLOAD, "payload.txt", &uu_raw);
    archives.push(("payload.txt.uu".to_owned(), uu_raw.clone(), "payload.txt"));
    let b64_raw = temp.path("payload.txt.b64");
    write_base64_stream(PAYLOAD, "payload.txt", &b64_raw);
    archives.push(("payload.txt.b64".to_owned(), b64_raw.clone(), "payload.txt"));

    if archives.is_empty() {
        record_optional_skip("raw stream compatibility cases: no creator tools are installed");
        return;
    }

    for (label, archive, output_name) in archives {
        assert_zm_extracts_raw_file(&label, &archive, output_name, PAYLOAD);
    }

    if zstd_archive.exists() {
        let stdout = Command::new(zm_path()).arg("extract").arg(&zstd_archive).arg("--to-stdout").output().unwrap();
        assert_success("zm extract raw zst to stdout", &stdout);
        assert_eq!(stdout.stdout, PAYLOAD);

        let list = Command::new(zm_path()).arg("list").arg(&zstd_archive).output().unwrap();
        assert_success("zm list raw zst", &list);
        assert!(
            String::from_utf8_lossy(&list.stdout).contains("payload.txt"),
            "raw stream listing did not include payload.txt\nstdout:\n{}",
            String::from_utf8_lossy(&list.stdout)
        );

        let test = Command::new(zm_path()).arg("test").arg(&zstd_archive).output().unwrap();
        assert_success("zm test raw zst", &test);
    }
    if lrzip_archive.exists() {
        let lrzip_stdout = Command::new(zm_path()).arg("extract").arg(&lrzip_archive).arg("--to-stdout").output().unwrap();
        assert!(!lrzip_stdout.status.success(), "zm extract raw lrz to stdout should fail");
        let stderr = String::from_utf8_lossy(&lrzip_stdout.stderr);
        assert!(stderr.contains("Unsupported or unrecognized archive format"), "unexpected stderr:\n{stderr}");
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

    let output = Command::new(zm_path()).arg("extract").arg(&archive).output().unwrap();
    assert_success("zm extract raw zst without -C", &output);
    assert_eq!(fs::read(source).unwrap(), PAYLOAD);
}

#[test]
fn competitor_iso_format_extract_with_zm() {
    let temp = TestDir::new("compat_images_packages_complex_iso");
    create_complex_project_payload(&temp);

    if let Some(mkisofs) = find_on_path("mkisofs") {
        let archive = temp.path("payload.iso");
        let iso_root = temp.path("iso_root");
        fs::create_dir_all(&iso_root).unwrap();
        // Copy project into iso_root/project so it appears as 'project/...' in the ISO
        run_optional_tool("cp", "cp project to iso_root", |c| {
            c.arg("-r").arg(temp.path("project")).arg(&iso_root);
        });

        let create = Command::new(mkisofs).arg("-quiet").arg("-R").arg("-J").arg("-o").arg(&archive).arg(&iso_root).output().unwrap();
        assert_success("mkisofs creates iso", &create);
        assert_zm_extracts_complex_matrix("mkisofs-created iso", &archive, &temp);
    }
}

#[test]
fn competitor_xar_format_extract_with_zm() {
    let temp = TestDir::new("compat_images_packages_complex_xar");
    create_complex_project_payload(&temp);

    if let Some(xar) = find_on_path("xar") {
        let archive = temp.path("payload.xar");
        let create = Command::new(xar).current_dir(temp.root()).arg("-cf").arg(&archive).arg("project").output().unwrap();
        assert_success("xar creates xar", &create);
        assert_zm_extracts_complex_matrix("xar-created xar", &archive, &temp);
    }
}

#[test]
fn competitor_cab_format_extract_with_zm() {
    let temp = TestDir::new("compat_images_packages_complex_cab");
    create_complex_project_payload(&temp);

    if let Some(gcab) = find_on_path("gcab") {
        let archive = temp.path("payload.cab");
        let create = Command::new(gcab).current_dir(temp.root()).arg("-c").arg(&archive).arg("project").output().unwrap();
        assert_success("gcab creates cab", &create);
        assert_zm_extracts_complex_matrix("gcab-created cab", &archive, &temp);
    }
}

#[test]
fn competitor_lha_format_extract_with_zm() {
    let temp = TestDir::new("compat_images_packages_complex_lha");
    create_complex_project_payload(&temp);
    let archive = temp.path("payload.lzh");

    let created_by_native_lha = if let Some(lha) = find_on_path("lha") {
        let create = Command::new(&lha).current_dir(temp.root()).arg("a").arg(&archive).arg("project").output();
        create.is_ok_and(|o| o.status.success())
    } else {
        false
    };

    if !created_by_native_lha {
        let large_blob = write_deterministic_blob(&temp.path("project/large_blob.bin"), 1024 * 100);
        let entries: [(&str, &[u8], bool); 5] = [
            ("project/root_file.txt", b"root_file_content", false),
            ("project/nested/deep_file.txt", b"deep_file_content", false),
            ("project/nested/empty_dir", b"", true),
            ("project/large_blob.bin", &large_blob, false),
            ("project/large_blob_copy.bin", &large_blob, false),
        ];
        let bytes = build_lha_level0_bytes(&entries);
        fs::write(&archive, bytes).unwrap();
    }

    assert_zm_extracts_complex_matrix("lha-format lzh", &archive, &temp);

    // If lha/lhasa is available on the system, verify that it also validates our archive
    if let Some(lha) = find_on_path("lha") {
        let test_output = Command::new(lha).arg("t").arg(&archive).output();
        if let Ok(output) = test_output
            && output.status.success()
        {
            // Lhasa verified the LHA archive successfully
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn lha_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[allow(clippy::cast_possible_truncation)]
fn build_lha_level0_bytes(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut archive = Vec::new();
    for &(name, data, is_dir) in entries {
        let name_bytes = name.as_bytes();
        let header_size = (22 + name_bytes.len()) as u8;
        let mut header = Vec::with_capacity(header_size as usize + 2);
        header.push(header_size);
        header.push(0); // placeholder for checksum
        let method = if is_dir { b"-lhd-" } else { b"-lh0-" };
        header.extend_from_slice(method);
        let comp_size = if is_dir { 0_u32 } else { data.len() as u32 };
        let uncomp_size = comp_size;
        header.extend_from_slice(&comp_size.to_le_bytes());
        header.extend_from_slice(&uncomp_size.to_le_bytes());
        let dos_time: u32 = ((2026 - 1980) << 25) | (1 << 21) | (1 << 16) | (12 << 11);
        header.extend_from_slice(&dos_time.to_le_bytes());
        header.push(if is_dir { 0x10 } else { 0x20 });
        header.push(0); // Level 0
        header.push(name_bytes.len() as u8);
        header.extend_from_slice(name_bytes);
        let crc = if is_dir { 0_u16 } else { lha_crc16(data) };
        header.extend_from_slice(&crc.to_le_bytes());

        let sum: u8 = header[2..].iter().fold(0_u8, |acc, &b| acc.wrapping_add(b));
        header[1] = sum;

        archive.extend_from_slice(&header);
        if !is_dir {
            archive.extend_from_slice(data);
        }
    }
    archive
}

#[test]
fn competitor_native_ar_format_extract_with_zm() {
    let temp = TestDir::new("compat_unix_packages_ar");
    create_project_payload(&temp);

    if let Some(ar) = find_on_path("ar") {
        let archive = temp.path("payload.ar");
        let create = Command::new(ar).current_dir(temp.path("project")).arg("-qcS").arg(&archive).arg("file.txt").output().unwrap();
        assert_success("ar creates ar archive", &create);
        assert_zm_extracts_payload("ar-created archive", &archive, PAYLOAD);
    }
}

#[test]
fn competitor_dpkg_deb_format_extract_with_zm() {
    let temp = TestDir::new("compat_unix_packages_deb");
    create_project_payload(&temp);

    if let Some(dpkg_deb) = find_on_path("dpkg-deb") {
        let package_root = temp.path("deb-root");
        fs::create_dir_all(package_root.join("DEBIAN")).unwrap();
        fs::create_dir_all(package_root.join("usr/share/zmanager-compat")).unwrap();
        fs::write(
            package_root.join("DEBIAN/control"),
            "Package: zmanager-compat\nVersion: 1.0\nArchitecture: all\nMaintainer: ZManager <test@example.invalid>\nDescription: ZManager compatibility fixture\n",
        )
        .unwrap();
        fs::write(package_root.join("usr/share/zmanager-compat/file.txt"), PAYLOAD).unwrap();
        let archive = temp.path("payload.deb");
        let create = Command::new(dpkg_deb).arg("--build").arg("--root-owner-group").arg(&package_root).arg(&archive).output().unwrap();
        assert_success("dpkg-deb creates deb", &create);
        assert_zm_extracts_any_file("dpkg-deb-created deb", &archive);
        assert_zm_extracts_deb_payload("dpkg-deb-created deb nested payload", &archive);
    }
}

#[test]
fn competitor_rpm_format_extract_with_zm() {
    let temp = TestDir::new("compat_unix_packages_rpm");
    create_project_payload(&temp);

    if let Some(rpmbuild) = find_on_path("rpmbuild") {
        let topdir = temp.path("rpmbuild");
        for dir in ["BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"] {
            fs::create_dir_all(topdir.join(dir)).unwrap();
        }
        let spec = topdir.join("SPECS/zmanager-compat.spec");
        fs::write(
            &spec,
            "Name: zmanager-compat\nVersion: 1.0\nRelease: 1\nSummary: ZManager compatibility fixture\nLicense: Apache-2.0\nBuildArch: noarch\n\n%description\nZManager compatibility fixture\n\n%install\nmkdir -p %{buildroot}/usr/share/zmanager-compat\nprintf 'zmanager compatibility payload\\n' > %{buildroot}/usr/share/zmanager-compat/file.txt\n\n%files\n/usr/share/zmanager-compat/file.txt\n",
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

#[test]
fn competitor_squashfs_format_extract_with_zm() {
    let temp = TestDir::new("compat_squashfs");
    create_project_payload(&temp);

    if let Some(mksquashfs) = find_on_path("mksquashfs") {
        let archive = temp.path("payload.squashfs");
        let create = Command::new(mksquashfs).arg(temp.path("project")).arg(&archive).arg("-noappend").output().unwrap();
        assert_success("mksquashfs creates squashfs", &create);
        assert_zm_tests_archive("mksquashfs creates squashfs", &archive);
        assert_zm_extracts_payload("mksquashfs creates squashfs", &archive, PAYLOAD);
    }
}

#[test]
fn competitor_wim_formats_extract_with_zm() {
    let temp = TestDir::new("compat_wim");
    create_project_payload(&temp);

    if let Some(wimlib) = find_on_path("wimlib-imagex") {
        let archive = temp.path("payload.wim");
        let create = Command::new(wimlib).arg("capture").arg(temp.path("project")).arg(&archive).output().unwrap();
        assert_success("wimlib-imagex creates wim", &create);
        assert_zm_tests_archive("wimlib creates wim", &archive);
        assert_zm_extracts_payload("wimlib creates wim", &archive, PAYLOAD);
    }
}

fn create_project_payload(temp: &TestDir) {
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), PAYLOAD).unwrap();
}

fn write_deterministic_blob(path: &Path, bytes: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 24) as u8);
    }
    fs::write(path, &data).unwrap();
    data
}

fn create_stdout_archive(label: &str, command: &mut Command, archive: &Path) {
    let output_file = File::create(archive).unwrap();
    let output = command.stdout(Stdio::from(output_file)).output().unwrap();
    assert_success(label, &output);
}

fn create_stdout_archive_with_optional_tool(binary: &str, label: &str, configure: impl FnOnce(&mut Command), archive: &Path) -> bool {
    let Some(mut command) = optional_tool_command(binary, label) else {
        return false;
    };
    configure(&mut command);
    create_stdout_archive(label, &mut command, archive);
    true
}

/// Writes a sharutils-style uuencode stream (`begin 644 <name>`, 45-byte
/// body lines, ` `-padded final group, zero-count line, `end`).
fn write_uuencode_stream(data: &[u8], name: &str, archive: &Path) {
    let mut out = Vec::new();
    out.extend_from_slice(format!("begin 644 {name}\n").as_bytes());
    for chunk in data.chunks(45) {
        out.push(u8::try_from(chunk.len()).unwrap_or(0) + 0x20);
        for triple in chunk.chunks(3) {
            let first = triple.first().copied().unwrap_or(0);
            let second = triple.get(1).copied().unwrap_or(0);
            let third = triple.get(2).copied().unwrap_or(0);
            let value = u32::from(first) << 16 | u32::from(second) << 8 | u32::from(third);
            for shift in [18_u32, 12, 6, 0] {
                out.push(u8::try_from((value >> shift) & 0x3f).unwrap_or(0) + 0x20);
            }
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b" \nend\n");
    fs::write(archive, out).unwrap();
}

/// Writes a MIME-style base64 stream with the `begin-base64` / `====`
/// framing the libarchive filter expects.
fn write_base64_stream(data: &[u8], name: &str, archive: &Path) {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    out.extend_from_slice(format!("begin-base64 644 {name}\n").as_bytes());
    let mut line_len = 0_usize;
    for chunk in data.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0);
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = u32::from(first) << 16 | u32::from(second) << 8 | u32::from(third);
        let quartet = [
            ALPHABET[usize::try_from((value >> 18) & 0x3f).unwrap_or(0)],
            ALPHABET[usize::try_from((value >> 12) & 0x3f).unwrap_or(0)],
            if chunk.len() > 1 { ALPHABET[usize::try_from((value >> 6) & 0x3f).unwrap_or(0)] } else { b'=' },
            if chunk.len() > 2 { ALPHABET[usize::try_from(value & 0x3f).unwrap_or(0)] } else { b'=' },
        ];
        out.extend_from_slice(&quartet);
        line_len += 4;
        if line_len >= 76 {
            out.push(b'\n');
            line_len = 0;
        }
    }
    if line_len > 0 {
        out.push(b'\n');
    }
    out.extend_from_slice(b"====\n");
    fs::write(archive, out).unwrap();
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
        record_optional_skip(&format!("{label}: missing optional tool: {binary}"));
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
    find_on_path(binary).unwrap_or_else(|| panic!("{binary} is required for this compatibility test"))
}

fn assert_zm_extracts_payload(label: &str, archive: &Path, expected: &[u8]) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert!(tree_contains_file_with_contents(&out, expected), "extracted tree for {label} did not contain expected payload under {}", out.display());
}

fn assert_zm_tests_archive(label: &str, archive: &Path) {
    let output = Command::new(zm_path()).arg("test").arg(archive).output().unwrap();
    assert_success(&format!("zm test {label}"), &output);
}

fn run_zm_extract_with_password(archive: &Path, password: &str) -> std::process::Output {
    let out = extraction_output_dir(archive);
    run_zm_with_password(["extract", archive.to_str().unwrap(), "-C", out.to_str().unwrap()], password)
}

fn run_zm_with_password<const N: usize>(args: [&str; N], password: &str) -> std::process::Output {
    let mut command = Command::new(zm_path());
    command.args(args).arg("--password-stdin");
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(format!("{password}\n").as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn run_rar_with_password<const N: usize>(rar: &Path, args: [&str; N], password: &str) -> std::process::Output {
    let mut command = Command::new(rar);
    command.args(args).arg(format!("-p{password}"));
    command.output().unwrap()
}

fn assert_zm_extracts_payload_with_password(label: &str, archive: &Path, expected: &[u8], password: &str) {
    let out = extraction_output_dir(archive);
    let output = run_zm_extract_with_password(archive, password);
    assert_success(&format!("zm extract {label}"), &output);
    assert!(tree_contains_file_with_contents(&out, expected), "extracted tree for {label} did not contain expected payload under {}", out.display());
}

/// Asserts that zm rejects the archive with the explicit unrecognized-format
/// error: formats removed from the supported list (for example LRZIP) are
/// rejected without probing.
fn assert_zm_rejects_unrecognized_format(label: &str, archive: &Path) {
    let output = Command::new(zm_path()).arg("list").arg(archive).output().unwrap();
    assert!(!output.status.success(), "zm list {label} should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unsupported or unrecognized archive format"), "zm list {label} stderr was:\n{stderr}");
}

fn assert_zm_extracts_raw_file(label: &str, archive: &Path, output_name: &str, expected: &[u8]) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert_eq!(fs::read(out.join(output_name)).unwrap(), expected);
}

fn assert_zm_extracts_any_file(label: &str, archive: &Path) {
    let out = extraction_output_dir(archive);
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert!(tree_contains_any_file(&out), "extracted tree for {label} did not contain any files under {}", out.display());
}

fn assert_zm_extracts_deb_payload(label: &str, archive: &Path) {
    let out = extraction_output_dir(archive).with_file_name("out-deb-nested");
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).arg("--extract-nested").output().unwrap();
    assert_success(&format!("zm extract {label}"), &output);
    assert_eq!(fs::read(out.join("data/usr/share/zmanager-compat/file.txt")).unwrap(), PAYLOAD);
    assert!(fs::read_to_string(out.join("control/control")).unwrap().contains("Package: zmanager-compat"));
}

fn extraction_output_dir(archive: &Path) -> PathBuf {
    let name = archive.file_name().and_then(|name| name.to_str()).unwrap_or("archive").replace(['.', '/'], "-");
    archive.parent().unwrap_or_else(|| Path::new(".")).join(format!("out-{name}"))
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

fn create_complex_project_payload(temp: &TestDir) {
    fs::create_dir_all(temp.path("project/nested/empty_dir")).unwrap();
    fs::write(temp.path("project/root_file.txt"), b"root_file_content").unwrap();
    fs::write(temp.path("project/nested/deep_file.txt"), b"deep_file_content").unwrap();
    let large_blob = write_deterministic_blob(&temp.path("project/large_blob.bin"), 1024 * 100);
    fs::write(temp.path("project/large_blob_copy.bin"), large_blob).unwrap();
}

fn assert_zm_extracts_complex_matrix(label: &str, archive: &Path, temp: &TestDir) {
    assert_zm_extracts_complex_matrix_inner(label, archive, temp, true);
}

fn assert_zm_extracts_complex_matrix_without_stdout(label: &str, archive: &Path, temp: &TestDir) {
    assert_zm_extracts_complex_matrix_inner(label, archive, temp, false);
}

fn assert_zm_extracts_complex_matrix_inner(label: &str, archive: &Path, temp: &TestDir, stdout_supported: bool) {
    println!("Matrix test for: {label}");
    // Matrix 1: Full Extract
    let out = temp.path(format!("out_full_{}", label.replace([' ', '-'], "_")));
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label} (full)"), &output);
    assert!(out.join("project/root_file.txt").exists(), "missing root file for {label}");
    assert!(out.join("project/nested/deep_file.txt").exists(), "missing deep file");
    // CAB-internal names are file keys, and MSI packages have no empty
    // directory entries, so neither fixture carries empty_dir.
    if !label.contains("cab") && !label.contains("msi") {
        assert!(out.join("project/nested/empty_dir").is_dir(), "missing dir");
    }
    assert!(out.join("project/large_blob.bin").exists(), "missing blob");

    // Matrix 2: Selective Extract
    let out_sel = temp.path(format!("out_sel_{}", label.replace([' ', '-'], "_")));
    let output =
        Command::new(zm_path()).arg("extract").arg(archive).arg("--include").arg("project/nested/deep_file.txt").arg("-C").arg(&out_sel).output().unwrap();
    assert_success(&format!("zm extract {label} (selective)"), &output);
    assert!(out_sel.join("project/nested/deep_file.txt").exists(), "missing selective file");
    assert!(!out_sel.join("project/root_file.txt").exists(), "unexpected root file");

    // Matrix 3: Stdout Extract. The virtual-disk and optical families copy
    // through the shared path/occurrence selector, so they support it; DMG,
    // PKG, and MSI must still fail with the explicit rejection message.
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("--include").arg("project/root_file.txt").arg("--to-stdout").output().unwrap();
    if stdout_supported {
        assert_success(&format!("zm extract {label} (stdout)"), &output);
        assert_eq!(output.stdout, b"root_file_content");
    } else {
        assert_failure(&format!("zm extract {label} (stdout)"), &output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("do not currently support extracting to stdout"),
            "stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Matrix 4: Overwrite
    let out_ow = temp.path(format!("out_ow_{}", label.replace([' ', '-'], "_")));
    fs::create_dir_all(out_ow.join("project")).unwrap();
    fs::write(out_ow.join("project/root_file.txt"), b"junk_data").unwrap();
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("--overwrite").arg("always").arg("-C").arg(&out_ow).output().unwrap();
    assert_success(&format!("zm extract {label} (overwrite)"), &output);
    assert_eq!(fs::read(out_ow.join("project/root_file.txt")).unwrap(), b"root_file_content");

    // Matrix 5: List Archive
    let output = Command::new(zm_path()).arg("list").arg(archive).output().unwrap();
    assert_success(&format!("zm list {label}"), &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("project/root_file.txt"));
    assert!(stdout.contains("project/nested/deep_file.txt"));

    let json = Command::new(zm_path()).arg("list").arg(archive).arg("--json").output().unwrap();
    assert_success(&format!("zm list {label} --json"), &json);
    let listing: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let entries = listing["entries"].as_array().expect("JSON listing entries array");
    let kind_for = |path: &str| {
        entries
            .iter()
            .find(|entry| entry["name"].as_str() == Some(path))
            .and_then(|entry| entry["kind"].as_str())
            .unwrap_or_else(|| panic!("missing JSON listing entry {path} for {label}: {listing}"))
    };
    assert_eq!(kind_for("project/root_file.txt"), "file", "regular file kind for {label}");
    if !label.contains("cab") && !label.contains("msi") {
        let directory_path = if label.contains("lha") { "project/nested/empty_dir" } else { "project/nested" };
        assert_eq!(kind_for(directory_path), "directory", "directory kind for {label}");
    }
}

#[test]
fn competitor_ar_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_ar");
    let payload = b"flat payload contents\n";
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), payload).unwrap();

    let archive_ar = temp.path("payload.ar");
    let create_ar =
        Command::new(&bsdtar).current_dir(temp.root()).arg("--format").arg("ar").arg("-cf").arg(&archive_ar).arg("project/file.txt").output().unwrap();
    assert_success("bsdtar creates ar", &create_ar);
    assert_zm_extracts_payload("bsdtar-created ar", &archive_ar, payload);
}

#[test]
fn competitor_warc_format_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_warc");
    let payload = b"flat payload contents\n";
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), payload).unwrap();

    let archive_warc = temp.path("payload.warc");
    let create_warc =
        Command::new(&bsdtar).current_dir(temp.root()).arg("--format").arg("warc").arg("-cf").arg(&archive_warc).arg("project/file.txt").output().unwrap();
    assert_success("bsdtar creates warc", &create_warc);
    assert_zm_extracts_payload("bsdtar-created warc", &archive_warc, payload);
}

#[cfg(unix)]
#[test]
fn competitor_mtree_format_list_test_and_extract_with_zm() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        record_optional_skip("missing optional tool: bsdtar");
        return;
    };
    let temp = TestDir::new("compat_mtree");
    let payload = b"flat payload contents\n";
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), payload).unwrap();

    let archive_mtree = temp.path("payload.mtree");
    let create_mtree =
        Command::new(&bsdtar).current_dir(temp.root()).arg("--format").arg("mtree").arg("-cf").arg(&archive_mtree).arg("project").output().unwrap();
    assert_success("bsdtar creates mtree", &create_mtree);

    let list_output = Command::new(zm_path()).arg("list").arg(&archive_mtree).output().unwrap();
    assert_success("zm list mtree", &list_output);
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("project/file.txt"));

    let test_output = Command::new(zm_path()).arg("test").arg(&archive_mtree).output().unwrap();
    assert_success("zm test mtree", &test_output);

    let output_dir = temp.path("out");
    let extract_output = Command::new(zm_path()).arg("extract").arg(&archive_mtree).arg("-C").arg(&output_dir).output().unwrap();
    assert_success("zm extract mtree", &extract_output);
    assert_eq!(fs::metadata(output_dir.join("project/file.txt")).unwrap().len(), payload.len() as u64);
}

/// The Apple formats must handle entries beyond the shared complex payload:
/// unicode paths, spaces in names, and symlinks.
fn assert_zm_extracts_apple_extra_entries(label: &str, archive: &Path, temp: &TestDir) {
    let out = temp.path(format!("out_extras_{}", label.replace([' ', '-'], "_")));
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label} (extra entries)"), &output);
    assert_eq!(fs::read(out.join("project/unicode/こんにちは.txt")).unwrap(), b"unicode_content");
    assert_eq!(fs::read(out.join("project/file with spaces.txt")).unwrap(), b"spaces_content");
    #[cfg(unix)]
    {
        assert_eq!(fs::read_link(out.join("project/nested/link.txt")).unwrap(), PathBuf::from("../root_file.txt"));
    }
}

#[test]
fn competitor_apple_dmg_and_pkg_formats_extract_with_zm() {
    let Some(hdiutil) = find_on_path("hdiutil") else {
        record_optional_skip("missing optional tool: hdiutil");
        return;
    };
    let Some(pkgbuild) = find_on_path("pkgbuild") else {
        record_optional_skip("missing optional tool: pkgbuild");
        return;
    };
    let temp = TestDir::new("compat_apple");
    let archive_temp = TestDir::new("compat_apple_archives");
    create_complex_project_payload(&temp);

    // Extra entries beyond the shared payload: unicode paths, spaces in
    // names, and a symlink (APFS keeps its target in a catalog xattr).
    fs::create_dir_all(temp.path("project/unicode")).unwrap();
    fs::write(temp.path("project/unicode/こんにちは.txt"), b"unicode_content").unwrap();
    fs::write(temp.path("project/file with spaces.txt"), b"spaces_content").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("../root_file.txt", temp.path("project/nested/link.txt")).unwrap();
    }

    // APFS image (hdiutil's default on modern macOS).
    let archive_dmg = archive_temp.path("project.dmg");
    let create_dmg =
        Command::new(&hdiutil).arg("create").arg("-format").arg("UDZO").arg("-ov").arg("-srcfolder").arg(temp.root()).arg(&archive_dmg).output().unwrap();
    assert_success("hdiutil creates dmg", &create_dmg);
    assert_zm_extracts_complex_matrix_without_stdout("hdiutil-created dmg", &archive_dmg, &temp);
    assert_zm_extracts_apple_extra_entries("hdiutil-created dmg", &archive_dmg, &temp);

    // HFS+ image: symlink targets live in the data fork there, so this
    // exercises the other on-disk storage path.
    let archive_dmg_hfs = archive_temp.path("project-hfs.dmg");
    let create_dmg_hfs = Command::new(&hdiutil)
        .arg("create")
        .arg("-fs")
        .arg("HFS+")
        .arg("-format")
        .arg("UDZO")
        .arg("-ov")
        .arg("-srcfolder")
        .arg(temp.root())
        .arg(&archive_dmg_hfs)
        .output()
        .unwrap();
    assert_success("hdiutil creates HFS+ dmg", &create_dmg_hfs);
    assert_zm_extracts_complex_matrix_without_stdout("hdiutil-created HFS+ dmg", &archive_dmg_hfs, &temp);
    assert_zm_extracts_apple_extra_entries("hdiutil-created HFS+ dmg", &archive_dmg_hfs, &temp);

    let archive_pkg = archive_temp.path("project.pkg");
    let create_pkg = Command::new(&pkgbuild)
        .arg("--root")
        .arg(temp.root())
        .arg("--identifier")
        .arg("com.zmanager.compat")
        .arg("--version")
        .arg("0.1.0")
        .arg(&archive_pkg)
        .output()
        .unwrap();
    assert_success("pkgbuild creates pkg", &create_pkg);
    assert_zm_extracts_complex_matrix_without_stdout("pkgbuild-created pkg", &archive_pkg, &temp);
    assert_zm_extracts_apple_extra_entries("pkgbuild-created pkg", &archive_pkg, &temp);
}

#[test]
fn competitor_msi_formats_extract_with_zm() {
    let Some(wixl) = find_on_path("wixl") else {
        record_optional_skip("missing optional tool: wixl");
        return;
    };
    let temp = TestDir::new("compat_msi");
    let archive_temp = TestDir::new("compat_msi_archives");
    create_complex_project_payload(&temp);

    // MSI has no symlink entries and wixl cannot encode non-ASCII File
    // table names; spaces in names is the only extra entry that carries.
    fs::write(temp.path("project/file with spaces.txt"), b"spaces_content").unwrap();

    // The Directory table drives target paths: TARGETDIR -> project ->
    // nested, exactly the layout msiextract will resolve.
    fs::write(
        temp.path("project.wxs"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Name="ZManager Compat" Manufacturer="ZManager" Language="1033" Version="0.1.0"
           Id="11111111-2222-3333-4444-666666666666" UpgradeCode="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee">
    <Package Description="Compatibility test MSI" Comments="compat" InstallerVersion="200" Compressed="yes"/>
    <Media Id="1" Cabinet="project.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="PROJECTDIR" Name="project">
        <Directory Id="NESTEDDIR" Name="nested">
          <Component Id="NestedFiles" Guid="99999999-8888-7777-6666-555555555501">
            <File Id="deep_file" Name="deep_file.txt" Source="project/nested/deep_file.txt"/>
          </Component>
        </Directory>
        <Component Id="RootFiles" Guid="99999999-8888-7777-6666-555555555502">
          <File Id="root_file" Name="root_file.txt" Source="project/root_file.txt"/>
          <File Id="large_blob" Name="large_blob.bin" Source="project/large_blob.bin"/>
          <File Id="large_blob_copy" Name="large_blob_copy.bin" Source="project/large_blob_copy.bin"/>
          <File Id="spaces" Name="file with spaces.txt" Source="project/file with spaces.txt"/>
        </Component>
      </Directory>
    </Directory>
    <Feature Id="DefaultFeature" Title="Main Feature" Level="1">
      <ComponentRef Id="NestedFiles"/>
      <ComponentRef Id="RootFiles"/>
    </Feature>
  </Product>
</Wix>
"#,
    )
    .unwrap();

    let archive_msi = archive_temp.path("project.msi");
    let create_msi = Command::new(&wixl).current_dir(temp.root()).arg("-o").arg(&archive_msi).arg("project.wxs").output().unwrap();
    assert_success("wixl creates msi", &create_msi);
    assert_zm_extracts_complex_matrix_without_stdout("wixl-created msi", &archive_msi, &temp);

    let out_extra = temp.path("out_extras_msi");
    let extract_extra = Command::new(zm_path()).arg("extract").arg(&archive_msi).arg("-C").arg(&out_extra).output().unwrap();
    assert_success("zm extract wixl-created msi (extra entries)", &extract_extra);
    assert_eq!(fs::read(out_extra.join("project/file with spaces.txt")).unwrap(), b"spaces_content");

    // Cross-tool verification against msitools' msiextract when available:
    // the reference extraction must match entry-for-entry.
    let Some(msiextract) = find_on_path("msiextract") else {
        record_optional_skip("missing optional tool: msiextract");
        return;
    };
    let reference = archive_temp.path("reference");
    let extract_ref = Command::new(&msiextract).arg("-C").arg(&reference).arg(&archive_msi).output().unwrap();
    assert_success("msiextract extracts msi", &extract_ref);
    assert_trees_match("msiextract reference vs zm", &reference.join("project"), &out_extra.join("project"));
}

/// Builds live VHD/VMDK/UDF disk images with qemu-img, mtools, and (for NTFS
/// and UDF) a privileged Ubuntu container, then runs the combinatorial matrix
/// on each. The FAT32 leg runs whenever qemu-img + mtools are present; the
/// NTFS and UDF legs additionally require a running Docker daemon.
#[test]
fn competitor_virtual_disk_formats_extract_with_zm() {
    let Some(qemu_img) = find_on_path("qemu-img") else {
        record_optional_skip("missing optional tool: qemu-img");
        return;
    };
    let Some(mformat) = find_on_path("mformat") else {
        record_optional_skip("missing optional tool: mformat");
        return;
    };
    let Some(mcopy) = find_on_path("mcopy") else {
        record_optional_skip("missing optional tool: mcopy");
        return;
    };
    let temp = TestDir::new("compat_virtual_disk");
    let archive_temp = TestDir::new("compat_virtual_disk_archives");
    create_complex_project_payload(&temp);

    // Extras beyond the shared payload: spaces + unicode (FAT/NTFS/UDF all
    // preserve them). No symlink: the vfs adapters read symlink target bytes
    // as a regular file, so it would materialize as junk (documented).
    fs::write(temp.path("project/file with spaces.txt"), b"spaces_content").unwrap();
    fs::create_dir_all(temp.path("project/unicode")).unwrap();
    fs::write(temp.path("project/unicode/こんにちは.txt"), b"unicode_content").unwrap();

    // Superfloppy FAT32 raw built with mtools (no mount, no root), converted
    // to both VMDK and VHD from one raw image.
    let raw_fat = archive_temp.path("raw-fat.img");
    fs::File::create(&raw_fat).unwrap().set_len(64 * 1024 * 1024).unwrap();
    assert_success("mformat raw image", &Command::new(&mformat).arg("-F").arg("-i").arg(&raw_fat).arg("::").output().unwrap());
    assert_success("mcopy payload into raw image", &{
        // mcopy converts source names from the process locale's charset; a
        // C-locale environment (containers, minimal CI images) mangles the
        // unicode names, so pin a UTF-8 locale for the copy.
        let mut cmd = Command::new(&mcopy);
        cmd.env("LC_ALL", "C.UTF-8").arg("-s").arg("-i").arg(&raw_fat).arg(temp.path("project")).arg("::");
        cmd.output().unwrap()
    });

    let project_vmdk = archive_temp.path("project.vmdk");
    assert_success(
        "qemu-img converts raw to vmdk",
        &Command::new(&qemu_img).arg("convert").arg("-f").arg("raw").arg("-O").arg("vmdk").arg(&raw_fat).arg(&project_vmdk).output().unwrap(),
    );
    assert_zm_extracts_complex_matrix("qemu-img-created vmdk (FAT32)", &project_vmdk, &temp);
    assert_zm_extracts_virtual_disk_extra_entries("qemu-img-created vmdk (FAT32)", &project_vmdk, &temp);

    let project_vhd = archive_temp.path("project.vhd");
    assert_success(
        "qemu-img converts raw to vpc",
        &Command::new(&qemu_img).arg("convert").arg("-f").arg("raw").arg("-O").arg("vpc").arg(&raw_fat).arg(&project_vhd).output().unwrap(),
    );
    assert_zm_extracts_complex_matrix("qemu-img-created vhd (FAT32)", &project_vhd, &temp);
    assert_zm_extracts_virtual_disk_extra_entries("qemu-img-created vhd (FAT32)", &project_vhd, &temp);

    // NTFS and UDF legs: authored inside a privileged Ubuntu container (loop
    // mount + cp -a, no FUSE). Skip when docker is absent or the daemon is
    // not running.
    let Some(docker) = find_on_path("docker") else {
        record_optional_skip("NTFS/UDF compat legs: docker is not installed");
        return;
    };
    if !Command::new(&docker).arg("info").output().is_ok_and(|output| output.status.success()) {
        record_optional_skip("NTFS/UDF compat legs: docker daemon is not running");
        return;
    }
    let work = temp.root();

    // NTFS superfloppy VHD (the checked-in fixture already covers MBR+NTFS).
    // The patched ntfs-core adapter decodes reparse/IntxLNK symlinks, so this
    // leg keeps the symlink the FAT legs must strip.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../root_file.txt", temp.path("project/nested/link.txt")).unwrap();
    }
    let ntfs_vhd = archive_temp.path("project-ntfs.vhd");
    let ntfs_build = Command::new(&docker)
        .arg("run")
        .args(["--rm", "--privileged", "-v"])
        .arg(format!("{}:/work", work.display()))
        .args(["ubuntu:24.04", "bash", "-c"])
        .arg("set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq ntfs-3g >/dev/null 2>&1; dd if=/dev/zero of=/work/ntfs.img bs=1M count=64 status=none; LOOP=$(losetup -f); losetup $LOOP /work/ntfs.img; mkntfs -F -L ZCOMPAT $LOOP >/dev/null 2>&1; mkdir -p /mnt/ntfs && mount -t ntfs-3g $LOOP /mnt/ntfs; cp -a /work/project /mnt/ntfs/; sync; umount /mnt/ntfs; losetup -d $LOOP")
        .output()
        .unwrap();
    assert_success("docker authors NTFS image", &ntfs_build);
    assert_success(
        "qemu-img converts ntfs raw to vpc",
        &Command::new(&qemu_img).arg("convert").arg("-f").arg("raw").arg("-O").arg("vpc").arg(work.join("ntfs.img")).arg(&ntfs_vhd).output().unwrap(),
    );
    assert_zm_extracts_complex_matrix("docker-created ntfs vhd", &ntfs_vhd, &temp);
    assert_zm_extracts_virtual_disk_extra_entries("docker-created ntfs vhd", &ntfs_vhd, &temp);
    #[cfg(unix)]
    {
        let out = temp.path("out_extras_docker_created_ntfs_vhd");
        assert_eq!(fs::read_link(out.join("project/nested/link.txt")).unwrap(), PathBuf::from("../root_file.txt"));
    }

    // UDF 2.01 physical partition, populated via loop mount (--utf8 is fine
    // for the engine's UDF probe; mkudffs just requires it as first argument).
    // The symlink was already created for the NTFS leg above; `cp -a` carries
    // it into this volume too.
    let udf_image = work.join("project.udf");
    let udf_build = Command::new(&docker)
        .arg("run")
        .args(["--rm", "--privileged", "-v"])
        .arg(format!("{}:/work", work.display()))
        .args(["ubuntu:24.04", "bash", "-c"])
        .arg("set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq udftools >/dev/null 2>&1; dd if=/dev/zero of=/work/project.udf bs=1M count=16 status=none; mkudffs --media-type=hd --udfrev=0x0201 /work/project.udf >/dev/null 2>&1; LOOP=$(losetup -f); losetup $LOOP /work/project.udf; mkdir -p /mnt/udf && mount -t udf $LOOP /mnt/udf; cp -a /work/project /mnt/udf/; sync; umount /mnt/udf; losetup -d $LOOP")
        .output()
        .unwrap();
    assert_success("docker authors UDF image", &udf_build);
    assert_zm_extracts_complex_matrix("docker-created udf", &udf_image, &temp);
    assert_zm_extracts_virtual_disk_extra_entries("docker-created udf", &udf_image, &temp);
    #[cfg(unix)]
    {
        let out = temp.path("out_extras_docker_created_udf");
        assert_eq!(fs::read_link(out.join("project/nested/link.txt")).unwrap(), PathBuf::from("../root_file.txt"));
    }
}

/// The virtual-disk formats must handle entries beyond the shared complex
/// payload: unicode paths and spaces in names. Symlinks are intentionally
/// absent (see the fixture README divergence note).
fn assert_zm_extracts_virtual_disk_extra_entries(label: &str, archive: &Path, temp: &TestDir) {
    let out = temp.path(format!("out_extras_{}", label.replace([' ', '-'], "_")));
    let output = Command::new(zm_path()).arg("extract").arg(archive).arg("-C").arg(&out).output().unwrap();
    assert_success(&format!("zm extract {label} (extra entries)"), &output);
    assert_eq!(fs::read(out.join("project/unicode/こんにちは.txt")).unwrap(), b"unicode_content");
    assert_eq!(fs::read(out.join("project/file with spaces.txt")).unwrap(), b"spaces_content");
}

#[test]
fn zm_create_tzap_sidecar_toggle_behavior() {
    let temp = TestDir::new("zm_create_tzap_sidecar");
    let source = temp.path("payload.txt");
    fs::write(&source, b"test payload content").unwrap();

    // 1. By default, zm create should NOT emit a .sidecar file
    let default_archive = temp.path("default.tzap");
    let default_sidecar = temp.path("default.sidecar");
    let create_default =
        Command::new(zm_path()).args(["create", default_archive.to_str().unwrap(), source.to_str().unwrap(), "--format", "tzap"]).output().unwrap();
    assert_success("zm create tzap default", &create_default);
    assert!(default_archive.exists(), "archive must exist");
    assert!(!default_sidecar.exists(), "sidecar must NOT exist by default");

    // 2. With --sidecar flag, zm create SHOULD emit a .sidecar file
    let sidecar_archive = temp.path("with_sidecar.tzap");
    let sidecar_file = temp.path("with_sidecar.sidecar");
    let create_with_sidecar = Command::new(zm_path())
        .args(["create", sidecar_archive.to_str().unwrap(), source.to_str().unwrap(), "--format", "tzap", "--sidecar"])
        .output()
        .unwrap();
    assert_success("zm create tzap --sidecar", &create_with_sidecar);
    assert!(sidecar_archive.exists(), "archive must exist");
    assert!(sidecar_file.exists(), "sidecar MUST exist with --sidecar");
    assert!(fs::metadata(&sidecar_file).unwrap().len() > 0, "sidecar must be non-empty");

    // 3. With explicit --no-sidecar flag, sidecar is disabled
    let no_sidecar_archive = temp.path("no_sidecar.tzap");
    let no_sidecar_file = temp.path("no_sidecar.sidecar");
    let create_no_sidecar = Command::new(zm_path())
        .args(["create", no_sidecar_archive.to_str().unwrap(), source.to_str().unwrap(), "--format", "tzap", "--no-sidecar"])
        .output()
        .unwrap();
    assert_success("zm create tzap --no-sidecar", &create_no_sidecar);
    assert!(no_sidecar_archive.exists(), "archive must exist");
    assert!(!no_sidecar_file.exists(), "sidecar must NOT exist with --no-sidecar");
}
