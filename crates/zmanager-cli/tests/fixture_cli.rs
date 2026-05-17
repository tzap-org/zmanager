use std::env;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

#[test]
fn cli_lists_all_fixture_archives() {
    for fixture in fixture_manifest() {
        let output = Command::new(cli_path())
            .arg("list")
            .arg(fixture.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "failed to list {} ({})\nstdout:\n{}\nstderr:\n{}",
            fixture.filename,
            fixture.format,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_extracts_extractable_fixture_archives() {
    for fixture in fixture_manifest()
        .into_iter()
        .filter(|fixture| fixture.extract)
    {
        let temp = TestDir::new("fixture_cli_extracts");
        let output = Command::new(cli_path())
            .arg("extract")
            .arg(fixture.path())
            .arg(temp.path("out"))
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "failed to extract {} ({})\nstdout:\n{}\nstderr:\n{}",
            fixture.filename,
            fixture.format,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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

    let output = Command::new(unzip)
        .arg("-t")
        .arg(&fixture)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "unzip failed for {}\nstdout:\n{}\nstderr:\n{}",
        fixture.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn optional_bsdtar_lists_common_libarchive_fixtures_when_available() {
    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };

    for filename in [
        "basic.tar.gz",
        "basic.tar.xz",
        "basic.tar.zst",
        "basic.cpio",
    ] {
        let fixture = archives_dir().join(filename);
        if !fixture.exists() {
            continue;
        }
        let output = Command::new(&bsdtar)
            .arg("-tf")
            .arg(&fixture)
            .output()
            .unwrap();

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

#[test]
fn zm_doctor_accepts_command_local_json_flag() {
    let output = Command::new(zm_path())
        .arg("doctor")
        .arg("--json")
        .output()
        .unwrap();
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf", &create);

    let list = Command::new(zm_path())
        .arg("-tf")
        .arg(&archive)
        .output()
        .unwrap();
    assert_success("zm -tf", &list);
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("README.md"), "{list_stdout}");
    assert!(list_stdout.contains("src/main.rs"), "{list_stdout}");

    let test = Command::new(zm_path())
        .arg("-Tf")
        .arg(&archive)
        .output()
        .unwrap();
    assert_success("zm -Tf", &test);

    let extract = Command::new(zm_path())
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm -xf", &extract);

    assert_eq!(
        fs::read_to_string(temp.path("out/project/README.md")).unwrap(),
        "hello"
    );
}

#[test]
fn zm_create_accepts_multiple_explicit_sources() {
    let temp = TestDir::new("zm_multiple_sources");
    fs::write(temp.path("README.md"), "readme").unwrap();
    fs::write(temp.path("LICENSE"), "license").unwrap();
    let archive = temp.path("release.zip");

    let output = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("README.md"))
        .arg(temp.path("LICENSE"))
        .output()
        .unwrap();
    assert_success("zm create multiple sources", &output);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
    assert_success("zm list --name-only", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("README.md"), "{stdout}");
    assert!(stdout.contains("LICENSE"), "{stdout}");
}

#[test]
fn zm_create_accepts_long_create_file_form() {
    let temp = TestDir::new("zm_long_create_file");
    fs::write(temp.path("file.txt"), "content").unwrap();
    let archive = temp.path("long.zip");

    let output = Command::new(zm_path())
        .arg("--create")
        .arg("--file")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert_success("zm --create --file", &output);

    let list = Command::new(zm_path())
        .arg("--list")
        .arg("--file")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
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

    let output = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("project"))
        .arg("src")
        .arg("README.md")
        .output()
        .unwrap();
    assert_success("zm -cf -C", &output);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
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

    let list = Command::new(zm_path())
        .arg("-tf")
        .arg(&archive)
        .output()
        .unwrap();
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
        write!(
            stdin,
            "{}\0{}\0",
            temp.path("a space.txt").display(),
            temp.path("b.txt").display()
        )
        .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_success("zm --files-from - --null", &output);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
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

    let first = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert_success("first zm -cf", &first);

    let second = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert!(
        !second.status.success(),
        "second create unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    let forced = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg("--force")
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
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

    let create = Command::new(zm_path())
        .arg("-jcf")
        .arg(&archive)
        .arg(temp.path("src/main.rs"))
        .arg(temp.path("docs/guide.md"))
        .output()
        .unwrap();
    assert_success("zm -jcf", &create);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
    assert_success("zm list junk archive", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("main.rs"), "{stdout}");
    assert!(stdout.contains("guide.md"), "{stdout}");
    assert!(!stdout.contains("src/main.rs"), "{stdout}");
    assert!(!stdout.contains("docs/guide.md"), "{stdout}");

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_test = Command::new(unzip)
        .arg("-t")
        .arg(&archive)
        .output()
        .unwrap();
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

    let output = Command::new(zm_path())
        .arg("-jcf")
        .arg(&archive)
        .arg(temp.path("src/config.json"))
        .arg(temp.path("test/config.json"))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "duplicate junk paths unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("duplicate junk path"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("src/config.json"), "stderr:\n{stderr}");
    assert!(stderr.contains("test/config.json"), "stderr:\n{stderr}");
    assert!(
        !archive.exists(),
        "failed create should not leave final archive"
    );
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

    let zip_output = Command::new(zip)
        .current_dir(&temp.root)
        .arg("-jq")
        .arg(&archive)
        .arg("src/main.rs")
        .arg("docs/guide.md")
        .output()
        .unwrap();
    assert_success("zip -j", &zip_output);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
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

    let create = Command::new(zm_path())
        .arg("-9cf")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert_success("zm -9cf", &create);

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_test = Command::new(unzip)
        .arg("-t")
        .arg(&archive)
        .output()
        .unwrap();
    assert_success("unzip -t zm -9 archive", &unzip_test);
}

#[test]
fn zm_create_and_extract_zip_preserves_unicode_paths() {
    let temp = TestDir::new("zm_unicode_zip_roundtrip");
    fs::create_dir_all(temp.path("project/数据")).unwrap();
    fs::write(temp.path("project/数据/emoji-😀.txt"), "unicode\n").unwrap();
    let archive = temp.path("unicode.zip");

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm create unicode zip", &create);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
    assert_success("zm list unicode zip", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("project/数据/emoji-😀.txt"), "{stdout}");

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract unicode zip", &extract);
    assert_eq!(
        fs::read_to_string(temp.path("out/project/数据/emoji-😀.txt")).unwrap(),
        "unicode\n"
    );
}

#[test]
fn zm_extract_zip_rejects_unicode_case_collision() {
    let temp = TestDir::new("zm_zip_unicode_case_collision");
    let archive = temp.path("unicode-collision.zip");
    write_zip_entries(
        &archive,
        CompressionMethod::Stored,
        &[("Über.txt", b"upper\n"), ("über.txt", b"lower\n")],
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();

    assert_failure("zm extract unicode collision zip", &extract);
    let stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(stderr.contains("collides with previous entry"), "{stderr}");
}

#[test]
fn zm_extract_zip_rejects_high_expansion_ratio_before_writing() {
    let temp = TestDir::new("zm_zip_expansion_ratio");
    let archive = temp.path("bomb.zip");
    let repeated = vec![0_u8; 8 * 1024 * 1024];
    write_zip_entries(
        &archive,
        CompressionMethod::Deflated,
        &[("bomb.bin", repeated.as_slice())],
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();

    assert_failure("zm extract high-ratio zip", &extract);
    let stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(
        stderr.contains("ratio limit"),
        "expected expansion-ratio failure\nstderr:\n{stderr}"
    );
    assert!(!temp.path("out/bomb.bin").exists());
    assert_no_zmanager_temp_files(&temp.path("out"));
}

#[test]
fn zm_create_tar_zst_level_round_trips_and_bsdtar_extracts_when_available() {
    let temp = TestDir::new("zm_tar_zst_level");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "zstd level\n").unwrap();
    let archive = temp.path("project.tar.zst");

    let create = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("project"))
        .arg("--level")
        .arg("1")
        .output()
        .unwrap();
    assert_success("zm create tar.zst --level 1", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-zm"))
        .output()
        .unwrap();
    assert_success("zm extract tar.zst level archive", &extract);
    assert_eq!(
        fs::read_to_string(temp.path("out-zm/project/file.txt")).unwrap(),
        "zstd level\n"
    );

    let Some(bsdtar) = find_on_path("bsdtar") else {
        return;
    };
    fs::create_dir_all(temp.path("out-bsdtar")).unwrap();
    let bsdtar_extract = Command::new(bsdtar)
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-bsdtar"))
        .output()
        .unwrap();
    assert_success("bsdtar -xf zm tar.zst level archive", &bsdtar_extract);
    assert_eq!(
        fs::read_to_string(temp.path("out-bsdtar/project/file.txt")).unwrap(),
        "zstd level\n"
    );
}

#[test]
fn zm_create_7z_level_round_trips_with_backend() {
    let temp = TestDir::new("zm_7z_level");
    fs::create_dir_all(temp.path("project")).unwrap();
    fs::write(temp.path("project/file.txt"), "7z level\n").unwrap();
    let archive = temp.path("project.7z");

    let create = Command::new(zm_path())
        .arg("create")
        .arg(&archive)
        .arg(temp.path("project"))
        .arg("--level")
        .arg("1")
        .output()
        .unwrap();
    assert_success("zm create 7z --level 1", &create);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--name-only")
        .output()
        .unwrap();
    assert_success("zm list 7z level archive", &list);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("project/file.txt"),
        "{}",
        String::from_utf8_lossy(&list.stdout)
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract 7z level archive", &extract);
    assert_eq!(
        fs::read_to_string(temp.path("out/project/file.txt")).unwrap(),
        "7z level\n"
    );
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf 7z for external 7zip", &create);

    let test = Command::new(sevenzip)
        .arg("t")
        .arg("-bd")
        .arg(&archive)
        .output()
        .unwrap();
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

    let create = Command::new(sevenzip)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-t7z")
        .arg("-bd")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("7zz a competitor 7z archive", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract 7zz-created archive", &extract);
    assert_eq!(
        fs::read_to_string(temp.path("out/project/file.txt")).unwrap(),
        "created by 7zip\n"
    );
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
    let create_tar = Command::new(&sevenzip)
        .current_dir(&temp.root)
        .arg("a")
        .arg("-ttar")
        .arg("-bd")
        .arg(&tar_archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("7zz a -ttar archive", &create_tar);

    assert_zm_extracts_7zip_tar_family_archive("7zz-created tar", &tar_archive, &temp);

    for (format, archive_name) in [("gzip", "project.tar.gz"), ("xz", "project.tar.xz")] {
        let compressed_archive = temp.path(archive_name);
        let create_compressed = Command::new(&sevenzip)
            .current_dir(&temp.root)
            .arg("a")
            .arg(format!("-t{format}"))
            .arg("-bd")
            .arg(&compressed_archive)
            .arg(&tar_archive)
            .output()
            .unwrap();
        assert_success(&format!("7zz a -t{format} archive"), &create_compressed);

        assert_zm_extracts_7zip_tar_family_archive(
            &format!("7zz-created {archive_name}"),
            &compressed_archive,
            &temp,
        );
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf follows symlink", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract followed symlink archive", &extract);

    let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
    assert!(
        metadata.is_file(),
        "followed symlink should extract as file"
    );
    assert_eq!(
        fs::read_to_string(temp.path("out/project/link.txt")).unwrap(),
        "target\n"
    );
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

    let create = Command::new(zm_path())
        .arg("-ycf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -ycf preserves symlink", &create);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--long")
        .output()
        .unwrap();
    assert_success("zm list preserved symlink", &list);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("symlink"),
        "{}",
        String::from_utf8_lossy(&list.stdout)
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract preserved symlink archive", &extract);

    let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "expected extracted symlink"
    );
    assert_eq!(
        fs::read_link(temp.path("out/project/link.txt")).unwrap(),
        PathBuf::from("target.txt")
    );
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

    let zip_output = Command::new(zip)
        .current_dir(&temp.root)
        .arg("-qry")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
    assert_success("zip -qry", &zip_output);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract competitor symlink zip", &extract);
    assert!(
        fs::symlink_metadata(temp.path("out/project/link.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "expected competitor symlink to extract as symlink"
    );
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

    let create = Command::new(zm_path())
        .arg("-ycf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -ycf tar.zst preserves symlink", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract tar.zst preserved symlink archive", &extract);
    assert!(
        fs::symlink_metadata(temp.path("out/project/link.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "expected tar.zst symlink to extract as symlink"
    );
}

#[cfg(unix)]
#[test]
fn zm_extract_tar_zst_materializes_safe_hardlink_entries() {
    use std::os::unix::fs::MetadataExt as _;

    let temp = TestDir::new("zm_tar_zst_hardlink_extract");
    let archive = temp.path("hardlink.tar.zst");
    write_tar_zst_with_hardlink(
        &archive,
        "project/target.txt",
        "project/hard.txt",
        b"hardlink payload\n",
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract tar.zst hardlink", &extract);

    let target = temp.path("out/project/target.txt");
    let hardlink = temp.path("out/project/hard.txt");
    assert_eq!(fs::read(&hardlink).unwrap(), b"hardlink payload\n");
    assert_eq!(
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&hardlink).unwrap().ino()
    );
}

#[cfg(unix)]
#[test]
fn zm_extract_libarchive_tar_materializes_safe_hardlink_entries() {
    use std::os::unix::fs::MetadataExt as _;

    let temp = TestDir::new("zm_tar_hardlink_extract");
    let archive = temp.path("hardlink.tar");
    write_tar_with_hardlink(
        &archive,
        "project/target.txt",
        "project/hard.txt",
        b"hardlink payload\n",
    );

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .output()
        .unwrap();
    assert_success("zm extract tar hardlink", &extract);

    let target = temp.path("out/project/target.txt");
    let hardlink = temp.path("out/project/hard.txt");
    assert_eq!(fs::read(&hardlink).unwrap(), b"hardlink payload\n");
    assert_eq!(
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&hardlink).unwrap().ino()
    );
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

    let output = Command::new(zm_path())
        .arg("-ycf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "7z preserve symlink unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("7z symlink preservation is not supported"),
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
    let zip_create = Command::new(zm_path())
        .arg("-Xcf")
        .arg(&zip_archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -Xcf zip", &zip_create);
    if let Some(unzip) = find_on_path("unzip") {
        let unzip_test = Command::new(unzip)
            .arg("-t")
            .arg(&zip_archive)
            .output()
            .unwrap();
        assert_success("unzip -t zm -X zip", &unzip_test);
    }

    let tar_zst_archive = temp.path("project.tar.zst");
    let tar_zst_create = Command::new(zm_path())
        .arg("-Xcf")
        .arg(&tar_zst_archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -Xcf tar.zst", &tar_zst_create);
    let tar_zst_extract = Command::new(zm_path())
        .arg("extract")
        .arg(&tar_zst_archive)
        .arg("-C")
        .arg(temp.path("out-tar-zst"))
        .output()
        .unwrap();
    assert_success("zm extract -X tar.zst", &tar_zst_extract);
    assert_eq!(
        fs::read_to_string(temp.path("out-tar-zst/project/file.txt")).unwrap(),
        "metadata\n"
    );

    let sevenz_archive = temp.path("project.7z");
    let sevenz_create = Command::new(zm_path())
        .arg("-Xcf")
        .arg(&sevenz_archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -Xcf 7z", &sevenz_create);
    let sevenz_extract = Command::new(zm_path())
        .arg("extract")
        .arg(&sevenz_archive)
        .arg("-C")
        .arg(temp.path("out-7z"))
        .output()
        .unwrap();
    assert_success("zm extract -X 7z", &sevenz_extract);
    assert_eq!(
        fs::read_to_string(temp.path("out-7z/project/file.txt")).unwrap(),
        "metadata\n"
    );
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

    let zip_output = Command::new(zip)
        .current_dir(&temp.root)
        .arg("-qr")
        .arg(&archive)
        .arg("project")
        .output()
        .unwrap();
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

    assert_eq!(
        fs::read_to_string(temp.path("out/keep.txt")).unwrap(),
        "keep\n"
    );
    assert!(!temp.path("out/drop.txt").exists());
    assert!(!temp.path("out/nested/deep.txt").exists());
}

#[test]
fn zm_extract_zip_honors_overwrite_policies() {
    let temp = TestDir::new("zm_extract_zip_overwrite");
    fs::write(temp.path("file.txt"), "archive\n").unwrap();
    let archive = temp.path("file.zip");
    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert_success("zm -cf overwrite fixture", &create);

    fs::create_dir_all(temp.path("out-never")).unwrap();
    fs::write(temp.path("out-never/file.txt"), "old\n").unwrap();
    let never = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-never"))
        .output()
        .unwrap();
    assert_failure("zm extract default overwrite refusal", &never);
    assert_eq!(
        fs::read_to_string(temp.path("out-never/file.txt")).unwrap(),
        "old\n"
    );

    fs::create_dir_all(temp.path("out-always")).unwrap();
    fs::write(temp.path("out-always/file.txt"), "old\n").unwrap();
    let always = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-always"))
        .arg("--overwrite")
        .arg("always")
        .output()
        .unwrap();
    assert_success("zm extract --overwrite always", &always);
    assert_eq!(
        fs::read_to_string(temp.path("out-always/file.txt")).unwrap(),
        "archive\n"
    );

    fs::create_dir_all(temp.path("out-rename")).unwrap();
    fs::write(temp.path("out-rename/file.txt"), "old\n").unwrap();
    let rename = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-rename"))
        .arg("--overwrite")
        .arg("rename")
        .output()
        .unwrap();
    assert_success("zm extract --overwrite rename", &rename);
    assert_eq!(
        fs::read_to_string(temp.path("out-rename/file.txt")).unwrap(),
        "old\n"
    );
    assert_eq!(
        fs::read_to_string(temp.path("out-rename/file (1).txt")).unwrap(),
        "archive\n"
    );

    let ask = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out-ask"))
        .arg("--overwrite")
        .arg("ask")
        .output()
        .unwrap();
    assert_failure("zm extract --overwrite ask without terminal", &ask);
}

#[cfg(unix)]
#[test]
fn zm_extract_overwrite_always_replaces_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("zm_extract_zip_overwrite_symlink");
    fs::write(temp.path("file.txt"), "archive\n").unwrap();
    let archive = temp.path("file.zip");
    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("file.txt"))
        .output()
        .unwrap();
    assert_success("zm -cf symlink overwrite fixture", &create);

    fs::create_dir_all(temp.path("out")).unwrap();
    fs::write(temp.path("outside.txt"), "outside\n").unwrap();
    symlink(temp.path("outside.txt"), temp.path("out/file.txt")).unwrap();

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(temp.path("out"))
        .arg("--overwrite")
        .arg("always")
        .output()
        .unwrap();
    assert_success("zm extract --overwrite always over symlink", &extract);

    assert!(
        fs::symlink_metadata(temp.path("out/file.txt"))
            .unwrap()
            .file_type()
            .is_file(),
        "expected symlink path to become a regular file"
    );
    assert_eq!(
        fs::read_to_string(temp.path("out/file.txt")).unwrap(),
        "archive\n"
    );
    assert_eq!(
        fs::read_to_string(temp.path("outside.txt")).unwrap(),
        "outside\n"
    );
}

#[test]
fn zm_extract_tar_zst_honors_filters_and_strip_components() {
    let temp = TestDir::new("zm_extract_tar_zst_filters");
    fs::create_dir_all(temp.path("project/nested")).unwrap();
    fs::write(temp.path("project/keep.txt"), "keep\n").unwrap();
    fs::write(temp.path("project/drop.txt"), "drop\n").unwrap();
    fs::write(temp.path("project/nested/deep.txt"), "deep\n").unwrap();
    let archive = temp.path("project.tar.zst");

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
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

    assert_eq!(
        fs::read_to_string(temp.path("out/deep.txt")).unwrap(),
        "deep\n"
    );
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
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

    assert_eq!(
        fs::read_to_string(temp.path("out/deep.txt")).unwrap(),
        "deep\n"
    );
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf zip test filter fixture", &create);

    let test = Command::new(zm_path())
        .arg("test")
        .arg(&archive)
        .arg("--include")
        .arg("project/keep.txt")
        .arg("--json")
        .output()
        .unwrap();
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
        let create = Command::new(zm_path())
            .arg("-cf")
            .arg(&archive)
            .arg(temp.path("project"))
            .output()
            .unwrap();
        assert_success("zm -cf non-zip test filter fixture", &create);

        let test = Command::new(zm_path())
            .arg("test")
            .arg(&archive)
            .arg("--include")
            .arg("project/keep.txt")
            .arg("--json")
            .output()
            .unwrap();
        assert_success("zm test non-zip --include --json", &test);
        let stdout = String::from_utf8_lossy(&test.stdout);
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

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf zip stdout fixture", &create);

    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(&archive)
        .arg("--to-stdout")
        .arg("--include")
        .arg("project/keep.txt")
        .output()
        .unwrap();
    assert_success("zm extract zip --to-stdout", &extract);
    assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
    assert!(
        extract.stderr.is_empty(),
        "stderr should stay quiet unless verbose/error:\n{}",
        String::from_utf8_lossy(&extract.stderr)
    );

    let Some(unzip) = find_on_path("unzip") else {
        return;
    };
    let unzip_output = Command::new(unzip)
        .arg("-p")
        .arg(&archive)
        .arg("project/keep.txt")
        .output()
        .unwrap();
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
        let create = Command::new(zm_path())
            .arg("-cf")
            .arg(&archive)
            .arg(temp.path("project"))
            .output()
            .unwrap();
        assert_success("zm -cf non-zip stdout fixture", &create);

        let extract = Command::new(zm_path())
            .arg("extract")
            .arg(&archive)
            .arg("--to-stdout")
            .arg("--include")
            .arg("project/keep.txt")
            .output()
            .unwrap();
        assert_success("zm extract non-zip --to-stdout", &extract);
        assert_eq!(String::from_utf8_lossy(&extract.stdout), "keep\n");
        assert!(
            extract.stderr.is_empty(),
            "stderr should stay quiet unless verbose/error:\n{}",
            String::from_utf8_lossy(&extract.stderr)
        );
    }
}

#[test]
fn zm_list_tree_prints_hierarchical_archive_paths() {
    let temp = TestDir::new("zm_list_tree");
    fs::create_dir_all(temp.path("project/src")).unwrap();
    fs::write(temp.path("project/README.md"), "readme\n").unwrap();
    fs::write(temp.path("project/src/main.rs"), "fn main() {}\n").unwrap();
    let archive = temp.path("project.zip");

    let create = Command::new(zm_path())
        .arg("-cf")
        .arg(&archive)
        .arg(temp.path("project"))
        .output()
        .unwrap();
    assert_success("zm -cf tree fixture", &create);

    let list = Command::new(zm_path())
        .arg("list")
        .arg(&archive)
        .arg("--tree")
        .output()
        .unwrap();
    assert_success("zm list --tree", &list);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("project/"), "{stdout}");
    assert!(stdout.contains("  README.md"), "{stdout}");
    assert!(stdout.contains("  src/"), "{stdout}");
    assert!(stdout.contains("    main.rs"), "{stdout}");
}

#[test]
fn zm_global_modes_validate_values_and_do_not_break_json() {
    let valid = Command::new(zm_path())
        .arg("--color")
        .arg("never")
        .arg("--progress")
        .arg("never")
        .arg("doctor")
        .arg("--json")
        .output()
        .unwrap();
    assert_success("zm global color/progress modes", &valid);
    assert!(
        String::from_utf8_lossy(&valid.stdout).contains("\"ready\":true"),
        "{}",
        String::from_utf8_lossy(&valid.stdout)
    );

    let invalid = Command::new(zm_path())
        .arg("--color")
        .arg("sometimes")
        .arg("doctor")
        .output()
        .unwrap();
    assert_failure("zm --color invalid value", &invalid);
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("invalid value for --color"),
        "{}",
        String::from_utf8_lossy(&invalid.stderr)
    );
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
    assert_eq!(
        fs::read_to_string(temp.path("out/secret.txt")).unwrap(),
        "secret\n"
    );

    let test = Command::new(zm_path())
        .arg("--no-password-prompt")
        .arg("test")
        .arg(&archive)
        .output()
        .unwrap();
    assert_failure("zm --no-password-prompt test encrypted zip", &test);
    assert!(
        String::from_utf8_lossy(&test.stderr).contains("prompts are disabled"),
        "{}",
        String::from_utf8_lossy(&test.stderr)
    );
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

    assert!(
        !fixtures.is_empty(),
        "fixture manifest is empty: {}",
        manifest_path.display()
    );
    for fixture in &fixtures {
        assert!(
            fixture.path().exists(),
            "missing fixture archive: {}",
            fixture.path().display()
        );
        assert_eq!(
            sha256_hex(&fixture.path()),
            fixture.sha256,
            "fixture checksum drifted: {}",
            fixture.filename
        );
        assert!(
            fixture.password.is_none(),
            "password-protected fixtures are not wired into generic CLI tests yet: {}",
            fixture.filename
        );
    }

    fixtures
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

fn zm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zm"))
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(label: &str, output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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

#[cfg(unix)]
fn write_tar_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
    let file = File::create(path).unwrap();
    write_tar_hardlink_entries(file, target_path, link_path, contents);
}

#[cfg(unix)]
fn write_tar_zst_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
    let file = File::create(path).unwrap();
    let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
    let encoder = write_tar_hardlink_entries(encoder, target_path, link_path, contents);
    encoder.finish().unwrap();
}

#[cfg(unix)]
fn write_tar_hardlink_entries<W: std::io::Write>(
    writer: W,
    target_path: &str,
    link_path: &str,
    contents: &[u8],
) -> W {
    let mut builder = tar::Builder::new(writer);

    let mut file_header = tar::Header::new_gnu();
    file_header.set_entry_type(tar::EntryType::Regular);
    file_header.set_size(contents.len().try_into().unwrap());
    file_header.set_mode(0o644);
    file_header.set_mtime(0);
    file_header.set_cksum();
    builder
        .append_data(&mut file_header, target_path, contents)
        .unwrap();

    let mut link_header = tar::Header::new_gnu();
    link_header.set_entry_type(tar::EntryType::Link);
    link_header.set_size(0);
    link_header.set_mode(0o644);
    link_header.set_mtime(0);
    link_header.set_cksum();
    builder
        .append_link(&mut link_header, link_path, Path::new(target_path))
        .unwrap();

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
        assert!(
            !name.to_string_lossy().starts_with(".zmanager-"),
            "temporary output file was left behind: {}",
            path.display()
        );
        if path.is_dir() {
            assert_no_zmanager_temp_files(&path);
        }
    }
}

fn archives_dir() -> PathBuf {
    repo_root().join("fixtures/archives")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

fn find_7zip() -> Option<PathBuf> {
    find_on_path("7zz").or_else(|| find_on_path("7z"))
}

fn assert_zm_extracts_7zip_tar_family_archive(label: &str, archive: &Path, temp: &TestDir) {
    let output_dir_name = format!(
        "out-{}",
        archive
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("archive")
            .replace('.', "-")
    );
    let extract = Command::new(zm_path())
        .arg("extract")
        .arg(archive)
        .arg("-C")
        .arg(temp.path(output_dir_name))
        .output()
        .unwrap();
    assert_success(&format!("zm extract {label}"), &extract);
    assert_eq!(
        fs::read_to_string(temp.path(format!(
                "out-{}/project/file.txt",
                archive
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("archive")
                    .replace('.', "-")
            )))
        .unwrap(),
        "created by 7zip tar\n"
    );
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
