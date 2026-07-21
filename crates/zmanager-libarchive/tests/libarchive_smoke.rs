use std::path::{Path, PathBuf};

use zmanager_libarchive::{Error, FileType, ReadArchive};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/archives")
        .join(name)
}

#[test]
fn linked_libarchive_version_apis_are_available() {
    let version = zmanager_libarchive::version();
    assert!(version.contains("3."));

    let details = zmanager_libarchive::version_details();
    assert!(!details.is_empty());

    let number = zmanager_libarchive::version_number();
    assert!(number >= 3_008_008);
}

#[test]
fn opens_and_lists_entries_from_fixture_zip() {
    let fixture = fixture_path("basic.zip");
    let mut archive = ReadArchive::open(&fixture).expect("open basic.zip fixture");

    let mut saw_readme = false;
    let mut saw_dir = false;
    while let Some(entry) = archive
        .next_entry()
        .expect("advancing through fixture entries should be stable")
    {
        match entry.pathname().as_deref() {
            Some("payload/") => {
                saw_dir = true;
            }
            Some("payload/README.txt") => {
                saw_readme = true;
            }
            _ => {}
        }

        if entry.file_type() != FileType::RegularFile {
            archive
                .skip_data()
                .expect("skip_data should work for non-regular entries");
        }
    }

    assert!(saw_dir);
    assert!(saw_readme);
}

#[test]
fn reads_fixture_file_payload_contents() {
    let fixture = fixture_path("basic.zip");
    let mut archive = ReadArchive::open(&fixture).expect("open basic.zip fixture");

    while let Some(entry) = archive
        .next_entry()
        .expect("advancing through fixture entries should be stable")
    {
        let is_target_file = entry.pathname().as_deref() == Some("payload/README.txt");
        if !is_target_file {
            if entry.file_type() != FileType::RegularFile {
                archive
                    .skip_data()
                    .expect("skip_data should work for non-target entries");
            }
            continue;
        }

        let mut output = Vec::new();
        let mut buffer = [0_u8; 64];
        loop {
            let read = archive
                .read_data(&mut buffer)
                .expect("read_data should succeed");
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
        }

        assert_eq!(output, b"ZManager fixture payload\n");
        assert_eq!(entry.file_type(), FileType::RegularFile);
        return;
    }

    panic!("missing payload/README.txt entry in basic.zip");
}

#[test]
fn open_missing_archive_returns_archive_error() {
    let missing = fixture_path("missing.zip");
    let err = ReadArchive::open(&missing)
        .err()
        .expect("missing archive should return an error");

    match err {
        Error::Archive { .. } => {}
        other => panic!("unexpected error type: {other}"),
    }
}
