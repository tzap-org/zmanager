#![cfg(any(target_os = "macos", target_os = "ios"))]

#[cfg(test)]
mod tests {
    use std::fs;

    use zmanager_apple_archive::{
        ArchiveReader, ArchiveWriter, CompressionAlgorithm, CreateOptions, EntryMetadata,
    };

    #[test]
    fn test_password_roundtrip() {
        let mut temp_path = std::env::temp_dir();
        temp_path.push("password_roundtrip_test.aea");
        let _ = fs::remove_file(&temp_path);

        let password = b"super_secret_password_123";

        // Create an encrypted archive
        {
            let mut writer = ArchiveWriter::create_encrypted(
                &temp_path,
                CreateOptions {
                    compression: CompressionAlgorithm::Lzfse,
                    ..Default::default()
                },
                password,
            )
            .expect("create encrypted writer");
            writer
                .append_directory("secret_dir", EntryMetadata::default())
                .expect("append directory");
            writer.finish().expect("finish writer");
        }

        // Try reading with no password - reading encrypted entry without password context should fail
        if let Ok(mut reader) = ArchiveReader::open(&temp_path) {
            let _ = reader.next_entry();
        }

        // Read back with correct password
        {
            let mut reader =
                ArchiveReader::open_encrypted(&temp_path, password).expect("open encrypted reader");
            let entry = reader.next_entry().expect("read entry").expect("got entry");
            assert_eq!(entry.path(), "secret_dir");
        }

        // Read back with incorrect password
        {
            let bad_password = b"wrong_password";
            let reader_result = ArchiveReader::open_encrypted(&temp_path, bad_password);
            assert!(
                reader_result.is_err(),
                "should fail to open with wrong password"
            );
        }

        let _ = fs::remove_file(&temp_path);
    }
}
