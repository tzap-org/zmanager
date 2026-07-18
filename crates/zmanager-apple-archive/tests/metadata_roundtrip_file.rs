//! Integration test to verify that portable metadata survives a full
//! archive round‑trip for every supported compression algorithm.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, SystemTime};

    use zmanager_apple_archive::{
        ArchiveReader, ArchiveWriter, CreateOptions, EntryMetadata, CompressionAlgorithm,
    };

    // Helper to create a temporary file path, write an archive, then read it back.
    fn roundtrip(metadata: EntryMetadata, algo: CompressionAlgorithm) -> EntryMetadata {
        // Create a temporary file in the OS temp directory.
        let mut temp_path = std::env::temp_dir();
        temp_path.push(format!("metadata_roundtrip_{:?}.aar", algo));
        // Ensure any previous file is removed.
        let _ = fs::remove_file(&temp_path);

        // Write archive to the temporary file.
        {
            let mut writer = ArchiveWriter::create(&temp_path, CreateOptions {
                compression: algo,
                ..Default::default()
            })
            .expect("create writer");
            writer
                .append_directory("test_dir", metadata)
                .expect("append directory");
            writer.finish().expect("finish writer");
        }
        // Read back from the file.
        let mut reader = ArchiveReader::open(&temp_path).expect("open reader");
        let entry = reader
            .next_entry()
            .expect("read entry")
            .expect("got entry");
        // Clean up the temporary file.
        let _ = fs::remove_file(&temp_path);
        entry.metadata()
    }

    #[test]
    fn test_metadata_roundtrip_all_algorithms() {
        // Populate every optional field with deterministic data.
        let test_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let original = EntryMetadata {
            mode: Some(0o644),
            modified: Some(test_time),
        };
        for algo in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Lz4,
            CompressionAlgorithm::Zlib,
            CompressionAlgorithm::Lzma,
            CompressionAlgorithm::Lzfse,
            CompressionAlgorithm::Lzbitmap,
        ] {
            let round = roundtrip(original, algo);
            assert_eq!(original, round, "metadata mismatch for {algo:?}");
        }
    }
}
