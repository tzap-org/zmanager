//! Integration test to verify that portable metadata survives a full
//! archive round‑trip for every supported compression algorithm.

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::{Duration, SystemTime};

    use zmanager_apple_archive::{
        ArchiveReader, ArchiveWriter, CreateOptions, EntryMetadata, CompressionAlgorithm,
    };

    // Helper to create a temporary in‑memory archive.
    fn roundtrip(metadata: EntryMetadata, algo: CompressionAlgorithm) -> EntryMetadata {
        // Write archive to a byte buffer.
        let mut buffer = Vec::new();
        {
            let mut writer = ArchiveWriter::create(
                Cursor::new(&mut buffer),
                CreateOptions {
                    compression: algo,
                    ..Default::default()
                },
            )
            .expect("create writer");
            writer
                .append_directory("test_dir", metadata)
                .expect("append directory");
            writer.finish().expect("finish writer");
        }
        // Read back.
        let mut reader = ArchiveReader::open(Cursor::new(&buffer)).expect("open reader");
        let entry = reader
            .next_entry()
            .expect("read entry")
            .expect("got entry");
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
