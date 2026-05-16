#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zip::{ZipArchive, ZipReadOptions};

fuzz_target!(|data: &[u8]| {
    let cursor = Cursor::new(data);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return;
    };

    let limit = archive.len().min(64);
    for index in 0..limit {
        {
            let Ok(file) = archive.by_index_raw(index) else {
                continue;
            };
            let _ = file.name();
            let _ = file.size();
            let _ = file.compressed_size();
            let _ = file.is_dir();
            let _ = file.is_symlink();
        }

        let _ = archive.by_index_with_options(index, ZipReadOptions::new());
    }
});
