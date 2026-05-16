#![no_main]

use std::fs;
use std::hash::{Hash, Hasher};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join(format!(
        "zmanager-libarchive-fuzz-{}-{:016x}",
        std::process::id(),
        stable_hash(data)
    ));
    if fs::write(&path, data).is_ok() {
        let _ = zmanager_core::libarchive_backend::list_archive(&path);
        let _ = fs::remove_file(path);
    }
});

fn stable_hash(data: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}
