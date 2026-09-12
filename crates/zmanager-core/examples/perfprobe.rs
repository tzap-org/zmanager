//! TEMPORARY verification probe - delete after measuring.
use std::path::Path;
use std::time::Instant;
use zmanager_core::archive_browser::{BrowserExtractOptions, extract_entry_with_options};

fn main() {
    let base = std::env::args().nth(1).unwrap();
    for name in ["dir.cpio", "dir.cpio.gz", "big.tzap"] {
        let archive = format!("{base}/{name}");
        if !Path::new(&archive).exists() { continue; }
        let dest = std::env::temp_dir().join(format!("zm-v-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let start = Instant::now();
        match extract_entry_with_options(Path::new(&archive), "payload", &dest, BrowserExtractOptions::default()) {
            Ok(r) => {
                // verify the extracted bytes are actually all there
                let n = std::fs::read_dir(dest.join("payload")).map(|d| d.count()).unwrap_or(0);
                println!("{name:<14} {:>10.2?}  bytes={} files_on_disk={}", start.elapsed(), r.written_bytes, n);
            }
            Err(e) => println!("{name:<14} ERR {e}"),
        }
        let _ = std::fs::remove_dir_all(&dest);
    }
}
