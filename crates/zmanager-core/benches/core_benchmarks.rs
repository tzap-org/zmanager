//! Performance benchmark suite for `zmanager-core` (CR-177).
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::implicit_clone, clippy::collapsible_if)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zmanager_core::backend_test_support::gitignore::{GitignoreRule, gitignore_decision, parse_gitignore_rule};
use zmanager_core::backend_test_support::jobs::ProgressCoalescer;
use zmanager_core::engine::types::normalize_engine_path;
use zmanager_core::engine::{ArchiveSource, ExtractOptions, create_default_engine};
use zmanager_core::manifest::{ManifestFileType, PlanOptions, plan_archives};
use zmanager_core::safety::{ExtractionPolicy, OverwritePolicy, archive_pattern_matches, case_collision_key, normalize_archive_path};

static NEXT_BENCH_ID: AtomicU64 = AtomicU64::new(0);

/// Wall-clock ceiling for the pathological glob case. The iterative matcher
/// resolves it in microseconds; the bound is loose enough to absorb loaded-CI
/// jitter while still failing instantly on exponential backtracking.
const PATHOLOGICAL_GLOB_BUDGET: Duration = Duration::from_millis(10);

struct BenchDir {
    root: PathBuf,
}

impl BenchDir {
    fn new(label: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let id = NEXT_BENCH_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("zm-bench-{label}-{}-{now}-{id}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }

    fn create_dir(&self, relative: impl AsRef<Path>) {
        fs::create_dir_all(self.path(relative)).unwrap();
    }

    fn write_file(&self, relative: impl AsRef<Path>, contents: &[u8]) {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
}

impl Drop for BenchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn bench_glob_matching() {
    println!("\n=== Benchmark 1: Glob Matching ===");

    // Generate 1,000 synthetic paths
    let mut paths = Vec::with_capacity(1000);
    for dir_idx in 0..20 {
        for file_idx in 0..50 {
            paths.push(format!("src/module_{dir_idx}/submodule_{file_idx}/file_{file_idx}.rs"));
        }
    }

    // Generate pattern sets: 1, 10, 100
    let mut patterns_100 = Vec::with_capacity(100);
    patterns_100.push("*.rs".to_string());
    for i in 1..100 {
        patterns_100.push(format!("src/module_{i}/**/*.rs"));
    }
    let patterns_1 = &patterns_100[..1];
    let patterns_10 = &patterns_100[..10];

    for (count, pat_slice) in [(1, patterns_1), (10, patterns_10), (100, &patterns_100[..])] {
        let start = Instant::now();
        let iterations = 100;
        let mut match_count = 0;
        for _ in 0..iterations {
            for path in &paths {
                for pat in pat_slice {
                    if archive_pattern_matches(pat, path) {
                        match_count += 1;
                    }
                }
            }
        }
        let elapsed = start.elapsed();
        let per_op = elapsed / (iterations * paths.len() as u32 * count as u32);
        println!("archive_pattern_matches: 1k paths x {count:3} patterns x {iterations} iters: total {elapsed:?}, per match: {per_op:?}");
        std::hint::black_box(match_count);
    }

    // Gitignore rules benchmark: 1k paths against 1, 10, 100 rules
    let mut rules_100: Vec<GitignoreRule> = Vec::with_capacity(100);
    rules_100.push(parse_gitignore_rule("*.rs", "").unwrap());
    for i in 1..100 {
        rules_100.push(parse_gitignore_rule(&format!("target/debug/build_{i}/"), "").unwrap());
    }
    let rules_1 = &rules_100[..1];
    let rules_10 = &rules_100[..10];

    for (count, rule_slice) in [(1, rules_1), (10, rules_10), (100, &rules_100[..])] {
        let start = Instant::now();
        let iterations = 100;
        let mut decision_count = 0;
        for _ in 0..iterations {
            for path in &paths {
                if let Some((ignored, _)) = gitignore_decision(path, ManifestFileType::File, rule_slice) {
                    if ignored {
                        decision_count += 1;
                    }
                }
            }
        }
        let elapsed = start.elapsed();
        let per_op = elapsed / (iterations * paths.len() as u32);
        println!("gitignore_decision:      1k paths x {count:3} rules    x {iterations} iters: total {elapsed:?}, per decision: {per_op:?}");
        std::hint::black_box(decision_count);
    }

    // Pathological pattern check. The bound is the point of this case: the
    // recursive matcher CR-178 replaced took 75 s on 11 `*a` groups, so any
    // reintroduced backtracking fails the bench run rather than just printing a
    // slow number nobody reads.
    let pathological_pattern = format!("{}*b", "*a".repeat(15));
    let non_matching_path = "a".repeat(60) + "c";
    let start = Instant::now();
    let res = archive_pattern_matches(&pathological_pattern, &non_matching_path);
    let elapsed = start.elapsed();
    println!("pathological pattern (15x *a + *b): {elapsed:?} (result: {res})");
    assert!(!res);
    assert!(
        elapsed < PATHOLOGICAL_GLOB_BUDGET,
        "pathological glob took {elapsed:?}, over the {PATHOLOGICAL_GLOB_BUDGET:?} budget (CR-178 backtracking regression)"
    );
}

fn bench_path_normalization() {
    println!("\n=== Benchmark 2: Path Normalization ===");
    let sample_paths = [
        "simple/clean/path.txt",
        "src//nested/./dir/../../clean/path.rs",
        "windows\\style\\path\\to\\file.dat",
        "UPPERCASE_AND_lowercase/Mixed_Case/Path_With_Numbers_123.JSON",
        "adversarial/../../../../../../../etc/passwd",
        "unicode/path/with/café/and/naïve/file.txt",
    ];

    let iterations = 50_000;
    let start = Instant::now();
    for _ in 0..iterations {
        for path in sample_paths {
            let _ = std::hint::black_box(normalize_archive_path(path));
            let _ = std::hint::black_box(normalize_engine_path(path));
            let _ = std::hint::black_box(case_collision_key(path));
        }
    }
    let elapsed = start.elapsed();
    let total_ops = (iterations * sample_paths.len() * 3) as u32;
    println!("path normalization suite: {total_ops} ops: {elapsed:?}, per op: {:?}", elapsed / total_ops);
}

fn create_5k_files_fixture(dir: &BenchDir) {
    let payload = vec![0x42_u8; 512];
    for dir_idx in 0..50 {
        let dir_rel = format!("dir_{dir_idx:02}");
        dir.create_dir(&dir_rel);
        for file_idx in 0..100 {
            let file_rel = format!("{dir_rel}/file_{file_idx:03}.dat");
            dir.write_file(&file_rel, &payload);
        }
    }
}

fn create_5k_zip_fixture(zip_path: &Path) {
    let file = File::create(zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let payload = vec![0x42_u8; 512];
    for dir_idx in 0..50 {
        for file_idx in 0..100 {
            let name = format!("dir_{dir_idx:02}/file_{file_idx:03}.dat");
            zip.start_file(name, options).unwrap();
            zip.write_all(&payload).unwrap();
        }
    }
    zip.finish().unwrap();
}

fn create_5k_tar_fixture(tar_path: &Path) {
    let file = File::create(tar_path).unwrap();
    let mut tar = tar::Builder::new(file);
    let payload = vec![0x42_u8; 512];
    for dir_idx in 0..50 {
        for file_idx in 0..100 {
            let name = format!("dir_{dir_idx:02}/file_{file_idx:03}.dat");
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, &payload[..]).unwrap();
        }
    }
    tar.finish().unwrap();
}

fn bench_extract_small_files() {
    println!("\n=== Benchmark 3: Extract Small Files (5,000 entries, 512B each) ===");
    let temp = BenchDir::new("extract_small_files");
    let zip_path = temp.path("archive_5k.zip");
    let tar_path = temp.path("archive_5k.tar");

    println!("Creating 5k-entry fixtures...");
    create_5k_zip_fixture(&zip_path);
    create_5k_tar_fixture(&tar_path);

    let engine = create_default_engine().unwrap();

    // Benchmark ZIP extraction
    {
        let dest_dir = temp.path("dest_zip");
        fs::create_dir_all(&dest_dir).unwrap();
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(&zip_path), zmanager_core::engine::OpenOptions::default()).unwrap();

        let start = Instant::now();
        let mut options = ExtractOptions {
            destination: dest_dir.clone(),
            policy: ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            ..ExtractOptions::default()
        };
        let report = handle.extract(&mut options).unwrap();
        let elapsed = start.elapsed();
        println!("ZIP extract 5k files: {elapsed:?} ({} written, rate: {:.1} files/s)", report.written_entries, 5000.0 / elapsed.as_secs_f64());
        let _ = fs::remove_dir_all(&dest_dir);
    }

    // Benchmark TAR extraction
    {
        let dest_dir = temp.path("dest_tar");
        fs::create_dir_all(&dest_dir).unwrap();
        let mut handle = engine.open(ArchiveSource::from_path_autodetect(&tar_path), zmanager_core::engine::OpenOptions::default()).unwrap();

        let start = Instant::now();
        let mut options = ExtractOptions {
            destination: dest_dir.clone(),
            policy: ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            ..ExtractOptions::default()
        };
        let report = handle.extract(&mut options).unwrap();
        let elapsed = start.elapsed();
        println!("TAR extract 5k files: {elapsed:?} ({} written, rate: {:.1} files/s)", report.written_entries, 5000.0 / elapsed.as_secs_f64());
        let _ = fs::remove_dir_all(&dest_dir);
    }
}

fn bench_manifest_walk() {
    println!("\n=== Benchmark 4: Manifest Walk (5,000 files) ===");
    let temp = BenchDir::new("manifest_walk");
    println!("Creating 5k-file tree...");
    create_5k_files_fixture(&temp);

    // Write a .gitignore at root and in some subdirectories
    temp.write_file(".gitignore", b"*.tmp\n*.bak\n/dir_00/*.dat\n!/dir_00/file_000.dat\n");
    temp.write_file("dir_01/.gitignore", b"file_050.dat\nfile_051.dat\n");

    let source_dir = &temp.root;

    // 1. Without respect_gitignore
    {
        let options = PlanOptions { respect_gitignore: false, ..PlanOptions::default() };
        let start = Instant::now();
        let plan = plan_archives(std::slice::from_ref(source_dir), &options).unwrap();
        let elapsed = start.elapsed();
        println!("plan_archives (clean=false, 5k files): {elapsed:?} ({} entries)", plan.entries.len());
    }

    // 2. With respect_gitignore (gitignore active)
    {
        let options = PlanOptions { respect_gitignore: true, ..PlanOptions::default() };
        let start = Instant::now();
        let plan = plan_archives(std::slice::from_ref(source_dir), &options).unwrap();
        let elapsed = start.elapsed();
        println!("plan_archives (clean=true,  5k files): {elapsed:?} ({} entries)", plan.entries.len());
    }
}

fn bench_progress_coalescer() {
    println!("\n=== Benchmark 5: Progress Coalescer (1 GB at 128 KiB chunks) ===");
    let chunks = 8192; // 8192 * 128 KiB = 1 GiB
    let path = "some/very/long/archive/path/to/a/source/file/in/a/deep/hierarchy/large_file.bin";

    let start = Instant::now();
    let iterations = 10;
    for _ in 0..iterations {
        let mut coalescer = ProgressCoalescer::new(Some(1024 * 1024 * 1024));
        let mut batches = 0;
        for _ in 0..chunks {
            if coalescer.record(Some(path), 128 * 1024).is_some() {
                batches += 1;
            }
        }
        if coalescer.flush().is_some() {
            batches += 1;
        }
        std::hint::black_box(batches);
    }
    let elapsed = start.elapsed();
    let total_chunks = (iterations * chunks) as u32;
    println!("progress coalescer: {total_chunks} 128KiB chunks: {elapsed:?}, per chunk: {:?}", elapsed / total_chunks);
}

fn bench_indexed_selection_and_source_reopening() {
    println!("\n=== Benchmark 6: Indexed Selection and Source Reopening ===");
    let temp = BenchDir::new("indexed_selection");
    let tar_path = temp.path("archive_5k.tar");
    create_5k_tar_fixture(&tar_path);
    let engine = create_default_engine().unwrap();

    // One retained session exercises the normal selected-entry path: the
    // handle resolves each public EntryId through the adapter's retained
    // index, then the source cursor factory reopens the underlying file for
    // the operation. This is the hot path used by preview/copy callers.
    let mut retained_handle = engine.open(ArchiveSource::from_path_autodetect(&tar_path), zmanager_core::engine::OpenOptions::default()).unwrap();
    let listing = retained_handle.list().unwrap();
    let selected_ids: Vec<_> = listing.entries.iter().take(256).map(|entry| entry.id).collect();
    let start = Instant::now();
    let mut retained_bytes = 0_u64;
    for entry_id in &selected_ids {
        retained_bytes += retained_handle.copy_entry(*entry_id, &mut io::sink()).unwrap().written_bytes;
    }
    let retained_elapsed = start.elapsed();
    println!("retained session: {} indexed selections with source cursors reopened: {retained_elapsed:?} ({retained_bytes} bytes)", selected_ids.len());

    // This deliberately heavier comparison reopens and relists the archive
    // for every selected entry. It gives the source-reopening cost a visible
    // baseline without pretending that a microbenchmark can prove global
    // optimality across every native backend.
    let start = Instant::now();
    let mut reopened_bytes = 0_u64;
    for _ in &selected_ids {
        let mut reopened_handle = engine.open(ArchiveSource::from_path_autodetect(&tar_path), zmanager_core::engine::OpenOptions::default()).unwrap();
        let reopened_listing = reopened_handle.list().unwrap();
        let entry_id = reopened_listing.entries[0].id;
        reopened_bytes += reopened_handle.copy_entry(entry_id, &mut io::sink()).unwrap().written_bytes;
    }
    let reopened_elapsed = start.elapsed();
    println!("reopen per selection: {} source opens + listings: {reopened_elapsed:?} ({reopened_bytes} bytes)", selected_ids.len());
    assert!(retained_bytes > 0);
    assert!(reopened_bytes > 0);
}

fn main() {
    println!("Running ZManager Core Performance Benchmarks (CR-177)...");
    bench_glob_matching();
    bench_path_normalization();
    bench_extract_small_files();
    bench_manifest_walk();
    bench_progress_coalescer();
    bench_indexed_selection_and_source_reopening();
    println!("\nAll benchmarks completed successfully.");
}
