//! Reproducible planning performance benchmark.
//!
//! Creates a temporary directory with 100,000 entries (90 % regular files,
//! 10 % directories / symlinks) and measures planning elapsed time.
//!
//! Run with:
//!   cargo test -p zmanager-core plan_benchmark --release -- --nocapture --ignored
//!
//! The test is `#[ignore]` by default because it creates 100,000 files and
//! takes several seconds. Use `--release` for representative timings.
//!
//! ## Performance budget (from the unified-table-columns ADR)
//!
//! - Median elapsed-time regression ≤ 20 % vs the safe-base baseline
//! - Additional peak resident memory ≤ 128 MiB
//! - Bounded identity caches: 4,096 entries, 4 concurrent lookups, 4,096
//!   distinct identities per plan, 250 ms per-lookup deadline

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::manifest::{PlanOptions, plan_archive};

// ---------------------------------------------------------------------------
// Benchmark fixture parameters
// ---------------------------------------------------------------------------

/// Total planned entries.
const ENTRY_COUNT: usize = 100_000;

/// Portion that are regular files.
const FILE_FRACTION: f64 = 0.90;

/// Portion that are directories.
const DIR_FRACTION: f64 = 0.08;

/// Portion that are symlinks.
const SYMLINK_FRACTION: f64 = 0.02;

/// Number of warm-up runs before measured runs.
const WARMUP_RUNS: usize = 1;

/// Number of measured runs.
const MEASURED_RUNS: usize = 3;

// ---------------------------------------------------------------------------
// Fixture creation
// ---------------------------------------------------------------------------

struct BenchmarkFixture {
    root: PathBuf,
}

impl BenchmarkFixture {
    /// Create the fixture directory tree with the configured entry counts.
    fn create() -> io::Result<Self> {
        let root = std::env::temp_dir().join(format!("zmanager-bench-{}", std::process::id()));
        fs::create_dir_all(&root)?;

        let file_count = (ENTRY_COUNT as f64 * FILE_FRACTION) as usize;
        let dir_count = (ENTRY_COUNT as f64 * DIR_FRACTION) as usize;
        let symlink_count = ENTRY_COUNT - file_count - dir_count;

        eprintln!(
            "Creating benchmark fixture: {} files, {} dirs, {} symlinks ({} total)",
            file_count, dir_count, symlink_count, ENTRY_COUNT
        );

        // Create all entries inside a single level to keep traversal simple.
        // Use subdirectories to avoid a single directory with 100,000 entries
        // (which would be slow to create and unrealistic).
        let shard_count = 100;
        let entries_per_shard = ENTRY_COUNT / shard_count;

        for shard in 0..shard_count {
            let shard_dir = root.join(format!("s{:03}", shard));
            fs::create_dir_all(&shard_dir)?;

            let file_in_shard = (entries_per_shard as f64 * FILE_FRACTION) as usize;
            let dir_in_shard = (entries_per_shard as f64 * DIR_FRACTION) as usize;
            let symlink_in_shard = entries_per_shard - file_in_shard - dir_in_shard;

            for i in 0..file_in_shard {
                let path = shard_dir.join(format!("f{:06}.txt", i));
                let mut f = File::create(&path)?;
                // Write a small amount of data so files have non-zero size
                writeln!(f, "benchmark entry {}", i)?;
            }

            for i in 0..dir_in_shard {
                let path = shard_dir.join(format!("d{:06}", i));
                fs::create_dir_all(&path)?;
            }

            // Symlinks: link to existing regular files in the same shard
            #[cfg(unix)]
            for i in 0..symlink_in_shard {
                let link_path = shard_dir.join(format!("l{:06}.lnk", i));
                // Target: the first regular file in this shard (always exists)
                let target = format!("f{:06}.txt", i % file_in_shard.max(1));
                let _ = std::os::unix::fs::symlink(&target, &link_path);
            }

            // On non-Unix, symlinks aren't supported — create extra files instead
            #[cfg(not(unix))]
            for i in 0..symlink_in_shard {
                let path = shard_dir.join(format!("x{:06}.txt", i));
                let mut f = File::create(&path)?;
                writeln!(f, "fallback entry {}", i)?;
            }
        }

        eprintln!("Fixture created at {}", root.display());
        Ok(Self { root })
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for BenchmarkFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Measurement helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Measurement {
    duration: Duration,
}

fn run_plan(root: &Path) -> Result<Measurement, String> {
    let start = Instant::now();
    let manifest = plan_archive(root, &PlanOptions::default())
        .map_err(|e| format!("plan_archive failed: {e}"))?;
    let elapsed = start.elapsed();

    // Sanity check: must have planned the expected number of entries
    // (allow small variance from shard rounding)
    let expected_min = ENTRY_COUNT - 200;
    let expected_max = ENTRY_COUNT + 200;
    assert!(
        manifest.entries.len() >= expected_min && manifest.entries.len() <= expected_max,
        "unexpected entry count: {} (expected {}-{})",
        manifest.entries.len(),
        expected_min,
        expected_max,
    );

    Ok(Measurement { duration: elapsed })
}

fn report_measurements(label: &str, measurements: &[Measurement]) {
    let mut durations: Vec<f64> = measurements
        .iter()
        .map(|m| m.duration.as_secs_f64())
        .collect();
    durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let median = durations[durations.len() / 2];
    let min = durations.first().unwrap();
    let max = durations.last().unwrap();
    let mean = durations.iter().sum::<f64>() / durations.len() as f64;

    println!(
        "{label}: median {median:.3}s  mean {mean:.3}s  min {min:.3}s  max {max:.3}s  ({} runs)",
        measurements.len(),
    );

    // Record for the build verification matrix
    println!("BENCH_RESULT {label} median_seconds={median:.3} mean_seconds={mean:.3}");
}

// ---------------------------------------------------------------------------
// Benchmark test
// ---------------------------------------------------------------------------

/// Entry-count sanity fixtures (fast, always run).
#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[test]
    fn benchmark_fixture_counts_are_consistent() {
        let file_count = (ENTRY_COUNT as f64 * FILE_FRACTION) as usize;
        let dir_count = (ENTRY_COUNT as f64 * DIR_FRACTION) as usize;
        let symlink_count = ENTRY_COUNT - file_count - dir_count;
        assert_eq!(file_count + dir_count + symlink_count, ENTRY_COUNT);
        assert!(file_count > dir_count, "files should dominate");
        assert!(symlink_count < dir_count, "symlinks are the minority");
    }

    #[test]
    fn benchmark_creates_and_plans_small_fixture() {
        // Verify the benchmark infrastructure works with a tiny fixture
        let root = std::env::temp_dir().join(format!("zmanager-bench-tiny-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();

        let sub = root.join("test");
        fs::create_dir_all(&sub).unwrap();
        for i in 0..10 {
            let path = sub.join(format!("f{:03}.txt", i));
            let mut f = File::create(&path).unwrap();
            writeln!(f, "entry {}", i).unwrap();
        }
        // Create a symlink
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("f000.txt", sub.join("link.lnk"));
        }

        let manifest = plan_archive(&root, &PlanOptions::default()).unwrap();
        assert!(
            manifest.entries.len() > 0,
            "should have planned some entries"
        );
        eprintln!("Small fixture: {} entries planned", manifest.entries.len());

        fs::remove_dir_all(&root).unwrap();
    }
}

/// Full-scale benchmark. Ignored by default — run with `--ignored`.
#[test]
#[ignore]
fn plan_benchmark_100k_entries() {
    let fixture = BenchmarkFixture::create().expect("failed to create benchmark fixture");

    // Warm-up
    eprintln!("Warm-up run...");
    let _ = run_plan(fixture.root()).expect("warm-up plan failed");

    // Measured runs
    let mut measurements = Vec::with_capacity(MEASURED_RUNS);
    for i in 0..MEASURED_RUNS {
        eprintln!("Measured run {}/{}...", i + 1, MEASURED_RUNS);
        let m = run_plan(fixture.root()).expect("measured plan failed");
        measurements.push(m);
    }

    report_measurements("plan_100k_safe_base", &measurements);

    // Regression guard: first measured run serves as the baseline.
    // Subsequent WP6 metadata slices should not regress beyond 20 %.
    // This is a self-consistency check — real regression tests compare
    // against the safe-base baseline established here.
    let median = {
        let mut d: Vec<f64> = measurements
            .iter()
            .map(|m| m.duration.as_secs_f64())
            .collect();
        d.sort_by(|a, b| a.partial_cmp(b).unwrap());
        d[d.len() / 2]
    };

    // Document the baseline
    println!("BASELINE plan_100k_safe_base median_seconds={median:.3}  entry_count={ENTRY_COUNT}");

    // The benchmark itself should complete in a reasonable time
    // (upper bound to catch unintentional O(n²) regressions)
    assert!(
        median < 120.0,
        "planning 100k entries took {median:.1}s — exceeds 120s upper bound"
    );
}
