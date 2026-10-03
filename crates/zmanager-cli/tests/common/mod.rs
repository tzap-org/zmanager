//! Shared helpers for the CLI's integration tests.
//!
//! `tests/common/mod.rs` is not compiled as its own test binary; each
//! integration test that needs these helpers declares `mod common;`.

#![allow(dead_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

/// A uniquely named temporary directory that removes itself on drop.
pub struct TestDir {
    root: PathBuf,
}

impl TestDir {
    /// Creates a fresh, uniquely named directory under the system temp dir.
    pub fn new(label: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = env::temp_dir().join(format!("zmanager-{label}-{}-{now}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    /// Returns the test directory root itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves a path relative to the test directory root.
    pub fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Cargo's binary for the current target/profile, or an explicit artifact audit.
pub fn zm_path() -> PathBuf {
    env::var_os("ZMANAGER_AUDIT_BINARY").map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_zm")), PathBuf::from)
}

/// Asserts that a command invocation succeeded, dumping stdout/stderr on failure.
pub fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Asserts that a command invocation failed, dumping stdout/stderr on success.
pub fn assert_failure(label: &str, output: &Output) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Removes ANSI escape sequences from a string.
pub fn strip_ansi(input: &str) -> String {
    let mut stripped = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            stripped.push(ch);
        }
    }
    stripped
}

/// Searches `PATH` for an executable with the given name.
pub fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(binary)).find(|candidate| candidate.is_file())
}

/// Asserts that a file is only readable/writable by its owner (mode 0600).
#[cfg(unix)]
pub fn assert_owner_only_file(path: PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// No-op on platforms without Unix permission bits.
#[cfg(not(unix))]
pub fn assert_owner_only_file(_path: PathBuf) {}

/// Apple tools drop `._` `AppleDouble` companion entries during extraction
/// (pkgutil --expand-full, ditto), while zm materializes them as regular
/// files (fidelity-first, like tar). Filter them on both sides so the
/// cross-tool comparison asserts the payload content is identical modulo
/// that known, documented divergence.
pub fn is_apple_double(rel: &Path) -> bool {
    rel.file_name().is_some_and(|name| name.to_string_lossy().starts_with("._"))
}

/// Recursively collects the relative paths of every entry under `root`,
/// skipping `AppleDouble` (`._`) entries and anything `skip` rejects.
pub fn collect_tree_entries_filtered(root: &Path, skip: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(dir) = stack.pop() {
        let mut children = fs::read_dir(root.join(&dir)).unwrap().map(|entry| entry.unwrap().path()).collect::<Vec<_>>();
        children.sort();
        for child in children {
            let rel = dir.join(child.file_name().unwrap());
            if is_apple_double(&rel) || skip(&rel) {
                continue;
            }
            entries.push(rel.clone());
            if fs::symlink_metadata(&child).unwrap().is_dir() {
                stack.push(rel);
            }
        }
    }
    entries
}

/// Recursively collects the relative paths of every entry under `root`.
pub fn collect_tree_entries(root: &Path) -> Vec<PathBuf> {
    collect_tree_entries_filtered(root, |_| false)
}

/// Asserts `actual` matches `expected` entry-for-entry: same tree shape,
/// byte-identical file contents, identical symlink targets.
pub fn assert_trees_match(label: &str, expected: &Path, actual: &Path) {
    assert_trees_match_filtered(label, expected, actual, |_| false);
}

/// Asserts `actual` matches `expected` entry-for-entry: same tree shape,
/// byte-identical file contents, identical symlink targets. Entries `skip`
/// rejects are ignored on both sides (documented divergences between zm and
/// the reference tool).
pub fn assert_trees_match_filtered(label: &str, expected: &Path, actual: &Path, skip: impl Fn(&Path) -> bool) {
    let expected_entries = collect_tree_entries_filtered(expected, &skip);
    let actual_entries = collect_tree_entries_filtered(actual, &skip);

    for rel in &expected_entries {
        let actual_path = actual.join(rel);
        assert!(fs::symlink_metadata(&actual_path).is_ok(), "{label}: zm output is missing {}", rel.display());
        let expected_meta = fs::symlink_metadata(expected.join(rel)).unwrap();
        let actual_meta = fs::symlink_metadata(&actual_path).unwrap();
        assert_eq!(expected_meta.is_symlink(), actual_meta.is_symlink(), "{label}: type mismatch for {}", rel.display());
        if expected_meta.is_symlink() {
            assert_eq!(
                fs::read_link(expected.join(rel)).unwrap(),
                fs::read_link(&actual_path).unwrap(),
                "{label}: symlink target mismatch for {}",
                rel.display()
            );
        } else if expected_meta.is_file() {
            assert_eq!(fs::read(expected.join(rel)).unwrap(), fs::read(&actual_path).unwrap(), "{label}: content mismatch for {}", rel.display());
        }
    }
    assert_eq!(actual_entries.len(), expected_entries.len(), "{label}: zm output has entries the reference tool does not");
}
