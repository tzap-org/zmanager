//! Shared temporary file and directory name generation.
//!
//! The archive backends need unique, process-scoped temporary names for
//! decoded intermediates and preview roots. These were historically generated
//! inline with pid-plus-nanoseconds schemes duplicated in three places; the
//! core helper lives here so the schemes cannot drift.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Builds a unique temporary name component: `{label}-{pid}-{nanos}`.
///
/// `nanos` is the current Unix timestamp in nanoseconds at call time. In
/// theory two calls in the same process in the same nanosecond collide;
/// callers that create directories or files must retry on `AlreadyExists`
/// when they need to be robust (see [`TemporaryDirectory`]).
pub(crate) fn unique_temp_name(label: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    format!("{label}-{}-{now}", std::process::id())
}

/// A temporary directory allocation failed.
#[derive(Debug)]
pub(crate) struct TempDirAllocError {
    /// The path that was attempted (or the parent, for the final retry error).
    pub(crate) path: PathBuf,
    /// The underlying allocation failure.
    pub(crate) source: io::Error,
}

impl fmt::Display for TempDirAllocError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "could not allocate temporary directory at {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for TempDirAllocError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// A uniquely named temporary directory that removes itself on drop.
pub(crate) struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    /// Creates a uniquely named temporary directory, retrying on
    /// same-process-same-nanosecond collisions.
    ///
    /// Uses `create_dir` (not `create_dir_all`) so an existing path fails
    /// with `AlreadyExists` and the retry loop advances; two concurrent
    /// allocations can never share one directory.
    pub(crate) fn new(label: &str) -> Result<Self, TempDirAllocError> {
        Self::new_in(&std::env::temp_dir(), label)
    }

    /// Creates a uniquely named temporary directory below `parent`.
    pub(crate) fn new_in(parent: &Path, label: &str) -> Result<Self, TempDirAllocError> {
        let unique = unique_temp_name(label);

        for attempt in 0..100 {
            let path = parent.join(format!("{unique}-{attempt}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(TempDirAllocError { path, source }),
            }
        }

        Err(TempDirAllocError {
            path: parent.to_path_buf(),
            source: io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate temporary directory for {label}")),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::TemporaryDirectory;

    #[test]
    fn temporary_directories_do_not_reuse_existing_paths() {
        let first = TemporaryDirectory::new("temp-names-test").unwrap();
        let first_path = first.path().to_path_buf();

        let second = TemporaryDirectory::new("temp-names-test").unwrap();

        assert_ne!(second.path(), first_path);
        assert!(first_path.is_dir());
        assert!(second.path().is_dir());
    }
}
