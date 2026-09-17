//! Shared extraction-materialization helpers used by the archive backends.
//!
//! These helpers were historically triplicated across the tar
//! zstd, and Apple Archive backends with only the per-backend error enums
//! differing. They live here as `io::Result`-based, error-type-agnostic
//! functions; each backend keeps a thin wrapper that maps errors into its own
//! error enum.

use crate::safety::ExtractionEntryKind;
use filetime::FileTime;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Permission bits preserved when restoring entry modes.
/// Mode bits restored on extraction. Privileged bits (setuid/setgid/sticky)
/// are deliberately preserved: 7-Zip 26.01 (`SetFileAttrib_PosixHighDetect`,
/// `CPP/Windows/FileDir.cpp`) applies the archive's full mode subject only to
/// the process umask, and dpkg does the same for `.deb` payloads, so
/// stripping would make extraction diverge from the reference tools (CR-034).
pub(crate) const MODE_MASK: u32 = 0o7777;

/// A hardlink whose creation is deferred until all archive entries have been
/// planned and ordered.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DeferredHardlink {
    pub(crate) source_path: PathBuf,
    pub(crate) destination_path: PathBuf,
}

/// Whether `path` is the archive root (empty, "/", or ".").
#[must_use]
pub(crate) fn is_root_entry_path(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    trimmed.is_empty() || trimmed == "."
}

/// Whether the entry is the archive's root directory entry.
#[must_use]
pub(crate) fn is_archive_root_directory(path: &str, kind: &ExtractionEntryKind) -> bool {
    matches!(kind, ExtractionEntryKind::Directory) && is_root_entry_path(path)
}

/// Materializes deferred hardlinks in dependency order.
///
/// This is the pure link-creation part of the backends' deferred-hardlink
/// passes; report bookkeeping is left to the caller.
pub(crate) fn materialize_deferred_hardlinks(hardlinks: &[DeferredHardlink]) -> io::Result<()> {
    let paths = hardlinks.iter().map(|hardlink| (hardlink.source_path.clone(), hardlink.destination_path.clone())).collect::<Vec<_>>();
    let order = crate::safety::deferred_link_dependency_order(&paths)?;
    for index in order {
        let hardlink = &hardlinks[index];
        write_hardlink(&hardlink.source_path, &hardlink.destination_path)?;
    }
    Ok(())
}

/// Applies restored mode bits and modification time to an extracted path.
pub(crate) fn apply_metadata(path: &Path, mode: Option<u32>, mtime: Option<FileTime>) -> io::Result<()> {
    // Windows uses the Read-only attribute for the POSIX write-bit projection.
    // Apply the timestamp while the path is writable: setting Read-only first
    // makes `filetime` reopen the file with insufficient access rights.
    #[cfg(not(unix))]
    if mode.is_some()
        && let Ok(fs_metadata) = fs::metadata(path)
        && fs_metadata.permissions().readonly()
    {
        let mut perms = fs_metadata.permissions();
        perms.set_readonly(false);
        fs::set_permissions(path, perms)?;
    }

    if let Some(mtime) = mtime {
        filetime::set_file_mtime(path, mtime)?;
    }

    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode & MODE_MASK))?;
    }

    #[cfg(not(unix))]
    if let Some(mode) = mode {
        let fs_metadata = fs::metadata(path)?;
        let mut perms = fs_metadata.permissions();
        perms.set_readonly(mode & 0o222 == 0);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Uses `set_symlink_file_times` to avoid following the link. Errors are
/// reported so extraction cannot claim metadata was restored when it was not.
pub(crate) fn apply_symlink_mtime(path: &Path, mtime: Option<FileTime>) -> io::Result<()> {
    if let Some(mtime) = mtime {
        filetime::set_symlink_file_times(path, mtime, mtime)?;
    }
    Ok(())
}

/// Creates a hard link from `source_path` to `destination_path`, ensuring the
/// destination's parent directory exists first.
pub(crate) fn write_hardlink(source_path: &Path, destination_path: &Path) -> io::Result<()> {
    ensure_parent_dir(destination_path)?;
    fs::hard_link(source_path, destination_path)
}

/// Creates a symbolic link at `destination_path` pointing at `target`,
/// ensuring the destination's parent directory exists first.
#[cfg(unix)]
pub(crate) fn write_symlink(target: &Path, destination_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::symlink;

    ensure_parent_dir(destination_path)?;
    symlink(target, destination_path)
}

/// Reports that symlink extraction is unsupported on this platform.
#[cfg(not(unix))]
pub(crate) fn write_symlink(_target: &Path, _destination_path: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "symlink extraction is not supported on this platform"))
}

/// Creates the parent directory of `path` when it has one.
pub(crate) fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply_metadata;
    use filetime::FileTime;
    use std::fs;

    #[test]
    fn applies_mtime_before_windows_read_only_attribute() {
        let root = std::env::temp_dir().join(format!(
            "zmanager-extract-materialize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("system clock should be after the Unix epoch").as_nanos()
        ));
        fs::create_dir_all(&root).expect("test root should be created");
        let path = root.join("read-only.txt");
        fs::write(&path, b"read-only\n").expect("test file should be written");

        let result = apply_metadata(&path, Some(0o444), Some(FileTime::from_unix_time(1_500_000_000, 0)));

        let _ = fs::remove_dir_all(&root);
        result.expect("read-only metadata should be applied without blocking mtime restoration");
    }
}
