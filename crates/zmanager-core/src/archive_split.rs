//! Shared split-archive destination handling for the ZIP and 7z backends.
//!
//! Both backends split output into numbered volumes and guard their
//! destinations with the same existence/replace checks. These helpers were
//! previously copied into each backend with a different error type; the
//! `io::Result`-based versions here keep the checks in one place and each
//! backend maps errors into its own error enum.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Number of volumes needed for `archive_size` bytes at `volume_size` each.
pub(crate) fn split_volume_count(archive_size: u64, volume_size: u64) -> Option<usize> {
    let count = archive_size.max(1).div_ceil(volume_size);
    usize::try_from(count).ok()
}

/// Collects sibling paths in `directory` whose names `matcher` recognizes,
/// ordered by the parsed part number. Shared by the zip and 7z volume splits
/// (CR-122): both previously shipped their own `read_dir` + map skeletons.
pub(crate) fn existing_volume_paths(directory: &Path, matcher: &mut impl FnMut(&str) -> Option<u32>) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(source),
    };
    let mut paths = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        if let Some(part) = matcher(candidate_name) {
            paths.insert(part, entry.path());
        }
    }
    Ok(paths.into_values().collect())
}

/// Deduplicated paths from two volume-path lists, preserving order.
#[must_use]
pub(crate) fn unique_paths<'a>(left: &'a [PathBuf], right: &'a [PathBuf]) -> Vec<&'a Path> {
    let mut seen = BTreeSet::new();
    left.iter().chain(right.iter()).filter_map(|path| if seen.insert(path.clone()) { Some(path.as_path()) } else { None }).collect()
}

/// Returns an error when `path` exists and must not be replaced.
///
/// Directories are always refused (a split writer must never replace a
/// directory with a volume file); an existing file is accepted only when
/// `replace_existing` is set; a missing destination is fine.
pub(crate) fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Err(io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())))
        }
        Ok(_) if !replace_existing => Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("destination already exists: {}", path.display()))),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}
