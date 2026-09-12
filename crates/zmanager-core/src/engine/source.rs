//! Owned archive source access descriptors and discovery (ARC-101, ARC-102).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Access capabilities supported by an archive source.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SourceAccess {
    /// Source is seekable (supports random access and position rewind).
    Seekable,
    /// Source is sequential-only (stream cannot seek backwards).
    SequentialOnly,
    /// Source consists of an ordered set of volume files.
    MultiVolumeSet,
}

/// A session-owned cursor capability for path-backed and explicit-volume
/// sources. The source module owns how a cursor is created; adapters only
/// receive the capability and never rediscover source paths themselves.
#[derive(Debug, Clone)]
pub(crate) struct SourceCursorFactory {
    source: ArchiveSource,
}

impl SourceCursorFactory {
    pub(crate) fn new(source: &ArchiveSource) -> Self {
        Self { source: source.clone() }
    }

    pub(crate) fn source(&self) -> &ArchiveSource {
        &self.source
    }

    pub(crate) fn open_primary_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new().read(true).open(self.source().primary_path())
    }
}

/// A snapshot of the file metadata that backs an opened archive source.
///
/// The engine uses this value to reject stale entry identities before an
/// operation can be dispatched to an adapter. It includes filesystem identity
/// where the platform exposes it, but it is not a content hash or a substitute
/// for adapter-owned parser/cursor state; the handle uses it to reject a
/// replaced or truncated path before dispatching a subsequent operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceFingerprint {
    files: Vec<SourceFileFingerprint>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SourceFileFingerprint {
    path: PathBuf,
    exists: bool,
    identity: Option<(u64, u64)>,
    length: Option<u64>,
    modified: Option<SystemTime>,
}

#[allow(clippy::unnecessary_wraps)]
fn source_file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Some((metadata.dev(), metadata.ino()))
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Owned archive source description.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ArchiveSource {
    /// Single archive file path.
    Path(PathBuf),
    /// Explicit ordered multi-volume file set (e.g. `.z01`, `.z02`, ..., `.zip`).
    VolumeSet(Vec<PathBuf>),
}

impl ArchiveSource {
    /// Returns the explicitly owned paths that make up this source.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        match self {
            Self::Path(path) => std::slice::from_ref(path),
            Self::VolumeSet(paths) => paths,
        }
    }

    /// Captures the source paths plus format-owned sibling paths discovered
    /// while opening a path-backed multi-volume format.
    pub(crate) fn fingerprint_with_additional_paths(&self, additional_paths: &[PathBuf]) -> std::io::Result<SourceFingerprint> {
        let mut paths = self.paths().to_vec();
        for path in additional_paths {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }

        let mut files = Vec::with_capacity(paths.len());
        for path in &paths {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    files.push(SourceFileFingerprint {
                        path: path.clone(),
                        exists: true,
                        identity: source_file_identity(&metadata),
                        length: Some(metadata.len()),
                        modified: metadata.modified().ok(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    files.push(SourceFileFingerprint { path: path.clone(), exists: false, identity: None, length: None, modified: None });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SourceFingerprint { files })
    }

    /// Returns whether the source and its format-owned sibling paths still
    /// match a previously captured fingerprint.
    pub(crate) fn matches_fingerprint_with_additional_paths(&self, expected: &SourceFingerprint, additional_paths: &[PathBuf]) -> std::io::Result<bool> {
        Ok(self.fingerprint_with_additional_paths(additional_paths)? == *expected)
    }

    /// Returns the primary path associated with this source.
    #[must_use]
    pub fn primary_path(&self) -> &Path {
        match self {
            Self::Path(path) => path,
            Self::VolumeSet(volumes) => volumes.last().map_or_else(|| Path::new(""), |p| p.as_path()),
        }
    }

    /// Returns the source access capability.
    #[must_use]
    pub(crate) fn access_capability(&self) -> SourceAccess {
        match self {
            Self::Path(_) => SourceAccess::Seekable,
            Self::VolumeSet(_) => SourceAccess::MultiVolumeSet,
        }
    }

    /// Returns the aggregate byte length including format-owned sibling paths.
    pub(crate) fn length_hint_with_additional_paths(&self, additional_paths: &[PathBuf]) -> std::io::Result<Option<u64>> {
        let mut paths = self.paths().to_vec();
        for path in additional_paths {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
        if paths.is_empty() {
            return Ok(None);
        }
        let mut length = 0u64;
        for path in &paths {
            let metadata = match std::fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A format-owned volume set may be addressed by a
                    // logical base path that is not itself a physical file
                    // (for example `archive.tzap` beside
                    // `archive.vol000.tzap`). The discovered physical paths
                    // still need to contribute to the source-size limit.
                    let logical_base_is_missing = matches!(self, Self::Path(primary) if primary == path && !additional_paths.is_empty());
                    if logical_base_is_missing {
                        continue;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            length =
                length.checked_add(metadata.len()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "archive source length overflow"))?;
        }
        Ok(Some(length))
    }

    /// Returns the session-owned cursor capability for this source.
    pub(crate) fn cursor_factory(&self) -> SourceCursorFactory {
        SourceCursorFactory::new(self)
    }

    /// Creates an `ArchiveSource` from a path, automatically discovering multi-volume sidecars if present.
    #[must_use]
    pub fn from_path_autodetect(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        if is_split_zip_archive_path(path)
            && let Some(volumes) = discover_split_zip_volumes(path)
        {
            return Self::VolumeSet(volumes);
        }
        Self::Path(path.to_path_buf())
    }
}

/// Returns true if `path` points to a split-ZIP volume or the final `.zip`
/// of a split set (ARC-102).
///
/// This consolidated predicate is the single split-ZIP identity rule shared
/// by format detection and source ownership. Sidecar volumes match `.z`
/// followed by at least two digits (`.z01`, `.z001`, ...); numbered raw
/// segments match a base ending in `.zip` plus a three-digit suffix
/// (`.zip.001`); a final `.zip` qualifies when a `.z01` sibling exists.
#[must_use]
pub fn is_split_zip_archive_path(path: &Path) -> bool {
    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };
    if is_split_zip_sidecar_extension(&filename) || is_numbered_zip_volume_name(&filename) {
        return true;
    }
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("zip")) {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if parent.join(format!("{stem}.z01")).is_file() {
            return true;
        }
    }
    false
}

/// A `.z`-style sidecar volume name, e.g. `archive.z01` or `archive.z001`.
fn is_split_zip_sidecar_extension(filename: &str) -> bool {
    let Some((base, extension)) = filename.rsplit_once('.') else {
        return false;
    };
    !base.is_empty() && extension.len() >= 3 && (extension.starts_with('z') || extension.starts_with('Z')) && extension[1..].chars().all(|c| c.is_ascii_digit())
}

fn is_numbered_zip_volume_name(filename: &str) -> bool {
    let Some((base, suffix)) = filename.rsplit_once('.') else {
        return false;
    };
    base.to_ascii_lowercase().ends_with(".zip") && suffix.len() == 3 && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SplitZipPart {
    Sidecar(u32),
    Numbered(u32),
    Final,
}

/// Parses one candidate split-ZIP volume name into its set base and part.
fn parse_split_zip_part(name: &str) -> Option<(&str, SplitZipPart)> {
    let (base, extension) = name.rsplit_once('.')?;
    if extension == "zip" {
        return Some((base, SplitZipPart::Final));
    }
    if is_split_zip_sidecar_extension(name) {
        let index = extension[1..].parse().ok()?;
        return (index > 0).then_some((base, SplitZipPart::Sidecar(index)));
    }
    if extension.len() == 3 && extension.bytes().all(|byte| byte.is_ascii_digit()) && base.to_ascii_lowercase().ends_with(".zip") {
        let index = extension.parse().ok()?;
        return (index > 0).then_some((base, SplitZipPart::Numbered(index)));
    }
    None
}

/// Discovers the ordered split-ZIP volume set for a member path.
///
/// Covers both `.zNN` sidecar sets (with their final `.zip`) and numbered
/// `.zip.NNN` raw-segment sets. Parts must be contiguous from index 1;
/// otherwise the set is considered incomplete and `None` is returned.
#[must_use]
pub fn discover_split_zip_volumes(path: &Path) -> Option<Vec<PathBuf>> {
    let file_name = path.file_name()?.to_str()?;
    let lower_name = file_name.to_ascii_lowercase();
    let (base, _) = parse_split_zip_part(&lower_name)?;
    // A bare relative file name (`archive.z01`, no directory component) has
    // `parent() == Some("")`, not `None`; `unwrap_or_else` only substitutes
    // "." on `None`, so `read_dir` used to receive the empty path and fail,
    // silently discovering zero sidecar volumes for the most common way to
    // invoke this against an archive in the current directory (the same bug
    // class fixed for TZAP volume discovery in `tzap::open`).
    let directory = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let entries = std::fs::read_dir(directory).ok()?;

    let mut sidecars = std::collections::BTreeMap::new();
    let mut numbered = std::collections::BTreeMap::new();
    let mut final_zip = None;
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        let Some((candidate_base, part)) = parse_split_zip_part(&candidate_lower) else {
            continue;
        };
        if candidate_base != base {
            continue;
        }
        match part {
            SplitZipPart::Sidecar(index) => {
                sidecars.insert(index, entry.path());
            }
            SplitZipPart::Numbered(index) => {
                numbered.insert(index, entry.path());
            }
            SplitZipPart::Final => final_zip = Some(entry.path()),
        }
    }

    if !numbered.is_empty() {
        let max = *numbered.keys().last()?;
        for expected in 1..=max {
            numbered.get(&expected)?;
        }
        return Some(numbered.into_values().collect());
    }
    if !sidecars.is_empty() {
        let max = *sidecars.keys().last()?;
        for expected in 1..=max {
            sidecars.get(&expected)?;
        }
        let mut volumes = sidecars.into_values().collect::<Vec<_>>();
        volumes.push(final_zip?);
        return Some(volumes);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ArchiveSource;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Removes the bare relative fixture files the test creates in the process
    /// working directory, even if an assertion unwinds first.
    struct Cleanup(Vec<std::path::PathBuf>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    #[test]
    fn source_fingerprint_records_filesystem_identity() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("zmanager-source-fingerprint-{unique}"));
        std::fs::write(&path, b"source").unwrap();

        let fingerprint = ArchiveSource::Path(path.clone()).fingerprint_with_additional_paths(&[]).unwrap();

        #[cfg(unix)]
        assert!(fingerprint.files[0].identity.is_some());
        #[cfg(not(unix))]
        assert!(fingerprint.files[0].identity.is_none());

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn source_fingerprint_includes_format_owned_sibling_paths() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let primary = std::env::temp_dir().join(format!("zmanager-source-primary-{unique}"));
        let sibling = std::env::temp_dir().join(format!("zmanager-source-sibling-{unique}"));
        std::fs::write(&primary, b"primary").unwrap();
        std::fs::write(&sibling, b"sibling").unwrap();

        let source = ArchiveSource::Path(primary.clone());
        let additional = vec![sibling.clone()];
        let fingerprint = source.fingerprint_with_additional_paths(&additional).unwrap();
        std::fs::write(&sibling, b"changed sibling").unwrap();

        assert!(!source.matches_fingerprint_with_additional_paths(&fingerprint, &additional).unwrap());

        std::fs::remove_file(primary).unwrap();
        std::fs::remove_file(sibling).unwrap();
    }

    #[test]
    fn source_aggregate_length_includes_format_owned_sibling_paths() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let primary = std::env::temp_dir().join(format!("zmanager-source-metadata-primary-{unique}"));
        let sibling = std::env::temp_dir().join(format!("zmanager-source-metadata-sibling-{unique}"));
        std::fs::write(&primary, b"primary").unwrap();
        std::fs::write(&sibling, b"sibling").unwrap();

        let path_source = ArchiveSource::Path(primary.clone());
        assert_eq!(path_source.length_hint_with_additional_paths(&[]).unwrap(), Some(7));
        assert_eq!(path_source.length_hint_with_additional_paths(std::slice::from_ref(&sibling)).unwrap(), Some(14));

        let volume_source = ArchiveSource::VolumeSet(vec![primary.clone(), sibling.clone()]);
        assert_eq!(volume_source.length_hint_with_additional_paths(&[]).unwrap(), Some(14));

        std::fs::remove_file(primary).unwrap();
        std::fs::remove_file(sibling).unwrap();
    }

    #[test]
    fn discover_split_zip_volumes_normalizes_bare_relative_path() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = format!("zm_bare_split_zip_{unique}");
        let z01_name = format!("{base}.z01");
        let zip_name = format!("{base}.zip");
        let z01 = std::path::PathBuf::from(&z01_name);
        let zip = std::path::PathBuf::from(&zip_name);
        let _ = std::fs::remove_file(&z01);
        let _ = std::fs::remove_file(&zip);
        std::fs::write(&z01, b"part1").unwrap();
        std::fs::write(&zip, b"part2").unwrap();

        let _guard = Cleanup(vec![z01.clone(), zip.clone()]);

        let discovered = super::discover_split_zip_volumes(std::path::Path::new(&z01_name));
        assert!(discovered.is_some(), "failed to discover split zip with bare relative path");
        let volumes = discovered.unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0], std::path::PathBuf::from(".").join(&z01_name));
        assert_eq!(volumes[1], std::path::PathBuf::from(".").join(&zip_name));
    }
}
