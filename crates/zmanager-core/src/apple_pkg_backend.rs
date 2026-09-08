use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use std::fmt;
use std::io::{self, Read as _, Write};
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(PkgBackendError);

/// Entry reported by [`list_pkg`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PkgListEntry {
    /// Path inside the package payload.
    pub path: String,
    /// Entry kind.
    pub kind: PkgEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Symlink target when the payload entry is symbolic.
    pub link_target: Option<String>,
}

/// Kind of a [`PkgListEntry`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PkgEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// `.pkg` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PkgExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for PkgExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// `.pkg` backend error.
#[derive(Debug)]
pub enum PkgBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Underlying XAR error.
    Xara(String),
    /// Underlying PBZX error.
    Pbzx(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for PkgBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Xara(message) => write!(f, "XAR backend error: {message}"),
            Self::Pbzx(message) => write!(f, "PBZX backend error: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for PkgBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Xara(_) | Self::Pbzx(_) | Self::Cancelled => None,
        }
    }
}

/// Extracts a `.pkg` archive with an overwrite resolver.
pub fn extract_pkg_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<PkgExtractReport, PkgBackendError> {
    extract_pkg_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.pkg` archive without job progress callbacks.
pub fn extract_pkg(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy) -> Result<PkgExtractReport, PkgBackendError> {
    extract_pkg_inner(archive_path, destination, policy, None, None)
}

/// Decodes a component `Payload` into its underlying CPIO archive.
///
/// Apple's `pkgbuild` produces a Payload compressed with one of several
/// codecs: `pbzx` (Apple's streaming format), gzip, zlib, or bzip2, or
/// uncompressed old/new-style CPIO for tiny packages. The codec is chosen
/// by `pkgbuild` from the payload size, so a backend that only understands
/// `pbzx` fails on small packages.
fn decode_payload(payload_bytes: &[u8]) -> Result<dpp::pbzx::Archive, PkgBackendError> {
    const PBZX_MAGIC: &[u8] = b"pbzx";
    const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
    const ZLIB_MAGIC: &[u8] = &[0x78];
    const BZIP2_MAGIC: &[u8] = b"BZh";
    const CPIO_MAGICS: &[&[u8]] = &[b"070701", b"070702", b"070707"];

    fn from_cpio(cpio: &[u8]) -> Result<dpp::pbzx::Archive, PkgBackendError> {
        dpp::pbzx::Archive::from_cpio(cpio).map_err(|e| PkgBackendError::Pbzx(format!("cpio payload: {e}")))
    }

    if payload_bytes.starts_with(PBZX_MAGIC) {
        let cursor = std::io::Cursor::new(payload_bytes);
        dpp::pbzx::Archive::from_reader(cursor).map_err(|e| PkgBackendError::Pbzx(format!("pbzx payload: {e}")))
    } else if payload_bytes.starts_with(GZIP_MAGIC) {
        let mut decoder = flate2::read::GzDecoder::new(payload_bytes);
        let mut cpio = Vec::new();
        decoder.read_to_end(&mut cpio).map_err(|e| PkgBackendError::Pbzx(format!("gzip payload: {e}")))?;
        from_cpio(&cpio)
    } else if payload_bytes.starts_with(ZLIB_MAGIC) {
        let mut decoder = flate2::read::ZlibDecoder::new(payload_bytes);
        let mut cpio = Vec::new();
        decoder.read_to_end(&mut cpio).map_err(|e| PkgBackendError::Pbzx(format!("zlib payload: {e}")))?;
        from_cpio(&cpio)
    } else if payload_bytes.starts_with(BZIP2_MAGIC) {
        let mut decoder = bzip2::read::BzDecoder::new(payload_bytes);
        let mut cpio = Vec::new();
        decoder.read_to_end(&mut cpio).map_err(|e| PkgBackendError::Pbzx(format!("bzip2 payload: {e}")))?;
        from_cpio(&cpio)
    } else if CPIO_MAGICS.iter().any(|magic| payload_bytes.starts_with(magic)) {
        from_cpio(payload_bytes)
    } else {
        let magic = &payload_bytes[..payload_bytes.len().min(8)];
        Err(PkgBackendError::Pbzx(format!("unsupported Payload compression (magic {magic:02x?})")))
    }
}

/// Normalizes a CPIO entry path for safety planning and display: strips the
/// `./` and `/` prefixes cpio archives carry, and returns `None` for the
/// root entry.
fn normalize_cpio_path(path: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() || path == "." { None } else { Some(path.to_string()) }
}

/// Reads every CPIO entry across all package components.
///
/// Components without a Payload are skipped, matching the extraction
/// behavior.
fn read_payload_entries(archive_path: &Path) -> Result<Vec<dpp::pbzx::CpioEntry>, PkgBackendError> {
    let file = std::fs::File::open(archive_path).map_err(|source| PkgBackendError::Io { path: archive_path.to_path_buf(), source })?;
    let mut pkg = dpp::xara::PkgReader::open(file).map_err(|e| PkgBackendError::Xara(e.to_string()))?;

    let mut entries = Vec::new();
    for component in pkg.components() {
        let Ok(payload_bytes) = pkg.payload(&component) else {
            continue; // Some components might not have a payload, just skip
        };
        let archive = decode_payload(&payload_bytes)?;
        entries.extend(archive.entries().map_err(|e| PkgBackendError::Pbzx(e.to_string()))?);
    }
    Ok(entries)
}

/// Lists the payload entries of a `.pkg` archive without extracting them.
pub fn list_pkg(archive_path: impl AsRef<Path>) -> Result<Vec<PkgListEntry>, PkgBackendError> {
    let entries = read_payload_entries(archive_path.as_ref())?;
    Ok(entries
        .into_iter()
        .filter_map(|entry| {
            let path = normalize_cpio_path(&entry.path)?;
            let kind = if entry.is_dir {
                PkgEntryKind::Directory
            } else if entry.is_symlink {
                PkgEntryKind::Symlink
            } else {
                PkgEntryKind::File
            };
            let link_target = entry.is_symlink.then(|| String::from_utf8_lossy(entry.data.as_deref().unwrap_or_default()).into_owned());
            Some(PkgListEntry { path, kind, size: entry.size, link_target })
        })
        .collect())
}

#[allow(clippy::too_many_lines)]
fn extract_pkg_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<PkgExtractReport, PkgBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| PkgBackendError::Io { path: destination.to_path_buf(), source })?;

    let entries = read_payload_entries(archive_path)?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = PkgExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

    for cpio_entry in entries {
        if let Some(ctx) = context.as_deref_mut() {
            ctx.check_cancelled()?;
        }
        let Some(archive_entry_path) = normalize_cpio_path(&cpio_entry.path) else {
            continue;
        };

        let size = cpio_entry.size;

        let kind = if cpio_entry.is_dir {
            ExtractionEntryKind::Directory
        } else if cpio_entry.is_symlink {
            let target = PathBuf::from(String::from_utf8_lossy(cpio_entry.data.as_ref().unwrap_or(&Vec::new())).into_owned());
            ExtractionEntryKind::Symlink { target }
        } else {
            ExtractionEntryKind::File
        };

        let safety_entry = ExtractionEntry { archive_path: archive_entry_path, kind, uncompressed_size: Some(size), compressed_size: None };

        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, mut context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, PkgBackendError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    let replace_existing = decision.replace_existing;
                    let destination_path = decision.destination_path;

                    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(destination_path)
                            .map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                    }

                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            std::fs::create_dir_all(destination_path).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            Ok::<u64, PkgBackendError>(0)
                        }
                        ExtractionEntryKind::File => {
                            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path)
                                .map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            let file = output.file_mut().map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            let written_bytes = match &cpio_entry.data {
                                Some(data) => {
                                    file.write_all(data).map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                                    data.len() as u64
                                }
                                None => 0,
                            };

                            output
                                .commit_with_replace(replace_existing)
                                .map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            if let Some(ctx) = context.as_deref_mut() {
                                ctx.bytes_processed(Some(&safety_entry.archive_path), written_bytes);
                            }

                            report.written_entries += 1;
                            report.written_bytes += written_bytes;
                            Ok(written_bytes)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                                return Ok(0);
                            }

                            #[cfg(unix)]
                            {
                                crate::extract_materialize::write_symlink(Path::new(target), destination_path)
                                    .map_err(|source| PkgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = target;
                            }
                            Ok::<u64, PkgBackendError>(0)
                        }
                        _ => Ok::<u64, PkgBackendError>(0),
                    }
                }
            }
        })?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{PkgEntryKind, extract_pkg_with_overwrite_resolver, list_pkg};
    use crate::safety::{ExtractionPolicy, OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver};
    use crate::test_support::TestDir;
    use std::fs;
    use std::path::PathBuf;

    struct AlwaysReplace;
    impl OverwriteResolver for AlwaysReplace {
        fn decide(&mut self, _conflict: &OverwriteConflict) -> OverwriteDecision {
            OverwriteDecision::Replace
        }
    }

    fn pkg_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    #[test]
    fn checked_in_pkg_fixture_lists_with_normalized_paths() {
        let archive = pkg_fixture("basic.pkg");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let listing = list_pkg(&archive).unwrap();
        let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
        assert!(paths.contains(&"payload/README.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/file.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/empty-dir"), "{paths:?}");
        assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{paths:?}");
        let link = listing.iter().find(|entry| entry.path == "payload/nested/readme-link.txt").expect("missing symlink");
        assert_eq!(link.link_target.as_deref(), Some("../README.txt"));
        assert!(paths.contains(&"payload/unicode/こんにちは.txt"), "{paths:?}");
        assert!(listing.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "pkg paths must be normalized: {paths:?}");

        let readme = listing.iter().find(|entry| entry.path == "payload/README.txt").unwrap();
        assert_eq!(readme.kind, PkgEntryKind::File);
        assert_eq!(readme.size, 25);
        let link = listing.iter().find(|entry| entry.path == "payload/nested/readme-link.txt").unwrap();
        assert_eq!(link.kind, PkgEntryKind::Symlink);
        // pkgbuild emits AppleDouble entries for files carrying extended
        // attributes (macOS adds com.apple.provenance to every new file).
        assert!(listing.iter().any(|entry| entry.path.contains("/._")), "expected ._ AppleDouble entries: {paths:?}");
    }

    #[test]
    fn checked_in_pkg_fixture_extracts_every_file_with_byte_accurate_report() {
        let archive = pkg_fixture("basic.pkg");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let temp = TestDir::new("checked_in_pkg_fixture_extract");
        let report = extract_pkg_with_overwrite_resolver(
            &archive,
            temp.path("out"),
            ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            &mut AlwaysReplace,
        )
        .unwrap();

        // The fixture carries one symlink; it is materialized on unix and
        // skipped with a warning elsewhere.
        assert_eq!(report.skipped_entries, usize::from(!cfg!(unix)), "warnings: {:?}", report.warnings);
        assert_eq!(fs::read_to_string(temp.path("out/payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");
        assert!(temp.path("out/payload/nested/empty-dir").is_dir());
        #[cfg(unix)]
        {
            assert_eq!(fs::read_link(temp.path("out/payload/nested/readme-link.txt")).unwrap(), PathBuf::from("../README.txt"));
        }

        // Every listed file entry contributes exactly its declared size, and
        // the AppleDouble entries are written as plain files too.
        let listing = list_pkg(&archive).unwrap();
        let declared_file_bytes: u64 = listing.iter().filter(|entry| entry.kind == PkgEntryKind::File).map(|entry| entry.size).sum();
        // The fixture's symlink is not reflected in written_entries on any
        // platform (materialized on unix, skipped elsewhere; the pkg backend
        // does not count it), so the File count matches unconditionally.
        assert_eq!(report.written_entries, listing.iter().filter(|entry| entry.kind == PkgEntryKind::File).count());
        assert_eq!(report.written_bytes, declared_file_bytes, "written bytes must sum the declared sizes of all listed files");
    }
}
