use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(DmgBackendError);

/// Entry reported by [`list_dmg`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DmgListEntry {
    /// Path inside the disk image.
    pub path: String,
    /// Entry kind.
    pub kind: DmgEntryKind,
    /// Declared uncompressed size.
    pub size: u64,
    /// Target path for a symbolic link, when the image exposes one.
    pub link_target: Option<String>,
}

/// Kind of a [`DmgListEntry`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DmgEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// `.dmg` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DmgExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for DmgExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// `.dmg` backend error.
#[derive(Debug)]
pub enum DmgBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Underlying DPP error.
    Dpp(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for DmgBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Dpp(message) => write!(f, "DMG backend error: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for DmgBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Dpp(_) | Self::Cancelled => None,
        }
    }
}

struct ProgressWriter<'a, 'b, W: io::Write> {
    inner: W,
    context: Option<&'a mut JobContext<'b>>,
    archive_path: &'a str,
}

impl<W: io::Write> io::Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        if let Some(ctx) = self.context.as_deref_mut() {
            if ctx.check_cancelled().is_err() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
            }
            ctx.bytes_processed(Some(self.archive_path), written as u64);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// HFS+ volumes carry a reserved `\0\0\0\0HFS+ Private Data` directory
/// (Finder metadata) that cannot exist as a real path; skip it and any other
/// entry whose raw name contains NUL bytes.
fn is_reserved_volume_entry(path: &str) -> bool {
    path.contains('\0')
}

/// Lists the entries of a `.dmg` archive without extracting them.
pub fn list_dmg(archive_path: impl AsRef<Path>) -> Result<Vec<DmgListEntry>, DmgBackendError> {
    let mut pipeline = dpp::DmgPipeline::open(archive_path.as_ref()).map_err(|e| DmgBackendError::Dpp(e.to_string()))?;
    let mut fs = pipeline.open_filesystem().map_err(|e| DmgBackendError::Dpp(e.to_string()))?;

    let entries = fs.walk().map_err(|e| DmgBackendError::Dpp(e.to_string()))?;

    let entries = entries
        .into_iter()
        .map(|entry| {
            let path = entry.path.strip_prefix('/').unwrap_or(&entry.path).to_string();
            if path.is_empty() || is_reserved_volume_entry(&path) {
                return Ok(None);
            }
            let kind = match entry.entry.kind {
                dpp::FsEntryKind::File => DmgEntryKind::File,
                dpp::FsEntryKind::Directory => DmgEntryKind::Directory,
                dpp::FsEntryKind::Symlink => DmgEntryKind::Symlink,
            };
            let link_target = (kind == DmgEntryKind::Symlink)
                .then(|| fs.read_file(&entry.path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
                .transpose()
                .map_err(|e| DmgBackendError::Dpp(e.to_string()))?;
            Ok(Some(DmgListEntry { path, kind, size: entry.entry.size, link_target }))
        })
        .collect::<Result<Vec<_>, DmgBackendError>>()?;

    Ok(entries.into_iter().flatten().collect())
}

/// Extracts a `.dmg` archive with an overwrite resolver.
pub fn extract_dmg_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<DmgExtractReport, DmgBackendError> {
    extract_dmg_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts a `.dmg` archive without job progress callbacks.
pub fn extract_dmg(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy) -> Result<DmgExtractReport, DmgBackendError> {
    extract_dmg_inner(archive_path, destination, policy, None, None)
}

fn extract_dmg_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<DmgExtractReport, DmgBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| DmgBackendError::Io { path: destination.to_path_buf(), source })?;

    let mut pipeline = dpp::DmgPipeline::open(archive_path).map_err(|e| DmgBackendError::Dpp(e.to_string()))?;
    let mut fs = pipeline.open_filesystem().map_err(|e| DmgBackendError::Dpp(e.to_string()))?;

    let entries = fs.walk().map_err(|e| DmgBackendError::Dpp(e.to_string()))?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut report = DmgExtractReport { written_entries: 0, skipped_entries: 0, written_bytes: 0, warnings: Vec::new() };

    for walk_entry in entries {
        let archive_entry_path = walk_entry.path.strip_prefix('/').unwrap_or(&walk_entry.path).to_string();
        if archive_entry_path.is_empty() {
            continue;
        }
        if is_reserved_volume_entry(&archive_entry_path) {
            crate::extract_loop::skip_entry(&mut report, context.as_deref_mut(), format!("skipped {archive_entry_path}: reserved filesystem entry"));
            continue;
        }

        let size = walk_entry.entry.size;

        let kind = match walk_entry.entry.kind {
            dpp::FsEntryKind::File => ExtractionEntryKind::File,
            dpp::FsEntryKind::Directory => ExtractionEntryKind::Directory,
            dpp::FsEntryKind::Symlink => {
                let target_bytes = fs.read_file(&walk_entry.path).map_err(|e| DmgBackendError::Dpp(e.to_string()))?;
                let target = PathBuf::from(String::from_utf8_lossy(&target_bytes).into_owned());
                ExtractionEntryKind::Symlink { target }
            }
        };

        let safety_entry = ExtractionEntry { archive_path: archive_entry_path, kind, uncompressed_size: Some(size), compressed_size: None };

        crate::extract_loop::process_extraction_entry(&mut report, context.as_deref_mut(), &mut planner, &safety_entry, &mut |action, report, mut context| {
            match action {
                crate::extract_loop::EntryAction::Skip => Ok::<u64, DmgBackendError>(0),
                crate::extract_loop::EntryAction::Write(decision) => {
                    let replace_existing = decision.replace_existing;
                    let destination_path = decision.destination_path;

                    if replace_existing && !matches!(safety_entry.kind, ExtractionEntryKind::File) {
                        crate::safety::remove_destination_for_replace(destination_path)
                            .map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                    }

                    match &safety_entry.kind {
                        ExtractionEntryKind::Directory => {
                            std::fs::create_dir_all(destination_path).map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            Ok::<u64, DmgBackendError>(0)
                        }
                        ExtractionEntryKind::File => {
                            let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path)
                                .map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            let mut file = output.file_mut().map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            let written_bytes = if context.is_some() {
                                let mut writer = ProgressWriter { inner: &mut file, context: context.as_deref_mut(), archive_path: &safety_entry.archive_path };
                                fs.read_file_to(&walk_entry.path, &mut writer).map_err(|e| DmgBackendError::Dpp(e.to_string()))?
                            } else {
                                fs.read_file_to(&walk_entry.path, &mut file).map_err(|e| DmgBackendError::Dpp(e.to_string()))?
                            };

                            output
                                .commit_with_replace(replace_existing)
                                .map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;

                            report.written_entries += 1;
                            report.written_bytes += written_bytes;
                            Ok(written_bytes)
                        }
                        ExtractionEntryKind::Symlink { target } => {
                            // APFS stores symlink targets in a "com.apple.fs.symlink"
                            // extended attribute, HFS+ in the data fork; the DPP reader
                            // exposes both via read_file. Skip rather than materialize
                            // a broken empty symlink if a target is still missing.
                            if target.as_os_str().is_empty() {
                                crate::extract_loop::skip_entry(
                                    report,
                                    context,
                                    format!("symlink {} skipped: disk image does not expose the symlink target", safety_entry.archive_path),
                                );
                                return Ok(0);
                            }
                            if crate::safety::should_skip_symlink_materialization(&safety_entry.kind) {
                                crate::extract_loop::skip_entry(report, context, crate::safety::unsupported_symlink_warning(&safety_entry.archive_path));
                                return Ok(0);
                            }

                            #[cfg(unix)]
                            {
                                crate::extract_materialize::write_symlink(Path::new(target), destination_path)
                                    .map_err(|source| DmgBackendError::Io { path: destination_path.to_path_buf(), source })?;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = target;
                            }
                            report.written_entries += 1;
                            Ok::<u64, DmgBackendError>(0)
                        }
                        _ => Ok::<u64, DmgBackendError>(0),
                    }
                }
            }
        })?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{DmgEntryKind, extract_dmg_with_overwrite_resolver, list_dmg};
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

    fn dmg_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    #[test]
    fn checked_in_dmg_fixture_lists_with_normalized_paths() {
        let archive = dmg_fixture("basic.dmg");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let listing = list_dmg(&archive).unwrap();
        let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
        assert!(paths.contains(&"payload/README.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/file.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/empty-dir"), "{paths:?}");
        assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/unicode/こんにちは.txt"), "{paths:?}");
        assert!(listing.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "dmg paths must be normalized: {paths:?}");

        let readme = listing.iter().find(|entry| entry.path == "payload/README.txt").unwrap();
        assert_eq!(readme.kind, DmgEntryKind::File);
        assert_eq!(readme.size, 25);
        let link = listing.iter().find(|entry| entry.path == "payload/nested/readme-link.txt").unwrap();
        assert_eq!(link.kind, DmgEntryKind::Symlink);
        assert_eq!(link.link_target.as_deref(), Some("../README.txt"));
    }

    #[test]
    fn checked_in_dmg_fixture_extracts_every_file_with_byte_accurate_report() {
        let archive = dmg_fixture("basic.dmg");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let temp = TestDir::new("checked_in_dmg_fixture_extract");
        let report = extract_dmg_with_overwrite_resolver(
            &archive,
            temp.path("out"),
            ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            &mut AlwaysReplace,
        )
        .unwrap();

        // The fixture carries one symlink; it is materialized on unix and
        // skipped with a warning elsewhere (no symlink materialization
        // off-unix), so the written count is platform-aware.
        assert_eq!(report.written_entries, if cfg!(unix) { 5 } else { 4 });
        assert_eq!(report.written_bytes, 81);
        assert_eq!(report.skipped_entries, usize::from(!cfg!(unix)), "warnings: {:?}", report.warnings);
        assert_eq!(fs::read_to_string(temp.path("out/payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/unicode/こんにちは.txt")).unwrap(), "unicode path fixture\n");
        assert!(temp.path("out/payload/nested/empty-dir").is_dir());
        // APFS stores the symlink target in a "com.apple.fs.symlink" xattr,
        // which the reader exposes via read_file; the link is materialized.
        #[cfg(unix)]
        {
            let link = fs::read_link(temp.path("out/payload/nested/readme-link.txt")).unwrap();
            assert_eq!(link, PathBuf::from("../README.txt"));
        }
    }
}
