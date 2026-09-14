use crate::backend_impl::backend_report::open_member_source;
use crate::jobs::JobContext;
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive};
use crate::safety::ExtractionSafetyError;
use crate::tar_metadata::{ExactLengthReader, changed_during_read_note};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Options for `.tar.zst` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdCreateOptions {
    /// Zstd compression level.
    pub level: i32,
    /// Zstd worker count. `None` chooses a sensible local default.
    pub threads: Option<u32>,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
}

impl Default for TarZstdCreateOptions {
    fn default() -> Self {
        Self { level: 3, threads: crate::parallelism::available_parallelism_at_least_two(), preserve_metadata: true, replace_existing: false }
    }
}

/// `.tar.zst` creation report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarZstdCreateReport {
    /// Number of tar entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into regular file entries.
    pub written_bytes: u64,
    /// Zstd level used.
    pub level: i32,
    /// Zstd thread count requested.
    pub threads: Option<u32>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// `.tar.zst` backend error.
#[derive(Debug)]
pub enum TarZstdError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for TarZstdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TarZstdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Cancelled => None,
        }
    }
}

/// Creates a `.tar.zst` archive from one source path.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, filesystem reads, tar writing, or
/// zstd compression fail.
pub fn create_tar_zst_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
) -> Result<TarZstdCreateReport, TarZstdError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_tar_zst_from_manifest(&manifest, destination, options)
}

/// Creates a `.tar.zst` archive from a manifest.
///
/// # Errors
///
/// Returns [`TarZstdError`] when source files cannot be read, tar writing fails,
/// or zstd compression fails.
pub fn create_tar_zst_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
) -> Result<TarZstdCreateReport, TarZstdError> {
    create_tar_zst_from_manifest_inner(manifest, destination, options, None)
}

/// Creates a `.tar.zst` archive from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`TarZstdError`] when source files cannot be read, tar writing fails,
/// zstd compression fails, or cancellation is requested.
pub fn create_tar_zst_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TarZstdCreateReport, TarZstdError> {
    create_tar_zst_from_manifest_inner(manifest, destination, options, Some(context))
}

fn create_tar_zst_from_manifest_inner(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TarZstdCreateReport, TarZstdError> {
    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;
    let file = output.file_mut().map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;
    let mut encoder = zstd::stream::write::Encoder::new(file, options.level).map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;

    if let Some(threads) = options.threads
        && threads > 0
    {
        encoder.multithread(threads).map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;
    }

    let mut builder = Builder::new(encoder);
    builder.follow_symlinks(false);
    let mut report = TarZstdCreateReport { written_entries: 0, written_bytes: 0, level: options.level, threads: options.threads, warnings: Vec::new() };

    for entry in &manifest.entries {
        append_manifest_entry(&mut builder, entry, options.preserve_metadata, &mut report, context.as_deref_mut())?;
    }

    let encoder = builder.into_inner().map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;
    encoder.finish().map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;
    output.commit_with_file_replace(options.replace_existing).map_err(|source| TarZstdError::Io { path: destination.to_path_buf(), source })?;

    Ok(report)
}
fn append_manifest_entry<W: io::Write>(
    builder: &mut Builder<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut TarZstdCreateReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), TarZstdError> {
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
        context.entry_started(&entry.archive_path, Some(entry.size));
        context.check_cancelled()?;
    }

    // A PAX mtime record applies to the *next* member in the stream, so it is
    // written per branch, once this entry is certain to produce a member.
    // Writing it up front left a skipped member's timestamp attached to
    // whichever member happened to follow it.
    let processed = match entry.file_type {
        ManifestFileType::Directory => {
            append_manifest_mtime(builder, entry, preserve_metadata)?;
            if preserve_metadata {
                builder.append_dir(&entry.archive_path, &entry.source_path).map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })?;
            } else {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, io::empty())
                    .map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })?;
            }
            report.written_entries += 1;
            0
        }
        ManifestFileType::File => {
            // The header promises a length before the bytes are written, so the
            // member must be exactly that long even if the file moves underneath
            // us. `append_path_with_name`/`append_file` copy to EOF and pad from
            // the actual length instead, which shifts every later header and
            // silently truncates the archive at this member.
            let Some(mut source) = open_member_source(&entry.source_path, &mut report.warnings) else {
                return Ok(());
            };
            append_manifest_mtime(builder, entry, preserve_metadata)?;
            let mut header = Header::new_gnu();
            if preserve_metadata {
                let stat = source.metadata().map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })?;
                header.set_metadata(&stat);
            } else {
                header.set_mode(0o644);
                header.set_mtime(0);
            }
            header.set_entry_type(EntryType::Regular);
            header.set_size(entry.size);
            header.set_cksum();
            let mut exact = ExactLengthReader::new(&mut source, entry.size);
            builder.append_data(&mut header, &entry.archive_path, &mut exact).map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })?;
            let (padded, grew) = (exact.padded(), exact.grew());
            if let Some(note) = changed_during_read_note(&entry.archive_path, entry.size, padded, grew) {
                report.warnings.push(note);
            }
            report.written_entries += 1;
            report.written_bytes += entry.size;
            if let Some(context) = context.as_deref_mut() {
                context.bytes_processed(Some(&entry.archive_path), entry.size);
            }
            entry.size
        }
        ManifestFileType::Symlink => {
            let Some(target) = &entry.symlink_target else {
                let warning = format!("skipped symlink {}: missing target", entry.archive_path);
                report.warnings.push(warning.clone());
                if let Some(context) = context.as_deref_mut() {
                    context.warning(warning);
                    context.entry_finished(&entry.archive_path, 0);
                }
                return Ok(());
            };
            append_manifest_mtime(builder, entry, preserve_metadata)?;
            append_symlink(builder, entry, target, preserve_metadata)?;
            report.written_entries += 1;
            0
        }
        ManifestFileType::Other => {
            let warning = format!("skipped special file {}: TAR.ZST backend only writes files, directories, and symlinks", entry.archive_path);
            report.warnings.push(warning.clone());
            if let Some(context) = context.as_deref_mut() {
                context.warning(warning);
            }
            0
        }
    };

    if let Some(context) = context {
        context.entry_finished(&entry.archive_path, processed);
    }

    Ok(())
}

/// Writes this entry's PAX `mtime` record, when tar needs one.
///
/// A PAX extension header applies to the member that *follows* it, so the
/// caller must already be committed to writing that member. Call this only
/// after the last point at which the entry can still be skipped, never before
/// one -- a record with no member of its own silently retimes the next file.
fn append_manifest_mtime<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, preserve_metadata: bool) -> Result<(), TarZstdError> {
    if !preserve_metadata {
        return Ok(());
    }
    crate::tar_metadata::append_pax_mtime(builder, entry.modified).map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })
}

fn append_symlink<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, target: &Path, preserve_metadata: bool) -> Result<(), TarZstdError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    if preserve_metadata && let Some(mode) = entry.permissions.unix_mode {
        header.set_mode(mode & crate::extract_materialize::MODE_MASK);
    }
    if preserve_metadata && let Some(modified) = entry.modified.and_then(crate::tar_metadata::system_time_to_unix_seconds) {
        header.set_mtime(modified);
    }
    if !preserve_metadata {
        header.set_mode(0o777);
        header.set_mtime(0);
    }
    builder.append_link(&mut header, &entry.archive_path, target).map_err(|source| TarZstdError::Io { path: entry.source_path.clone(), source })
}

// See `crate::parallelism::available_parallelism_at_least_two`.
#[cfg(test)]
mod tests {
    use super::{TarZstdCreateOptions, create_tar_zst_from_path};
    use crate::jobs::CancellationToken;
    use crate::safety::{ExtractionPolicy, OverwritePolicy, OverwriteResolver};
    use crate::test_support::TestDir;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::Path;
    use std::time::UNIX_EPOCH;

    /// Extracts through the public engine seam (the only read path).
    fn extract_via_engine(
        archive: &Path,
        destination: &Path,
        policy: ExtractionPolicy,
        cancellation: Option<CancellationToken>,
    ) -> Result<crate::engine::ExtractReport, crate::engine::ArchiveError> {
        let mut handle = crate::engine::create_default_engine()
            .unwrap()
            .open(crate::engine::ArchiveSource::Path(archive.to_path_buf()), crate::engine::OpenOptions::default())
            .unwrap();
        let mut options =
            crate::engine::ExtractOptions { destination: destination.to_path_buf(), policy, cancellation, ..crate::engine::ExtractOptions::default() };
        handle.extract(&mut options)
    }

    struct CancellingResolver(CancellationToken);
    impl OverwriteResolver for CancellingResolver {
        fn decide(&mut self, _conflict: &crate::safety::OverwriteConflict) -> crate::safety::OverwriteDecision {
            self.0.cancel();
            crate::safety::OverwriteDecision::Skip
        }
    }

    #[test]
    fn creates_and_extracts_tar_zst() {
        let temp = TestDir::new("creates_and_extracts_tar_zst");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        temp.write_file("project/hello cafe.txt", b"unicode");
        let archive = temp.path("archive.tar.zst");

        let create_report = create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions::default()).unwrap();
        let extract_report = extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        assert_eq!(create_report.level, 3);
        assert_eq!(create_report.written_entries, 5);
        assert_eq!(extract_report.written_entries, 5);
        assert_eq!(fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(), "fn main() {}\n");
        assert_eq!(fs::read_to_string(temp.path("out/project/hello cafe.txt")).unwrap(), "unicode");
        assert!(temp.path("out/project/empty").is_dir());
    }

    // The permission-mode and symlink assertions are Unix-only and the source
    // path and extracted metadata bindings are only meaningfully exercised
    // there, so the whole test is gated instead of sprinkling
    // `unused_variables` allows.
    #[cfg(unix)]
    #[test]

    fn preserves_metadata_during_creation_and_extraction() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TestDir::new("preserves_metadata_tar_zst");
        let (path, _fixture_mtime) = crate::test_support::script_fixture_with_metadata(&temp);
        fs::set_permissions(temp.path("project"), fs::Permissions::from_mode(0o1750)).unwrap();

        // Add a symlink to test symlink metadata
        std::os::unix::fs::symlink("script.sh", temp.path("project/link.sh")).unwrap();
        // Set a specific mtime on the symlink
        let time = filetime::FileTime::from_unix_time(1_500_000_000, 234_567_890);
        filetime::set_file_mtime(&path, time).unwrap();
        filetime::set_symlink_file_times(temp.path("project/link.sh"), time, time).unwrap();

        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions { preserve_metadata: true, ..TarZstdCreateOptions::default() }).unwrap();

        extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let out_path = temp.path("out/project/script.sh");
        let metadata = fs::metadata(&out_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        let directory_metadata = fs::metadata(temp.path("out/project")).unwrap();
        assert_eq!(directory_metadata.permissions().mode() & 0o7777, 0o1750);
        assert_eq!(metadata.mtime(), 1_500_000_000);
        assert_eq!(metadata.mtime_nsec(), 234_567_890);

        // Verify symlink metadata
        let link_metadata = fs::symlink_metadata(temp.path("out/project/link.sh")).unwrap();
        let link_mtime = filetime::FileTime::from_last_modification_time(&link_metadata);
        assert!(link_metadata.is_symlink());
        assert_eq!(link_mtime.unix_seconds(), 1_500_000_000);
        assert_eq!(link_mtime.nanoseconds(), 234_567_890);
    }

    #[cfg(unix)]
    #[test]
    fn preserves_pre_epoch_modification_time() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("preserves_pre_epoch_mtime_tar_zst");
        temp.write_file("project/old.txt", b"old");
        let source = temp.path("project/old.txt");
        filetime::set_file_mtime(&source, filetime::FileTime::from_unix_time(-2, 750_000_000)).unwrap();
        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions::default()).unwrap();
        extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let metadata = fs::metadata(temp.path("out/project/old.txt")).unwrap();
        assert_eq!(metadata.mtime(), -2);
        assert_eq!(metadata.mtime_nsec(), 750_000_000);
    }

    #[test]

    fn accepts_custom_compression_level_and_thread_count() {
        let temp = TestDir::new("accepts_custom_compression_level_and_thread_count");
        temp.write_file("project/file.txt", b"content");
        let archive = temp.path("archive.tar.zst");
        let options = TarZstdCreateOptions { level: 1, threads: Some(1), preserve_metadata: true, replace_existing: false };

        let report = create_tar_zst_from_path(temp.path("project"), archive, &options).unwrap();

        assert_eq!(report.level, 1);
        assert_eq!(report.threads, Some(1));
    }

    #[test]
    fn handles_larger_files() {
        let temp = TestDir::new("handles_larger_files_tar_zst");
        let contents = vec![b'x'; 1024 * 1024];
        temp.write_file("project/large.bin", &contents);
        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions::default()).unwrap();
        extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        assert_eq!(fs::read(temp.path("out/project/large.bin")).unwrap(), contents);
    }

    #[test]
    fn cancelled_extraction_removes_partial_file_output() {
        let temp = TestDir::new("cancelled_extraction_removes_partial_file_output_tar_zst");
        let contents = vec![b'x'; crate::DEFAULT_IO_BUFFER_BYTES * 4];
        temp.write_file("project/large.bin", &contents);
        temp.write_file("project/second.bin", &contents);
        let archive = temp.path("archive.tar.zst");
        create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions::default()).unwrap();

        // Pre-create a conflicting destination entry and cancel through the
        // overwrite resolver: the extraction loop observes the cancelled token
        // at the next entry boundary, leaves the pre-existing file untouched,
        // and writes no later entries or temporary output.
        temp.write_file("out/project/large.bin", b"original");
        let token = CancellationToken::new();

        let mut resolver = CancellingResolver(token.clone());

        let mut handle =
            crate::engine::create_default_engine().unwrap().open(crate::engine::ArchiveSource::Path(archive), crate::engine::OpenOptions::default()).unwrap();
        let mut options = crate::engine::ExtractOptions {
            destination: temp.path("out").clone(),
            policy: ExtractionPolicy { overwrite: OverwritePolicy::Ask, ..ExtractionPolicy::default() },
            cancellation: Some(token),
            overwrite_resolver: Some(&mut resolver),
            ..crate::engine::ExtractOptions::default()
        };
        let error = handle.extract(&mut options).unwrap_err();

        assert_eq!(error.kind, crate::engine::ErrorKind::Cancelled);
        assert_eq!(fs::read(temp.path("out/project/large.bin")).unwrap(), b"original");
        assert!(!temp.path("out/project/second.bin").exists());
        assert!(!contains_temporary_output(&temp.path("out/project")));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_symlinks() {
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;

        let temp = TestDir::new("preserves_symlinks");
        temp.write_file("project/target.txt", b"target");
        symlink("target.txt", temp.path("project/link.txt")).unwrap();
        let archive = temp.path("archive.tar.zst");

        create_tar_zst_from_path(temp.path("project"), &archive, &TarZstdCreateOptions::default()).unwrap();
        extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let metadata = fs::symlink_metadata(temp.path("out/project/link.txt")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_eq!(fs::read_link(temp.path("out/project/link.txt")).unwrap(), PathBuf::from("target.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn extracts_hardlinks_inside_destination() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("extracts_hardlinks_inside_destination_tar_zst");
        let archive = temp.path("archive.tar.zst");
        write_tar_zst_with_hardlink(&archive, "project/target.txt", "project/link.txt", b"target");

        let report = extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let target = temp.path("out/project/target.txt");
        let link = temp.path("out/project/link.txt");
        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::read(&link).unwrap(), b"target");
        assert_eq!(fs::metadata(&target).unwrap().ino(), fs::metadata(&link).unwrap().ino());
    }

    #[cfg(unix)]
    #[test]
    fn extracts_forward_hardlinks_inside_destination() {
        use std::os::unix::fs::MetadataExt;

        let temp = TestDir::new("extracts_forward_hardlinks_inside_destination_tar_zst");
        let archive = temp.path("archive.tar.zst");
        write_tar_zst_with_forward_hardlink(&archive, "project/target.txt", "project/link.txt", b"target");

        let report = extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        let target = temp.path("out/project/target.txt");
        let link = temp.path("out/project/link.txt");
        assert_eq!(report.written_entries, 2);
        assert_eq!(fs::read(&link).unwrap(), b"target");
        assert_eq!(fs::metadata(&target).unwrap().ino(), fs::metadata(&link).unwrap().ino());
    }

    #[test]
    fn extraction_skips_archive_root_directory_entries() {
        let temp = TestDir::new("extracts_tar_zst_with_root_directory");
        let archive = temp.path("archive.tar.zst");
        write_tar_zst_with_root_directory(&archive, "payload/file.txt", b"payload");

        let report = extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap();

        assert_eq!(report.written_entries, 1);
        assert_eq!(report.skipped_entries, 1);
        assert_eq!(fs::read(temp.path("out/payload/file.txt")).unwrap(), b"payload");
        assert!(report.warnings.iter().any(|warning| warning == "skipped archive root directory entry"));
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal_tar_zst");
        let archive = temp.path("archive.tar.zst");
        write_raw_tar_zst(&archive, "../escape.txt", b"escape");

        let error = extract_via_engine(&archive, &temp.path("out"), ExtractionPolicy::default(), None).unwrap_err();

        assert_eq!(error.kind, crate::engine::ErrorKind::SafetyViolation);
    }

    #[test]
    fn converts_system_time_to_unix_seconds() {
        assert_eq!(crate::tar_metadata::system_time_to_unix_seconds(UNIX_EPOCH), Some(0));
    }

    fn write_raw_tar_zst(path: &Path, entry_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let header = raw_tar_header(entry_path, contents.len().try_into().unwrap());

        encoder.write_all(&header).unwrap();
        encoder.write_all(contents).unwrap();

        let padding_len = (512 - (contents.len() % 512)) % 512;
        encoder.write_all(&vec![0; padding_len]).unwrap();
        encoder.write_all(&[0; 1024]).unwrap();
        encoder.finish().unwrap();
    }

    #[cfg(unix)]
    fn write_tar_zst_with_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder.append_data(&mut file_header, target_path, contents).unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_mtime(0);
        link_header.set_cksum();
        builder.append_link(&mut link_header, link_path, Path::new(target_path)).unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    #[cfg(unix)]
    fn write_tar_zst_with_forward_hardlink(path: &Path, target_path: &str, link_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_mtime(0);
        link_header.set_cksum();
        builder.append_link(&mut link_header, link_path, Path::new(target_path)).unwrap();

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder.append_data(&mut file_header, target_path, contents).unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn write_tar_zst_with_root_directory(path: &Path, entry_path: &str, contents: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut root_header = tar::Header::new_gnu();
        root_header.set_entry_type(tar::EntryType::Directory);
        root_header.set_size(0);
        root_header.set_mode(0o755);
        root_header.set_mtime(0);
        root_header.set_cksum();
        builder.append_data(&mut root_header, ".", io::empty()).unwrap();

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len().try_into().unwrap());
        file_header.set_mode(0o644);
        file_header.set_mtime(0);
        file_header.set_cksum();
        builder.append_data(&mut file_header, entry_path, contents).unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn contains_temporary_output(path: &Path) -> bool {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        entries.filter_map(Result::ok).any(|entry| entry.file_name().to_string_lossy().starts_with(".zmanager-"))
    }

    fn raw_tar_header(path: &str, size: u64) -> [u8; 512] {
        let mut header = [0_u8; 512];

        write_bytes(&mut header[0..100], path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        write_bytes(&mut header[257..263], b"ustar\0");
        write_bytes(&mut header[263..265], b"00");

        let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
        write_checksum(&mut header[148..156], checksum);

        header
    }

    fn write_bytes(destination: &mut [u8], source: &[u8]) {
        let len = destination.len().min(source.len());
        destination[..len].copy_from_slice(&source[..len]);
    }

    fn write_octal(destination: &mut [u8], value: u64) {
        let encoded = format!("{value:0width$o}\0", width = destination.len() - 1);
        write_bytes(destination, encoded.as_bytes());
    }

    fn write_checksum(destination: &mut [u8], value: u32) {
        let encoded = format!("{value:06o}\0 ");
        write_bytes(destination, encoded.as_bytes());
    }
}
crate::backend_error_from_impls!(TarZstdError);
