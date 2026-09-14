//! Native `.tar.gz` / `.tgz` archive creation.

use crate::backend_impl::backend_report::open_member_source;
use crate::jobs::{JobCancelled, JobContext};
use crate::manifest::{ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive};
use crate::safety::ExtractionSafetyError;
use crate::tar_metadata::{ExactLengthReader, changed_during_read_note};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};

/// Options for `.tar.gz` / `.tgz` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzCreateOptions {
    /// Gzip compression level (0-9).
    pub level: i32,
    /// Preserve portable metadata such as mode bits and modification time.
    pub preserve_metadata: bool,
    /// Replace an existing destination archive at commit time.
    pub replace_existing: bool,
}

impl Default for TarGzCreateOptions {
    fn default() -> Self {
        Self { level: 6, preserve_metadata: true, replace_existing: false }
    }
}

/// Creation report returned by the `.tar.gz` / `.tgz` writer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarGzCreateReport {
    /// Entries written to the archive.
    pub written_entries: usize,
    /// Sum of uncompressed file bytes written.
    pub written_bytes: u64,
    /// Compression level used.
    pub level: i32,
    /// Non-fatal creation warnings.
    pub warnings: Vec<String>,
}

/// Error returned by the `.tar.gz` / `.tgz` creator.
#[derive(Debug)]
pub enum TarGzError {
    /// Archive planning failed.
    Plan(PlanError),
    /// Gzip compression level is outside the supported 0-9 range.
    InvalidLevel {
        level: i32,
    },
    /// Filesystem or stream I/O failed.
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Safety(ExtractionSafetyError),
    /// The job was cancelled.
    Cancelled,
}

impl fmt::Display for TarGzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(err) => write!(f, "planning failed: {err}"),
            Self::InvalidLevel { level } => write!(f, "invalid gzip compression level {level}: expected 0-9"),
            Self::Io { path, source } => {
                write!(f, "I/O failed for {}: {source}", path.display())
            }
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for TarGzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Cancelled | Self::InvalidLevel { .. } => None,
        }
    }
}

impl From<PlanError> for TarGzError {
    fn from(value: PlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<JobCancelled> for TarGzError {
    fn from(_value: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl From<ExtractionSafetyError> for TarGzError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Creates a `.tar.gz` / `.tgz` archive from a source path.
///
/// # Errors
///
/// Returns [`TarGzError`] when planning fails, files cannot be read, or writing fails.
pub fn create_tar_gz_from_path(source: impl AsRef<Path>, destination: impl AsRef<Path>, options: &TarGzCreateOptions) -> Result<TarGzCreateReport, TarGzError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;
    create_tar_gz_from_manifest(&manifest, destination, options)
}

/// Creates a `.tar.gz` / `.tgz` archive from a manifest.
///
/// # Errors
///
/// Returns [`TarGzError`] when source files cannot be read, tar writing fails,
/// or gzip compression fails.
pub fn create_tar_gz_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
) -> Result<TarGzCreateReport, TarGzError> {
    create_tar_gz_from_manifest_inner(manifest, destination, options, None)
}

/// Creates a `.tar.gz` / `.tgz` archive from a manifest while emitting job events.
///
/// # Errors
///
/// Returns [`TarGzError`] when source files cannot be read, tar writing fails,
/// gzip compression fails, or cancellation is requested.
pub fn create_tar_gz_from_manifest_with_context(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
    context: &mut JobContext<'_>,
) -> Result<TarGzCreateReport, TarGzError> {
    create_tar_gz_from_manifest_inner(manifest, destination, options, Some(context))
}

fn create_tar_gz_from_manifest_inner(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &TarGzCreateOptions,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<TarGzCreateReport, TarGzError> {
    let destination = destination.as_ref();
    // flate2's level is a u32 with an internal 0-9 contract; a negative i32
    // bit-cast would silently produce a huge level, so reject out-of-range
    // values up front (the CLI validates at parse time too).
    if !(0..=9).contains(&options.level) {
        return Err(TarGzError::InvalidLevel { level: options.level });
    }
    let mut output = crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    let file = output.file_mut().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;

    let encoder = GzEncoder::new(file, Compression::new(options.level.cast_unsigned()));
    let mut builder = Builder::new(encoder);
    builder.follow_symlinks(false);
    let mut report = TarGzCreateReport { written_entries: 0, written_bytes: 0, level: options.level, warnings: Vec::new() };

    for entry in &manifest.entries {
        append_manifest_entry(&mut builder, entry, options.preserve_metadata, &mut report, context.as_deref_mut())?;
    }

    let encoder = builder.into_inner().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    encoder.finish().map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;
    output.commit_with_file_replace(options.replace_existing).map_err(|source| TarGzError::Io { path: destination.to_path_buf(), source })?;

    Ok(report)
}
fn append_manifest_entry<W: io::Write>(
    builder: &mut Builder<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut TarGzCreateReport,
    mut context: Option<&mut JobContext<'_>>,
) -> Result<(), TarGzError> {
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
        context.entry_started(&entry.archive_path, Some(entry.size));
        context.check_cancelled()?;
    }

    append_manifest_mtime(builder, entry, preserve_metadata)?;

    let processed = match entry.file_type {
        ManifestFileType::Directory => {
            if preserve_metadata {
                builder.append_dir(&entry.archive_path, &entry.source_path).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
            } else {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.archive_path, io::empty())
                    .map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
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
            let mut header = Header::new_gnu();
            if preserve_metadata {
                let stat = source.metadata().map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
                header.set_metadata(&stat);
            } else {
                header.set_mode(0o644);
                header.set_mtime(0);
            }
            header.set_entry_type(EntryType::Regular);
            header.set_size(entry.size);
            header.set_cksum();
            let mut exact = ExactLengthReader::new(&mut source, entry.size);
            builder.append_data(&mut header, &entry.archive_path, &mut exact).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })?;
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
            append_symlink(builder, entry, target, preserve_metadata)?;
            report.written_entries += 1;
            0
        }
        ManifestFileType::Other => {
            let warning = format!("skipped special file {}: tar.gz backend only writes files, directories, and symlinks", entry.archive_path);
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

fn append_manifest_mtime<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, preserve_metadata: bool) -> Result<(), TarGzError> {
    if !preserve_metadata || entry.file_type == ManifestFileType::Other {
        return Ok(());
    }
    crate::tar_metadata::append_pax_mtime(builder, entry.modified).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })
}

fn append_symlink<W: io::Write>(builder: &mut Builder<W>, entry: &ManifestEntry, target: &Path, preserve_metadata: bool) -> Result<(), TarGzError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    if preserve_metadata && let Some(mode) = entry.permissions.unix_mode {
        header.set_mode(mode & 0o7777);
    }
    if preserve_metadata && let Some(modified) = entry.modified.and_then(crate::tar_metadata::system_time_to_unix_seconds) {
        header.set_mtime(modified);
    }
    if !preserve_metadata {
        header.set_mode(0o777);
        header.set_mtime(0);
    }
    builder.append_link(&mut header, &entry.archive_path, target).map_err(|source| TarGzError::Io { path: entry.source_path.clone(), source })
}

#[cfg(test)]
mod tests {
    use super::{TarGzCreateOptions, create_tar_gz_from_path};
    use crate::test_support::TestDir;
    use std::fs::{self, File};
    use std::time::SystemTime;

    /// Extracts through the public engine seam (the only read path).
    fn extract_via_engine(archive: &std::path::Path, destination: &std::path::Path) -> crate::engine::ExtractReport {
        let mut handle = crate::engine::create_default_engine()
            .unwrap()
            .open(crate::engine::ArchiveSource::Path(archive.to_path_buf()), crate::engine::OpenOptions::default())
            .unwrap();
        let mut options = crate::engine::ExtractOptions { destination: destination.to_path_buf(), ..crate::engine::ExtractOptions::default() };
        handle.extract(&mut options).unwrap()
    }

    #[test]
    fn creates_and_extracts_tar_gz() {
        let temp = TestDir::new("creates_and_extracts_tar_gz");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.create_dir("project/empty");
        temp.write_file("project/hello cafe.txt", b"unicode");
        let archive = temp.path("archive.tar.gz");

        let create_report = create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions::default()).unwrap();

        let extract_report = extract_via_engine(&archive, &temp.path("out"));

        assert_eq!(create_report.level, 6);
        assert_eq!(create_report.written_entries, 5);
        assert_eq!(extract_report.written_entries, 5);
        assert_eq!(fs::read_to_string(temp.path("out/project/src/main.rs")).unwrap(), "fn main() {}\n");
    }

    #[test]
    fn respects_preserve_metadata_true() {
        let temp = TestDir::new("respects_preserve_metadata_true");
        let file_path = temp.path("project/file.txt");
        temp.write_file("project/file.txt", b"content");

        // Set a specific mod time
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::new(12_345_678, 345_678_901);
        filetime::set_file_mtime(&file_path, filetime::FileTime::from_system_time(mtime)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let archive = temp.path("archive.tar.gz");

        create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { preserve_metadata: true, ..TarGzCreateOptions::default() }).unwrap();

        // Inspect the headers directly
        let file = File::open(&archive).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut tar_archive = tar::Archive::new(decoder);
        let entries = tar_archive.entries().unwrap();

        let mut found_file = false;
        for entry_res in entries {
            let entry = entry_res.unwrap();
            let path = entry.path().unwrap();
            if path.ends_with("file.txt") {
                found_file = true;
                let header = entry.header();
                assert_eq!(header.mtime().unwrap(), 12_345_678);
                #[cfg(unix)]
                {
                    assert_eq!(header.mode().unwrap() & 0o777, 0o755);
                }
            }
        }
        assert!(found_file);

        extract_via_engine(&archive, &temp.path("out"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(temp.path("out/project/file.txt")).unwrap();
            assert_eq!(metadata.mtime(), 12_345_678);
            assert_eq!(metadata.mtime_nsec(), 345_678_901);
        }
    }

    #[test]
    fn respects_preserve_metadata_false() {
        let temp = TestDir::new("respects_preserve_metadata_false");
        let file_path = temp.path("project/file.txt");
        temp.write_file("project/file.txt", b"content");

        // Set a specific mod time
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12_345_678);
        filetime::set_file_mtime(&file_path, filetime::FileTime::from_system_time(mtime)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let archive = temp.path("archive.tar.gz");

        create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { preserve_metadata: false, ..TarGzCreateOptions::default() }).unwrap();

        // Inspect the headers directly
        let file = File::open(&archive).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut tar_archive = tar::Archive::new(decoder);
        let entries = tar_archive.entries().unwrap();

        let mut found_file = false;
        for entry_res in entries {
            let entry = entry_res.unwrap();
            let path = entry.path().unwrap();
            if path.ends_with("file.txt") {
                found_file = true;
                let header = entry.header();
                // mtime is cleared to 0 (unix epoch)
                assert_eq!(header.mtime().unwrap(), 0);
                // mode defaults to 0o644 for files
                assert_eq!(header.mode().unwrap() & 0o777, 0o644);
            }
        }
        assert!(found_file);
    }

    #[test]
    fn respects_custom_compression_level() {
        let temp = TestDir::new("respects_custom_compression_level");
        temp.write_file("project/file.txt", b"content");
        let archive = temp.path("archive.tar.gz");

        let report = create_tar_gz_from_path(temp.path("project"), &archive, &TarGzCreateOptions { level: 3, ..TarGzCreateOptions::default() }).unwrap();

        assert_eq!(report.level, 3);
    }
}
