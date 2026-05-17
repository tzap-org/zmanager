use crate::manifest::{
    ArchiveManifest, ManifestEntry, ManifestFileType, PlanError, PlanOptions, plan_archive,
};
use crate::safety::{
    ExtractionDecision, ExtractionEntry, ExtractionEntryKind, ExtractionPolicy,
    ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver,
};
use crate::secrets::SecretString;
use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
use sevenz_rust2::{
    Archive, ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderMethod, Password, SourceReader,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

/// Options for `.7z` creation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZCreateOptions {
    /// Whether regular files should be packed into a solid block.
    pub solid: bool,
    /// Compression level for LZMA2 where supported.
    pub level: Option<u32>,
    /// Preserve timestamps and attributes exposed by the 7z backend.
    pub preserve_metadata: bool,
    /// Optional AES password. Empty strings are treated as no password.
    pub password: Option<SecretString>,
}

impl Default for SevenZCreateOptions {
    fn default() -> Self {
        Self {
            solid: true,
            level: None,
            preserve_metadata: true,
            password: None,
        }
    }
}

/// Summary of a created `.7z` archive.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZCreateReport {
    /// Number of archive entries written.
    pub written_entries: usize,
    /// Number of source bytes copied into file entries.
    pub written_bytes: u64,
    /// Whether solid compression was requested.
    pub solid: bool,
    /// Whether AES encryption was enabled.
    pub encrypted: bool,
    /// Non-fatal creation warnings.
    pub warnings: Vec<String>,
}

/// One `.7z` listing entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZListEntry {
    /// Raw path reported by the 7z archive.
    pub name: String,
    /// Entry kind.
    pub kind: SevenZEntryKind,
    /// Uncompressed size.
    pub size: u64,
    /// Compressed size when reported by the backend.
    pub compressed_size: u64,
    /// Whether the entry has a data stream.
    pub has_stream: bool,
}

/// Portable 7z entry type exposed by the backend.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SevenZEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// 7z anti-item marker.
    AntiItem,
}

/// Archive listing returned by the 7z backend.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZListing {
    /// Entries in archive order.
    pub entries: Vec<SevenZListEntry>,
    /// Whether the archive is solid.
    pub solid: bool,
}

/// Extraction report returned by the 7z backend.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SevenZExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped.
    pub skipped_entries: usize,
    /// File bytes copied from the archive.
    pub written_bytes: u64,
    /// Non-fatal extraction warnings.
    pub warnings: Vec<String>,
}

/// Error returned by the 7z backend.
#[derive(Debug)]
pub enum SevenZError {
    /// Manifest planning failed.
    Plan(PlanError),
    /// The 7z crate returned an error.
    SevenZ(sevenz_rust2::Error),
    /// A password is required to read encrypted 7z data.
    PasswordRequired,
    /// The supplied password did not decrypt 7z data.
    InvalidPassword,
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
}

impl fmt::Display for SevenZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::SevenZ(source) => write!(f, "7z operation failed: {source}"),
            Self::PasswordRequired => write!(f, "password required to decrypt 7z data"),
            Self::InvalidPassword => write!(f, "provided 7z password is incorrect"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
        }
    }
}

impl std::error::Error for SevenZError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::SevenZ(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::PasswordRequired | Self::InvalidPassword => None,
        }
    }
}

impl From<PlanError> for SevenZError {
    fn from(source: PlanError) -> Self {
        Self::Plan(source)
    }
}

impl From<sevenz_rust2::Error> for SevenZError {
    fn from(source: sevenz_rust2::Error) -> Self {
        map_7z_error(source)
    }
}

impl From<ExtractionSafetyError> for SevenZError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

/// Creates a `.7z` archive from a source path.
///
/// # Errors
///
/// Returns [`SevenZError`] when planning, filesystem reads, or 7z writing fails.
pub fn create_7z_from_path(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
) -> Result<SevenZCreateReport, SevenZError> {
    let manifest = plan_archive(source, &PlanOptions::default())?;

    create_7z_from_manifest(&manifest, destination, options)
}

/// Creates a `.7z` archive from a manifest.
///
/// # Errors
///
/// Returns [`SevenZError`] when source files cannot be read or 7z writing fails.
pub fn create_7z_from_manifest(
    manifest: &ArchiveManifest,
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
) -> Result<SevenZCreateReport, SevenZError> {
    let destination = destination.as_ref();
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination).map_err(|source| {
            SevenZError::Io {
                path: destination.to_path_buf(),
                source,
            }
        })?;
    let output_file = output.file_mut().map_err(|source| SevenZError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    let mut writer = ArchiveWriter::new(output_file)?;
    let encrypted = configure_content_methods(&mut writer, options);
    let mut report = SevenZCreateReport {
        written_entries: 0,
        written_bytes: 0,
        solid: options.solid,
        encrypted,
        warnings: Vec::new(),
    };

    if options.solid {
        write_solid_manifest(
            &mut writer,
            manifest,
            options.preserve_metadata,
            &mut report,
        )?;
    } else {
        write_non_solid_manifest(
            &mut writer,
            manifest,
            options.preserve_metadata,
            &mut report,
        )?;
    }

    writer.finish().map_err(|source| SevenZError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    output.commit().map_err(|source| SevenZError::Io {
        path: destination.to_path_buf(),
        source,
    })?;

    Ok(report)
}

/// Lists `.7z` archive entries.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be opened or parsed.
pub fn list_7z(
    path: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<SevenZListing, SevenZError> {
    let path = path.as_ref();
    let password = archive_password(password);
    let mut file = File::open(path).map_err(|source| SevenZError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let archive = Archive::read(&mut file, &password)?;
    let entries = archive
        .files
        .iter()
        .map(|entry| SevenZListEntry {
            name: entry.name().to_owned(),
            kind: entry_kind(entry),
            size: entry.size(),
            compressed_size: entry.compressed_size,
            has_stream: entry.has_stream(),
        })
        .collect();

    Ok(SevenZListing {
        entries,
        solid: archive.is_solid,
    })
}

/// Extracts a `.7z` archive through the shared extraction safety policy.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, or filesystem writes fail.
pub fn extract_7z(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(archive_path, destination, password, policy, None)
}

/// Extracts a `.7z` archive with an overwrite resolver.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, an entry is unsafe,
/// password validation fails, filesystem writes fail, or the resolver aborts
/// extraction.
pub fn extract_7z_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<SevenZExtractReport, SevenZError> {
    extract_7z_inner(
        archive_path,
        destination,
        password,
        policy,
        Some(overwrite_resolver),
    )
}

fn extract_7z_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<SevenZExtractReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| SevenZError::Io {
            path: destination.to_path_buf(),
            source,
        })?;

    let file = File::open(archive_path).map_err(|source| SevenZError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let password = archive_password(password);
    let mut reader = ArchiveReader::new(file, password)?;
    let decisions = plan_extraction(
        reader.archive().files.as_slice(),
        &destination_root,
        policy,
        overwrite_resolver,
    )?;
    let mut report = SevenZExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut callback_error = None;

    let result = reader.for_each_entries(|entry, entry_reader| {
        match extract_entry(entry, entry_reader, &decisions, &mut report) {
            Ok(()) => Ok(true),
            Err(error) => {
                callback_error = Some(error);
                Err(callback_failed_error())
            }
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;

    Ok(report)
}

/// Copies selected regular `.7z` file entries to a writer in archive order.
///
/// # Errors
///
/// Returns [`SevenZError`] when the archive cannot be read, a password is
/// missing/incorrect, or output writing fails.
pub fn copy_7z_files_to_writer<W: Write>(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    mut selected: impl FnMut(&str) -> bool,
    output: &mut W,
) -> Result<SevenZExtractReport, SevenZError> {
    let archive_path = archive_path.as_ref();
    let file = File::open(archive_path).map_err(|source| SevenZError::Io {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let password = archive_password(password);
    let mut reader = ArchiveReader::new(file, password)?;
    let mut report = SevenZExtractReport {
        written_entries: 0,
        skipped_entries: 0,
        written_bytes: 0,
        warnings: Vec::new(),
    };
    let mut callback_error = None;

    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_anti_item() || !selected(entry.name()) || entry.is_directory() {
            if let Err(error) = drain_reader(entry_reader, entry.name()) {
                callback_error = Some(error);
                return Err(callback_failed_error());
            }
            report.skipped_entries += 1;
            return Ok(true);
        }

        match io::copy(entry_reader, output) {
            Ok(copied) => {
                report.written_entries += 1;
                report.written_bytes += copied;
                Ok(true)
            }
            Err(source) => {
                callback_error = Some(SevenZError::Io {
                    path: PathBuf::from(entry.name()),
                    source,
                });
                Err(callback_failed_error())
            }
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    result?;

    Ok(report)
}

fn configure_content_methods<W: io::Write + io::Seek>(
    writer: &mut ArchiveWriter<W>,
    options: &SevenZCreateOptions,
) -> bool {
    let password = options
        .password
        .as_ref()
        .map(SecretString::expose_secret)
        .filter(|password| !password.is_empty());
    let level = options.level.map(Lzma2Options::from_level);

    match (password, level) {
        (Some(password), Some(level)) => {
            writer.set_content_methods(vec![
                AesEncoderOptions::new(Password::from(password)).into(),
                level.into(),
            ]);
            true
        }
        (Some(password), None) => {
            writer.set_content_methods(vec![
                AesEncoderOptions::new(Password::from(password)).into(),
                EncoderMethod::LZMA2.into(),
            ]);
            true
        }
        (None, Some(level)) => {
            writer.set_content_methods(vec![level.into()]);
            false
        }
        (None, None) => false,
    }
}

fn archive_password(password: Option<&str>) -> Password {
    password
        .filter(|password| !password.is_empty())
        .map_or_else(Password::empty, Password::from)
}

fn map_7z_error(source: sevenz_rust2::Error) -> SevenZError {
    match source {
        sevenz_rust2::Error::PasswordRequired => SevenZError::PasswordRequired,
        sevenz_rust2::Error::MaybeBadPassword(_) => SevenZError::InvalidPassword,
        source => SevenZError::SevenZ(source),
    }
}

fn write_non_solid_manifest<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    manifest: &ArchiveManifest,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
) -> Result<(), SevenZError> {
    for entry in &manifest.entries {
        append_non_solid_entry(writer, entry, preserve_metadata, report)?;
    }

    Ok(())
}

fn append_non_solid_entry<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    entry: &ManifestEntry,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
) -> Result<(), SevenZError> {
    match entry.file_type {
        ManifestFileType::Directory => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            writer.push_archive_entry::<&[u8]>(archive_entry, None)?;
            report.written_entries += 1;
        }
        ManifestFileType::File => {
            let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
            let file = File::open(&entry.source_path).map_err(|source| SevenZError::Io {
                path: entry.source_path.clone(),
                source,
            })?;
            writer.push_archive_entry(archive_entry, Some(file))?;
            report.written_entries += 1;
            report.written_bytes += entry.size;
        }
        ManifestFileType::Symlink => {
            report.warnings.push(format!(
                "skipped symlink {}: 7z backend does not materialize symlink entries in v1",
                entry.archive_path
            ));
        }
        ManifestFileType::Other => {
            report.warnings.push(format!(
                "skipped unsupported entry {}: 7z backend only writes files and directories in v1",
                entry.archive_path
            ));
        }
    }

    Ok(())
}

fn write_solid_manifest<W: Write + Seek>(
    writer: &mut ArchiveWriter<W>,
    manifest: &ArchiveManifest,
    preserve_metadata: bool,
    report: &mut SevenZCreateReport,
) -> Result<(), SevenZError> {
    let mut solid_entries = Vec::new();
    let mut solid_readers = Vec::new();

    for entry in &manifest.entries {
        match entry.file_type {
            ManifestFileType::Directory => {
                let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
                writer.push_archive_entry::<&[u8]>(archive_entry, None)?;
                report.written_entries += 1;
            }
            ManifestFileType::File => {
                let archive_entry = sevenz_archive_entry(entry, preserve_metadata);
                let file = File::open(&entry.source_path).map_err(|source| SevenZError::Io {
                    path: entry.source_path.clone(),
                    source,
                })?;
                solid_entries.push(archive_entry);
                solid_readers.push(SourceReader::new(file));
                report.written_entries += 1;
                report.written_bytes += entry.size;
            }
            ManifestFileType::Symlink => {
                report.warnings.push(format!(
                    "skipped symlink {}: 7z backend does not materialize symlink entries in v1",
                    entry.archive_path
                ));
            }
            ManifestFileType::Other => {
                report.warnings.push(format!(
                    "skipped unsupported entry {}: 7z backend only writes files and directories in v1",
                    entry.archive_path
                ));
            }
        }
    }

    if !solid_entries.is_empty() {
        writer.push_archive_entries(solid_entries, solid_readers)?;
    }

    Ok(())
}

fn sevenz_archive_entry(entry: &ManifestEntry, preserve_metadata: bool) -> ArchiveEntry {
    if preserve_metadata {
        return ArchiveEntry::from_path(&entry.source_path, entry.archive_path.clone());
    }

    match entry.file_type {
        ManifestFileType::Directory => ArchiveEntry::new_directory(&entry.archive_path),
        ManifestFileType::File | ManifestFileType::Symlink | ManifestFileType::Other => {
            ArchiveEntry::new_file(&entry.archive_path)
        }
    }
}

fn entry_kind(entry: &ArchiveEntry) -> SevenZEntryKind {
    if entry.is_anti_item() {
        SevenZEntryKind::AntiItem
    } else if entry.is_directory() {
        SevenZEntryKind::Directory
    } else {
        SevenZEntryKind::File
    }
}

fn plan_extraction(
    entries: &[ArchiveEntry],
    destination: &Path,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<HashMap<String, ExtractionDecision>, SevenZError> {
    let mut planner = match overwrite_resolver {
        Some(resolver) => {
            ExtractionSafetyPlanner::new_with_overwrite_resolver(destination, policy, resolver)
        }
        None => ExtractionSafetyPlanner::new(destination, policy),
    };
    let mut decisions = HashMap::with_capacity(entries.len());

    for entry in entries {
        if entry.is_anti_item() {
            continue;
        }

        let kind = if entry.is_directory() {
            ExtractionEntryKind::Directory
        } else {
            ExtractionEntryKind::File
        };
        let safety_entry = ExtractionEntry {
            archive_path: entry.name().to_owned(),
            kind,
            uncompressed_size: Some(entry.size()),
            compressed_size: (entry.compressed_size > 0).then_some(entry.compressed_size),
        };
        let decision = planner.validate_entry(&safety_entry)?;
        decisions.insert(entry.name().to_owned(), decision);
    }

    Ok(decisions)
}

fn extract_entry(
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
    decisions: &HashMap<String, ExtractionDecision>,
    report: &mut SevenZExtractReport,
) -> Result<(), SevenZError> {
    if entry.is_anti_item() {
        drain_reader(reader, entry.name())?;
        report.skipped_entries += 1;
        report
            .warnings
            .push(format!("skipped anti-item {}", entry.name()));
        return Ok(());
    }

    let decision = decisions
        .get(entry.name())
        .ok_or_else(|| missing_extraction_decision(entry.name()))?;
    match decision {
        ExtractionDecision::Write {
            destination_path,
            replace_existing,
            ..
        } => {
            if *replace_existing && entry.is_directory() {
                crate::safety::remove_destination_for_replace(destination_path).map_err(
                    |source| SevenZError::Io {
                        path: destination_path.clone(),
                        source,
                    },
                )?;
            }
            if entry.is_directory() {
                fs::create_dir_all(destination_path).map_err(|source| SevenZError::Io {
                    path: destination_path.clone(),
                    source,
                })?;
                report.written_entries += 1;
            } else {
                let written_bytes = write_file_entry(reader, destination_path, *replace_existing)?;
                report.written_entries += 1;
                report.written_bytes += written_bytes;
            }
        }
        ExtractionDecision::Skip { reason, .. } => {
            drain_reader(reader, entry.name())?;
            report.skipped_entries += 1;
            report
                .warnings
                .push(format!("skipped {}: {reason}", entry.name()));
        }
    }

    Ok(())
}

fn missing_extraction_decision(archive_path: &str) -> SevenZError {
    SevenZError::SevenZ(sevenz_rust2::Error::Other(Cow::Owned(format!(
        "missing extraction decision for {archive_path}"
    ))))
}

fn write_file_entry(
    reader: &mut dyn Read,
    destination_path: &Path,
    replace_existing: bool,
) -> Result<u64, SevenZError> {
    let mut output =
        crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| {
            SevenZError::Io {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
    let copied = io::copy(
        reader,
        output.file_mut().map_err(|source| SevenZError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?,
    )
    .map_err(|source| SevenZError::Io {
        path: destination_path.to_path_buf(),
        source,
    })?;
    output
        .commit_with_replace(replace_existing)
        .map_err(|source| SevenZError::Io {
            path: destination_path.to_path_buf(),
            source,
        })?;
    Ok(copied)
}

fn drain_reader(reader: &mut dyn Read, archive_path: &str) -> Result<(), SevenZError> {
    io::copy(reader, &mut io::sink()).map_err(|source| SevenZError::Io {
        path: PathBuf::from(archive_path),
        source,
    })?;
    Ok(())
}

fn callback_failed_error() -> sevenz_rust2::Error {
    sevenz_rust2::Error::Other(Cow::Borrowed("zmanager extraction callback failed"))
}

#[cfg(test)]
mod tests {
    use super::{
        SevenZCreateOptions, SevenZEntryKind, SevenZError, create_7z_from_path, extract_7z, list_7z,
    };
    use crate::safety::{ExtractionPolicy, ExtractionSafetyError};
    use crate::secrets::SecretString;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn creates_and_extracts_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        temp.create_dir("payload/empty");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions::default(),
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert!(report.solid);
        assert_eq!(report.written_bytes, 10);
        assert!(listing.solid);
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/file.txt")
        );
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.kind == SevenZEntryKind::Directory)
        );
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "hello"
        );
        assert!(temp.path("out/payload/empty").is_dir());
    }

    #[test]
    fn creates_and_extracts_non_solid_7z_archive() {
        let temp = TestDir::new("creates_and_extracts_non_solid_7z_archive");
        temp.write_file("payload/file.txt", b"hello");
        temp.write_file("payload/nested/second.txt", b"world");
        let archive = temp.path("payload.7z");

        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: None,
                preserve_metadata: true,
                password: None,
            },
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert!(!listing.solid);
        assert_eq!(extract_report.written_bytes, 10);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/nested/second.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn encrypted_archive_requires_correct_password() {
        let temp = TestDir::new("encrypted_archive_requires_correct_password");
        temp.write_file("payload/file.txt", b"secret");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: true,
                level: None,
                preserve_metadata: true,
                password: Some(SecretString::from("correct horse")),
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(matches!(
            list_7z(&archive, None),
            Err(SevenZError::PasswordRequired)
        ));
        assert!(matches!(
            extract_7z(
                &archive,
                temp.path("wrong"),
                Some("wrong password"),
                ExtractionPolicy::default()
            ),
            Err(SevenZError::InvalidPassword)
        ));

        let listing = list_7z(&archive, Some("correct horse")).unwrap();
        let extract_report = extract_7z(
            &archive,
            temp.path("out"),
            Some("correct horse"),
            ExtractionPolicy::default(),
        )
        .unwrap();

        assert_eq!(listing.entries.len(), 2);
        assert_eq!(extract_report.written_bytes, 6);
        assert_eq!(
            fs::read_to_string(temp.path("out/payload/file.txt")).unwrap(),
            "secret"
        );
    }

    #[test]
    fn extraction_rejects_traversal() {
        let temp = TestDir::new("extraction_rejects_traversal");
        let archive = temp.path("hostile.7z");
        let output = File::create(&archive).unwrap();
        let mut writer = sevenz_rust2::ArchiveWriter::new(output).unwrap();
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("../evil.txt"),
                Some(&b"owned"[..]),
            )
            .unwrap();
        writer.finish().unwrap();

        let error = extract_7z(
            &archive,
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            SevenZError::Safety(ExtractionSafetyError::ParentTraversal { .. })
        ));
        assert!(!temp.path("evil.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn creation_skips_symlinks_with_warning() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("creation_skips_symlinks_with_warning");
        temp.write_file("payload/file.txt", b"hello");
        symlink("file.txt", temp.path("payload/link.txt")).unwrap();
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions::default(),
        )
        .unwrap();
        let listing = list_7z(&archive, None).unwrap();

        assert_eq!(report.warnings.len(), 1);
        assert!(
            !listing
                .entries
                .iter()
                .any(|entry| entry.name == "payload/link.txt")
        );
    }

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("zmanager-{name}-{}-{now}", std::process::id()));
            fs::create_dir_all(&root).unwrap();

            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }

        fn create_dir(&self, relative: impl AsRef<Path>) {
            fs::create_dir_all(self.path(relative)).unwrap();
        }

        fn write_file(&self, relative: impl AsRef<Path>, contents: &[u8]) {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
