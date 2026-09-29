//! Windows Installer (`.msi`) extraction backend.
//!
//! An MSI file is a Compound File Binary (OLE) document holding a relational
//! database plus embedded binary streams. The `File` table declares every
//! file (key, display name, size, sequence); each file hangs off a component,
//! and the component's `Directory_` resolves where the file belongs on the
//! target; the `Media` table maps sequence ranges to embedded cabinet
//! streams. Per the MSI specification, files are stored in the cabinet under
//! their File-table *key*, so extraction reads each entry by key and
//! materializes it under the resolved target path.
//!
//! Only embedded cabinets (`Media.Cabinet` starting with `#`) are supported;
//! external cabinets and multi-cabinet spanning are skipped with a warning.
//! The MSI database has no symlink or directory entries, so every listed
//! entry is a regular file.

use crate::jobs::JobContext;
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner, OverwriteResolver};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

crate::backend_error_from_impls!(MsiBackendError);

/// Entry reported by [`list_msi`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MsiListEntry {
    /// Target-relative path inside the package (the `Directory` table
    /// resolves the folder; the `FileName` column supplies the leaf).
    pub path: String,
    /// Declared uncompressed size from the `File` table.
    pub size: u64,
}

/// `.msi` extraction report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MsiExtractReport {
    /// Number of entries written.
    pub written_entries: usize,
    /// Number of entries skipped by policy.
    pub skipped_entries: usize,
    /// Number of file bytes extracted.
    pub written_bytes: u64,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for MsiExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// `.msi` backend error.
#[derive(Debug)]
pub enum MsiBackendError {
    /// Manifest planning failed.
    Plan(crate::manifest::PlanError),
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// Extraction safety rejected an entry.
    Safety(ExtractionSafetyError),
    /// The MSI database could not be parsed or queried.
    Msi(String),
    /// An embedded cabinet could not be decoded.
    Cab(String),
    /// Job was cancelled cooperatively.
    Cancelled,
}

impl fmt::Display for MsiBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(source) => write!(f, "manifest planning failed: {source}"),
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Safety(source) => write!(f, "extraction safety rejected entry: {source}"),
            Self::Msi(message) => write!(f, "MSI backend error: {message}"),
            Self::Cab(message) => write!(f, "CAB backend error: {message}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for MsiBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Msi(_) | Self::Cab(_) | Self::Cancelled => None,
        }
    }
}

/// One `File`-table row resolved into an extractable entry.
#[derive(Debug, Clone)]
struct MsiFileEntry {
    /// Target-relative path with `/` separators.
    path: String,
    /// Declared size from `File.FileSize`.
    size: u64,
    /// `File.File` key; the name the file is stored under in the cabinet.
    file_key: String,
    /// The cabinet holding this file: an embedded stream name, or the name
    /// of an external `.cab` next to the MSI (unsupported, skipped).
    cabinet: CabinetRef,
}

#[derive(Debug, Clone)]
enum CabinetRef {
    /// `Media.Cabinet` began with `#`; the remainder names the embedded
    /// compound-document stream.
    Embedded(String),
    /// `Media.Cabinet` did not begin with `#`; the file lives in an external
    /// cabinet file, which this backend does not open.
    External(String),
}

/// The target-side name a `Directory.DefaultDir` contributes to a path.
///
/// Per the spec (and matching `msiextract`), `DefaultDir` has no `#` or
/// `short|long`-only semantics on its own: the value is `[target]:[source]`
/// (the target half is used for installation), each half may be a
/// `short|long` pair (the long name is used on the target), `.` means the
/// directory lives in its parent, and `SourceDir` is the conventional root
/// name. `\`-separated values name multiple nested directories (a single
/// `DefaultDir` cannot itself contain `\` on Windows).
fn target_dir_components(default_dir: &str) -> Vec<String> {
    let mut components = Vec::new();
    let target_half = default_dir.split_once(':').map_or(default_dir, |(target, _)| target);
    for part in target_half.split('\\') {
        let part = part.rsplit_once('|').map_or(part, |(_, long)| long);
        if !part.is_empty() && part != "." && part != "SourceDir" {
            components.push(part.to_string());
        }
    }
    components
}

/// The display leaf of a `File.FileName`: prefer the long name after the
/// `short|` separator, falling back to the short name when the long half is
/// empty (a malformed `short|` row). A name without `|` is used as-is; the
/// Filename data type has no `#` or path syntax.
fn target_file_leaf(file_name: &str) -> Option<String> {
    let leaf = match file_name.split_once('|') {
        Some((_, long)) if !long.is_empty() => long,
        Some((short, _)) => short,
        None => file_name,
    };
    if leaf.is_empty() { None } else { Some(leaf.to_string()) }
}

/// Resolves a `Directory`-table row id to its target-relative path (the root
/// resolves to an empty path), walking up to the row whose parent is null or
/// itself.
fn resolve_directory_path(id: &str, rows: &[(String, Option<String>, String)]) -> String {
    // Walk up collecting one component level per directory row, then reverse
    // the *levels* only — the components of a single `\`-separated
    // DefaultDir keep their order.
    let mut levels: Vec<Vec<String>> = Vec::new();
    let mut current = id;
    let mut hops = 0;
    while hops < rows.len() + 1 {
        hops += 1;
        let Some((_, parent, default_dir)) = rows.iter().find(|(directory, _, _)| directory == current) else {
            break;
        };
        levels.push(target_dir_components(default_dir));
        match parent {
            Some(parent) if !parent.is_empty() && parent != current => current = parent,
            _ => break,
        }
    }
    levels.reverse();
    levels.into_iter().flatten().collect::<Vec<_>>().join("/")
}

fn open_package(archive_path: &Path) -> Result<msi::Package<std::fs::File>, MsiBackendError> {
    let file = std::fs::File::open(archive_path).map_err(|source| MsiBackendError::Io { path: archive_path.to_path_buf(), source })?;
    msi::Package::open(file).map_err(|error| MsiBackendError::Msi(error.to_string()))
}

/// Reads the `File`, `Directory`, and `Media` tables and resolves every file
/// to a target-relative path. Returns the entries plus the number of rows
/// skipped in the manifest (empty file names, sequences no cabinet covers);
/// skipped rows carry a warning. Takes an already-open `package` so callers
/// that also need it for cabinet extraction don't open the compound-file
/// document a second time.
fn read_manifest(package: &mut msi::Package<std::fs::File>, warnings: &mut Vec<String>) -> Result<(Vec<MsiFileEntry>, usize), MsiBackendError> {
    let directory_rows = package
        .select_rows(msi::Select::table("Directory").columns(&["Directory", "Directory_Parent", "DefaultDir"]))
        .map_err(|error| MsiBackendError::Msi(format!("Directory table: {error}")))?
        .map(|row| {
            let id = row[0].as_str().unwrap_or_default().to_string();
            let parent = row[1].as_str().map(str::to_string);
            let default_dir = row[2].as_str().unwrap_or_default().to_string();
            (id, parent, default_dir)
        })
        .collect::<Vec<_>>();

    // Files hang off the Directory table through their component
    // (File.Component_ -> Component.Directory_).
    let component_directories = package
        .select_rows(msi::Select::table("Component").columns(&["Component", "Directory_"]))
        .map_err(|error| MsiBackendError::Msi(format!("Component table: {error}")))?
        .map(|row| (row[0].as_str().unwrap_or_default().to_string(), row[1].as_str().unwrap_or_default().to_string()))
        .collect::<HashMap<_, _>>();

    let media_rows = package
        .select_rows(msi::Select::table("Media").columns(&["DiskId", "LastSequence", "Cabinet"]))
        .map_err(|error| MsiBackendError::Msi(format!("Media table: {error}")))?
        .map(|row| {
            let disk_id = row[0].as_int().unwrap_or(0);
            let last_sequence = row[1].as_int().and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
            let cabinet = row[2].as_str().unwrap_or_default().to_string();
            (disk_id, last_sequence, cabinet)
        })
        .collect::<Vec<_>>();
    // Media rows are queried by increasing sequence; sort defensively.
    let mut media_rows = media_rows;
    media_rows.sort_by_key(|(disk_id, last_sequence, _)| (*disk_id, *last_sequence));

    let mut entries = Vec::new();
    let mut manifest_skips = 0usize;
    let file_rows = package
        .select_rows(msi::Select::table("File").columns(&["File", "Component_", "FileName", "FileSize", "Sequence"]))
        .map_err(|error| MsiBackendError::Msi(format!("File table: {error}")))?;
    for row in file_rows {
        let Some(file_key) = row[0].as_str() else { continue };
        let component = row[1].as_str().unwrap_or_default();
        let file_name = row[2].as_str().unwrap_or_default();
        let file_size = row[3].as_int().and_then(|v| u64::try_from(v).ok()).unwrap_or(0);
        let sequence = row[4].as_int().and_then(|v| u32::try_from(v).ok()).unwrap_or(0);

        let Some(leaf) = target_file_leaf(file_name) else {
            warnings.push(format!("skipped {file_key}: File table has no usable file name"));
            manifest_skips += 1;
            continue;
        };
        let directory = component_directories.get(component).map_or("", String::as_str);
        let directory_path = resolve_directory_path(directory, &directory_rows);
        let path = if directory_path.is_empty() { leaf } else { format!("{directory_path}/{leaf}") };

        // The file's cabinet is the first media row whose sequence range
        // covers it.
        let cabinet = match media_rows.iter().find(|(_, last_sequence, _)| sequence <= *last_sequence) {
            Some((_, _, cabinet_name)) if cabinet_name.starts_with('#') => CabinetRef::Embedded(cabinet_name[1..].to_string()),
            Some((_, _, cabinet_name)) if !cabinet_name.is_empty() => CabinetRef::External(cabinet_name.clone()),
            _ => {
                warnings.push(format!("skipped {path}: no cabinet covers file sequence {sequence}"));
                manifest_skips += 1;
                continue;
            }
        };

        entries.push(MsiFileEntry { path, size: file_size, file_key: file_key.to_string(), cabinet });
    }
    Ok((entries, manifest_skips))
}

/// Lists the files of an `.msi` package without extracting them.
pub fn list_msi(archive_path: impl AsRef<Path>) -> Result<Vec<MsiListEntry>, MsiBackendError> {
    let mut package = open_package(archive_path.as_ref())?;
    let mut warnings = Vec::new();
    let (entries, _) = read_manifest(&mut package, &mut warnings)?;
    Ok(entries.into_iter().map(|entry| MsiListEntry { path: entry.path, size: entry.size }).collect())
}

/// Extracts an `.msi` archive with an overwrite resolver.
pub fn extract_msi_with_overwrite_resolver(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: &mut dyn OverwriteResolver,
) -> Result<MsiExtractReport, MsiBackendError> {
    extract_msi_inner(archive_path, destination, policy, None, Some(overwrite_resolver))
}

/// Extracts an `.msi` archive with a job context for progress and
/// cancellation, and optionally an overwrite resolver.
pub(crate) fn extract_msi_with_context(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
    context: Option<&mut JobContext<'_>>,
) -> Result<MsiExtractReport, MsiBackendError> {
    extract_msi_inner(archive_path, destination, policy, context, overwrite_resolver)
}

/// Extracts an `.msi` archive without job progress callbacks.
pub fn extract_msi(archive_path: impl AsRef<Path>, destination: impl AsRef<Path>, policy: ExtractionPolicy) -> Result<MsiExtractReport, MsiBackendError> {
    extract_msi_inner(archive_path, destination, policy, None, None)
}

fn extract_msi_inner(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    mut context: Option<&mut JobContext<'_>>,
    overwrite_resolver: Option<&mut dyn OverwriteResolver>,
) -> Result<MsiExtractReport, MsiBackendError> {
    let archive_path = archive_path.as_ref();
    let destination = destination.as_ref();
    let destination_root =
        crate::safety::prepare_destination_root(destination).map_err(|source| MsiBackendError::Io { path: destination.to_path_buf(), source })?;

    let mut package = open_package(archive_path)?;
    let mut warnings = Vec::new();
    let (entries, manifest_skips) = read_manifest(&mut package, &mut warnings)?;

    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(&destination_root, policy, overwrite_resolver);
    let mut io_buffer = vec![0_u8; crate::DEFAULT_IO_BUFFER_BYTES];
    let mut report = MsiExtractReport { written_entries: 0, skipped_entries: manifest_skips, written_bytes: 0, warnings };

    // Files sharing an embedded cabinet share one cabinet reader; group in
    // first-seen order so the manifest order is preserved. Files declared
    // with an external cabinet are skipped up front.
    let mut groups: Vec<(String, Vec<&MsiFileEntry>)> = Vec::new();
    let mut group_index: HashMap<&str, usize> = HashMap::new();
    for entry in &entries {
        let stream_name = match &entry.cabinet {
            CabinetRef::Embedded(stream_name) => stream_name.as_str(),
            CabinetRef::External(name) => {
                crate::extract_loop::skip_entry(
                    &mut report,
                    context.as_deref_mut(),
                    format!("skipped {}: external cabinet {name} is not supported", entry.path),
                );
                continue;
            }
        };
        let index = *group_index.entry(stream_name).or_insert_with(|| {
            groups.push((stream_name.to_string(), Vec::new()));
            groups.len() - 1
        });
        groups[index].1.push(entry);
    }

    for (stream_name, group) in groups {
        if !package.has_stream(&stream_name) {
            for entry in &group {
                crate::extract_loop::skip_entry(
                    &mut report,
                    context.as_deref_mut(),
                    format!("skipped {}: cabinet stream {stream_name} is missing", entry.path),
                );
            }
            continue;
        }
        let stream = package.read_stream(&stream_name).map_err(|error| MsiBackendError::Msi(format!("read stream {stream_name}: {error}")))?;
        let mut cabinet = cab::Cabinet::new(stream).map_err(|error| MsiBackendError::Cab(format!("open cabinet {stream_name}: {error}")))?;

        for entry in group {
            if let Some(ctx) = context.as_deref_mut() {
                ctx.check_cancelled()?;
            }

            if cabinet.get_file_entry(&entry.file_key).is_none() {
                crate::extract_loop::skip_entry(&mut report, context.as_deref_mut(), format!("skipped {}: not present in cabinet {stream_name}", entry.path));
                continue;
            }

            let safety_entry = ExtractionEntry {
                archive_path: entry.path.clone(),
                kind: ExtractionEntryKind::File,
                uncompressed_size: Some(entry.size),
                compressed_size: None,
            };

            crate::extract_loop::process_extraction_entry(
                &mut report,
                context.as_deref_mut(),
                &mut planner,
                &safety_entry,
                &mut |action, report, mut context| match action {
                    crate::extract_loop::EntryAction::Skip => Ok::<u64, MsiBackendError>(0),
                    crate::extract_loop::EntryAction::Write(decision) => {
                        let replace_existing = decision.replace_existing;
                        let destination_path = decision.destination_path;

                        let mut file_reader = cabinet
                            .read_file(&entry.file_key)
                            .map_err(|error| MsiBackendError::Cab(format!("read {} from cabinet {stream_name}: {error}", entry.file_key)))?;

                        let written_bytes = crate::extract_loop::copy_file_entry(
                            destination_path,
                            replace_existing,
                            Some(&safety_entry.archive_path),
                            context.as_deref_mut(),
                            &mut io_buffer,
                            |buffer| {
                                io::Read::read(&mut file_reader, buffer).map_err(|source| MsiBackendError::Io { path: destination_path.to_path_buf(), source })
                            },
                            |source, path| MsiBackendError::Io { path: path.to_path_buf(), source },
                        )?;

                        report.written_entries += 1;
                        report.written_bytes += written_bytes;
                        if written_bytes != entry.size {
                            // The file is materialized as-is; the declared
                            // size was a lie, so warn about the divergence.
                            report.warnings.push(format!("{}: extracted {} bytes, File table declares {}", entry.path, written_bytes, entry.size));
                        }
                        Ok(written_bytes)
                    }
                },
            )?;
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{MsiListEntry, extract_msi_with_overwrite_resolver, list_msi};
    use crate::safety::{ExtractionPolicy, OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver};
    use crate::test_support::TestDir;
    use std::fs;
    use std::path::{Path, PathBuf};

    struct AlwaysReplace;
    impl OverwriteResolver for AlwaysReplace {
        fn decide(&mut self, _conflict: &OverwriteConflict) -> OverwriteDecision {
            OverwriteDecision::Replace
        }
    }

    fn msi_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives").join(name)
    }

    #[test]
    fn checked_in_msi_fixture_lists_with_resolved_directory_paths() {
        let archive = msi_fixture("basic.msi");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let listing = list_msi(&archive).unwrap();
        let paths = listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>();
        assert!(paths.contains(&"payload/README.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/nested/file.txt"), "{paths:?}");
        assert!(paths.contains(&"payload/dir with spaces/file with spaces.txt"), "{paths:?}");
        assert!(listing.iter().all(|entry| !entry.path.starts_with('/') && !entry.path.starts_with("./")), "msi paths must be normalized: {paths:?}");

        let readme = listing.iter().find(|entry| entry.path == "payload/README.txt").unwrap();
        assert_eq!(readme.size, 25);
        // The MSI database has no directory or symlink entries: every listed
        // entry is a regular file.
        assert!(listing.iter().all(|entry: &MsiListEntry| !entry.path.ends_with('/')));
    }

    #[test]
    fn checked_in_msi_fixture_extracts_every_file_with_byte_accurate_report() {
        let archive = msi_fixture("basic.msi");
        assert!(archive.is_file(), "missing fixture; run scripts/generate_fixtures.sh");

        let temp = TestDir::new("checked_in_msi_fixture_extract");
        let report = extract_msi_with_overwrite_resolver(
            &archive,
            temp.path("out"),
            ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            &mut AlwaysReplace,
        )
        .unwrap();

        assert_eq!(report.skipped_entries, 0, "warnings: {:?}", report.warnings);
        assert_eq!(fs::read_to_string(temp.path("out/payload/README.txt")).unwrap(), "ZManager fixture payload\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/nested/file.txt")).unwrap(), "nested fixture file\n");
        assert_eq!(fs::read_to_string(temp.path("out/payload/dir with spaces/file with spaces.txt")).unwrap(), "spaces in path\n");

        let listing = list_msi(&archive).unwrap();
        let declared_file_bytes: u64 = listing.iter().map(|entry| entry.size).sum();
        assert_eq!(report.written_entries, listing.len());
        assert_eq!(report.written_bytes, declared_file_bytes, "written bytes must sum the declared sizes of all listed files");
    }

    #[test]
    fn target_dir_components_resolves_spec_forms() {
        use super::target_dir_components;
        // Plain names pass through; `short|long` pairs use the long name.
        assert_eq!(target_dir_components("payload"), vec!["payload"]);
        assert_eq!(target_dir_components("SHORT|payload"), vec!["payload"]);
        // `[target]:[source]` uses the target half (both halves may carry
        // their own short|long pair).
        assert_eq!(target_dir_components("target:source"), vec!["target"]);
        assert_eq!(target_dir_components("SHORT|target:SHORT2|source"), vec!["target"]);
        // `\` separates multiple nested directory names.
        assert_eq!(target_dir_components("part1\\part2"), vec!["part1", "part2"]);
        // `.` places the directory in its parent; `SourceDir` is the
        // conventional root name; empty contributes nothing.
        assert_eq!(target_dir_components("."), Vec::<String>::new());
        assert_eq!(target_dir_components("SourceDir"), Vec::<String>::new());
        assert_eq!(target_dir_components(""), Vec::<String>::new());
        // `#` has no special meaning in DefaultDir (verified against the
        // spec and msiextract): the name is literal.
        assert_eq!(target_dir_components("#hidden"), vec!["#hidden"]);
    }

    #[test]
    fn target_file_leaf_resolves_spec_forms() {
        use super::target_file_leaf;
        assert_eq!(target_file_leaf("README.txt"), Some("README.txt".to_owned()));
        assert_eq!(target_file_leaf("README.TXT|README.txt"), Some("README.txt".to_owned()));
        // A malformed `short|` row falls back to the short name; a fully
        // empty FileName has no usable leaf at all.
        assert_eq!(target_file_leaf("SHORT.TXT|"), Some("SHORT.TXT".to_owned()));
        assert_eq!(target_file_leaf(""), None);
        assert_eq!(target_file_leaf("|"), None);
    }

    // One crafted MSI row each for the File and Media tables.
    struct CraftedFileRow {
        key: &'static str,
        component: &'static str,
        file_name: &'static str,
        file_size: i32,
        sequence: i32,
    }

    struct CraftedCabinet {
        /// The embedded stream name; the cab is built with the `cab` crate.
        stream_name: &'static str,
        /// (cab entry name, data) — cab entries are keyed by File-table key.
        files: Vec<(&'static str, &'static [u8])>,
    }

    struct CraftedMsi {
        /// (`id`, `parent`, `default_dir`); parent `None` marks the root.
        directories: Vec<(&'static str, Option<&'static str>, &'static str)>,
        /// (component id, directory id).
        components: Vec<(&'static str, &'static str)>,
        files: Vec<CraftedFileRow>,
        /// (`disk_id`, `last_sequence`, `cabinet`).
        media: Vec<(i32, i32, &'static str)>,
        streams: Vec<CraftedCabinet>,
    }

    fn crafted_msi() -> CraftedMsi {
        CraftedMsi {
            directories: vec![("TARGETDIR", None, "SourceDir"), ("PAYLOADDIR", Some("TARGETDIR"), "payload")],
            components: vec![("PayloadFiles", "PAYLOADDIR")],
            files: Vec::new(),
            media: Vec::new(),
            streams: Vec::new(),
        }
    }

    /// Writes a crafted MSI through the `msi` and `cab` crates' write paths,
    /// so the skip-with-warning safety nets can be exercised on packages no
    /// MSI builder would produce (missing streams, absent keys, size lies).
    fn write_crafted_msi(spec: &CraftedMsi, destination: &Path) {
        use std::io::{Cursor, Write as _};

        let cursor = Cursor::new(Vec::new());
        let mut package = msi::Package::create(msi::PackageType::Installer, cursor).unwrap();

        package
            .create_table(
                "Directory",
                vec![
                    msi::Column::build("Directory").primary_key().string(72),
                    msi::Column::build("Directory_Parent").nullable().string(72),
                    msi::Column::build("DefaultDir").string(255),
                ],
            )
            .unwrap();
        let mut insert = msi::Insert::into("Directory");
        for (id, parent, default_dir) in &spec.directories {
            insert = insert.row(vec![
                msi::Value::Str((*id).to_owned()),
                parent.map_or(msi::Value::Null, |parent| msi::Value::Str(parent.to_owned())),
                msi::Value::Str((*default_dir).to_owned()),
            ]);
        }
        package.insert_rows(insert).unwrap();

        package.create_table("Component", vec![msi::Column::build("Component").primary_key().string(72), msi::Column::build("Directory_").string(72)]).unwrap();
        let mut insert = msi::Insert::into("Component");
        for (component, directory) in &spec.components {
            insert = insert.row(vec![msi::Value::Str((*component).to_owned()), msi::Value::Str((*directory).to_owned())]);
        }
        package.insert_rows(insert).unwrap();

        package
            .create_table(
                "File",
                vec![
                    msi::Column::build("File").primary_key().string(72),
                    msi::Column::build("Component_").string(72),
                    msi::Column::build("FileName").string(255),
                    msi::Column::build("FileSize").int32(),
                    msi::Column::build("Sequence").int32(),
                ],
            )
            .unwrap();
        let mut insert = msi::Insert::into("File");
        for file in &spec.files {
            insert = insert.row(vec![
                msi::Value::Str(file.key.to_owned()),
                msi::Value::Str(file.component.to_owned()),
                msi::Value::Str(file.file_name.to_owned()),
                msi::Value::Int(file.file_size),
                msi::Value::Int(file.sequence),
            ]);
        }
        package.insert_rows(insert).unwrap();

        package
            .create_table(
                "Media",
                vec![
                    msi::Column::build("DiskId").primary_key().int16(),
                    msi::Column::build("LastSequence").int32(),
                    msi::Column::build("Cabinet").nullable().string(255),
                ],
            )
            .unwrap();
        let mut insert = msi::Insert::into("Media");
        for (disk_id, last_sequence, cabinet) in &spec.media {
            insert = insert.row(vec![msi::Value::Int(*disk_id), msi::Value::Int(*last_sequence), msi::Value::Str((*cabinet).to_owned())]);
        }
        package.insert_rows(insert).unwrap();

        for cabinet in &spec.streams {
            let mut builder = cab::CabinetBuilder::new();
            let folder = builder.add_folder(cab::CompressionType::MsZip);
            for (name, _) in &cabinet.files {
                folder.add_file(*name);
            }
            let mut cab_bytes = Cursor::new(Vec::new());
            let mut writer = builder.build(&mut cab_bytes).unwrap();
            for (_, data) in &cabinet.files {
                let mut file_writer = writer.next_file().unwrap().unwrap();
                file_writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();

            let mut stream = package.write_stream(cabinet.stream_name).unwrap();
            stream.write_all(cab_bytes.get_ref()).unwrap();
        }

        package.flush().unwrap();
        let bytes = package.into_inner().unwrap().into_inner();
        fs::write(destination, bytes).unwrap();
    }

    fn extract_crafted(report_label: &str, spec: &CraftedMsi) -> (TestDir, crate::msi_backend::MsiExtractReport) {
        let temp = TestDir::new(report_label);
        write_crafted_msi(spec, &temp.path("crafted.msi"));
        let report = extract_msi_with_overwrite_resolver(
            temp.path("crafted.msi"),
            temp.path("out"),
            ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() },
            &mut AlwaysReplace,
        )
        .unwrap();
        (temp, report)
    }

    #[test]
    fn external_cabinet_files_are_skipped_with_warning() {
        let mut spec = crafted_msi();
        spec.files = vec![CraftedFileRow { key: "readme", component: "PayloadFiles", file_name: "README.txt", file_size: 25, sequence: 1 }];
        // No `#` prefix: the cabinet lives outside the MSI, which this
        // backend does not open.
        spec.media = vec![(1, 10, "ext.cab")];

        let (temp, report) = extract_crafted("msi_external_cabinet", &spec);
        assert_eq!(report.written_entries, 0);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("external cabinet ext.cab")), "{:?}", report.warnings);
        assert!(!temp.path("out/payload/README.txt").exists());

        // Listing is the File-table manifest, so the file is still listed.
        let listing = list_msi(temp.path("crafted.msi")).unwrap();
        assert_eq!(listing.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), vec!["payload/README.txt"]);
    }

    #[test]
    fn missing_cabinet_stream_is_skipped_with_warning() {
        let mut spec = crafted_msi();
        spec.files = vec![CraftedFileRow { key: "readme", component: "PayloadFiles", file_name: "README.txt", file_size: 25, sequence: 1 }];
        // Declares an embedded cabinet that does not exist as a stream.
        spec.media = vec![(1, 10, "#nope.cab")];

        let (_, report) = extract_crafted("msi_missing_stream", &spec);
        assert_eq!(report.written_entries, 0);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("cabinet stream nope.cab is missing")), "{:?}", report.warnings);
    }

    #[test]
    fn file_key_absent_from_cabinet_is_skipped_with_warning() {
        let mut spec = crafted_msi();
        spec.files = vec![
            CraftedFileRow { key: "readme", component: "PayloadFiles", file_name: "README.txt", file_size: 11, sequence: 1 },
            CraftedFileRow { key: "ghost", component: "PayloadFiles", file_name: "ghost.txt", file_size: 11, sequence: 2 },
        ];
        spec.media = vec![(1, 10, "#data.cab")];
        spec.streams = vec![CraftedCabinet { stream_name: "data.cab", files: vec![("readme", b"hello world")] }];

        let (temp, report) = extract_crafted("msi_absent_key", &spec);
        assert_eq!(report.written_entries, 1);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("ghost.txt: not present in cabinet data.cab")), "{:?}", report.warnings);
        assert_eq!(fs::read_to_string(temp.path("out/payload/README.txt")).unwrap(), "hello world");
    }

    #[test]
    fn empty_file_name_row_is_skipped_with_warning() {
        let mut spec = crafted_msi();
        spec.files = vec![CraftedFileRow { key: "anon", component: "PayloadFiles", file_name: "", file_size: 11, sequence: 1 }];
        spec.media = vec![(1, 10, "#data.cab")];
        spec.streams = vec![CraftedCabinet { stream_name: "data.cab", files: vec![("anon", b"hello world")] }];

        let (temp, report) = extract_crafted("msi_empty_file_name", &spec);
        assert_eq!(report.written_entries, 0);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("no usable file name")), "{:?}", report.warnings);
        let listing = list_msi(temp.path("crafted.msi")).unwrap();
        assert!(listing.is_empty());
    }

    #[test]
    fn file_without_covering_cabinet_row_is_skipped_with_warning() {
        let mut spec = crafted_msi();
        spec.files = vec![CraftedFileRow { key: "readme", component: "PayloadFiles", file_name: "README.txt", file_size: 25, sequence: 99 }];
        // The Media row's last sequence (10) does not cover sequence 99.
        spec.media = vec![(1, 10, "#data.cab")];

        let (_, report) = extract_crafted("msi_no_cabinet_row", &spec);
        assert_eq!(report.written_entries, 0);
        assert_eq!(report.skipped_entries, 1);
        assert!(report.warnings.iter().any(|warning| warning.contains("no cabinet covers file sequence 99")), "{:?}", report.warnings);
    }

    #[test]
    fn size_mismatch_warns_but_still_writes_the_file() {
        let mut spec = crafted_msi();
        spec.files = vec![CraftedFileRow { key: "readme", component: "PayloadFiles", file_name: "README.txt", file_size: 100, sequence: 1 }];
        spec.media = vec![(1, 10, "#data.cab")];
        spec.streams = vec![CraftedCabinet { stream_name: "data.cab", files: vec![("readme", b"hello world")] }];

        let (temp, report) = extract_crafted("msi_size_mismatch", &spec);
        assert_eq!(report.written_entries, 1);
        assert_eq!(report.written_bytes, 11);
        assert!(report.warnings.iter().any(|warning| warning.contains("extracted 11 bytes, File table declares 100")), "{:?}", report.warnings);
        assert_eq!(fs::read_to_string(temp.path("out/payload/README.txt")).unwrap(), "hello world");
    }

    #[test]
    fn resolved_paths_handle_spec_name_forms() {
        let mut spec = crafted_msi();
        spec.directories = vec![
            ("TARGETDIR", None, "SourceDir"),
            ("PAYLOADDIR", Some("TARGETDIR"), "SHORT|payload"),
            ("MULTIDIR", Some("PAYLOADDIR"), "part1\\part2"),
            ("DOTDIR", Some("PAYLOADDIR"), "."),
            ("COLONDIR", Some("PAYLOADDIR"), "target:source"),
        ];
        spec.components = vec![("C1", "PAYLOADDIR"), ("C2", "MULTIDIR"), ("C3", "DOTDIR"), ("C4", "COLONDIR")];
        spec.files = vec![
            // FileName `short|long` uses the long name.
            CraftedFileRow { key: "k1", component: "C1", file_name: "README.TXT|readme.txt", file_size: 3, sequence: 1 },
            // Malformed `short|` falls back to the short name.
            CraftedFileRow { key: "k2", component: "C1", file_name: "SHORT2.TXT|", file_size: 3, sequence: 2 },
            // A `\` DefaultDir names nested directories.
            CraftedFileRow { key: "k3", component: "C2", file_name: "f3.txt", file_size: 3, sequence: 3 },
            // `.` DefaultDir lives in its parent.
            CraftedFileRow { key: "k4", component: "C3", file_name: "f4.txt", file_size: 3, sequence: 4 },
            // `[target]:[source]` DefaultDir uses the target half.
            CraftedFileRow { key: "k5", component: "C4", file_name: "f5.txt", file_size: 3, sequence: 5 },
        ];
        spec.media = vec![(1, 10, "#data.cab")];
        spec.streams =
            vec![CraftedCabinet { stream_name: "data.cab", files: vec![("k1", b"one"), ("k2", b"two"), ("k3", b"thr"), ("k4", b"fou"), ("k5", b"fiv")] }];

        let (temp, report) = extract_crafted("msi_spec_forms", &spec);
        assert_eq!(report.skipped_entries, 0, "warnings: {:?}", report.warnings);
        assert_eq!(report.written_entries, 5);
        assert_eq!(report.written_bytes, 15);
        assert_eq!(fs::read_to_string(temp.path("out/payload/readme.txt")).unwrap(), "one");
        assert_eq!(fs::read_to_string(temp.path("out/payload/SHORT2.TXT")).unwrap(), "two");
        assert_eq!(fs::read_to_string(temp.path("out/payload/part1/part2/f3.txt")).unwrap(), "thr");
        assert_eq!(fs::read_to_string(temp.path("out/payload/f4.txt")).unwrap(), "fou");
        assert_eq!(fs::read_to_string(temp.path("out/payload/target/f5.txt")).unwrap(), "fiv");
    }
}
