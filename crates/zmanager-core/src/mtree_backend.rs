//! Native MTREE manifest reader.
//!
//! MTREE describes filesystem metadata and optional digests; it does not
//! contain the file payloads. Extraction therefore materializes the declared
//! filesystem shape and file sizes (as sparse placeholder files), while list
//! and test report the manifest entries and declared metadata.

/// Minimal `mtree(5)` manifest reader.
///
/// Replaces the unmaintained `mtree` crate, which was Unix-only (a single
/// `std::os::unix::ffi::OsStrExt` import), panicked via `unimplemented!()` on
/// `/unset`, and resolved relative entries against the *process* working
/// directory rather than the manifest's own directory stack — which made the
/// standard nested form unreadable.
mod manifest {
    use std::path::PathBuf;

    /// Entry kinds the `type=` keyword can name.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub(super) enum FileType {
        BlockDevice,
        CharacterDevice,
        Directory,
        Fifo,
        File,
        SymbolicLink,
        Socket,
    }

    impl FileType {
        /// The `type=` keyword spelling, which is also the reader's reported
        /// `file_type` string.
        pub(super) const fn as_str(self) -> &'static str {
            match self {
                Self::BlockDevice => "block",
                Self::CharacterDevice => "char",
                Self::Directory => "dir",
                Self::Fifo => "fifo",
                Self::File => "file",
                Self::SymbolicLink => "link",
                Self::Socket => "socket",
            }
        }

        fn parse(value: &[u8]) -> Option<Self> {
            Some(match value {
                b"block" => Self::BlockDevice,
                b"char" => Self::CharacterDevice,
                b"dir" => Self::Directory,
                b"fifo" => Self::Fifo,
                b"file" => Self::File,
                b"link" => Self::SymbolicLink,
                b"socket" => Self::Socket,
                _ => return None,
            })
        }
    }

    /// One manifest record, with `/set` defaults already folded in.
    #[derive(Debug, Clone)]
    pub(super) struct Record {
        /// Manifest-relative path, with the directory stack applied.
        pub(super) path: PathBuf,
        /// `type=`, absent when neither the record nor `/set` declared one.
        pub(super) file_type: Option<FileType>,
        /// `size=`, when declared.
        pub(super) size: Option<u64>,
        /// `link=`, when declared.
        pub(super) link: Option<PathBuf>,
    }

    /// Decodes the `vis(3)` escaping BSD `mtree` applies to path words:
    /// `\ooo` octal triples and `\\`. Any other backslash is kept literally,
    /// matching the lenient readers in the wild.
    fn unescape(word: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(word.len());
        let mut i = 0;
        while i < word.len() {
            if word[i] == b'\\' && i + 3 < word.len() + 1 {
                let rest = &word[i + 1..];
                if rest.first() == Some(&b'\\') {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                if rest.len() >= 3 && rest[..3].iter().all(|b| (b'0'..=b'7').contains(b)) {
                    let value = (rest[0] - b'0') * 64 + (rest[1] - b'0') * 8 + (rest[2] - b'0');
                    out.push(value);
                    i += 4;
                    continue;
                }
            }
            out.push(word[i]);
            i += 1;
        }
        out
    }

    /// Builds a `PathBuf` from raw manifest bytes.
    ///
    /// Unix filenames are arbitrary bytes, not necessarily UTF-8, and the
    /// replaced crate preserved them via `OsStr::from_bytes`. A lossy
    /// conversion would rewrite `caf\xe9.txt` as `caf<U+FFFD>.txt` — a
    /// different name — so the byte-exact path is kept where the platform has
    /// one. This is a `cfg` pair with a working fallback, not the replaced
    /// crate's unconditional Unix-only import: Windows still compiles.
    #[cfg(unix)]
    fn path_from_bytes(bytes: &[u8]) -> PathBuf {
        use std::os::unix::ffi::OsStrExt as _;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes).to_owned())
    }

    /// Windows paths are UTF-16 and have no byte-oriented `OsStr`
    /// constructor, so a non-UTF-8 manifest name cannot round-trip there.
    #[cfg(not(unix))]
    fn path_from_bytes(bytes: &[u8]) -> PathBuf {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Splits a line into whitespace-delimited words. `mtree` permits both
    /// spaces and tabs; the previous crate split on spaces alone.
    fn words(line: &[u8]) -> Vec<&[u8]> {
        line.split(|byte| matches!(byte, b' ' | b'\t' | b'\r')).filter(|word| !word.is_empty()).collect()
    }

    /// Parses `key=value`, returning `None` for a bare keyword (`/unset` names
    /// keywords without values).
    fn split_keyword(word: &[u8]) -> (&[u8], Option<&[u8]>) {
        match word.iter().position(|byte| *byte == b'=') {
            Some(at) => (&word[..at], Some(&word[at + 1..])),
            None => (word, None),
        }
    }

    /// Keywords carried by `/set`, applied to every following record until
    /// overridden or `/unset`.
    #[derive(Debug, Clone, Default)]
    struct Defaults {
        file_type: Option<FileType>,
        size: Option<u64>,
        link: Option<Vec<u8>>,
    }

    /// Reads every record in a manifest.
    ///
    /// Returns the offending line number and a message on malformed input;
    /// it never panics, and never consults the process working directory.
    pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Record>, String> {
        let mut defaults = Defaults::default();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut records = Vec::new();

        for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            let number = index + 1;
            let words = words(line);
            let Some(first) = words.first().copied() else {
                continue;
            };
            if first.starts_with(b"#") {
                continue;
            }
            if first == b".." {
                stack.pop();
                continue;
            }

            if let Some(name) = first.strip_prefix(b"/") {
                match name {
                    b"set" => {
                        for word in &words[1..] {
                            let (key, value) = split_keyword(word);
                            apply_keyword(&mut defaults, key, value, number)?;
                        }
                    }
                    b"unset" => {
                        for word in &words[1..] {
                            let (key, _) = split_keyword(word);
                            match key {
                                b"type" => defaults.file_type = None,
                                b"size" => defaults.size = None,
                                b"link" => defaults.link = None,
                                _ => {}
                            }
                        }
                    }
                    other => {
                        return Err(format!("line {number}: unknown directive /{}", String::from_utf8_lossy(other)));
                    }
                }
                continue;
            }

            // Per mtree(5), a word containing `/` is a full path used as-is;
            // a bare name is relative to the enclosing directory.
            let is_full = first.contains(&b'/');
            let mut record = Defaults { file_type: defaults.file_type, size: defaults.size, link: defaults.link.clone() };
            for word in &words[1..] {
                let (key, value) = split_keyword(word);
                apply_keyword(&mut record, key, value, number)?;
            }

            let name = unescape(first);
            let path = if is_full {
                path_from_bytes(&name)
            } else {
                let mut joined = Vec::new();
                for component in &stack {
                    joined.extend_from_slice(component);
                    joined.push(b'/');
                }
                joined.extend_from_slice(&name);
                path_from_bytes(&joined)
            };

            if !is_full && record.file_type == Some(FileType::Directory) {
                // `.` names the tree root, which adds no path component.
                if name != b"." {
                    stack.push(name.clone());
                }
            }

            records.push(Record {
                path,
                file_type: record.file_type,
                size: record.size,
                link: record.link.as_deref().map(|raw| path_from_bytes(&unescape(raw))),
            });
        }

        Ok(records)
    }

    /// Folds one `key=value` pair into a keyword set.
    fn apply_keyword(into: &mut Defaults, key: &[u8], value: Option<&[u8]>, number: usize) -> Result<(), String> {
        match key {
            b"type" => {
                let Some(value) = value else { return Ok(()) };
                let Some(parsed) = FileType::parse(value) else {
                    return Err(format!("line {number}: invalid MTREE file type {:?}", String::from_utf8_lossy(value)));
                };
                into.file_type = Some(parsed);
            }
            b"size" => {
                let Some(value) = value else { return Ok(()) };
                let text = String::from_utf8_lossy(value);
                let parsed = text.parse::<u64>().map_err(|_| format!("line {number}: invalid MTREE size {text:?}"))?;
                into.size = Some(parsed);
            }
            b"link" => {
                let Some(value) = value else { return Ok(()) };
                into.link = Some(value.to_vec());
            }
            // Every other keyword (mode, uid, gid, time, digests, flags, ...)
            // describes metadata this reader does not surface.
            _ => {}
        }
        Ok(())
    }
}

use crate::archive_browser::BrowserEntryKind;
use crate::engine::types::TestOptions;
use crate::extract_loop::{EntryAction, process_extraction_entry};
use crate::jobs::{CancellationToken, JobCancelled};
use crate::safety::{ExtractionEntry, ExtractionEntryKind, ExtractionPolicy, ExtractionSafetyError, ExtractionSafetyPlanner};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

const MAX_MTREE_BYTES: u64 = 64 * 1024 * 1024;

/// One normalized MTREE manifest entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MtreeEntry {
    /// Retained manifest-order entry ID.
    pub index: usize,
    /// Normalized relative manifest path.
    pub path: String,
    /// Portable entry kind.
    pub kind: BrowserEntryKind,
    /// Declared regular-file size, when present.
    pub size: Option<u64>,
    /// Declared file type name.
    pub file_type: String,
    /// Symbolic-link target when the manifest declares one.
    pub link_target: Option<PathBuf>,
}

/// Normalized MTREE operation report.
pub type MtreeReport = crate::backend_impl::backend_report::BackendReport;

/// Native MTREE operation error.
#[derive(Debug)]
pub enum MtreeError {
    /// Filesystem I/O failed.
    Io { path: PathBuf, source: io::Error },
    /// The manifest is malformed or cannot be normalized safely.
    Invalid { path: PathBuf, message: String },
    /// A manifest path violated shared path safety rules.
    Safety(ExtractionSafetyError),
    /// The caller cancelled the operation.
    Cancelled,
}

impl From<ExtractionSafetyError> for MtreeError {
    fn from(source: ExtractionSafetyError) -> Self {
        Self::Safety(source)
    }
}

impl From<JobCancelled> for MtreeError {
    fn from(_: JobCancelled) -> Self {
        Self::Cancelled
    }
}

impl fmt::Display for MtreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O failed for {}: {source}", path.display()),
            Self::Invalid { path, message } => write!(f, "invalid MTREE {}: {message}", path.display()),
            Self::Safety(source) => write!(f, "MTREE path rejected by extraction safety: {source}"),
            Self::Cancelled => write!(f, "job cancelled"),
        }
    }
}

impl std::error::Error for MtreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Safety(source) => Some(source),
            Self::Invalid { .. } | Self::Cancelled => None,
        }
    }
}

/// Lists MTREE manifest records.
pub fn list(path: impl AsRef<Path>) -> Result<Vec<MtreeEntry>, MtreeError> {
    let path = path.as_ref();
    let bytes = read_manifest(path)?;
    let records = manifest::parse(&bytes).map_err(|message| invalid(path, message))?;
    let mut entries = Vec::new();
    let mut used_paths = Vec::new();
    for record in records {
        // The `.` record names the tree root, which describes the destination
        // directory rather than an entry inside the manifest.
        if is_tree_root(&record.path) {
            continue;
        }
        let normalized = normalize_path(&record.path)?;
        if used_paths.iter().any(|existing| existing == &normalized) {
            return Err(invalid(path, format!("duplicate path {normalized}")));
        }
        used_paths.push(normalized.clone());
        let file_type = record.file_type.unwrap_or(manifest::FileType::File);
        entries.push(MtreeEntry {
            index: entries.len(),
            path: normalized,
            kind: map_kind(file_type),
            size: record.size,
            file_type: file_type.as_str().to_owned(),
            link_target: record.link,
        });
    }
    Ok(entries)
}

/// Validates selected MTREE manifest records and their declared metadata.
pub fn test(path: impl AsRef<Path>, options: &TestOptions) -> Result<MtreeReport, MtreeError> {
    let path = path.as_ref();
    let entries = list(path)?;
    let mut report = MtreeReport::default();
    for entry in entries {
        if options.is_cancelled() {
            return Err(MtreeError::Cancelled);
        }
        if !options.selects(&entry.path) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        report.entries = report.entries.saturating_add(1);
        if entry.kind == BrowserEntryKind::File {
            report.bytes = report.bytes.saturating_add(entry.size.unwrap_or(0));
        }
    }
    Ok(report)
}

/// Materializes the filesystem shape declared by an MTREE manifest.
///
/// MTREE is a manifest, not a payload container. Regular files are therefore
/// created as sparse placeholders with their declared size; their original
/// contents are not available in the manifest. Symbolic links are restored
/// from their declared targets, and directories are created normally.
pub fn extract(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    overwrite_resolver: Option<&mut dyn crate::safety::OverwriteResolver>,
    cancellation: Option<&CancellationToken>,
) -> Result<MtreeReport, MtreeError> {
    let path = path.as_ref();
    let entries = list(path)?;
    let mut report = MtreeReport::default();
    let mut planner = ExtractionSafetyPlanner::with_overwrite_resolver(destination.as_ref(), policy, overwrite_resolver);

    for entry in entries {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(MtreeError::Cancelled);
        }

        let safety_entry = ExtractionEntry {
            archive_path: entry.path.clone(),
            kind: match entry.kind {
                BrowserEntryKind::File => ExtractionEntryKind::File,
                BrowserEntryKind::Directory => ExtractionEntryKind::Directory,
                BrowserEntryKind::Symlink => ExtractionEntryKind::Symlink {
                    target: entry.link_target.clone().ok_or_else(|| invalid(path, format!("symbolic-link entry {} has no link target", entry.path)))?,
                },
                BrowserEntryKind::Hardlink => ExtractionEntryKind::Hardlink {
                    target: entry.link_target.clone().ok_or_else(|| invalid(path, format!("hard-link entry {} has no link target", entry.path)))?,
                },
                BrowserEntryKind::Special | BrowserEntryKind::FileCopy => ExtractionEntryKind::Special,
            },
            uncompressed_size: (entry.kind == BrowserEntryKind::File).then_some(entry.size.unwrap_or(0)),
            compressed_size: None,
        };

        process_extraction_entry(&mut report, None, &mut planner, &safety_entry, &mut |action, report, _context| {
            let EntryAction::Write(decision) = action else {
                return Ok(0);
            };

            if decision.replace_existing {
                crate::safety::remove_destination_for_replace(decision.destination_path).map_err(|source| io_error(decision.destination_path, source))?;
            }

            let written = match &safety_entry.kind {
                ExtractionEntryKind::Directory => {
                    fs::create_dir_all(decision.destination_path).map_err(|source| io_error(decision.destination_path, source))?;
                    0
                }
                ExtractionEntryKind::File => {
                    let mut output = crate::atomic_file::AtomicOutputFile::create(decision.destination_path)
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    output
                        .file_mut()
                        .map_err(|source| io_error(decision.destination_path, source))?
                        .set_len(entry.size.unwrap_or(0))
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    output.commit_with_replace(decision.replace_existing).map_err(|source| io_error(decision.destination_path, source))?;
                    entry.size.unwrap_or(0)
                }
                ExtractionEntryKind::Symlink { target } => {
                    crate::extract_materialize::write_symlink(target, decision.destination_path)
                        .map_err(|source| io_error(decision.destination_path, source))?;
                    0
                }
                ExtractionEntryKind::Hardlink { .. } | ExtractionEntryKind::Device | ExtractionEntryKind::Special => {
                    return Err(invalid(path, format!("unsupported MTREE entry type for {}", entry.path)));
                }
            };
            report.entries = report.entries.saturating_add(1);
            report.bytes = report.bytes.saturating_add(written);
            Ok(written)
        })?;
    }

    Ok(report)
}

/// True for the manifest's `.` root record, which carries no path component.
fn is_tree_root(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let trimmed = text.trim_start_matches("./");
    trimmed.is_empty() || trimmed == "."
}

fn normalize_path(path: &Path) -> Result<String, MtreeError> {
    let raw = path.to_string_lossy();
    crate::safety::normalize_archive_path(&raw).map_err(MtreeError::Safety)
}

fn read_manifest(path: &Path) -> Result<Vec<u8>, MtreeError> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::new();
    file.take(MAX_MTREE_BYTES.saturating_add(1)).read_to_end(&mut bytes).map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_MTREE_BYTES {
        return Err(invalid(path, format!("manifest exceeds {MAX_MTREE_BYTES} byte limit")));
    }
    validate_type_parameters(path, &bytes)?;
    Ok(bytes)
}

fn validate_type_parameters(path: &Path, bytes: &[u8]) -> Result<(), MtreeError> {
    for line in bytes.split(|byte| *byte == b'\n') {
        for token in line.split(|byte| *byte == b' ').filter(|token| !token.is_empty()) {
            let Some(value) = token.strip_prefix(b"type=") else {
                continue;
            };
            if !matches!(value, b"block" | b"char" | b"dir" | b"fifo" | b"file" | b"link" | b"socket") {
                return Err(invalid(path, format!("invalid MTREE file type {:?}", String::from_utf8_lossy(value))));
            }
        }
    }
    Ok(())
}

fn map_kind(file_type: manifest::FileType) -> BrowserEntryKind {
    match file_type {
        manifest::FileType::Directory => BrowserEntryKind::Directory,
        manifest::FileType::SymbolicLink => BrowserEntryKind::Symlink,
        manifest::FileType::File => BrowserEntryKind::File,
        manifest::FileType::BlockDevice | manifest::FileType::CharacterDevice | manifest::FileType::Fifo | manifest::FileType::Socket => {
            BrowserEntryKind::Special
        }
    }
}

fn invalid(path: &Path, error: impl fmt::Display) -> MtreeError {
    MtreeError::Invalid { path: path.to_path_buf(), message: error.to_string() }
}

fn io_error(path: &Path, source: io::Error) -> MtreeError {
    MtreeError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
mod tests {
    //! Regression corpus for the MTREE reader.
    //!
    //! The `expected` strings were captured from the previous `mtree`-crate
    //! implementation before it was replaced, so they pin observable output
    //! across the swap. Two cases deliberately differ; both are marked, and
    //! both were failures before.

    use super::{MtreeError, list};
    use crate::test_support::TestDir;

    /// `(name, manifest, expected rendering)`.
    const CASES: &[(&str, &str, &str)] = &[
        (
            "flat_fixture_shape",
            "#mtree\n\
             ./payload gname=staff uname=zz time=1787753256.763303226 mode=755 gid=20 uid=501 type=dir\n\
             ./payload/README.txt gname=staff uname=zz time=1787753256.763373225 mode=644 gid=20 uid=501 type=file size=25\n\
             ./payload/nested gname=staff uname=zz time=1787753256.766384870 mode=755 gid=20 uid=501 type=dir\n\
             ./payload/nested/file.txt gname=staff uname=zz time=1787753256.764843236 mode=644 gid=20 uid=501 type=file size=20\n\
             ./payload/nested/readme-link.txt gname=staff uname=zz mode=755 gid=20 uid=501 type=link link=../README.txt\n",
            "[0] payload dir None None\n\
             [1] payload/README.txt file Some(25) None\n\
             [2] payload/nested dir None None\n\
             [3] payload/nested/file.txt file Some(20) None\n\
             [4] payload/nested/readme-link.txt link None Some(\"../README.txt\")",
        ),
        (
            "every_file_type",
            "./b type=block\n./c type=char\n./d type=dir\n./f type=fifo\n./r type=file size=7\n./l type=link link=./r\n./s type=socket\n",
            "[0] b block None None\n[1] c char None None\n[2] d dir None None\n[3] f fifo None None\n[4] r file Some(7) None\n[5] l link None Some(\"./r\")\n[6] s socket None None",
        ),
        ("type_absent_defaults_to_file", "./no-type-keyword size=3\n", "[0] no-type-keyword file Some(3) None"),
        (
            "set_defaults_apply",
            "/set type=file size=11\n./a\n./b size=22\n./c type=dir\n",
            "[0] a file Some(11) None\n[1] b file Some(22) None\n[2] c dir Some(11) None",
        ),
        ("set_redefined_midway", "/set type=file\n./a\n/set type=dir\n./b\n", "[0] a file None None\n[1] b dir None None"),
        ("comments_and_blank_lines", "#leading\n\n./a type=file size=1\n\n#trailing\n./b type=dir\n", "[0] a file Some(1) None\n[1] b dir None None"),
        (
            "dotdot_lines",
            "./a type=dir\n./a/b type=file size=2\n..\n./c type=file size=3\n",
            "[0] a dir None None\n[1] a/b file Some(2) None\n[2] c file Some(3) None",
        ),
        ("size_absent_on_file", "./a type=file\n", "[0] a file None None"),
        ("link_without_target", "./a type=link\n", "[0] a link None None"),
        ("trailing_whitespace_and_extra_spaces", "./a   type=file    size=5\n", "[0] a file Some(5) None"),
        ("no_trailing_newline", "./a type=file size=9", "[0] a file Some(9) None"),
        ("duplicate_path_rejected", "./a type=file size=1\n./a type=file size=2\n", "ERR invalid MTREE <manifest>: duplicate path a"),
        ("invalid_type_rejected", "./a type=wormhole\n", "ERR invalid MTREE <manifest>: invalid MTREE file type \"wormhole\""),
        ("empty_manifest", "", ""),
        ("only_comments", "#mtree\n#nothing else\n", ""),
        ("relative_single_name", "onlyname type=file size=4\n", "[0] onlyname file Some(4) None"),
        // --- Deliberate improvements over the previous implementation. ---
        // Was: ERR "the selected MTREE parser does not support /unset directives".
        // The replaced crate hit `unimplemented!()` on `/unset`, so the reader
        // rejected the manifest up front rather than panicking.
        ("unset_clears_a_set_default", "/set type=file\n/unset type\n./a\n", "[0] a file None None"),
        // Was: ERR "archive path is empty". The previous crate joined relative
        // records onto the *process* working directory and never pushed
        // directory records, so the standard nested form `mtree -c` emits could
        // not be read at all.
        (
            "relative_form_nested",
            "/set type=file\n. type=dir\nfile1 size=1\nsubdir type=dir\nnested size=2\n..\nfile2 size=3\n",
            "[0] file1 file Some(1) None\n[1] subdir dir None None\n[2] subdir/nested file Some(2) None\n[3] file2 file Some(3) None",
        ),
        // --- Behaviour the previous crate had no notion of. ---
        // BSD `mtree` vis(3)-escapes spaces in path words; decoding them is what
        // keeps a name with a space from splitting into two tokens.
        ("octal_escape_in_name", "./with\\040space type=file size=1\n", "[0] with space file Some(1) None"),
        ("tab_separated_fields", "./a\ttype=file\tsize=6\n", "[0] a file Some(6) None"),
        // Path safety is enforced by the shared normalizer, not the parser.
        (
            "parent_traversal_rejected",
            "../escape type=file size=1\n",
            "ERR MTREE path rejected by extraction safety: archive path attempts parent traversal: ../escape",
        ),
        ("absolute_path_rejected", "/etc/passwd type=file size=1\n", "ERR invalid MTREE <manifest>: line 1: unknown directive /etc/passwd"),
        ("invalid_size_rejected", "./a type=file size=notanumber\n", "ERR invalid MTREE <manifest>: line 1: invalid MTREE size \"notanumber\""),
    ];

    fn run(manifest: &str) -> (Result<Vec<super::MtreeEntry>, MtreeError>, String) {
        let temp = TestDir::new("mtree-regression");
        temp.write_file("case.mtree", manifest.as_bytes());
        let path = temp.path("case.mtree");
        let outcome = list(&path);
        (outcome, path.display().to_string())
    }

    /// Renders an outcome as a stable, diffable string with the temporary
    /// manifest path elided so the expectation is machine-independent.
    fn render(manifest: &str) -> String {
        let (outcome, path) = run(manifest);
        match outcome {
            Ok(entries) => entries
                .iter()
                .map(|entry| format!("[{}] {} {} {:?} {:?}", entry.index, entry.path, entry.file_type, entry.size, entry.link_target))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(error) => format!("ERR {}", error.to_string().replace(&path, "<manifest>")),
        }
    }

    #[test]
    fn reader_output_matches_golden_corpus() {
        for (name, manifest, expected) in CASES {
            let normalized_expectation: String = expected.lines().map(str::trim_start).collect::<Vec<_>>().join("\n");
            assert_eq!(render(manifest), normalized_expectation, "case {name}");
        }
    }

    #[test]
    fn reader_never_panics_on_hostile_input() {
        let hostile: &[&[u8]] = &[
            b"\xff\xfe\x00\x01 type=file",
            b"/set",
            b"/unset",
            b"..",
            b"../../..",
            b"\\",
            b"./a type=",
            b"./a size=",
            b"./a link=",
            b"./a size=99999999999999999999999999",
            b"=",
            b"./a =value",
            b"\n\n\n",
            b"/notadirective x=1",
        ];
        for case in hostile {
            let temp = TestDir::new("mtree-hostile");
            temp.write_file("case.mtree", case);
            // The contract is "returns", not "succeeds": malformed input must
            // surface as an error rather than unwinding.
            let _ = list(temp.path("case.mtree"));
        }
    }

    /// Unix filenames are arbitrary bytes. The replaced crate preserved them
    /// through `OsStr::from_bytes`; a lossy conversion would silently rename
    /// the symlink target, so the reader must hand back the exact bytes.
    #[test]
    #[cfg(unix)]
    fn non_utf8_link_target_keeps_its_exact_bytes() {
        use std::os::unix::ffi::OsStrExt as _;
        let temp = TestDir::new("mtree-non-utf8");
        temp.write_file("case.mtree", b"./link type=link link=../caf\xe9.txt\n");
        let entries = list(temp.path("case.mtree")).expect("manifest parses");
        assert_eq!(entries.len(), 1);
        let target = entries[0].link_target.as_deref().expect("link target");
        assert_eq!(target.as_os_str().as_bytes(), b"../caf\xe9.txt", "link target bytes must survive verbatim");
    }

    #[test]
    fn reads_the_repository_fixture() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/archives/basic.mtree");
        let entries = list(&fixture).expect("fixture parses");
        assert_eq!(entries.len(), 5, "fixture entry count");
        assert_eq!(entries[0].path, "payload");
        assert_eq!(entries[4].file_type, "link");
        assert_eq!(entries[4].link_target.as_deref(), Some(std::path::Path::new("../README.txt")));
    }
}
