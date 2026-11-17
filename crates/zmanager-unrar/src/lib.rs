//! Extraction-only bridge to the bundled `UnRAR` source.
//!
//! `UnRAR` source code may be used in any software to handle RAR archives
//! without limitations free of charge, but cannot be used to develop RAR
//! (`WinRAR`) compatible archiver and to re-create RAR compression algorithm,
//! which is proprietary. Distribution of modified `UnRAR` source code in
//! separate form or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "`UnRAR` source code" words, is
//! included in license, or in documentation if license is not available, and
//! in source code comments of resulting package.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroizing;

const ERAR_SUCCESS: c_int = 0;
const ERAR_NO_MEMORY: c_int = 11;
const ERAR_BAD_DATA: c_int = 12;
const ERAR_BAD_ARCHIVE: c_int = 13;
const ERAR_UNKNOWN_FORMAT: c_int = 14;
const ERAR_EOPEN: c_int = 15;
const ERAR_ECREATE: c_int = 16;
const ERAR_ECLOSE: c_int = 17;
const ERAR_EREAD: c_int = 18;
const ERAR_EWRITE: c_int = 19;
const ERAR_MISSING_PASSWORD: c_int = 22;
const ERAR_BAD_PASSWORD: c_int = 24;
const ERAR_LARGE_DICT: c_int = 25;

const ZMU_UNRAR_ABORTED: c_int = -1000;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const MIN_RAR_BLOCK_HEADER_BYTES: u64 = 7;

const KIBIBYTE_BYTES: u64 = 1024;
const MEBIBYTE_BYTES: u64 = 1024 * KIBIBYTE_BYTES;
const MAX_LARGE_DICTIONARY_MIB: u64 = 512;

// The bundled UnRAR implementation keeps error state in a process-global
// `ErrHandler`, so separate archive handles are not thread-safe with respect
// to one another. Keep each complete bridge operation isolated from every
// other operation.
static UNRAR_OPERATION_LOCK: Mutex<()> = Mutex::new(());

/// Maximum RAR dictionary size accepted by the bundled `UnRAR` bridge.
pub const MAX_LARGE_DICTIONARY_BYTES: u64 = MAX_LARGE_DICTIONARY_MIB * MEBIBYTE_BYTES;

const RHDF_ENCRYPTED: u32 = 0x04;
const RHDF_SOLID: u32 = 0x10;
const RHDF_DIRECTORY: u32 = 0x20;

const FSREDIR_NONE: u32 = 0;
const FSREDIR_UNIXSYMLINK: u32 = 1;
const FSREDIR_WINSYMLINK: u32 = 2;
const FSREDIR_JUNCTION: u32 = 3;
const FSREDIR_HARDLINK: u32 = 4;
const FSREDIR_FILECOPY: u32 = 5;

type ListCallback = extern "C" fn(*mut c_void, *const c_char, u64, u64, c_uint, c_uint, *const c_char, u32, u64) -> c_int;

type ExtractCallback = extern "C" fn(*mut c_void, usize, *const c_char, u64, c_uint, c_uint, bool) -> c_int;

type ExtractEventCallback = extern "C" fn(*mut c_void, c_int, *const u8, usize) -> c_int;

// Mirrors the `ZMU_UNRAR_EVENT_*` constants in the C++ bridge.
const ZMU_UNRAR_EVENT_DATA: c_int = 1;
const ZMU_UNRAR_EVENT_ENTRY_DONE: c_int = 2;

unsafe extern "C" {
    fn zmu_unrar_list(archive: *const c_char, password: *const c_char, user: *mut c_void, callback: ListCallback) -> c_int;

    fn zmu_unrar_extract(
        archive: *const c_char,
        password: *const c_char,
        user: *mut c_void,
        callback: ExtractCallback,
        event_callback: ExtractEventCallback,
    ) -> c_int;

    #[cfg(test)]
    fn zmu_unrar_large_dictionary_allowed(dict_size_kb: u64) -> c_int;
}

/// One RAR archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarEntry {
    /// Ordinal of the logical entry, excluding multipart continuation headers.
    pub index: usize,
    /// Archive path reported by `UnRAR`.
    pub path: String,
    /// Uncompressed size in bytes.
    pub unpacked_size: u64,
    /// RAR dictionary size in bytes for this entry.
    pub dictionary_size: u64,
    /// Portable entry kind.
    pub kind: RarEntryKind,
    /// Link or file-copy target for RAR redirection entries.
    pub link_target: Option<String>,
    /// Whether entry data is encrypted.
    pub encrypted: bool,
    /// Whether the entry is part of a solid archive.
    pub solid: bool,
    /// Original file attributes (Unix or Windows).
    pub file_attr: u32,
    /// Modification time (Windows FILETIME).
    pub mtime: u64,
}

/// Portable RAR entry type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RarEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link or junction.
    Symlink,
    /// Hard link or file-copy redirection.
    Hardlink,
    /// File-copy redirection.
    FileCopy,
    /// Unknown redirection type.
    Special,
}

/// Error returned by the `UnRAR` bridge.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnrarError {
    /// Path cannot be passed to the C ABI.
    InvalidPath { path: PathBuf, reason: String },
    /// The file is too short to contain a RAR block after its signature.
    InvalidArchive { path: PathBuf, reason: String },
    /// `UnRAR` reported a numeric status.
    Status { code: i32, message: &'static str },
    /// `UnRAR` callback received invalid UTF-8.
    InvalidEntryName,
    /// Selected destination cannot be passed to the C ABI.
    InvalidDestination { path: PathBuf, reason: String },
    /// The extraction callback could not fit the selected destination path.
    DestinationTooLong { path: PathBuf },
    /// Selected entry is missing, ambiguous, or changed since listing.
    UnexpectedEntry { path: String },
    /// Decoding would exceed the configured allowance.
    DecodedLimit { limit: u64 },
    /// Actual payload size did not match the selected entry's header.
    DecodedSizeMismatch { path: String },
    /// Writing the decoded payload failed.
    Output { path: String, kind: io::ErrorKind, reason: String },
    /// Extraction was cancelled by the caller.
    Cancelled,
}

impl fmt::Display for UnrarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, reason } => {
                write!(f, "invalid RAR archive path {}: {reason}", path.display())
            }
            Self::InvalidArchive { path, reason } => {
                write!(f, "invalid RAR archive {}: {reason}", path.display())
            }
            Self::Status { code, message } => write!(f, "UnRAR failed with {message} ({code})"),
            Self::InvalidEntryName => write!(f, "UnRAR entry name is not valid UTF-8"),
            Self::InvalidDestination { path, reason } => {
                write!(f, "invalid RAR destination {}: {reason}", path.display())
            }
            Self::DestinationTooLong { path } => {
                write!(f, "RAR destination path is too long: {}", path.display())
            }
            Self::UnexpectedEntry { path } => write!(f, "missing, ambiguous, or changed RAR file entry: {path}"),
            Self::DecodedLimit { limit } => write!(f, "RAR decoding exceeds the configured {limit}-byte limit"),
            Self::DecodedSizeMismatch { path } => write!(f, "decoded RAR file size does not match its header: {path}"),
            Self::Output { path, reason, .. } => write!(f, "could not write decoded RAR file {path}: {reason}"),
            Self::Cancelled => write!(f, "RAR extraction was cancelled"),
        }
    }
}

impl std::error::Error for UnrarError {}

/// Returns whether a large RAR dictionary request is within `ZManager`'s limit.
#[must_use]
#[cfg(test)]
fn large_dictionary_allowed_bytes(bytes: u64) -> bool {
    let kilobytes = bytes.div_ceil(KIBIBYTE_BYTES);
    unsafe { zmu_unrar_large_dictionary_allowed(kilobytes) == 1 }
}

/// Lists RAR entries through the bundled `UnRAR` source.
///
/// # Errors
///
/// Returns [`UnrarError`] when the archive cannot be opened, decrypted, or read.
pub fn list_archive(archive: impl AsRef<Path>, password: Option<&str>) -> Result<Vec<RarEntry>, UnrarError> {
    let _operation_guard = UNRAR_OPERATION_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let archive_path = archive.as_ref();
    validate_archive_prefix(archive_path)?;
    let archive = path_to_cstring(archive_path)?;
    let password = optional_password_to_c_buffer(password)?;
    let mut context = ListContext { entries: Vec::new(), error: None };

    let code =
        unsafe { zmu_unrar_list(archive.as_ptr(), optional_c_buffer_ptr(password.as_ref()), ptr::from_mut(&mut context).cast::<c_void>(), list_callback) };

    if let Some(error) = context.error {
        return Err(error);
    }
    check_status(code)?;
    Ok(context.entries)
}

/// Extracts selected RAR file entries to exact destination paths.
///
/// The caller is responsible for validating archive paths and preparing
/// destination parent directories before calling this function.
///
/// # Errors
///
/// Returns [`UnrarError`] when `UnRAR` cannot extract the archive or a selected
/// destination cannot be passed to the C ABI.
pub fn extract_selected(archive: impl AsRef<Path>, password: Option<&str>, selections: &BTreeMap<String, PathBuf>) -> Result<(), UnrarError> {
    extract_paths(archive.as_ref(), password, selections, None)
}

/// Observes a selected-entry extraction.
///
/// Every method has a no-op default so callers implement only what they use.
pub trait ExtractObserver {
    /// Returns `true` to stop extraction with [`UnrarError::Cancelled`].
    ///
    /// Polled before every archive header and after every decoded chunk of a
    /// selected entry, so a single large entry is interruptible too.
    fn is_cancelled(&mut self) -> bool {
        false
    }

    /// A selected entry is about to be written.
    fn entry_started(&mut self, path: &str, unpacked_size: u64) {
        let _ = (path, unpacked_size);
    }

    /// `bytes` more decoded bytes of the entry reported by the last
    /// [`Self::entry_started`] have been written.
    fn bytes_written(&mut self, path: &str, bytes: u64) {
        let _ = (path, bytes);
    }

    /// The entry reported by the last [`Self::entry_started`] is completely
    /// written.
    fn entry_finished(&mut self, path: &str) {
        let _ = path;
    }
}

/// Extracts selected RAR file entries to exact destination paths, reporting
/// progress to and polling cancellation from `observer`.
///
/// A partially decoded file is discarded. Finished files remain available.
///
/// The caller validates archive paths and prepares destination parents.
///
/// # Errors
///
/// Returns an error if a path cannot be selected uniquely, decoding or writing
/// fails, or the observer cancels.
pub fn extract_selected_with_observer(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selections: &BTreeMap<String, PathBuf>,
    observer: &mut dyn ExtractObserver,
) -> Result<(), UnrarError> {
    extract_paths(archive.as_ref(), password, selections, Some(observer))
}

fn extract_paths(
    archive: &Path,
    password: Option<&str>,
    selections: &BTreeMap<String, PathBuf>,
    observer: Option<&mut dyn ExtractObserver>,
) -> Result<(), UnrarError> {
    let mut files = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in list_archive(archive, password)? {
        let Some(path) = selections.get(&entry.path) else { continue };
        if entry.kind != RarEntryKind::File || !seen.insert(entry.path.clone()) {
            return Err(UnrarError::UnexpectedEntry { path: entry.path });
        }
        files.insert(entry.index, RarFileDestination { entry, path: path.clone(), replace_existing: true });
    }
    if let Some(path) = selections.keys().find(|path| !seen.contains(*path)) {
        return Err(UnrarError::UnexpectedEntry { path: path.clone() });
    }
    extract_files(archive, password, &files, observer)
}

/// A regular archive member and its caller-validated destination.
pub struct RarFileDestination {
    /// The entry returned by listing.
    pub entry: RarEntry,
    /// Exact output path.
    pub path: PathBuf,
    /// Whether a completed file may replace an existing path.
    pub replace_existing: bool,
}

/// Extracts exact regular-file entries and publishes each after checksum verification.
///
/// # Errors
///
/// Returns an error if a selection changed, decoding or writing fails, or
/// the observer cancels.
pub fn extract_files(
    archive: &Path,
    password: Option<&str>,
    files: &BTreeMap<usize, RarFileDestination>,
    observer: Option<&mut dyn ExtractObserver>,
) -> Result<(), UnrarError> {
    if let Some((_, file)) = files.iter().find(|(index, file)| **index != file.entry.index) {
        return Err(UnrarError::UnexpectedEntry { path: file.entry.path.clone() });
    }
    let mut sink = FileSink { files, observer, output: None };
    decode_files(archive, password, files.values().map(|file| &file.entry), None, &mut sink)
}

struct FileSink<'a, 'b> {
    files: &'a BTreeMap<usize, RarFileDestination>,
    observer: Option<&'b mut dyn ExtractObserver>,
    output: Option<tempfile::NamedTempFile>,
}

impl DecodeSink for FileSink<'_, '_> {
    fn is_cancelled(&mut self) -> bool {
        self.observer.as_mut().is_some_and(|observer| observer.is_cancelled())
    }

    fn entry_started(&mut self, entry: &RarEntry) -> io::Result<()> {
        let parent = self.files[&entry.index].path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        self.output = Some(tempfile::NamedTempFile::new_in(parent)?);
        if let Some(observer) = self.observer.as_mut() {
            observer.entry_started(&entry.path, entry.unpacked_size);
        }
        Ok(())
    }

    fn write_data(&mut self, entry: &RarEntry, bytes: &[u8]) -> io::Result<()> {
        self.output.as_mut().expect("entry started").write_all(bytes)?;
        if let Some(observer) = self.observer.as_mut() {
            observer.bytes_written(&entry.path, bytes.len() as u64);
        }
        Ok(())
    }

    fn entry_finished(&mut self, entry: &RarEntry) -> io::Result<()> {
        let output = self.output.take().expect("entry started");
        let destination = &self.files[&entry.index];
        if destination.replace_existing {
            output.persist(&destination.path)?;
        } else {
            output.persist_noclobber(&destination.path)?;
        }
        if let Some(observer) = self.observer.as_mut() {
            observer.entry_finished(&entry.path);
        }
        Ok(())
    }
}

/// Receives checksummed regular-file payloads without giving native code
/// filesystem destinations. Chunks arrive before checksum verification.
pub trait DecodeSink {
    /// Whether to stop at the next header or chunk.
    fn is_cancelled(&mut self) -> bool {
        false
    }

    /// Begins reading the selected entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink cannot begin accepting the file.
    fn entry_started(&mut self, _entry: &RarEntry) -> io::Result<()> {
        Ok(())
    }

    /// Consumes a decoded chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if consuming the chunk fails.
    fn write_data(&mut self, entry: &RarEntry, bytes: &[u8]) -> io::Result<()>;

    /// Finishes the selected entry after successful checksum verification.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink cannot finish writing the file.
    fn entry_finished(&mut self, _entry: &RarEntry) -> io::Result<()> {
        Ok(())
    }
}

/// Decodes exact entries by ordinal and checks each header against the listing.
///
/// The optional byte limit covers selected files and declared sizes of
/// preceding solid members the native decoder must process.
///
/// # Errors
///
/// Returns an error for a changed entry, failed decode, exceeded byte limit,
/// cancellation, or sink write failure.
pub fn decode_files<'a>(
    archive_path: &Path,
    password: Option<&str>,
    entries: impl IntoIterator<Item = &'a RarEntry>,
    limit: Option<u64>,
    sink: &mut dyn DecodeSink,
) -> Result<(), UnrarError> {
    let mut selections = BTreeMap::new();
    for entry in entries {
        if entry.kind != RarEntryKind::File || selections.insert(entry.index, entry).is_some() {
            return Err(UnrarError::UnexpectedEntry { path: entry.path.clone() });
        }
    }
    if sink.is_cancelled() {
        return Err(UnrarError::Cancelled);
    }
    if selections.is_empty() {
        return Ok(());
    }
    let code;
    let mut context = ExtractContext { selections, sink, current: None, error: None, panic: None, limit, charged: 0 };
    {
        let _operation_guard = UNRAR_OPERATION_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        validate_archive_prefix(archive_path)?;
        let archive = path_to_cstring(archive_path)?;
        let password = optional_password_to_c_buffer(password)?;
        code = unsafe {
            zmu_unrar_extract(
                archive.as_ptr(),
                optional_c_buffer_ptr(password.as_ref()),
                ptr::from_mut(&mut context).cast::<c_void>(),
                extract_callback,
                extract_event_callback,
            )
        };
    }
    if let Some(panic) = context.panic {
        std::panic::resume_unwind(panic);
    }
    if let Some(error) = context.error {
        return Err(error);
    }
    check_status(code)?;
    if let Some((_, entry)) = context.selections.first_key_value() {
        return Err(UnrarError::UnexpectedEntry { path: entry.path.clone() });
    }
    Ok(())
}

struct ListContext {
    entries: Vec<RarEntry>,
    error: Option<UnrarError>,
}

struct ExtractContext<'a, 'b> {
    selections: BTreeMap<usize, &'a RarEntry>,
    sink: &'b mut dyn DecodeSink,
    current: Option<(&'a RarEntry, u64)>,
    error: Option<UnrarError>,
    panic: Option<Box<dyn std::any::Any + Send>>,
    limit: Option<u64>,
    charged: u64,
}

impl ExtractContext<'_, '_> {
    fn check_cancelled(&mut self) -> Result<(), UnrarError> {
        if self.sink.is_cancelled() { Err(UnrarError::Cancelled) } else { Ok(()) }
    }

    fn charge(&mut self, size: u64) -> Result<(), UnrarError> {
        if let Some(limit) = self.limit {
            if size > limit - self.charged {
                return Err(UnrarError::DecodedLimit { limit });
            }
            self.charged += size;
        }
        Ok(())
    }

    fn callback(&mut self, action: impl FnOnce(&mut Self) -> Result<c_int, UnrarError>) -> c_int {
        match catch_unwind(AssertUnwindSafe(|| action(self))) {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                self.error = Some(error);
                -1
            }
            Err(panic) => {
                self.panic = Some(panic);
                -1
            }
        }
    }
}

fn output_error(entry: &RarEntry, error: &io::Error) -> UnrarError {
    UnrarError::Output { path: entry.path.clone(), kind: error.kind(), reason: error.to_string() }
}

extern "C" fn list_callback(
    user: *mut c_void,
    path: *const c_char,
    unpacked_size: u64,
    dictionary_size: u64,
    flags: c_uint,
    redir_type: c_uint,
    redir_target: *const c_char,
    file_attr: u32,
    mtime: u64,
) -> c_int {
    let context = unsafe { &mut *user.cast::<ListContext>() };
    let Some(path) = c_path_to_string(path) else {
        context.error = Some(UnrarError::InvalidEntryName);
        return -1;
    };
    let link_target = match optional_c_path_to_string(redir_target) {
        Ok(link_target) => link_target,
        Err(error) => {
            context.error = Some(error);
            return -1;
        }
    };

    context.entries.push(RarEntry {
        index: context.entries.len(),
        path,
        unpacked_size,
        dictionary_size,
        kind: entry_kind(flags, redir_type),
        link_target,
        encrypted: (flags & RHDF_ENCRYPTED) != 0,
        solid: (flags & RHDF_SOLID) != 0,
        file_attr,
        mtime,
    });

    0
}

extern "C" fn extract_callback(
    user: *mut c_void,
    index: usize,
    path: *const c_char,
    unpacked_size: u64,
    flags: c_uint,
    redir_type: c_uint,
    solid_archive: bool,
) -> c_int {
    let context = unsafe { &mut *user.cast::<ExtractContext<'_, '_>>() };
    context.callback(|context| {
        context.check_cancelled()?;
        let kind = entry_kind(flags, redir_type);
        let entry = context.selections.get(&index).copied();
        if entry.is_some() || (solid_archive && kind == RarEntryKind::File) {
            context.charge(unpacked_size)?;
        }
        let Some(entry) = entry else { return Ok(0) };
        let path = c_path_to_string(path).ok_or(UnrarError::InvalidEntryName)?;
        if kind != RarEntryKind::File || path != entry.path || unpacked_size != entry.unpacked_size {
            return Err(UnrarError::UnexpectedEntry { path: entry.path.clone() });
        }
        context.sink.entry_started(entry).map_err(|error| output_error(entry, &error))?;
        context.current = Some((entry, 0));
        Ok(1)
    })
}

extern "C" fn extract_event_callback(user: *mut c_void, event: c_int, data: *const u8, size: usize) -> c_int {
    let context = unsafe { &mut *user.cast::<ExtractContext<'_, '_>>() };
    context.callback(|context| match event {
        ZMU_UNRAR_EVENT_DATA => {
            context.check_cancelled()?;
            let (entry, written) = context.current.as_mut().expect("entry started");
            if size as u64 > entry.unpacked_size - *written {
                return Err(UnrarError::DecodedSizeMismatch { path: entry.path.clone() });
            }
            if size != 0 {
                if data.is_null() || size > isize::MAX as usize {
                    return Err(UnrarError::DecodedSizeMismatch { path: entry.path.clone() });
                }
                // UnRAR owns the buffer for the duration of the callback.
                let bytes = unsafe { std::slice::from_raw_parts(data, size) };
                context.sink.write_data(entry, bytes).map_err(|error| output_error(entry, &error))?;
            }
            *written += size as u64;
            Ok(0)
        }
        ZMU_UNRAR_EVENT_ENTRY_DONE => {
            let (entry, written) = context.current.take().expect("entry started");
            if written != entry.unpacked_size {
                return Err(UnrarError::DecodedSizeMismatch { path: entry.path.clone() });
            }
            context.sink.entry_finished(entry).map_err(|error| output_error(entry, &error))?;
            context.selections.remove(&entry.index);
            Ok(c_int::from(context.selections.is_empty()))
        }
        _ => Ok(0),
    })
}

fn entry_kind(flags: u32, redir_type: u32) -> RarEntryKind {
    if (flags & RHDF_DIRECTORY) != 0 {
        return RarEntryKind::Directory;
    }

    match redir_type {
        FSREDIR_NONE => RarEntryKind::File,
        FSREDIR_UNIXSYMLINK | FSREDIR_WINSYMLINK | FSREDIR_JUNCTION => RarEntryKind::Symlink,
        FSREDIR_HARDLINK => RarEntryKind::Hardlink,
        FSREDIR_FILECOPY => RarEntryKind::FileCopy,
        _ => RarEntryKind::Special,
    }
}

fn validate_archive_prefix(path: &Path) -> Result<(), UnrarError> {
    let mut file = std::fs::File::open(path).map_err(|error| UnrarError::InvalidArchive { path: path.to_path_buf(), reason: error.to_string() })?;
    let archive_len = file.metadata().map_err(|error| UnrarError::InvalidArchive { path: path.to_path_buf(), reason: error.to_string() })?.len();
    let mut prefix = [0_u8; RAR5_SIGNATURE.len()];
    file.read_exact(&mut prefix).map_err(|error| UnrarError::InvalidArchive { path: path.to_path_buf(), reason: error.to_string() })?;
    let signature_len = if prefix.starts_with(RAR5_SIGNATURE) {
        RAR5_SIGNATURE.len()
    } else if prefix.starts_with(RAR4_SIGNATURE) {
        RAR4_SIGNATURE.len()
    } else {
        return Err(UnrarError::InvalidArchive { path: path.to_path_buf(), reason: "missing RAR signature".to_owned() });
    };
    let minimum_len = u64::try_from(signature_len).unwrap_or(u64::MAX).saturating_add(MIN_RAR_BLOCK_HEADER_BYTES);
    if archive_len < minimum_len {
        return Err(UnrarError::InvalidArchive { path: path.to_path_buf(), reason: "truncated first block header".to_owned() });
    }
    Ok(())
}

fn optional_c_path_to_string(path: *const c_char) -> Result<Option<String>, UnrarError> {
    if path.is_null() {
        return Ok(None);
    }
    let value = unsafe { CStr::from_ptr(path) }.to_str().map_err(|_| UnrarError::InvalidEntryName)?;
    if value.is_empty() { Ok(None) } else { Ok(Some(value.to_owned())) }
}

fn c_path_to_string(path: *const c_char) -> Option<String> {
    if path.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(path) }.to_str().ok().map(ToOwned::to_owned)
}

fn path_to_cstring(path: &Path) -> Result<CString, UnrarError> {
    let Some(text) = path.to_str() else {
        return Err(UnrarError::InvalidPath { path: path.to_path_buf(), reason: "path is not valid UTF-8".to_owned() });
    };
    CString::new(text).map_err(|source| UnrarError::InvalidPath { path: path.to_path_buf(), reason: source.to_string() })
}

fn optional_password_to_c_buffer(password: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, UnrarError> {
    password
        .filter(|password| !password.is_empty())
        .map(|password| {
            if password.as_bytes().contains(&0) {
                return Err(UnrarError::InvalidPath { path: PathBuf::from("<password>"), reason: "password contains a NUL byte".to_owned() });
            }
            let mut bytes = Vec::with_capacity(password.len() + 1);
            bytes.extend_from_slice(password.as_bytes());
            bytes.push(0);
            Ok(Zeroizing::new(bytes))
        })
        .transpose()
}

fn optional_c_buffer_ptr(value: Option<&Zeroizing<Vec<u8>>>) -> *const c_char {
    value.map_or(ptr::null(), |value| value.as_ptr().cast())
}

fn check_status(code: c_int) -> Result<(), UnrarError> {
    if code == ERAR_SUCCESS {
        return Ok(());
    }

    Err(UnrarError::Status { code, message: status_message(code) })
}

const fn status_message(code: c_int) -> &'static str {
    match code {
        ERAR_NO_MEMORY => "out of memory",
        ERAR_BAD_DATA => "bad archive data",
        ERAR_BAD_ARCHIVE => "bad archive",
        ERAR_UNKNOWN_FORMAT => "unknown archive format",
        ERAR_EOPEN => "open error",
        ERAR_ECREATE => "create error",
        ERAR_ECLOSE => "close error",
        ERAR_EREAD => "read error",
        ERAR_EWRITE => "write error",
        ERAR_MISSING_PASSWORD => "missing password",
        ERAR_BAD_PASSWORD => "bad password",
        ERAR_LARGE_DICT => "large dictionary exceeds configured limit",
        ZMU_UNRAR_ABORTED => "operation aborted",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LARGE_DICTIONARY_BYTES, large_dictionary_allowed_bytes};

    #[test]
    fn large_dictionary_policy_allows_up_to_512_mib() {
        assert!(large_dictionary_allowed_bytes(MAX_LARGE_DICTIONARY_BYTES - 1));
        assert!(large_dictionary_allowed_bytes(MAX_LARGE_DICTIONARY_BYTES));
        assert!(!large_dictionary_allowed_bytes(MAX_LARGE_DICTIONARY_BYTES + 1));
    }

    #[test]
    fn native_selection_uses_the_requested_ordinal_and_regular_file_type() {
        use super::{DecodeSink, ExtractContext, RHDF_DIRECTORY, RarEntry, RarEntryKind, UnrarError, extract_callback};
        use std::{io, ptr};

        struct Sink;

        impl DecodeSink for Sink {
            fn write_data(&mut self, _entry: &RarEntry, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }
        }

        let entry = RarEntry {
            index: 4,
            path: "report.txt".to_owned(),
            unpacked_size: 16,
            dictionary_size: 0,
            kind: RarEntryKind::File,
            link_target: None,
            encrypted: false,
            solid: false,
            file_attr: 0,
            mtime: 0,
        };
        let name = std::ffi::CString::new(entry.path.as_str()).unwrap();
        let mut sink = Sink;
        let mut context =
            ExtractContext { selections: [(entry.index, &entry)].into(), sink: &mut sink, current: None, error: None, panic: None, limit: None, charged: 0 };
        let user = ptr::from_mut(&mut context).cast();
        assert_eq!(extract_callback(user, entry.index + 1, name.as_ptr(), entry.unpacked_size, 0, 0, false), 0);
        assert!(context.current.is_none());
        assert_eq!(extract_callback(user, entry.index, name.as_ptr(), entry.unpacked_size, RHDF_DIRECTORY, 0, false), -1);
        assert!(matches!(context.error, Some(UnrarError::UnexpectedEntry { .. })));
    }
}
