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
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
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
const ZMU_UNRAR_DESTINATION_TOO_LONG: c_int = -1001;

const KIBIBYTE_BYTES: u64 = 1024;
const MEBIBYTE_BYTES: u64 = 1024 * KIBIBYTE_BYTES;
const MAX_LARGE_DICTIONARY_MIB: u64 = 512;

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

type ListCallback =
    extern "C" fn(*mut c_void, *const c_char, u64, u64, c_uint, c_uint, *const c_char) -> c_int;

type ExtractCallback = extern "C" fn(
    *mut c_void,
    *const c_char,
    u64,
    c_uint,
    c_uint,
    *const c_char,
    *mut c_char,
    usize,
) -> c_int;

unsafe extern "C" {
    fn zmu_unrar_list(
        archive: *const c_char,
        password: *const c_char,
        user: *mut c_void,
        callback: ListCallback,
    ) -> c_int;

    fn zmu_unrar_extract(
        archive: *const c_char,
        password: *const c_char,
        user: *mut c_void,
        callback: ExtractCallback,
    ) -> c_int;

    fn zmu_unrar_large_dictionary_allowed(dict_size_kb: u64) -> c_int;
}

/// One RAR archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RarEntry {
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
    /// `UnRAR` reported a numeric status.
    Status { code: i32, message: &'static str },
    /// `UnRAR` callback received invalid UTF-8.
    InvalidEntryName,
    /// Selected destination cannot be passed to the C ABI.
    InvalidDestination { path: PathBuf, reason: String },
    /// The extraction callback could not fit the selected destination path.
    DestinationTooLong { path: PathBuf },
}

impl fmt::Display for UnrarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, reason } => {
                write!(f, "invalid RAR archive path {}: {reason}", path.display())
            }
            Self::Status { code, message } => write!(f, "UnRAR failed with {message} ({code})"),
            Self::InvalidEntryName => write!(f, "UnRAR entry name is not valid UTF-8"),
            Self::InvalidDestination { path, reason } => {
                write!(f, "invalid RAR destination {}: {reason}", path.display())
            }
            Self::DestinationTooLong { path } => {
                write!(f, "RAR destination path is too long: {}", path.display())
            }
        }
    }
}

impl std::error::Error for UnrarError {}

/// Returns whether a large RAR dictionary request is within `ZManager`'s limit.
#[must_use]
pub fn large_dictionary_allowed_bytes(bytes: u64) -> bool {
    let kilobytes = bytes.div_ceil(KIBIBYTE_BYTES);
    unsafe { zmu_unrar_large_dictionary_allowed(kilobytes) == 1 }
}

/// Lists RAR entries through the bundled `UnRAR` source.
///
/// # Errors
///
/// Returns [`UnrarError`] when the archive cannot be opened, decrypted, or read.
pub fn list_archive(
    archive: impl AsRef<Path>,
    password: Option<&str>,
) -> Result<Vec<RarEntry>, UnrarError> {
    let archive = path_to_cstring(archive.as_ref())?;
    let password = optional_password_to_c_buffer(password)?;
    let mut context = ListContext {
        entries: Vec::new(),
        error: None,
    };

    let code = unsafe {
        zmu_unrar_list(
            archive.as_ptr(),
            optional_c_buffer_ptr(password.as_ref()),
            ptr::from_mut(&mut context).cast::<c_void>(),
            list_callback,
        )
    };

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
pub fn extract_selected(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selections: &BTreeMap<String, PathBuf>,
) -> Result<(), UnrarError> {
    extract_selected_with_progress(archive, password, selections, None)
}

/// Extracts selected RAR file entries to exact destination paths and emits
/// progress callbacks.
///
/// The caller is responsible for validating archive paths and preparing
/// destination parent directories before calling this function.
///
/// # Errors
///
/// Returns [`UnrarError`] when `UnRAR` cannot extract the archive, a selected
/// destination cannot be passed to the C ABI, or the progress callback fails.
pub fn extract_selected_with_progress(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selections: &BTreeMap<String, PathBuf>,
    progress: Option<&mut dyn FnMut(String, u64)>,
) -> Result<(), UnrarError> {
    let archive = path_to_cstring(archive.as_ref())?;
    let password = optional_password_to_c_buffer(password)?;
    let mut context = ExtractContext {
        selections,
        error: None,
        progress,
    };

    let code = unsafe {
        zmu_unrar_extract(
            archive.as_ptr(),
            optional_c_buffer_ptr(password.as_ref()),
            ptr::from_mut(&mut context).cast::<c_void>(),
            extract_callback,
        )
    };

    if let Some(error) = context.error {
        return Err(error);
    }
    check_status(code)
}

struct ListContext {
    entries: Vec<RarEntry>,
    error: Option<UnrarError>,
}

struct ExtractContext<'a, 'b> {
    selections: &'a BTreeMap<String, PathBuf>,
    error: Option<UnrarError>,
    progress: Option<&'b mut dyn FnMut(String, u64)>,
}

extern "C" fn list_callback(
    user: *mut c_void,
    path: *const c_char,
    unpacked_size: u64,
    dictionary_size: u64,
    flags: c_uint,
    redir_type: c_uint,
    redir_target: *const c_char,
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
        path,
        unpacked_size,
        dictionary_size,
        kind: entry_kind(flags, redir_type),
        link_target,
        encrypted: (flags & RHDF_ENCRYPTED) != 0,
        solid: (flags & RHDF_SOLID) != 0,
    });

    0
}

extern "C" fn extract_callback(
    user: *mut c_void,
    path: *const c_char,
    unpacked_size: u64,
    _flags: c_uint,
    _redir_type: c_uint,
    _redir_target: *const c_char,
    destination: *mut c_char,
    destination_size: usize,
) -> c_int {
    let context = unsafe { &mut *user.cast::<ExtractContext<'_, '_>>() };
    let Some(path) = c_path_to_string(path) else {
        context.error = Some(UnrarError::InvalidEntryName);
        return -1;
    };
    let Some(destination_path) = context.selections.get(&path) else {
        return 0;
    };

    if let Some(progress) = context.progress.as_mut() {
        progress(path.clone(), unpacked_size);
    }

    let destination_string = match destination_to_cstring(destination_path) {
        Ok(destination) => destination,
        Err(error) => {
            context.error = Some(error);
            return -1;
        }
    };
    let bytes = destination_string.as_bytes_with_nul();
    if bytes.len() > destination_size {
        context.error = Some(UnrarError::DestinationTooLong {
            path: destination_path.clone(),
        });
        return -2;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), destination, bytes.len());
    }
    1
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

fn optional_c_path_to_string(path: *const c_char) -> Result<Option<String>, UnrarError> {
    if path.is_null() {
        return Ok(None);
    }
    let value = unsafe { CStr::from_ptr(path) }
        .to_str()
        .map_err(|_| UnrarError::InvalidEntryName)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_owned()))
    }
}

fn c_path_to_string(path: *const c_char) -> Option<String> {
    if path.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(path) }
        .to_str()
        .ok()
        .map(ToOwned::to_owned)
}

fn path_to_cstring(path: &Path) -> Result<CString, UnrarError> {
    let Some(text) = path.to_str() else {
        return Err(UnrarError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8".to_owned(),
        });
    };
    CString::new(text).map_err(|source| UnrarError::InvalidPath {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

fn destination_to_cstring(path: &Path) -> Result<CString, UnrarError> {
    let Some(text) = path.to_str() else {
        return Err(UnrarError::InvalidDestination {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8".to_owned(),
        });
    };
    CString::new(text).map_err(|source| UnrarError::InvalidDestination {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

fn optional_password_to_c_buffer(
    password: Option<&str>,
) -> Result<Option<Zeroizing<Vec<u8>>>, UnrarError> {
    password
        .filter(|password| !password.is_empty())
        .map(|password| {
            if password.as_bytes().contains(&0) {
                return Err(UnrarError::InvalidPath {
                    path: PathBuf::from("<password>"),
                    reason: "password contains a NUL byte".to_owned(),
                });
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

    if code == ZMU_UNRAR_DESTINATION_TOO_LONG {
        return Err(UnrarError::Status {
            code,
            message: "destination path too long",
        });
    }

    Err(UnrarError::Status {
        code,
        message: status_message(code),
    })
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
        ZMU_UNRAR_DESTINATION_TOO_LONG => "destination path too long",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LARGE_DICTIONARY_BYTES, large_dictionary_allowed_bytes};

    #[test]
    fn large_dictionary_policy_allows_up_to_512_mib() {
        assert!(large_dictionary_allowed_bytes(
            MAX_LARGE_DICTIONARY_BYTES - 1
        ));
        assert!(large_dictionary_allowed_bytes(MAX_LARGE_DICTIONARY_BYTES));
        assert!(!large_dictionary_allowed_bytes(
            MAX_LARGE_DICTIONARY_BYTES + 1
        ));
    }
}
