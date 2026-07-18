//! Narrow raw FFI declarations for the libarchive APIs used by `ZManager`.
//!
//! This is intentionally not a complete libarchive binding. Keep additions
//! close to actual call sites in `zmanager-libarchive`.

use libc::{c_char, c_int, c_long, c_void, size_t, time_t};

#[allow(non_camel_case_types)]
pub enum archive {}

#[allow(non_camel_case_types)]
pub enum archive_entry {}

#[cfg(all(windows, target_pointer_width = "64"))]
#[allow(non_camel_case_types)]
pub type la_ssize_t = i64;

#[cfg(not(all(windows, target_pointer_width = "64")))]
#[allow(non_camel_case_types)]
pub type la_ssize_t = isize;

#[cfg(windows)]
#[allow(non_camel_case_types)]
pub type la_mode_t = u16;

#[cfg(not(windows))]
#[allow(non_camel_case_types)]
pub type la_mode_t = libc::mode_t;

pub const ARCHIVE_VERSION_NUMBER: c_int = 3_008_008;

pub const ARCHIVE_EOF: c_int = 1;
pub const ARCHIVE_OK: c_int = 0;
pub const ARCHIVE_RETRY: c_int = -10;
pub const ARCHIVE_WARN: c_int = -20;
pub const ARCHIVE_FAILED: c_int = -25;
pub const ARCHIVE_FATAL: c_int = -30;

pub const AE_IFMT: la_mode_t = 0o170_000 as la_mode_t;
pub const AE_IFREG: la_mode_t = 0o100_000 as la_mode_t;
pub const AE_IFLNK: la_mode_t = 0o120_000 as la_mode_t;
pub const AE_IFSOCK: la_mode_t = 0o140_000 as la_mode_t;
pub const AE_IFCHR: la_mode_t = 0o020_000 as la_mode_t;
pub const AE_IFBLK: la_mode_t = 0o060_000 as la_mode_t;
pub const AE_IFDIR: la_mode_t = 0o040_000 as la_mode_t;
pub const AE_IFIFO: la_mode_t = 0o010_000 as la_mode_t;

#[cfg(windows)]
#[allow(non_camel_case_types)]
pub type wchar_t = u16;

unsafe extern "C" {
    pub fn archive_version_number() -> c_int;
    pub fn archive_version_string() -> *const c_char;
    pub fn archive_version_details() -> *const c_char;

    pub fn archive_errno(archive: *mut archive) -> c_int;
    pub fn archive_error_string(archive: *mut archive) -> *const c_char;

    pub fn archive_read_new() -> *mut archive;
    pub fn archive_read_support_filter_all(archive: *mut archive) -> c_int;
    pub fn archive_read_support_format_all(archive: *mut archive) -> c_int;
    pub fn archive_read_add_passphrase(archive: *mut archive, passphrase: *const c_char) -> c_int;
    pub fn archive_read_open_filename(
        archive: *mut archive,
        filename: *const c_char,
        block_size: size_t,
    ) -> c_int;
    pub fn archive_read_open_filenames(
        archive: *mut archive,
        filenames: *const *const c_char,
        block_size: size_t,
    ) -> c_int;
    pub fn archive_read_next_header(archive: *mut archive, entry: *mut *mut archive_entry)
    -> c_int;
    pub fn archive_read_data(
        archive: *mut archive,
        buffer: *mut c_void,
        length: size_t,
    ) -> la_ssize_t;
    pub fn archive_read_data_skip(archive: *mut archive) -> c_int;
    pub fn archive_read_free(archive: *mut archive) -> c_int;

    pub fn archive_entry_pathname(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_pathname_utf8(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_size(entry: *mut archive_entry) -> i64;
    pub fn archive_entry_filetype(entry: *mut archive_entry) -> la_mode_t;
    pub fn archive_entry_mode(entry: *mut archive_entry) -> la_mode_t;
    pub fn archive_entry_mtime(entry: *mut archive_entry) -> time_t;
    pub fn archive_entry_mtime_nsec(entry: *mut archive_entry) -> c_long;
    pub fn archive_entry_mtime_is_set(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_symlink(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_symlink_utf8(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_hardlink(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_hardlink_utf8(entry: *mut archive_entry) -> *const c_char;
    pub fn archive_entry_is_data_encrypted(entry: *mut archive_entry) -> c_int;
    pub fn archive_entry_is_metadata_encrypted(entry: *mut archive_entry) -> c_int;
}

#[cfg(windows)]
unsafe extern "C" {
    pub fn archive_read_open_filename_w(
        archive: *mut archive,
        filename: *const wchar_t,
        block_size: size_t,
    ) -> c_int;
    pub fn archive_read_open_filenames_w(
        archive: *mut archive,
        filenames: *const *const wchar_t,
        block_size: size_t,
    ) -> c_int;
}
