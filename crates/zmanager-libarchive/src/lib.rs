//! Safe, narrow read-side wrapper around libarchive for Z-Manager.
//!
//! This crate deliberately exposes only the APIs that Z-Manager needs for
//! listing and extraction. It is not a general libarchive binding.

mod locale;

use libc::{c_char, c_int};
use std::error;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zmanager_libarchive_sys as sys;

const BLOCK_SIZE: usize = 10_240;

/// Result alias for libarchive wrapper operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error returned by the Z-Manager libarchive wrapper.
#[derive(Debug)]
pub enum Error {
    /// A libarchive operation failed.
    Archive {
        /// Libarchive return status.
        status: c_int,
        /// Native errno reported by libarchive.
        errno: c_int,
        /// Human-readable libarchive message.
        message: String,
    },
    /// Libarchive returned a null archive pointer.
    NullArchive,
    /// Libarchive returned a null entry pointer.
    NullEntry,
    /// A path or passphrase contained an interior NUL byte.
    InteriorNul(NulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive {
                status,
                errno,
                message,
            } => write!(
                f,
                "libarchive operation failed with status {status}, errno {errno}: {message}"
            ),
            Self::NullArchive => write!(f, "libarchive returned a null archive pointer"),
            Self::NullEntry => write!(f, "libarchive returned a null entry pointer"),
            Self::InteriorNul(source) => write!(f, "input contains an interior NUL byte: {source}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InteriorNul(source) => Some(source),
            Self::Archive { .. } | Self::NullArchive | Self::NullEntry => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(source: NulError) -> Self {
        Self::InteriorNul(source)
    }
}

/// Portable file type reported by libarchive.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FileType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link.
    SymbolicLink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharacterDevice,
    /// FIFO.
    Fifo,
    /// Socket.
    Socket,
    /// Unknown or unsupported entry type.
    Unknown,
}

/// Owned metadata for the current archive entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Entry {
    path: Option<String>,
    size: i64,
    mode: u32,
    file_type: FileType,
    modified: Option<SystemTime>,
    symlink: Option<String>,
    hardlink: Option<String>,
    data_encrypted: bool,
    metadata_encrypted: bool,
}

impl Entry {
    /// Raw path reported by libarchive.
    #[must_use]
    pub fn pathname(&self) -> Option<String> {
        self.path.clone()
    }

    /// Entry size reported by libarchive.
    #[must_use]
    pub fn size(&self) -> i64 {
        self.size
    }

    /// File mode reported by libarchive.
    #[must_use]
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Entry file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// Modification time, when present.
    #[must_use]
    pub fn mtime(&self) -> Option<SystemTime> {
        self.modified
    }

    /// Symlink target, when present.
    #[must_use]
    pub fn symlink(&self) -> Option<String> {
        self.symlink.clone()
    }

    /// Hardlink target, when present.
    #[must_use]
    pub fn hardlink(&self) -> Option<String> {
        self.hardlink.clone()
    }

    /// Whether entry data is encrypted.
    #[must_use]
    pub fn is_data_encrypted(&self) -> bool {
        self.data_encrypted
    }

    /// Whether entry metadata is encrypted.
    #[must_use]
    pub fn is_metadata_encrypted(&self) -> bool {
        self.metadata_encrypted
    }
}

/// Read-only libarchive handle.
pub struct ReadArchive {
    archive: NonNull<sys::archive>,
}

impl ReadArchive {
    /// Opens one archive file.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive cannot initialize or open the file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(&[path.as_ref().to_path_buf()], None)
    }

    /// Opens one archive file with a passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive cannot initialize or open the file.
    pub fn open_with_passphrase(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open_inner(&[path.as_ref().to_path_buf()], Some(passphrase))
    }

    /// Opens a multi-volume archive from already sorted part paths.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive cannot initialize or open the files.
    pub fn open_filenames(paths: &[PathBuf]) -> Result<Self> {
        Self::open_inner(paths, None)
    }

    /// Opens a multi-volume archive from already sorted part paths and a passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive cannot initialize or open the files.
    pub fn open_filenames_with_passphrase(paths: &[PathBuf], passphrase: &str) -> Result<Self> {
        Self::open_inner(paths, Some(passphrase))
    }

    fn open_inner(paths: &[PathBuf], passphrase: Option<&str>) -> Result<Self> {
        let archive = Self::new()?;
        archive.enable_read_support()?;
        if let Some(passphrase) = passphrase {
            archive.add_passphrase(passphrase)?;
        }
        archive.open_paths(paths)?;
        Ok(archive)
    }

    fn new() -> Result<Self> {
        // SAFETY: archive_read_new has no preconditions and returns either a
        // valid handle or null.
        let archive = unsafe { sys::archive_read_new() };
        let archive = NonNull::new(archive).ok_or(Error::NullArchive)?;
        Ok(Self { archive })
    }

    fn enable_read_support(&self) -> Result<()> {
        self.check_status(unsafe { sys::archive_read_support_filter_all(self.as_ptr()) })?;
        self.check_status(unsafe { sys::archive_read_support_format_all(self.as_ptr()) })?;
        Ok(())
    }

    fn add_passphrase(&self, passphrase: &str) -> Result<()> {
        let passphrase = CString::new(passphrase)?;
        self.check_status(unsafe {
            sys::archive_read_add_passphrase(self.as_ptr(), passphrase.as_ptr())
        })?;
        Ok(())
    }

    fn open_paths(&self, paths: &[PathBuf]) -> Result<()> {
        if paths.len() == 1 {
            self.open_path(&paths[0])
        } else {
            self.open_multi_path(paths)
        }
    }

    #[cfg(windows)]
    fn open_path(&self, path: &Path) -> Result<()> {
        let wide = wide_path(path);
        self.check_status(unsafe {
            sys::archive_read_open_filename_w(self.as_ptr(), wide.as_ptr(), BLOCK_SIZE)
        })?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn open_path(&self, path: &Path) -> Result<()> {
        let path = c_path(path)?;
        self.check_status(unsafe {
            sys::archive_read_open_filename(self.as_ptr(), path.as_ptr(), BLOCK_SIZE)
        })?;
        Ok(())
    }

    #[cfg(windows)]
    fn open_multi_path(&self, paths: &[PathBuf]) -> Result<()> {
        let wide_paths = paths.iter().map(|path| wide_path(path)).collect::<Vec<_>>();
        let mut pointers = wide_paths
            .iter()
            .map(|path| path.as_ptr())
            .collect::<Vec<_>>();
        pointers.push(ptr::null());

        self.check_status(unsafe {
            sys::archive_read_open_filenames_w(self.as_ptr(), pointers.as_ptr(), BLOCK_SIZE)
        })?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn open_multi_path(&self, paths: &[PathBuf]) -> Result<()> {
        let c_paths = paths
            .iter()
            .map(|path| c_path(path))
            .collect::<Result<Vec<_>>>()?;
        let mut pointers = c_paths.iter().map(|path| path.as_ptr()).collect::<Vec<_>>();
        pointers.push(ptr::null());

        self.check_status(unsafe {
            sys::archive_read_open_filenames(self.as_ptr(), pointers.as_ptr(), BLOCK_SIZE)
        })?;
        Ok(())
    }

    /// Reads the next archive entry header.
    ///
    /// Returns `Ok(None)` when the archive is exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive cannot read the next entry.
    pub fn next_entry(&mut self) -> Result<Option<Entry>> {
        let _locale = locale::Utf8LocaleGuard::new();
        let mut entry = ptr::null_mut();
        let status =
            unsafe { sys::archive_read_next_header(self.as_ptr(), std::ptr::addr_of_mut!(entry)) };
        if status == sys::ARCHIVE_EOF {
            return Ok(None);
        }
        self.check_status(status)?;

        let entry = NonNull::new(entry).ok_or(Error::NullEntry)?;
        Ok(Some(read_entry(entry)))
    }

    /// Reads data from the current file entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive reports a read failure.
    pub fn read_data(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let read = unsafe {
            sys::archive_read_data(
                self.as_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if read < 0 {
            let status = c_int::try_from(read).unwrap_or(sys::ARCHIVE_FATAL);
            Err(self.error_from_archive(status))
        } else {
            usize::try_from(read).map_err(|_| self.error_from_archive(sys::ARCHIVE_FATAL))
        }
    }

    /// Skips data for the current entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if libarchive reports a skip failure.
    pub fn skip_data(&mut self) -> Result<()> {
        let status = unsafe { sys::archive_read_data_skip(self.as_ptr()) };
        self.check_status(status)?;
        Ok(())
    }

    fn as_ptr(&self) -> *mut sys::archive {
        self.archive.as_ptr()
    }

    fn check_status(&self, status: c_int) -> Result<c_int> {
        if status < sys::ARCHIVE_OK {
            Err(self.error_from_archive(status))
        } else {
            Ok(status)
        }
    }

    fn error_from_archive(&self, status: c_int) -> Error {
        let errno = unsafe { sys::archive_errno(self.as_ptr()) };
        let message = unsafe { nullable_c_string(sys::archive_error_string(self.as_ptr())) }
            .unwrap_or_else(|| "unknown libarchive error".to_owned());
        Error::Archive {
            status,
            errno,
            message,
        }
    }
}

impl Drop for ReadArchive {
    fn drop(&mut self) {
        let _ = unsafe { sys::archive_read_free(self.as_ptr()) };
    }
}

fn read_entry(entry: NonNull<sys::archive_entry>) -> Entry {
    let entry = entry.as_ptr();
    let mode = unsafe { sys::archive_entry_mode(entry) };
    Entry {
        path: entry_string(
            entry,
            sys::archive_entry_pathname_utf8,
            sys::archive_entry_pathname,
        ),
        size: unsafe { sys::archive_entry_size(entry) },
        mode: u32::from(mode),
        file_type: file_type(unsafe { sys::archive_entry_filetype(entry) }),
        modified: modified_time(entry),
        symlink: entry_string(
            entry,
            sys::archive_entry_symlink_utf8,
            sys::archive_entry_symlink,
        ),
        hardlink: entry_string(
            entry,
            sys::archive_entry_hardlink_utf8,
            sys::archive_entry_hardlink,
        ),
        data_encrypted: unsafe { sys::archive_entry_is_data_encrypted(entry) != 0 },
        metadata_encrypted: unsafe { sys::archive_entry_is_metadata_encrypted(entry) != 0 },
    }
}

fn entry_string(
    entry: *mut sys::archive_entry,
    utf8_fn: unsafe extern "C" fn(*mut sys::archive_entry) -> *const c_char,
    fallback_fn: unsafe extern "C" fn(*mut sys::archive_entry) -> *const c_char,
) -> Option<String> {
    unsafe { nullable_c_string(utf8_fn(entry)).or_else(|| nullable_c_string(fallback_fn(entry))) }
}

unsafe fn nullable_c_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

fn file_type(value: sys::la_mode_t) -> FileType {
    match value & sys::AE_IFMT {
        sys::AE_IFREG => FileType::RegularFile,
        sys::AE_IFDIR => FileType::Directory,
        sys::AE_IFLNK => FileType::SymbolicLink,
        sys::AE_IFBLK => FileType::BlockDevice,
        sys::AE_IFCHR => FileType::CharacterDevice,
        sys::AE_IFIFO => FileType::Fifo,
        sys::AE_IFSOCK => FileType::Socket,
        _ => FileType::Unknown,
    }
}

fn modified_time(entry: *mut sys::archive_entry) -> Option<SystemTime> {
    if unsafe { sys::archive_entry_mtime_is_set(entry) } == 0 {
        return None;
    }
    let seconds = unsafe { sys::archive_entry_mtime(entry) };
    system_time_from_unix_seconds(seconds)
}

fn system_time_from_unix_seconds(seconds: libc::time_t) -> Option<SystemTime> {
    if seconds >= 0 {
        let seconds = u64::try_from(seconds).ok()?;
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
}

#[cfg(unix)]
fn c_path(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(path.as_os_str().as_bytes()).map_err(Error::from)
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<sys::wchar_t> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Returns the linked libarchive version string.
#[must_use]
pub fn version() -> String {
    unsafe { nullable_c_string(sys::archive_version_string()) }.unwrap_or_default()
}

/// Returns detailed linked libarchive version information.
#[must_use]
pub fn version_details() -> String {
    unsafe { nullable_c_string(sys::archive_version_details()) }.unwrap_or_default()
}

/// Returns the linked libarchive numeric version.
#[must_use]
pub fn version_number() -> c_int {
    unsafe { sys::archive_version_number() }
}
