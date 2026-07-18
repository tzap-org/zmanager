//! Safe, narrow `AppleArchive` wrapper for `zmanager-core`.
//!
//! The native `AppleArchive` API is available only on Apple targets. This crate
//! keeps that native boundary out of `zmanager-core`, whose workspace policy
//! denies unsafe code.

use std::error;
use std::ffi::NulError;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const APPLE_TARGET: bool = cfg!(any(target_os = "macos", target_os = "ios"));

/// Result alias for `AppleArchive` wrapper operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns whether this target can use the native `AppleArchive` library.
#[must_use]
pub const fn is_supported() -> bool {
    APPLE_TARGET
}

/// Error returned by the `AppleArchive` wrapper.
#[derive(Debug)]
pub enum Error {
    /// The native `AppleArchive` library is not available on this target.
    UnsupportedPlatform,
    /// The native library returned a null object.
    NullObject(&'static str),
    /// A native operation returned a negative status.
    Status {
        /// Operation being performed.
        operation: &'static str,
        /// Native status code.
        status: i64,
    },
    /// A native object returned an invalid size.
    SizeOutOfRange {
        /// Field or operation being converted.
        field: &'static str,
    },
    /// A file path or archive string contained an interior NUL byte.
    InteriorNul(NulError),
    /// Reader or writer callback I/O failed.
    Io(io::Error),
    /// Processing was cancelled by the caller.
    Cancelled,
    /// A file entry was shorter or longer than its declared data blob.
    SizeMismatch {
        /// Archive path.
        path: String,
        /// Declared data size.
        expected: u64,
        /// Bytes read from the caller.
        actual: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "AppleArchive is supported only on macOS and iOS")
            }
            Self::NullObject(object) => write!(f, "AppleArchive returned a null {object}"),
            Self::Status { operation, status } => {
                write!(f, "AppleArchive {operation} failed with status {status}")
            }
            Self::SizeOutOfRange { field } => {
                write!(f, "AppleArchive {field} value is out of range")
            }
            Self::InteriorNul(source) => write!(f, "input contains an interior NUL byte: {source}"),
            Self::Io(source) => write!(f, "I/O operation failed: {source}"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::SizeMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "archive entry {path} declared {expected} data bytes but source produced {actual}"
            ),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InteriorNul(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::UnsupportedPlatform
            | Self::NullObject(_)
            | Self::Status { .. }
            | Self::SizeOutOfRange { .. }
            | Self::Cancelled
            | Self::SizeMismatch { .. } => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(source: NulError) -> Self {
        Self::InteriorNul(source)
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// `AppleArchive` entry type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Character or block device.
    Device,
    /// Metadata entry.
    Metadata,
    /// FIFO, socket, whiteout, or another unsupported special type.
    Special,
}

/// Portable metadata attached to an archive entry.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct EntryMetadata {
    /// Low Unix mode bits when present.
    pub mode: Option<u32>,
    /// Modification time when present.
    pub modified: Option<SystemTime>,
}

/// Compression used for newly created `.aar` files.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum CompressionAlgorithm {
    /// No compression.
    None,
    /// LZ4 compression.
    Lz4,
    /// ZLIB compression.
    Zlib,
    /// LZMA compression.
    Lzma,
    /// LZFSE compression.
    #[default]
    Lzfse,
    /// LZBITMAP compression.
    Lzbitmap,
}

/// Options for `AppleArchive` creation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CreateOptions {
    /// Compression algorithm.
    pub compression: CompressionAlgorithm,
    /// Compression block size in bytes.
    pub block_size: usize,
    /// Native worker thread count. Zero lets `AppleArchive` choose.
    pub threads: i32,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            compression: CompressionAlgorithm::default(),
            block_size: 4 * 1024 * 1024,
            threads: 0,
        }
    }
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BlobKey {
    Data,
    Other,
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
struct EntryBlob {
    raw: platform::FieldKey,
    key: BlobKey,
    size: u64,
}

/// Owned metadata for one archive entry.
#[derive(Debug, Clone)]
pub struct Entry {
    path: String,
    kind: EntryKind,
    size: Option<u64>,
    data_size: Option<u64>,
    metadata: EntryMetadata,
    link_target: Option<PathBuf>,
    #[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
    blobs: Vec<EntryBlob>,
}

impl Entry {
    /// Raw path stored in the archive.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Entry type.
    #[must_use]
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Uncompressed file data size when present.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Data blob size when present.
    #[must_use]
    pub fn data_size(&self) -> Option<u64> {
        self.data_size
    }

    /// Portable metadata.
    #[must_use]
    pub fn metadata(&self) -> EntryMetadata {
        self.metadata
    }

    /// Symlink target when present.
    #[must_use]
    pub fn link_target(&self) -> Option<&Path> {
        self.link_target.as_deref()
    }

    /// Returns whether this entry carries a file data blob.
    #[must_use]
    pub fn has_data_blob(&self) -> bool {
        self.data_size.is_some()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod platform {
    use super::{
        BlobKey, CompressionAlgorithm, CreateOptions, Entry, EntryBlob, EntryKind, EntryMetadata,
        Error, Result,
    };
    use libc::{c_char, c_int, c_void, mode_t, size_t, timespec};
    use std::cmp;
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};
    use std::ptr::{self, NonNull};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const UINT32_APPEND: u32 = u32::MAX;
    const FIELD_TYPE_UINT: c_int = 1;
    const FIELD_TYPE_STRING: c_int = 2;
    const FIELD_TYPE_TIMESPEC: c_int = 4;
    const FIELD_TYPE_BLOB: c_int = 5;
    const ENTRY_TYPE_REG: u64 = b'F' as u64;
    const ENTRY_TYPE_DIR: u64 = b'D' as u64;
    const ENTRY_TYPE_LNK: u64 = b'L' as u64;
    #[allow(dead_code)]
    const ENTRY_TYPE_FIFO: u64 = b'P' as u64;
    const ENTRY_TYPE_CHR: u64 = b'C' as u64;
    const ENTRY_TYPE_BLK: u64 = b'B' as u64;
    #[allow(dead_code)]
    const ENTRY_TYPE_SOCK: u64 = b'S' as u64;
    const ENTRY_TYPE_METADATA: u64 = b'M' as u64;
    const COMPRESSION_NONE: u32 = 0x000;
    const COMPRESSION_LZ4: u32 = 0x100;
    const COMPRESSION_ZLIB: u32 = 0x505;
    const COMPRESSION_LZMA: u32 = 0x306;
    const COMPRESSION_LZFSE: u32 = 0x801;
    const COMPRESSION_LZBITMAP: u32 = 0x702;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub(crate) union FieldKey {
        skey: [c_char; 4],
        ikey: u32,
    }

    impl std::fmt::Debug for FieldKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let raw = unsafe { self.skey };
            #[allow(clippy::cast_sign_loss)]
            let bytes = [raw[0] as u8, raw[1] as u8, raw[2] as u8];
            write!(f, "{}", String::from_utf8_lossy(&bytes))
        }
    }

    #[allow(non_camel_case_types)]
    enum AAHeaderImpl {}
    #[allow(non_camel_case_types)]
    enum AAByteStreamImpl {}
    #[allow(non_camel_case_types)]
    enum AAArchiveStreamImpl {}

    type AAHeader = *mut AAHeaderImpl;
    type AAByteStream = *mut AAByteStreamImpl;
    type AAArchiveStream = *mut AAArchiveStreamImpl;
    type AAFlagSet = u64;
    type AACompressionAlgorithm = u32;

    #[link(name = "AppleArchive")]
    unsafe extern "C" {
        fn AAFileStreamOpenWithPath(
            path: *const c_char,
            open_flags: c_int,
            open_mode: mode_t,
        ) -> AAByteStream;
        fn AACompressionOutputStreamOpen(
            compressed_stream: AAByteStream,
            compression_algorithm: AACompressionAlgorithm,
            block_size: size_t,
            flags: AAFlagSet,
            n_threads: c_int,
        ) -> AAByteStream;
        fn AADecompressionInputStreamOpen(
            compressed_stream: AAByteStream,
            flags: AAFlagSet,
            n_threads: c_int,
        ) -> AAByteStream;
        fn AAByteStreamClose(stream: AAByteStream) -> c_int;
        fn AAEncodeArchiveOutputStreamOpen(
            stream: AAByteStream,
            msg_data: *mut c_void,
            msg_proc: *mut c_void,
            flags: AAFlagSet,
            n_threads: c_int,
        ) -> AAArchiveStream;
        fn AADecodeArchiveInputStreamOpen(
            stream: AAByteStream,
            msg_data: *mut c_void,
            msg_proc: *mut c_void,
            flags: AAFlagSet,
            n_threads: c_int,
        ) -> AAArchiveStream;
        fn AAArchiveStreamReadHeader(stream: AAArchiveStream, header: *mut AAHeader) -> c_int;
        fn AAArchiveStreamReadBlob(
            stream: AAArchiveStream,
            key: FieldKey,
            buffer: *mut c_void,
            nbyte: size_t,
        ) -> c_int;
        fn AAArchiveStreamWriteHeader(stream: AAArchiveStream, header: AAHeader) -> c_int;
        fn AAArchiveStreamWriteBlob(
            stream: AAArchiveStream,
            key: FieldKey,
            buffer: *const c_void,
            nbyte: size_t,
        ) -> c_int;
        fn AAArchiveStreamClose(stream: AAArchiveStream) -> c_int;
        fn AAHeaderCreate() -> AAHeader;
        fn AAHeaderDestroy(header: AAHeader);
        fn AAHeaderGetFieldCount(header: AAHeader) -> u32;
        fn AAHeaderGetFieldType(header: AAHeader, index: u32) -> c_int;
        fn AAHeaderGetFieldKey(header: AAHeader, index: u32) -> FieldKey;
        fn AAHeaderGetKeyIndex(header: AAHeader, key: FieldKey) -> c_int;
        fn AAHeaderGetFieldUInt(header: AAHeader, index: u32, value: *mut u64) -> c_int;
        fn AAHeaderGetFieldString(
            header: AAHeader,
            index: u32,
            capacity: size_t,
            value: *mut c_char,
            length: *mut size_t,
        ) -> c_int;
        fn AAHeaderGetFieldTimespec(header: AAHeader, index: u32, value: *mut timespec) -> c_int;
        fn AAHeaderGetFieldBlob(
            header: AAHeader,
            index: u32,
            size: *mut u64,
            offset: *mut u64,
        ) -> c_int;
        fn AAHeaderSetFieldUInt(header: AAHeader, index: u32, key: FieldKey, value: u64) -> c_int;
        fn AAHeaderSetFieldString(
            header: AAHeader,
            index: u32,
            key: FieldKey,
            value: *const c_char,
            length: size_t,
        ) -> c_int;
        fn AAHeaderSetFieldTimespec(
            header: AAHeader,
            index: u32,
            key: FieldKey,
            value: *const timespec,
        ) -> c_int;
        fn AAHeaderSetFieldBlob(header: AAHeader, index: u32, key: FieldKey, size: u64) -> c_int;
    }

    #[allow(clippy::struct_field_names)]
    pub struct ArchiveReader {
        archive_stream: ArchiveStream,
        _decompression_stream: ByteStream,
        _file_stream: ByteStream,
    }

    impl ArchiveReader {
        /// # Errors
        ///
        /// Returns an error if the underlying I/O streams cannot be created or initialized.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            let file_stream = ByteStream::open_path(path.as_ref(), libc::O_RDONLY, 0)?;
            let decompression_stream =
                ByteStream::decompression_input(file_stream.as_ptr(), "open decompression stream")?;
            let archive_stream =
                ArchiveStream::decode_input(decompression_stream.as_ptr(), "open decode stream")?;
            Ok(Self {
                archive_stream,
                _decompression_stream: decompression_stream,
                _file_stream: file_stream,
            })
        }

        /// # Errors
        ///
        /// Returns an error if reading the next entry header from the archive stream fails.
        pub fn next_entry(&mut self) -> Result<Option<Entry>> {
            let mut raw_header = ptr::null_mut();
            let status =
                unsafe { AAArchiveStreamReadHeader(self.archive_stream.as_ptr(), &raw mut raw_header) };
            if status < 0 {
                return Err(Error::Status {
                    operation: "read header",
                    status: i64::from(status),
                });
            }
            if status == 0 {
                return Ok(None);
            }
            let header = Header::from_raw(raw_header)?;
            header.to_entry()
        }

        /// # Errors
        ///
        /// Returns an error if advancing the stream to skip the entry data fails.
        pub fn skip_entry_data(&mut self, entry: &Entry) -> Result<()> {
            self.process_entry_blobs(entry, None).map(|_| ())
        }

        /// # Errors
        ///
        /// Returns an error if reading the file data from the archive stream fails.
        pub fn read_entry_data<W: Write>(
            &mut self,
            entry: &Entry,
            output: &mut W,
            mut on_bytes: impl FnMut(u64) -> bool,
        ) -> Result<u64> {
            let data_bytes = self.process_entry_blobs(
                entry,
                Some(&mut |bytes| {
                    output.write_all(bytes)?;
                    let keep_going = on_bytes(bytes.len() as u64);
                    Ok(keep_going)
                }),
            )?;
            if let Some(expected_bytes) = entry.size().or(entry.data_size())
                && data_bytes != expected_bytes {
                    return Err(Error::SizeMismatch {
                        path: entry.path().to_owned(),
                        expected: expected_bytes,
                        actual: data_bytes,
                    });
                }
            Ok(data_bytes)
        }

        #[allow(clippy::type_complexity)]
        fn process_entry_blobs(
            &mut self,
            entry: &Entry,
            mut data_chunk: Option<&mut dyn FnMut(&[u8]) -> io::Result<bool>>,
        ) -> Result<u64> {
            let mut buffer = vec![0_u8; crate::DEFAULT_BUFFER_BYTES];
            let mut data_bytes = 0_u64;
            for blob in &entry.blobs {
                let mut remaining = blob.size;
                while remaining > 0 {
                    let chunk_len = usize::try_from(cmp::min(remaining, buffer.len() as u64)).unwrap_or(usize::MAX);
                    check_status(
                        unsafe {
                            AAArchiveStreamReadBlob(
                                self.archive_stream.as_ptr(),
                                blob.raw,
                                buffer.as_mut_ptr().cast(),
                                chunk_len,
                            )
                        },
                        "read blob",
                    )?;
                    if blob.key == BlobKey::Data {
                        if let Some(callback) = data_chunk.as_deref_mut()
                            && !callback(&buffer[..chunk_len])? {
                                return Err(Error::Cancelled);
                            }
                        data_bytes += chunk_len as u64;
                    }
                    remaining -= chunk_len as u64;
                }
            }
            Ok(data_bytes)
        }
    }

    #[allow(clippy::struct_field_names)]
    pub struct ArchiveWriter {
        archive_stream: Option<ArchiveStream>,
        compression_stream: Option<ByteStream>,
        file_stream: Option<ByteStream>,
    }

    impl ArchiveWriter {
        /// # Errors
        ///
        /// Returns an error if the underlying I/O streams cannot be created or initialized.
        pub fn create(path: impl AsRef<Path>, options: CreateOptions) -> Result<Self> {
            let file_stream = ByteStream::open_path(
                path.as_ref(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )?;
            let compression_stream = ByteStream::compression_output(
                file_stream.as_ptr(),
                options.compression.to_native(),
                options.block_size,
                options.threads,
                "open compression stream",
            )?;
            let archive_stream = ArchiveStream::encode_output(
                compression_stream.as_ptr(),
                options.threads,
                "open encode stream",
            )?;
            Ok(Self {
                archive_stream: Some(archive_stream),
                compression_stream: Some(compression_stream),
                file_stream: Some(file_stream),
            })
        }

        /// # Errors
        ///
        /// Returns an error if writing the header to the archive stream fails.
        pub fn append_directory(&mut self, path: &str, metadata: EntryMetadata) -> Result<()> {
            let mut header = Header::new()?;
            header.append_uint(field_key(b"TYP"), ENTRY_TYPE_DIR)?;
            header.append_string(field_key(b"PAT"), path)?;
            header.append_metadata(metadata)?;
            self.write_header(&header)
        }

        /// # Errors
        ///
        /// Returns an error if writing the header to the archive stream fails.
        pub fn append_symlink(
            &mut self,
            path: &str,
            target: &Path,
            metadata: EntryMetadata,
        ) -> Result<()> {
            let mut header = Header::new()?;
            header.append_uint(field_key(b"TYP"), ENTRY_TYPE_LNK)?;
            header.append_string(field_key(b"PAT"), path)?;
            header.append_string(field_key(b"LNK"), &target.to_string_lossy())?;
            header.append_metadata(metadata)?;
            self.write_header(&header)
        }

        /// # Errors
        ///
        /// Returns an error if writing the header or file data to the archive stream fails.
        pub fn append_file<R: Read>(
            &mut self,
            path: &str,
            size: u64,
            metadata: EntryMetadata,
            input: &mut R,
            mut on_bytes: impl FnMut(u64) -> bool,
        ) -> Result<u64> {
            let mut header = Header::new()?;
            header.append_uint(field_key(b"TYP"), ENTRY_TYPE_REG)?;
            header.append_string(field_key(b"PAT"), path)?;
            header.append_uint(field_key(b"SIZ"), size)?;
            header.append_metadata(metadata)?;
            header.append_blob(field_key(b"DAT"), size)?;
            self.write_header(&header)?;

            let mut buffer = vec![0_u8; crate::DEFAULT_BUFFER_BYTES];
            let mut written = 0_u64;
            while written < size {
                let remaining = size - written;
                let max_read = usize::try_from(cmp::min(remaining, buffer.len() as u64)).unwrap_or(usize::MAX);
                let read = input.read(&mut buffer[..max_read])?;
                if read == 0 {
                    return Err(Error::SizeMismatch {
                        path: path.to_owned(),
                        expected: size,
                        actual: written,
                    });
                }
                check_status(
                    unsafe {
                        AAArchiveStreamWriteBlob(
                            self.archive_stream()?.as_ptr(),
                            field_key(b"DAT"),
                            buffer[..read].as_ptr().cast(),
                            read,
                        )
                    },
                    "write data blob",
                )?;
                written += read as u64;
                if !on_bytes(read as u64) {
                    return Err(Error::Cancelled);
                }
            }

            Ok(written)
        }

        /// # Errors
        ///
        /// Returns an error if closing any of the underlying streams fails.
        pub fn finish(mut self) -> Result<()> {
            let mut first_error = None;
            close_archive_option(
                &mut self.archive_stream,
                "close archive stream",
                &mut first_error,
            );
            close_byte_option(
                &mut self.compression_stream,
                "close compression stream",
                &mut first_error,
            );
            close_byte_option(&mut self.file_stream, "close file stream", &mut first_error);

            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn write_header(&mut self, header: &Header) -> Result<()> {
            check_status(
                unsafe {
                    AAArchiveStreamWriteHeader(self.archive_stream()?.as_ptr(), header.as_ptr())
                },
                "write header",
            )
        }

        fn archive_stream(&self) -> Result<&ArchiveStream> {
            self.archive_stream.as_ref().ok_or(Error::Status {
                operation: "use finalized archive stream",
                status: -1,
            })
        }
    }

    impl CompressionAlgorithm {
        fn to_native(self) -> AACompressionAlgorithm {
            match self {
                Self::None => COMPRESSION_NONE,
                Self::Lz4 => COMPRESSION_LZ4,
                Self::Zlib => COMPRESSION_ZLIB,
                Self::Lzma => COMPRESSION_LZMA,
                Self::Lzfse => COMPRESSION_LZFSE,
                Self::Lzbitmap => COMPRESSION_LZBITMAP,
            }
        }
    }

    struct Header {
        ptr: NonNull<AAHeaderImpl>,
    }

    impl Header {
        fn new() -> Result<Self> {
            let ptr = unsafe { AAHeaderCreate() };
            let ptr = NonNull::new(ptr).ok_or(Error::NullObject("header"))?;
            Ok(Self { ptr })
        }

        fn from_raw(ptr: AAHeader) -> Result<Self> {
            let ptr = NonNull::new(ptr).ok_or(Error::NullObject("header"))?;
            Ok(Self { ptr })
        }

        fn as_ptr(&self) -> AAHeader {
            self.ptr.as_ptr()
        }

        fn to_entry(&self) -> Result<Option<Entry>> {
            let Some(path) = self.string_for_key(field_key(b"PAT"))? else {
                return Ok(Some(Entry {
                    path: String::new(),
                    kind: EntryKind::Metadata,
                    size: None,
                    data_size: None,
                    metadata: EntryMetadata::default(),
                    link_target: None,
                    blobs: self.blobs()?,
                }));
            };
            let entry_type = self
                .uint_for_key(field_key(b"TYP"))?
                .unwrap_or(ENTRY_TYPE_REG);
            let kind = entry_kind(entry_type);
            let blobs = self.blobs()?;
            let data_size = blobs
                .iter()
                .find_map(|blob| (blob.key == BlobKey::Data).then_some(blob.size));
            let size = self.uint_for_key(field_key(b"SIZ"))?.or(data_size);
            let metadata = EntryMetadata {
                mode: self
                    .uint_for_key(field_key(b"MOD"))?
                    .and_then(|mode| u32::try_from(mode).ok()),
                modified: self.timespec_for_key(field_key(b"MTM"))?,
            };
            let link_target = self.string_for_key(field_key(b"LNK"))?.map(PathBuf::from);

            Ok(Some(Entry {
                path,
                kind,
                size,
                data_size,
                metadata,
                link_target,
                blobs,
            }))
        }

        fn append_uint(&mut self, key: FieldKey, value: u64) -> Result<()> {
            check_status(
                unsafe { AAHeaderSetFieldUInt(self.as_ptr(), UINT32_APPEND, key, value) },
                "append uint field",
            )
        }

        fn append_string(&mut self, key: FieldKey, value: &str) -> Result<()> {
            let value = CString::new(value)?;
            let length = value.as_bytes().len();
            check_status(
                unsafe {
                    AAHeaderSetFieldString(
                        self.as_ptr(),
                        UINT32_APPEND,
                        key,
                        value.as_ptr(),
                        length,
                    )
                },
                "append string field",
            )
        }

        fn append_blob(&mut self, key: FieldKey, size: u64) -> Result<()> {
            check_status(
                unsafe { AAHeaderSetFieldBlob(self.as_ptr(), UINT32_APPEND, key, size) },
                "append blob field",
            )
        }

        fn append_metadata(&mut self, metadata: EntryMetadata) -> Result<()> {
            if let Some(mode) = metadata.mode {
                self.append_uint(field_key(b"MOD"), u64::from(mode & 0o7777))?;
            }
            if let Some(modified) = metadata.modified
                && let Some(value) = system_time_to_timespec(modified)
            {
                check_status(
                    unsafe {
                        AAHeaderSetFieldTimespec(
                            self.as_ptr(),
                            UINT32_APPEND,
                            field_key(b"MTM"),
                            &raw const value,
                        )
                    },
                    "append timespec field",
                )?;
            }
            Ok(())
        }

        fn uint_for_key(&self, key: FieldKey) -> Result<Option<u64>> {
            let Some(index) = self.index_for_key(key) else {
                return Ok(None);
            };
            if self.field_type(index)? != FIELD_TYPE_UINT {
                return Ok(None);
            }
            let mut value = 0_u64;
            check_status(
                unsafe { AAHeaderGetFieldUInt(self.as_ptr(), index, &raw mut value) },
                "get uint field",
            )?;
            Ok(Some(value))
        }

        fn string_for_key(&self, key: FieldKey) -> Result<Option<String>> {
            let Some(index) = self.index_for_key(key) else {
                return Ok(None);
            };
            if self.field_type(index)? != FIELD_TYPE_STRING {
                return Ok(None);
            }
            let mut length = 0_usize;
            check_status(
                unsafe {
                    AAHeaderGetFieldString(self.as_ptr(), index, 0, ptr::null_mut(), &raw mut length)
                },
                "measure string field",
            )?;
            let capacity = length.checked_add(1).ok_or(Error::SizeOutOfRange {
                field: "string length",
            })?;
            let mut buffer = vec![0_u8; capacity];
            check_status(
                unsafe {
                    AAHeaderGetFieldString(
                        self.as_ptr(),
                        index,
                        capacity,
                        buffer.as_mut_ptr().cast(),
                        &raw mut length,
                    )
                },
                "get string field",
            )?;
            buffer.truncate(length);
            Ok(Some(String::from_utf8_lossy(&buffer).into_owned()))
        }

        fn timespec_for_key(&self, key: FieldKey) -> Result<Option<SystemTime>> {
            let Some(index) = self.index_for_key(key) else {
                return Ok(None);
            };
            if self.field_type(index)? != FIELD_TYPE_TIMESPEC {
                return Ok(None);
            }
            let mut value = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            check_status(
                unsafe { AAHeaderGetFieldTimespec(self.as_ptr(), index, &raw mut value) },
                "get timespec field",
            )?;
            Ok(timespec_to_system_time(value))
        }

        fn blobs(&self) -> Result<Vec<EntryBlob>> {
            let mut blobs = Vec::new();
            let field_count = unsafe { AAHeaderGetFieldCount(self.as_ptr()) };
            for index in 0..field_count {
                if self.field_type(index)? != FIELD_TYPE_BLOB {
                    continue;
                }
                let key = unsafe { AAHeaderGetFieldKey(self.as_ptr(), index) };
                let mut size = 0_u64;
                let mut offset = 0_u64;
                check_status(
                    unsafe { AAHeaderGetFieldBlob(self.as_ptr(), index, &raw mut size, &raw mut offset) },
                    "get blob field",
                )?;
                blobs.push(EntryBlob {
                    raw: key,
                    key: blob_key(key),
                    size,
                });
            }
            Ok(blobs)
        }

        fn field_type(&self, index: u32) -> Result<c_int> {
            let status = unsafe { AAHeaderGetFieldType(self.as_ptr(), index) };
            if status < 0 {
                Err(Error::Status {
                    operation: "get field type",
                    status: i64::from(status),
                })
            } else {
                Ok(status)
            }
        }

        fn index_for_key(&self, key: FieldKey) -> Option<u32> {
            let index = unsafe { AAHeaderGetKeyIndex(self.as_ptr(), key) };
            u32::try_from(index).ok()
        }
    }

    impl Drop for Header {
        fn drop(&mut self) {
            unsafe { AAHeaderDestroy(self.as_ptr()) };
        }
    }

    struct ByteStream {
        ptr: Option<NonNull<AAByteStreamImpl>>,
    }

    impl ByteStream {
        fn open_path(path: &Path, flags: c_int, mode: mode_t) -> Result<Self> {
            let path = c_path(path)?;
            let ptr = unsafe { AAFileStreamOpenWithPath(path.as_ptr(), flags, mode) };
            Self::from_ptr(ptr, "file stream")
        }

        fn compression_output(
            stream: AAByteStream,
            algorithm: AACompressionAlgorithm,
            block_size: usize,
            threads: i32,
            object: &'static str,
        ) -> Result<Self> {
            let ptr =
                unsafe { AACompressionOutputStreamOpen(stream, algorithm, block_size, 0, threads) };
            Self::from_ptr(ptr, object)
        }

        fn decompression_input(stream: AAByteStream, object: &'static str) -> Result<Self> {
            let ptr = unsafe { AADecompressionInputStreamOpen(stream, 0, 0) };
            Self::from_ptr(ptr, object)
        }

        fn from_ptr(ptr: AAByteStream, object: &'static str) -> Result<Self> {
            let ptr = NonNull::new(ptr).ok_or(Error::NullObject(object))?;
            Ok(Self { ptr: Some(ptr) })
        }

        fn as_ptr(&self) -> AAByteStream {
            self.ptr.expect("byte stream is open").as_ptr()
        }

        fn close(&mut self, operation: &'static str) -> Result<()> {
            if let Some(ptr) = self.ptr.take() {
                check_status(unsafe { AAByteStreamClose(ptr.as_ptr()) }, operation)?;
            }
            Ok(())
        }
    }

    impl Drop for ByteStream {
        fn drop(&mut self) {
            let _ = self.close("close byte stream");
        }
    }

    struct ArchiveStream {
        ptr: Option<NonNull<AAArchiveStreamImpl>>,
    }

    impl ArchiveStream {
        fn encode_output(stream: AAByteStream, threads: i32, object: &'static str) -> Result<Self> {
            let ptr = unsafe {
                AAEncodeArchiveOutputStreamOpen(
                    stream,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    threads,
                )
            };
            Self::from_ptr(ptr, object)
        }

        fn decode_input(stream: AAByteStream, object: &'static str) -> Result<Self> {
            let ptr = unsafe {
                AADecodeArchiveInputStreamOpen(stream, ptr::null_mut(), ptr::null_mut(), 0, 0)
            };
            Self::from_ptr(ptr, object)
        }

        fn from_ptr(ptr: AAArchiveStream, object: &'static str) -> Result<Self> {
            let ptr = NonNull::new(ptr).ok_or(Error::NullObject(object))?;
            Ok(Self { ptr: Some(ptr) })
        }

        fn as_ptr(&self) -> AAArchiveStream {
            self.ptr.expect("archive stream is open").as_ptr()
        }

        fn close(&mut self, operation: &'static str) -> Result<()> {
            if let Some(ptr) = self.ptr.take() {
                check_status(unsafe { AAArchiveStreamClose(ptr.as_ptr()) }, operation)?;
            }
            Ok(())
        }
    }

    impl Drop for ArchiveStream {
        fn drop(&mut self) {
            let _ = self.close("close archive stream");
        }
    }

    fn close_archive_option(
        stream: &mut Option<ArchiveStream>,
        operation: &'static str,
        first_error: &mut Option<Error>,
    ) {
        if let Some(mut stream) = stream.take()
            && let Err(error) = stream.close(operation)
            && first_error.is_none()
        {
            *first_error = Some(error);
        }
    }

    fn close_byte_option(
        stream: &mut Option<ByteStream>,
        operation: &'static str,
        first_error: &mut Option<Error>,
    ) {
        if let Some(mut stream) = stream.take()
            && let Err(error) = stream.close(operation)
            && first_error.is_none()
        {
            *first_error = Some(error);
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn field_key(key: &[u8; 3]) -> FieldKey {
        FieldKey {
            skey: [key[0] as c_char, key[1] as c_char, key[2] as c_char, 0],
        }
    }

    #[allow(clippy::cast_sign_loss)]
    fn raw_key_bytes(key: FieldKey) -> [u8; 3] {
        let raw = unsafe { key.skey };
        [raw[0] as u8, raw[1] as u8, raw[2] as u8]
    }

    fn blob_key(key: FieldKey) -> BlobKey {
        if raw_key_bytes(key) == *b"DAT" {
            BlobKey::Data
        } else {
            BlobKey::Other
        }
    }

    fn entry_kind(value: u64) -> EntryKind {
        match value {
            ENTRY_TYPE_REG => EntryKind::File,
            ENTRY_TYPE_DIR => EntryKind::Directory,
            ENTRY_TYPE_LNK => EntryKind::Symlink,
            ENTRY_TYPE_CHR | ENTRY_TYPE_BLK => EntryKind::Device,
            ENTRY_TYPE_METADATA => EntryKind::Metadata,
            _ => EntryKind::Special,
        }
    }

    fn check_status(status: c_int, operation: &'static str) -> Result<()> {
        if status < 0 {
            Err(Error::Status {
                operation,
                status: i64::from(status),
            })
        } else {
            Ok(())
        }
    }

    fn c_path(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(Error::from)
    }

    fn timespec_to_system_time(value: timespec) -> Option<SystemTime> {
        let nanos = u32::try_from(value.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        if value.tv_sec >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(
                u64::try_from(value.tv_sec).unwrap_or(0),
                nanos,
            ))
        } else {
            UNIX_EPOCH.checked_sub(Duration::new(value.tv_sec.unsigned_abs(), nanos))
        }
    }

    fn system_time_to_timespec(value: SystemTime) -> Option<timespec> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Some(timespec {
                tv_sec: duration.as_secs().try_into().ok()?,
                tv_nsec: duration.subsec_nanos().into(),
            }),
            Err(error) => {
                let duration = error.duration();
                Some(timespec {
                    tv_sec: -i64::try_from(duration.as_secs()).ok()?,
                    tv_nsec: duration.subsec_nanos().into(),
                })
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
mod platform {
    use super::{CreateOptions, Entry, Error, Result};
    use std::io::{Read, Write};
    use std::path::Path;

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct FieldKey;

    pub struct ArchiveReader;

    impl ArchiveReader {
        pub fn open(_path: impl AsRef<Path>) -> Result<Self> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn next_entry(&mut self) -> Result<Option<Entry>> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn skip_entry_data(&mut self, _entry: &Entry) -> Result<()> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn read_entry_data<W: Write>(
            &mut self,
            _entry: &Entry,
            _output: &mut W,
            _on_bytes: impl FnMut(u64) -> bool,
        ) -> Result<u64> {
            Err(Error::UnsupportedPlatform)
        }
    }

    pub struct ArchiveWriter;

    impl ArchiveWriter {
        pub fn create(_path: impl AsRef<Path>, _options: CreateOptions) -> Result<Self> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn append_directory(
            &mut self,
            _path: &str,
            _metadata: super::EntryMetadata,
        ) -> Result<()> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn append_symlink(
            &mut self,
            _path: &str,
            _target: &Path,
            _metadata: super::EntryMetadata,
        ) -> Result<()> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn append_file<R: Read>(
            &mut self,
            _path: &str,
            _size: u64,
            _metadata: super::EntryMetadata,
            _input: &mut R,
            _on_bytes: impl FnMut(u64) -> bool,
        ) -> Result<u64> {
            Err(Error::UnsupportedPlatform)
        }

        pub fn finish(self) -> Result<()> {
            Err(Error::UnsupportedPlatform)
        }
    }
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
const DEFAULT_BUFFER_BYTES: usize = 128 * 1024;

pub use platform::{ArchiveReader, ArchiveWriter};
