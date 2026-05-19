//! Manual C ABI tracer facade for Swift integration.
//!
//! This crate intentionally exposes only a tiny C surface. The Rust core keeps
//! the real job model, while this layer owns C strings, opaque handles, and
//! polling-friendly JSON event batches.

use std::ffi::{CStr, CString, c_char};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use serde_json::{Value, json};
use zmanager_core::jobs::{CancellationToken, JobEvent, JobEventSink, JobKind};
use zmanager_core::manifest::{PlanOptions, plan_archive};
use zmanager_core::safety::{ExtractionPolicy, OverwritePolicy};
use zmanager_core::secrets::SecretString;
use zmanager_core::tar_zst_backend::TarZstdCreateOptions;
use zmanager_core::zip_backend::{ZipCompression, ZipCreateOptions};

/// C ABI status code returned by FFI entry points.
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ZManagerFfiStatus {
    /// Operation started or completed successfully.
    Ok = 0,
    /// A required pointer argument was null.
    NullArgument = 1,
    /// A C string argument was not valid UTF-8.
    InvalidUtf8 = 2,
    /// A non-pointer argument was outside the supported range.
    InvalidArgument = 3,
}

const DEFAULT_COMPRESSION_LEVEL_SENTINEL: i32 = -1;
const ZIP_STORE_COMPRESSION_LEVEL: i32 = 0;
const ZIP_MIN_DEFLATE_COMPRESSION_LEVEL: i32 = 1;
const ZIP_MAX_COMPRESSION_LEVEL: i32 = 9;
const TAR_ZST_MIN_COMPRESSION_LEVEL: i32 = 1;
const TAR_ZST_MAX_COMPRESSION_LEVEL: i32 = 9;

/// Opaque FFI job handle.
pub struct ZManagerFfiJob {
    receiver: Mutex<Receiver<Value>>,
    token: CancellationToken,
    finished: Arc<AtomicBool>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

/// Runs the core health check through the future FFI facade boundary.
#[must_use]
pub fn healthcheck_ready() -> bool {
    zmanager_core::healthcheck().ready
}

/// Returns whether the Rust core is available.
#[unsafe(no_mangle)]
pub extern "C" fn zmanager_ffi_healthcheck() -> bool {
    healthcheck_ready()
}

/// Starts a ZIP creation job.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `source` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create(
    source: *const c_char,
    destination: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointers and a null password to
    // the shared ZIP start implementation.
    unsafe {
        start_zip_create_job(
            source,
            destination,
            ptr::null(),
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts a ZIP creation job with AES-256 encryption.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `source`, `destination`, and `password` must point to valid NUL-terminated
/// UTF-8 C strings. `out_job` must point to writable storage for one job
/// pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create_encrypted(
    source: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_zip_create_job(
            source,
            destination,
            password,
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts a ZIP creation job with optional password and compression level.
///
/// Pass null for `password` to create a plain ZIP. Pass `-1` for
/// `compression_level` to use the default Deflate level, `0` to store files,
/// or `1..=9` for explicit Deflate levels. Pass true for `replace_existing`
/// only after the caller has confirmed replacement with the user.
///
/// # Safety
///
/// `source` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string. `out_job` must point to writable storage for
/// one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create_with_options(
    source: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_zip_create_job(
            source,
            destination,
            password,
            compression_level,
            replace_existing,
            out_job,
        )
    }
}

/// Starts a ZIP creation job from multiple source roots.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` must point to a valid NUL-terminated UTF-8 C string.
/// `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create_many(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer array and a null password
    // to the shared ZIP start implementation.
    unsafe {
        start_zip_create_many_job(
            sources,
            source_count,
            destination,
            ptr::null(),
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts an encrypted ZIP creation job from multiple source roots.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` and `password` must point to valid NUL-terminated UTF-8 C
/// strings. `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create_many_encrypted(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    password: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_zip_create_many_job(
            sources,
            source_count,
            destination,
            password,
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts a ZIP creation job from multiple source roots with optional password
/// and compression level.
///
/// Pass null for `password` to create a plain ZIP. Pass `-1` for
/// `compression_level` to use the default Deflate level, `0` to store files,
/// or `1..=9` for explicit Deflate levels. Pass true for `replace_existing`
/// only after the caller has confirmed replacement with the user.
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` must point to a valid NUL-terminated UTF-8 C string.
/// `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string. `out_job` must point to writable storage for
/// one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_zip_create_many_with_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_zip_create_many_job(
            sources,
            source_count,
            destination,
            password,
            compression_level,
            replace_existing,
            out_job,
        )
    }
}

unsafe fn start_zip_create_job(
    source: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if source.is_null() || destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let Some(source) = c_string_arg(source) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let password = if password.is_null() {
        None
    } else {
        let Some(password) = c_string_arg(password) else {
            return ZManagerFfiStatus::InvalidUtf8;
        };
        Some(SecretString::from(password))
    };

    let source = PathBuf::from(source);
    let destination = PathBuf::from(destination);
    let options = match zip_create_options(password, compression_level, replace_existing) {
        Ok(options) => options,
        Err(status) => return status,
    };

    spawn_archive_job(out_job, move |thread_token, sink| {
        let _ = zmanager_core::jobs::run_zip_create_job(
            source,
            destination,
            &options,
            &thread_token,
            sink,
        );
    })
}

unsafe fn start_zip_create_many_job(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let sources = match unsafe { c_string_array_arg(sources, source_count) } {
        Ok(sources) => sources,
        Err(status) => return status,
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let password = if password.is_null() {
        None
    } else {
        let Some(password) = c_string_arg(password) else {
            return ZManagerFfiStatus::InvalidUtf8;
        };
        Some(SecretString::from(password))
    };

    let sources = sources.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let destination = PathBuf::from(destination);
    let options = match zip_create_options(password, compression_level, replace_existing) {
        Ok(options) => options,
        Err(status) => return status,
    };

    spawn_archive_job(out_job, move |thread_token, sink| {
        let _ = zmanager_core::jobs::run_zip_create_job_from_sources(
            &sources,
            destination,
            &options,
            &thread_token,
            sink,
        );
    })
}

/// Starts a clean source `.tar.zst` creation job.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `source` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_clean_source_create(
    source: *const c_char,
    destination: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointers and default options to
    // the shared clean-source start implementation.
    unsafe {
        start_clean_source_create_job(
            source,
            destination,
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts a clean source `.tar.zst` creation job with a compression level.
///
/// Pass `-1` for `compression_level` to use the default zstd level, `1..=9`
/// for an explicit level, and true for `replace_existing` only after the
/// caller has confirmed replacement with the user.
///
/// # Safety
///
/// `source` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_clean_source_create_with_options(
    source: *const c_char,
    destination: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_clean_source_create_job(
            source,
            destination,
            compression_level,
            replace_existing,
            out_job,
        )
    }
}

unsafe fn start_clean_source_create_job(
    source: *const c_char,
    destination: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if source.is_null() || destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let Some(source) = c_string_arg(source) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };

    let source = PathBuf::from(source);
    let destination = PathBuf::from(destination);
    let options = match tar_zst_create_options(compression_level, replace_existing) {
        Ok(options) => options,
        Err(status) => return status,
    };

    spawn_archive_job(out_job, move |thread_token, sink| {
        let _ = zmanager_core::jobs::run_clean_source_tar_zst_create_job(
            source,
            destination,
            &options,
            &thread_token,
            sink,
        );
    })
}

/// Starts a clean source `.tar.zst` creation job from multiple source roots.
///
/// Events are polled as JSON batches with [`zmanager_ffi_poll_events`]. The
/// returned job must be released with [`zmanager_ffi_job_free`].
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` must point to a valid NUL-terminated UTF-8 C string.
/// `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_clean_source_create_many(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer array and default options
    // to the shared clean-source start implementation.
    unsafe {
        start_clean_source_create_many_job(
            sources,
            source_count,
            destination,
            DEFAULT_COMPRESSION_LEVEL_SENTINEL,
            false,
            out_job,
        )
    }
}

/// Starts a clean source `.tar.zst` creation job from multiple source roots
/// with a compression level.
///
/// Pass `-1` for `compression_level` to use the default zstd level, `1..=9`
/// for an explicit level, and true for `replace_existing` only after the
/// caller has confirmed replacement with the user.
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` must point to a valid NUL-terminated UTF-8 C string.
/// `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_clean_source_create_many_with_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_clean_source_create_many_job(
            sources,
            source_count,
            destination,
            compression_level,
            replace_existing,
            out_job,
        )
    }
}

unsafe fn start_clean_source_create_many_job(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let sources = match unsafe { c_string_array_arg(sources, source_count) } {
        Ok(sources) => sources,
        Err(status) => return status,
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };

    let sources = sources.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let destination = PathBuf::from(destination);
    let options = match tar_zst_create_options(compression_level, replace_existing) {
        Ok(options) => options,
        Err(status) => return status,
    };

    spawn_archive_job(out_job, move |thread_token, sink| {
        let _ = zmanager_core::jobs::run_clean_source_tar_zst_create_job_from_sources(
            &sources,
            destination,
            &options,
            &thread_token,
            sink,
        );
    })
}

/// Starts an archive extraction job routed by archive extension.
///
/// ZIP, TAR.ZST, 7z, and RAR use their native extraction backends. Other
/// formats use the libarchive fallback with coarse lifecycle events.
///
/// # Safety
///
/// `archive_path` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `out_job` must point to writable storage for one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_extract_archive(
    archive_path: *const c_char,
    destination: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointers and no password/options
    // to the shared extract start implementation.
    unsafe { start_extract_archive_job(archive_path, destination, ptr::null(), false, out_job) }
}

/// Starts an archive extraction job with optional password and overwrite
/// behavior routed by archive extension.
///
/// ZIP, TAR.ZST, 7z, and RAR use their native extraction backends. Other
/// formats use the libarchive fallback with coarse lifecycle events.
///
/// # Safety
///
/// `archive_path` and `destination` must point to valid NUL-terminated UTF-8 C
/// strings. `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string. `out_job` must point to writable storage for
/// one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_extract_archive_with_options(
    archive_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_extract_archive_job(
            archive_path,
            destination,
            password,
            replace_existing,
            out_job,
        )
    }
}

unsafe fn start_extract_archive_job(
    archive_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if archive_path.is_null() || destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let Some(archive_path) = c_string_arg(archive_path) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let password = if password.is_null() {
        None
    } else {
        let Some(password) = c_string_arg(password) else {
            return ZManagerFfiStatus::InvalidUtf8;
        };
        (!password.is_empty()).then_some(password)
    };

    let archive_path = PathBuf::from(archive_path);
    let destination = PathBuf::from(destination);

    spawn_archive_job(out_job, move |thread_token, sink| {
        let policy = extraction_policy(replace_existing);
        let password = password.as_deref();
        if is_zip_family_archive(&archive_path) {
            let _ = zmanager_core::jobs::run_zip_extract_job_with_password_and_policy(
                archive_path,
                destination,
                password,
                policy,
                &thread_token,
                sink,
            );
        } else if is_7z_archive(&archive_path) {
            let _ = zmanager_core::jobs::run_7z_extract_job_with_password_and_policy(
                archive_path,
                destination,
                password,
                policy,
                &thread_token,
                sink,
            );
        } else if is_rar_archive(&archive_path) {
            let _ = zmanager_core::jobs::run_rar_extract_job_with_password_and_policy(
                archive_path,
                destination,
                password,
                policy,
                &thread_token,
                sink,
            );
        } else if is_tar_zst_archive(&archive_path) {
            let _ = zmanager_core::jobs::run_tar_zst_extract_job_with_policy(
                archive_path,
                destination,
                policy,
                &thread_token,
                sink,
            );
        } else {
            let _ = zmanager_core::jobs::run_libarchive_extract_job_with_password_and_policy(
                archive_path,
                destination,
                password,
                policy,
                &thread_token,
                sink,
            );
        }
    })
}

/// Plans the clean source archive profile and returns a JSON summary.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `source` must point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_plan_clean_source(source: *const c_char) -> *mut c_char {
    if source.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null source\"}");
    }

    let Some(source) = c_string_arg(source) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 source\"}");
    };

    let json = match plan_archive(PathBuf::from(source), &PlanOptions::clean_source()) {
        Ok(manifest) => json!({
            "ok": true,
            "included_entries": manifest.included_count(),
            "included_bytes": manifest.total_bytes,
            "excluded_entries": manifest.excluded_count(),
            "excluded_bytes": manifest.excluded_bytes,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Lists archive entries for the browser UI and returns a JSON object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_list_archive(archive_path: *const c_char) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }

    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };

    let json = match zmanager_core::archive_browser::list_entries(PathBuf::from(archive_path)) {
        Ok(listing) => archive_listing_to_json(&listing),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Extracts one archive entry to a destination directory and returns a JSON
/// object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path`, `entry_path`, and `destination` must point to valid
/// NUL-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_extract_archive_entry(
    archive_path: *const c_char,
    entry_path: *const c_char,
    destination: *const c_char,
) -> *mut c_char {
    // SAFETY: this forwards the same checked pointers and no password/options
    // to the shared entry extraction implementation.
    unsafe { extract_archive_entry(archive_path, entry_path, destination, ptr::null(), false) }
}

/// Extracts one archive entry to a destination directory with optional password
/// and overwrite behavior and returns a JSON object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path`, `entry_path`, and `destination` must point to valid
/// NUL-terminated UTF-8 C strings. `password` may be null; if non-null it must
/// point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_extract_archive_entry_with_options(
    archive_path: *const c_char,
    entry_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    replace_existing: bool,
) -> *mut c_char {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        extract_archive_entry(
            archive_path,
            entry_path,
            destination,
            password,
            replace_existing,
        )
    }
}

unsafe fn extract_archive_entry(
    archive_path: *const c_char,
    entry_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    replace_existing: bool,
) -> *mut c_char {
    if archive_path.is_null() || entry_path.is_null() || destination.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null argument\"}");
    }

    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let Some(entry_path) = c_string_arg(entry_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 entry path\"}");
    };
    let Some(destination) = c_string_arg(destination) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 destination\"}");
    };
    let password = if password.is_null() {
        None
    } else {
        let Some(password) = c_string_arg(password) else {
            return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 password\"}");
        };
        (!password.is_empty()).then_some(password)
    };

    let json = match zmanager_core::archive_browser::extract_entry_with_options(
        PathBuf::from(archive_path),
        &entry_path,
        PathBuf::from(destination),
        zmanager_core::archive_browser::BrowserExtractOptions {
            password: password.as_deref(),
            replace_existing,
        },
    ) {
        Ok(report) => json!({
            "ok": true,
            "destination_path": report.destination_path.to_string_lossy(),
            "written_bytes": report.written_bytes,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Extracts one archive entry to a controlled temporary preview directory and
/// returns a JSON object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` and `entry_path` must point to valid NUL-terminated UTF-8 C
/// strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_preview_archive_entry(
    archive_path: *const c_char,
    entry_path: *const c_char,
) -> *mut c_char {
    if archive_path.is_null() || entry_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null argument\"}");
    }

    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let Some(entry_path) = c_string_arg(entry_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 entry path\"}");
    };

    let json = match zmanager_core::archive_browser::preview_entry(
        PathBuf::from(archive_path),
        &entry_path,
    ) {
        Ok(report) => json!({
            "ok": true,
            "cleanup_root": report.cleanup_root.to_string_lossy(),
            "preview_path": report.preview_path.to_string_lossy(),
            "written_bytes": report.written_bytes,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Polls all currently buffered job events as a JSON array string.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn zmanager_ffi_poll_events(job: *mut ZManagerFfiJob) -> *mut c_char {
    let Some(job) = job_ref(job) else {
        return owned_c_string("[]");
    };

    let Ok(receiver) = job.receiver.lock() else {
        return owned_c_string("[]");
    };
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }

    let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_owned());
    owned_c_string(&json)
}

/// Requests cooperative cancellation for a running job.
#[unsafe(no_mangle)]
pub extern "C" fn zmanager_ffi_job_cancel(job: *mut ZManagerFfiJob) {
    if let Some(job) = job_ref(job) {
        job.token.cancel();
    }
}

/// Returns whether the background job thread has finished.
#[unsafe(no_mangle)]
pub extern "C" fn zmanager_ffi_job_is_finished(job: *const ZManagerFfiJob) -> bool {
    let Some(job) = const_job_ref(job) else {
        return true;
    };

    job.finished.load(Ordering::SeqCst)
}

/// Releases a job handle.
///
/// # Safety
///
/// `job` must be null or a pointer returned by
/// [`zmanager_ffi_start_zip_create`] or
/// [`zmanager_ffi_start_clean_source_create`]. Each non-null job pointer must
/// be freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_job_free(job: *mut ZManagerFfiJob) {
    if job.is_null() {
        return;
    }

    // SAFETY: `job` was allocated by `Box::into_raw` in this crate and this
    // function takes ownership exactly once by API contract.
    let job = unsafe { Box::from_raw(job) };
    job.token.cancel();
    if let Ok(mut join_handle) = job.join_handle.lock()
        && let Some(join_handle) = join_handle.take()
    {
        if job.finished.load(Ordering::SeqCst) {
            let _ = join_handle.join();
        } else {
            let _ = thread::Builder::new()
                .name("zmanager-ffi-job-reaper".to_owned())
                .spawn(move || {
                    let _ = join_handle.join();
                });
        }
    }
}

/// Releases a string returned by this FFI layer.
///
/// # Safety
///
/// `value` must be null or a pointer returned by this crate from
/// `CString::into_raw`. Each non-null string pointer must be freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    // SAFETY: `value` must be a pointer returned by `CString::into_raw` from
    // this crate. Reconstructing it drops and frees the allocation.
    unsafe {
        drop(CString::from_raw(value));
    }
}

fn c_string_arg(value: *const c_char) -> Option<String> {
    // SAFETY: callers pass a non-null, NUL-terminated C string. The caller is
    // responsible for keeping it alive for this call; we copy it immediately.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(ToOwned::to_owned)
}

unsafe fn c_string_array_arg(
    values: *const *const c_char,
    value_count: usize,
) -> Result<Vec<String>, ZManagerFfiStatus> {
    if values.is_null() || value_count == 0 {
        return Err(ZManagerFfiStatus::NullArgument);
    }

    // SAFETY: callers pass a non-null pointer to `value_count` C string
    // pointers. Each string is copied before this function returns.
    let values = unsafe { slice::from_raw_parts(values, value_count) };
    let mut strings = Vec::with_capacity(value_count);
    for value in values {
        if (*value).is_null() {
            return Err(ZManagerFfiStatus::NullArgument);
        }
        let Some(string) = c_string_arg(*value) else {
            return Err(ZManagerFfiStatus::InvalidUtf8);
        };
        strings.push(string);
    }

    Ok(strings)
}

fn zip_create_options(
    password: Option<SecretString>,
    compression_level: i32,
    replace_existing: bool,
) -> Result<ZipCreateOptions, ZManagerFfiStatus> {
    let (compression, level) = match compression_level {
        DEFAULT_COMPRESSION_LEVEL_SENTINEL => (ZipCompression::Deflate, None),
        ZIP_STORE_COMPRESSION_LEVEL => (ZipCompression::Store, None),
        level
            if (ZIP_MIN_DEFLATE_COMPRESSION_LEVEL..=ZIP_MAX_COMPRESSION_LEVEL).contains(&level) =>
        {
            (ZipCompression::Deflate, Some(i64::from(level)))
        }
        _ => return Err(ZManagerFfiStatus::InvalidArgument),
    };

    Ok(ZipCreateOptions {
        compression,
        level,
        preserve_metadata: true,
        replace_existing,
        password,
    })
}

fn tar_zst_create_options(
    compression_level: i32,
    replace_existing: bool,
) -> Result<TarZstdCreateOptions, ZManagerFfiStatus> {
    let mut options = TarZstdCreateOptions::default();
    options.replace_existing = replace_existing;
    if compression_level == DEFAULT_COMPRESSION_LEVEL_SENTINEL {
        return Ok(options);
    }

    if !(TAR_ZST_MIN_COMPRESSION_LEVEL..=TAR_ZST_MAX_COMPRESSION_LEVEL).contains(&compression_level)
    {
        return Err(ZManagerFfiStatus::InvalidArgument);
    }

    options.level = compression_level;
    Ok(options)
}

fn spawn_archive_job<F>(out_job: *mut *mut ZManagerFfiJob, runner: F) -> ZManagerFfiStatus
where
    F: FnOnce(CancellationToken, &mut dyn JobEventSink) + Send + 'static,
{
    let (sender, receiver) = mpsc::channel::<Value>();
    let token = CancellationToken::new();
    let thread_token = token.clone();
    let finished = Arc::new(AtomicBool::new(false));
    let thread_finished = Arc::clone(&finished);

    let join_handle = thread::spawn(move || {
        let mut sink = |event: JobEvent| {
            let _ = sender.send(event_to_json_value(&event));
        };
        runner(thread_token, &mut sink);
        thread_finished.store(true, Ordering::SeqCst);
    });

    let job = Box::new(ZManagerFfiJob {
        receiver: Mutex::new(receiver),
        token,
        finished,
        join_handle: Mutex::new(Some(join_handle)),
    });

    // SAFETY: public callers checked `out_job` for null before reaching this
    // helper. It points to caller-owned storage for one opaque handle pointer.
    unsafe {
        *out_job = Box::into_raw(job);
    }

    ZManagerFfiStatus::Ok
}

fn job_ref(job: *mut ZManagerFfiJob) -> Option<&'static ZManagerFfiJob> {
    if job.is_null() {
        return None;
    }

    // SAFETY: opaque job pointers are created by this crate and remain valid
    // until `zmanager_ffi_job_free`. We only borrow here.
    Some(unsafe { &*job })
}

fn const_job_ref(job: *const ZManagerFfiJob) -> Option<&'static ZManagerFfiJob> {
    if job.is_null() {
        return None;
    }

    // SAFETY: opaque job pointers are created by this crate and remain valid
    // until `zmanager_ffi_job_free`. We only borrow here.
    Some(unsafe { &*job })
}

fn owned_c_string(value: &str) -> *mut c_char {
    let value = value.replace('\0', "\\u0000");
    CString::new(value).map_or(ptr::null_mut(), CString::into_raw)
}

fn event_to_json_value(event: &JobEvent) -> Value {
    match event {
        JobEvent::Started { kind, total_bytes } => json!({
            "type": "started",
            "kind": job_kind_name(*kind),
            "total_bytes": total_bytes,
        }),
        JobEvent::EntryStarted { path, bytes } => json!({
            "type": "entry_started",
            "path": path,
            "bytes": bytes,
        }),
        JobEvent::BytesProcessed {
            path,
            bytes,
            total_bytes_processed,
        } => json!({
            "type": "bytes_processed",
            "path": path,
            "bytes": bytes,
            "total_bytes_processed": total_bytes_processed,
        }),
        JobEvent::EntryFinished { path, bytes } => json!({
            "type": "entry_finished",
            "path": path,
            "bytes": bytes,
        }),
        JobEvent::Warning { message } => json!({
            "type": "warning",
            "message": message,
        }),
        JobEvent::Completed { entries, bytes } => json!({
            "type": "completed",
            "entries": entries,
            "bytes": bytes,
        }),
        JobEvent::Failed { message } => json!({
            "type": "failed",
            "message": message,
        }),
        JobEvent::Cancelled { message } => json!({
            "type": "cancelled",
            "message": message,
        }),
    }
}

fn archive_listing_to_json(listing: &zmanager_core::archive_browser::BrowserListing) -> String {
    let entries = listing
        .entries
        .iter()
        .map(|entry| {
            json!({
                "path": entry.path,
                "kind": browser_entry_kind_name(entry.kind),
                "size": entry.size,
                "compressed_size": entry.compressed_size,
                "modified": entry.modified,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "ok": true,
        "entries": entries,
    })
    .to_string()
}

fn browser_entry_kind_name(kind: zmanager_core::archive_browser::BrowserEntryKind) -> &'static str {
    match kind {
        zmanager_core::archive_browser::BrowserEntryKind::File => "file",
        zmanager_core::archive_browser::BrowserEntryKind::Directory => "directory",
        zmanager_core::archive_browser::BrowserEntryKind::Symlink => "symlink",
        zmanager_core::archive_browser::BrowserEntryKind::Hardlink => "hardlink",
        zmanager_core::archive_browser::BrowserEntryKind::Special => "special",
    }
}

fn ffi_error_json(message: &str) -> String {
    json!({
        "ok": false,
        "message": message,
    })
    .to_string()
}

fn extraction_policy(replace_existing: bool) -> ExtractionPolicy {
    ExtractionPolicy {
        overwrite: if replace_existing {
            OverwritePolicy::Replace
        } else {
            OverwritePolicy::Refuse
        },
        ..ExtractionPolicy::default()
    }
}

fn job_kind_name(kind: JobKind) -> &'static str {
    match kind {
        JobKind::ZipCreate => "zip_create",
        JobKind::ZipExtract => "zip_extract",
        JobKind::SevenZCreate => "7z_create",
        JobKind::SevenZExtract => "7z_extract",
        JobKind::RarExtract => "rar_extract",
        JobKind::TarZstdCreate => "tar_zst_create",
        JobKind::TarZstdExtract => "tar_zst_extract",
        JobKind::ArchiveExtract => "archive_extract",
    }
}

fn is_zip_family_archive(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "zip" | "zipx" | "jar" | "war" | "ipa" | "apk" | "appx" | "xpi"
            )
        })
}

fn is_tar_zst_archive(path: &std::path::Path) -> bool {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tzst"))
    {
        return true;
    }

    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zst"))
        && path
            .file_stem()
            .and_then(|stem| std::path::Path::new(stem).extension())
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tar"))
}

fn is_7z_archive(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

fn is_rar_archive(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension.to_ascii_lowercase().as_str(), "rar" | "cbr"))
}

#[cfg(test)]
mod tests {
    use super::{
        ZManagerFfiJob, ZManagerFfiStatus, zmanager_ffi_extract_archive_entry,
        zmanager_ffi_extract_archive_entry_with_options, zmanager_ffi_job_free,
        zmanager_ffi_job_is_finished, zmanager_ffi_list_archive, zmanager_ffi_plan_clean_source,
        zmanager_ffi_poll_events, zmanager_ffi_preview_archive_entry,
        zmanager_ffi_start_clean_source_create, zmanager_ffi_start_clean_source_create_many,
        zmanager_ffi_start_clean_source_create_many_with_options,
        zmanager_ffi_start_extract_archive, zmanager_ffi_start_extract_archive_with_options,
        zmanager_ffi_start_zip_create, zmanager_ffi_start_zip_create_encrypted,
        zmanager_ffi_start_zip_create_many, zmanager_ffi_start_zip_create_many_with_options,
        zmanager_ffi_string_free,
    };
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::ptr;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn c_abi_zip_create_job_can_be_started_and_polled() {
        let temp = std::env::temp_dir().join(format!(
            "zmanager-ffi-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"hello").unwrap();
        let source = CString::new(temp.join("payload").to_string_lossy().as_ref()).unwrap();
        let destination =
            CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create(source.as_ptr(), destination.as_ptr(), &raw mut job)
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let mut events = String::new();
        for _ in 0..200 {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        events.push_str(&poll_events(job));

        // SAFETY: `job` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_job_free(job);
        }
        fs::remove_dir_all(temp).unwrap();

        assert!(events.contains("\"type\":\"started\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert!(events.contains("payload/file.txt"));
    }

    #[test]
    fn c_abi_zip_create_many_keeps_all_dropped_roots() {
        let temp = test_root("zmanager-ffi-many");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"a").unwrap();
        fs::create_dir_all(temp.join("folder")).unwrap();
        fs::write(temp.join("folder/b.txt"), b"bb").unwrap();
        let source_a = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let source_b = CString::new(temp.join("folder").to_string_lossy().as_ref()).unwrap();
        let sources = [source_a.as_ptr(), source_b.as_ptr()];
        let destination =
            CString::new(temp.join("selection.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create_many(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let events = drain_job(job);

        let listing = zmanager_core::zip_backend::list_zip(temp.join("selection.zip")).unwrap();
        let names = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["a.txt", "folder/", "folder/b.txt"]);
        assert!(events.contains("\"type\":\"completed\""));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_zip_create_many_options_apply_store_level() {
        let temp = test_root("zmanager-ffi-many-options");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), vec![b'a'; 4096]).unwrap();
        let source = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("selection.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                ptr::null(),
                0,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));

        let listing = zmanager_core::zip_backend::list_zip(temp.join("selection.zip")).unwrap();
        let entry = listing
            .entries
            .iter()
            .find(|entry| entry.name == "a.txt")
            .unwrap();
        assert_eq!(entry.compressed_size, entry.size);
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_zip_create_many_options_reject_invalid_level() {
        let temp = test_root("zmanager-ffi-many-invalid-options");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"a").unwrap();
        let source = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("selection.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                ptr::null(),
                10,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::InvalidArgument);
        assert!(job.is_null());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_zip_create_many_options_replace_existing_file() {
        let temp = test_root("zmanager-ffi-many-replace-options");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"new").unwrap();
        fs::write(temp.join("selection.zip"), b"old").unwrap();
        let source = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("selection.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                ptr::null(),
                6,
                true,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));

        let listing = zmanager_core::zip_backend::list_zip(temp.join("selection.zip")).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "a.txt"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_clean_source_plan_and_create_use_tar_zst_profile() {
        let temp = std::env::temp_dir().join(format!(
            "zmanager-ffi-clean-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(temp.join("payload/src")).unwrap();
        fs::create_dir_all(temp.join("payload/node_modules/pkg")).unwrap();
        fs::write(temp.join("payload/src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(temp.join("payload/node_modules/pkg/index.js"), b"drop").unwrap();
        let source = CString::new(temp.join("payload").to_string_lossy().as_ref()).unwrap();

        // SAFETY: `source` is a valid C string for the duration of the call.
        let raw_plan = unsafe { zmanager_ffi_plan_clean_source(source.as_ptr()) };
        let plan = c_string(raw_plan);
        assert!(plan.contains("\"ok\":true"));
        assert!(plan.contains("\"excluded_entries\":1"));
        assert!(plan.contains("\"excluded_bytes\":4"));

        let destination = CString::new(
            temp.join("payload.clean.tar.zst")
                .to_string_lossy()
                .as_ref(),
        )
        .unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_clean_source_create(
                source.as_ptr(),
                destination.as_ptr(),
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let mut events = String::new();
        for _ in 0..200 {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        events.push_str(&poll_events(job));

        // SAFETY: `job` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_job_free(job);
        }
        fs::remove_dir_all(temp).unwrap();

        assert!(events.contains("\"kind\":\"tar_zst_create\""));
        assert!(events.contains("payload/src/main.rs"));
        assert!(!events.contains("node_modules"));
    }

    #[test]
    fn c_abi_clean_source_create_many_keeps_all_dropped_roots() {
        let temp = test_root("zmanager-ffi-clean-many");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"a").unwrap();
        fs::create_dir_all(temp.join("folder/node_modules/pkg")).unwrap();
        fs::write(temp.join("folder/b.txt"), b"bb").unwrap();
        fs::write(temp.join("folder/node_modules/pkg/index.js"), b"drop").unwrap();
        let source_a = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let source_b = CString::new(temp.join("folder").to_string_lossy().as_ref()).unwrap();
        let sources = [source_a.as_ptr(), source_b.as_ptr()];
        let destination = CString::new(
            temp.join("selection.clean.tar.zst")
                .to_string_lossy()
                .as_ref(),
        )
        .unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_clean_source_create_many(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let events = drain_job(job);

        let listing =
            zmanager_core::archive_browser::list_entries(temp.join("selection.clean.tar.zst"))
                .unwrap();
        let paths = listing
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["a.txt", "folder", "folder/b.txt"]);
        assert!(events.contains("\"type\":\"completed\""));
        assert!(!events.contains("node_modules"));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_clean_source_create_many_options_accept_level() {
        let temp = test_root("zmanager-ffi-clean-many-options");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"a").unwrap();
        let source = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("selection.clean.tzst").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_clean_source_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                1,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));

        let listing =
            zmanager_core::archive_browser::list_entries(temp.join("selection.clean.tzst"))
                .unwrap();
        assert_eq!(listing.entries[0].path, "a.txt");
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_clean_source_create_many_options_replace_existing_file() {
        let temp = test_root("zmanager-ffi-clean-many-replace-options");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("a.txt"), b"new").unwrap();
        fs::write(temp.join("selection.clean.tzst"), b"old").unwrap();
        let source = CString::new(temp.join("a.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("selection.clean.tzst").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_clean_source_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                1,
                true,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));

        let listing =
            zmanager_core::archive_browser::list_entries(temp.join("selection.clean.tzst"))
                .unwrap();
        assert_eq!(listing.entries[0].path, "a.txt");
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_encrypted_zip_create_uses_password() {
        let temp = std::env::temp_dir().join(format!(
            "zmanager-ffi-encrypted-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret").unwrap();
        let source = CString::new(temp.join("payload").to_string_lossy().as_ref()).unwrap();
        let destination =
            CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("correct horse").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_zip_create_encrypted(
                source.as_ptr(),
                destination.as_ptr(),
                password.as_ptr(),
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let mut events = String::new();
        for _ in 0..200 {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        events.push_str(&poll_events(job));

        // SAFETY: `job` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_job_free(job);
        }

        assert!(events.contains("\"type\":\"completed\""));
        assert!(matches!(
            zmanager_core::zip_backend::test_zip(temp.join("archive.zip")),
            Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired)
        ));
        zmanager_core::zip_backend::test_zip_with_password(
            temp.join("archive.zip"),
            Some("correct horse"),
        )
        .unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_archive_browser_lists_extracts_and_previews_zip_entry() {
        let temp = test_root("zmanager-ffi-browser");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"preview me").unwrap();
        zmanager_core::zip_backend::create_zip_from_path(
            temp.join("payload"),
            temp.join("archive.zip"),
            &zmanager_core::zip_backend::ZipCreateOptions::default(),
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let entry = CString::new("payload/file.txt").unwrap();
        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();

        // SAFETY: `archive` is a valid C string for the duration of the call.
        let listing = c_string(unsafe { zmanager_ffi_list_archive(archive.as_ptr()) });
        assert!(listing.contains("\"ok\":true"));
        assert!(listing.contains("\"path\":\"payload/file.txt\""));

        // SAFETY: all C strings are valid for the duration of the call.
        let extract = c_string(unsafe {
            zmanager_ffi_extract_archive_entry(
                archive.as_ptr(),
                entry.as_ptr(),
                destination.as_ptr(),
            )
        });
        assert!(extract.contains("\"ok\":true"));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload/file.txt")).unwrap(),
            "preview me"
        );

        // SAFETY: all C strings are valid for the duration of the call.
        let preview = c_string(unsafe {
            zmanager_ffi_preview_archive_entry(archive.as_ptr(), entry.as_ptr())
        });
        assert!(preview.contains("\"ok\":true"));
        let cleanup_root = json_string_field(&preview, "cleanup_root").unwrap();
        let preview_path = json_string_field(&preview, "preview_path").unwrap();
        assert_eq!(fs::read_to_string(&preview_path).unwrap(), "preview me");
        fs::remove_dir_all(cleanup_root).unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_extract_archive_job_routes_zip() {
        let temp = test_root("zmanager-ffi-extract");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"extract me").unwrap();
        zmanager_core::zip_backend::create_zip_from_path(
            temp.join("payload"),
            temp.join("archive.zip"),
            &zmanager_core::zip_backend::ZipCreateOptions::default(),
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive(archive.as_ptr(), destination.as_ptr(), &raw mut job)
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let mut events = String::new();
        for _ in 0..200 {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        events.push_str(&poll_events(job));

        // SAFETY: `job` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_job_free(job);
        }

        assert!(events.contains("\"kind\":\"zip_extract\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload/file.txt")).unwrap(),
            "extract me"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_extract_archive_options_use_password_and_replace_existing() {
        let temp = test_root("zmanager-ffi-extract-options");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret").unwrap();
        zmanager_core::zip_backend::create_zip_from_path(
            temp.join("payload"),
            temp.join("archive.zip"),
            &zmanager_core::zip_backend::ZipCreateOptions {
                password: Some(zmanager_core::secrets::SecretString::from("correct horse")),
                ..zmanager_core::zip_backend::ZipCreateOptions::default()
            },
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let missing_password_destination =
            CString::new(temp.join("missing-password").to_string_lossy().as_ref()).unwrap();
        let mut missing_password_job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `missing_password_job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive(
                archive.as_ptr(),
                missing_password_destination.as_ptr(),
                &raw mut missing_password_job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!missing_password_job.is_null());
        let missing_password_events = drain_job(missing_password_job);
        assert!(missing_password_events.contains("password required"));

        let destination = temp.join("out");
        fs::create_dir_all(destination.join("payload")).unwrap();
        fs::write(destination.join("payload/file.txt"), b"old").unwrap();
        let destination = CString::new(destination.to_string_lossy().as_ref()).unwrap();
        let password = CString::new("correct horse").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: all C strings live for the duration of the call and `job` is
        // valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive_with_options(
                archive.as_ptr(),
                destination.as_ptr(),
                password.as_ptr(),
                true,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload/file.txt")).unwrap(),
            "secret"
        );

        let selected_destination = temp.join("selected");
        fs::create_dir_all(selected_destination.join("payload")).unwrap();
        fs::write(selected_destination.join("payload/file.txt"), b"old").unwrap();
        let selected_destination =
            CString::new(selected_destination.to_string_lossy().as_ref()).unwrap();
        let entry = CString::new("payload/file.txt").unwrap();

        // SAFETY: all C strings are valid for the duration of the call.
        let selected = c_string(unsafe {
            zmanager_ffi_extract_archive_entry_with_options(
                archive.as_ptr(),
                entry.as_ptr(),
                selected_destination.as_ptr(),
                password.as_ptr(),
                true,
            )
        });
        assert!(selected.contains("\"ok\":true"));
        assert_eq!(
            fs::read_to_string(temp.join("selected/payload/file.txt")).unwrap(),
            "secret"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_extract_archive_options_route_7z_passwords_to_native_backend() {
        let temp = test_root("zmanager-ffi-extract-7z-options");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret 7z").unwrap();
        zmanager_core::sevenz_backend::create_7z_from_path(
            temp.join("payload"),
            temp.join("archive.7z"),
            &zmanager_core::sevenz_backend::SevenZCreateOptions {
                password: Some(zmanager_core::secrets::SecretString::from("correct horse")),
                ..zmanager_core::sevenz_backend::SevenZCreateOptions::default()
            },
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.7z").to_string_lossy().as_ref()).unwrap();
        let missing_password_destination =
            CString::new(temp.join("missing-password").to_string_lossy().as_ref()).unwrap();
        let mut missing_password_job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `missing_password_job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive(
                archive.as_ptr(),
                missing_password_destination.as_ptr(),
                &raw mut missing_password_job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!missing_password_job.is_null());
        let missing_password_events = drain_job(missing_password_job);
        assert!(missing_password_events.contains("\"kind\":\"7z_extract\""));
        assert!(missing_password_events.contains("password required"));

        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("correct horse").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: all C strings live for the duration of the call and `job` is
        // valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive_with_options(
                archive.as_ptr(),
                destination.as_ptr(),
                password.as_ptr(),
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"7z_extract\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload/file.txt")).unwrap(),
            "secret 7z"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_extract_archive_options_route_rar_passwords_to_native_backend_when_available() {
        let Some(rar) = find_on_path("rar") else {
            return;
        };
        let temp = test_root("zmanager-ffi-extract-rar-options");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret rar").unwrap();
        let archive_path = temp.join("archive.rar");
        let create = Command::new(rar)
            .current_dir(&temp)
            .arg("a")
            .arg("-idq")
            .arg("-ma5")
            .arg("-psecret")
            .arg(&archive_path)
            .arg("payload")
            .output()
            .unwrap();
        assert!(
            create.status.success(),
            "rar create failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        );

        let archive = CString::new(archive_path.to_string_lossy().as_ref()).unwrap();
        let missing_password_destination =
            CString::new(temp.join("missing-password").to_string_lossy().as_ref()).unwrap();
        let mut missing_password_job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and
        // `missing_password_job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive(
                archive.as_ptr(),
                missing_password_destination.as_ptr(),
                &raw mut missing_password_job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!missing_password_job.is_null());
        let missing_password_events = drain_job(missing_password_job);
        assert!(missing_password_events.contains("\"kind\":\"rar_extract\""));
        assert!(missing_password_events.to_lowercase().contains("password"));

        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("secret").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: all C strings live for the duration of the call and `job` is
        // valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive_with_options(
                archive.as_ptr(),
                destination.as_ptr(),
                password.as_ptr(),
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"rar_extract\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload/file.txt")).unwrap(),
            "secret rar"
        );
        fs::remove_dir_all(temp).unwrap();
    }

    fn drain_job(job: *mut ZManagerFfiJob) -> String {
        let mut events = String::new();
        for _ in 0..200 {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        events.push_str(&poll_events(job));

        // SAFETY: `job` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_job_free(job);
        }

        events
    }

    fn poll_events(job: *mut ZManagerFfiJob) -> String {
        let raw = zmanager_ffi_poll_events(job);
        assert!(!raw.is_null());
        c_string(raw)
    }

    fn c_string(raw: *mut std::ffi::c_char) -> String {
        // SAFETY: `raw` is returned by this crate as a valid NUL-terminated C
        // string and remains valid until freed below.
        let value = unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `raw` was returned by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_string_free(raw);
        }
        value
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn json_string_field(json: &str, field: &str) -> Option<PathBuf> {
        let marker = format!("\"{field}\":\"");
        let start = json.find(&marker)? + marker.len();
        let mut output = String::new();
        let mut escaped = false;

        for character in json[start..].chars() {
            if escaped {
                output.push(match character {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return Some(Path::new(&output).to_path_buf());
            } else {
                output.push(character);
            }
        }

        None
    }

    fn find_on_path(command: &str) -> Option<PathBuf> {
        std::env::var_os("PATH")?
            .to_string_lossy()
            .split(':')
            .map(|directory| Path::new(directory).join(command))
            .find(|candidate| candidate.is_file())
    }
}
