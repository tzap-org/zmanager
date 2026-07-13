//! Manual C ABI tracer facade for Swift integration.
//!
//! This crate intentionally exposes only a tiny C surface. The Rust core keeps
//! the real job model, while this layer owns C strings, opaque handles, and
//! polling-friendly JSON event batches.

use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509NameBuilder};
use serde_json::{Value, json};
use zmanager_core::jobs::{CancellationToken, JobEvent, JobEventSink, JobKind, JobPhase};
use zmanager_core::local_identity_store::{
    FileTzapLocalIdentityStore, TzapContactRecord, TzapEnrolledCertificateRecord,
    TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
    TzapRecipientEncryptionKeyRecord,
};
use zmanager_core::manifest::{PlanOptions, plan_archive, plan_archives};
use zmanager_core::safety::{ExtractionPolicy, OverwritePolicy};
use zmanager_core::secrets::SecretString;
use zmanager_core::sevenz_backend::SevenZCreateOptions;
use zmanager_core::tar_zst_backend::TarZstdCreateOptions;
use zmanager_core::tzap_backend::{
    TzapCreateOptions, TzapKeySource, TzapX509SigningOptions, TzapX509TrustOptions,
};
use zmanager_core::x509_format::{hex_lower, x509_name_to_string};
use zmanager_core::zip_backend::{ZipCompression, ZipCreateOptions};
use zmanager_core::{auth_client::TzapSessionStore, trust};

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
const TZAP_MIN_COMPRESSION_LEVEL: i32 = 1;
const TZAP_MAX_COMPRESSION_LEVEL: i32 = 9;
const TZAP_DEFAULT_COMPRESSION_LEVEL: i32 = 3;
const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
const TZAP_SPLIT_VOLUME_LOSS_TOLERANCE: u8 = 1;
const TZAP_MAX_RECOVERY_PERCENTAGE: u8 = 100;
const SEVENZ_MIN_COMPRESSION_LEVEL: i32 = 1;
const SEVENZ_MAX_COMPRESSION_LEVEL: i32 = 9;
const DEFAULT_SEVENZ_ENCRYPT_FILE_NAMES: bool = true;
const ARCHIVE_FORMAT_TAR_ZST: i32 = 0;
const ARCHIVE_FORMAT_ZIP: i32 = 1;
const ARCHIVE_FORMAT_SEVENZ: i32 = 2;
const ARCHIVE_FORMAT_TZAP: i32 = 3;
const OVERWRITE_MODE_REFUSE: u32 = 0;
const OVERWRITE_MODE_REPLACE: u32 = 1;
const OVERWRITE_MODE_RENAME: u32 = 2;
const SELF_SIGNED_IDENTITY_RSA_BITS: u32 = 3072;
const SELF_SIGNED_IDENTITY_VALID_DAYS: u32 = 3_650;
const SELF_SIGNED_IDENTITY_SERIAL_BITS: i32 = 159;
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
const DEFAULT_TZAP_REDIRECT_URI: &str = "zmanager://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const DEFAULT_TZAP_ACCOUNT_KEY: &str =
    zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;
const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";
const OP_CERT_ENROLL: &str = "cert_enroll";
const OP_CERT_RENEW: &str = "cert_renew";
const OP_CERT_REVOKE: &str = "cert_revoke";
const OP_DEVICE_RETIRE: &str = "device_retire";
const MISSING_TZAP_SESSION: &str = "no local TZAP session";
const DEV_ONLY_SELF_SIGNED_IDENTITY_KIND: &str = "dev_only_self_signed_x509_identity";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FfiArchiveFormat {
    TarZst,
    Zip,
    SevenZ,
    Tzap,
}

/// Opaque FFI job handle.
pub struct ZManagerFfiJob {
    receiver: Mutex<Receiver<Value>>,
    token: CancellationToken,
    finished: Arc<AtomicBool>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone)]
struct FfiTzapContext {
    state_dir: PathBuf,
    account_key: String,
}

impl FfiTzapContext {
    fn from_request(request: &Value) -> Result<Self, String> {
        Ok(Self {
            state_dir: request_path(request, "state_dir")?.unwrap_or_else(default_tzap_state_dir),
            account_key: request_string(request, "account_key")?
                .unwrap_or_else(|| DEFAULT_TZAP_ACCOUNT_KEY.to_owned()),
        })
    }
}

#[derive(Debug, Clone)]
struct FfiTzapSessionStore {
    path: PathBuf,
}

impl FfiTzapSessionStore {
    fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(AUTH_SESSION_FILE),
        }
    }
}

impl TzapSessionStore for FfiTzapSessionStore {
    fn save_session(
        &mut self,
        account_key: &str,
        session: zmanager_core::auth_client::TzapSessionRecord,
    ) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
        if !root.is_object() {
            root = json!({ "sessions": {} });
        }
        root["sessions"][account_key] = session_json(&session, true);
        write_secret_json_file(&self.path, &root).map_err(|error| {
            zmanager_core::auth_client::TzapAuthError::Storage {
                message: format!("could not write {}: {error}", self.path.display()),
            }
        })
    }

    fn load_session(
        &self,
        account_key: &str,
    ) -> Option<zmanager_core::auth_client::TzapSessionRecord> {
        let root = read_json_file(&self.path)?;
        session_from_json(root.get("sessions")?.get(account_key)?).ok()
    }

    fn clear_session(
        &mut self,
        account_key: &str,
    ) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let Some(mut root) = read_json_file(&self.path) else {
            return Ok(());
        };
        if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
            sessions.remove(account_key);
        }
        write_secret_json_file(&self.path, &root).map_err(|error| {
            zmanager_core::auth_client::TzapAuthError::Storage {
                message: format!("could not write {}: {error}", self.path.display()),
            }
        })
    }
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
    let options = match zip_create_options(password, compression_level, replace_existing, None) {
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
    let options = match zip_create_options(password, compression_level, replace_existing, None) {
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

/// Starts a ZIP, TAR.ZST, or 7z creation job from multiple source roots.
///
/// `archive_format` must be one of the `ZMANAGER_FFI_ARCHIVE_FORMAT_*`
/// constants from the C header. Set `clean_source` to apply the same
/// `.gitignore` and developer-default exclusions as the CLI `--clean` flag.
/// Pass null or an empty string for `password` to create an unencrypted archive.
/// TAR.ZST does not support passwords and rejects non-empty passwords.
///
/// Pass `-1` for `compression_level` to use the format default, or `1..=9` for
/// an explicit level. Pass true for `replace_existing` only after the caller has
/// confirmed replacement with the user.
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `destination` must point to a valid NUL-terminated UTF-8 C string.
/// `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string. `out_job` must point to writable storage for
/// one job pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer arguments and no explicit
    // archive-path exclusions to the extended create entry point.
    unsafe {
        zmanager_ffi_start_archive_create_many_with_exclusions(
            sources,
            source_count,
            destination,
            archive_format,
            clean_source,
            password,
            compression_level,
            replace_existing,
            ptr::null(),
            0,
            out_job,
        )
    }
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots with
/// explicit archive-path exclusions.
///
/// `exclude_archive_paths` may be null only when `exclude_archive_path_count`
/// is zero. Paths must use archive paths, such as `Project/build`.
///
/// # Safety
///
/// `sources`, `destination`, `password`, and `out_job` follow the same rules as
/// [`zmanager_ffi_start_archive_create_many_with_options`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer arguments and preserves
    // the existing 7z encrypted-header default for callers that do not expose
    // the file-name encryption option.
    unsafe {
        zmanager_ffi_start_archive_create_many_with_exclusions_and_options(
            sources,
            source_count,
            destination,
            archive_format,
            clean_source,
            password,
            compression_level,
            replace_existing,
            DEFAULT_SEVENZ_ENCRYPT_FILE_NAMES,
            exclude_archive_paths,
            exclude_archive_path_count,
            out_job,
        )
    }
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots
/// with explicit archive-path exclusions and 7z-specific encryption options.
///
/// `encrypt_file_names` controls 7z encrypted headers when a 7z password is
/// provided. It is ignored for other formats and for unencrypted 7z archives.
///
/// # Safety
///
/// `sources`, `destination`, `password`, `exclude_archive_paths`, and `out_job`
/// follow the same rules as
/// [`zmanager_ffi_start_archive_create_many_with_exclusions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions_and_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer arguments and no split
    // volume size to the advanced create entry point.
    unsafe {
        zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options(
            sources,
            source_count,
            destination,
            archive_format,
            clean_source,
            password,
            compression_level,
            replace_existing,
            encrypt_file_names,
            0,
            exclude_archive_paths,
            exclude_archive_path_count,
            out_job,
        )
    }
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots
/// with explicit archive-path exclusions, encryption options, and split volume
/// size.
///
/// `volume_size` is zero for a normal archive. Non-zero sizes are supported for
/// ZIP, TZAP, and 7z. ZIP creates `.z01`, `.z02`, ..., `.zip` volume sets; TZAP
/// creates `.vol000.tzap`, `.vol001.tzap`, ... sets; 7z creates numbered `.7z.001`,
/// `.7z.002`, ... output files.
///
/// # Safety
///
/// `sources`, `destination`, `password`, `exclude_archive_paths`, and `out_job`
/// follow the same rules as
/// [`zmanager_ffi_start_archive_create_many_with_exclusions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: u64,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer arguments and preserves
    // the previous TZAP writer defaults for callers that do not expose the new
    // TZAP recovery controls.
    unsafe {
        zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_options(
            sources,
            source_count,
            destination,
            archive_format,
            clean_source,
            password,
            compression_level,
            replace_existing,
            encrypt_file_names,
            volume_size,
            TZAP_DEFAULT_RECOVERY_PERCENTAGE,
            tzap_default_volume_loss_tolerance(volume_size),
            exclude_archive_paths,
            exclude_archive_path_count,
            out_job,
        )
    }
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots
/// with explicit archive-path exclusions, encryption options, split volume size,
/// and TZAP recovery options.
///
/// `tzap_recovery_percentage` maps to TZAP's bit-rot buffer percentage and must
/// be at most 100. `tzap_volume_loss_tolerance` is used only for TZAP split
/// archives and must be zero when `volume_size` is zero.
///
/// # Safety
///
/// `sources`, `destination`, `password`, `exclude_archive_paths`, and `out_job`
/// follow the same rules as
/// [`zmanager_ffi_start_archive_create_many_with_exclusions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: u64,
    tzap_recovery_percentage: u8,
    tzap_volume_loss_tolerance: u8,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this forwards the same checked pointer arguments and no TZAP
    // signing profile to the signing-aware entry point.
    unsafe {
        zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_signing_options(
            sources,
            source_count,
            destination,
            archive_format,
            clean_source,
            password,
            compression_level,
            replace_existing,
            encrypt_file_names,
            volume_size,
            tzap_recovery_percentage,
            tzap_volume_loss_tolerance,
            exclude_archive_paths,
            exclude_archive_path_count,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            out_job,
        )
    }
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots
/// with explicit archive-path exclusions, encryption options, split volume size,
/// TZAP recovery options, and optional TZAP X.509 signing inputs.
///
/// `tzap_signing_cert` and `tzap_signing_private_key` must be both null or both
/// valid UTF-8 file paths. `tzap_signing_cert` may point to a PEM bundle whose
/// first certificate is the signer and whose remaining certificates are
/// intermediates. `tzap_signing_chain` is an optional list of extra
/// intermediate certificate file paths and requires a signing certificate.
///
/// # Safety
///
/// `sources`, `destination`, `password`, `exclude_archive_paths`, signing
/// paths, and `out_job` follow the same pointer rules as
/// [`zmanager_ffi_start_archive_create_many_with_exclusions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_signing_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: u64,
    tzap_recovery_percentage: u8,
    tzap_volume_loss_tolerance: u8,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    tzap_signing_cert: *const c_char,
    tzap_signing_private_key: *const c_char,
    tzap_signing_chain: *const *const c_char,
    tzap_signing_chain_count: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let Some(archive_format) = ffi_archive_format(archive_format) else {
        return ZManagerFfiStatus::InvalidArgument;
    };
    let sources = match unsafe { c_string_array_arg(sources, source_count) } {
        Ok(sources) => sources,
        Err(status) => return status,
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let password = match optional_password_arg(password) {
        Ok(password) => password,
        Err(status) => return status,
    };
    let exclude_archive_paths = match unsafe {
        optional_c_string_array_arg(exclude_archive_paths, exclude_archive_path_count)
    } {
        Ok(paths) => paths,
        Err(status) => return status,
    };
    let tzap_x509_signing = match unsafe {
        optional_tzap_x509_signing_arg(
            tzap_signing_cert,
            tzap_signing_private_key,
            tzap_signing_chain,
            tzap_signing_chain_count,
        )
    } {
        Ok(signing) => signing,
        Err(status) => return status,
    };

    let create_options = match ffi_create_options(FfiCreateRequest {
        archive_format,
        password,
        compression_level,
        replace_existing,
        encrypt_file_names,
        volume_size,
        tzap_recovery_percentage,
        tzap_volume_loss_tolerance,
        tzap_x509_signing,
    }) {
        Ok(options) => options,
        Err(status) => return status,
    };
    start_archive_create_many_with_options_job(
        out_job,
        sources,
        destination,
        clean_source,
        exclude_archive_paths,
        create_options,
    )
}

/// Starts a ZIP, TAR.ZST, TZAP, or 7z creation job from multiple source roots
/// with explicit archive-path exclusions, encryption options, split volume size,
/// TZAP recovery options, and optional TZAP X.509 signing identity inputs.
///
/// Callers may pass either certificate/key files or a PKCS#12 identity file.
/// `tzap_signing_identity_p12` points to a `.p12`/`.pfx` identity containing
/// certificate, private key, and optional intermediates. `tzap_signing_identity_password`
/// may be null or empty for identities with an empty import password.
///
/// # Safety
///
/// `sources`, `destination`, `password`, `exclude_archive_paths`, signing
/// paths, and `out_job` follow the same pointer rules as
/// [`zmanager_ffi_start_archive_create_many_with_exclusions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_identity_options(
    sources: *const *const c_char,
    source_count: usize,
    destination: *const c_char,
    archive_format: i32,
    clean_source: bool,
    password: *const c_char,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: u64,
    tzap_recovery_percentage: u8,
    tzap_volume_loss_tolerance: u8,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
    tzap_signing_cert: *const c_char,
    tzap_signing_private_key: *const c_char,
    tzap_signing_chain: *const *const c_char,
    tzap_signing_chain_count: usize,
    tzap_signing_identity_p12: *const c_char,
    tzap_signing_identity_password: *const c_char,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    if destination.is_null() || out_job.is_null() {
        return ZManagerFfiStatus::NullArgument;
    }

    let Some(archive_format) = ffi_archive_format(archive_format) else {
        return ZManagerFfiStatus::InvalidArgument;
    };
    let sources = match unsafe { c_string_array_arg(sources, source_count) } {
        Ok(sources) => sources,
        Err(status) => return status,
    };
    let Some(destination) = c_string_arg(destination) else {
        return ZManagerFfiStatus::InvalidUtf8;
    };
    let password = match optional_password_arg(password) {
        Ok(password) => password,
        Err(status) => return status,
    };
    let exclude_archive_paths = match unsafe {
        optional_c_string_array_arg(exclude_archive_paths, exclude_archive_path_count)
    } {
        Ok(paths) => paths,
        Err(status) => return status,
    };
    let tzap_x509_signing = match unsafe {
        optional_tzap_x509_signing_identity_arg(
            tzap_signing_cert,
            tzap_signing_private_key,
            tzap_signing_chain,
            tzap_signing_chain_count,
            tzap_signing_identity_p12,
            tzap_signing_identity_password,
        )
    } {
        Ok(signing) => signing,
        Err(status) => return status,
    };

    let create_options = match ffi_create_options(FfiCreateRequest {
        archive_format,
        password,
        compression_level,
        replace_existing,
        encrypt_file_names,
        volume_size,
        tzap_recovery_percentage,
        tzap_volume_loss_tolerance,
        tzap_x509_signing,
    }) {
        Ok(options) => options,
        Err(status) => return status,
    };
    start_archive_create_many_with_options_job(
        out_job,
        sources,
        destination,
        clean_source,
        exclude_archive_paths,
        create_options,
    )
}

/// Starts an archive extraction job routed by archive extension.
///
/// ZIP, TAR.ZST, TZAP, 7z, and passworded RAR use their native extraction
/// backends. Other formats use the libarchive fallback with coarse lifecycle
/// events.
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
    unsafe {
        start_extract_archive_job(
            archive_path,
            destination,
            ptr::null(),
            OVERWRITE_MODE_REFUSE,
            0,
            out_job,
        )
    }
}

/// Starts an archive extraction job with optional password and overwrite
/// behavior routed by archive extension.
///
/// ZIP, TAR.ZST, TZAP, 7z, and passworded RAR use their native extraction
/// backends. Other formats use the libarchive fallback with coarse lifecycle
/// events.
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
            overwrite_mode_from_replace_existing(replace_existing),
            0,
            out_job,
        )
    }
}

/// Starts an archive extraction job with optional password, overwrite mode, and
/// path component stripping.
///
/// `overwrite_mode` is one of `ZMANAGER_FFI_OVERWRITE_*`.
/// `strip_components` drops leading archive path components before writing.
///
/// # Safety
///
/// `archive_path`, `destination`, and `password` follow the same pointer rules
/// as [`zmanager_ffi_start_extract_archive_with_options`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_start_extract_archive_with_policy(
    archive_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    overwrite_mode: u32,
    strip_components: usize,
    out_job: *mut *mut ZManagerFfiJob,
) -> ZManagerFfiStatus {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        start_extract_archive_job(
            archive_path,
            destination,
            password,
            overwrite_mode,
            strip_components,
            out_job,
        )
    }
}

unsafe fn start_extract_archive_job(
    archive_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    overwrite_mode: u32,
    strip_components: usize,
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
    let Ok(policy) = extraction_policy_with_mode(overwrite_mode, strip_components) else {
        return ZManagerFfiStatus::InvalidArgument;
    };

    spawn_archive_job(out_job, move |thread_token, sink| {
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
        } else if is_rar_archive(&archive_path) && password.is_some() {
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
        } else if is_tzap_archive(&archive_path) {
            let _ = zmanager_core::jobs::run_tzap_extract_job_with_password_and_policy(
                archive_path,
                destination,
                password,
                policy,
                &thread_token,
                sink,
            );
        } else if let Some(format) =
            zmanager_core::raw_stream_backend::detect_raw_stream_format(&archive_path)
        {
            let _ = zmanager_core::jobs::run_raw_stream_extract_job_with_policy(
                archive_path,
                format,
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
    unsafe { zmanager_ffi_plan_archive(source, true) }
}

/// Plans an archive source and returns a JSON summary.
///
/// Set `clean_source` to apply the same `.gitignore` and developer-default
/// exclusions as the CLI `--clean` flag. The returned string must be released
/// with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `source` must point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_plan_archive(
    source: *const c_char,
    clean_source: bool,
) -> *mut c_char {
    if source.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null source\"}");
    }

    let Some(source) = c_string_arg(source) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 source\"}");
    };

    let plan_options = if clean_source {
        PlanOptions::clean_source()
    } else {
        PlanOptions::default()
    };
    let json = match plan_archive(PathBuf::from(source), &plan_options) {
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

/// Plans multiple archive sources with explicit archive-path exclusions and
/// returns a JSON summary.
///
/// # Safety
///
/// `sources` must point to `source_count` valid NUL-terminated UTF-8 C strings.
/// `exclude_archive_paths` may be null only when `exclude_archive_path_count`
/// is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_plan_archive_many_with_exclusions(
    sources: *const *const c_char,
    source_count: usize,
    clean_source: bool,
    exclude_archive_paths: *const *const c_char,
    exclude_archive_path_count: usize,
) -> *mut c_char {
    let sources = match unsafe { c_string_array_arg(sources, source_count) } {
        Ok(sources) => sources,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };
    let exclude_archive_paths = match unsafe {
        optional_c_string_array_arg(exclude_archive_paths, exclude_archive_path_count)
    } {
        Ok(paths) => paths,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };

    let sources = sources.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let plan_options = archive_plan_options(clean_source, exclude_archive_paths);
    let json = match plan_archives(&sources, &plan_options) {
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
    // SAFETY: this forwards the same checked archive path and no password to
    // the password-aware listing entry point.
    unsafe { zmanager_ffi_list_archive_with_options(archive_path, ptr::null()) }
}

/// Lists archive entries with optional password support and returns a JSON
/// object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
/// `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_list_archive_with_options(
    archive_path: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }

    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let password = match unsafe { optional_password_string_arg(password) } {
        Ok(password) => password,
        Err(message) => return owned_c_string(&ffi_error_json(message)),
    };

    let json = match zmanager_core::archive_browser::list_entries_with_options(
        PathBuf::from(archive_path),
        zmanager_core::archive_browser::BrowserListOptions {
            password: password.as_deref(),
        },
    ) {
        Ok(listing) => archive_listing_to_json(&listing),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Verifies TZAP X.509 `RootAuth` and returns a JSON object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
/// `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string. `trusted_ca_certs` may be null only when
/// `trusted_ca_cert_count` is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_verify_tzap_x509(
    archive_path: *const c_char,
    password: *const c_char,
    trusted_ca_certs: *const *const c_char,
    trusted_ca_cert_count: usize,
    trusted_system_roots: bool,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }
    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let password = match unsafe { optional_password_string_arg(password) } {
        Ok(password) => password,
        Err(message) => return owned_c_string(&ffi_error_json(message)),
    };
    let trust = match unsafe {
        tzap_x509_trust_options_from_ffi(
            trusted_ca_certs,
            trusted_ca_cert_count,
            trusted_system_roots,
        )
    } {
        Ok(trust) => trust,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };
    if !trust.has_trust_source() {
        return owned_c_string(&ffi_error_json("X.509 verification requires trusted roots"));
    }

    let json =
        match zmanager_core::tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
            PathBuf::from(archive_path),
            password.as_deref(),
            |_| true,
            Some(&trust),
        ) {
            Ok(report) => match report.x509_root_auth.as_ref() {
                Some(root_auth) => json!({
                    "ok": true,
                    "entries": report.entries,
                    "tested_entries": report.tested_entries,
                    "skipped_entries": report.skipped_entries,
                    "tested_bytes": report.tested_bytes,
                    "root_auth": tzap_x509_root_auth_json(root_auth),
                })
                .to_string(),
                None => ffi_error_json("missing X.509 RootAuth verification report"),
            },
            Err(error) => ffi_error_json(&error.to_string()),
        };

    owned_c_string(&json)
}

/// Verifies TZAP X.509 `RootAuth` without the archive key and returns JSON.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
/// `trusted_ca_certs` may be null only when `trusted_ca_cert_count` is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_verify_tzap_x509_public_no_key(
    archive_path: *const c_char,
    trusted_ca_certs: *const *const c_char,
    trusted_ca_cert_count: usize,
    trusted_system_roots: bool,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }
    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let trust = match unsafe {
        tzap_x509_trust_options_from_ffi(
            trusted_ca_certs,
            trusted_ca_cert_count,
            trusted_system_roots,
        )
    } {
        Ok(trust) => trust,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };
    if !trust.has_trust_source() {
        return owned_c_string(&ffi_error_json("X.509 verification requires trusted roots"));
    }

    let json = match zmanager_core::tzap_backend::verify_tzap_x509_public_no_key(
        PathBuf::from(archive_path),
        &trust,
    ) {
        Ok(root_auth) => json!({
            "ok": true,
            "verification_mode": "public-no-key",
            "root_auth": tzap_x509_root_auth_json(&root_auth),
            "public_diagnostics": &root_auth.diagnostics,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Inspects TZAP X.509 `RootAuth` signer metadata without trusted roots.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
/// `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_inspect_tzap_x509_signer(
    archive_path: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }
    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };
    let password = match unsafe { optional_password_string_arg(password) } {
        Ok(password) => password,
        Err(message) => return owned_c_string(&ffi_error_json(message)),
    };

    let json = match zmanager_core::tzap_backend::inspect_tzap_x509_signer(
        PathBuf::from(archive_path),
        password.as_deref(),
    ) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "full",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Inspects TZAP X.509 `RootAuth` signer metadata without the archive key or trusted roots.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_inspect_tzap_x509_public_no_key_signer(
    archive_path: *const c_char,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }
    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };

    let json = match zmanager_core::tzap_backend::inspect_tzap_x509_public_no_key_signer(
        PathBuf::from(archive_path),
    ) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "public-no-key",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Returns public, no-password TZAP metadata as JSON.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` must point to a valid NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_public_metadata_summary(
    archive_path: *const c_char,
) -> *mut c_char {
    if archive_path.is_null() {
        return owned_c_string("{\"ok\":false,\"message\":\"null archive path\"}");
    }
    let Some(archive_path) = c_string_arg(archive_path) else {
        return owned_c_string("{\"ok\":false,\"message\":\"invalid UTF-8 archive path\"}");
    };

    let archive_path = PathBuf::from(archive_path);
    let json = match zmanager_core::tzap_backend::summarize_tzap_public_metadata(&archive_path) {
        Ok(summary) => {
            let signature = match zmanager_core::tzap_backend::verify_tzap_x509_public_no_key(
                &archive_path,
                &TzapX509TrustOptions {
                    trusted_ca_certificates: Vec::new(),
                    trusted_system_roots: true,
                    include_official_tzap_root: true,
                },
            ) {
                Ok(root_auth) => json!({
                    "status": "verified",
                    "verification_mode": "public-no-key",
                    "root_auth": tzap_x509_root_auth_json(&root_auth),
                }),
                Err(error) => {
                    match zmanager_core::tzap_backend::inspect_tzap_x509_public_no_key_signer(
                        &archive_path,
                    ) {
                        Ok(root_auth) => json!({
                            "status": "unverified",
                            "verification_mode": "public-no-key-inspection",
                            "message": format!(
                                "Signer certificate inspected, but trust was not verified: {error}"
                            ),
                            "root_auth": tzap_x509_signer_inspection_json(&root_auth),
                        }),
                        Err(_) => json!({
                            "status": "unverified",
                            "message": error.to_string(),
                        }),
                    }
                }
            };

            json!({
                "ok": true,
                "metadata": tzap_public_metadata_json(&summary),
                "signature": signature,
            })
            .to_string()
        }
        Err(error) => ffi_error_json(&error.to_string()),
    };

    owned_c_string(&json)
}

/// Creates a self-signed TZAP signing identity as PKCS#12 plus a public PEM certificate.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `identity_p12` and `common_name` must point to valid NUL-terminated UTF-8 C
/// strings. `public_certificate` and `identity_password` may be null; when
/// non-null they must point to valid NUL-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_create_tzap_self_signed_identity(
    identity_p12: *const c_char,
    public_certificate: *const c_char,
    common_name: *const c_char,
    identity_password: *const c_char,
) -> *mut c_char {
    if identity_p12.is_null() || common_name.is_null() {
        return owned_c_string(&ffi_error_json("identity path and name are required"));
    }
    let Some(identity_p12) = c_string_arg(identity_p12) else {
        return owned_c_string(&ffi_error_json("invalid UTF-8 identity path"));
    };
    let public_certificate = match optional_c_string_arg(public_certificate) {
        Ok(path) => path,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };
    let Some(common_name) = c_string_arg(common_name) else {
        return owned_c_string(&ffi_error_json("invalid UTF-8 identity name"));
    };
    let common_name = common_name.trim();
    if common_name.is_empty() {
        return owned_c_string(&ffi_error_json("signing identity name is required"));
    }
    let password = match pkcs12_password_arg(identity_password) {
        Ok(password) => password,
        Err(status) => return owned_c_string(&ffi_status_json(status)),
    };

    let identity_path = PathBuf::from(identity_p12);
    let public_certificate_path = public_certificate.map(PathBuf::from);
    let json = match create_self_signed_tzap_identity(
        &identity_path,
        public_certificate_path.as_deref(),
        common_name,
        &password,
    ) {
        Ok(certificate) => json!({
            "ok": true,
            "identity_kind": DEV_ONLY_SELF_SIGNED_IDENTITY_KIND,
            "official_tzap_signing_identity": false,
            "identity_path": identity_path.display().to_string(),
            "public_certificate_path": public_certificate_path
                .as_ref()
                .map(|path| path.display().to_string()),
            "certificate": certificate,
        })
        .to_string(),
        Err(message) => ffi_error_json(&message),
    };

    owned_c_string(&json)
}

/// Creates a hosted-auth launch URL from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `environment`, `auth_base_url`,
/// `account_base_url`, `client_id`, `redirect_uri`, `provider_id`, `org_id`,
/// and `now_unix_seconds`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_auth_login_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id =
            request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri = request_string(&request, "redirect_uri")?
            .unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let provider_id = request_string(&request, "provider_id")?
            .unwrap_or_else(|| DEFAULT_TZAP_PROVIDER_ID.into());
        let now_unix_seconds =
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);

        let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
        let pending = tracker.begin(provider_id, redirect_uri.clone(), now_unix_seconds);
        save_pending_auth(&context.state_dir, &pending).map_err(|error| error.to_string())?;

        let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            environment,
            client_id,
            redirect_uri,
        );
        if let Some(auth_base_url) = request_string(&request, "auth_base_url")? {
            config.hosted_auth_base_url = auth_base_url;
        }
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        let launch_url = config
            .launch_url(&pending)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "status": "pending",
            "launch_url": launch_url,
            "state": pending.state,
            "expires_at_unix_seconds": pending
                .created_at_unix_seconds
                .saturating_add(zmanager_core::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS),
        }))
    });
    owned_c_string(&response)
}

/// Completes a hosted-auth callback/handoff from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `state`, `redirect_uri`,
/// `callback_url`, `relay_body`, and `now_unix_seconds`. `relay_body` is the
/// hosted relay JSON string, not provider credentials. The returned string must
/// be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_auth_callback_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let pending = load_pending_auth(&context.state_dir)?;
        let state = required_request_string(&request, "state")?;
        let redirect_uri = request_string(&request, "redirect_uri")?
            .unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let relay_body = required_request_string(&request, "relay_body")?.into_bytes();
        let callback = zmanager_core::auth_client::TzapHostedAuthCallback {
            state,
            redirect_uri,
            pkce_verifier: pending.pkce.verifier.clone(),
            callback_url: request_string(&request, "callback_url")?,
            relay_body,
        };
        let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
        tracker
            .insert_pending(pending)
            .map_err(|error| error.to_string())?;
        let mut session_store = FfiTzapSessionStore::new(&context.state_dir);
        let session = zmanager_core::auth_client::complete_hosted_auth_handoff(
            &mut tracker,
            &mut session_store,
            &context.account_key,
            &callback,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        )
        .map_err(|error| error.to_string())?;
        let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
        Ok(json!({
            "ok": true,
            "authenticated": true,
            "session": session_summary_json(&session),
        }))
    });
    owned_c_string(&response)
}

/// Returns local hosted-auth session status as JSON.
///
/// Request fields: `state_dir`, `account_key`, and `now_unix_seconds`. The
/// returned string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_auth_status_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let store = FfiTzapSessionStore::new(&context.state_dir);
        let now = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        Ok(match store.load_session(&context.account_key) {
            Some(session) => json!({
                "ok": true,
                "authenticated": true,
                "session": session_summary_json_at(&session, now),
            }),
            None => json!({
                "ok": true,
                "authenticated": false,
            }),
        })
    });
    owned_c_string(&response)
}

/// Clears local hosted-auth state and session material.
///
/// Request fields: `state_dir` and `account_key`. The returned string must be
/// freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_auth_forget_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let mut store = FfiTzapSessionStore::new(&context.state_dir);
        store
            .clear_session(&context.account_key)
            .map_err(|error| error.to_string())?;
        let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
        Ok(json!({
            "ok": true,
            "forgotten": true,
        }))
    });
    owned_c_string(&response)
}

/// Creates a hosted Account UI URL from a JSON request.
///
/// Request fields: `environment`, `client_id`, `redirect_uri`,
/// `account_base_url`, and `org_id`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_auth_account_url_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id =
            request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri = request_string(&request, "redirect_uri")?
            .unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            environment,
            client_id,
            redirect_uri,
        );
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        Ok(json!({
            "ok": true,
            "account_url": config.account_url(),
        }))
    });
    owned_c_string(&response)
}

/// Returns non-secret local certificate/key/contact inventory as JSON.
///
/// Request fields: `state_dir` and `account_key`. The returned string must be
/// freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_certificate_inventory_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store
            .load_inventory(&context.account_key)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "inventory": inventory_summary_json(&inventory),
        }))
    });
    owned_c_string(&response)
}

/// Enrolls a local fake-service TZAP certificate for the active session.
///
/// The returned string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must be null or point to a valid NUL-terminated UTF-8 JSON
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_cert_enroll_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = run_fake_tzap_service(
        request_json,
        OP_CERT_ENROLL,
        |store, session, options, _| {
            zmanager_core::local_fake_tzap::enroll_local_fake_certificate(store, session, options)
                .map(|certificate| {
                    json!({
                        "ok": true,
                        "operation": OP_CERT_ENROLL,
                        "certificate": certificate_summary_json(&certificate),
                    })
                })
                .map_err(|error| error.to_string())
        },
    );
    owned_c_string(&response)
}

/// Renews a local fake-service TZAP certificate for the active session.
///
/// The returned string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must be null or point to a valid NUL-terminated UTF-8 JSON
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_cert_renew_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = run_fake_tzap_service(
        request_json,
        OP_CERT_RENEW,
        |store, session, options, request| {
            let certificate_id = required_request_string(request, "certificate_id")?;
            zmanager_core::local_fake_tzap::renew_local_fake_certificate(
                store,
                session,
                options,
                &certificate_id,
            )
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_RENEW,
                    "certificate": certificate_summary_json(&certificate),
                })
            })
            .map_err(|error| error.to_string())
        },
    );
    owned_c_string(&response)
}

/// Revokes a local fake-service TZAP certificate for the active session.
///
/// The returned string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must be null or point to a valid NUL-terminated UTF-8 JSON
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_cert_revoke_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = run_fake_tzap_service(
        request_json,
        OP_CERT_REVOKE,
        |store, session, options, request| {
            let certificate_id = required_request_string(request, "certificate_id")?;
            zmanager_core::local_fake_tzap::revoke_local_fake_certificate(
                store,
                session,
                options,
                &certificate_id,
            )
            .map(|completion| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_REVOKE,
                    "completion": retirement_completion_label(completion),
                })
            })
            .map_err(|error| error.to_string())
        },
    );
    owned_c_string(&response)
}

/// Retires local fake-service personal device certificates for the active session.
///
/// The returned string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must be null or point to a valid NUL-terminated UTF-8 JSON
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_device_retire_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = run_fake_tzap_service(
        request_json,
        OP_DEVICE_RETIRE,
        |store, session, options, _| {
            zmanager_core::local_fake_tzap::retire_local_fake_device(store, session, options)
                .map(|report| {
                    json!({
                        "ok": true,
                        "operation": OP_DEVICE_RETIRE,
                        "completion": retirement_completion_label(report.completion),
                        "attempted_sign_device_ids": report.attempted_sign_device_ids,
                    })
                })
                .map_err(|error| error.to_string())
        },
    );
    owned_c_string(&response)
}

/// Signs a TZAP document payload from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `certificate_id`, `payload`,
/// `claimed_signing_time`, and `now_unix_seconds`. The returned string must be
/// freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_document_sign_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let certificate_id = required_request_string(&request, "certificate_id")?;
        let payload = request
            .get("payload")
            .cloned()
            .ok_or_else(|| "missing or invalid field: payload".to_owned())?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut signing_request = zmanager_core::document_signing::TzapDocumentSigningRequest::new(
            context.account_key,
            certificate_id,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        );
        signing_request.claimed_signing_time = request_string(&request, "claimed_signing_time")?;
        let envelope = zmanager_core::document_signing::sign_tzap_document_payload(
            &store,
            &signing_request,
            payload,
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "envelope": envelope,
        }))
    });
    owned_c_string(&response)
}

/// Verifies a TZAP document envelope from a JSON request.
///
/// Request fields: `envelope`, optional `mode` (`offline` or `valid_now`),
/// optional `status_response`, `custom_trust_root_sha256`, and
/// `verifier_time_unix_seconds`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_document_verify_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let envelope = request
            .get("envelope")
            .ok_or_else(|| "missing or invalid field: envelope".to_owned())?;
        let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
        let options = zmanager_core::document_verification::TzapOfflineVerificationOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256: request_string_array(&request, "custom_trust_root_sha256")?,
            custom_trust_root_certificates_der: Vec::new(),
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let result =
            zmanager_core::document_verification::verify_tzap_document_envelope_offline_json(
                &bytes, &options,
            );
        if request_string(&request, "mode")?
            .as_deref()
            .unwrap_or("offline")
            == "offline"
            || result.state == trust::TzapVerificationState::Invalid
        {
            return Ok(document_verification_result_json(&result));
        }
        if request_string(&request, "mode")?.as_deref() != Some("valid_now") {
            return Err("document verify mode must be offline or valid_now".to_owned());
        }
        let envelope = zmanager_core::document_envelope::parse_tzap_document_envelope_json(&bytes)
            .map_err(|error| error.to_string())?;
        let status_value = request
            .get("status_response")
            .ok_or_else(|| "missing or invalid field: status_response".to_owned())?;
        let status =
            zmanager_core::status_client::TzapStatusResponse::from_json_value(status_value)
                .map_err(|error| error.to_string())?;
        let result = zmanager_core::status_client::verify_tzap_document_envelope_valid_now(
            &envelope, &options, &status,
        );
        Ok(document_verification_result_json(&result))
    });
    owned_c_string(&response)
}

/// Generates and stores a local recipient key from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `label`, and
/// `created_at_unix_seconds`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_recipient_key_generate_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let material = zmanager_core::device_identity::generate_recipient_encryption_key()
            .map_err(|error| error.to_string())?;
        let record = TzapRecipientEncryptionKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            algorithm: material.algorithm.to_owned(),
            public_key_fingerprint: material.public_key_fingerprint,
            public_key_der: material.public_key_spki_der,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?
                .unwrap_or_else(current_unix_seconds),
            label: request_string(&request, "label")?,
        };
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store
            .load_inventory(&context.account_key)
            .map_err(|error| error.to_string())?;
        inventory
            .recipient_encryption_keys
            .retain(|existing| existing.key_id != record.key_id);
        inventory.recipient_encryption_keys.push(record.clone());
        store
            .save_inventory(&context.account_key, inventory)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "recipient_key": recipient_key_summary_json(&record),
        }))
    });
    owned_c_string(&response)
}

/// Removes a local recipient key from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, and `key_id`. The returned
/// string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_recipient_key_remove_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let key_id = required_request_string(&request, "key_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store
            .load_inventory(&context.account_key)
            .map_err(|error| error.to_string())?;
        let before = inventory.recipient_encryption_keys.len();
        inventory
            .recipient_encryption_keys
            .retain(|record| record.key_id != key_id);
        let removed = before != inventory.recipient_encryption_keys.len();
        store
            .save_inventory(&context.account_key, inventory)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    });
    owned_c_string(&response)
}

/// Exports a TZAP contact card from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `recipient_key_id`,
/// `certificate_id`, `display_name`, `device_label`, `created_at_unix_seconds`,
/// and `expires_at_unix_seconds`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_contact_export_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let export_request = zmanager_core::contact_card::TzapContactCardExportRequest {
            account_key: context.account_key,
            recipient_key_id: required_request_string(&request, "recipient_key_id")?,
            certificate_id: required_request_string(&request, "certificate_id")?,
            display_name: required_request_string(&request, "display_name")?,
            device_label: request_string(&request, "device_label")?
                .unwrap_or_else(|| "ZManager".to_owned()),
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?
                .unwrap_or_else(current_unix_seconds),
            expires_at_unix_seconds: request_u64(&request, "expires_at_unix_seconds")?,
        };
        let card = zmanager_core::contact_card::export_tzap_contact_card(&store, &export_request)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact_card": card,
        }))
    });
    owned_c_string(&response)
}

/// Imports or previews a TZAP contact card from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, `contact_card`, `accept`,
/// `accepted_at_unix_seconds`, `verifier_time_unix_seconds`, and
/// `custom_trust_root_sha256`. The returned string must be freed with
/// [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_contact_import_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let card = request
            .get("contact_card")
            .cloned()
            .ok_or_else(|| "missing or invalid field: contact_card".to_owned())?;
        let options = zmanager_core::contact_card::TzapContactCardImportOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256: request_string_array(&request, "custom_trust_root_sha256")?,
            custom_trust_root_certificates_der: Vec::new(),
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let accepted_at = request
            .get("accept")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            .then_some(
                request_u64(&request, "accepted_at_unix_seconds")?
                    .unwrap_or_else(current_unix_seconds),
            );
        let contact = zmanager_core::contact_card::import_tzap_contact_card(
            &mut store,
            &context.account_key,
            &card,
            &options,
            accepted_at,
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact": contact_summary_json(&contact),
        }))
    });
    owned_c_string(&response)
}

/// Lists accepted TZAP contacts from a JSON request.
///
/// Request fields: `state_dir` and `account_key`. The returned string must be
/// freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_contact_list_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store
            .load_inventory(&context.account_key)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contacts": inventory
                .contacts
                .iter()
                .map(contact_summary_json)
                .collect::<Vec<_>>(),
        }))
    });
    owned_c_string(&response)
}

/// Removes an accepted TZAP contact from a JSON request.
///
/// Request fields: `state_dir`, `account_key`, and `contact_id`. The returned
/// string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_contact_remove_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let contact_id = required_request_string(&request, "contact_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store
            .load_inventory(&context.account_key)
            .map_err(|error| error.to_string())?;
        let before = inventory.contacts.len();
        inventory
            .contacts
            .retain(|contact| contact.contact_id != contact_id);
        let removed = before != inventory.contacts.len();
        store
            .save_inventory(&context.account_key, inventory)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    });
    owned_c_string(&response)
}

/// Creates a multi-recipient TZAP archive for accepted contacts.
///
/// Request fields: `state_dir`, `account_key`, `destination`, `sources`,
/// `contact_ids`, `replace_existing`, and `now_unix_seconds`. The returned
/// string must be freed with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `request_json` must point to a valid NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_tzap_share_create_json(
    request_json: *const c_char,
) -> *mut c_char {
    let response = with_json_request(request_json, |request| {
        let context = FfiTzapContext::from_request(&request)?;
        let destination = required_request_path(&request, "destination")?;
        let sources = required_request_path_array(&request, "sources")?;
        let contact_ids = request_string_array(&request, "contact_ids")?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let recipients = zmanager_core::contact_card::accepted_contact_recipients(
            &store,
            &context.account_key,
            &contact_ids,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        )
        .map_err(|error| error.to_string())?;
        let recipient_status_caveats = recipients
            .iter()
            .filter(|recipient| recipient.missing_status_caveat)
            .count();
        let recipient_public_keys = recipients
            .into_iter()
            .map(|recipient| recipient.recipient_public_key_der)
            .collect();
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientPublicKeys(recipient_public_keys),
            level: TZAP_DEFAULT_COMPRESSION_LEVEL,
            preserve_metadata: true,
            replace_existing: request
                .get("replace_existing")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            volume_size: None,
            recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
            volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut event_sink = |_event: JobEvent| {};
        let report = zmanager_core::jobs::run_tzap_create_job_from_sources_with_plan_options(
            &sources,
            &destination,
            &options,
            &PlanOptions::default(),
            &token,
            &mut event_sink,
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "archive": destination.display().to_string(),
            "format": "tzap",
            "entries": report.written_entries,
            "bytes": report.written_bytes,
            "recipients": contact_ids.len(),
            "recipient_status_caveats": recipient_status_caveats,
            "volume_count": report.volume_count,
        }))
    });
    owned_c_string(&response)
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
    unsafe {
        extract_archive_entry(
            archive_path,
            entry_path,
            destination,
            ptr::null(),
            OVERWRITE_MODE_REFUSE,
            0,
        )
    }
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
            overwrite_mode_from_replace_existing(replace_existing),
            0,
        )
    }
}

/// Extracts one archive entry with optional password, overwrite mode, and path
/// component stripping.
///
/// `overwrite_mode` is one of `ZMANAGER_FFI_OVERWRITE_*`.
/// `strip_components` drops leading archive path components before writing.
///
/// # Safety
///
/// `archive_path`, `entry_path`, `destination`, and `password` follow the same
/// pointer rules as [`zmanager_ffi_extract_archive_entry_with_options`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_extract_archive_entry_with_policy(
    archive_path: *const c_char,
    entry_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    overwrite_mode: u32,
    strip_components: usize,
) -> *mut c_char {
    // SAFETY: this public C entry point has the same pointer contract as the
    // shared implementation.
    unsafe {
        extract_archive_entry(
            archive_path,
            entry_path,
            destination,
            password,
            overwrite_mode,
            strip_components,
        )
    }
}

unsafe fn extract_archive_entry(
    archive_path: *const c_char,
    entry_path: *const c_char,
    destination: *const c_char,
    password: *const c_char,
    overwrite_mode: u32,
    strip_components: usize,
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
    let password = match unsafe { optional_password_string_arg(password) } {
        Ok(password) => password,
        Err(message) => return owned_c_string(&ffi_error_json(message)),
    };
    let Some(overwrite) = overwrite_policy_from_mode(overwrite_mode) else {
        return owned_c_string(&ffi_error_json("invalid overwrite mode"));
    };

    let json = match zmanager_core::archive_browser::extract_entry_with_options(
        PathBuf::from(archive_path),
        &entry_path,
        PathBuf::from(destination),
        zmanager_core::archive_browser::BrowserExtractOptions {
            password: password.as_deref(),
            overwrite,
            strip_components,
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
    // SAFETY: this forwards the same checked pointers and no password to the
    // password-aware preview entry point.
    unsafe {
        zmanager_ffi_preview_archive_entry_with_options(archive_path, entry_path, ptr::null())
    }
}

/// Extracts one archive entry to a controlled temporary preview directory with
/// optional password support and returns a JSON object.
///
/// The returned string must be released with [`zmanager_ffi_string_free`].
///
/// # Safety
///
/// `archive_path` and `entry_path` must point to valid NUL-terminated UTF-8 C
/// strings. `password` may be null; if non-null it must point to a valid
/// NUL-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zmanager_ffi_preview_archive_entry_with_options(
    archive_path: *const c_char,
    entry_path: *const c_char,
    password: *const c_char,
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
    let password = match unsafe { optional_password_string_arg(password) } {
        Ok(password) => password,
        Err(message) => return owned_c_string(&ffi_error_json(message)),
    };

    let json = match zmanager_core::archive_browser::preview_entry_with_options(
        PathBuf::from(archive_path),
        &entry_path,
        zmanager_core::archive_browser::BrowserExtractOptions {
            password: password.as_deref(),
            ..zmanager_core::archive_browser::BrowserExtractOptions::default()
        },
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

fn with_json_request(
    request_json: *const c_char,
    operation: impl FnOnce(Value) -> Result<Value, String>,
) -> String {
    match parse_json_request(request_json).and_then(operation) {
        Ok(response) => response.to_string(),
        Err(message) => ffi_error_json(&message),
    }
}

fn parse_json_request(request_json: *const c_char) -> Result<Value, String> {
    if request_json.is_null() {
        return Err("null request JSON".to_owned());
    }
    let request =
        c_string_arg(request_json).ok_or_else(|| "invalid UTF-8 request JSON".to_owned())?;
    if request.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&request).map_err(|error| format!("invalid request JSON: {error}"))
}

fn request_string(request: &Value, field: &'static str) -> Result<Option<String>, String> {
    match request.get(field) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        None | Some(Value::Null | Value::String(_)) => Ok(None),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn required_request_string(request: &Value, field: &'static str) -> Result<String, String> {
    request_string(request, field)?.ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn request_path(request: &Value, field: &'static str) -> Result<Option<PathBuf>, String> {
    Ok(request_string(request, field)?.map(PathBuf::from))
}

fn required_request_path(request: &Value, field: &'static str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required_request_string(request, field)?))
}

fn request_u64(request: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("missing or invalid field: {field}"))
            .map(Some),
    }
}

fn request_i64(request: &Value, field: &'static str) -> Result<Option<i64>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .ok_or_else(|| format!("missing or invalid field: {field}"))
            .map(Some),
    }
}

fn request_string_array(request: &Value, field: &'static str) -> Result<Vec<String>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("missing or invalid field: {field}"))
            })
            .collect(),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn required_request_path_array(
    request: &Value,
    field: &'static str,
) -> Result<Vec<PathBuf>, String> {
    let paths = request_string_array(request, field)?
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if paths.is_empty() {
        Err(format!("missing or invalid field: {field}"))
    } else {
        Ok(paths)
    }
}

fn parse_auth_environment(
    value: &str,
) -> Result<zmanager_core::auth_client::TzapHostedAuthEnvironment, String> {
    match value {
        "local" => Ok(zmanager_core::auth_client::TzapHostedAuthEnvironment::Local),
        "dev" => Ok(zmanager_core::auth_client::TzapHostedAuthEnvironment::Dev),
        "prod" => Ok(zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod),
        _ => Err("environment must be local, dev, or prod".to_owned()),
    }
}

fn default_tzap_state_dir() -> PathBuf {
    std::env::var_os("ZMANAGER_TZAP_STATE_DIR").map_or_else(
        || {
            std::env::var_os("HOME").map_or_else(
                || PathBuf::from(".").join(".zmanager").join("tzap"),
                |home| PathBuf::from(home).join(".zmanager").join("tzap"),
            )
        },
        PathBuf::from,
    )
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_secret_json_file(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_secret_file(path, &bytes)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

fn save_pending_auth(
    state_dir: &Path,
    pending: &zmanager_core::auth_client::TzapPendingAuthState,
) -> std::io::Result<()> {
    write_secret_json_file(
        &state_dir.join(AUTH_PENDING_FILE),
        &json!({
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "pkce_verifier": pending.pkce.verifier,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
        }),
    )
}

fn load_pending_auth(
    state_dir: &Path,
) -> Result<zmanager_core::auth_client::TzapPendingAuthState, String> {
    let value = read_json_file(&state_dir.join(AUTH_PENDING_FILE))
        .ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
    let verifier = required_request_string(&value, "pkce_verifier")?;
    let pkce = zmanager_core::auth_client::TzapPkcePair::from_verifier(&verifier)
        .map_err(|error| error.to_string())?;
    Ok(zmanager_core::auth_client::TzapPendingAuthState {
        state: required_request_string(&value, "state")?,
        provider_id: required_request_string(&value, "provider_id")?,
        redirect_uri: required_request_string(&value, "redirect_uri")?,
        pkce,
        created_at_unix_seconds: request_u64(&value, "created_at_unix_seconds")?
            .ok_or_else(|| "missing or invalid field: created_at_unix_seconds".to_owned())?,
    })
}

fn session_json(
    session: &zmanager_core::auth_client::TzapSessionRecord,
    include_token: bool,
) -> Value {
    let mut value = json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    });
    if include_token {
        value["access_token"] = json!(session.access_token.expose());
    }
    value
}

fn session_summary_json(session: &zmanager_core::auth_client::TzapSessionRecord) -> Value {
    session_summary_json_at(session, current_unix_seconds())
}

fn session_summary_json_at(
    session: &zmanager_core::auth_client::TzapSessionRecord,
    now_unix_seconds: u64,
) -> Value {
    json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "expired": session.is_expired_at(now_unix_seconds),
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    })
}

fn session_from_json(
    value: &Value,
) -> Result<zmanager_core::auth_client::TzapSessionRecord, String> {
    let assurance = required_request_string(value, "identity_assurance")?;
    let identity_assurance = trust::TzapIdentityAssurance::from_str(&assurance)
        .ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(zmanager_core::auth_client::TzapSessionRecord {
        audience: required_request_string(value, "audience")?,
        access_token: zmanager_core::auth_client::TzapBearerToken::new(required_request_string(
            value,
            "access_token",
        )?)
        .map_err(|error| error.to_string())?,
        expires_at_unix_seconds: request_u64(value, "expires_at_unix_seconds")?
            .ok_or_else(|| "missing or invalid field: expires_at_unix_seconds".to_owned())?,
        identity_assurance,
        selected_org_id: request_string(value, "selected_org_id")?,
        login_session_id: request_string(value, "login_session_id")?,
    })
}

fn stable_tzap_error_json(operation: &str, message: &str) -> String {
    json!({
        "ok": false,
        "operation": operation,
        "error": message,
    })
    .to_string()
}

fn run_fake_tzap_service<F>(
    request_json: *const c_char,
    operation: &'static str,
    action: F,
) -> String
where
    F: FnOnce(
        &mut FileTzapLocalIdentityStore,
        &zmanager_core::auth_client::TzapSessionRecord,
        &zmanager_core::local_fake_tzap::TzapLocalFakeServiceOptions,
        &Value,
    ) -> Result<Value, String>,
{
    match parse_json_request(request_json).and_then(|request| {
        let context = FfiTzapContext::from_request(&request)?;
        let session_store = FfiTzapSessionStore::new(&context.state_dir);
        let Some(session) = session_store.load_session(&context.account_key) else {
            return Err(MISSING_TZAP_SESSION.to_owned());
        };
        let mut identity_store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let options = zmanager_core::local_fake_tzap::TzapLocalFakeServiceOptions {
            account_key: context.account_key,
            now_unix_seconds: request_u64(&request, "now_unix_seconds")?
                .unwrap_or_else(current_unix_seconds),
        };
        action(&mut identity_store, &session, &options, &request)
    }) {
        Ok(value) => value.to_string(),
        Err(message) => stable_tzap_error_json(operation, &message),
    }
}

fn inventory_summary_json(inventory: &TzapLocalIdentityInventory) -> Value {
    json!({
        "device_signing_key_count": inventory.device_signing_keys.len(),
        "recipient_encryption_keys": inventory
            .recipient_encryption_keys
            .iter()
            .map(recipient_key_summary_json)
            .collect::<Vec<_>>(),
        "certificates": inventory
            .enrolled_certificates
            .iter()
            .map(certificate_summary_json)
            .collect::<Vec<_>>(),
        "contacts": inventory
            .contacts
            .iter()
            .map(contact_summary_json)
            .collect::<Vec<_>>(),
        "emergency_blocklist": {
            "blocked_root_sha256": inventory.emergency_blocklist.blocked_root_sha256,
            "blocked_issuer_sha256": inventory.emergency_blocklist.blocked_issuer_sha256,
            "updated_at_unix_seconds": inventory.emergency_blocklist.updated_at_unix_seconds,
        },
    })
}

fn certificate_summary_json(certificate: &TzapEnrolledCertificateRecord) -> Value {
    json!({
        "certificate_id": certificate.certificate_id,
        "certificate_sha256": certificate.certificate_sha256,
        "issuer_certificate_sha256": certificate.issuer_certificate_sha256,
        "issuer_key_identifier": certificate.issuer_key_identifier,
        "serial_number": certificate.serial_number,
        "not_before_unix_seconds": certificate.not_before_unix_seconds,
        "not_after_unix_seconds": certificate.not_after_unix_seconds,
        "sign_device_id": certificate.sign_device_id,
        "signing_key_id": certificate.signing_key_id,
        "state": certificate.state.as_str(),
        "active": certificate.state == TzapLocalCertificateState::Active,
        "public_metadata": {
            "version": certificate.public_metadata.version,
            "public_signer_id": certificate.public_metadata.public_signer_id,
            "public_org_id": certificate.public_metadata.public_org_id,
            "public_device_id": certificate.public_metadata.public_device_id,
            "assurance_level": certificate.public_metadata.assurance_level.as_str(),
            "policy_oid": certificate.public_metadata.policy_oid,
        },
    })
}

fn retirement_completion_label(
    completion: zmanager_core::certificate_lifecycle::TzapRetirementCompletion,
) -> &'static str {
    match completion {
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
}

fn recipient_key_summary_json(record: &TzapRecipientEncryptionKeyRecord) -> Value {
    json!({
        "key_id": record.key_id,
        "algorithm": record.algorithm,
        "public_key_fingerprint": record.public_key_fingerprint,
        "public_key_der": URL_SAFE_NO_PAD.encode(&record.public_key_der),
        "created_at_unix_seconds": record.created_at_unix_seconds,
        "label": record.label,
    })
}

fn contact_summary_json(contact: &TzapContactRecord) -> Value {
    json!({
        "contact_id": contact.contact_id,
        "display_name": contact.display_name,
        "signing_certificate_sha256": contact.signing_certificate_sha256,
        "recipient_public_key_fingerprint": contact.recipient_public_key_fingerprint,
        "trust_anchor_type": contact.trust_anchor_type.as_str(),
        "verification_state": contact.verification_state.as_str(),
        "missing_status_caveat": contact.missing_status_caveat,
        "accepted_at_unix_seconds": contact.accepted_at_unix_seconds,
    })
}

fn document_verification_result_json(
    result: &zmanager_core::document_verification::TzapDocumentVerificationResult,
) -> Value {
    json!({
        "ok": result.state != trust::TzapVerificationState::Invalid,
        "state": result.state.as_str(),
        "trust_anchor_type": result.trust_anchor_type.as_str(),
        "reason": result.reason,
        "root_certificate_sha256": result.root_certificate_sha256,
        "public_metadata": result.public_metadata.as_ref().map(|metadata| {
            json!({
                "version": metadata.version,
                "public_signer_id": metadata.public_signer_id,
                "public_org_id": metadata.public_org_id,
                "public_device_id": metadata.public_device_id,
                "assurance_level": metadata.assurance_level.as_str(),
                "policy_oid": metadata.policy_oid,
            })
        }),
    })
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

unsafe fn optional_c_string_array_arg(
    values: *const *const c_char,
    value_count: usize,
) -> Result<Vec<String>, ZManagerFfiStatus> {
    if value_count == 0 {
        return Ok(Vec::new());
    }

    unsafe { c_string_array_arg(values, value_count) }
}

fn optional_c_string_arg(value: *const c_char) -> Result<Option<String>, ZManagerFfiStatus> {
    if value.is_null() {
        return Ok(None);
    }

    let Some(value) = c_string_arg(value) else {
        return Err(ZManagerFfiStatus::InvalidUtf8);
    };
    Ok((!value.is_empty()).then_some(value))
}

unsafe fn optional_tzap_x509_signing_arg(
    certificate: *const c_char,
    private_key: *const c_char,
    chain: *const *const c_char,
    chain_count: usize,
) -> Result<Option<TzapX509SigningOptions>, ZManagerFfiStatus> {
    let certificate = optional_c_string_arg(certificate)?;
    let private_key = optional_c_string_arg(private_key)?;
    let chain = unsafe { optional_c_string_array_arg(chain, chain_count) }?;

    match (certificate, private_key) {
        (Some(certificate), Some(private_key)) => {
            Ok(Some(TzapX509SigningOptions::CertificateAndKey {
                signing_certificate: PathBuf::from(certificate),
                signing_private_key: PathBuf::from(private_key),
                signing_chain: chain.into_iter().map(PathBuf::from).collect(),
            }))
        }
        (None, None) if chain.is_empty() => Ok(None),
        _ => Err(ZManagerFfiStatus::InvalidArgument),
    }
}

unsafe fn optional_tzap_x509_signing_identity_arg(
    certificate: *const c_char,
    private_key: *const c_char,
    chain: *const *const c_char,
    chain_count: usize,
    identity_p12: *const c_char,
    identity_password: *const c_char,
) -> Result<Option<TzapX509SigningOptions>, ZManagerFfiStatus> {
    let file_identity =
        unsafe { optional_tzap_x509_signing_arg(certificate, private_key, chain, chain_count) }?;
    let identity_p12 = optional_c_string_arg(identity_p12)?;
    let identity_password = pkcs12_password_arg(identity_password)?;

    match (file_identity, identity_p12) {
        (Some(identity), None) => Ok(Some(identity)),
        (None, Some(identity)) => Ok(Some(TzapX509SigningOptions::Pkcs12 {
            identity: PathBuf::from(identity),
            password: identity_password,
        })),
        (None, None) if identity_password.is_empty() => Ok(None),
        _ => Err(ZManagerFfiStatus::InvalidArgument),
    }
}

unsafe fn tzap_x509_trust_options_from_ffi(
    trusted_ca_certs: *const *const c_char,
    trusted_ca_cert_count: usize,
    trusted_system_roots: bool,
) -> Result<TzapX509TrustOptions, ZManagerFfiStatus> {
    let has_explicit_roots = trusted_system_roots || trusted_ca_cert_count > 0;
    let trusted_ca_certs =
        unsafe { optional_c_string_array_arg(trusted_ca_certs, trusted_ca_cert_count) }?;
    Ok(TzapX509TrustOptions {
        trusted_ca_certificates: trusted_ca_certs.into_iter().map(PathBuf::from).collect(),
        trusted_system_roots,
        include_official_tzap_root: !has_explicit_roots,
    })
}

fn tzap_default_volume_loss_tolerance(volume_size: u64) -> u8 {
    if volume_size == 0 {
        TZAP_SINGLE_VOLUME_LOSS_TOLERANCE
    } else {
        TZAP_SPLIT_VOLUME_LOSS_TOLERANCE
    }
}

fn archive_plan_options(clean_source: bool, exclude_archive_paths: Vec<String>) -> PlanOptions {
    let mut options = if clean_source {
        PlanOptions::clean_source()
    } else {
        PlanOptions::default()
    };
    options.exclude_archive_paths = exclude_archive_paths;
    options
}

fn create_self_signed_tzap_identity(
    identity_path: &Path,
    public_certificate_path: Option<&Path>,
    common_name: &str,
    password: &SecretString,
) -> Result<Value, String> {
    let key = PKey::from_rsa(
        Rsa::generate(SELF_SIGNED_IDENTITY_RSA_BITS)
            .map_err(|source| format!("could not generate signing key: {source}"))?,
    )
    .map_err(|source| format!("could not prepare signing key: {source}"))?;
    let certificate = create_self_signed_certificate(common_name, &key)?;
    let identity = Pkcs12::builder()
        .name(common_name)
        .pkey(&key)
        .cert(&certificate)
        .build2(password.expose_secret())
        .map_err(|source| format!("could not create PKCS#12 identity: {source}"))?;

    write_output_file(
        identity_path,
        &identity
            .to_der()
            .map_err(|source| format!("could not encode PKCS#12 identity: {source}"))?,
    )?;
    if let Some(path) = public_certificate_path {
        write_output_file(
            path,
            &certificate
                .to_pem()
                .map_err(|source| format!("could not encode public certificate: {source}"))?,
        )?;
    }

    x509_certificate_summary_json(&certificate)
}

fn create_self_signed_certificate(common_name: &str, key: &PKey<Private>) -> Result<X509, String> {
    let mut name = X509NameBuilder::new()
        .map_err(|source| format!("could not create certificate name: {source}"))?;
    name.append_entry_by_text("CN", common_name)
        .map_err(|source| format!("could not set certificate name: {source}"))?;
    let name = name.build();

    let mut builder =
        X509::builder().map_err(|source| format!("could not create certificate: {source}"))?;
    builder
        .set_version(2)
        .map_err(|source| format!("could not set certificate version: {source}"))?;
    let serial = random_certificate_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|source| format!("could not set certificate serial number: {source}"))?;
    builder
        .set_subject_name(&name)
        .map_err(|source| format!("could not set certificate subject: {source}"))?;
    builder
        .set_issuer_name(&name)
        .map_err(|source| format!("could not set certificate issuer: {source}"))?;
    builder
        .set_pubkey(key)
        .map_err(|source| format!("could not set certificate public key: {source}"))?;
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|source| format!("could not set certificate start date: {source}"))?;
    builder
        .set_not_before(&not_before)
        .map_err(|source| format!("could not set certificate start date: {source}"))?;
    let not_after = Asn1Time::days_from_now(SELF_SIGNED_IDENTITY_VALID_DAYS)
        .map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder
        .set_not_after(&not_after)
        .map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(|source| format!("could not set certificate constraints: {source}"))?,
        )
        .map_err(|source| format!("could not set certificate constraints: {source}"))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|source| format!("could not set certificate key usage: {source}"))?,
        )
        .map_err(|source| format!("could not set certificate key usage: {source}"))?;
    builder
        .sign(key, MessageDigest::sha256())
        .map_err(|source| format!("could not sign certificate: {source}"))?;

    Ok(builder.build())
}

fn random_certificate_serial() -> Result<Asn1Integer, String> {
    let mut serial =
        BigNum::new().map_err(|source| format!("could not create serial number: {source}"))?;
    serial
        .rand(
            SELF_SIGNED_IDENTITY_SERIAL_BITS,
            MsbOption::MAYBE_ZERO,
            false,
        )
        .map_err(|source| format!("could not create serial number: {source}"))?;
    serial
        .to_asn1_integer()
        .map_err(|source| format!("could not encode serial number: {source}"))
}

fn x509_certificate_summary_json(certificate: &X509) -> Result<Value, String> {
    let fingerprint = certificate
        .digest(MessageDigest::sha256())
        .map_err(|source| format!("could not fingerprint certificate: {source}"))?;
    let serial_number = certificate
        .serial_number()
        .to_bn()
        .map_err(|source| format!("could not read certificate serial number: {source}"))?
        .to_hex_str()
        .map_err(|source| format!("could not encode certificate serial number: {source}"))?
        .to_string();

    Ok(json!({
        "subject": x509_name_to_string(certificate.subject_name()),
        "issuer": x509_name_to_string(certificate.issuer_name()),
        "serial_number": serial_number,
        "certificate_sha256": hex_lower(fingerprint.as_ref()),
        "not_before": certificate.not_before().to_string(),
        "not_after": certificate.not_after().to_string(),
    }))
}

fn write_output_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|source| format!("could not create {}: {source}", parent.display()))?;
    }

    fs::write(path, bytes).map_err(|source| format!("could not write {}: {source}", path.display()))
}

fn start_archive_create_many_with_options_job(
    out_job: *mut *mut ZManagerFfiJob,
    sources: Vec<String>,
    destination: String,
    clean_source: bool,
    exclude_archive_paths: Vec<String>,
    create_options: FfiCreateOptions,
) -> ZManagerFfiStatus {
    let sources = sources.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let destination = PathBuf::from(destination);

    spawn_archive_job(out_job, move |thread_token, sink| {
        let plan_options = archive_plan_options(clean_source, exclude_archive_paths);
        match create_options {
            FfiCreateOptions::TarZst(options) => {
                let _ = zmanager_core::jobs::run_tar_zst_create_job_from_sources_with_plan_options(
                    &sources,
                    destination,
                    &options,
                    &plan_options,
                    &thread_token,
                    sink,
                );
            }
            FfiCreateOptions::Zip(options) => {
                let _ = zmanager_core::jobs::run_zip_create_job_from_sources_with_plan_options(
                    &sources,
                    destination,
                    &options,
                    &plan_options,
                    &thread_token,
                    sink,
                );
            }
            FfiCreateOptions::SevenZ(options) => {
                let _ = zmanager_core::jobs::run_7z_create_job_from_sources_with_plan_options(
                    &sources,
                    destination,
                    &options,
                    &plan_options,
                    &thread_token,
                    sink,
                );
            }
            FfiCreateOptions::Tzap(options) => {
                let _ = zmanager_core::jobs::run_tzap_create_job_from_sources_with_plan_options(
                    &sources,
                    destination,
                    &options,
                    &plan_options,
                    &thread_token,
                    sink,
                );
            }
        }
    })
}

fn ffi_status_json(status: ZManagerFfiStatus) -> String {
    ffi_error_json(match status {
        ZManagerFfiStatus::Ok => "ok",
        ZManagerFfiStatus::NullArgument => "null argument",
        ZManagerFfiStatus::InvalidUtf8 => "invalid UTF-8 argument",
        ZManagerFfiStatus::InvalidArgument => "invalid argument",
    })
}

enum FfiCreateOptions {
    TarZst(TarZstdCreateOptions),
    Zip(ZipCreateOptions),
    SevenZ(SevenZCreateOptions),
    Tzap(TzapCreateOptions),
}

struct FfiCreateRequest {
    archive_format: FfiArchiveFormat,
    password: Option<SecretString>,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: u64,
    tzap_recovery_percentage: u8,
    tzap_volume_loss_tolerance: u8,
    tzap_x509_signing: Option<TzapX509SigningOptions>,
}

fn ffi_archive_format(value: i32) -> Option<FfiArchiveFormat> {
    match value {
        ARCHIVE_FORMAT_TAR_ZST => Some(FfiArchiveFormat::TarZst),
        ARCHIVE_FORMAT_ZIP => Some(FfiArchiveFormat::Zip),
        ARCHIVE_FORMAT_SEVENZ => Some(FfiArchiveFormat::SevenZ),
        ARCHIVE_FORMAT_TZAP => Some(FfiArchiveFormat::Tzap),
        _ => None,
    }
}

fn optional_password_arg(
    password: *const c_char,
) -> Result<Option<SecretString>, ZManagerFfiStatus> {
    if password.is_null() {
        return Ok(None);
    }

    let Some(password) = c_string_arg(password) else {
        return Err(ZManagerFfiStatus::InvalidUtf8);
    };
    if password.is_empty() {
        return Ok(None);
    }

    Ok(Some(SecretString::from(password)))
}

fn pkcs12_password_arg(password: *const c_char) -> Result<SecretString, ZManagerFfiStatus> {
    if password.is_null() {
        return Ok(SecretString::from(""));
    }

    let Some(password) = c_string_arg(password) else {
        return Err(ZManagerFfiStatus::InvalidUtf8);
    };

    Ok(SecretString::from(password))
}

unsafe fn optional_password_string_arg(
    password: *const c_char,
) -> Result<Option<String>, &'static str> {
    if password.is_null() {
        return Ok(None);
    }

    let Some(password) = c_string_arg(password) else {
        return Err("invalid UTF-8 password");
    };
    if password.is_empty() {
        return Ok(None);
    }

    Ok(Some(password))
}

fn ffi_create_options(request: FfiCreateRequest) -> Result<FfiCreateOptions, ZManagerFfiStatus> {
    let volume_size = match request.volume_size {
        0 => None,
        size => Some(size),
    };

    match request.archive_format {
        FfiArchiveFormat::TarZst => {
            if request.password.is_some() {
                return Err(ZManagerFfiStatus::InvalidArgument);
            }
            if request.tzap_x509_signing.is_some() {
                return Err(ZManagerFfiStatus::InvalidArgument);
            }
            if volume_size.is_some() {
                return Err(ZManagerFfiStatus::InvalidArgument);
            }
            tar_zst_create_options(request.compression_level, request.replace_existing)
                .map(FfiCreateOptions::TarZst)
        }
        FfiArchiveFormat::Zip => {
            if request.tzap_x509_signing.is_some() {
                return Err(ZManagerFfiStatus::InvalidArgument);
            }
            zip_create_options(
                request.password,
                request.compression_level,
                request.replace_existing,
                volume_size,
            )
            .map(FfiCreateOptions::Zip)
        }
        FfiArchiveFormat::SevenZ => {
            if request.tzap_x509_signing.is_some() {
                return Err(ZManagerFfiStatus::InvalidArgument);
            }
            sevenz_create_options(
                request.password,
                request.compression_level,
                request.replace_existing,
                request.encrypt_file_names,
                volume_size,
            )
            .map(FfiCreateOptions::SevenZ)
        }
        FfiArchiveFormat::Tzap => tzap_create_options(
            request.password,
            request.compression_level,
            request.replace_existing,
            volume_size,
            request.tzap_recovery_percentage,
            request.tzap_volume_loss_tolerance,
            request.tzap_x509_signing,
        )
        .map(FfiCreateOptions::Tzap),
    }
}

fn tzap_create_options(
    password: Option<SecretString>,
    compression_level: i32,
    replace_existing: bool,
    volume_size: Option<u64>,
    recovery_percentage: u8,
    volume_loss_tolerance: u8,
    x509_signing: Option<TzapX509SigningOptions>,
) -> Result<TzapCreateOptions, ZManagerFfiStatus> {
    let level = match compression_level {
        DEFAULT_COMPRESSION_LEVEL_SENTINEL => None,
        level if (TZAP_MIN_COMPRESSION_LEVEL..=TZAP_MAX_COMPRESSION_LEVEL).contains(&level) => {
            Some(level)
        }
        _ => return Err(ZManagerFfiStatus::InvalidArgument),
    };

    if recovery_percentage > TZAP_MAX_RECOVERY_PERCENTAGE {
        return Err(ZManagerFfiStatus::InvalidArgument);
    }
    if volume_size.is_none() && volume_loss_tolerance != 0 {
        return Err(ZManagerFfiStatus::InvalidArgument);
    }

    Ok(TzapCreateOptions {
        key_source: password.map_or(TzapKeySource::NoPassword, TzapKeySource::Passphrase),
        level: level.unwrap_or(TZAP_DEFAULT_COMPRESSION_LEVEL),
        preserve_metadata: true,
        replace_existing,
        volume_size,
        recovery_percentage,
        volume_loss_tolerance,
        x509_signing,
    })
}

fn zip_create_options(
    password: Option<SecretString>,
    compression_level: i32,
    replace_existing: bool,
    volume_size: Option<u64>,
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
        volume_size,
    })
}

fn tar_zst_create_options(
    compression_level: i32,
    replace_existing: bool,
) -> Result<TarZstdCreateOptions, ZManagerFfiStatus> {
    let mut options = TarZstdCreateOptions {
        replace_existing,
        ..TarZstdCreateOptions::default()
    };
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

fn sevenz_create_options(
    password: Option<SecretString>,
    compression_level: i32,
    replace_existing: bool,
    encrypt_file_names: bool,
    volume_size: Option<u64>,
) -> Result<SevenZCreateOptions, ZManagerFfiStatus> {
    let level = match compression_level {
        DEFAULT_COMPRESSION_LEVEL_SENTINEL => None,
        level if (SEVENZ_MIN_COMPRESSION_LEVEL..=SEVENZ_MAX_COMPRESSION_LEVEL).contains(&level) => {
            Some(u32::try_from(level).map_err(|_| ZManagerFfiStatus::InvalidArgument)?)
        }
        _ => return Err(ZManagerFfiStatus::InvalidArgument),
    };

    Ok(SevenZCreateOptions {
        solid: true,
        level,
        preserve_metadata: true,
        password,
        encrypt_file_names,
        replace_existing,
        volume_size,
        ..SevenZCreateOptions::default()
    })
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

fn progress_path_identity_hex(identity: &[u8; 32]) -> String {
    identity.iter().map(|byte| format!("{byte:02x}")).collect()
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
            recent_paths,
            recent_path_identities,
            bytes,
            total_bytes_processed,
            entries,
            total_entries_processed,
            recent_paths_truncated,
        } => json!({
            "type": "bytes_processed",
            "path": path,
            "recent_paths": recent_paths,
            "recent_path_identities": recent_path_identities.iter().map(progress_path_identity_hex).collect::<Vec<_>>(),
            "bytes": bytes,
            "total_bytes_processed": total_bytes_processed,
            "entries": entries,
            "total_entries_processed": total_entries_processed,
            "recent_paths_truncated": recent_paths_truncated,
        }),
        JobEvent::PhaseStarted { phase, total_bytes } => json!({
            "type": "phase_started",
            "phase": job_phase_name(*phase),
            "total_bytes": total_bytes,
        }),
        JobEvent::PhaseBytesProcessed {
            phase,
            path,
            recent_paths,
            recent_path_identities,
            bytes,
            total_bytes_processed,
            total_bytes,
            recent_paths_truncated,
        } => json!({
            "type": "phase_bytes_processed",
            "phase": job_phase_name(*phase),
            "path": path,
            "recent_paths": recent_paths,
            "recent_path_identities": recent_path_identities.iter().map(progress_path_identity_hex).collect::<Vec<_>>(),
            "bytes": bytes,
            "total_bytes_processed": total_bytes_processed,
            "total_bytes": total_bytes,
            "recent_paths_truncated": recent_paths_truncated,
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

fn tzap_public_metadata_json(
    summary: &zmanager_core::tzap_backend::TzapPublicMetadataSummary,
) -> Value {
    let volumes = summary
        .volumes
        .iter()
        .map(|volume| {
            json!({
                "index": volume.index,
                "path": volume.path.display().to_string(),
                "size": volume.size,
            })
        })
        .collect::<Vec<_>>();
    let format = &summary.format;

    json!({
        "requested_path": summary.requested_path.display().to_string(),
        "expected_volume_count": summary.expected_volume_count,
        "present_volume_count": summary.present_volume_count,
        "missing_volume_indices": &summary.missing_volume_indices,
        "total_size": summary.total_size,
        "expected_volume_size": summary.expected_volume_size,
        "volumes": volumes,
        "format": {
            "format_version": format.format_version,
            "volume_format_revision": format.volume_format_revision,
            "archive_uuid": hex_lower(&format.archive_uuid),
            "session_id": hex_lower(&format.session_id),
            "compression_algorithm": format.compression_algorithm,
            "encryption_algorithm": format.encryption_algorithm,
            "recovery_algorithm": format.recovery_algorithm,
            "key_derivation": format.key_derivation,
            "password_required": format.password_required,
            "bit_rot_buffer_percentage": format.bit_rot_buffer_percentage,
            "volume_loss_tolerance": format.volume_loss_tolerance,
            "data_shard_count": format.data_shard_count,
            "parity_shard_count": format.parity_shard_count,
            "index_data_shard_count": format.index_data_shard_count,
            "index_parity_shard_count": format.index_parity_shard_count,
            "index_root_data_shard_count": format.index_root_data_shard_count,
            "index_root_parity_shard_count": format.index_root_parity_shard_count,
            "block_size": format.block_size,
            "chunk_size": format.chunk_size,
            "envelope_target_size": format.envelope_target_size,
            "has_dictionary": format.has_dictionary,
        },
    })
}

fn tzap_x509_root_auth_json(
    report: &zmanager_core::tzap_backend::TzapX509VerificationReport,
) -> Value {
    let status = report
        .diagnostics
        .first()
        .map_or("root_auth_content_verified", String::as_str);
    json!({
        "status": status,
        "diagnostics": &report.diagnostics,
        "authenticator": "x509",
        "archive_root": hex_lower(&report.archive_root),
        "authenticator_id": report.authenticator_id,
        "signer_identity_type": report.signer_identity_type,
        "total_data_block_count": report.total_data_block_count,
        "signature_verified": true,
        "trust_validated": true,
        "subject": report.subject,
        "issuer": report.issuer,
        "serial_number": report.serial_number_hex,
        "certificate_sha256": hex_lower(&report.certificate_sha256),
        "signed_at_unix_seconds": report.signed_at_unix_seconds,
        "verified_chain_subjects": report.verified_chain_subjects,
        "trust_anchor_subject": report.trust_anchor_subject,
    })
}

fn tzap_x509_signer_inspection_json(
    report: &zmanager_core::tzap_backend::TzapX509SignerInspection,
) -> Value {
    let status = report
        .diagnostics
        .first()
        .map_or("root_auth_signer_inspected", String::as_str);
    json!({
        "status": status,
        "diagnostics": &report.diagnostics,
        "authenticator": "x509",
        "archive_root": hex_lower(&report.archive_root),
        "authenticator_id": report.authenticator_id,
        "signer_identity_type": report.signer_identity_type,
        "total_data_block_count": report.total_data_block_count,
        "signature_verified": true,
        "trust_validated": false,
        "subject": report.subject,
        "issuer": report.issuer,
        "serial_number": report.serial_number_hex,
        "certificate_sha256": hex_lower(&report.certificate_sha256),
        "signed_at_unix_seconds": report.signed_at_unix_seconds,
        "verified_chain_subjects": [],
        "trust_anchor_subject": Value::Null,
    })
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

fn extraction_policy_with_mode(
    overwrite_mode: u32,
    strip_components: usize,
) -> Result<ExtractionPolicy, ()> {
    let Some(overwrite) = overwrite_policy_from_mode(overwrite_mode) else {
        return Err(());
    };

    Ok(ExtractionPolicy {
        overwrite,
        strip_components,
        ..ExtractionPolicy::default()
    })
}

fn overwrite_policy_from_mode(overwrite_mode: u32) -> Option<OverwritePolicy> {
    match overwrite_mode {
        OVERWRITE_MODE_REFUSE => Some(OverwritePolicy::Refuse),
        OVERWRITE_MODE_REPLACE => Some(OverwritePolicy::Replace),
        OVERWRITE_MODE_RENAME => Some(OverwritePolicy::Rename),
        _ => None,
    }
}

fn overwrite_mode_from_replace_existing(replace_existing: bool) -> u32 {
    if replace_existing {
        OVERWRITE_MODE_REPLACE
    } else {
        OVERWRITE_MODE_REFUSE
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
        JobKind::TzapCreate => "tzap_create",
        JobKind::TzapExtract => "tzap_extract",
        JobKind::AppleArchiveCreate => "aar_create",
        JobKind::AppleArchiveExtract => "aar_extract",
        JobKind::ArchiveExtract => "archive_extract",
        JobKind::RawStreamExtract => "raw_stream_extract",
    }
}

fn job_phase_name(phase: JobPhase) -> &'static str {
    match phase {
        JobPhase::PlanningPayload => "planning_payload",
        JobPhase::PlanningMetadata => "planning_metadata",
        JobPhase::EmittingPayload => "emitting_payload",
        JobPhase::EmittingMetadata => "emitting_metadata",
        JobPhase::CommittingOutput => "committing_output",
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

fn is_tzap_archive(path: &std::path::Path) -> bool {
    zmanager_core::tzap_backend::is_tzap_archive_path(path)
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
        ZManagerFfiJob, ZManagerFfiStatus, zmanager_ffi_create_tzap_self_signed_identity,
        zmanager_ffi_extract_archive_entry, zmanager_ffi_extract_archive_entry_with_options,
        zmanager_ffi_extract_archive_entry_with_policy, zmanager_ffi_job_free,
        zmanager_ffi_job_is_finished, zmanager_ffi_list_archive,
        zmanager_ffi_list_archive_with_options, zmanager_ffi_plan_archive,
        zmanager_ffi_plan_clean_source, zmanager_ffi_poll_events,
        zmanager_ffi_preview_archive_entry, zmanager_ffi_preview_archive_entry_with_options,
        zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options,
        zmanager_ffi_start_archive_create_many_with_exclusions_and_options,
        zmanager_ffi_start_archive_create_many_with_options,
        zmanager_ffi_start_clean_source_create, zmanager_ffi_start_clean_source_create_many,
        zmanager_ffi_start_clean_source_create_many_with_options,
        zmanager_ffi_start_extract_archive, zmanager_ffi_start_extract_archive_with_options,
        zmanager_ffi_start_extract_archive_with_policy, zmanager_ffi_start_zip_create,
        zmanager_ffi_start_zip_create_encrypted, zmanager_ffi_start_zip_create_many,
        zmanager_ffi_start_zip_create_many_with_options, zmanager_ffi_string_free,
        zmanager_ffi_tzap_public_metadata_summary,
    };
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::ptr;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use zmanager_core::safety::ExtractionPolicy;
    use zmanager_core::tzap_backend::TzapX509SigningOptions;

    const TEST_ARCHIVE_FORMAT_TAR_ZST: i32 = super::ARCHIVE_FORMAT_TAR_ZST;
    const TEST_ARCHIVE_FORMAT_ZIP: i32 = super::ARCHIVE_FORMAT_ZIP;
    const TEST_ARCHIVE_FORMAT_SEVENZ: i32 = super::ARCHIVE_FORMAT_SEVENZ;
    const TEST_ARCHIVE_FORMAT_TZAP: i32 = super::ARCHIVE_FORMAT_TZAP;
    const TEST_7Z_VOLUME_SIZE: u64 = 1_048_576;
    const TEST_JOB_POLL_ATTEMPTS: usize = 1_000;
    const TEST_JOB_POLL_INTERVAL: Duration = Duration::from_millis(10);

    #[test]
    fn ffi_serializes_phase_progress_events() {
        use zmanager_core::jobs::{JobEvent, JobPhase};

        let generic = super::event_to_json_value(&JobEvent::BytesProcessed {
            path: Some("payload/current.bin".to_owned()),
            recent_paths: vec![
                "payload/previous.bin".to_owned(),
                "payload/current.bin".to_owned(),
            ],
            recent_path_identities: vec![[1; 32], [2; 32]],
            bytes: 512,
            total_bytes_processed: 1024,
            entries: 1,
            total_entries_processed: 2,
            recent_paths_truncated: false,
        });
        assert_eq!(generic["type"], "bytes_processed");
        assert_eq!(generic["path"], "payload/current.bin");
        assert_eq!(generic["recent_paths"][0], "payload/previous.bin");
        assert_eq!(generic["recent_paths"][1], "payload/current.bin");

        let started = super::event_to_json_value(&JobEvent::PhaseStarted {
            phase: JobPhase::PlanningPayload,
            total_bytes: Some(1024),
        });
        assert_eq!(started["type"], "phase_started");
        assert_eq!(started["phase"], "planning_payload");
        assert_eq!(started["total_bytes"], 1024);

        let processed = super::event_to_json_value(&JobEvent::PhaseBytesProcessed {
            phase: JobPhase::EmittingPayload,
            path: Some("payload/file.bin".to_owned()),
            recent_paths: vec![
                "payload/previous.bin".to_owned(),
                "payload/file.bin".to_owned(),
            ],
            recent_path_identities: vec![[1; 32], [2; 32]],
            bytes: 256,
            total_bytes_processed: 768,
            total_bytes: Some(1024),
            recent_paths_truncated: false,
        });
        assert_eq!(processed["type"], "phase_bytes_processed");
        assert_eq!(processed["phase"], "emitting_payload");
        assert_eq!(processed["path"], "payload/file.bin");
        assert_eq!(processed["recent_paths"][0], "payload/previous.bin");
        assert_eq!(processed["recent_paths"][1], "payload/file.bin");
        assert_eq!(processed["bytes"], 256);
        assert_eq!(processed["total_bytes_processed"], 768);
        assert_eq!(processed["total_bytes"], 1024);
    }

    #[test]
    fn ffi_tzap_routing_recognizes_numbered_volumes() {
        assert!(super::is_tzap_archive(Path::new("project.tzap")));
        assert!(super::is_tzap_archive(Path::new("project.vol000.tzap")));
        assert!(super::is_tzap_archive(Path::new("project.vol001.tzap")));

        assert!(!super::is_tzap_archive(Path::new("project.tzap.tmp")));
        assert!(!super::is_tzap_archive(Path::new("project.zip.000")));
    }

    #[test]
    fn ffi_default_tzap_volume_loss_tolerance_matches_split_shape() {
        assert_eq!(super::tzap_default_volume_loss_tolerance(0), 0);
        assert_eq!(
            super::tzap_default_volume_loss_tolerance(10 * 1024 * 1024),
            1
        );
    }

    #[test]
    fn c_abi_create_tzap_self_signed_identity_writes_pkcs12_and_public_cert() {
        let temp = test_root("zmanager-ffi-self-signed-identity");
        fs::create_dir_all(&temp).unwrap();
        let identity_path = temp.join("signer.p12");
        let cert_path = temp.join("signer.pem");
        let identity = CString::new(identity_path.to_string_lossy().as_ref()).unwrap();
        let cert = CString::new(cert_path.to_string_lossy().as_ref()).unwrap();
        let common_name = CString::new("Local Signing Identity").unwrap();
        let password = CString::new("identity password").unwrap();

        let response = c_string(unsafe {
            zmanager_ffi_create_tzap_self_signed_identity(
                identity.as_ptr(),
                cert.as_ptr(),
                common_name.as_ptr(),
                password.as_ptr(),
            )
        });

        let response_json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response_json["ok"], true);
        assert_eq!(
            response_json["certificate"]["subject"],
            "CN=Local Signing Identity"
        );
        assert_eq!(
            response_json["certificate"]["issuer"],
            "CN=Local Signing Identity"
        );
        assert!(response_json["certificate"]["serial_number"].is_string());
        assert_eq!(
            response_json["certificate"]["certificate_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert!(identity_path.exists());
        assert!(cert_path.exists());

        let parsed_identity = openssl::pkcs12::Pkcs12::from_der(&fs::read(&identity_path).unwrap())
            .unwrap()
            .parse2("identity password")
            .unwrap();
        let identity_cert = parsed_identity.cert.unwrap();
        let public_cert = openssl::x509::X509::from_pem(&fs::read(&cert_path).unwrap()).unwrap();
        assert_eq!(
            identity_cert
                .subject_name()
                .entries()
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap(),
            "Local Signing Identity"
        );
        assert_eq!(
            identity_cert.to_der().unwrap(),
            public_cert.to_der().unwrap()
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn ffi_tzap_signing_identity_args_accept_one_identity_shape() {
        let cert = CString::new("/tmp/signer.pem").unwrap();
        let key = CString::new("/tmp/signer.key").unwrap();
        let chain = CString::new("/tmp/intermediate.pem").unwrap();
        let identity = CString::new("/tmp/signer.p12").unwrap();
        let identity_password = CString::new("identity password").unwrap();
        let chain_paths = [chain.as_ptr()];

        let pkcs12 = unsafe {
            super::optional_tzap_x509_signing_identity_arg(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                identity.as_ptr(),
                identity_password.as_ptr(),
            )
        }
        .unwrap()
        .unwrap();
        match pkcs12 {
            TzapX509SigningOptions::Pkcs12 { identity, password } => {
                assert_eq!(identity, PathBuf::from("/tmp/signer.p12"));
                assert_eq!(password.expose_secret(), "identity password");
            }
            TzapX509SigningOptions::CertificateAndKey { .. } => {
                panic!("expected PKCS#12 identity")
            }
        }

        let advanced = unsafe {
            super::optional_tzap_x509_signing_identity_arg(
                cert.as_ptr(),
                key.as_ptr(),
                chain_paths.as_ptr(),
                chain_paths.len(),
                ptr::null(),
                ptr::null(),
            )
        }
        .unwrap()
        .unwrap();
        match advanced {
            TzapX509SigningOptions::CertificateAndKey {
                signing_certificate,
                signing_private_key,
                signing_chain,
            } => {
                assert_eq!(signing_certificate, PathBuf::from("/tmp/signer.pem"));
                assert_eq!(signing_private_key, PathBuf::from("/tmp/signer.key"));
                assert_eq!(signing_chain, vec![PathBuf::from("/tmp/intermediate.pem")]);
            }
            TzapX509SigningOptions::Pkcs12 { .. } => {
                panic!("expected certificate and key identity")
            }
        }

        let both = unsafe {
            super::optional_tzap_x509_signing_identity_arg(
                cert.as_ptr(),
                key.as_ptr(),
                ptr::null(),
                0,
                identity.as_ptr(),
                ptr::null(),
            )
        };
        assert_eq!(both, Err(ZManagerFfiStatus::InvalidArgument));

        let password_only = unsafe {
            super::optional_tzap_x509_signing_identity_arg(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                identity_password.as_ptr(),
            )
        };
        assert_eq!(password_only, Err(ZManagerFfiStatus::InvalidArgument));
    }

    #[test]
    fn c_abi_list_split_tzap_uses_tzap_backend_route() {
        let temp = test_root("zmanager-ffi-split-tzap-list-route");
        fs::create_dir_all(&temp).unwrap();
        let archive = temp.join("project.vol000.tzap");
        fs::write(&archive, b"not a real tzap volume").unwrap();
        let archive = CString::new(archive.to_string_lossy().as_ref()).unwrap();

        // SAFETY: the archive path C string lives for the duration of the call,
        // and a null password is valid for password-aware listing.
        let raw = unsafe { zmanager_ffi_list_archive_with_options(archive.as_ptr(), ptr::null()) };
        assert!(!raw.is_null());
        // SAFETY: FFI returns a NUL-terminated string allocated by this crate.
        let response = unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `raw` was allocated by this crate and has not been freed yet.
        unsafe {
            zmanager_ffi_string_free(raw);
        }
        fs::remove_dir_all(temp).unwrap();

        assert!(
            response.contains("TZAP browser operation failed"),
            "{response}"
        );
        assert!(!response.contains("libarchive"), "{response}");
    }

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
        for _ in 0..TEST_JOB_POLL_ATTEMPTS {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(TEST_JOB_POLL_INTERVAL);
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
        assert!(plan.contains("\"excluded_bytes\":0"));

        // SAFETY: `source` is a valid C string for the duration of the call.
        let raw_default_plan = unsafe { zmanager_ffi_plan_archive(source.as_ptr(), false) };
        let default_plan = c_string(raw_default_plan);
        assert!(default_plan.contains("\"ok\":true"));
        assert!(default_plan.contains("\"excluded_entries\":0"));
        assert!(default_plan.contains("\"excluded_bytes\":0"));

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
        for _ in 0..TEST_JOB_POLL_ATTEMPTS {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(TEST_JOB_POLL_INTERVAL);
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
    fn c_abi_generic_create_many_applies_clean_source_to_zip() {
        let temp = test_root("zmanager-ffi-generic-clean-zip");
        fs::create_dir_all(temp.join("project/node_modules/pkg")).unwrap();
        fs::write(temp.join("project/src.txt"), b"keep").unwrap();
        fs::write(temp.join("project/node_modules/pkg/index.js"), b"drop").unwrap();
        let source = CString::new(temp.join("project").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("project.clean.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_ZIP,
                true,
                ptr::null(),
                1,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"zip_create\""));
        assert!(!events.contains("node_modules"));

        let listing = zmanager_core::zip_backend::list_zip(temp.join("project.clean.zip")).unwrap();
        let paths = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["project/", "project/src.txt"]);
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_creates_encrypted_7z() {
        let temp = test_root("zmanager-ffi-generic-7z");
        fs::create_dir_all(temp.join("project")).unwrap();
        fs::write(temp.join("project/secret.txt"), b"secret").unwrap();
        let source = CString::new(temp.join("project").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination = CString::new(temp.join("project.7z").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("correct horse").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source, destination, and password C strings live for the
        // duration of the call, and `job` is valid writable storage for the
        // out pointer.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_SEVENZ,
                false,
                password.as_ptr(),
                5,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"7z_create\""));
        assert!(events.contains("\"type\":\"completed\""));

        assert!(matches!(
            zmanager_core::sevenz_backend::extract_7z(
                temp.join("project.7z"),
                temp.join("missing-password-out"),
                None,
                ExtractionPolicy::default(),
            ),
            Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired
                | zmanager_core::sevenz_backend::SevenZError::InvalidPassword)
        ));
        zmanager_core::sevenz_backend::extract_7z(
            temp.join("project.7z"),
            temp.join("out"),
            Some("correct horse"),
            ExtractionPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(temp.join("out/project/secret.txt")).unwrap(),
            "secret"
        );
        zmanager_core::sevenz_backend::list_7z(temp.join("project.7z"), Some("correct horse"))
            .unwrap();
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_creates_split_7z_volumes() {
        let temp = test_root("zmanager-ffi-generic-split-7z");
        fs::create_dir_all(temp.join("project")).unwrap();
        fs::write(
            temp.join("project/blob.bin"),
            deterministic_bytes(3 * 1024 * 1024),
        )
        .unwrap();
        let source = CString::new(temp.join("project").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination = CString::new(temp.join("project.7z").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, `job` is valid writable storage, and null exclusions are valid
        // with a zero count.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_SEVENZ,
                false,
                ptr::null(),
                1,
                false,
                true,
                TEST_7Z_VOLUME_SIZE,
                ptr::null(),
                0,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"7z_create\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert!(!temp.join("project.7z").exists());
        assert_eq!(
            fs::metadata(temp.join("project.7z.001")).unwrap().len(),
            TEST_7Z_VOLUME_SIZE
        );
        assert!(temp.join("project.7z.002").exists());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_creates_split_zip_volumes() {
        let temp = test_root("zmanager-ffi-generic-zip-volume-size");
        fs::create_dir_all(temp.join("project")).unwrap();
        fs::write(
            temp.join("project/blob.bin"),
            deterministic_bytes(3 * 1024 * 1024),
        )
        .unwrap();
        let source = CString::new(temp.join("project").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination =
            CString::new(temp.join("project.zip").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, `job` is valid writable storage, and null exclusions are valid
        // with a zero count.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_ZIP,
                false,
                ptr::null(),
                super::ZIP_STORE_COMPRESSION_LEVEL,
                false,
                false,
                TEST_7Z_VOLUME_SIZE,
                ptr::null(),
                0,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"zip_create\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert!(temp.join("project.z01").exists());
        assert!(temp.join("project.zip").exists());
        assert_eq!(
            fs::metadata(temp.join("project.z01")).unwrap().len(),
            TEST_7Z_VOLUME_SIZE
        );
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_can_leave_7z_file_names_visible() {
        let temp = test_root("zmanager-ffi-generic-7z-visible-names");
        fs::create_dir_all(temp.join("project")).unwrap();
        fs::write(temp.join("project/secret.txt"), b"secret").unwrap();
        let source = CString::new(temp.join("project").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination = CString::new(temp.join("project.7z").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("correct horse").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source, destination, and password C strings live for the
        // duration of the call, and `job` is valid writable storage for the
        // out pointer. Null exclusions are valid with a zero count.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_exclusions_and_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_SEVENZ,
                false,
                password.as_ptr(),
                5,
                false,
                false,
                ptr::null(),
                0,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"7z_create\""));
        assert!(events.contains("\"type\":\"completed\""));

        let listing =
            zmanager_core::sevenz_backend::list_7z(temp.join("project.7z"), None).unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == "project/secret.txt")
        );
        assert!(matches!(
            zmanager_core::sevenz_backend::extract_7z(
                temp.join("project.7z"),
                temp.join("missing-password-out"),
                None,
                ExtractionPolicy::default(),
            ),
            Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired
                | zmanager_core::sevenz_backend::SevenZError::InvalidPassword)
        ));
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_rejects_tar_zst_password() {
        let temp = test_root("zmanager-ffi-generic-tzst-password");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("file.txt"), b"payload").unwrap();
        let source = CString::new(temp.join("file.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination = CString::new(temp.join("file.tzst").to_string_lossy().as_ref()).unwrap();
        let password = CString::new("not supported").unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source, destination, and password C strings live for the
        // duration of the call, and `job` is valid writable storage for the
        // out pointer.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_TAR_ZST,
                false,
                password.as_ptr(),
                1,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::InvalidArgument);
        assert!(job.is_null());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn c_abi_generic_create_many_creates_unencrypted_tzap_without_password() {
        let temp = test_root("zmanager-ffi-generic-tzap-unencrypted");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("file.txt"), b"payload").unwrap();
        let source = CString::new(temp.join("file.txt").to_string_lossy().as_ref()).unwrap();
        let sources = [source.as_ptr()];
        let destination = CString::new(temp.join("file.tzap").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: source and destination C strings live for the duration of the
        // call, and `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_archive_create_many_with_options(
                sources.as_ptr(),
                sources.len(),
                destination.as_ptr(),
                TEST_ARCHIVE_FORMAT_TZAP,
                false,
                ptr::null(),
                1,
                false,
                &raw mut job,
            )
        };

        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""), "{events}");

        let listing = c_string(unsafe { zmanager_ffi_list_archive(destination.as_ptr()) });
        assert!(listing.contains("\"ok\":true"), "{listing}");
        assert!(listing.contains("\"path\":\"file.txt\""), "{listing}");

        let summary =
            c_string(unsafe { zmanager_ffi_tzap_public_metadata_summary(destination.as_ptr()) });
        assert!(summary.contains("\"ok\":true"), "{summary}");
        assert!(summary.contains("\"expected_volume_count\":1"), "{summary}");
        assert!(summary.contains("\"present_volume_count\":1"), "{summary}");
        assert!(summary.contains("\"password_required\":false"), "{summary}");
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
        for _ in 0..TEST_JOB_POLL_ATTEMPTS {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(TEST_JOB_POLL_INTERVAL);
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
    fn c_abi_archive_browser_previews_encrypted_zip_entry_with_password() {
        let temp = test_root("zmanager-ffi-browser-encrypted-preview");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret preview").unwrap();
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
        let entry = CString::new("payload/file.txt").unwrap();

        // SAFETY: all C strings are valid for the duration of the call.
        let missing_password = c_string(unsafe {
            zmanager_ffi_preview_archive_entry(archive.as_ptr(), entry.as_ptr())
        });
        assert!(missing_password.contains("\"ok\":false"));
        assert!(missing_password.to_lowercase().contains("password"));

        let password = CString::new("correct horse").unwrap();
        // SAFETY: all C strings are valid for the duration of the call.
        let preview = c_string(unsafe {
            zmanager_ffi_preview_archive_entry_with_options(
                archive.as_ptr(),
                entry.as_ptr(),
                password.as_ptr(),
            )
        });
        assert!(preview.contains("\"ok\":true"));
        let cleanup_root = json_string_field(&preview, "cleanup_root").unwrap();
        let preview_path = json_string_field(&preview, "preview_path").unwrap();
        assert_eq!(fs::read_to_string(&preview_path).unwrap(), "secret preview");
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
        for _ in 0..TEST_JOB_POLL_ATTEMPTS {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(TEST_JOB_POLL_INTERVAL);
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
    fn c_abi_lists_and_extracts_raw_bzip2_stream() {
        const RAW_BZIP2_PAYLOAD: &[u8] = &[
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x60, 0x95, 0x84, 0xfa,
            0x00, 0x00, 0x04, 0x11, 0x80, 0x40, 0x00, 0x24, 0x04, 0xd0, 0xa0, 0x20, 0x00, 0x31,
            0x06, 0x4c, 0x41, 0x00, 0xd3, 0xd2, 0x08, 0x13, 0x63, 0xd8, 0xf1, 0x77, 0x24, 0x53,
            0x85, 0x09, 0x06, 0x09, 0x58, 0x4f, 0xa0,
        ];
        let temp = test_root("zmanager-ffi-raw-bzip2");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("payload.txt.bz2"), RAW_BZIP2_PAYLOAD).unwrap();

        let archive =
            CString::new(temp.join("payload.txt.bz2").to_string_lossy().as_ref()).unwrap();
        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();

        // SAFETY: `archive` is a valid C string for the duration of the call.
        let listing = c_string(unsafe { zmanager_ffi_list_archive(archive.as_ptr()) });
        assert!(listing.contains("\"ok\":true"));
        assert!(listing.contains("\"path\":\"payload.txt\""));

        let mut job: *mut ZManagerFfiJob = ptr::null_mut();
        // SAFETY: the C strings live for the duration of the call and
        // `job` is valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive(archive.as_ptr(), destination.as_ptr(), &raw mut job)
        };
        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"raw_stream_extract\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("out/payload.txt")).unwrap(),
            "raw payload"
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
    fn c_abi_extract_archive_policy_strips_components_and_renames_conflicts() {
        let temp = test_root("zmanager-ffi-extract-policy");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"policy").unwrap();
        zmanager_core::zip_backend::create_zip_from_path(
            temp.join("payload"),
            temp.join("archive.zip"),
            &zmanager_core::zip_backend::ZipCreateOptions::default(),
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.zip").to_string_lossy().as_ref()).unwrap();
        let destination = temp.join("selected");
        fs::create_dir_all(&destination).unwrap();
        fs::write(destination.join("file.txt"), b"old").unwrap();
        let destination = CString::new(destination.to_string_lossy().as_ref()).unwrap();
        let entry = CString::new("payload/file.txt").unwrap();

        // SAFETY: all C strings are valid for the duration of the call.
        let selected = c_string(unsafe {
            zmanager_ffi_extract_archive_entry_with_policy(
                archive.as_ptr(),
                entry.as_ptr(),
                destination.as_ptr(),
                ptr::null(),
                super::OVERWRITE_MODE_RENAME,
                1,
            )
        });
        assert!(selected.contains("\"ok\":true"));
        assert_eq!(
            fs::read_to_string(temp.join("selected/file 2.txt")).unwrap(),
            "policy"
        );
        assert!(!temp.join("selected/payload/file.txt").exists());

        let all_destination = CString::new(temp.join("all").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();
        // SAFETY: the C strings live for the duration of the call and `job` is
        // valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive_with_policy(
                archive.as_ptr(),
                all_destination.as_ptr(),
                ptr::null(),
                super::OVERWRITE_MODE_RENAME,
                1,
                &raw mut job,
            )
        };
        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());
        let events = drain_job(job);
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            fs::read_to_string(temp.join("all/file.txt")).unwrap(),
            "policy"
        );
        assert!(!temp.join("all/payload/file.txt").exists());
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
    fn c_abi_list_archive_options_read_encrypted_7z_headers() {
        let temp = test_root("zmanager-ffi-list-7z-options");
        fs::create_dir_all(temp.join("payload")).unwrap();
        fs::write(temp.join("payload/file.txt"), b"secret 7z").unwrap();
        zmanager_core::sevenz_backend::create_7z_from_path(
            temp.join("payload"),
            temp.join("archive.7z"),
            &zmanager_core::sevenz_backend::SevenZCreateOptions {
                password: Some(zmanager_core::secrets::SecretString::from("correct horse")),
                encrypt_file_names: true,
                ..zmanager_core::sevenz_backend::SevenZCreateOptions::default()
            },
        )
        .unwrap();

        let archive = CString::new(temp.join("archive.7z").to_string_lossy().as_ref()).unwrap();
        let without_password = c_string(unsafe { zmanager_ffi_list_archive(archive.as_ptr()) });
        assert!(without_password.contains("\"ok\":false"));
        assert!(without_password.to_lowercase().contains("password"));

        let password = CString::new("correct horse").unwrap();
        let with_password = c_string(unsafe {
            zmanager_ffi_list_archive_with_options(archive.as_ptr(), password.as_ptr())
        });
        assert!(with_password.contains("\"ok\":true"));
        assert!(with_password.contains("payload/file.txt"));

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

    #[test]
    fn c_abi_extract_archive_uses_libarchive_for_unencrypted_split_rar_when_available() {
        let Some(rar) = find_on_path("rar") else {
            return;
        };
        let temp = test_root("zmanager-ffi-extract-split-rar");
        fs::create_dir_all(temp.join("source/project")).unwrap();
        fs::write(temp.join("source/project/file.txt"), b"absolute split rar").unwrap();
        fs::write(
            temp.join("source/project/big.bin"),
            deterministic_bytes(16 * 1024),
        )
        .unwrap();

        let archive_base = temp.join("archive.rar");
        let create = Command::new(rar)
            .current_dir(&temp)
            .arg("a")
            .arg("-idq")
            .arg("-ma5")
            .arg("-v4k")
            .arg(&archive_base)
            .arg(temp.join("source/project"))
            .output()
            .unwrap();
        assert!(
            create.status.success(),
            "rar create failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        );

        let first_part = temp.join("archive.part1.rar");
        assert!(first_part.exists());
        let archive = CString::new(first_part.to_string_lossy().as_ref()).unwrap();
        let destination = CString::new(temp.join("out").to_string_lossy().as_ref()).unwrap();
        let mut job: *mut ZManagerFfiJob = ptr::null_mut();

        // SAFETY: the C strings live for the duration of the call and `job` is
        // valid writable storage for the out pointer.
        let status = unsafe {
            zmanager_ffi_start_extract_archive_with_policy(
                archive.as_ptr(),
                destination.as_ptr(),
                ptr::null(),
                super::OVERWRITE_MODE_RENAME,
                0,
                &raw mut job,
            )
        };
        assert_eq!(status, ZManagerFfiStatus::Ok);
        assert!(!job.is_null());

        let events = drain_job(job);
        assert!(events.contains("\"kind\":\"archive_extract\""));
        assert!(events.contains("\"type\":\"completed\""));
        assert_eq!(
            find_file_contents(&temp.join("out"), "file.txt").as_deref(),
            Some("absolute split rar")
        );

        fs::remove_dir_all(temp).unwrap();
    }

    fn drain_job(job: *mut ZManagerFfiJob) -> String {
        let mut events = String::new();
        for _ in 0..TEST_JOB_POLL_ATTEMPTS {
            let chunk = poll_events(job);
            events.push_str(&chunk);
            if zmanager_ffi_job_is_finished(job) && chunk == "[]" {
                break;
            }
            thread::sleep(TEST_JOB_POLL_INTERVAL);
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

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_9abc_def0_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
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

    fn find_file_contents(root: &Path, file_name: &str) -> Option<String> {
        for entry in fs::read_dir(root).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(contents) = find_file_contents(&path, file_name) {
                    return Some(contents);
                }
            } else if path.file_name().and_then(|name| name.to_str()) == Some(file_name) {
                return fs::read_to_string(path).ok();
            }
        }
        None
    }
}
