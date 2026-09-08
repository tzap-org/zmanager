//! Hosted-auth session storage and pending-handoff persistence (CR-136,
//! CR-113).
//!
//! Single implementation of TZAP auth state: the OS-keyring-backed session
//! and pending-handoff records in production keyring builds, the legacy
//! atomic files in reduced/non-keyring builds, and the shared state-directory
//! default. Both the JSON service (`tzap_service`) and the CLI use these.

use crate::auth_client::TzapSessionStore;
#[cfg(feature = "keyring")]
use crate::identity_catalog::TzapSecretMaterialStore;
#[cfg(feature = "keyring")]
use crate::keyring_store::NativeTzapSecretStore;
use crate::trust;
use crate::tzap_service::{request_string, request_u64, required_request_string};
#[cfg(not(feature = "keyring"))]
use crate::write_atomic_secret_file;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";

pub struct TzapFfiSessionStore {
    #[cfg(feature = "keyring")]
    inner: NativeTzapSecretStore,
    #[cfg(not(feature = "keyring"))]
    path: PathBuf,
}

impl TzapFfiSessionStore {
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        #[cfg(feature = "keyring")]
        {
            let mut store = Self { inner: NativeTzapSecretStore::default() };
            store.migrate_legacy_session(state_dir);
            store
        }
        #[cfg(not(feature = "keyring"))]
        {
            Self { path: state_dir.join(AUTH_SESSION_FILE) }
        }
    }

    #[cfg(feature = "keyring")]
    fn migrate_legacy_session(&mut self, state_dir: &Path) {
        let path = state_dir.join(AUTH_SESSION_FILE);
        let Some(root) = read_json_file(&path) else { return };
        let Some(sessions) = root.get("sessions").and_then(Value::as_object) else { return };
        let mut migrated = true;
        for (account_key, value) in sessions {
            let Ok(session) = session_from_json(value) else {
                migrated = false;
                break;
            };
            if self.inner.save_session(account_key, session).is_err() {
                migrated = false;
                break;
            }
        }
        if migrated {
            let _ = fs::remove_file(path);
        }
    }
}

impl TzapSessionStore for TzapFfiSessionStore {
    fn save_session(&mut self, account_key: &str, session: crate::auth_client::TzapSessionRecord) -> Result<(), crate::auth_client::TzapAuthError> {
        #[cfg(feature = "keyring")]
        {
            self.inner.save_session(account_key, session)
        }
        #[cfg(not(feature = "keyring"))]
        {
            let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
            if !root.is_object() {
                root = json!({ "sessions": {} });
            }
            root["sessions"][account_key] = session_json(&session, true);
            write_secret_json_file(&self.path, &root)
                .map_err(|error| crate::auth_client::TzapAuthError::Storage { message: format!("could not write {}: {error}", self.path.display()) })
        }
    }

    fn load_session(&self, account_key: &str) -> Option<crate::auth_client::TzapSessionRecord> {
        #[cfg(feature = "keyring")]
        {
            self.inner.load_session(account_key)
        }
        #[cfg(not(feature = "keyring"))]
        {
            let root = read_json_file(&self.path)?;
            session_from_json(root.get("sessions")?.get(account_key)?).ok()
        }
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), crate::auth_client::TzapAuthError> {
        #[cfg(feature = "keyring")]
        {
            self.inner.clear_session(account_key)
        }
        #[cfg(not(feature = "keyring"))]
        {
            let Some(mut root) = read_json_file(&self.path) else {
                return Ok(());
            };
            if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
                sessions.remove(account_key);
            }
            write_secret_json_file(&self.path, &root)
                .map_err(|error| crate::auth_client::TzapAuthError::Storage { message: format!("could not write {}: {error}", self.path.display()) })
        }
    }
}

pub fn parse_auth_environment(value: &str) -> Result<crate::auth_client::TzapHostedAuthEnvironment, String> {
    match value {
        "local" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Local),
        "staging" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Staging),
        "prod" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Prod),
        _ => Err("environment must be local, staging, or prod".to_owned()),
    }
}

/// Default TZAP state directory (CR-113: the CLI's `ZM_TZAP_STATE_DIR` is
/// honored first, then the legacy `ZMANAGER_TZAP_STATE_DIR`, then the home
/// fallback, so both CLI and FFI consumers keep working).
#[must_use]
pub fn default_tzap_state_dir() -> PathBuf {
    for variable in ["ZM_TZAP_STATE_DIR", "ZMANAGER_TZAP_STATE_DIR"] {
        if let Some(path) = std::env::var_os(variable)
            && !path.is_empty()
        {
            return PathBuf::from(path);
        }
    }
    std::env::var_os("HOME").map_or_else(|| PathBuf::from(".").join(".zmanager").join("tzap"), |home| PathBuf::from(home).join(".zmanager").join("tzap"))
}

pub(crate) fn current_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(not(feature = "keyring"))]
fn write_secret_json_file(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_atomic_secret_file(path, &bytes)
}

/// Persists the pending handoff; the login metadata (`client_id`,
/// `auth_base_url`) lets the callback exchange a handoff code without the
/// caller repeating the login options (CR-113: adopted from the CLI).
pub fn save_pending_auth(
    state_dir: &Path,
    pending: &crate::auth_client::TzapPendingAuthState,
    config: &crate::auth_client::TzapHostedAuthLaunchConfig,
) -> std::io::Result<()> {
    #[cfg(feature = "keyring")]
    {
        let mut store = NativeTzapSecretStore::default();
        let reference = crate::keyring_store::pending_auth_reference();
        let value = json!({
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "pkce_verifier": pending.pkce.verifier,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
            "client_id": config.client_id,
            "auth_base_url": config.hosted_auth_base_url,
            "requested_audience": config.requested_audience,
        });
        let bytes = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
        store
            .put_at(crate::identity_catalog::TzapSecretPurpose::Session, &reference, crate::secrets::SecretBytes::from(bytes))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let _ = state_dir;
        Ok(())
    }
    #[cfg(not(feature = "keyring"))]
    {
        write_secret_json_file(
            &state_dir.join(AUTH_PENDING_FILE),
            &json!({
                "state": pending.state,
                "provider_id": pending.provider_id,
                "redirect_uri": pending.redirect_uri,
                "pkce_verifier": pending.pkce.verifier,
                "created_at_unix_seconds": pending.created_at_unix_seconds,
                "client_id": config.client_id,
                "auth_base_url": config.hosted_auth_base_url,
                "requested_audience": config.requested_audience,
            }),
        )
    }
}

#[derive(Debug, Default)]
pub struct TzapPendingAuthMetadata {
    pub client_id: Option<String>,
    pub auth_base_url: Option<String>,
    pub requested_audience: Option<String>,
}

#[must_use]
pub fn load_pending_auth_metadata(state_dir: &Path) -> TzapPendingAuthMetadata {
    let Some(value) = pending_auth_json(state_dir) else {
        return TzapPendingAuthMetadata::default();
    };
    TzapPendingAuthMetadata {
        client_id: request_string(&value, "client_id").ok().flatten(),
        auth_base_url: request_string(&value, "auth_base_url").ok().flatten(),
        requested_audience: request_string(&value, "requested_audience").ok().flatten(),
    }
}

pub fn load_pending_auth(state_dir: &Path) -> Result<crate::auth_client::TzapPendingAuthState, String> {
    let value = pending_auth_json(state_dir).ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
    let parsed = (|| {
        let verifier = required_request_string(&value, "pkce_verifier")?;
        let pkce = crate::auth_client::TzapPkcePair::from_verifier(&verifier).map_err(|error| error.to_string())?;
        Ok(crate::auth_client::TzapPendingAuthState {
            state: required_request_string(&value, "state")?,
            provider_id: required_request_string(&value, "provider_id")?,
            redirect_uri: required_request_string(&value, "redirect_uri")?,
            pkce,
            created_at_unix_seconds: request_u64(&value, "created_at_unix_seconds")?
                .ok_or_else(|| "missing or invalid field: created_at_unix_seconds".to_owned())?,
        })
    })();
    if parsed.is_err() {
        // A malformed handoff must not remain replayable or repeatedly break
        // future callbacks. Preserve no private material in the error path.
        let _ = clear_pending_auth(state_dir);
    }
    parsed
}

/// Clears the pending handoff from the same backend used by
/// `save_pending_auth`.
pub fn clear_pending_auth(state_dir: &Path) -> std::io::Result<()> {
    #[cfg(feature = "keyring")]
    {
        let mut store = NativeTzapSecretStore::default();
        let reference = crate::keyring_store::pending_auth_reference();
        store.delete(crate::identity_catalog::TzapSecretPurpose::Session, &reference).map_err(|error| std::io::Error::other(error.to_string()))?;
        match fs::remove_file(state_dir.join(AUTH_PENDING_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
    #[cfg(not(feature = "keyring"))]
    {
        match fs::remove_file(state_dir.join(AUTH_PENDING_FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn pending_auth_json(state_dir: &Path) -> Option<Value> {
    #[cfg(feature = "keyring")]
    {
        let store = NativeTzapSecretStore::new("default").ok()?;
        let reference = crate::keyring_store::pending_auth_reference();
        if let Ok(bytes) = store.resolve(crate::identity_catalog::TzapSecretPurpose::Session, &reference) {
            return serde_json::from_slice(bytes.expose_secret()).ok();
        }
        read_json_file(&state_dir.join(AUTH_PENDING_FILE))
    }
    #[cfg(not(feature = "keyring"))]
    {
        read_json_file(&state_dir.join(AUTH_PENDING_FILE))
    }
}

#[cfg(not(feature = "keyring"))]
fn session_json(session: &crate::auth_client::TzapSessionRecord, include_token: bool) -> Value {
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

pub(crate) fn session_summary_json(session: &crate::auth_client::TzapSessionRecord) -> Value {
    session_summary_json_at(session, current_unix_seconds())
}

pub(crate) fn session_summary_json_at(session: &crate::auth_client::TzapSessionRecord, now_unix_seconds: u64) -> Value {
    json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "expired": session.is_expired_at(now_unix_seconds),
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    })
}

fn session_from_json(value: &Value) -> Result<crate::auth_client::TzapSessionRecord, String> {
    let assurance = required_request_string(value, "identity_assurance")?;
    let identity_assurance = trust::TzapIdentityAssurance::parse(&assurance).ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(crate::auth_client::TzapSessionRecord {
        audience: required_request_string(value, "audience")?,
        access_token: crate::auth_client::TzapBearerToken::new(required_request_string(value, "access_token")?).map_err(|error| error.to_string())?,
        expires_at_unix_seconds: request_u64(value, "expires_at_unix_seconds")?
            .ok_or_else(|| "missing or invalid field: expires_at_unix_seconds".to_owned())?,
        identity_assurance,
        selected_org_id: request_string(value, "selected_org_id")?,
        login_session_id: request_string(value, "login_session_id")?,
    })
}
