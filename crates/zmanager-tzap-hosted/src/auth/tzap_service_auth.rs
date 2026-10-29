//! Hosted-auth session storage and shared state-directory defaults.
//!
//! Pending logins use `auth_flow_store` exclusively. Legacy global keyring
//! pending records and verifier-bearing files are never imported into it.

use crate::auth_client::TzapSessionStore;
#[cfg(all(feature = "keyring", not(test)))]
use crate::keyring_store::NativeTzapSecretStore;
#[cfg(any(not(feature = "keyring"), test))]
use crate::write_atomic_secret_file;
use serde_json::{Value, json};
#[cfg(any(not(feature = "keyring"), test))]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(not(feature = "keyring"), test))]
const AUTH_SESSION_FILE: &str = "auth-session.json";

pub struct TzapFfiSessionStore {
    #[cfg(all(feature = "keyring", not(test)))]
    inner: NativeTzapSecretStore,
    #[cfg(any(not(feature = "keyring"), test))]
    path: PathBuf,
}

impl TzapFfiSessionStore {
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        #[cfg(all(feature = "keyring", not(test)))]
        {
            // Legacy sessions have no issuer/principal proof. Never import
            // them over the shared native slot; require fresh authentication.
            let _ = state_dir;
            Self { inner: NativeTzapSecretStore::default() }
        }
        #[cfg(any(not(feature = "keyring"), test))]
        {
            Self { path: state_dir.join(AUTH_SESSION_FILE) }
        }
    }
}

impl TzapSessionStore for TzapFfiSessionStore {
    fn save_session(&mut self, account_key: &str, session: crate::auth_client::TzapSessionRecord) -> Result<(), crate::auth_client::TzapAuthError> {
        #[cfg(all(feature = "keyring", not(test)))]
        {
            self.inner.save_session(account_key, session)
        }
        #[cfg(any(not(feature = "keyring"), test))]
        {
            let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
            if !root.is_object() {
                root = json!({ "sessions": {} });
            }
            root["sessions"][account_key] = session.to_secure_json();
            write_secret_json_file(&self.path, &root)
                .map_err(|error| crate::auth_client::TzapAuthError::Storage { message: format!("could not write {}: {error}", self.path.display()) })
        }
    }

    fn load_session(&self, account_key: &str) -> Option<crate::auth_client::TzapSessionRecord> {
        #[cfg(all(feature = "keyring", not(test)))]
        {
            self.inner.load_session(account_key)
        }
        #[cfg(any(not(feature = "keyring"), test))]
        {
            let root = read_json_file(&self.path)?;
            session_from_json(root.get("sessions")?.get(account_key)?).ok()
        }
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), crate::auth_client::TzapAuthError> {
        #[cfg(all(feature = "keyring", not(test)))]
        {
            self.inner.clear_session(account_key)
        }
        #[cfg(any(not(feature = "keyring"), test))]
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

#[cfg(any(not(feature = "keyring"), test))]
fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(any(not(feature = "keyring"), test))]
fn write_secret_json_file(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_atomic_secret_file(path, &bytes)
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

#[cfg(any(not(feature = "keyring"), test))]
fn session_from_json(value: &Value) -> Result<crate::auth_client::TzapSessionRecord, String> {
    crate::auth_client::TzapSessionRecord::from_secure_json(value).map_err(|error| error.to_string())
}
