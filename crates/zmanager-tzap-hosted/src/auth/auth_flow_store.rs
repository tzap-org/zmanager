//! Cross-process ownership and native-secret persistence for a hosted login.
//!
//! The destination session slot is global to the current OS user. Public
//! metadata locates one pending flow; its authoritative binding and verifier
//! live together in a fresh native-secret item, never in a disk fallback.

use crate::auth_client::{AUTH_HANDOFF_LIFETIME_SECONDS, TzapHostedAuthLaunchConfig, TzapPendingAuthState, TzapPkcePair};
use crate::identity_catalog::TzapSecretRef;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};

pub struct TzapAuthSlot {
    lock: File,
    metadata_path: PathBuf,
    state_dir: PathBuf,
    account_key: String,
    secure_scope: String,
    application: String,
}

/// Short ownership guard for mutations of the shared session slot.
/// Uses exactly the same lock as a browser login, without a pending context.
pub struct TzapSessionSlotOwnership {
    lock: File,
    account_key: String,
}

impl TzapSessionSlotOwnership {
    pub fn acquire(account_key: &str, secure_scope: &str) -> Result<Self, String> {
        let (lock, _) = acquire_slot_file(&slot_root()?, account_key, secure_scope)?;
        Ok(Self { lock, account_key: account_key.to_owned() })
    }

    pub fn clear_if_current(
        &self,
        sessions: &mut impl crate::auth_client::TzapSessionStore,
        expected: &crate::auth_client::TzapSessionRecord,
    ) -> Result<bool, crate::auth_client::TzapAuthError> {
        if sessions.load_session(&self.account_key).as_ref() != Some(expected) {
            return Ok(false);
        }
        sessions.clear_session(&self.account_key)?;
        Ok(true)
    }
}

impl Drop for TzapSessionSlotOwnership {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

fn validate_slot_context(account_key: &str, secure_scope: &str) -> Result<(), String> {
    if account_key.is_empty()
        || account_key.contains([':', '/', '\\'])
        || account_key.contains("..")
        || account_key.chars().any(char::is_control)
        || secure_scope.is_empty()
        || secure_scope.len() > 128
        || !secure_scope.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid hosted auth slot".to_owned());
    }
    Ok(())
}

fn acquire_slot_file(root: &Path, account_key: &str, secure_scope: &str) -> Result<(File, PathBuf), String> {
    validate_slot_context(account_key, secure_scope)?;
    fs::create_dir_all(root).map_err(|_| "could not create hosted auth ownership directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|_| "could not protect hosted auth ownership directory")?;
    }
    // Framing avoids concatenation aliases. The fixed service/scope is
    // exactly the one used by the shared native session store.
    let digest = Sha256::digest(format!("org.tzap.zmanager.identity\0{secure_scope}\0{account_key}").as_bytes());
    let stem = crate::x509_format::hex_lower(&digest);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let lock = options.open(root.join(format!("{stem}.lock"))).map_err(|_| "could not open hosted auth ownership lock")?;
    lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => "login_in_progress".to_owned(),
        fs::TryLockError::Error(_) => "could not acquire hosted auth ownership lock".to_owned(),
    })?;
    Ok((lock, root.join(format!("{stem}.json"))))
}

/// Does not implement Debug because `pending` contains the PKCE verifier.
pub struct TzapSavedAuthFlow {
    pub pending: TzapPendingAuthState,
    pub config: TzapHostedAuthLaunchConfig,
    pub flow_id: String,
    pub phase: String,
    reference: TzapSecretRef,
    public_binding: Value,
}

impl TzapAuthSlot {
    /// Locks `(native keyring service/default scope, account_key)`, independent
    /// of the selected state directory, auth server, or application.
    pub fn acquire(state_dir: &Path, account_key: &str, application: &str) -> Result<Self, String> {
        Self::acquire_scoped(state_dir, account_key, application, "default")
    }

    pub fn acquire_scoped(state_dir: &Path, account_key: &str, application: &str, secure_scope: &str) -> Result<Self, String> {
        Self::acquire_scoped_at(&slot_root()?, state_dir, account_key, application, secure_scope)
    }

    #[cfg(test)]
    fn acquire_at(root: &Path, state_dir: &Path, account_key: &str, application: &str) -> Result<Self, String> {
        Self::acquire_scoped_at(root, state_dir, account_key, application, "default")
    }

    fn acquire_scoped_at(root: &Path, state_dir: &Path, account_key: &str, application: &str, secure_scope: &str) -> Result<Self, String> {
        if !matches!(application, "cli" | "desktop") {
            return Err("invalid hosted auth application".to_owned());
        }
        validate_slot_context(account_key, secure_scope)?;
        fs::create_dir_all(state_dir).map_err(|_| "could not create hosted auth state directory")?;
        let state_dir = fs::canonicalize(state_dir).map_err(|_| "could not resolve hosted auth state directory")?;
        let (lock, metadata_path) = acquire_slot_file(root, account_key, secure_scope)?;
        Ok(Self {
            lock,
            metadata_path,
            state_dir,
            account_key: account_key.to_owned(),
            secure_scope: secure_scope.to_owned(),
            application: application.to_owned(),
        })
    }

    pub fn create(&self, pending: &TzapPendingAuthState, config: &TzapHostedAuthLaunchConfig, restart: bool, now: u64) -> Result<TzapSavedAuthFlow, String> {
        config.validate().map_err(|error| error.to_string())?;
        crate::auth_client::validate_oauth_state(&pending.state).map_err(|error| error.to_string())?;
        crate::auth_client::validate_pkce_verifier(&pending.pkce.verifier).map_err(|error| error.to_string())?;
        if pending.redirect_uri != config.redirect_uri
            || crate::auth_client::pkce_s256_challenge(&pending.pkce.verifier) != pending.pkce.challenge
            || now < pending.created_at_unix_seconds
            || now >= pending.created_at_unix_seconds.saturating_add(AUTH_HANDOFF_LIFETIME_SECONDS)
        {
            return Err("invalid pending hosted auth binding".to_owned());
        }
        if let Some(existing) = self.metadata()? {
            let expired = existing.get("expires_at_unix_seconds").and_then(Value::as_u64).is_some_and(|expiry| expiry <= now);
            if !restart && !expired {
                return Err("pending_login_exists; complete the pending login or use --restart".to_owned());
            }
            // The slot lock is held. Explicit restart can discard another
            // application's abandoned record, but can never steal its lock.
            self.clear_metadata_record(&existing)?;
        }
        let reference = TzapSecretRef::generate();
        let flow_id = reference.as_str().to_owned();
        let binding = json!({
            "format_version": 2,
            "application": self.application,
            "account_key": self.account_key,
            "secure_scope": self.secure_scope,
            "state_dir": self.state_dir,
            "flow_id": flow_id,
            "secret_reference": reference.as_str(),
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
            "expires_at_unix_seconds": pending.created_at_unix_seconds.saturating_add(AUTH_HANDOFF_LIFETIME_SECONDS),
            "client_id": config.client_id,
            "auth_base_url": config.hosted_auth_base_url,
            "account_base_url": config.hosted_account_base_url,
            "signing_base_url": config.hosted_signing_base_url,
            "environment": crate::session_provenance::environment_name(config.environment),
            "requested_audience": config.requested_audience,
            "selected_org_id": config.selected_org_id,
            "phase": "pending",
        });
        let flow =
            TzapSavedAuthFlow { pending: pending.clone(), config: config.clone(), flow_id, phase: "pending".to_owned(), reference, public_binding: binding };
        self.persist(&flow, true)?;
        Ok(flow)
    }

    pub fn load(&self) -> Result<TzapSavedAuthFlow, String> {
        let mut binding = self.metadata()?.ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
        if binding.get("format_version").and_then(Value::as_u64) != Some(2)
            || binding["application"] != self.application
            || binding["account_key"] != self.account_key
            || binding["secure_scope"] != self.secure_scope
            || binding["state_dir"] != json!(self.state_dir)
        {
            return Err("pending login belongs to another context; complete it there or restart login explicitly".to_owned());
        }
        let reference = TzapSecretRef::parse(field(&binding, "secret_reference")?).map_err(|_| "invalid pending auth reference")?;
        let secure_bytes = read_secret(&self.secure_scope, &reference)?.ok_or("secure pending auth record is missing")?;
        let mut secure: Value = serde_json::from_slice(&secure_bytes).map_err(|_| "invalid secure pending auth record")?;
        let verifier = field(&secure, "pkce_verifier")?;
        secure.as_object_mut().ok_or("invalid secure pending auth record")?.remove("pkce_verifier");
        if secure != binding {
            // A crash may leave the public phase behind secure intent. Only
            // that monotonic difference is repairable; all routing and owner
            // fields must still match byte-for-byte before exposing a verifier.
            let public_phase = auth_phase_rank(binding["phase"].as_str());
            let secure_phase = auth_phase_rank(secure["phase"].as_str());
            let mut advanced = binding.clone();
            advanced["phase"] = secure["phase"].clone();
            if advanced != secure || !matches!((public_phase, secure_phase), (Some(public), Some(authoritative)) if authoritative > public) {
                return Err("pending auth metadata does not match its secure binding; restart login".to_owned());
            }
            binding = secure;
        }
        let pending = TzapPendingAuthState {
            state: field(&binding, "state")?,
            provider_id: field(&binding, "provider_id")?,
            redirect_uri: field(&binding, "redirect_uri")?,
            pkce: TzapPkcePair::from_verifier(&verifier).map_err(|_| "invalid pending PKCE record")?,
            created_at_unix_seconds: binding["created_at_unix_seconds"].as_u64().ok_or("invalid pending creation time")?,
        };
        let config = TzapHostedAuthLaunchConfig {
            environment: crate::session_provenance::parse_environment(&field(&binding, "environment")?).map_err(|error| error.to_string())?,
            client_id: field(&binding, "client_id")?,
            redirect_uri: pending.redirect_uri.clone(),
            hosted_auth_base_url: field(&binding, "auth_base_url")?,
            hosted_account_base_url: field(&binding, "account_base_url")?,
            hosted_signing_base_url: field(&binding, "signing_base_url")?,
            requested_audience: field(&binding, "requested_audience")?,
            selected_org_id: binding["selected_org_id"].as_str().map(str::to_owned),
        };
        Ok(TzapSavedAuthFlow { pending, config, flow_id: field(&binding, "flow_id")?, phase: field(&binding, "phase")?, reference, public_binding: binding })
    }

    pub fn load_optional(&self) -> Result<Option<TzapSavedAuthFlow>, String> {
        if self.metadata()?.is_none() { Ok(None) } else { self.load().map(Some) }
    }

    /// Persist intent before transmitting the one-time code. An interrupted
    /// exchange is never retried automatically, even if the server used it.
    pub fn begin_exchange(&self, flow: &mut TzapSavedAuthFlow) -> Result<(), String> {
        if flow.phase != "pending" {
            return Err("hosted auth exchange already attempted; restart login".to_owned());
        }
        self.require_same_flow(flow)?;
        "exchanging".clone_into(&mut flow.phase);
        flow.public_binding["phase"] = json!(flow.phase);
        self.persist(flow, false)
    }

    pub fn clear(&self, flow: &TzapSavedAuthFlow) -> Result<(), String> {
        self.require_same_flow(flow)?;
        self.clear_metadata_record(&flow.public_binding)
    }

    pub fn mark_persisted(&self, flow: &mut TzapSavedAuthFlow) -> Result<(), String> {
        self.require_same_flow(flow)?;
        if flow.phase == "persisted" {
            return Ok(());
        }
        if flow.phase != "exchanging" {
            return Err("hosted auth flow is not exchanging".to_owned());
        }
        "persisted".clone_into(&mut flow.phase);
        flow.public_binding["phase"] = json!(flow.phase);
        self.persist(flow, false)
    }

    pub fn recover_committed_session(
        &self,
        flow: &TzapSavedAuthFlow,
        sessions: &impl crate::auth_client::TzapSessionStore,
        now: u64,
    ) -> Result<Option<crate::auth_client::TzapSessionRecord>, String> {
        if flow.phase == "pending" {
            return Ok(None);
        }
        if !matches!(flow.phase.as_str(), "exchanging" | "persisted") {
            return Err("invalid pending hosted auth phase".to_owned());
        }
        self.require_same_flow(flow)?;
        let expected = crate::session_provenance::TzapSessionProvenance::from_launch(&flow.config, &flow.flow_id).map_err(|error| error.to_string())?;
        let session = sessions.load_session(&self.account_key).ok_or("hosted auth exchange outcome is uncertain; restart login")?;
        if session.require_hosted_provenance().map_err(|error| error.to_string())? != &expected
            || session.audience != flow.config.requested_audience
            || session.is_expired_at(now)
        {
            return Err("no valid session commit for this hosted auth flow; restart login".to_owned());
        }
        Ok(Some(session))
    }

    fn require_same_flow(&self, flow: &TzapSavedAuthFlow) -> Result<(), String> {
        let current = self.metadata()?.ok_or("pending hosted auth flow no longer exists")?;
        if current["flow_id"] != flow.flow_id || current["secret_reference"] != flow.reference.as_str() {
            return Err("pending hosted auth flow was replaced".to_owned());
        }
        Ok(())
    }

    fn persist(&self, flow: &TzapSavedAuthFlow, creating: bool) -> Result<(), String> {
        let metadata = serde_json::to_vec(&flow.public_binding).map_err(|_| "could not encode pending auth")?;
        if metadata.len() > 32768 {
            return Err("pending auth metadata is too large".to_owned());
        }
        let mut secure = flow.public_binding.clone();
        secure["pkce_verifier"] = json!(flow.pending.pkce.verifier);
        let bytes = serde_json::to_vec(&secure).map_err(|_| "could not encode secure pending auth")?;
        let publish_metadata =
            || zmanager_core::write_atomic_secret_file(&self.metadata_path, &metadata).map_err(|_| "could not persist pending auth metadata".to_owned());
        if creating {
            // Track the random reference before creating a secret. A crash
            // here leaves a repairable pointer, never an untracked verifier.
            publish_metadata()?;
        }
        write_secret(&self.secure_scope, &flow.reference, &bytes)?;
        if !creating {
            // Transitions update secure intent first. A crash leaves the two
            // records unequal, failing closed rather than repeating exchange.
            publish_metadata()?;
        }
        Ok(())
    }

    fn clear_metadata_record(&self, binding: &Value) -> Result<(), String> {
        let reference = TzapSecretRef::parse(field(binding, "secret_reference")?).map_err(|_| "invalid pending auth reference")?;
        if let Some(bytes) = read_secret(&self.secure_scope, &reference)? {
            let secure: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid secure pending auth record")?;
            if secure["account_key"] != self.account_key
                || secure["secure_scope"] != self.secure_scope
                || secure["flow_id"] != binding["flow_id"]
                || secure["secret_reference"] != reference.as_str()
            {
                return Err("pending auth cleanup does not own the secure record".to_owned());
            }
            delete_secret(&self.secure_scope, &reference)?;
        }
        // Missing secret is also safe to finish cleaning: a previous process
        // may have deleted it and crashed before unlinking the public pointer.
        fs::remove_file(&self.metadata_path).map_err(|_| "could not clear pending auth metadata".to_owned())
    }

    fn metadata(&self) -> Result<Option<Value>, String> {
        let file = match File::open(&self.metadata_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("could not read pending auth metadata".to_owned()),
        };
        let mut bytes = Vec::new();
        file.take(32769).read_to_end(&mut bytes).map_err(|_| "could not read pending auth metadata")?;
        if bytes.len() > 32768 {
            return Err("pending auth metadata is too large".to_owned());
        }
        serde_json::from_slice(&bytes).map(Some).map_err(|_| "invalid pending auth metadata".to_owned())
    }
}

impl Drop for TzapAuthSlot {
    fn drop(&mut self) {
        // Do not unlink the lock inode; all processes must lock the same file.
        let _ = self.lock.unlock();
    }
}

fn field(value: &Value, name: &str) -> Result<String, String> {
    value.get(name).and_then(Value::as_str).filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| "invalid pending auth record".to_owned())
}

fn auth_phase_rank(phase: Option<&str>) -> Option<u8> {
    match phase? {
        "pending" => Some(0),
        "exchanging" => Some(1),
        "persisted" => Some(2),
        _ => None,
    }
}

fn slot_root() -> Result<PathBuf, String> {
    #[cfg(test)]
    {
        Ok(std::env::temp_dir().join(format!("zmanager-auth-slot-tests-{}", std::process::id())))
    }
    #[cfg(not(test))]
    {
        #[cfg(windows)]
        let home = std::env::var_os("LOCALAPPDATA");
        #[cfg(not(windows))]
        let home = std::env::var_os("HOME");
        home.filter(|path| !path.is_empty())
            .map(|home| PathBuf::from(home).join(".zmanager").join("auth-slots"))
            .ok_or_else(|| "hosted auth requires a user data directory".to_owned())
    }
}

#[cfg(all(feature = "keyring", not(test)))]
fn write_secret(scope: &str, reference: &TzapSecretRef, bytes: &[u8]) -> Result<(), String> {
    use crate::identity_catalog::{TzapSecretMaterialStore as _, TzapSecretPurpose};
    crate::keyring_store::NativeTzapSecretStore::new(scope)
        .map_err(|_| "invalid native pending auth scope")?
        .put_at(TzapSecretPurpose::Session, reference, crate::secrets::SecretBytes::from(bytes.to_vec()))
        .map_err(|_| "could not save pending auth to native secure storage".to_owned())
}

#[cfg(all(feature = "keyring", not(test)))]
fn read_secret(scope: &str, reference: &TzapSecretRef) -> Result<Option<Vec<u8>>, String> {
    match crate::keyring_store::NativeTzapSecretStore::new(scope)
        .map_err(|_| "invalid native pending auth scope")?
        .resolve_fresh(crate::identity_catalog::TzapSecretPurpose::Session, reference)
    {
        Ok(bytes) => Ok(Some(bytes.expose_secret().to_vec())),
        Err(crate::identity_catalog::TzapSecretStoreError::Missing { .. }) => Ok(None),
        Err(_) => Err("could not read pending auth from native secure storage".to_owned()),
    }
}

#[cfg(all(feature = "keyring", not(test)))]
fn delete_secret(scope: &str, reference: &TzapSecretRef) -> Result<(), String> {
    use crate::identity_catalog::{TzapSecretMaterialStore as _, TzapSecretPurpose};
    crate::keyring_store::NativeTzapSecretStore::new(scope)
        .map_err(|_| "invalid native pending auth scope")?
        .delete(TzapSecretPurpose::Session, reference)
        .map_err(|_| "could not clear native pending auth".to_owned())
}

#[cfg(all(not(feature = "keyring"), not(test)))]
fn write_secret(_: &str, _: &TzapSecretRef, _: &[u8]) -> Result<(), String> {
    Err("hosted auth requires native secure storage in this build".to_owned())
}
#[cfg(all(not(feature = "keyring"), not(test)))]
fn read_secret(_: &str, _: &TzapSecretRef) -> Result<Option<Vec<u8>>, String> {
    Err("hosted auth requires native secure storage in this build".to_owned())
}
#[cfg(all(not(feature = "keyring"), not(test)))]
fn delete_secret(_: &str, _: &TzapSecretRef) -> Result<(), String> {
    Err("hosted auth requires native secure storage in this build".to_owned())
}

#[cfg(test)]
fn test_secrets() -> &'static std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>> = std::sync::OnceLock::new();
    STORE.get_or_init(std::sync::Mutex::default)
}
#[cfg(test)]
fn write_secret(_scope: &str, reference: &TzapSecretRef, bytes: &[u8]) -> Result<(), String> {
    test_secrets().lock().unwrap().insert(reference.as_str().to_owned(), bytes.to_vec());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_client::{TzapHostedAuthEnvironment, TzapOAuthStateTracker};

    fn fixture() -> (PathBuf, TzapPendingAuthState, TzapHostedAuthLaunchConfig) {
        let root = std::env::temp_dir().join(format!("zmanager-auth-slot-fixture-{}", rand::random::<u64>()));
        let config = TzapHostedAuthLaunchConfig::for_environment(TzapHostedAuthEnvironment::Staging, "zmanager-cli", "tzap://auth/callback");
        let pending = TzapOAuthStateTracker::new().begin("hosted", &config.redirect_uri, 100);
        (root, pending, config)
    }

    #[test]
    fn slot_excludes_other_directories_and_applications_but_allows_other_accounts() {
        let (root, _, _) = fixture();
        let lock_root = root.join("locks");
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        assert!(matches!(TzapAuthSlot::acquire_at(&lock_root, &root.join("b"), "one", "desktop"), Err(error) if error == "login_in_progress"));
        let other = TzapAuthSlot::acquire_at(&lock_root, &root.join("b"), "two", "desktop").unwrap();
        drop((slot, other));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detached_flow_keeps_verifier_off_disk_and_requires_explicit_restart() {
        let (root, pending, config) = fixture();
        let lock_root = root.join("locks");
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        let disk = fs::read_to_string(&slot.metadata_path).unwrap();
        assert!(!disk.contains(&pending.pkce.verifier) && !disk.contains("pkce_verifier"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&slot.metadata_path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(slot);
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        assert_eq!(slot.load().unwrap().pending, pending);
        assert!(slot.create(&pending, &config, false, 101).is_err());
        let replacement = slot.create(&pending, &config, true, 101).unwrap();
        assert_ne!(flow.flow_id, replacement.flow_id);
        assert!(slot.clear(&flow).is_err());
        assert_eq!(slot.load().unwrap().flow_id, replacement.flow_id);
        slot.clear(&replacement).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn desktop_restart_replaces_detached_cli_flow_without_stale_cli_cancel_erasing_it() {
        let (root, pending, config) = fixture();
        let lock_root = root.join("locks");
        let cli = TzapAuthSlot::acquire_at(&lock_root, &root.join("cli-state"), "one", "cli").unwrap();
        let cli_flow = cli.create(&pending, &config, false, 100).unwrap();
        drop(cli);

        let desktop = TzapAuthSlot::acquire_at(&lock_root, &root.join("desktop-state"), "one", "desktop").unwrap();
        assert!(desktop.load().is_err(), "Desktop must not read the CLI verifier binding");
        assert!(matches!(desktop.create(&pending, &config, false, 101), Err(error) if error.contains("pending_login_exists")));

        let desktop_flow = desktop.create(&pending, &config, true, 101).unwrap();
        assert_ne!(desktop_flow.flow_id, cli_flow.flow_id);
        drop(desktop);

        // A restarted CLI holding the old flow ID can neither clear nor
        // replace the Desktop flow. Completion/cancellation must compare IDs.
        let cli = TzapAuthSlot::acquire_at(&lock_root, &root.join("cli-state"), "one", "cli").unwrap();
        assert!(cli.clear(&cli_flow).is_err());
        assert!(matches!(cli.create(&pending, &config, false, 102), Err(error) if error.contains("pending_login_exists")));
        drop(cli);

        let desktop = TzapAuthSlot::acquire_at(&lock_root, &root.join("desktop-state"), "one", "desktop").unwrap();
        let restored = desktop.load().unwrap();
        assert_eq!(restored.flow_id, desktop_flow.flow_id);
        desktop.clear(&restored).unwrap();
        drop(desktop);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_context_and_modified_public_origin_cannot_read_verifier() {
        let (root, pending, config) = fixture();
        let lock_root = root.join("locks");
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        drop(slot);
        for (dir, app) in [("b", "cli"), ("a", "desktop")] {
            let wrong = TzapAuthSlot::acquire_at(&lock_root, &root.join(dir), "one", app).unwrap();
            assert!(wrong.load().is_err());
            assert!(wrong.create(&pending, &config, false, 101).is_err());
        }
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        let mut changed = flow.public_binding.clone();
        changed["auth_base_url"] = json!("https://fixture-wrong-origin.invalid");
        fs::write(&slot.metadata_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(slot.load().is_err());
        let fresh = slot.create(&pending, &config, true, 101).unwrap();
        slot.clear(&fresh).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exchange_intent_survives_restart_and_cannot_be_retried() {
        let (root, pending, config) = fixture();
        let lock_root = root.join("locks");
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        let mut flow = slot.create(&pending, &config, false, 100).unwrap();
        slot.begin_exchange(&mut flow).unwrap();
        drop(slot);
        let slot = TzapAuthSlot::acquire_at(&lock_root, &root.join("a"), "one", "cli").unwrap();
        let mut restored = slot.load().unwrap();
        assert_eq!(restored.phase, "exchanging");
        assert!(slot.begin_exchange(&mut restored).is_err());
        slot.clear(&restored).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_owned_slot_lock_blocks_a_separate_process() {
        let (root, _, _) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "slot-lock", "cli").unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "auth_flow_store::tests::slot_lock_child", "--test-threads=1"])
            .env("ZM_AUTH_SLOT_TEST_ROOT", &root)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_finishes_cleanup_after_secure_record_was_already_deleted() {
        let (root, pending, config) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        delete_secret("default", &flow.reference).unwrap();
        assert!(slot.load().is_err());
        let fresh = slot.create(&pending, &config, true, 101).unwrap();
        slot.clear(&fresh).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_initial_metadata_publication_cannot_leave_an_untracked_verifier() {
        let (root, pending, config) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        slot.clear(&flow).unwrap();
        // Make the atomic publication fail at its final destination. Calling
        // the real persistence seam proves the native write never precedes it.
        fs::create_dir(&slot.metadata_path).unwrap();
        assert!(slot.persist(&flow, true).is_err());
        assert!(read_secret("default", &flow.reference).unwrap().is_none());
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_previous_session_cannot_be_mistaken_for_the_current_flow_commit() {
        use crate::auth_client::{InMemoryTzapSessionStore, TzapBearerToken, TzapSessionRecord, TzapSessionStore as _};
        let (root, pending, config) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "cli").unwrap();
        let mut flow = slot.create(&pending, &config, false, 100).unwrap();
        slot.begin_exchange(&mut flow).unwrap();
        let mut session = TzapSessionRecord {
            user_id: Some("user_fixture_one".to_owned()),
            provenance: None,
            audience: "sign.tzap.org".to_owned(),
            access_token: TzapBearerToken::new("fixture-previous-token").unwrap(),
            expires_at_unix_seconds: 2000,
            identity_assurance: crate::trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("fixture-previous-session".to_owned()),
        };
        session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&config, "another-flow").unwrap()).unwrap();
        let mut sessions = InMemoryTzapSessionStore::new();
        sessions.save_session("one", session).unwrap();
        assert!(slot.recover_committed_session(&flow, &sessions, 101).is_err());
        assert!(slot.begin_exchange(&mut flow).is_err());
        assert_eq!(sessions.load_session("one").unwrap().login_session_id.as_deref(), Some("fixture-previous-session"));
        slot.clear(&flow).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_expiry_cannot_delete_a_replacement_and_session_mutations_share_the_login_lock() {
        use crate::auth_client::{InMemoryTzapSessionStore, TzapBearerToken, TzapSessionRecord, TzapSessionStore as _};
        let (root, _, _) = fixture();
        let (lock, _) = acquire_slot_file(&root.join("locks"), "one", "default").unwrap();
        let ownership = TzapSessionSlotOwnership { lock, account_key: "one".to_owned() };
        assert!(matches!(TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "desktop"), Err(error) if error == "login_in_progress"));
        let previous = TzapSessionRecord {
            user_id: Some("user_fixture_one".to_owned()),
            provenance: None,
            audience: "sign.tzap.org".to_owned(),
            access_token: TzapBearerToken::new("fixture-previous-token").unwrap(),
            expires_at_unix_seconds: 2000,
            identity_assurance: crate::trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("fixture-previous-session".to_owned()),
        };
        let mut replacement = previous.clone();
        replacement.access_token = TzapBearerToken::new("fixture-replacement-token").unwrap();
        replacement.login_session_id = Some("fixture-replacement-session".to_owned());
        let mut sessions = InMemoryTzapSessionStore::new();
        sessions.save_session("one", replacement.clone()).unwrap();
        assert!(!ownership.clear_if_current(&mut sessions, &previous).unwrap());
        assert_eq!(sessions.load_session("one"), Some(replacement.clone()));
        assert!(ownership.clear_if_current(&mut sessions, &replacement).unwrap());
        assert!(sessions.load_session("one").is_none());
        drop(ownership);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_phase_publication_preserves_secure_intent_without_allowing_exchange_replay() {
        let (root, pending, config) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        for phase in ["exchanging", "persisted"] {
            // Stop between the two writes in a real transition: secure
            // intent advanced, the public pointer still says pending.
            let mut secure = flow.public_binding.clone();
            secure["phase"] = json!(phase);
            secure["pkce_verifier"] = json!(pending.pkce.verifier);
            write_secret("default", &flow.reference, &serde_json::to_vec(&secure).unwrap()).unwrap();
            let mut restored = slot.load().unwrap();
            assert_eq!(restored.phase, phase);
            assert!(slot.begin_exchange(&mut restored).is_err());
            assert_eq!(restored.config, config);
        }
        let restored = slot.load().unwrap();
        slot.clear(&restored).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_phase_cannot_advance_or_downgrade_secure_authority() {
        let (root, pending, config) = fixture();
        let slot = TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("a"), "one", "cli").unwrap();
        let flow = slot.create(&pending, &config, false, 100).unwrap();
        let mut tampered = flow.public_binding.clone();
        tampered["phase"] = json!("persisted");
        fs::write(&slot.metadata_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(slot.load().is_err());
        slot.clear(&flow).unwrap();
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn slot_lock_child() {
        let Some(root) = std::env::var_os("ZM_AUTH_SLOT_TEST_ROOT") else { return };
        let root = PathBuf::from(root);
        assert!(matches!(TzapAuthSlot::acquire_at(&root.join("locks"), &root.join("b"), "slot-lock", "desktop"), Err(error) if error == "login_in_progress"));
    }
}
#[cfg(test)]
fn read_secret(_scope: &str, reference: &TzapSecretRef) -> Result<Option<Vec<u8>>, String> {
    Ok(test_secrets().lock().unwrap().get(reference.as_str()).cloned())
}
#[cfg(test)]
fn delete_secret(_scope: &str, reference: &TzapSecretRef) -> Result<(), String> {
    test_secrets().lock().unwrap().remove(reference.as_str());
    Ok(())
}
