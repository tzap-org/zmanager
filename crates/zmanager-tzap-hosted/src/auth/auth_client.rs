//! Auth-client primitives for TZAP hosted Auth launch and bootstrap flows.

use crate::http_client::{require_success, send_json_request, trim_trailing_slash};
use crate::trust;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

pub const LOGIN_TZAP_BASE_URL: &str = "https://login.tzap.org";
pub const SIGN_TZAP_BASE_URL: &str = "https://sign.tzap.org";
pub const PROVIDER_DISCOVERY_PATH: &str = "/auth/providers";
pub const HOSTED_AUTH_AUTHORIZE_PATH: &str = "/auth/launch";
pub const HOSTED_ACCOUNT_PATH: &str = "/account";
pub const CURRENT_USER_PATH: &str = "/v1/me";
pub const LOCAL_HOSTED_AUTH_BASE_URL: &str = "http://localhost:8787";
pub const LOCAL_HOSTED_ACCOUNT_BASE_URL: &str = "http://localhost:8787";
pub const STAGING_HOSTED_AUTH_BASE_URL: &str = "https://staging.tzap.org";
pub const STAGING_HOSTED_ACCOUNT_BASE_URL: &str = "https://staging.tzap.org";
pub const PROD_HOSTED_AUTH_BASE_URL: &str = LOGIN_TZAP_BASE_URL;
pub const PROD_HOSTED_ACCOUNT_BASE_URL: &str = "https://account.tzap.org";

pub const PKCE_METHOD_S256: &str = "S256";
pub const PKCE_VERIFIER_RANDOM_BYTES: usize = 32;
pub const PKCE_VERIFIER_MIN_LENGTH: usize = 43;
pub const PKCE_VERIFIER_MAX_LENGTH: usize = 128;
pub const OAUTH_STATE_RANDOM_BYTES: usize = 32;
pub const AUTH_HANDOFF_LIFETIME_SECONDS: u64 = 10 * 60;
pub const SESSION_AUDIENCE_SIGN_TZAP: &str = "sign.tzap.org";
pub const SESSION_AUDIENCE_LOGIN_TZAP: &str = "login.tzap.org";
pub const HOSTED_AUTH_RESPONSE_MODE_RELAY: &str = "native_app_relay";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapHostedAuthEnvironment {
    Local,
    Staging,
    Prod,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapHostedAuthLaunchConfig {
    pub client_id: String,
    pub redirect_uri: String,
    pub hosted_auth_base_url: String,
    pub hosted_account_base_url: String,
    pub requested_audience: String,
    pub selected_org_id: Option<String>,
}

impl TzapHostedAuthLaunchConfig {
    #[must_use]
    pub fn for_environment(environment: TzapHostedAuthEnvironment, client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        let (hosted_auth_base_url, hosted_account_base_url) = match environment {
            TzapHostedAuthEnvironment::Local => (LOCAL_HOSTED_AUTH_BASE_URL, LOCAL_HOSTED_ACCOUNT_BASE_URL),
            TzapHostedAuthEnvironment::Staging => (STAGING_HOSTED_AUTH_BASE_URL, STAGING_HOSTED_ACCOUNT_BASE_URL),
            TzapHostedAuthEnvironment::Prod => (PROD_HOSTED_AUTH_BASE_URL, PROD_HOSTED_ACCOUNT_BASE_URL),
        };
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            hosted_auth_base_url: hosted_auth_base_url.to_owned(),
            hosted_account_base_url: hosted_account_base_url.to_owned(),
            requested_audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            selected_org_id: None,
        }
    }

    pub fn validate(&self) -> Result<(), TzapAuthError> {
        validate_non_empty_config("client_id", &self.client_id)?;
        validate_non_empty_config("redirect_uri", &self.redirect_uri)?;
        validate_non_empty_config("hosted_auth_base_url", &self.hosted_auth_base_url)?;
        validate_non_empty_config("hosted_account_base_url", &self.hosted_account_base_url)?;
        validate_non_empty_config("requested_audience", &self.requested_audience)?;
        Ok(())
    }

    pub fn launch_url(&self, pending: &TzapPendingAuthState) -> Result<String, TzapAuthError> {
        self.validate()?;
        if pending.redirect_uri != self.redirect_uri {
            return Err(TzapAuthError::RedirectUriMismatch);
        }

        let mut query = vec![
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("audience", self.requested_audience.as_str()),
            ("state", pending.state.as_str()),
            ("code_challenge", pending.pkce.challenge.as_str()),
            ("code_challenge_method", pending.pkce.method),
            ("response_mode", HOSTED_AUTH_RESPONSE_MODE_RELAY),
            ("provider_id", pending.provider_id.as_str()),
        ];
        if let Some(selected_org_id) = &self.selected_org_id {
            query.push(("org_id", selected_org_id.as_str()));
        }

        Ok(format!("{}{}?{}", trim_trailing_slash(&self.hosted_auth_base_url), HOSTED_AUTH_AUTHORIZE_PATH, encode_query_pairs(&query)))
    }

    #[must_use]
    pub fn account_url(&self) -> String {
        format!("{}{}", trim_trailing_slash(&self.hosted_account_base_url), HOSTED_ACCOUNT_PATH)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapAuthProviderType {
    Google,
    GitHub,
    EmailOtp,
    PhoneOtp,
    EnterpriseSso,
}

impl TzapAuthProviderType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::EmailOtp => "email_otp",
            Self::PhoneOtp => "phone_otp",
            Self::EnterpriseSso => "enterprise_sso",
        }
    }

    #[must_use]
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "google" => Some(Self::Google),
            "github" => Some(Self::GitHub),
            "email_otp" => Some(Self::EmailOtp),
            "phone_otp" => Some(Self::PhoneOtp),
            "enterprise_sso" => Some(Self::EnterpriseSso),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapDisabledProviderReason {
    NotConfigured,
    TemporarilyUnavailable,
    PolicyDisabled,
}

impl TzapDisabledProviderReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::PolicyDisabled => "policy_disabled",
        }
    }

    #[must_use]
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "not_configured" => Some(Self::NotConfigured),
            "temporarily_unavailable" => Some(Self::TemporarilyUnavailable),
            "policy_disabled" => Some(Self::PolicyDisabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPkcePair {
    pub verifier: String,
    pub challenge: String,
    pub method: &'static str,
}

impl TzapPkcePair {
    #[must_use]
    pub fn generate() -> Self {
        let verifier = random_base64url(PKCE_VERIFIER_RANDOM_BYTES);
        let challenge = pkce_s256_challenge(&verifier);
        Self { verifier, challenge, method: PKCE_METHOD_S256 }
    }

    pub fn from_verifier(verifier: &str) -> Result<Self, TzapAuthError> {
        validate_pkce_verifier(verifier)?;
        Ok(Self { verifier: verifier.to_owned(), challenge: pkce_s256_challenge(verifier), method: PKCE_METHOD_S256 })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPendingAuthState {
    pub state: String,
    pub provider_id: String,
    pub redirect_uri: String,
    pub pkce: TzapPkcePair,
    pub created_at_unix_seconds: u64,
}

#[derive(Default)]
pub struct TzapOAuthStateTracker {
    pending: HashMap<String, TzapPendingAuthState>,
}

impl TzapOAuthStateTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin(&mut self, provider_id: impl Into<String>, redirect_uri: impl Into<String>, created_at_unix_seconds: u64) -> TzapPendingAuthState {
        let provider_id = provider_id.into();
        let redirect_uri = redirect_uri.into();
        loop {
            let state = random_base64url(OAUTH_STATE_RANDOM_BYTES);
            if let std::collections::hash_map::Entry::Vacant(entry) = self.pending.entry(state.clone()) {
                let pending = TzapPendingAuthState {
                    state: state.clone(),
                    provider_id: provider_id.clone(),
                    redirect_uri: redirect_uri.clone(),
                    pkce: TzapPkcePair::generate(),
                    created_at_unix_seconds,
                };
                entry.insert(pending.clone());
                return pending;
            }
        }
    }

    pub fn insert_pending(&mut self, pending: TzapPendingAuthState) -> Result<(), TzapAuthError> {
        if self.pending.contains_key(&pending.state) {
            return Err(TzapAuthError::DuplicateState);
        }
        validate_oauth_state(&pending.state)?;
        validate_pkce_verifier(&pending.pkce.verifier)?;
        self.pending.insert(pending.state.clone(), pending);
        Ok(())
    }

    pub fn consume(&mut self, state: &str) -> Result<TzapPendingAuthState, TzapAuthError> {
        validate_oauth_state(state)?;
        self.pending.remove(state).ok_or(TzapAuthError::UnknownState)
    }

    pub fn consume_handoff(
        &mut self,
        callback: &TzapHostedAuthCallback,
        now_unix_seconds: u64,
        handoff_lifetime_seconds: u64,
    ) -> Result<TzapPendingAuthState, TzapAuthError> {
        reject_url_session_material(callback.callback_url.as_deref())?;
        validate_oauth_state(&callback.state)?;
        let pending = self.pending.get(&callback.state).ok_or(TzapAuthError::UnknownState)?;
        if pending.redirect_uri != callback.redirect_uri {
            return Err(TzapAuthError::RedirectUriMismatch);
        }
        if pending.pkce.verifier != callback.pkce_verifier {
            return Err(TzapAuthError::PkceVerifierMismatch);
        }
        let expires_at = pending.created_at_unix_seconds.saturating_add(handoff_lifetime_seconds);
        if now_unix_seconds > expires_at {
            return Err(TzapAuthError::ExpiredHandoff);
        }
        self.consume(&callback.state)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapHostedAuthCallback {
    pub state: String,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub callback_url: Option<String>,
    /// Rust-internal serialized session handoff envelope. This is never read
    /// from the native callback URL or exposed as a frontend field.
    pub relay_body: Vec<u8>,
}

pub fn complete_hosted_auth_handoff(
    tracker: &mut TzapOAuthStateTracker,
    session_store: &mut impl TzapSessionStore,
    account_key: &str,
    callback: &TzapHostedAuthCallback,
    now_unix_seconds: u64,
) -> Result<TzapSessionRecord, TzapAuthError> {
    complete_hosted_auth_handoff_for_audience(tracker, session_store, account_key, callback, now_unix_seconds, SESSION_AUDIENCE_SIGN_TZAP)
}

pub fn complete_hosted_auth_handoff_for_audience(
    tracker: &mut TzapOAuthStateTracker,
    session_store: &mut impl TzapSessionStore,
    account_key: &str,
    callback: &TzapHostedAuthCallback,
    now_unix_seconds: u64,
    expected_audience: &str,
) -> Result<TzapSessionRecord, TzapAuthError> {
    if !matches!(expected_audience, SESSION_AUDIENCE_SIGN_TZAP | SESSION_AUDIENCE_LOGIN_TZAP) {
        return Err(TzapAuthError::InvalidConfig { field: "expected_audience" });
    }
    tracker.consume_handoff(callback, now_unix_seconds, AUTH_HANDOFF_LIFETIME_SECONDS)?;
    let relay = TzapAuthRelayCompletion::from_json_bytes(&callback.relay_body)?;
    let session = relay.into_session();
    session.require_audience(expected_audience)?;
    session_store.save_session(account_key, session.clone())?;
    Ok(session)
}

#[derive(Clone, Eq, PartialEq)]
pub struct TzapBearerToken(String);

impl TzapBearerToken {
    pub fn new(value: impl Into<String>) -> Result<Self, TzapAuthError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TzapAuthError::EmptyToken);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TzapBearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TzapBearerToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapSessionRecord {
    pub audience: String,
    pub access_token: TzapBearerToken,
    pub expires_at_unix_seconds: u64,
    pub identity_assurance: trust::TzapIdentityAssurance,
    pub selected_org_id: Option<String>,
    pub login_session_id: Option<String>,
}

impl TzapSessionRecord {
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }

    pub fn require_audience(&self, expected: &str) -> Result<(), TzapAuthError> {
        if self.audience == expected { Ok(()) } else { Err(TzapAuthError::AudienceMismatch { expected: expected.to_owned(), actual: self.audience.clone() }) }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthRelayCompletion {
    pub session: TzapSessionRecord,
}

impl TzapAuthRelayCompletion {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TzapAuthError> {
        let value: Value = serde_json::from_slice(bytes).map_err(TzapAuthError::InvalidJson)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &Value) -> Result<Self, TzapAuthError> {
        reject_raw_provider_material(value)?;
        let object = object_at(value, "$")?;
        let status = required_string_field(object, "$", "status")?;
        match status.as_str() {
            "ok" => {
                let session = parse_session_record(required_field(object, "$", "session")?)?;
                Ok(Self { session })
            }
            "denied" => Err(TzapAuthError::DeniedHandoff),
            "expired" => Err(TzapAuthError::ExpiredHandoff),
            "cancelled" => Err(TzapAuthError::CancelledHandoff),
            "failed" => Err(TzapAuthError::FailedHandoff),
            _ => Err(TzapAuthError::InvalidHandoffStatus),
        }
    }

    #[must_use]
    pub fn into_session(self) -> TzapSessionRecord {
        self.session
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapAuthHttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

/// Cooperative cancellation shared by a hosted request and its caller.
#[derive(Clone, Default)]
pub struct TzapAuthCancellation(Arc<AtomicBool>);

impl TzapAuthCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl fmt::Debug for TzapAuthCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TzapAuthCancellation").field("cancelled", &self.is_cancelled()).finish()
    }
}

impl PartialEq for TzapAuthCancellation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for TzapAuthCancellation {}

/// Transport policy carried with every hosted request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthRequestOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_attempts: u8,
    pub retry_backoff: Duration,
    pub cancellation: Option<TzapAuthCancellation>,
}

impl Default for TzapAuthRequestOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_attempts: 3,
            retry_backoff: Duration::from_millis(50),
            cancellation: None,
        }
    }
}

impl TzapAuthRequestOptions {
    #[must_use]
    pub fn should_retry(&self, method: TzapAuthHttpMethod, status_code: u16) -> bool {
        matches!(method, TzapAuthHttpMethod::Get) && self.max_attempts > 1 && (status_code == 429 || (500..=599).contains(&status_code))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthHttpRequest {
    pub method: TzapAuthHttpMethod,
    pub url: String,
    pub bearer_token: Option<TzapBearerToken>,
    pub body: Option<Value>,
    pub options: TzapAuthRequestOptions,
    /// Extra request headers beyond `Authorization`/`Accept`/`Content-Type`
    /// (design need: `If-Match` on the backup PUT endpoints). Header names
    /// are sent verbatim.
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthHttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    /// Response headers, lower-cased names (design need: reading back the
    /// `ETag` version cert-root-server's backup endpoints return).
    pub headers: Vec<(String, String)>,
}

pub trait TzapAuthHttpTransport {
    fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCurrentUser {
    pub display_name: String,
    pub public_signer_id: Option<String>,
    pub assurance_level: Option<trust::TzapIdentityAssurance>,
    pub selected_org_id: Option<String>,
}

impl TzapCurrentUser {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TzapAuthError> {
        let value: Value = serde_json::from_slice(bytes).map_err(TzapAuthError::InvalidJson)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &Value) -> Result<Self, TzapAuthError> {
        reject_raw_provider_material(value)?;
        let object = object_at(value, "$")?;
        Ok(Self {
            display_name: required_string_field(object, "$", "display_name")?,
            public_signer_id: optional_string_field(object, "$", "public_signer_id")?,
            assurance_level: match object.get("assurance_level") {
                Some(Value::Null) | None => None,
                Some(_) => Some(parse_assurance_level(object, "$", "assurance_level")?),
            },
            selected_org_id: optional_string_field(object, "$", "selected_org_id")?,
        })
    }
}

pub fn fetch_current_user(transport: &impl TzapAuthHttpTransport, sign_base_url: &str, session: &TzapSessionRecord) -> Result<TzapCurrentUser, TzapAuthError> {
    fetch_current_user_for_audience(transport, sign_base_url, session, SESSION_AUDIENCE_SIGN_TZAP)
}

pub fn fetch_current_user_for_audience(
    transport: &impl TzapAuthHttpTransport,
    account_base_url: &str,
    session: &TzapSessionRecord,
    expected_audience: &str,
) -> Result<TzapCurrentUser, TzapAuthError> {
    if !matches!(expected_audience, SESSION_AUDIENCE_SIGN_TZAP | SESSION_AUDIENCE_LOGIN_TZAP) {
        return Err(TzapAuthError::InvalidConfig { field: "expected_audience" });
    }
    session.require_audience(expected_audience)?;
    let response = send_json_request(transport, TzapAuthHttpMethod::Get, account_base_url, CURRENT_USER_PATH, Some(session.access_token.clone()), None)?;
    let response = require_success(response, |status_code, _| TzapAuthError::HttpStatus { status_code })?;
    TzapCurrentUser::from_json_bytes(&response.body)
}

pub trait TzapSessionStore {
    fn save_session(&mut self, account_key: &str, session: TzapSessionRecord) -> Result<(), TzapAuthError>;
    fn load_session(&self, account_key: &str) -> Option<TzapSessionRecord>;
    fn clear_session(&mut self, account_key: &str) -> Result<(), TzapAuthError>;
}

#[derive(Default)]
pub struct InMemoryTzapSessionStore {
    sessions: HashMap<String, TzapSessionRecord>,
}

impl InMemoryTzapSessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TzapSessionStore for InMemoryTzapSessionStore {
    fn save_session(&mut self, account_key: &str, session: TzapSessionRecord) -> Result<(), TzapAuthError> {
        self.sessions.insert(account_key.to_owned(), session);
        Ok(())
    }

    fn load_session(&self, account_key: &str) -> Option<TzapSessionRecord> {
        self.sessions.get(account_key).cloned()
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), TzapAuthError> {
        self.sessions.remove(account_key);
        Ok(())
    }
}

#[derive(Debug)]
pub enum TzapAuthError {
    InvalidJson(serde_json::Error),
    ExpectedObject { path: &'static str },
    ExpectedArray { path: &'static str },
    MissingField { path: &'static str, field: &'static str },
    InvalidString { path: &'static str, field: &'static str },
    InvalidBoolean { path: &'static str, field: &'static str },
    InvalidProviderType { provider_id: String, provider_type: String },
    InvalidDisabledReason { provider_id: String, reason: String },
    DisabledProviderHasAuthorizationUrl { provider_id: String },
    EnabledProviderMissingAuthorizationUrl { provider_id: String },
    ProviderDisabled { provider_id: String, reason: Option<TzapDisabledProviderReason> },
    ProviderMissingAuthorizationUrl { provider_id: String },
    InvalidPkceVerifier,
    InvalidState,
    InvalidConfig { field: &'static str },
    DuplicateState,
    UnknownState,
    RedirectUriMismatch,
    PkceVerifierMismatch,
    ExpiredHandoff,
    DeniedHandoff,
    CancelledHandoff,
    FailedHandoff,
    InvalidHandoffStatus,
    SessionTokenInCallbackUrl,
    RawProviderMaterial,
    EmptyToken,
    Cancelled,
    InvalidAssuranceLevel { value: String },
    AudienceMismatch { expected: String, actual: String },
    Transport { message: String },
    Storage { message: String },
    HttpStatus { status_code: u16 },
}

impl fmt::Display for TzapAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "auth JSON is invalid: {err}"),
            Self::ExpectedObject { path } => write!(f, "{path} must be a JSON object"),
            Self::ExpectedArray { path } => write!(f, "{path} must be a JSON array"),
            Self::MissingField { path, field } => write!(f, "{path}.{field} is required"),
            Self::InvalidString { path, field } => {
                write!(f, "{path}.{field} must be a non-empty string")
            }
            Self::InvalidBoolean { path, field } => write!(f, "{path}.{field} must be a boolean"),
            Self::InvalidProviderType { provider_id, provider_type } => {
                write!(f, "provider {provider_id} has unknown type {provider_type}")
            }
            Self::InvalidDisabledReason { provider_id, reason } => {
                write!(f, "provider {provider_id} has unknown disabled reason {reason}")
            }
            Self::DisabledProviderHasAuthorizationUrl { provider_id } => {
                write!(f, "disabled provider {provider_id} must not include an authorization URL")
            }
            Self::EnabledProviderMissingAuthorizationUrl { provider_id } => {
                write!(f, "enabled provider {provider_id} is missing an authorization URL")
            }
            Self::ProviderDisabled { provider_id, reason } => {
                write!(f, "provider {provider_id} is disabled ({})", reason.map_or("unknown", TzapDisabledProviderReason::as_str))
            }
            Self::ProviderMissingAuthorizationUrl { provider_id } => {
                write!(f, "provider {provider_id} is missing an authorization URL")
            }
            Self::InvalidPkceVerifier => write!(f, "PKCE verifier is invalid"),
            Self::InvalidState => write!(f, "OAuth state is invalid"),
            Self::InvalidConfig { field } => {
                write!(f, "hosted auth config field is invalid: {field}")
            }
            Self::DuplicateState => write!(f, "OAuth state already exists"),
            Self::UnknownState => write!(f, "OAuth state is unknown or already consumed"),
            Self::RedirectUriMismatch => {
                write!(f, "hosted auth redirect URI does not match launch")
            }
            Self::PkceVerifierMismatch => {
                write!(f, "hosted auth PKCE verifier does not match launch")
            }
            Self::ExpiredHandoff => write!(f, "hosted auth handoff expired"),
            Self::DeniedHandoff => write!(f, "hosted auth handoff was denied"),
            Self::CancelledHandoff => write!(f, "hosted auth handoff was cancelled"),
            Self::FailedHandoff => write!(f, "hosted auth handoff failed"),
            Self::InvalidHandoffStatus => write!(f, "hosted auth handoff status is invalid"),
            Self::SessionTokenInCallbackUrl => write!(f, "hosted auth callback URL must not contain session tokens"),
            Self::RawProviderMaterial => write!(f, "hosted auth handoff must not contain raw provider material"),
            Self::EmptyToken => write!(f, "session token is empty"),
            Self::Cancelled => write!(f, "hosted auth request was cancelled"),
            Self::InvalidAssuranceLevel { value } => {
                write!(f, "identity assurance level is invalid: {value}")
            }
            Self::AudienceMismatch { expected, actual } => {
                write!(f, "session audience mismatch: expected {expected}, got {actual}")
            }
            Self::Transport { message } => {
                write!(f, "hosted auth HTTP transport failed: {message}")
            }
            Self::Storage { message } => write!(f, "hosted auth storage failed: {message}"),
            Self::HttpStatus { status_code } => {
                write!(f, "hosted auth HTTP request failed with status {status_code}")
            }
        }
    }
}

impl std::error::Error for TzapAuthError {}

#[must_use]
pub fn pkce_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn validate_pkce_verifier(verifier: &str) -> Result<(), TzapAuthError> {
    if !(PKCE_VERIFIER_MIN_LENGTH..=PKCE_VERIFIER_MAX_LENGTH).contains(&verifier.len()) {
        return Err(TzapAuthError::InvalidPkceVerifier);
    }
    if verifier.bytes().all(is_pkce_unreserved) { Ok(()) } else { Err(TzapAuthError::InvalidPkceVerifier) }
}

pub fn validate_oauth_state(state: &str) -> Result<(), TzapAuthError> {
    if state.len() < PKCE_VERIFIER_MIN_LENGTH || !state.bytes().all(is_pkce_unreserved) {
        return Err(TzapAuthError::InvalidState);
    }
    Ok(())
}

fn validate_non_empty_config(field: &'static str, value: &str) -> Result<(), TzapAuthError> {
    if value.is_empty() { Err(TzapAuthError::InvalidConfig { field }) } else { Ok(()) }
}

fn parse_session_record(value: &Value) -> Result<TzapSessionRecord, TzapAuthError> {
    let object = object_at(value, "session")?;
    Ok(TzapSessionRecord {
        audience: required_string_field(object, "session", "audience")?,
        access_token: TzapBearerToken::new(required_string_field(object, "session", "access_token")?)?,
        expires_at_unix_seconds: required_u64_field(object, "session", "expires_at_unix_seconds")?,
        identity_assurance: parse_assurance_level(object, "session", "identity_assurance")?,
        selected_org_id: optional_string_field(object, "session", "selected_org_id")?,
        login_session_id: optional_string_field(object, "session", "login_session_id")?,
    })
}

fn parse_assurance_level(object: &Map<String, Value>, path: &'static str, field: &'static str) -> Result<trust::TzapIdentityAssurance, TzapAuthError> {
    let value = required_string_field(object, path, field)?;
    trust::TzapIdentityAssurance::parse(&value).ok_or(TzapAuthError::InvalidAssuranceLevel { value })
}

fn reject_url_session_material(callback_url: Option<&str>) -> Result<(), TzapAuthError> {
    let Some(callback_url) = callback_url else {
        return Ok(());
    };
    let (before_fragment, fragment) = callback_url.split_once('#').map_or((callback_url, None), |(before, fragment)| (before, Some(fragment)));
    let query = before_fragment.split_once('?').map(|(_, query)| query);
    reject_url_session_material_parameters(query)?;
    reject_url_session_material_parameters(fragment)?;
    Ok(())
}

fn reject_url_session_material_parameters(parameter_text: Option<&str>) -> Result<(), TzapAuthError> {
    let Some(parameter_text) = parameter_text else {
        return Ok(());
    };
    for parameter in parameter_text.split('&') {
        let key = parameter.split_once('=').map_or(parameter, |(key, _)| key);
        if matches!(key, "relay_body" | "access_token" | "session_token" | "id_token" | "refresh_token") {
            return Err(TzapAuthError::SessionTokenInCallbackUrl);
        }
    }
    Ok(())
}

fn reject_raw_provider_material(value: &Value) -> Result<(), TzapAuthError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if is_disallowed_provider_material_field(key) {
                    return Err(TzapAuthError::RawProviderMaterial);
                }
                reject_raw_provider_material(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_raw_provider_material(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn is_disallowed_provider_material_field(field: &str) -> bool {
    matches!(field, "provider_subject" | "provider_sub" | "provider_token" | "provider_access_token" | "oauth_code" | "otp_code" | "magic_link_token")
}

fn object_at<'a>(value: &'a Value, path: &'static str) -> Result<&'a Map<String, Value>, TzapAuthError> {
    value.as_object().ok_or(TzapAuthError::ExpectedObject { path })
}

fn required_field<'a>(object: &'a Map<String, Value>, path: &'static str, field: &'static str) -> Result<&'a Value, TzapAuthError> {
    object.get(field).ok_or(TzapAuthError::MissingField { path, field })
}

fn required_string_field(object: &Map<String, Value>, path: &'static str, field: &'static str) -> Result<String, TzapAuthError> {
    let value = required_field(object, path, field)?;
    let Some(value) = value.as_str() else {
        return Err(TzapAuthError::InvalidString { path, field });
    };
    if value.is_empty() {
        return Err(TzapAuthError::InvalidString { path, field });
    }
    Ok(value.to_owned())
}

fn optional_string_field(object: &Map<String, Value>, path: &'static str, field: &'static str) -> Result<Option<String>, TzapAuthError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(TzapAuthError::InvalidString { path, field });
    };
    if value.is_empty() {
        return Err(TzapAuthError::InvalidString { path, field });
    }
    Ok(Some(value.to_owned()))
}

fn required_u64_field(object: &Map<String, Value>, path: &'static str, field: &'static str) -> Result<u64, TzapAuthError> {
    let value = required_field(object, path, field)?;
    value.as_u64().ok_or(TzapAuthError::InvalidString { path, field })
}

fn encode_query_pairs(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(key, value)| format!("{}={}", url_query_escape(key), url_query_escape(value))).collect::<Vec<_>>().join("&")
}

fn url_query_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        if is_url_query_unreserved(byte) {
            escaped.push(byte as char);
        } else {
            escaped.push('%');
            escaped.push(hex_digit(byte >> 4));
            escaped.push(hex_digit(byte & 0x0f));
        }
    }
    escaped
}

fn is_url_query_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

fn hex_digit(value: u8) -> char {
    char::from(crate::hex::HEX_UPPER[usize::from(value & 0x0f)])
}

fn random_base64url(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn is_pkce_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_HANDOFF_LIFETIME_SECONDS, InMemoryTzapSessionStore, LOGIN_TZAP_BASE_URL, PKCE_METHOD_S256, SESSION_AUDIENCE_LOGIN_TZAP,
        SESSION_AUDIENCE_SIGN_TZAP, SIGN_TZAP_BASE_URL, TzapAuthCancellation, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse,
        TzapAuthHttpTransport, TzapAuthRequestOptions, TzapBearerToken, TzapCurrentUser, TzapHostedAuthCallback, TzapHostedAuthEnvironment,
        TzapHostedAuthLaunchConfig, TzapOAuthStateTracker, TzapPendingAuthState, TzapPkcePair, TzapSessionRecord, TzapSessionStore,
        complete_hosted_auth_handoff, complete_hosted_auth_handoff_for_audience, fetch_current_user, fetch_current_user_for_audience, pkce_s256_challenge,
        validate_pkce_verifier,
    };
    use crate::http_client::send_json_request_with_options;
    use crate::trust;
    use serde_json::json;

    #[test]
    fn pkce_s256_uses_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(pkce_s256_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

        let pair = TzapPkcePair::from_verifier(verifier).unwrap();
        assert_eq!(pair.method, PKCE_METHOD_S256);
        assert_eq!(pair.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_generation_produces_valid_verifier_and_challenge() {
        let pair = TzapPkcePair::generate();
        validate_pkce_verifier(&pair.verifier).unwrap();
        assert_eq!(pair.challenge, pkce_s256_challenge(&pair.verifier));
        assert_ne!(pair.verifier, pair.challenge);
    }

    #[test]
    fn pkce_verifier_rejects_bad_length_and_characters() {
        assert!(matches!(TzapPkcePair::from_verifier("short"), Err(TzapAuthError::InvalidPkceVerifier)));
        assert!(matches!(
            TzapPkcePair::from_verifier("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ=STUVWXYZ0123456789"),
            Err(TzapAuthError::InvalidPkceVerifier)
        ));
    }

    #[test]
    fn oauth_state_tracker_consumes_state_once() {
        let mut tracker = TzapOAuthStateTracker::new();
        let pending = pending_auth_state();
        tracker.insert_pending(pending.clone()).unwrap();

        assert!(matches!(tracker.insert_pending(pending.clone()), Err(TzapAuthError::DuplicateState)));
        assert_eq!(tracker.consume(&pending.state).unwrap(), pending);
        assert!(matches!(tracker.consume("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"), Err(TzapAuthError::UnknownState)));
    }

    #[test]
    fn hosted_auth_launch_url_binds_state_redirect_pkce_and_org() {
        let pending = pending_auth_state();
        let mut config = TzapHostedAuthLaunchConfig::for_environment(TzapHostedAuthEnvironment::Prod, "zmanager-macos", pending.redirect_uri.clone());
        config.selected_org_id = Some("org_123".to_owned());

        let url = config.launch_url(&pending).unwrap();

        assert!(url.starts_with("https://login.tzap.org/auth/launch?"));
        assert!(url.contains("client_id=zmanager-macos"));
        assert!(url.contains("redirect_uri=zmanager%3A%2F%2Fauth%2Fcallback"));
        assert!(url.contains("audience=sign.tzap.org"));
        assert!(url.contains("state=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("response_mode=native_app_relay"));
        assert!(url.contains("provider_id=github"));
        assert!(url.contains("org_id=org_123"));
        assert_eq!(config.account_url(), "https://account.tzap.org/account");
    }

    #[test]
    fn hosted_auth_launch_url_supports_the_allow_listed_login_audience() {
        let pending = pending_auth_state();
        let mut config = TzapHostedAuthLaunchConfig::for_environment(TzapHostedAuthEnvironment::Prod, "zmanager-desktop", pending.redirect_uri.clone());
        config.requested_audience = SESSION_AUDIENCE_LOGIN_TZAP.to_owned();

        let url = config.launch_url(&pending).unwrap();

        assert!(url.contains("audience=login.tzap.org"));
    }

    #[test]
    fn staging_environment_uses_live_staging_https_origin() {
        let pending = pending_auth_state();
        let config = TzapHostedAuthLaunchConfig::for_environment(TzapHostedAuthEnvironment::Staging, "zmanager-macos", pending.redirect_uri.clone());

        let url = config.launch_url(&pending).unwrap();

        assert!(url.starts_with("https://staging.tzap.org/auth/launch?"));
        assert_eq!(config.account_url(), "https://staging.tzap.org/account");
    }

    #[test]
    fn hosted_auth_callback_rejects_state_redirect_pkce_and_expiry_mismatches() {
        let pending = pending_auth_state();

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.state = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq".to_owned();
        assert!(matches!(tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::UnknownState)));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.redirect_uri = "zmanager://auth/other".to_owned();
        assert!(matches!(tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::RedirectUriMismatch)));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.pkce_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPR".to_owned();
        assert!(matches!(tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::PkceVerifierMismatch)));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let callback = hosted_auth_callback(&pending, relay_success_body());
        assert!(matches!(tracker.consume_handoff(&callback, 701, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::ExpiredHandoff)));
    }

    #[test]
    fn hosted_auth_callback_validation_failures_do_not_consume_pending_state() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();

        let mut bad_callback = hosted_auth_callback(&pending, relay_success_body());
        bad_callback.pkce_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPR".to_owned();
        assert!(matches!(tracker.consume_handoff(&bad_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::PkceVerifierMismatch)));

        let good_callback = hosted_auth_callback(&pending, relay_success_body());
        assert_eq!(tracker.consume_handoff(&good_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS).unwrap(), pending);
    }

    #[test]
    fn hosted_auth_handoff_accepts_session_from_relay_body_only() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut store = InMemoryTzapSessionStore::new();
        let callback = hosted_auth_callback(&pending, relay_success_body());

        let session = complete_hosted_auth_handoff(&mut tracker, &mut store, "default", &callback, 101).unwrap();

        assert_eq!(session.audience, SESSION_AUDIENCE_SIGN_TZAP);
        assert_eq!(session.identity_assurance, trust::TzapIdentityAssurance::OauthVerifiedEmail);
        assert_eq!(session.selected_org_id.as_deref(), Some("org_123"));
        assert_eq!(session.login_session_id.as_deref(), Some("login_session_123"));
        assert_eq!(store.load_session("default"), Some(session));
    }

    #[test]
    fn hosted_auth_handoff_accepts_the_selected_login_audience() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut store = InMemoryTzapSessionStore::new();
        let mut relay = relay_success_body();
        let mut relay_json: serde_json::Value = serde_json::from_slice(&relay).unwrap();
        relay_json["session"]["audience"] = serde_json::Value::String(SESSION_AUDIENCE_LOGIN_TZAP.to_owned());
        relay = serde_json::to_vec(&relay_json).unwrap();
        let callback = hosted_auth_callback(&pending, relay);

        let session = complete_hosted_auth_handoff_for_audience(&mut tracker, &mut store, "default", &callback, 101, SESSION_AUDIENCE_LOGIN_TZAP).unwrap();

        assert_eq!(session.audience, SESSION_AUDIENCE_LOGIN_TZAP);
        assert_eq!(store.load_session("default"), Some(session));
    }

    #[test]
    fn hosted_auth_handoff_reports_session_store_failure() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut store = FailingSessionStore;
        let callback = hosted_auth_callback(&pending, relay_success_body());

        let error = complete_hosted_auth_handoff(&mut tracker, &mut store, "default", &callback, 101).unwrap_err();

        assert!(matches!(error, TzapAuthError::Storage { message } if message == "store failed"));
    }

    #[test]
    fn hosted_auth_handoff_rejects_tokens_in_callback_url_and_provider_material() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.callback_url = Some("zmanager://auth/callback?state=ok&access_token=never".to_owned());

        assert!(matches!(tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::SessionTokenInCallbackUrl)));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut fragment_callback = hosted_auth_callback(&pending, relay_success_body());
        fragment_callback.callback_url = Some("zmanager://auth/callback?state=ok#access_token=never&relay_body=never".to_owned());
        assert!(matches!(tracker.consume_handoff(&fragment_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::SessionTokenInCallbackUrl)));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut relay_query_callback = hosted_auth_callback(&pending, relay_success_body());
        relay_query_callback.callback_url = Some("zmanager://auth/callback?state=ok&relay_body=never".to_owned());
        assert!(matches!(tracker.consume_handoff(&relay_query_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS), Err(TzapAuthError::SessionTokenInCallbackUrl)));

        assert!(matches!(
            super::TzapAuthRelayCompletion::from_json_value(&json!({
                "status": "ok",
                "provider_subject": "google-oauth-subject",
                "session": relay_session_json()
            })),
            Err(TzapAuthError::RawProviderMaterial)
        ));
    }

    #[test]
    fn hosted_auth_relay_failures_are_typed() {
        assert!(matches!(super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "denied"})), Err(TzapAuthError::DeniedHandoff)));
        assert!(matches!(super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "expired"})), Err(TzapAuthError::ExpiredHandoff)));
        assert!(matches!(super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "cancelled"})), Err(TzapAuthError::CancelledHandoff)));
        assert!(matches!(super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "failed"})), Err(TzapAuthError::FailedHandoff)));
    }

    #[test]
    fn session_store_keeps_tokens_redacted_and_enforces_audience() {
        let token = TzapBearerToken::new("secret-token").unwrap();
        assert_eq!(format!("{token:?}"), "TzapBearerToken(<redacted>)");
        assert_eq!(token.expose(), "secret-token");

        let session = TzapSessionRecord {
            audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            access_token: token,
            expires_at_unix_seconds: 200,
            identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: Some("org_123".to_owned()),
            login_session_id: Some("login_session_123".to_owned()),
        };
        assert!(!session.is_expired_at(199));
        assert!(session.is_expired_at(200));
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP).unwrap();
        assert!(matches!(
            session.require_audience("login.tzap.org"),
            Err(TzapAuthError::AudienceMismatch { expected, actual })
                if expected == "login.tzap.org" && actual == SESSION_AUDIENCE_SIGN_TZAP
        ));

        let mut store = InMemoryTzapSessionStore::new();
        store.save_session("default", session.clone()).unwrap();
        assert_eq!(store.load_session("default"), Some(session));
        store.clear_session("default").unwrap();
        assert!(store.load_session("default").is_none());
    }

    #[test]
    fn auth_base_urls_are_owned_constants() {
        assert_eq!(LOGIN_TZAP_BASE_URL, "https://login.tzap.org");
        assert_eq!(SIGN_TZAP_BASE_URL, "https://sign.tzap.org");
    }

    #[test]
    fn current_user_fetch_uses_injected_transport_and_redacted_token() {
        let session = TzapSessionRecord {
            audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            access_token: TzapBearerToken::new("secret-token").unwrap(),
            expires_at_unix_seconds: 200,
            identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: Some("org_123".to_owned()),
            login_session_id: Some("login_session_123".to_owned()),
        };
        let transport = FakeAuthTransport {
            response: TzapAuthHttpResponse {
                status_code: 200,
                body: br#"{
                    "display_name": "Ada Lovelace",
                    "public_signer_id": "psign_0123456789ABCDEFGH",
                    "assurance_level": "oauth_verified_email",
                    "selected_org_id": "org_123"
                }"#
                .to_vec(),
                headers: Vec::new(),
            },
            last_request: std::cell::RefCell::new(None),
        };

        let current_user = fetch_current_user(&transport, SIGN_TZAP_BASE_URL, &session).unwrap();

        assert_eq!(current_user.display_name, "Ada Lovelace");
        assert_eq!(current_user.selected_org_id.as_deref(), Some("org_123"));
        assert_eq!(format!("{:?}", transport.last_request().bearer_token.as_ref().unwrap()), "TzapBearerToken(<redacted>)");

        let mut login_session = session.clone();
        login_session.audience = SESSION_AUDIENCE_LOGIN_TZAP.to_owned();
        let login_user = fetch_current_user_for_audience(&transport, SIGN_TZAP_BASE_URL, &login_session, SESSION_AUDIENCE_LOGIN_TZAP).unwrap();
        assert_eq!(login_user.selected_org_id.as_deref(), Some("org_123"));
    }

    #[test]
    fn current_user_accepts_legacy_endpoint_without_assurance() {
        let value = json!({
            "display_name": "Ada Lovelace",
            "public_signer_id": "psign_0123456789ABCDEFGH",
            "selected_org_id": "org_123"
        });
        let current_user = TzapCurrentUser::from_json_value(&value).unwrap();
        assert_eq!(current_user.assurance_level, None);
    }

    fn pending_auth_state() -> TzapPendingAuthState {
        TzapPendingAuthState {
            state: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned(),
            provider_id: "github".to_owned(),
            redirect_uri: "zmanager://auth/callback".to_owned(),
            pkce: TzapPkcePair::from_verifier("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ").unwrap(),
            created_at_unix_seconds: 100,
        }
    }

    fn hosted_auth_callback(pending: &TzapPendingAuthState, relay_body: Vec<u8>) -> TzapHostedAuthCallback {
        TzapHostedAuthCallback {
            state: pending.state.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            pkce_verifier: pending.pkce.verifier.clone(),
            callback_url: Some(format!("{}?state={}", pending.redirect_uri, pending.state)),
            relay_body,
        }
    }

    fn relay_success_body() -> Vec<u8> {
        json!({
            "status": "ok",
            "session": relay_session_json()
        })
        .to_string()
        .into_bytes()
    }

    fn relay_session_json() -> serde_json::Value {
        json!({
            "audience": SESSION_AUDIENCE_SIGN_TZAP,
            "access_token": "secret-token",
            "expires_at_unix_seconds": 200,
            "identity_assurance": "oauth_verified_email",
            "selected_org_id": "org_123",
            "login_session_id": "login_session_123"
        })
    }

    struct FakeAuthTransport {
        response: TzapAuthHttpResponse,
        last_request: std::cell::RefCell<Option<TzapAuthHttpRequest>>,
    }

    impl FakeAuthTransport {
        fn last_request(&self) -> TzapAuthHttpRequest {
            self.last_request.borrow().as_ref().expect("fake transport received request").clone()
        }
    }

    impl TzapAuthHttpTransport for FakeAuthTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            assert_eq!(request.method, TzapAuthHttpMethod::Get);
            assert_eq!(request.url, "https://sign.tzap.org/v1/me");
            self.last_request.replace(Some(request.clone()));
            Ok(self.response.clone())
        }
    }

    struct FailingSessionStore;

    impl TzapSessionStore for FailingSessionStore {
        fn save_session(&mut self, _account_key: &str, _session: TzapSessionRecord) -> Result<(), TzapAuthError> {
            Err(TzapAuthError::Storage { message: "store failed".to_owned() })
        }

        fn load_session(&self, _account_key: &str) -> Option<TzapSessionRecord> {
            None
        }

        fn clear_session(&mut self, _account_key: &str) -> Result<(), TzapAuthError> {
            Ok(())
        }
    }

    struct RetryFakeTransport {
        response: TzapAuthHttpResponse,
        attempts: std::cell::Cell<usize>,
        fail_count: usize,
        is_offline: bool,
    }

    impl TzapAuthHttpTransport for RetryFakeTransport {
        fn send(&self, _request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.attempts.set(self.attempts.get() + 1);
            if self.is_offline {
                return Err(TzapAuthError::Transport { message: "offline".to_owned() });
            }
            if self.attempts.get() <= self.fail_count {
                return Ok(TzapAuthHttpResponse { status_code: 500, body: Vec::new(), headers: Vec::new() });
            }
            Ok(self.response.clone())
        }
    }

    #[test]
    fn auth_client_retries_on_500_and_429_errors() {
        let session = TzapSessionRecord {
            audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            access_token: TzapBearerToken::new("secret-token").unwrap(),
            expires_at_unix_seconds: 200,
            identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: Some("org_123".to_owned()),
            login_session_id: Some("login_session_123".to_owned()),
        };
        let transport = RetryFakeTransport {
            response: TzapAuthHttpResponse {
                status_code: 200,
                body: br#"{
                    "display_name": "Ada Lovelace",
                    "public_signer_id": "psign_0123456789ABCDEFGH",
                    "assurance_level": "oauth_verified_email",
                    "selected_org_id": "org_123"
                }"#
                .to_vec(),
                headers: Vec::new(),
            },
            attempts: std::cell::Cell::new(0),
            fail_count: 2, // Fails twice, succeeds on third attempt
            is_offline: false,
        };

        let current_user = fetch_current_user(&transport, SIGN_TZAP_BASE_URL, &session).unwrap();
        assert_eq!(current_user.display_name, "Ada Lovelace");
        assert_eq!(transport.attempts.get(), 3);
    }

    #[test]
    fn auth_client_handles_offline_timeout_gracefully() {
        let session = TzapSessionRecord {
            audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            access_token: TzapBearerToken::new("secret-token").unwrap(),
            expires_at_unix_seconds: 200,
            identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: Some("org_123".to_owned()),
            login_session_id: Some("login_session_123".to_owned()),
        };
        let transport = RetryFakeTransport {
            response: TzapAuthHttpResponse { status_code: 200, body: Vec::new(), headers: Vec::new() },
            attempts: std::cell::Cell::new(0),
            fail_count: 0,
            is_offline: true, // Always fails with transport error
        };

        let result = fetch_current_user(&transport, SIGN_TZAP_BASE_URL, &session);
        assert!(matches!(result, Err(TzapAuthError::Transport { .. })));
        assert_eq!(transport.attempts.get(), 3); // Exhausts retries
    }

    #[test]
    fn cancelled_auth_request_does_not_reach_transport() {
        let cancellation = TzapAuthCancellation::new();
        cancellation.cancel();
        let transport = RetryFakeTransport {
            response: TzapAuthHttpResponse { status_code: 200, body: Vec::new(), headers: Vec::new() },
            attempts: std::cell::Cell::new(0),
            fail_count: 0,
            is_offline: false,
        };
        let options = TzapAuthRequestOptions { cancellation: Some(cancellation), ..TzapAuthRequestOptions::default() };

        let result = send_json_request_with_options(&transport, TzapAuthHttpMethod::Get, SIGN_TZAP_BASE_URL, "/v1/me", None, None, options);

        assert!(matches!(result, Err(TzapAuthError::Cancelled)));
        assert_eq!(transport.attempts.get(), 0);
    }
}
