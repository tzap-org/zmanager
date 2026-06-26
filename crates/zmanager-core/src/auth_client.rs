//! Auth-client primitives for TZAP hosted Auth launch and bootstrap flows.

use crate::trust;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt;

pub const SIGNUP_TZAP_BASE_URL: &str = "https://signup.tzap.org";
pub const LOGIN_TZAP_BASE_URL: &str = "https://login.tzap.org";
pub const SIGN_TZAP_BASE_URL: &str = "https://sign.tzap.org";
pub const PROVIDER_DISCOVERY_PATH: &str = "/auth/providers";
pub const HOSTED_AUTH_AUTHORIZE_PATH: &str = "/auth/launch";
pub const HOSTED_ACCOUNT_PATH: &str = "/account";
pub const CURRENT_USER_PATH: &str = "/v1/me";
pub const LOCAL_HOSTED_AUTH_BASE_URL: &str = "http://localhost:8787";
pub const LOCAL_HOSTED_ACCOUNT_BASE_URL: &str = "http://localhost:8787";
pub const DEV_HOSTED_AUTH_BASE_URL: &str = "https://login.dev.tzap.org";
pub const DEV_HOSTED_ACCOUNT_BASE_URL: &str = "https://account.dev.tzap.org";
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
    Dev,
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
    pub fn for_environment(
        environment: TzapHostedAuthEnvironment,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let (hosted_auth_base_url, hosted_account_base_url) = match environment {
            TzapHostedAuthEnvironment::Local => {
                (LOCAL_HOSTED_AUTH_BASE_URL, LOCAL_HOSTED_ACCOUNT_BASE_URL)
            }
            TzapHostedAuthEnvironment::Dev => {
                (DEV_HOSTED_AUTH_BASE_URL, DEV_HOSTED_ACCOUNT_BASE_URL)
            }
            TzapHostedAuthEnvironment::Prod => {
                (PROD_HOSTED_AUTH_BASE_URL, PROD_HOSTED_ACCOUNT_BASE_URL)
            }
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

        Ok(format!(
            "{}{}?{}",
            trim_trailing_slash(&self.hosted_auth_base_url),
            HOSTED_AUTH_AUTHORIZE_PATH,
            encode_query_pairs(&query)
        ))
    }

    #[must_use]
    pub fn account_url(&self) -> String {
        format!(
            "{}{}",
            trim_trailing_slash(&self.hosted_account_base_url),
            HOSTED_ACCOUNT_PATH
        )
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
pub struct TzapAuthProvider {
    pub id: String,
    pub display_name: String,
    pub provider_type: TzapAuthProviderType,
    pub enabled: bool,
    pub authorization_url: Option<String>,
    pub disabled_reason: Option<TzapDisabledProviderReason>,
}

impl TzapAuthProvider {
    pub fn authorization_target(&self) -> Result<&str, TzapAuthError> {
        if !self.enabled {
            return Err(TzapAuthError::ProviderDisabled {
                provider_id: self.id.clone(),
                reason: self.disabled_reason,
            });
        }
        self.authorization_url.as_deref().ok_or_else(|| {
            TzapAuthError::ProviderMissingAuthorizationUrl {
                provider_id: self.id.clone(),
            }
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapProviderDiscovery {
    pub providers: Vec<TzapAuthProvider>,
}

impl TzapProviderDiscovery {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, TzapAuthError> {
        let value: Value = serde_json::from_slice(bytes).map_err(TzapAuthError::InvalidJson)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &Value) -> Result<Self, TzapAuthError> {
        let object = object_at(value, "$")?;
        let providers = required_field(object, "$", "providers")?
            .as_array()
            .ok_or(TzapAuthError::ExpectedArray { path: "providers" })?;
        let providers = providers
            .iter()
            .map(parse_provider)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { providers })
    }

    #[must_use]
    pub fn provider(&self, provider_id: &str) -> Option<&TzapAuthProvider> {
        self.providers
            .iter()
            .find(|provider| provider.id == provider_id)
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
        Self {
            verifier,
            challenge,
            method: PKCE_METHOD_S256,
        }
    }

    pub fn from_verifier(verifier: &str) -> Result<Self, TzapAuthError> {
        validate_pkce_verifier(verifier)?;
        Ok(Self {
            verifier: verifier.to_owned(),
            challenge: pkce_s256_challenge(verifier),
            method: PKCE_METHOD_S256,
        })
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

    pub fn begin(
        &mut self,
        provider_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        created_at_unix_seconds: u64,
    ) -> TzapPendingAuthState {
        let provider_id = provider_id.into();
        let redirect_uri = redirect_uri.into();
        loop {
            let state = random_base64url(OAUTH_STATE_RANDOM_BYTES);
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.pending.entry(state.clone())
            {
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
        self.pending
            .remove(state)
            .ok_or(TzapAuthError::UnknownState)
    }

    pub fn consume_handoff(
        &mut self,
        callback: &TzapHostedAuthCallback,
        now_unix_seconds: u64,
        handoff_lifetime_seconds: u64,
    ) -> Result<TzapPendingAuthState, TzapAuthError> {
        reject_url_session_material(callback.callback_url.as_deref())?;
        validate_oauth_state(&callback.state)?;
        let pending = self
            .pending
            .get(&callback.state)
            .ok_or(TzapAuthError::UnknownState)?;
        if pending.redirect_uri != callback.redirect_uri {
            return Err(TzapAuthError::RedirectUriMismatch);
        }
        if pending.pkce.verifier != callback.pkce_verifier {
            return Err(TzapAuthError::PkceVerifierMismatch);
        }
        let expires_at = pending
            .created_at_unix_seconds
            .saturating_add(handoff_lifetime_seconds);
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
    pub relay_body: Vec<u8>,
}

pub fn complete_hosted_auth_handoff(
    tracker: &mut TzapOAuthStateTracker,
    session_store: &mut impl TzapSessionStore,
    account_key: &str,
    callback: &TzapHostedAuthCallback,
    now_unix_seconds: u64,
) -> Result<TzapSessionRecord, TzapAuthError> {
    let pending =
        tracker.consume_handoff(callback, now_unix_seconds, AUTH_HANDOFF_LIFETIME_SECONDS)?;
    let relay = TzapAuthRelayCompletion::from_json_bytes(&callback.relay_body)?;
    let session = relay.into_session();
    session.require_audience(&pending_expected_audience(&pending))?;
    session_store.save_session(account_key, session.clone());
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
        if self.audience == expected {
            Ok(())
        } else {
            Err(TzapAuthError::AudienceMismatch {
                expected: expected.to_owned(),
                actual: self.audience.clone(),
            })
        }
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
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthHttpRequest {
    pub method: TzapAuthHttpMethod,
    pub url: String,
    pub bearer_token: Option<TzapBearerToken>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapAuthHttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
}

pub trait TzapAuthHttpTransport {
    fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapCurrentUser {
    pub display_name: String,
    pub public_signer_id: Option<String>,
    pub assurance_level: trust::TzapIdentityAssurance,
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
            assurance_level: parse_assurance_level(object, "$", "assurance_level")?,
            selected_org_id: optional_string_field(object, "$", "selected_org_id")?,
        })
    }
}

pub fn fetch_current_user(
    transport: &impl TzapAuthHttpTransport,
    sign_base_url: &str,
    session: &TzapSessionRecord,
) -> Result<TzapCurrentUser, TzapAuthError> {
    session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
    let request = TzapAuthHttpRequest {
        method: TzapAuthHttpMethod::Get,
        url: format!(
            "{}{}",
            trim_trailing_slash(sign_base_url),
            CURRENT_USER_PATH
        ),
        bearer_token: Some(session.access_token.clone()),
        body: None,
    };
    let response = transport.send(&request)?;
    if !(200..=299).contains(&response.status_code) {
        return Err(TzapAuthError::HttpStatus {
            status_code: response.status_code,
        });
    }
    TzapCurrentUser::from_json_bytes(&response.body)
}

pub trait TzapSessionStore {
    fn save_session(&mut self, account_key: &str, session: TzapSessionRecord);
    fn load_session(&self, account_key: &str) -> Option<TzapSessionRecord>;
    fn clear_session(&mut self, account_key: &str);
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
    fn save_session(&mut self, account_key: &str, session: TzapSessionRecord) {
        self.sessions.insert(account_key.to_owned(), session);
    }

    fn load_session(&self, account_key: &str) -> Option<TzapSessionRecord> {
        self.sessions.get(account_key).cloned()
    }

    fn clear_session(&mut self, account_key: &str) {
        self.sessions.remove(account_key);
    }
}

#[derive(Debug)]
pub enum TzapAuthError {
    InvalidJson(serde_json::Error),
    ExpectedObject {
        path: &'static str,
    },
    ExpectedArray {
        path: &'static str,
    },
    MissingField {
        path: &'static str,
        field: &'static str,
    },
    InvalidString {
        path: &'static str,
        field: &'static str,
    },
    InvalidBoolean {
        path: &'static str,
        field: &'static str,
    },
    InvalidProviderType {
        provider_id: String,
        provider_type: String,
    },
    InvalidDisabledReason {
        provider_id: String,
        reason: String,
    },
    DisabledProviderHasAuthorizationUrl {
        provider_id: String,
    },
    EnabledProviderMissingAuthorizationUrl {
        provider_id: String,
    },
    ProviderDisabled {
        provider_id: String,
        reason: Option<TzapDisabledProviderReason>,
    },
    ProviderMissingAuthorizationUrl {
        provider_id: String,
    },
    InvalidPkceVerifier,
    InvalidState,
    InvalidConfig {
        field: &'static str,
    },
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
    InvalidAssuranceLevel {
        value: String,
    },
    AudienceMismatch {
        expected: String,
        actual: String,
    },
    Transport {
        message: String,
    },
    HttpStatus {
        status_code: u16,
    },
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
            Self::InvalidProviderType {
                provider_id,
                provider_type,
            } => write!(f, "provider {provider_id} has unknown type {provider_type}"),
            Self::InvalidDisabledReason {
                provider_id,
                reason,
            } => write!(
                f,
                "provider {provider_id} has unknown disabled reason {reason}"
            ),
            Self::DisabledProviderHasAuthorizationUrl { provider_id } => write!(
                f,
                "disabled provider {provider_id} must not include an authorization URL"
            ),
            Self::EnabledProviderMissingAuthorizationUrl { provider_id } => {
                write!(
                    f,
                    "enabled provider {provider_id} is missing an authorization URL"
                )
            }
            Self::ProviderDisabled {
                provider_id,
                reason,
            } => write!(
                f,
                "provider {provider_id} is disabled ({})",
                reason.map_or("unknown", TzapDisabledProviderReason::as_str)
            ),
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
            Self::SessionTokenInCallbackUrl => write!(
                f,
                "hosted auth callback URL must not contain session tokens"
            ),
            Self::RawProviderMaterial => write!(
                f,
                "hosted auth handoff must not contain raw provider material"
            ),
            Self::EmptyToken => write!(f, "session token is empty"),
            Self::InvalidAssuranceLevel { value } => {
                write!(f, "identity assurance level is invalid: {value}")
            }
            Self::AudienceMismatch { expected, actual } => {
                write!(
                    f,
                    "session audience mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Transport { message } => {
                write!(f, "hosted auth HTTP transport failed: {message}")
            }
            Self::HttpStatus { status_code } => {
                write!(
                    f,
                    "hosted auth HTTP request failed with status {status_code}"
                )
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
    if verifier.bytes().all(is_pkce_unreserved) {
        Ok(())
    } else {
        Err(TzapAuthError::InvalidPkceVerifier)
    }
}

pub fn validate_oauth_state(state: &str) -> Result<(), TzapAuthError> {
    if state.len() < PKCE_VERIFIER_MIN_LENGTH || !state.bytes().all(is_pkce_unreserved) {
        return Err(TzapAuthError::InvalidState);
    }
    Ok(())
}

fn validate_non_empty_config(field: &'static str, value: &str) -> Result<(), TzapAuthError> {
    if value.is_empty() {
        Err(TzapAuthError::InvalidConfig { field })
    } else {
        Ok(())
    }
}

fn pending_expected_audience(_pending: &TzapPendingAuthState) -> String {
    SESSION_AUDIENCE_SIGN_TZAP.to_owned()
}

fn parse_session_record(value: &Value) -> Result<TzapSessionRecord, TzapAuthError> {
    let object = object_at(value, "session")?;
    Ok(TzapSessionRecord {
        audience: required_string_field(object, "session", "audience")?,
        access_token: TzapBearerToken::new(required_string_field(
            object,
            "session",
            "access_token",
        )?)?,
        expires_at_unix_seconds: required_u64_field(object, "session", "expires_at_unix_seconds")?,
        identity_assurance: parse_assurance_level(object, "session", "identity_assurance")?,
        selected_org_id: optional_string_field(object, "session", "selected_org_id")?,
        login_session_id: optional_string_field(object, "session", "login_session_id")?,
    })
}

fn parse_assurance_level(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<trust::TzapIdentityAssurance, TzapAuthError> {
    let value = required_string_field(object, path, field)?;
    trust::TzapIdentityAssurance::from_str(&value)
        .ok_or(TzapAuthError::InvalidAssuranceLevel { value })
}

fn reject_url_session_material(callback_url: Option<&str>) -> Result<(), TzapAuthError> {
    let Some(callback_url) = callback_url else {
        return Ok(());
    };
    let (before_fragment, fragment) = callback_url
        .split_once('#')
        .map_or((callback_url, None), |(before, fragment)| {
            (before, Some(fragment))
        });
    let query = before_fragment.split_once('?').map(|(_, query)| query);
    reject_url_session_material_parameters(query)?;
    reject_url_session_material_parameters(fragment)?;
    Ok(())
}

fn reject_url_session_material_parameters(
    parameter_text: Option<&str>,
) -> Result<(), TzapAuthError> {
    let Some(parameter_text) = parameter_text else {
        return Ok(());
    };
    for parameter in parameter_text.split('&') {
        let key = parameter.split_once('=').map_or(parameter, |(key, _)| key);
        if matches!(
            key,
            "relay_body" | "access_token" | "session_token" | "id_token" | "refresh_token"
        ) {
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
    matches!(
        field,
        "provider_subject"
            | "provider_sub"
            | "provider_token"
            | "provider_access_token"
            | "oauth_code"
            | "otp_code"
            | "magic_link_token"
    )
}

fn parse_provider(value: &Value) -> Result<TzapAuthProvider, TzapAuthError> {
    let path = "providers[]";
    let object = value
        .as_object()
        .ok_or(TzapAuthError::ExpectedObject { path })?;

    let id = required_string_field(object, path, "id")?;
    let display_name = required_string_field(object, path, "display_name")?;
    let provider_type_value = required_string_field(object, path, "provider_type")?;
    let provider_type =
        TzapAuthProviderType::from_wire_value(&provider_type_value).ok_or_else(|| {
            TzapAuthError::InvalidProviderType {
                provider_id: id.clone(),
                provider_type: provider_type_value,
            }
        })?;
    let enabled = required_bool_field(object, path, "enabled")?;
    let authorization_url = optional_string_field(object, path, "authorization_url")?;
    let disabled_reason = optional_string_field(object, path, "disabled_reason")?
        .map(|reason| {
            TzapDisabledProviderReason::from_wire_value(&reason).ok_or_else(|| {
                TzapAuthError::InvalidDisabledReason {
                    provider_id: id.clone(),
                    reason,
                }
            })
        })
        .transpose()?;

    if enabled && authorization_url.is_none() {
        return Err(TzapAuthError::EnabledProviderMissingAuthorizationUrl { provider_id: id });
    }
    if !enabled && authorization_url.is_some() {
        return Err(TzapAuthError::DisabledProviderHasAuthorizationUrl { provider_id: id });
    }

    Ok(TzapAuthProvider {
        id,
        display_name,
        provider_type,
        enabled,
        authorization_url,
        disabled_reason,
    })
}

fn object_at<'a>(
    value: &'a Value,
    path: &'static str,
) -> Result<&'a Map<String, Value>, TzapAuthError> {
    value
        .as_object()
        .ok_or(TzapAuthError::ExpectedObject { path })
}

fn required_field<'a>(
    object: &'a Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<&'a Value, TzapAuthError> {
    object
        .get(field)
        .ok_or(TzapAuthError::MissingField { path, field })
}

fn required_string_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<String, TzapAuthError> {
    let value = required_field(object, path, field)?;
    let Some(value) = value.as_str() else {
        return Err(TzapAuthError::InvalidString { path, field });
    };
    if value.is_empty() {
        return Err(TzapAuthError::InvalidString { path, field });
    }
    Ok(value.to_owned())
}

fn optional_string_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<Option<String>, TzapAuthError> {
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

fn required_bool_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<bool, TzapAuthError> {
    let value = required_field(object, path, field)?;
    value
        .as_bool()
        .ok_or(TzapAuthError::InvalidBoolean { path, field })
}

fn required_u64_field(
    object: &Map<String, Value>,
    path: &'static str,
    field: &'static str,
) -> Result<u64, TzapAuthError> {
    let value = required_field(object, path, field)?;
    value
        .as_u64()
        .ok_or(TzapAuthError::InvalidString { path, field })
}

fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

fn encode_query_pairs(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", url_query_escape(key), url_query_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
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
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + (value - 10)) as char,
        _ => unreachable!("hex digit nibble is always less than 16"),
    }
}

fn random_base64url(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
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
        AUTH_HANDOFF_LIFETIME_SECONDS, InMemoryTzapSessionStore, LOGIN_TZAP_BASE_URL,
        PKCE_METHOD_S256, SESSION_AUDIENCE_SIGN_TZAP, SIGN_TZAP_BASE_URL, SIGNUP_TZAP_BASE_URL,
        TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse,
        TzapAuthHttpTransport, TzapAuthProviderType, TzapBearerToken, TzapHostedAuthCallback,
        TzapHostedAuthEnvironment, TzapHostedAuthLaunchConfig, TzapOAuthStateTracker,
        TzapPendingAuthState, TzapPkcePair, TzapProviderDiscovery, TzapSessionRecord,
        TzapSessionStore, complete_hosted_auth_handoff, fetch_current_user, pkce_s256_challenge,
        validate_pkce_verifier,
    };
    use crate::trust;
    use serde_json::json;

    #[test]
    fn pkce_s256_uses_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );

        let pair = TzapPkcePair::from_verifier(verifier).unwrap();
        assert_eq!(pair.method, PKCE_METHOD_S256);
        assert_eq!(
            pair.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
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
        assert!(matches!(
            TzapPkcePair::from_verifier("short"),
            Err(TzapAuthError::InvalidPkceVerifier)
        ));
        assert!(matches!(
            TzapPkcePair::from_verifier(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ=STUVWXYZ0123456789"
            ),
            Err(TzapAuthError::InvalidPkceVerifier)
        ));
    }

    #[test]
    fn oauth_state_tracker_consumes_state_once() {
        let mut tracker = TzapOAuthStateTracker::new();
        let pending = pending_auth_state();
        tracker.insert_pending(pending.clone()).unwrap();

        assert!(matches!(
            tracker.insert_pending(pending.clone()),
            Err(TzapAuthError::DuplicateState)
        ));
        assert_eq!(tracker.consume(&pending.state).unwrap(), pending);
        assert!(matches!(
            tracker.consume("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"),
            Err(TzapAuthError::UnknownState)
        ));
    }

    #[test]
    fn hosted_auth_launch_url_binds_state_redirect_pkce_and_org() {
        let pending = pending_auth_state();
        let mut config = TzapHostedAuthLaunchConfig::for_environment(
            TzapHostedAuthEnvironment::Prod,
            "zmanager-macos",
            pending.redirect_uri.clone(),
        );
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
    fn hosted_auth_callback_rejects_state_redirect_pkce_and_expiry_mismatches() {
        let pending = pending_auth_state();

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.state = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq".to_owned();
        assert!(matches!(
            tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::UnknownState)
        ));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.redirect_uri = "zmanager://auth/other".to_owned();
        assert!(matches!(
            tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::RedirectUriMismatch)
        ));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.pkce_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPR".to_owned();
        assert!(matches!(
            tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::PkceVerifierMismatch)
        ));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let callback = hosted_auth_callback(&pending, relay_success_body());
        assert!(matches!(
            tracker.consume_handoff(&callback, 701, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::ExpiredHandoff)
        ));
    }

    #[test]
    fn hosted_auth_callback_validation_failures_do_not_consume_pending_state() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();

        let mut bad_callback = hosted_auth_callback(&pending, relay_success_body());
        bad_callback.pkce_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPR".to_owned();
        assert!(matches!(
            tracker.consume_handoff(&bad_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::PkceVerifierMismatch)
        ));

        let good_callback = hosted_auth_callback(&pending, relay_success_body());
        assert_eq!(
            tracker
                .consume_handoff(&good_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS)
                .unwrap(),
            pending
        );
    }

    #[test]
    fn hosted_auth_handoff_accepts_session_from_relay_body_only() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut store = InMemoryTzapSessionStore::new();
        let callback = hosted_auth_callback(&pending, relay_success_body());

        let session =
            complete_hosted_auth_handoff(&mut tracker, &mut store, "default", &callback, 101)
                .unwrap();

        assert_eq!(session.audience, SESSION_AUDIENCE_SIGN_TZAP);
        assert_eq!(
            session.identity_assurance,
            trust::TzapIdentityAssurance::OauthVerifiedEmail
        );
        assert_eq!(session.selected_org_id.as_deref(), Some("org_123"));
        assert_eq!(
            session.login_session_id.as_deref(),
            Some("login_session_123")
        );
        assert_eq!(store.load_session("default"), Some(session));
    }

    #[test]
    fn hosted_auth_handoff_rejects_tokens_in_callback_url_and_provider_material() {
        let pending = pending_auth_state();
        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut callback = hosted_auth_callback(&pending, relay_success_body());
        callback.callback_url =
            Some("zmanager://auth/callback?state=ok&access_token=never".to_owned());

        assert!(matches!(
            tracker.consume_handoff(&callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::SessionTokenInCallbackUrl)
        ));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut fragment_callback = hosted_auth_callback(&pending, relay_success_body());
        fragment_callback.callback_url = Some(
            "zmanager://auth/callback?state=ok#access_token=never&relay_body=never".to_owned(),
        );
        assert!(matches!(
            tracker.consume_handoff(&fragment_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::SessionTokenInCallbackUrl)
        ));

        let mut tracker = TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).unwrap();
        let mut relay_query_callback = hosted_auth_callback(&pending, relay_success_body());
        relay_query_callback.callback_url =
            Some("zmanager://auth/callback?state=ok&relay_body=never".to_owned());
        assert!(matches!(
            tracker.consume_handoff(&relay_query_callback, 101, AUTH_HANDOFF_LIFETIME_SECONDS),
            Err(TzapAuthError::SessionTokenInCallbackUrl)
        ));

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
        assert!(matches!(
            super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "denied"})),
            Err(TzapAuthError::DeniedHandoff)
        ));
        assert!(matches!(
            super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "expired"})),
            Err(TzapAuthError::ExpiredHandoff)
        ));
        assert!(matches!(
            super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "cancelled"})),
            Err(TzapAuthError::CancelledHandoff)
        ));
        assert!(matches!(
            super::TzapAuthRelayCompletion::from_json_value(&json!({"status": "failed"})),
            Err(TzapAuthError::FailedHandoff)
        ));
    }

    #[test]
    fn provider_discovery_parses_enabled_and_disabled_providers() {
        let discovery = TzapProviderDiscovery::from_json_value(&json!({
            "providers": [
                {
                    "id": "google",
                    "display_name": "Google",
                    "provider_type": "google",
                    "enabled": true,
                    "authorization_url": "https://login.tzap.org/auth/google",
                    "disabled_reason": null
                },
                {
                    "id": "email",
                    "display_name": "Email",
                    "provider_type": "email_otp",
                    "enabled": false,
                    "disabled_reason": "not_configured"
                }
            ]
        }))
        .unwrap();

        let google = discovery.provider("google").unwrap();
        assert_eq!(google.provider_type, TzapAuthProviderType::Google);
        assert_eq!(
            google.authorization_target().unwrap(),
            "https://login.tzap.org/auth/google"
        );

        let email = discovery.provider("email").unwrap();
        assert!(matches!(
            email.authorization_target(),
            Err(TzapAuthError::ProviderDisabled { provider_id, .. })
                if provider_id == "email"
        ));
    }

    #[test]
    fn provider_discovery_rejects_unsafe_disabled_redirects() {
        assert!(matches!(
            TzapProviderDiscovery::from_json_value(&json!({
                "providers": [{
                    "id": "github",
                    "display_name": "GitHub",
                    "provider_type": "github",
                    "enabled": false,
                    "authorization_url": "https://login.tzap.org/auth/github",
                    "disabled_reason": "policy_disabled"
                }]
            })),
            Err(TzapAuthError::DisabledProviderHasAuthorizationUrl { provider_id })
                if provider_id == "github"
        ));

        assert!(matches!(
            TzapProviderDiscovery::from_json_value(&json!({
                "providers": [{
                    "id": "github",
                    "display_name": "GitHub",
                    "provider_type": "github",
                    "enabled": true
                }]
            })),
            Err(TzapAuthError::EnabledProviderMissingAuthorizationUrl { provider_id })
                if provider_id == "github"
        ));
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
        session
            .require_audience(SESSION_AUDIENCE_SIGN_TZAP)
            .unwrap();
        assert!(matches!(
            session.require_audience("login.tzap.org"),
            Err(TzapAuthError::AudienceMismatch { expected, actual })
                if expected == "login.tzap.org" && actual == SESSION_AUDIENCE_SIGN_TZAP
        ));

        let mut store = InMemoryTzapSessionStore::new();
        store.save_session("default", session.clone());
        assert_eq!(store.load_session("default"), Some(session));
        store.clear_session("default");
        assert!(store.load_session("default").is_none());
    }

    #[test]
    fn auth_base_urls_are_owned_constants() {
        assert_eq!(SIGNUP_TZAP_BASE_URL, "https://signup.tzap.org");
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
            },
            last_request: std::cell::RefCell::new(None),
        };

        let current_user = fetch_current_user(&transport, SIGN_TZAP_BASE_URL, &session).unwrap();

        assert_eq!(current_user.display_name, "Ada Lovelace");
        assert_eq!(current_user.selected_org_id.as_deref(), Some("org_123"));
        assert_eq!(
            format!(
                "{:?}",
                transport.last_request().bearer_token.as_ref().unwrap()
            ),
            "TzapBearerToken(<redacted>)"
        );
    }

    fn pending_auth_state() -> TzapPendingAuthState {
        TzapPendingAuthState {
            state: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned(),
            provider_id: "github".to_owned(),
            redirect_uri: "zmanager://auth/callback".to_owned(),
            pkce: TzapPkcePair::from_verifier("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
                .unwrap(),
            created_at_unix_seconds: 100,
        }
    }

    fn hosted_auth_callback(
        pending: &TzapPendingAuthState,
        relay_body: Vec<u8>,
    ) -> TzapHostedAuthCallback {
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
            self.last_request
                .borrow()
                .as_ref()
                .expect("fake transport received request")
                .clone()
        }
    }

    impl TzapAuthHttpTransport for FakeAuthTransport {
        fn send(
            &self,
            request: &TzapAuthHttpRequest,
        ) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            assert_eq!(request.method, TzapAuthHttpMethod::Get);
            assert_eq!(request.url, "https://sign.tzap.org/v1/me");
            self.last_request.replace(Some(request.clone()));
            Ok(self.response.clone())
        }
    }
}
