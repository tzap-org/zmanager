//! Client for the account-scoped contact-backup and key-backup endpoints
//! (design §8.5, §9.7), plus the email MFA step-up endpoints key-backup
//! restore depends on (`mobile-contact-book-tracker.md` C4).
//!
//! Both backup endpoints are opaque blob stores -- the server never parses
//! `payload`, so this client passes it through as `serde_json::Value`
//! unchanged. It performs no cryptography of its own: sealing/unsealing the
//! key-backup envelope and building/applying the contact snapshot are
//! `zmanager-core` concerns (`contact_snapshot`, `key_backup`), not this
//! transport layer's.

use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpTransport, TzapAuthRequestOptions, TzapSessionRecord};
use crate::http_client::{http_error_body, require_success, send_json_request, send_json_request_with_headers};
use crate::json_util::{json_object, required_field, required_string, required_u64};
use serde_json::Value;
use std::fmt;

pub const CONTACT_BACKUP_PATH: &str = "/v1/me/contact-backup";
pub const KEY_BACKUP_LIST_PATH: &str = "/v1/me/key-backup";
pub const MFA_EMAIL_START_PATH: &str = "/v1/me/mfa/email/start";
pub const MFA_STEP_UP_PATH: &str = "/v1/me/mfa/step-up";

fn key_backup_device_path(public_device_id: &str) -> String {
    format!("{KEY_BACKUP_LIST_PATH}/{public_device_id}")
}

/// A stored backup blob (contact snapshot or key-backup envelope) plus the
/// version needed for `If-Match` on the next write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapBackupRecord {
    pub version: u64,
    pub updated_at: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapKeyBackupRecord {
    pub public_device_id: String,
    pub version: u64,
    pub updated_at: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapKeyBackupList {
    pub device_ids: Vec<String>,
    pub items: Vec<TzapKeyBackupRecord>,
}

#[derive(Debug)]
pub enum TzapBackupError {
    Auth(TzapAuthError),
    /// No backup exists yet (404) -- distinct from a wrong password, which
    /// is a `zmanager_core::key_backup::TzapKeyBackupError` the caller sees
    /// only after a successful fetch (design §9.0, §12).
    NotFound,
    /// `If-Match` didn't match the current version (412): the caller should
    /// re-fetch, merge, and retry once (design §8.3).
    PreconditionFailed,
    /// The key-backup read needs a fresh MFA step-up (403 `admin_mfa_required`,
    /// design §9.7, C4) -- never returned for contact-backup or for a write.
    AdminMfaRequired,
    InvalidField {
        field: &'static str,
    },
    HttpStatus {
        status_code: u16,
        body: Option<String>,
    },
}

impl fmt::Display for TzapBackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "backup request failed: {error}"),
            Self::NotFound => write!(f, "no backup exists"),
            Self::PreconditionFailed => write!(f, "backup version mismatch"),
            Self::AdminMfaRequired => write!(f, "MFA step-up is required"),
            Self::InvalidField { field } => write!(f, "backup response field is invalid: {field}"),
            Self::HttpStatus { status_code, body } => match body {
                Some(body) => write!(f, "backup request failed with status {status_code}: {body}"),
                None => write!(f, "backup request failed with status {status_code}"),
            },
        }
    }
}

impl std::error::Error for TzapBackupError {}

impl From<TzapAuthError> for TzapBackupError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

/// Maps a non-2xx backup-endpoint response to a typed error, recognizing the
/// specific statuses/error-codes callers need to branch on.
fn classify_error(status_code: u16, response: &crate::auth_client::TzapAuthHttpResponse) -> TzapBackupError {
    if status_code == 404 {
        return TzapBackupError::NotFound;
    }
    if status_code == 412 {
        return TzapBackupError::PreconditionFailed;
    }
    if status_code == 403 {
        let is_admin_mfa_required = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|value| value.get("error").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|error| error == "admin_mfa_required");
        if is_admin_mfa_required {
            return TzapBackupError::AdminMfaRequired;
        }
    }
    TzapBackupError::HttpStatus { status_code, body: http_error_body(&response.body) }
}

fn parse_backup_record(body: &[u8]) -> Result<TzapBackupRecord, TzapBackupError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| TzapBackupError::InvalidField { field: "$" })?;
    let object = json_object::<TzapBackupError>(&value, "$")?;
    Ok(TzapBackupRecord {
        version: required_u64::<TzapBackupError>(object, "version")?,
        updated_at: required_string::<TzapBackupError>(object, "updated_at")?,
        payload: required_field::<TzapBackupError>(object, "payload")?.clone(),
    })
}

fn parse_key_backup_record(body: &[u8]) -> Result<TzapKeyBackupRecord, TzapBackupError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| TzapBackupError::InvalidField { field: "$" })?;
    let object = json_object::<TzapBackupError>(&value, "$")?;
    Ok(TzapKeyBackupRecord {
        public_device_id: required_string::<TzapBackupError>(object, "public_device_id")?,
        version: required_u64::<TzapBackupError>(object, "version")?,
        updated_at: required_string::<TzapBackupError>(object, "updated_at")?,
        payload: required_field::<TzapBackupError>(object, "payload")?.clone(),
    })
}

fn parse_key_backup_list(body: &[u8]) -> Result<TzapKeyBackupList, TzapBackupError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| TzapBackupError::InvalidField { field: "$" })?;
    let object = json_object::<TzapBackupError>(&value, "$")?;
    let device_ids = required_field::<TzapBackupError>(object, "device_ids")?
        .as_array()
        .ok_or(TzapBackupError::InvalidField { field: "device_ids" })?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(TzapBackupError::InvalidField { field: "device_ids[]" }))
        .collect::<Result<Vec<_>, _>>()?;
    let items = required_field::<TzapBackupError>(object, "items")?
        .as_array()
        .ok_or(TzapBackupError::InvalidField { field: "items" })?
        .iter()
        .map(|value| {
            let object = json_object::<TzapBackupError>(value, "items[]")?;
            Ok::<_, TzapBackupError>(TzapKeyBackupRecord {
                public_device_id: required_string::<TzapBackupError>(object, "public_device_id")?,
                version: required_u64::<TzapBackupError>(object, "version")?,
                updated_at: required_string::<TzapBackupError>(object, "updated_at")?,
                payload: required_field::<TzapBackupError>(object, "payload")?.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TzapKeyBackupList { device_ids, items })
}

fn if_match_header(version: Option<u64>) -> Vec<(String, String)> {
    match version {
        Some(version) => vec![("If-Match".to_owned(), version.to_string())],
        None => Vec::new(),
    }
}

/// Client for `/v1/me/contact-backup`, `/v1/me/key-backup*`, and the email
/// MFA step-up endpoints, over a caller-supplied transport (design §8.5,
/// §9.7; C4).
pub struct TzapBackupClient<'a, T> {
    sign_base_url: String,
    transport: &'a T,
}

impl<'a, T: TzapAuthHttpTransport> TzapBackupClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self { sign_base_url: sign_base_url.into(), transport }
    }

    pub fn fetch_contact_backup(&self, session: &TzapSessionRecord) -> Result<TzapBackupRecord, TzapBackupError> {
        let response = self.send(TzapAuthHttpMethod::Get, CONTACT_BACKUP_PATH, session, None, Vec::new())?;
        parse_backup_record(&response.body)
    }

    pub fn put_contact_backup(&self, session: &TzapSessionRecord, payload: Value, if_match: Option<u64>) -> Result<TzapBackupRecord, TzapBackupError> {
        let response = self.send(TzapAuthHttpMethod::Put, CONTACT_BACKUP_PATH, session, Some(payload), if_match_header(if_match))?;
        parse_backup_record(&response.body)
    }

    pub fn delete_contact_backup(&self, session: &TzapSessionRecord) -> Result<(), TzapBackupError> {
        self.send(TzapAuthHttpMethod::Delete, CONTACT_BACKUP_PATH, session, None, Vec::new())?;
        Ok(())
    }

    pub fn list_key_backups(&self, session: &TzapSessionRecord) -> Result<TzapKeyBackupList, TzapBackupError> {
        let response = self.send(TzapAuthHttpMethod::Get, KEY_BACKUP_LIST_PATH, session, None, Vec::new())?;
        parse_key_backup_list(&response.body)
    }

    pub fn fetch_key_backup(&self, session: &TzapSessionRecord, public_device_id: &str) -> Result<TzapKeyBackupRecord, TzapBackupError> {
        let response = self.send(TzapAuthHttpMethod::Get, &key_backup_device_path(public_device_id), session, None, Vec::new())?;
        parse_key_backup_record(&response.body)
    }

    pub fn put_key_backup(
        &self,
        session: &TzapSessionRecord,
        public_device_id: &str,
        payload: Value,
        if_match: Option<u64>,
    ) -> Result<TzapKeyBackupRecord, TzapBackupError> {
        let response = self.send(TzapAuthHttpMethod::Put, &key_backup_device_path(public_device_id), session, Some(payload), if_match_header(if_match))?;
        parse_key_backup_record(&response.body)
    }

    pub fn delete_key_backup(&self, session: &TzapSessionRecord, public_device_id: &str) -> Result<(), TzapBackupError> {
        self.send(TzapAuthHttpMethod::Delete, &key_backup_device_path(public_device_id), session, None, Vec::new())?;
        Ok(())
    }

    /// Sends a one-time code to the account's verified email
    /// (`POST /v1/me/mfa/email/start`, C4). Call this after a key-backup read
    /// returns [`TzapBackupError::AdminMfaRequired`], then collect a code from
    /// the user and call [`Self::verify_step_up`] before retrying the read.
    pub fn start_email_step_up(&self, session: &TzapSessionRecord) -> Result<(), TzapBackupError> {
        self.send(TzapAuthHttpMethod::Post, MFA_EMAIL_START_PATH, session, None, Vec::new())?;
        Ok(())
    }

    /// Verifies a step-up code (email or TOTP -- the server tries every
    /// active factor) so the account's session satisfies `requireRecent` for
    /// the freshness window.
    pub fn verify_step_up(&self, session: &TzapSessionRecord, code: &str) -> Result<(), TzapBackupError> {
        self.send(TzapAuthHttpMethod::Post, MFA_STEP_UP_PATH, session, Some(serde_json::json!({ "code": code })), Vec::new())?;
        Ok(())
    }

    fn send(
        &self,
        method: TzapAuthHttpMethod,
        path: &str,
        session: &TzapSessionRecord,
        body: Option<Value>,
        headers: Vec<(String, String)>,
    ) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapBackupError> {
        let response = if headers.is_empty() {
            send_json_request(self.transport, method, &self.sign_base_url, path, Some(session.access_token.clone()), body)?
        } else {
            send_json_request_with_headers(
                self.transport,
                method,
                &self.sign_base_url,
                path,
                Some(session.access_token.clone()),
                body,
                headers,
                TzapAuthRequestOptions::default(),
            )?
        };
        require_success(response, classify_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_client::TzapAuthHttpRequest;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockTransport<F> {
        requests: Mutex<Vec<TzapAuthHttpRequest>>,
        handler: F,
    }

    impl<F> MockTransport<F>
    where
        F: Fn(&TzapAuthHttpRequest) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapAuthError> + Send + Sync,
    {
        fn new(handler: F) -> Self {
            Self { requests: Mutex::new(Vec::new()), handler }
        }
    }

    impl<F> TzapAuthHttpTransport for MockTransport<F>
    where
        F: Fn(&TzapAuthHttpRequest) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapAuthError> + Send + Sync,
    {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapAuthError> {
            self.requests.lock().unwrap().push(request.clone());
            (self.handler)(request)
        }
    }

    fn test_session() -> TzapSessionRecord {
        TzapSessionRecord {
            audience: crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            access_token: crate::auth_client::TzapBearerToken::new("test-token").unwrap(),
            expires_at_unix_seconds: 9_999_999_999,
            identity_assurance: crate::trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("login-session-1".to_owned()),
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
    fn json_ok(status_code: u16, body: Value) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapAuthError> {
        Ok(crate::auth_client::TzapAuthHttpResponse { status_code, body: serde_json::to_vec(&body).unwrap(), headers: Vec::new() })
    }

    fn error_response(status_code: u16, error: &str) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapAuthError> {
        json_ok(status_code, serde_json::json!({ "error": error, "message": "test" }))
    }

    #[test]
    fn fetch_contact_backup_parses_version_and_payload() {
        let transport =
            MockTransport::new(|_| json_ok(200, serde_json::json!({ "version": 3, "updated_at": "2026-01-01T00:00:00Z", "payload": { "format": "plain" } })));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let record = client.fetch_contact_backup(&test_session()).unwrap();
        assert_eq!(record.version, 3);
        assert_eq!(record.payload, serde_json::json!({ "format": "plain" }));

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0].method, TzapAuthHttpMethod::Get));
        assert!(requests[0].url.ends_with(CONTACT_BACKUP_PATH));
    }

    #[test]
    fn fetch_contact_backup_maps_404_to_not_found() {
        let transport = MockTransport::new(|_| error_response(404, "contact_backup_not_found"));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let error = client.fetch_contact_backup(&test_session()).unwrap_err();
        assert!(matches!(error, TzapBackupError::NotFound));
    }

    #[test]
    fn put_contact_backup_sends_if_match_header_and_maps_412() {
        let transport = MockTransport::new(|_| error_response(412, "precondition_failed"));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let error = client.put_contact_backup(&test_session(), serde_json::json!({}), Some(5)).unwrap_err();
        assert!(matches!(error, TzapBackupError::PreconditionFailed));

        let requests = transport.requests.lock().unwrap();
        assert!(matches!(requests[0].method, TzapAuthHttpMethod::Put));
        assert!(requests[0].headers.iter().any(|(name, value)| name == "If-Match" && value == "5"));
    }

    #[test]
    fn list_key_backups_parses_device_ids_and_items() {
        let transport = MockTransport::new(|_| {
            json_ok(
                200,
                serde_json::json!({
                    "device_ids": ["pdev_1", "pdev_2"],
                    "items": [
                        { "public_device_id": "pdev_1", "version": 1, "updated_at": "2026-01-01T00:00:00Z", "payload": {"format": "v1"} },
                        { "public_device_id": "pdev_2", "version": 2, "updated_at": "2026-01-02T00:00:00Z", "payload": {"format": "v1"} }
                    ]
                }),
            )
        });
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let list = client.list_key_backups(&test_session()).unwrap();
        assert_eq!(list.device_ids, vec!["pdev_1", "pdev_2"]);
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[1].public_device_id, "pdev_2");
    }

    #[test]
    fn key_backup_read_maps_403_admin_mfa_required_distinctly_from_other_403s() {
        let transport = MockTransport::new(|_| error_response(403, "admin_mfa_required"));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let error = client.fetch_key_backup(&test_session(), "pdev_1").unwrap_err();
        assert!(matches!(error, TzapBackupError::AdminMfaRequired));

        let transport = MockTransport::new(|_| error_response(403, "some_other_forbidden_reason"));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        let error = client.fetch_key_backup(&test_session(), "pdev_1").unwrap_err();
        assert!(matches!(error, TzapBackupError::HttpStatus { status_code: 403, .. }));
    }

    #[test]
    fn start_email_step_up_and_verify_step_up_hit_the_expected_paths() {
        let transport = MockTransport::new(|_| json_ok(200, serde_json::json!({ "expires_at": "2026-01-01T00:10:00Z", "dev_code": "123456" })));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        client.start_email_step_up(&test_session()).unwrap();
        {
            let requests = transport.requests.lock().unwrap();
            assert!(requests[0].url.ends_with(MFA_EMAIL_START_PATH));
            assert!(requests[0].body.is_none());
        }

        let transport =
            MockTransport::new(|_| json_ok(200, serde_json::json!({ "capabilities": ["totp", "email"], "factors": [], "step_up_required": false })));
        let client = TzapBackupClient::new("https://sign.tzap.org", &transport);
        client.verify_step_up(&test_session(), "654321").unwrap();
        let requests = transport.requests.lock().unwrap();
        assert!(requests[0].url.ends_with(MFA_STEP_UP_PATH));
        assert_eq!(requests[0].body, Some(serde_json::json!({ "code": "654321" })));
    }
}
