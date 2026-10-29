//! The authenticated issuer, service routing, and durable login commit.

use crate::auth_client::{TzapAuthError, TzapHostedAuthEnvironment, TzapHostedAuthLaunchConfig};
use serde_json::{Value, json};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapSessionProvenance {
    pub environment: TzapHostedAuthEnvironment,
    pub auth_origin: String,
    pub account_origin: String,
    pub signing_origin: String,
    pub auth_flow_id: String,
}

impl TzapSessionProvenance {
    pub fn from_launch(config: &TzapHostedAuthLaunchConfig, flow_id: &str) -> Result<Self, TzapAuthError> {
        config.validate_for_environment(config.environment)?;
        let value = Self {
            environment: config.environment,
            auth_origin: endpoint_origin(&config.hosted_auth_base_url)?,
            account_origin: endpoint_origin(&config.hosted_account_base_url)?,
            signing_origin: endpoint_origin(&config.hosted_signing_base_url)?,
            auth_flow_id: flow_id.to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TzapAuthError> {
        validate_opaque_id(&self.auth_flow_id)?;
        for origin in [&self.auth_origin, &self.account_origin, &self.signing_origin] {
            if &endpoint_origin(origin)? != origin {
                return Err(TzapAuthError::InvalidSessionProvenance);
            }
        }
        let config = TzapHostedAuthLaunchConfig {
            environment: self.environment,
            client_id: "session-validation".to_owned(),
            redirect_uri: "tzap://auth/callback".to_owned(),
            hosted_auth_base_url: self.auth_origin.clone(),
            hosted_account_base_url: self.account_origin.clone(),
            hosted_signing_base_url: self.signing_origin.clone(),
            requested_audience: crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
            selected_org_id: None,
        };
        config.validate_for_environment(self.environment)
    }

    pub fn require_destination(&self, destination: &str) -> Result<(), TzapAuthError> {
        self.validate()?;
        let origin = request_origin(destination)?;
        if [&self.auth_origin, &self.account_origin, &self.signing_origin].contains(&&origin) { Ok(()) } else { Err(TzapAuthError::SessionOriginMismatch) }
    }

    pub fn require_signing_origin(&self, base_url: &str) -> Result<(), TzapAuthError> {
        self.validate()?;
        if endpoint_origin(base_url)? == self.signing_origin { Ok(()) } else { Err(TzapAuthError::SessionOriginMismatch) }
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "format_version": 1,
            "environment": environment_name(self.environment),
            "auth_origin": self.auth_origin,
            "account_origin": self.account_origin,
            "signing_origin": self.signing_origin,
            "auth_flow_id": self.auth_flow_id,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, TzapAuthError> {
        if value["format_version"].as_u64() != Some(1) {
            return Err(TzapAuthError::InvalidSessionProvenance);
        }
        let value = Self {
            environment: parse_environment(value["environment"].as_str().ok_or(TzapAuthError::InvalidSessionProvenance)?)?,
            auth_origin: field(value, "auth_origin")?,
            account_origin: field(value, "account_origin")?,
            signing_origin: field(value, "signing_origin")?,
            auth_flow_id: field(value, "auth_flow_id")?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[must_use]
pub const fn environment_name(environment: TzapHostedAuthEnvironment) -> &'static str {
    match environment {
        TzapHostedAuthEnvironment::Local => "local",
        TzapHostedAuthEnvironment::Staging => "staging",
        TzapHostedAuthEnvironment::Prod => "prod",
    }
}

pub fn parse_environment(value: &str) -> Result<TzapHostedAuthEnvironment, TzapAuthError> {
    match value {
        "local" => Ok(TzapHostedAuthEnvironment::Local),
        "staging" => Ok(TzapHostedAuthEnvironment::Staging),
        "prod" => Ok(TzapHostedAuthEnvironment::Prod),
        _ => Err(TzapAuthError::InvalidSessionProvenance),
    }
}

pub(crate) fn validate_opaque_id(value: &str) -> Result<(), TzapAuthError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte)) {
        return Err(TzapAuthError::InvalidSessionProvenance);
    }
    Ok(())
}

fn field(value: &Value, name: &str) -> Result<String, TzapAuthError> {
    value.get(name).and_then(Value::as_str).map(str::to_owned).ok_or(TzapAuthError::InvalidSessionProvenance)
}

fn endpoint_origin(value: &str) -> Result<String, TzapAuthError> {
    let parsed = url::Url::parse(value).map_err(|_| TzapAuthError::InvalidSessionProvenance)?;
    if parsed.path() != "/" || parsed.query().is_some() {
        return Err(TzapAuthError::InvalidSessionProvenance);
    }
    request_origin(value)
}

fn request_origin(value: &str) -> Result<String, TzapAuthError> {
    if value.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()) {
        return Err(TzapAuthError::InvalidSessionProvenance);
    }
    let parsed = url::Url::parse(value).map_err(|_| TzapAuthError::InvalidSessionProvenance)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TzapAuthError::InvalidSessionProvenance);
    }
    Ok(parsed.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_client::{TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken, TzapSessionRecord, fetch_current_user};
    use crate::trust::TzapIdentityAssurance;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn session() -> TzapSessionRecord {
        let mut session = TzapSessionRecord {
            user_id: Some("user_fixture_one".to_owned()),
            provenance: None,
            audience: "sign.tzap.org".to_owned(),
            access_token: TzapBearerToken::new("fixture-token-never-returned").unwrap(),
            expires_at_unix_seconds: 1000,
            identity_assurance: TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("fixture-session".to_owned()),
        };
        let config = TzapHostedAuthLaunchConfig::for_environment(TzapHostedAuthEnvironment::Staging, "zmanager-cli", "tzap://auth/callback");
        session.bind_provenance(TzapSessionProvenance::from_launch(&config, "fixture-flow").unwrap()).unwrap();
        session
    }

    struct ProfileTransport {
        calls: AtomicUsize,
        user_id: &'static str,
    }

    impl TzapAuthHttpTransport for ProfileTransport {
        fn send(&self, _: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(TzapAuthHttpResponse {
                status_code: 200,
                body: serde_json::to_vec(&json!({"user_id": self.user_id, "display_name": "Fixture Account"})).unwrap(),
                headers: Vec::new(),
            })
        }
    }

    #[test]
    fn wrong_origin_never_reaches_the_transport_and_a_valid_request_still_works() {
        let session = session();
        let transport = ProfileTransport { calls: AtomicUsize::new(0), user_id: "user_fixture_one" };
        for wrong in [
            "https://fixture-wrong.invalid",
            "https://staging.tzap.org.evil.invalid",
            "http://staging.tzap.org",
            "https://fixture@staging.tzap.org",
            "https://staging.tzap.org:444",
            "https://staging.tzap.org#fixture",
        ] {
            assert!(fetch_current_user(&transport, wrong, &session).is_err());
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fetch_current_user(&transport, "https://staging.tzap.org", &session).unwrap().user_id.as_deref(), Some("user_fixture_one"));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn authenticated_profile_must_agree_with_the_exchanged_principal() {
        let transport = ProfileTransport { calls: AtomicUsize::new(0), user_id: "user_fixture_other" };
        assert!(matches!(fetch_current_user(&transport, "https://staging.tzap.org", &session()), Err(TzapAuthError::SessionPrincipalMismatch)));
    }

    #[test]
    fn secure_round_trip_retains_principal_origins_and_commit_and_keeps_debug_redacted() {
        let session = session();
        let restored = TzapSessionRecord::from_secure_json(&session.to_secure_json()).unwrap();
        assert_eq!(restored, session);
        assert_eq!(restored.require_hosted_provenance().unwrap().auth_flow_id, "fixture-flow");
        assert!(!format!("{restored:?}").contains(session.access_token.expose()));
        assert!(restored.access_token.require_destination("https://fixture-wrong.invalid/v1/me").is_err());
    }

    #[test]
    fn legacy_or_malformed_session_cannot_claim_a_hosted_binding() {
        let mut json = session().to_secure_json();
        json.as_object_mut().unwrap().remove("provenance");
        assert!(matches!(TzapSessionRecord::from_secure_json(&json).unwrap().require_hosted_provenance(), Err(TzapAuthError::MissingSessionProvenance)));
        let mut json = session().to_secure_json();
        json["provenance"]["environment"] = json!("another-environment");
        assert!(TzapSessionRecord::from_secure_json(&json).is_err());
        let mut json = session().to_secure_json();
        json["user_id"] = Value::Null;
        assert!(TzapSessionRecord::from_secure_json(&json).is_err());
        let mut json = session().to_secure_json();
        json["provenance"]["signing_origin"] = json!("http://staging.tzap.org");
        assert!(TzapSessionRecord::from_secure_json(&json).is_err());
    }
}
