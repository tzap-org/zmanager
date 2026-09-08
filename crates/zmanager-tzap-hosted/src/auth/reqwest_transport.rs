//! The concrete HTTPS transport used by native FFI consumers.
//!
//! The hosted crate keeps its protocol clients transport-agnostic so the CLI,
//! mobile shells, and tests can supply their own policy. Mobile needs a
//! shared implementation, however, otherwise every shell would reimplement
//! the enrollment and handoff HTTP flows.

use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken};
use crate::http_client::{require_success, send_json_request};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Copy, Default)]
pub struct ReqwestTransport;

impl TzapAuthHttpTransport for ReqwestTransport {
    fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(request.options.connect_timeout)
            .timeout(request.options.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| TzapAuthError::Transport { message: error.to_string() })?;

        let mut builder = match request.method {
            TzapAuthHttpMethod::Get => client.get(&request.url),
            TzapAuthHttpMethod::Post => client.post(&request.url),
            TzapAuthHttpMethod::Put => client.put(&request.url),
            TzapAuthHttpMethod::Delete => client.delete(&request.url),
        }
        .header(reqwest::header::ACCEPT, "application/json");

        if let Some(token) = &request.bearer_token {
            builder = builder.bearer_auth(token.expose());
        }
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }

        let response = builder.send().map_err(|error| TzapAuthError::Transport { message: error.to_string() })?;
        let status_code = response.status().as_u16();
        let headers =
            response.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect();
        let body = response.bytes().map_err(|error| TzapAuthError::Transport { message: error.to_string() })?.to_vec();
        Ok(TzapAuthHttpResponse { status_code, body, headers })
    }
}

/// Fetches the first server-published trust root as PEM. Trust-root discovery
/// is protocol work, so callers such as mobile use this shared implementation
/// instead of duplicating the HTTP, JSON, URL, and PEM checks in each shell.
pub fn fetch_trust_root_pem(service_base_url: &str) -> Result<String, String> {
    let response =
        send_json_request(&ReqwestTransport, TzapAuthHttpMethod::Get, service_base_url, "/v1/trust/roots", None, None).map_err(|error| error.to_string())?;
    let response = require_success(response, |status_code, _| TzapAuthError::HttpStatus { status_code }).map_err(|error| error.to_string())?;
    let roots: Value = serde_json::from_slice(&response.body).map_err(|error| format!("invalid trust-root response: {error}"))?;
    let root = roots
        .get("roots")
        .and_then(Value::as_array)
        .and_then(|roots| roots.first())
        .or_else(|| roots.as_array().and_then(|roots| roots.first()))
        .ok_or_else(|| "the staging server returned no trust root".to_owned())?;
    let pem_url = root
        .get("certificatePemUrl")
        .or_else(|| root.get("certificate_pem_url"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "the staging server returned no trust-root URL".to_owned())?;
    let pem_url = if pem_url.starts_with("http://") || pem_url.starts_with("https://") {
        pem_url.to_owned()
    } else {
        format!("{}/{}", service_base_url.trim_end_matches('/'), pem_url.trim_start_matches('/'))
    };
    let request = TzapAuthHttpRequest {
        method: TzapAuthHttpMethod::Get,
        url: pem_url,
        bearer_token: None,
        body: None,
        options: crate::auth_client::TzapAuthRequestOptions::default(),
        headers: Vec::new(),
    };
    let pem_response = ReqwestTransport.send(&request).map_err(|error| error.to_string())?;
    let pem_response = require_success(pem_response, |status_code, _| TzapAuthError::HttpStatus { status_code }).map_err(|error| error.to_string())?;
    let pem = String::from_utf8(pem_response.body).map_err(|error| format!("trust root response was not UTF-8: {error}"))?;
    if !pem.contains("BEGIN CERTIFICATE") {
        return Err("the staging trust root was invalid".to_owned());
    }
    Ok(pem)
}

/// Exchanges the one-time callback code for a Rust-internal serialized session
/// handoff envelope. The code and resulting session token never leave this
/// function as a loggable return value or enter the callback URL.
pub fn exchange_handoff_code(
    auth_base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce_verifier: &str,
    handoff_code: &str,
) -> Result<Vec<u8>, String> {
    exchange_handoff_code_for_audience(
        auth_base_url,
        client_id,
        redirect_uri,
        state,
        pkce_verifier,
        handoff_code,
        crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP,
    )
}

/// Exchanges a handoff code for a specific, server-defined session audience.
/// The caller must use one of the audiences supported by the product flow;
/// arbitrary audience strings must never be accepted from the callback.
pub fn exchange_handoff_code_for_audience(
    auth_base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce_verifier: &str,
    handoff_code: &str,
    required_audience: &str,
) -> Result<Vec<u8>, String> {
    if !matches!(required_audience, crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP | crate::auth_client::SESSION_AUDIENCE_LOGIN_TZAP) {
        return Err("unsupported hosted session audience".to_owned());
    }
    let body = json!({
        "handoff_code": handoff_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_verifier": pkce_verifier,
        "required_audience": required_audience,
    });
    let response = send_json_request(&ReqwestTransport, TzapAuthHttpMethod::Post, auth_base_url, "/auth/session/exchange", None::<TzapBearerToken>, Some(body))
        .map_err(|error| error.to_string())?;
    let response = require_success(response, |status_code, _| TzapAuthError::HttpStatus { status_code }).map_err(|error| error.to_string())?;
    let exchange: Value = serde_json::from_slice(&response.body).map_err(|error| format!("invalid auth exchange response: {error}"))?;
    let session_token = exchange
        .get("session_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "auth exchange response is missing session_token".to_owned())?;
    let session_id = exchange
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "auth exchange response is missing session_id".to_owned())?;
    let audience = exchange.get("audience").and_then(Value::as_str).unwrap_or(crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP);
    let expires_at_unix_seconds = exchange
        .get("expires_at_unix_seconds")
        .and_then(Value::as_u64)
        .or_else(|| {
            exchange
                .get("expires_at")
                .and_then(Value::as_str)
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                .map(OffsetDateTime::unix_timestamp)
                .and_then(|value| u64::try_from(value).ok())
        })
        .ok_or_else(|| "auth exchange response is missing an expiration time".to_owned())?;
    let identity_assurance =
        exchange.get("identity_assurance").or_else(|| exchange.get("identity_assurance_level")).and_then(Value::as_str).unwrap_or("oauth_verified_email");

    serde_json::to_vec(&json!({
        "status": "ok",
        "session": {
            "audience": audience,
            "access_token": session_token,
            "expires_at_unix_seconds": expires_at_unix_seconds,
            "identity_assurance": identity_assurance,
            "selected_org_id": exchange.get("selected_org_id").cloned().unwrap_or(Value::Null),
            "login_session_id": session_id,
        }
    }))
    .map_err(|error| error.to_string())
}
