#![cfg_attr(not(feature = "tzap-online"), allow(dead_code, unused_imports))]

use super::TzapCliContext;
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{command_usage_error, json_escape, json_optional_string, print_error_line};
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn parse_tzap_context_args(args: &[String], global: &mut GlobalOptions, command: &str) -> Result<TzapCliContext, ExitCode> {
    let mut context = TzapCliContext::default();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error(command, &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, command, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        return Err(command_usage_error(command, &format!("unknown {command} option: {}", args[index]), global));
    }
    Ok(context)
}

pub(super) fn parse_cert_id_operation_args(args: &[String], global: &mut GlobalOptions, command: &str) -> Result<(TzapCliContext, String), ExitCode> {
    let mut context = TzapCliContext::default();
    let mut certificate_id = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error(command, &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, command, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        match args[index].as_str() {
            "--certificate-id" => {
                certificate_id = Some(take_value(args, &mut index, "--certificate-id").map_err(|error| command_usage_error(command, &error, global))?);
            }
            other => {
                return Err(command_usage_error(command, &format!("unknown {command} option: {other}"), global));
            }
        }
    }
    let Some(certificate_id) = certificate_id else {
        return Err(command_usage_error(command, "missing --certificate-id", global));
    };
    Ok((context, certificate_id))
}

pub(super) fn parse_tzap_context_option(
    args: &[String],
    index: &mut usize,
    context: &mut TzapCliContext,
    command: &str,
    global: &GlobalOptions,
) -> Result<bool, ExitCode> {
    match args[*index].as_str() {
        "--state-dir" => {
            context.state_dir = PathBuf::from(take_value(args, index, "--state-dir").map_err(|error| command_usage_error(command, &error, global))?);
        }
        "--account-key" => {
            context.account_key = take_value(args, index, "--account-key").map_err(|error| command_usage_error(command, &error, global))?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(feature = "tzap-online")]
pub(super) fn parse_environment_option(
    args: &[String],
    index: &mut usize,
    environment: &mut zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment,
    global: &GlobalOptions,
) -> Result<(), ExitCode> {
    let value = take_value(args, index, "--environment").map_err(|error| command_usage_error("auth", &error, global))?;
    *environment = match value.as_str() {
        "local" => zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Local,
        "staging" => zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Staging,
        "prod" => zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Prod,
        _ => return Err(command_usage_error("auth", "environment must be local, staging, or prod", global)),
    };
    Ok(())
}

pub(super) fn print_stable_tzap_error(operation: &str, message: &str, global: &GlobalOptions) {
    if global.json {
        println!("{{\"ok\":false,\"operation\":\"{}\",\"error\":\"{}\"}}", json_escape(operation), json_escape(message));
    } else {
        print_error_line(global, format_args!("{operation} failed: {message}"));
    }
}
pub(super) fn certificate_summary_value(cert: &zmanager_core::local_identity_store::TzapEnrolledCertificateRecord) -> serde_json::Value {
    json!({
        "certificate_id": cert.certificate_id,
        "certificate_sha256": cert.certificate_sha256,
        "state": cert.state.as_str(),
        "not_before_unix_seconds": cert.not_before_unix_seconds,
        "not_after_unix_seconds": cert.not_after_unix_seconds,
        "public_signer_id": cert.public_metadata.public_signer_id,
        "public_org_id": cert.public_metadata.public_org_id,
        "public_device_id": cert.public_metadata.public_device_id,
        "assurance_level": cert.public_metadata.assurance_level.as_str(),
    })
}

#[cfg(feature = "tzap-online")]
#[allow(clippy::needless_pass_by_value)]
pub(super) fn retirement_completion_label(completion: zmanager_tzap_hosted::certificate_lifecycle::TzapRetirementCompletion) -> &'static str {
    match completion {
        zmanager_tzap_hosted::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        zmanager_tzap_hosted::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
}

pub(super) fn current_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

pub(super) fn read_bytes_argument(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::stdin(), &mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

pub(super) fn read_json_argument(path: &str) -> Result<Value, String> {
    let bytes = read_bytes_argument(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

pub(super) fn write_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    // A failed or interrupted export must leave an existing envelope/card
    // intact. Reuse the core's durable atomic replacement and private modes.
    zmanager_core::write_atomic_secret_file(path, &bytes)
}

#[cfg(feature = "tzap-online")]
#[derive(Debug, Clone, Copy)]
pub(super) struct CliHttpJsonTransport;

#[cfg(feature = "tzap-online")]
impl zmanager_tzap_hosted::auth_client::TzapAuthHttpTransport for CliHttpJsonTransport {
    fn send(
        &self,
        request: &zmanager_tzap_hosted::auth_client::TzapAuthHttpRequest,
    ) -> Result<zmanager_tzap_hosted::auth_client::TzapAuthHttpResponse, zmanager_tzap_hosted::auth_client::TzapAuthError> {
        let method = match request.method {
            zmanager_tzap_hosted::auth_client::TzapAuthHttpMethod::Get => "GET",
            zmanager_tzap_hosted::auth_client::TzapAuthHttpMethod::Post => "POST",
            zmanager_tzap_hosted::auth_client::TzapAuthHttpMethod::Put => "PUT",
            zmanager_tzap_hosted::auth_client::TzapAuthHttpMethod::Delete => "DELETE",
        };
        http_json_request(
            method,
            &request.url,
            request.bearer_token.as_ref().map(zmanager_tzap_hosted::auth_client::TzapBearerToken::expose),
            request.body.as_ref(),
            &request.headers,
            &request.options,
        )
        .map_err(|message| zmanager_tzap_hosted::auth_client::TzapAuthError::Transport { message })
    }
}

#[cfg(feature = "tzap-online")]
pub(super) fn http_json_request(
    method: &str,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&Value>,
    headers: &[(String, String)],
    options: &zmanager_tzap_hosted::auth_client::TzapAuthRequestOptions,
) -> Result<zmanager_tzap_hosted::auth_client::TzapAuthHttpResponse, String> {
    if options.cancellation.as_ref().is_some_and(zmanager_tzap_hosted::auth_client::TzapAuthCancellation::is_cancelled) {
        return Err("hosted HTTPS request was cancelled".to_owned());
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(options.connect_timeout)
        .timeout(options.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("could not initialize hosted HTTPS client: {error}"))?;
    let request = build_hosted_http_request(&client, method, url, bearer_token, body, headers)?;
    let response = client.execute(request).map_err(|error| format!("hosted HTTPS request failed: {error}"))?;
    if options.cancellation.as_ref().is_some_and(zmanager_tzap_hosted::auth_client::TzapAuthCancellation::is_cancelled) {
        return Err("hosted HTTPS request was cancelled".to_owned());
    }
    let status_code = response.status().as_u16();
    let response_headers =
        response.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_owned(), value.to_owned()))).collect();
    let response_body = response.bytes().map_err(|error| format!("could not read hosted HTTPS response: {error}"))?.to_vec();

    #[cfg(feature = "staging-e2e-fault-injection")]
    let crash_after_issuance_commit = (200..300).contains(&status_code)
        && method == "POST"
        && reqwest::Url::parse(url).is_ok_and(|parsed| {
            if parsed.scheme() != "https" || parsed.host_str() != Some("staging.tzap.org") {
                return false;
            }
            let path = parsed.path();
            let enrollment_fault = std::env::var("ZM_STAGING_E2E_CRASH_AFTER_ENROLLMENT_COMMIT").ok().as_deref() == Some("1")
                && path == zmanager_tzap_hosted::enrollment_client::ENROLL_CERTIFICATES_PATH;
            let renewal_fault = std::env::var("ZM_STAGING_E2E_CRASH_AFTER_RENEWAL_COMMIT").ok().as_deref() == Some("1")
                && path.strip_prefix("/v1/certificates/").is_some_and(|suffix| {
                    let mut parts = suffix.split('/');
                    parts.next().is_some_and(|certificate_id| !certificate_id.is_empty()) && parts.next() == Some("renew") && parts.next().is_none()
                });
            enrollment_fault || renewal_fault
        });
    #[cfg(feature = "staging-e2e-fault-injection")]
    if crash_after_issuance_commit {
        // This process-level exit deliberately leaves the already-persisted
        // enrollment/renewal journal behind, simulating a lost reply and crash.
        std::process::exit(86);
    }

    Ok(zmanager_tzap_hosted::auth_client::TzapAuthHttpResponse { status_code, body: response_body, headers: response_headers })
}

#[cfg(feature = "tzap-online")]
pub(crate) fn build_hosted_http_request(
    client: &reqwest::blocking::Client,
    method: &str,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&Value>,
    headers: &[(String, String)],
) -> Result<reqwest::blocking::Request, String> {
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|error| format!("invalid hosted HTTP method: {error}"))?;
    let mut request = client.request(method, url).header(reqwest::header::ACCEPT, "application/json");
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    request.build().map_err(|error| format!("invalid hosted HTTPS request: {error}"))
}

/// Builds a `tzap_service` JSON request carrying the CLI context (CR-113:
/// the CLI delegates to the same `core::tzap_service` endpoints the FFI
/// calls, so the hosted-TZAP operations have one implementation path).
pub(super) fn service_request(context: &TzapCliContext, extra: Value) -> Value {
    let mut request = json!({
        "state_dir": context.state_dir.display().to_string(),
        "account_key": context.account_key,
    });
    if let Value::Object(extra) = extra {
        for (key, value) in extra {
            request[key] = value;
        }
    }
    request
}

/// Parses a `tzap_service` response envelope, returning the payload on
/// `ok: true` and the error message otherwise.
pub(super) fn service_envelope(response: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(response).map_err(|error| format!("invalid service response: {error}"))?;
    if value.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        Ok(value)
    } else {
        Err(value.get("message").and_then(Value::as_str).map_or_else(|| "service request failed".to_owned(), str::to_owned))
    }
}

/// Renders the session summary from the service envelope (CR-113: the CLI
/// keeps its output shape but the session content comes from the service).
#[cfg(feature = "tzap-online")]
pub(super) fn print_session_summary_json(session: &Value, global: &GlobalOptions) {
    let audience = session["audience"].as_str().unwrap_or_default();
    let expires_at_unix_seconds = session["expires_at_unix_seconds"].as_u64().unwrap_or(0);
    let expired = session["expired"].as_bool().unwrap_or(false);
    let identity_assurance = session["identity_assurance"].as_str().unwrap_or_default();
    let selected_org_id = session["selected_org_id"].as_str();
    let login_session_id = session["login_session_id"].as_str();
    if global.json {
        println!(
            "{{\"authenticated\":true,\"audience\":\"{}\",\"expires_at_unix_seconds\":{},\"expired\":{},\"identity_assurance\":\"{}\",\"selected_org_id\":{},\"login_session_id\":{}}}",
            json_escape(audience),
            expires_at_unix_seconds,
            expired,
            json_escape(identity_assurance),
            json_optional_string(selected_org_id),
            json_optional_string(login_session_id)
        );
    } else {
        let status = if expired { "expired" } else { "active" };
        println!("{status} session for {audience} ({identity_assurance})");
    }
}
