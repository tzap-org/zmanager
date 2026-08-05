//! TZAP service endpoints in the JSON wire format consumed by shell UIs.
//!
//! This module is ported from the legacy `zmanager_ffi_*` C-ABI facade.
//! Each endpoint parses a JSON request, orchestrates `zmanager-core`, and
//! returns a JSON response envelope. The wire contracts are the same as the
//! legacy facade; the FFI crate declares them as UniFFI functions.

use std::fs;
use std::path::{Path, PathBuf};
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

use crate::trust;

use crate::auth_client::TzapSessionStore;
use crate::jobs::{CancellationToken, JobEvent};
use crate::local_identity_store::{
    FileTzapLocalIdentityStore, TzapContactRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapRecipientEncryptionKeyRecord,
};
use crate::manifest::PlanOptions;
use crate::secrets::SecretString;
use crate::tzap_backend::{TzapCreateOptions, TzapKeySource, TzapX509TrustOptions};
use crate::x509_format::{hex_lower, x509_name_to_string};

const TZAP_DEFAULT_COMPRESSION_LEVEL: i32 = 3;
const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
const SELF_SIGNED_IDENTITY_RSA_BITS: u32 = 3072;
const SELF_SIGNED_IDENTITY_VALID_DAYS: u32 = 3_650;
const SELF_SIGNED_IDENTITY_SERIAL_BITS: i32 = 159;
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
const DEFAULT_TZAP_REDIRECT_URI: &str = "zmanager://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const DEFAULT_TZAP_ACCOUNT_KEY: &str = "default";
const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";
const OP_CERT_ENROLL: &str = "cert_enroll";
const OP_CERT_RENEW: &str = "cert_renew";
const OP_CERT_REVOKE: &str = "cert_revoke";
const OP_DEVICE_RETIRE: &str = "device_retire";
const MISSING_TZAP_SESSION: &str = "no local TZAP session";
const DEV_ONLY_SELF_SIGNED_IDENTITY_KIND: &str = "dev_only_self_signed_x509_identity";

struct TzapFfiContext {
    state_dir: PathBuf,
    account_key: String,
}

impl TzapFfiContext {
    fn from_request(request: &Value) -> Result<Self, String> {
        Ok(Self {
            state_dir: request_path(request, "state_dir")?.unwrap_or_else(default_tzap_state_dir),
            account_key: request_string(request, "account_key")?.unwrap_or_else(|| DEFAULT_TZAP_ACCOUNT_KEY.to_owned()),
        })
    }
}

#[derive(Debug, Clone)]
struct TzapFfiSessionStore {
    path: PathBuf,
}

impl TzapFfiSessionStore {
    fn new(state_dir: &Path) -> Self {
        Self { path: state_dir.join(AUTH_SESSION_FILE) }
    }
}

impl TzapSessionStore for TzapFfiSessionStore {
    fn save_session(
        &mut self,
        account_key: &str,
        session: crate::auth_client::TzapSessionRecord,
    ) -> Result<(), crate::auth_client::TzapAuthError> {
        let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
        if !root.is_object() {
            root = json!({ "sessions": {} });
        }
        root["sessions"][account_key] = session_json(&session, true);
        write_secret_json_file(&self.path, &root).map_err(|error| crate::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }

    fn load_session(&self, account_key: &str) -> Option<crate::auth_client::TzapSessionRecord> {
        let root = read_json_file(&self.path)?;
        session_from_json(root.get("sessions")?.get(account_key)?).ok()
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), crate::auth_client::TzapAuthError> {
        let Some(mut root) = read_json_file(&self.path) else {
            return Ok(());
        };
        if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
            sessions.remove(account_key);
        }
        write_secret_json_file(&self.path, &root).map_err(|error| crate::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }
}

fn with_json_request(request_json: &str, operation: impl FnOnce(Value) -> Result<Value, String>) -> String {
    match parse_json_request(request_json).and_then(operation) {
        Ok(response) => response.to_string(),
        Err(message) => ffi_error_json(&message),
    }
}

fn parse_json_request(request_json: &str) -> Result<Value, String> {
    if request_json.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(request_json).map_err(|error| format!("invalid request JSON: {error}"))
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
        Some(value) => value.as_u64().ok_or_else(|| format!("missing or invalid field: {field}")).map(Some),
    }
}

fn request_i64(request: &Value, field: &'static str) -> Result<Option<i64>, String> {
    match request.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().ok_or_else(|| format!("missing or invalid field: {field}")).map(Some),
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

fn required_request_path_array(request: &Value, field: &'static str) -> Result<Vec<PathBuf>, String> {
    let paths = request_string_array(request, field)?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() { Err(format!("missing or invalid field: {field}")) } else { Ok(paths) }
}

fn parse_auth_environment(value: &str) -> Result<crate::auth_client::TzapHostedAuthEnvironment, String> {
    match value {
        "local" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Local),
        "staging" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Staging),
        "prod" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Prod),
        _ => Err("environment must be local, staging, or prod".to_owned()),
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
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
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
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path)?;
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

fn save_pending_auth(state_dir: &Path, pending: &crate::auth_client::TzapPendingAuthState) -> std::io::Result<()> {
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

fn load_pending_auth(state_dir: &Path) -> Result<crate::auth_client::TzapPendingAuthState, String> {
    let value = read_json_file(&state_dir.join(AUTH_PENDING_FILE))
        .ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
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
}

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

fn session_summary_json(session: &crate::auth_client::TzapSessionRecord) -> Value {
    session_summary_json_at(session, current_unix_seconds())
}

fn session_summary_json_at(session: &crate::auth_client::TzapSessionRecord, now_unix_seconds: u64) -> Value {
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
    let identity_assurance =
        trust::TzapIdentityAssurance::parse(&assurance).ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(crate::auth_client::TzapSessionRecord {
        audience: required_request_string(value, "audience")?,
        access_token: crate::auth_client::TzapBearerToken::new(required_request_string(value, "access_token")?)
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

fn run_fake_tzap_service<F>(request_json: &str, operation: &'static str, action: F) -> String
where
    F: FnOnce(
        &mut FileTzapLocalIdentityStore,
        &crate::auth_client::TzapSessionRecord,
        &crate::local_fake_tzap::TzapLocalFakeServiceOptions,
        &Value,
    ) -> Result<Value, String>,
{
    match parse_json_request(request_json).and_then(|request| {
        let context = TzapFfiContext::from_request(&request)?;
        let session_store = TzapFfiSessionStore::new(&context.state_dir);
        let Some(session) = session_store.load_session(&context.account_key) else {
            return Err(MISSING_TZAP_SESSION.to_owned());
        };
        let mut identity_store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let options = crate::local_fake_tzap::TzapLocalFakeServiceOptions {
            account_key: context.account_key,
            now_unix_seconds: request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
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

fn document_verification_result_json(result: &crate::document_verification::TzapDocumentVerificationResult) -> Value {
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

#[allow(clippy::needless_pass_by_value)]
fn retirement_completion_label(completion: crate::certificate_lifecycle::TzapRetirementCompletion) -> &'static str {
    match completion {
        crate::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        crate::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
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
        &identity.to_der().map_err(|source| format!("could not encode PKCS#12 identity: {source}"))?,
    )?;
    if let Some(path) = public_certificate_path {
        write_output_file(
            path,
            &certificate.to_pem().map_err(|source| format!("could not encode public certificate: {source}"))?,
        )?;
    }

    x509_certificate_summary_json(&certificate)
}

fn create_self_signed_certificate(common_name: &str, key: &PKey<Private>) -> Result<X509, String> {
    let mut name = X509NameBuilder::new().map_err(|source| format!("could not create certificate name: {source}"))?;
    name.append_entry_by_text("CN", common_name)
        .map_err(|source| format!("could not set certificate name: {source}"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|source| format!("could not create certificate: {source}"))?;
    builder.set_version(2).map_err(|source| format!("could not set certificate version: {source}"))?;
    let serial = random_certificate_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|source| format!("could not set certificate serial number: {source}"))?;
    builder.set_subject_name(&name).map_err(|source| format!("could not set certificate subject: {source}"))?;
    builder.set_issuer_name(&name).map_err(|source| format!("could not set certificate issuer: {source}"))?;
    builder.set_pubkey(key).map_err(|source| format!("could not set certificate public key: {source}"))?;
    let not_before =
        Asn1Time::days_from_now(0).map_err(|source| format!("could not set certificate start date: {source}"))?;
    builder.set_not_before(&not_before).map_err(|source| format!("could not set certificate start date: {source}"))?;
    let not_after = Asn1Time::days_from_now(SELF_SIGNED_IDENTITY_VALID_DAYS)
        .map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder.set_not_after(&not_after).map_err(|source| format!("could not set certificate expiry: {source}"))?;
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
    builder.sign(key, MessageDigest::sha256()).map_err(|source| format!("could not sign certificate: {source}"))?;

    Ok(builder.build())
}

fn random_certificate_serial() -> Result<Asn1Integer, String> {
    let mut serial = BigNum::new().map_err(|source| format!("could not create serial number: {source}"))?;
    serial
        .rand(SELF_SIGNED_IDENTITY_SERIAL_BITS, MsbOption::MAYBE_ZERO, false)
        .map_err(|source| format!("could not create serial number: {source}"))?;
    serial.to_asn1_integer().map_err(|source| format!("could not encode serial number: {source}"))
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
        fs::create_dir_all(parent).map_err(|source| format!("could not create {}: {source}", parent.display()))?;
    }

    fs::write(path, bytes).map_err(|source| format!("could not write {}: {source}", path.display()))
}

pub fn create_tzap_self_signed_identity(
    identity_path: &str,
    public_certificate_path: Option<&str>,
    common_name: &str,
    password: &str,
) -> String {
    let identity_path = PathBuf::from(identity_path);
    let public_certificate_path = public_certificate_path.map(PathBuf::from);
    let json = match create_self_signed_tzap_identity(
        &identity_path,
        public_certificate_path.as_deref(),
        common_name,
        &SecretString::from(password),
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
    json
}

fn tzap_public_metadata_json(summary: &crate::tzap_backend::TzapPublicMetadataSummary) -> Value {
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
fn tzap_x509_root_auth_json(report: &crate::tzap_backend::TzapX509VerificationReport) -> Value {
    let status = report.diagnostics.first().map_or("root_auth_content_verified", String::as_str);
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
fn tzap_x509_signer_inspection_json(report: &crate::tzap_backend::TzapX509SignerInspection) -> Value {
    let status = report.diagnostics.first().map_or("root_auth_signer_inspected", String::as_str);
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
fn ffi_error_json(message: &str) -> String {
    json!({
        "ok": false,
        "message": message,
    })
    .to_string()
}
/// Verifies the X.509 `RootAuth` signer of a `.tzap` archive with an optional
/// password and explicit trust sources, returning a JSON response envelope.
pub fn verify_tzap_x509(
    archive_path: &str,
    password: Option<&str>,
    trusted_ca_certs: &[String],
    trusted_system_roots: bool,
) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    match crate::tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
        PathBuf::from(archive_path),
        password,
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
    }
}

/// Verifies the X.509 `RootAuth` signer of a `.tzap` archive without the
/// archive key, using explicit trust sources.
pub fn verify_tzap_x509_public_no_key(
    archive_path: &str,
    trusted_ca_certs: &[String],
    trusted_system_roots: bool,
) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    match crate::tzap_backend::verify_tzap_x509_public_no_key(PathBuf::from(archive_path), &trust) {
        Ok(root_auth) => json!({
            "ok": true,
            "verification_mode": "public-no-key",
            "root_auth": tzap_x509_root_auth_json(&root_auth),
            "public_diagnostics": &root_auth.diagnostics,
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Inspects the X.509 `RootAuth` signer of a `.tzap` archive with an optional
/// password, returning a JSON response envelope.
pub fn inspect_tzap_x509_signer(archive_path: &str, password: Option<&str>) -> String {
    match crate::tzap_backend::inspect_tzap_x509_signer(PathBuf::from(archive_path), password) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "full",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Inspects the X.509 `RootAuth` signer of a `.tzap` archive without the
/// archive key, returning a JSON response envelope.
pub fn inspect_tzap_x509_public_no_key_signer(archive_path: &str) -> String {
    match crate::tzap_backend::inspect_tzap_x509_public_no_key_signer(PathBuf::from(archive_path)) {
        Ok(report) => json!({
            "ok": true,
            "inspection_mode": "public-no-key",
            "root_auth": tzap_x509_signer_inspection_json(&report),
        })
        .to_string(),
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

/// Returns the public metadata summary for a `.tzap` archive as a JSON string.
///
/// The response envelope is `{ok, metadata, signature}` where `signature`
/// carries the X.509 `RootAuth` status when the archive is signed.
pub fn tzap_public_metadata_summary(archive_path: &str) -> String {
    let archive_path = PathBuf::from(archive_path);
    match crate::tzap_backend::summarize_tzap_public_metadata(&archive_path) {
        Ok(summary) => {
            let signature = match crate::tzap_backend::verify_tzap_x509_public_no_key(
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
                Err(error) => match crate::tzap_backend::inspect_tzap_x509_public_no_key_signer(&archive_path) {
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
                },
            };
            json!({
                "ok": true,
                "metadata": tzap_public_metadata_json(&summary),
                "signature": signature,
            })
            .to_string()
        }
        Err(error) => ffi_error_json(&error.to_string()),
    }
}

fn tzap_x509_trust_options(trusted_ca_certs: &[String], trusted_system_roots: bool) -> TzapX509TrustOptions {
    TzapX509TrustOptions {
        trusted_ca_certificates: trusted_ca_certs.iter().map(PathBuf::from).collect(),
        trusted_system_roots,
        include_official_tzap_root: false,
    }
}

pub fn tzap_auth_login_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(crate::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id = request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri =
            request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let provider_id = request_string(&request, "provider_id")?.unwrap_or_else(|| DEFAULT_TZAP_PROVIDER_ID.into());
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);

        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        let pending = tracker.begin(provider_id, redirect_uri.clone(), now_unix_seconds);
        save_pending_auth(&context.state_dir, &pending).map_err(|error| error.to_string())?;

        let mut config =
            crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
        if let Some(auth_base_url) = request_string(&request, "auth_base_url")? {
            config.hosted_auth_base_url = auth_base_url;
        }
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        let launch_url = config.launch_url(&pending).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "status": "pending",
            "launch_url": launch_url,
            "state": pending.state,
            "expires_at_unix_seconds": pending
                .created_at_unix_seconds
                .saturating_add(crate::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS),
        }))
    })
}

pub fn tzap_auth_callback_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let pending = load_pending_auth(&context.state_dir)?;
        let state = required_request_string(&request, "state")?;
        let redirect_uri =
            request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let relay_body = required_request_string(&request, "relay_body")?.into_bytes();
        let callback = crate::auth_client::TzapHostedAuthCallback {
            state,
            redirect_uri,
            pkce_verifier: pending.pkce.verifier.clone(),
            callback_url: request_string(&request, "callback_url")?,
            relay_body,
        };
        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        tracker.insert_pending(pending).map_err(|error| error.to_string())?;
        let mut session_store = TzapFfiSessionStore::new(&context.state_dir);
        let session = crate::auth_client::complete_hosted_auth_handoff(
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
    })
}

pub fn tzap_auth_status_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = TzapFfiSessionStore::new(&context.state_dir);
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
    })
}

pub fn tzap_auth_forget_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let mut store = TzapFfiSessionStore::new(&context.state_dir);
        store.clear_session(&context.account_key).map_err(|error| error.to_string())?;
        let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
        Ok(json!({
            "ok": true,
            "forgotten": true,
        }))
    })
}

pub fn tzap_auth_account_url_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(crate::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id = request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri =
            request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let mut config =
            crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        Ok(json!({
            "ok": true,
            "account_url": config.account_url(),
        }))
    })
}

pub fn tzap_certificate_inventory_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "inventory": inventory_summary_json(&inventory),
        }))
    })
}

pub fn tzap_cert_enroll_json(request_json: &str) -> String {
    run_fake_tzap_service(request_json, OP_CERT_ENROLL, |store, session, options, _| {
        crate::local_fake_tzap::enroll_local_fake_certificate(store, session, options)
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_ENROLL,
                    "certificate": certificate_summary_json(&certificate),
                })
            })
            .map_err(|error| error.to_string())
    })
}

pub fn tzap_cert_renew_json(request_json: &str) -> String {
    run_fake_tzap_service(request_json, OP_CERT_RENEW, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_fake_tzap::renew_local_fake_certificate(store, session, options, &certificate_id)
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_RENEW,
                    "certificate": certificate_summary_json(&certificate),
                })
            })
            .map_err(|error| error.to_string())
    })
}

pub fn tzap_cert_revoke_json(request_json: &str) -> String {
    run_fake_tzap_service(request_json, OP_CERT_REVOKE, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_fake_tzap::revoke_local_fake_certificate(store, session, options, &certificate_id)
            .map(|completion| {
                json!({
                    "ok": true,
                    "operation": OP_CERT_REVOKE,
                    "completion": retirement_completion_label(completion),
                })
            })
            .map_err(|error| error.to_string())
    })
}

pub fn tzap_device_retire_json(request_json: &str) -> String {
    run_fake_tzap_service(request_json, OP_DEVICE_RETIRE, |store, session, options, _| {
        crate::local_fake_tzap::retire_local_fake_device(store, session, options)
            .map(|report| {
                json!({
                    "ok": true,
                    "operation": OP_DEVICE_RETIRE,
                    "completion": retirement_completion_label(report.completion),
                    "attempted_sign_device_ids": report.attempted_sign_device_ids,
                })
            })
            .map_err(|error| error.to_string())
    })
}

pub fn tzap_document_sign_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let certificate_id = required_request_string(&request, "certificate_id")?;
        let payload = request.get("payload").cloned().ok_or_else(|| "missing or invalid field: payload".to_owned())?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut signing_request = crate::document_signing::TzapDocumentSigningRequest::new(
            context.account_key,
            certificate_id,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        );
        signing_request.claimed_signing_time = request_string(&request, "claimed_signing_time")?;
        let envelope = crate::document_signing::sign_tzap_document_payload(&store, &signing_request, payload)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "envelope": envelope,
        }))
    })
}

pub fn tzap_document_verify_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let envelope = request.get("envelope").ok_or_else(|| "missing or invalid field: envelope".to_owned())?;
        let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
        let options = crate::document_verification::TzapOfflineVerificationOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256: request_string_array(&request, "custom_trust_root_sha256")?,
            custom_trust_root_certificates_der: Vec::new(),
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let result = crate::document_verification::verify_tzap_document_envelope_offline_json(&bytes, &options);
        if request_string(&request, "mode")?.as_deref().unwrap_or("offline") == "offline"
            || result.state == trust::TzapVerificationState::Invalid
        {
            return Ok(document_verification_result_json(&result));
        }
        if request_string(&request, "mode")?.as_deref() != Some("valid_now") {
            return Err("document verify mode must be offline or valid_now".to_owned());
        }
        let envelope =
            crate::document_envelope::parse_tzap_document_envelope_json(&bytes).map_err(|error| error.to_string())?;
        let status_value =
            request.get("status_response").ok_or_else(|| "missing or invalid field: status_response".to_owned())?;
        let status = crate::status_client::TzapStatusResponse::from_json_value(status_value)
            .map_err(|error| error.to_string())?;
        let result = crate::status_client::verify_tzap_document_envelope_valid_now(&envelope, &options, &status);
        Ok(document_verification_result_json(&result))
    })
}

pub fn tzap_recipient_key_generate_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let material =
            crate::device_identity::generate_recipient_encryption_key().map_err(|error| error.to_string())?;
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
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        inventory.recipient_encryption_keys.retain(|existing| existing.key_id != record.key_id);
        inventory.recipient_encryption_keys.push(record.clone());
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "recipient_key": recipient_key_summary_json(&record),
        }))
    })
}

pub fn tzap_recipient_key_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let key_id = required_request_string(&request, "key_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        let before = inventory.recipient_encryption_keys.len();
        inventory.recipient_encryption_keys.retain(|record| record.key_id != key_id);
        let removed = before != inventory.recipient_encryption_keys.len();
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    })
}

pub fn tzap_contact_export_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let export_request = crate::contact_card::TzapContactCardExportRequest {
            account_key: context.account_key,
            recipient_key_id: required_request_string(&request, "recipient_key_id")?,
            certificate_id: required_request_string(&request, "certificate_id")?,
            display_name: required_request_string(&request, "display_name")?,
            device_label: request_string(&request, "device_label")?.unwrap_or_else(|| "ZManager".to_owned()),
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?
                .unwrap_or_else(current_unix_seconds),
            expires_at_unix_seconds: request_u64(&request, "expires_at_unix_seconds")?,
        };
        let card = crate::contact_card::export_tzap_contact_card(&store, &export_request)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact_card": card,
        }))
    })
}

pub fn tzap_contact_import_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let card =
            request.get("contact_card").cloned().ok_or_else(|| "missing or invalid field: contact_card".to_owned())?;
        let options = crate::contact_card::TzapContactCardImportOptions {
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
            .then_some(request_u64(&request, "accepted_at_unix_seconds")?.unwrap_or_else(current_unix_seconds));
        let contact = crate::contact_card::import_tzap_contact_card(
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
    })
}

pub fn tzap_contact_list_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contacts": inventory
                .contacts
                .iter()
                .map(contact_summary_json)
                .collect::<Vec<_>>(),
        }))
    })
}

pub fn tzap_contact_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let contact_id = required_request_string(&request, "contact_id")?;
        let mut store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let mut inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        let before = inventory.contacts.len();
        inventory.contacts.retain(|contact| contact.contact_id != contact_id);
        let removed = before != inventory.contacts.len();
        store.save_inventory(&context.account_key, inventory).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "removed": removed,
        }))
    })
}

pub fn tzap_share_create_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let destination = required_request_path(&request, "destination")?;
        let sources = required_request_path_array(&request, "sources")?;
        let contact_ids = request_string_array(&request, "contact_ids")?;
        let store = FileTzapLocalIdentityStore::new(&context.state_dir);
        let recipients = crate::contact_card::accepted_contact_recipients(
            &store,
            &context.account_key,
            &contact_ids,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        )
        .map_err(|error| error.to_string())?;
        let recipient_status_caveats = recipients.iter().filter(|recipient| recipient.missing_status_caveat).count();
        let recipient_public_keys =
            recipients.into_iter().map(|recipient| recipient.recipient_public_key_der).collect();
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientPublicKeys(recipient_public_keys),
            level: TZAP_DEFAULT_COMPRESSION_LEVEL,
            preserve_metadata: true,
            replace_existing: request.get("replace_existing").and_then(Value::as_bool).unwrap_or(false),
            volume_size: None,
            recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
            volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
            x509_signing: None,
        };
        let token = CancellationToken::new();
        let mut event_sink = |_event: JobEvent| {};
        let report = crate::jobs::run_tzap_create_job_from_sources_with_plan_options(
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
    })
}
