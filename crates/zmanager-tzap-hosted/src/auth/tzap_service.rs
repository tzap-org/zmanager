//! TZAP service endpoints in the JSON wire format consumed by shell UIs.
//!
//! This module is ported from the legacy `zmanager_ffi_*` C-ABI facade.
//! Each endpoint parses a JSON request, orchestrates `zmanager-core`, and
//! returns a JSON response envelope. The wire contracts are the same as the
//! legacy facade; the FFI crate declares them as `UniFFI` functions.

use std::fs;
use std::path::{Path, PathBuf};

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

use crate::auth_flow_store::TzapAuthSlot;
use crate::trust;
use crate::tzap_service_auth::{
    TzapFfiSessionStore, current_unix_seconds, default_tzap_state_dir, parse_auth_environment, session_summary_json, session_summary_json_at,
};

use crate::auth_client::TzapSessionStore;
use crate::engine::tzap::TzapPublicSignatureStatus;
use crate::engine::{TzapCreateOptions, TzapKeySource, TzapX509TrustOptions};
#[cfg(feature = "reqwest-transport")]
use crate::enrollment_client::TzapEnrollmentCertificateValidator;
use crate::jobs::{CancellationToken, JobEvent};
#[cfg(all(feature = "keyring", not(test)))]
use crate::keyring_store::NativeTzapLocalIdentityStore;
#[cfg(any(not(feature = "keyring"), test))]
use crate::local_identity_store::FileTzapLocalIdentityStore;
use crate::local_identity_store::{
    TzapContactRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
    TzapRecipientEncryptionKeyRecord,
};
use crate::manifest::PlanOptions;
use crate::secrets::SecretString;
use crate::x509_format::{hex_lower, x509_name_to_string};

const TZAP_DEFAULT_COMPRESSION_LEVEL: i32 = 3;
const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
const SELF_SIGNED_IDENTITY_RSA_BITS: u32 = 3072;
const SELF_SIGNED_IDENTITY_VALID_DAYS: u32 = 3_650;
const SELF_SIGNED_IDENTITY_SERIAL_BITS: i32 = 159;
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
const DEFAULT_TZAP_REDIRECT_URI: &str = "tzap://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const DEFAULT_TZAP_ACCOUNT_KEY: &str = "default";
const OP_CERT_ENROLL: &str = "cert_enroll";
const OP_CERT_RENEW: &str = "cert_renew";

#[cfg(all(feature = "keyring", not(test)))]
type ServiceIdentityStore = NativeTzapLocalIdentityStore;
#[cfg(any(not(feature = "keyring"), test))]
type ServiceIdentityStore = FileTzapLocalIdentityStore;

#[allow(clippy::unnecessary_wraps)]
fn new_identity_store(state_dir: &Path, account_key: &str) -> Result<ServiceIdentityStore, String> {
    #[cfg(all(feature = "keyring", not(test)))]
    {
        NativeTzapLocalIdentityStore::new(state_dir, account_key).map_err(|error| error.to_string())
    }
    #[cfg(any(not(feature = "keyring"), test))]
    {
        let _ = account_key;
        Ok(FileTzapLocalIdentityStore::new(state_dir))
    }
}
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

pub(crate) fn request_string(request: &Value, field: &'static str) -> Result<Option<String>, String> {
    match request.get(field) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        None | Some(Value::Null | Value::String(_)) => Ok(None),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

pub(crate) fn required_request_string(request: &Value, field: &'static str) -> Result<String, String> {
    request_string(request, field)?.ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn request_path(request: &Value, field: &'static str) -> Result<Option<PathBuf>, String> {
    Ok(request_string(request, field)?.map(PathBuf::from))
}

fn required_request_path(request: &Value, field: &'static str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required_request_string(request, field)?))
}

pub(crate) fn request_u64(request: &Value, field: &'static str) -> Result<Option<u64>, String> {
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
            .map(|value| value.as_str().filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| format!("missing or invalid field: {field}")))
            .collect(),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn required_request_path_array(request: &Value, field: &'static str) -> Result<Vec<PathBuf>, String> {
    let paths = request_string_array(request, field)?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() { Err(format!("missing or invalid field: {field}")) } else { Ok(paths) }
}

fn run_local_tzap_service<F>(request_json: &str, action: F) -> String
where
    F: FnOnce(
        &mut ServiceIdentityStore,
        &crate::auth_client::TzapSessionRecord,
        &crate::local_tzap_service::TzapLocalServiceOptions,
        &Value,
    ) -> Result<Value, String>,
{
    match parse_json_request(request_json).and_then(|request| {
        let context = TzapFfiContext::from_request(&request)?;
        let session_store = TzapFfiSessionStore::new(&context.state_dir);
        let Some(session) = session_store.load_session(&context.account_key) else {
            return Err(MISSING_TZAP_SESSION.to_owned());
        };
        if session.provenance.is_some() {
            return Err("hosted enrollment must use the authenticated signing service".to_owned());
        }
        let mut identity_store = new_identity_store(&context.state_dir, &context.account_key)?;
        let options = crate::local_tzap_service::TzapLocalServiceOptions {
            account_key: context.account_key,
            now_unix_seconds: request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        };
        action(&mut identity_store, &session, &options, &request)
    }) {
        Ok(value) => value.to_string(),
        // Single error envelope for every tzap service endpoint; consumers
        // parse `ok`/`message` only. The legacy `operation`/`error` shape
        // was dropped when the local endpoints were unified with the
        // JSON-request endpoints.
        Err(message) => ffi_error_json(&message),
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
    let key = PKey::from_rsa(Rsa::generate(SELF_SIGNED_IDENTITY_RSA_BITS).map_err(|source| format!("could not generate signing key: {source}"))?)
        .map_err(|source| format!("could not prepare signing key: {source}"))?;
    let certificate = create_self_signed_certificate(common_name, &key)?;
    let identity = Pkcs12::builder()
        .name(common_name)
        .pkey(&key)
        .cert(&certificate)
        .build2(password.expose_secret())
        .map_err(|source| format!("could not create PKCS#12 identity: {source}"))?;

    write_output_file(identity_path, &identity.to_der().map_err(|source| format!("could not encode PKCS#12 identity: {source}"))?)?;
    if let Some(path) = public_certificate_path {
        write_output_file(path, &certificate.to_pem().map_err(|source| format!("could not encode public certificate: {source}"))?)?;
    }

    x509_certificate_summary_json(&certificate)
}

fn create_self_signed_certificate(common_name: &str, key: &PKey<Private>) -> Result<X509, String> {
    let mut name = X509NameBuilder::new().map_err(|source| format!("could not create certificate name: {source}"))?;
    name.append_entry_by_text("CN", common_name).map_err(|source| format!("could not set certificate name: {source}"))?;
    let name = name.build();

    let mut builder = X509::builder().map_err(|source| format!("could not create certificate: {source}"))?;
    builder.set_version(2).map_err(|source| format!("could not set certificate version: {source}"))?;
    let serial = random_certificate_serial()?;
    builder.set_serial_number(&serial).map_err(|source| format!("could not set certificate serial number: {source}"))?;
    builder.set_subject_name(&name).map_err(|source| format!("could not set certificate subject: {source}"))?;
    builder.set_issuer_name(&name).map_err(|source| format!("could not set certificate issuer: {source}"))?;
    builder.set_pubkey(key).map_err(|source| format!("could not set certificate public key: {source}"))?;
    let not_before = Asn1Time::days_from_now(0).map_err(|source| format!("could not set certificate start date: {source}"))?;
    builder.set_not_before(&not_before).map_err(|source| format!("could not set certificate start date: {source}"))?;
    let not_after = Asn1Time::days_from_now(SELF_SIGNED_IDENTITY_VALID_DAYS).map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder.set_not_after(&not_after).map_err(|source| format!("could not set certificate expiry: {source}"))?;
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().map_err(|source| format!("could not set certificate constraints: {source}"))?)
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
    serial.rand(SELF_SIGNED_IDENTITY_SERIAL_BITS, MsbOption::MAYBE_ZERO, false).map_err(|source| format!("could not create serial number: {source}"))?;
    serial.to_asn1_integer().map_err(|source| format!("could not encode serial number: {source}"))
}

fn x509_certificate_summary_json(certificate: &X509) -> Result<Value, String> {
    let fingerprint = certificate.digest(MessageDigest::sha256()).map_err(|source| format!("could not fingerprint certificate: {source}"))?;
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

pub fn create_tzap_self_signed_identity(identity_path: &str, public_certificate_path: Option<&str>, common_name: &str, password: &str) -> String {
    let identity_path = PathBuf::from(identity_path);
    let public_certificate_path = public_certificate_path.map(PathBuf::from);

    match create_self_signed_tzap_identity(&identity_path, public_certificate_path.as_deref(), common_name, &SecretString::from(password)) {
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
    }
}

fn tzap_public_metadata_json(summary: &crate::engine::tzap::TzapPublicMetadataSummary) -> Value {
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
fn tzap_x509_root_auth_json(report: &crate::engine::tzap::TzapX509VerificationReport) -> Value {
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
fn tzap_x509_signer_inspection_json(report: &crate::engine::tzap::TzapX509SignerInspection) -> Value {
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
#[must_use]
pub fn verify_tzap_x509(archive_path: &str, password: Option<&str>, trusted_ca_certs: &[String], trusted_system_roots: bool) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    let backend_trust = crate::engine::tzap::TzapX509TrustOptions::from(trust);
    match crate::engine::tzap::test_tzap_with_optional_password_filter_and_x509_trust(PathBuf::from(archive_path), password, |_| true, Some(&backend_trust)) {
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
#[must_use]
pub fn verify_tzap_x509_public_no_key(archive_path: &str, trusted_ca_certs: &[String], trusted_system_roots: bool) -> String {
    let trust = tzap_x509_trust_options(trusted_ca_certs, trusted_system_roots);
    if !trust.has_trust_source() {
        return ffi_error_json("X.509 verification requires trusted roots");
    }
    let backend_trust = crate::engine::tzap::TzapX509TrustOptions::from(trust);
    match crate::engine::tzap::verify_tzap_x509_public_no_key(PathBuf::from(archive_path), &backend_trust) {
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
#[must_use]
pub fn inspect_tzap_x509_signer(archive_path: &str, password: Option<&str>) -> String {
    match crate::engine::tzap::inspect_tzap_x509_signer(PathBuf::from(archive_path), password) {
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
#[must_use]
pub fn inspect_tzap_x509_public_no_key_signer(archive_path: &str) -> String {
    match crate::engine::tzap::inspect_tzap_x509_public_no_key_signer(PathBuf::from(archive_path)) {
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
#[must_use]
pub fn tzap_public_metadata_summary(archive_path: &str) -> String {
    let archive_path = PathBuf::from(archive_path);
    match crate::engine::tzap::summarize_tzap_public_metadata(&archive_path) {
        Ok(summary) => {
            let signature = match crate::engine::tzap::verify_tzap_x509_public_no_key(
                &archive_path,
                &crate::engine::tzap::TzapX509TrustOptions {
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
                Err(error) => match crate::engine::tzap::inspect_tzap_x509_public_no_key_signer(&archive_path) {
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

/// Returns a bounded display summary for a `.tzap` archive as a JSON string.
///
/// The response envelope is `{ok, metadata, signature}` — the same envelope as
/// [`tzap_public_metadata_summary`] — but `signature` carries a different,
/// footer-derived vocabulary: `status` is `signed`, `unsigned`,
/// `not_authentic`, or `unavailable` (a `signed` payload embeds the signer
/// inspection without trust validation; `verified`/`unverified` from
/// [`tzap_public_metadata_summary`] do not appear here). Footer inspection is
/// assertion 1 only (the embedded certificate's key really signed the footer);
/// archive contents are never read, so a `signed` payload is explicitly marked
/// `verification_scope: "footer-only"` and `content_verified: false` — the
/// summary is bounded regardless of archive size. Content integrity and
/// trust-chain validation remain the explicit `verify_tzap_x509_public_no_key`
/// surface.
#[must_use]
pub fn tzap_public_metadata_display_summary(archive_path: &str) -> String {
    let archive_path = PathBuf::from(archive_path);
    match crate::engine::tzap::summarize_tzap_public_display(&archive_path) {
        Ok(summary) => {
            let signature = match &summary.signature {
                TzapPublicSignatureStatus::Signed { signer } => json!({
                    "status": "signed",
                    "verification_scope": "footer-only",
                    "content_verified": false,
                    "root_auth": tzap_x509_signer_inspection_json(signer),
                }),
                TzapPublicSignatureStatus::Unsigned => json!({
                    "status": "unsigned",
                }),
                TzapPublicSignatureStatus::NotAuthentic { reason } => json!({
                    "status": "not_authentic",
                    "message": reason,
                }),
                TzapPublicSignatureStatus::Unavailable { reason } => json!({
                    "status": "unavailable",
                    "message": reason,
                }),
            };
            json!({
                "ok": true,
                "metadata": tzap_public_metadata_json(&summary.metadata),
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

/// Builds the custom trust root inputs from the request (CR-113: the service
/// adopted the CLI's `--custom-trust-root-cert` behavior — PEM/DER files are
/// loaded and fingerprinted alongside the explicit SHA-256 pins).
fn custom_trust_roots_from_request(request: &Value) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
    let mut custom_trust_root_sha256 = request_string_array(request, "custom_trust_root_sha256")?;
    let custom_root_cert_paths = request_string_array(request, "custom_trust_root_cert_paths")?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let custom_trust_root_certificates_der = trust::load_custom_root_certificate_files(&custom_root_cert_paths, &mut custom_trust_root_sha256)?;
    Ok((custom_trust_root_sha256, custom_trust_root_certificates_der))
}

#[must_use]
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
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let provider_id = request_string(&request, "provider_id")?.unwrap_or_else(|| DEFAULT_TZAP_PROVIDER_ID.into());
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        let requested_audience = request_string(&request, "audience")?.unwrap_or_else(|| crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP.to_owned());
        if !matches!(requested_audience.as_str(), crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP | crate::auth_client::SESSION_AUDIENCE_LOGIN_TZAP) {
            return Err("unsupported hosted session audience".to_owned());
        }

        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        let pending = tracker.begin(provider_id, redirect_uri.clone(), now_unix_seconds);

        let mut config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
        if let Some(auth_base_url) = request_string(&request, "auth_base_url")? {
            config.hosted_auth_base_url = auth_base_url;
        }
        if let Some(account_base_url) = request_string(&request, "account_base_url")? {
            config.hosted_account_base_url = account_base_url;
        }
        if let Some(signing_base_url) = request_string(&request, "signing_base_url")? {
            config.hosted_signing_base_url = signing_base_url;
        }
        config.selected_org_id = request_string(&request, "org_id")?;
        config.requested_audience = requested_audience;
        config.validate_for_environment(environment).map_err(|error| error.to_string())?;
        let launch_url = config.launch_url(&pending).map_err(|error| error.to_string())?;
        let application = request_string(&request, "application")?.unwrap_or_else(|| "cli".to_owned());
        let slot = TzapAuthSlot::acquire(&context.state_dir, &context.account_key, &application)?;
        let restart = match request.get("restart") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err("restart must be a boolean".to_owned()),
        };
        slot.create(&pending, &config, restart, now_unix_seconds)?;
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

#[must_use]
pub fn tzap_auth_callback_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        // Reject the unsupported input shape before touching the secret
        // store, so the refusal does not depend on a pending handoff being
        // readable.
        if request.get("relay_body").is_some() {
            return Err("relay_body is not supported; use handoff_code".to_owned());
        }
        let context = TzapFfiContext::from_request(&request)?;
        let application = request_string(&request, "application")?.unwrap_or_else(|| "cli".to_owned());
        let slot = TzapAuthSlot::acquire(&context.state_dir, &context.account_key, &application)?;
        let mut flow = slot.load()?;
        let pending = flow.pending.clone();
        let callback_url = request_string(&request, "callback_url")?;
        let fields = if let Some(url) = callback_url.as_deref().filter(|url| url.contains('?')) {
            if request_string(&request, "state")?.is_some() || request_string(&request, "handoff_code")?.is_some() {
                return Err("callback URL cannot be combined with separate state or handoff_code fields".to_owned());
            }
            crate::browser_callback::parse_browser_callback(url, &pending.redirect_uri).map_err(|error| error.to_string())?
        } else {
            crate::browser_callback::TzapBrowserCallback {
                state: required_request_string(&request, "state")?,
                handoff_code: required_request_string(&request, "handoff_code")?,
            }
        };
        crate::browser_callback::validate_handoff_code(&fields.handoff_code).map_err(|error| error.to_string())?;
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| pending.redirect_uri.clone());
        let mut callback = crate::auth_client::TzapHostedAuthCallback {
            state: fields.state,
            redirect_uri,
            pkce_verifier: pending.pkce.verifier.clone(),
            callback_url,
            relay_body: Vec::new(),
        };
        let mut tracker = crate::auth_client::TzapOAuthStateTracker::new();
        tracker.insert_pending(pending.clone()).map_err(|error| error.to_string())?;
        tracker.validate_handoff_binding(&callback).map_err(|error| error.to_string())?;
        let requested_audience = flow.config.requested_audience.clone();
        if !matches!(requested_audience.as_str(), crate::auth_client::SESSION_AUDIENCE_SIGN_TZAP | crate::auth_client::SESSION_AUDIENCE_LOGIN_TZAP) {
            return Err("unsupported hosted session audience".to_owned());
        }
        if request_string(&request, "auth_base_url")?.is_some_and(|base| base != flow.config.hosted_auth_base_url)
            || request_string(&request, "client_id")?.is_some_and(|client| client != flow.config.client_id)
        {
            return Err("callback auth endpoint and client must match the saved login; restart login to change them".to_owned());
        }
        let mut session_store = TzapFfiSessionStore::new(&context.state_dir);
        let now = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        let session = if let Some(session) = slot.recover_committed_session(&flow, &session_store, now)? {
            session
        } else {
            tracker.validate_handoff(&callback, now, crate::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS).map_err(|error| error.to_string())?;
            if !cfg!(feature = "reqwest-transport") {
                return Err("handoff-code exchange is unavailable in this build".to_owned());
            }
            let provenance = crate::session_provenance::TzapSessionProvenance::from_launch(&flow.config, &flow.flow_id).map_err(|error| error.to_string())?;
            slot.begin_exchange(&mut flow)?;
            callback.relay_body = hosted_auth_session_handoff_payload(&flow.config, &pending, &callback.redirect_uri, &callback.state, &fields.handoff_code)?;
            crate::auth_client::complete_bound_hosted_auth_handoff(
                &mut tracker,
                &mut session_store,
                &context.account_key,
                &callback,
                request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
                &requested_audience,
                provenance,
            )
            .map_err(|error| error.to_string())?
        };
        // Once saved, cleanup failures cannot turn a committed auth result
        // back into a failed exchange. Both remaining phases prohibit replay.
        let cleanup_warning = slot.mark_persisted(&mut flow).and_then(|()| slot.clear(&flow)).err();
        Ok(json!({
            "ok": true,
            "authenticated": true,
            "session": session_summary_json(&session),
            "cleanup_warning": cleanup_warning,
        }))
    })
}

#[cfg(feature = "reqwest-transport")]
fn hosted_auth_session_handoff_payload(
    config: &crate::auth_client::TzapHostedAuthLaunchConfig,
    pending: &crate::auth_client::TzapPendingAuthState,
    redirect_uri: &str,
    state: &str,
    handoff_code: &str,
) -> Result<Vec<u8>, String> {
    crate::reqwest_transport::exchange_handoff_code_for_audience(
        &config.hosted_auth_base_url,
        &config.client_id,
        redirect_uri,
        state,
        &pending.pkce.verifier,
        handoff_code,
        &config.requested_audience,
    )
}

#[cfg(not(feature = "reqwest-transport"))]
fn hosted_auth_session_handoff_payload(
    _config: &crate::auth_client::TzapHostedAuthLaunchConfig,
    _pending: &crate::auth_client::TzapPendingAuthState,
    _redirect_uri: &str,
    _state: &str,
    _handoff_code: &str,
) -> Result<Vec<u8>, String> {
    Err("handoff-code exchange is unavailable in this build".to_owned())
}

#[must_use]
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

#[must_use]
pub fn tzap_auth_forget_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let application = request_string(&request, "application")?.unwrap_or_else(|| "cli".to_owned());
        let slot = TzapAuthSlot::acquire(&context.state_dir, &context.account_key, &application)?;
        if let Some(flow) = slot.load_optional()? {
            slot.clear(&flow)?;
        }
        let mut store = TzapFfiSessionStore::new(&context.state_dir);
        store.clear_session(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "forgotten": true,
        }))
    })
}

#[must_use]
pub fn tzap_auth_account_url_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let environment = request
            .get("environment")
            .and_then(Value::as_str)
            .map(parse_auth_environment)
            .transpose()?
            .unwrap_or(crate::auth_client::TzapHostedAuthEnvironment::Prod);
        let client_id = request_string(&request, "client_id")?.unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.into());
        let redirect_uri = request_string(&request, "redirect_uri")?.unwrap_or_else(|| DEFAULT_TZAP_REDIRECT_URI.into());
        let mut config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(environment, client_id, redirect_uri);
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

#[must_use]
pub fn tzap_certificate_inventory_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = new_identity_store(&context.state_dir, &context.account_key)?;
        let inventory = store.load_inventory(&context.account_key).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "inventory": inventory_summary_json(&inventory),
        }))
    })
}

#[must_use]
pub fn tzap_cert_enroll_json(request_json: &str) -> String {
    #[cfg(feature = "reqwest-transport")]
    if request_json_has_service_base_url(request_json) {
        return hosted_tzap_cert_enroll_json(request_json);
    }
    run_local_tzap_service(request_json, |store, session, options, _| {
        crate::local_tzap_service::enroll_local_certificate(store, session, options)
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

#[cfg(feature = "reqwest-transport")]
fn request_json_has_service_base_url(request_json: &str) -> bool {
    serde_json::from_str::<Value>(request_json)
        .ok()
        .and_then(|request| request.get("service_base_url").and_then(Value::as_str).map(|value| !value.is_empty()))
        .unwrap_or(false)
}

#[cfg(feature = "reqwest-transport")]
fn hosted_tzap_cert_enroll_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let service_base_url = request_string(&request, "service_base_url")?.ok_or_else(|| "missing or invalid field: service_base_url".to_owned())?;
        let session_store = TzapFfiSessionStore::new(&context.state_dir);
        let session = session_store.load_session(&context.account_key).ok_or_else(|| MISSING_TZAP_SESSION.to_owned())?;
        let (trusted_root_sha256, trusted_root_der) = custom_trust_roots_from_request(&request)?;
        if trusted_root_der.is_empty() {
            return Err("hosted certificate enrollment requires at least one trusted root certificate".to_owned());
        }
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        let enrollment_request = crate::enrollment_client::TzapEnrollmentRequest {
            account_key: context.account_key.clone(),
            org_id: request_string(&request, "org_id")?.or_else(|| session.selected_org_id.clone()),
            requested_validity_seconds: request_u64(&request, "requested_validity_seconds")?.unwrap_or(90 * 24 * 60 * 60),
            now_unix_seconds,
        };
        let label = match enrollment_request.org_id.as_deref() {
            Some(org_id) => format!("ZManager Mobile Enrollment (org:{org_id})"),
            None => "ZManager Mobile Enrollment (personal)".to_owned(),
        };
        let mut store = new_identity_store(&context.state_dir, &context.account_key)?;
        let transport = crate::reqwest_transport::ReqwestTransport;
        let enrollment_client = crate::enrollment_client::TzapEnrollmentClient::local_staging_server(&service_base_url, &transport);
        let lifecycle_client =
            crate::certificate_lifecycle::TzapCertificateLifecycleClient::local_staging_server(&service_base_url, &service_base_url, &transport);
        let validator =
            FfiTrustedEnrollmentCertificateValidator { trusted_root_sha256, trusted_root_der, options: crate::trust::TzapCertificateProfileOptions::default() };
        // Reuses the device's existing signing key and renews when it
        // already holds an active certificate, rather than minting a new
        // key on every call — see `enroll_or_renew_device_certificate`'s
        // doc comment for the *Identity proliferation* defect this fixes.
        let certificate = crate::certificate_lifecycle::enroll_or_renew_device_certificate(
            &enrollment_client,
            &lifecycle_client,
            &validator,
            &mut store,
            &session,
            &enrollment_request,
            &label,
        )
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "operation": OP_CERT_ENROLL,
            "service_base_url": service_base_url,
            "certificate": certificate_summary_json(&certificate),
        }))
    })
}

#[cfg(feature = "reqwest-transport")]
struct FfiTrustedEnrollmentCertificateValidator {
    trusted_root_sha256: Vec<String>,
    trusted_root_der: Vec<Vec<u8>>,
    options: crate::trust::TzapCertificateProfileOptions,
}

#[cfg(feature = "reqwest-transport")]
impl TzapEnrollmentCertificateValidator for FfiTrustedEnrollmentCertificateValidator {
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<crate::trust::TzapCertificatePublicMetadata, crate::enrollment_client::TzapEnrollmentError> {
        self.validate_chain(chain_der).map(|validation| validation.public_metadata)
    }

    fn validate_and_complete_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, crate::trust::TzapCertificatePublicMetadata), crate::enrollment_client::TzapEnrollmentError> {
        if let Ok(validation) = self.validate_chain(chain_der) {
            return Ok((chain_der.to_vec(), validation.public_metadata));
        }
        let mut last_error = None;
        for root_der in &self.trusted_root_der {
            let mut completed_chain = chain_der.to_vec();
            completed_chain.push(root_der.clone());
            match self.validate_chain(&completed_chain) {
                Ok(validation) => return Ok((completed_chain, validation.public_metadata)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| crate::enrollment_client::TzapEnrollmentError::CertificateChain("certificate chain validation failed".to_owned())))
    }
}

#[cfg(feature = "reqwest-transport")]
impl FfiTrustedEnrollmentCertificateValidator {
    fn validate_chain(&self, chain_der: &[Vec<u8>]) -> Result<crate::trust::TzapCertificateProfileValidation, crate::enrollment_client::TzapEnrollmentError> {
        let validation = crate::trust::validate_custom_tzap_certificate_chain_der(chain_der, &self.options)
            .map_err(|error| crate::enrollment_client::TzapEnrollmentError::CertificateChain(error.to_string()))?;
        if !self.trusted_root_sha256.iter().any(|trusted| trusted == &validation.root_certificate_sha256) {
            return Err(crate::enrollment_client::TzapEnrollmentError::CertificateChain("root certificate is not in the temporary trust store".to_owned()));
        }
        Ok(validation)
    }
}

#[must_use]
pub fn tzap_cert_renew_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_tzap_service::renew_local_certificate(store, session, options, &certificate_id)
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

#[must_use]
pub fn tzap_cert_revoke_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, request| {
        let certificate_id = required_request_string(request, "certificate_id")?;
        crate::local_tzap_service::revoke_local_certificate(store, session, options, &certificate_id)
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

#[must_use]
pub fn tzap_device_retire_json(request_json: &str) -> String {
    run_local_tzap_service(request_json, |store, session, options, _| {
        crate::local_tzap_service::retire_local_device(store, session, options)
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

#[must_use]
pub fn tzap_document_sign_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let certificate_id = required_request_string(&request, "certificate_id")?;
        let payload = request.get("payload").cloned().ok_or_else(|| "missing or invalid field: payload".to_owned())?;
        let store = new_identity_store(&context.state_dir, &context.account_key)?;
        let mut signing_request = crate::document_signing::TzapDocumentSigningRequest::new(
            context.account_key,
            certificate_id,
            request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds),
        );
        signing_request.claimed_signing_time = request_string(&request, "claimed_signing_time")?;
        let envelope = crate::document_signing::sign_tzap_document_payload(&store, &signing_request, payload).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "envelope": envelope,
        }))
    })
}

#[must_use]
pub fn tzap_document_verify_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let envelope = request.get("envelope").ok_or_else(|| "missing or invalid field: envelope".to_owned())?;
        let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
        let (custom_trust_root_sha256, custom_trust_root_certificates_der) = custom_trust_roots_from_request(&request)?;
        let options = crate::document_verification::TzapOfflineVerificationOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256,
            custom_trust_root_certificates_der,
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
        };
        let result = crate::document_verification::verify_tzap_document_envelope_offline_json(&bytes, &options);
        if request_string(&request, "mode")?.as_deref().unwrap_or("offline") == "offline" || result.state == trust::TzapVerificationState::Invalid {
            return Ok(document_verification_result_json(&result));
        }
        if request_string(&request, "mode")?.as_deref() != Some("valid_now") {
            return Err("document verify mode must be offline or valid_now".to_owned());
        }
        let envelope = crate::document_envelope::parse_tzap_document_envelope_json(&bytes).map_err(|error| error.to_string())?;
        let status_value = request.get("status_response").ok_or_else(|| "missing or invalid field: status_response".to_owned())?;
        let status = crate::status_client::TzapStatusResponse::from_json_value(status_value).map_err(|error| error.to_string())?;
        let result = crate::status_client::verify_tzap_document_envelope_valid_now(&envelope, &options, &status);
        Ok(document_verification_result_json(&result))
    })
}

#[must_use]
pub fn tzap_recipient_key_generate_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let material = crate::device_identity::generate_recipient_encryption_key().map_err(|error| error.to_string())?;
        let record = TzapRecipientEncryptionKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            algorithm: material.algorithm.to_owned(),
            public_key_fingerprint: material.public_key_fingerprint,
            public_key_der: material.public_key_spki_der,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?.unwrap_or_else(current_unix_seconds),
            label: request_string(&request, "label")?,
        };
        let mut store = new_identity_store(&context.state_dir, &context.account_key)?;
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

#[must_use]
pub fn tzap_recipient_key_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let key_id = required_request_string(&request, "key_id")?;
        let mut store = new_identity_store(&context.state_dir, &context.account_key)?;
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

#[must_use]
pub fn tzap_contact_export_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = new_identity_store(&context.state_dir, &context.account_key)?;
        let export_request = crate::contact_card::TzapContactCardExportRequest {
            account_key: context.account_key,
            recipient_key_id: required_request_string(&request, "recipient_key_id")?,
            certificate_id: required_request_string(&request, "certificate_id")?,
            display_name: required_request_string(&request, "display_name")?,
            device_label: request_string(&request, "device_label")?.unwrap_or_else(|| "ZManager".to_owned()),
            created_at_unix_seconds: request_u64(&request, "created_at_unix_seconds")?.unwrap_or_else(current_unix_seconds),
            expires_at_unix_seconds: request_u64(&request, "expires_at_unix_seconds")?,
            compact: request.get("compact").and_then(Value::as_bool).unwrap_or(false),
        };
        let card = crate::contact_card::export_tzap_contact_card(&store, &export_request).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact_card": card,
        }))
    })
}

#[must_use]
pub fn tzap_contact_import_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let card = request.get("contact_card").cloned().ok_or_else(|| "missing or invalid field: contact_card".to_owned())?;
        let (custom_trust_root_sha256, custom_trust_root_certificates_der) = custom_trust_roots_from_request(&request)?;
        let intermediate_cache = trust::TzapIntermediateCache::new(context.state_dir.join("intermediates"));
        let service_base_url = request_string(&request, "service_base_url")?;
        #[cfg(feature = "reqwest-transport")]
        let intermediate_resolver = crate::intermediate_client::TzapOnlineIntermediateResolver::with_reqwest(intermediate_cache, service_base_url);
        #[cfg(not(feature = "reqwest-transport"))]
        let intermediate_resolver = {
            let _ = &service_base_url;
            intermediate_cache
        };

        let options = crate::contact_card::TzapContactCardImportOptions {
            verifier_time_unix_seconds: request_i64(&request, "verifier_time_unix_seconds")?
                .unwrap_or_else(|| i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX)),
            official_root_pins: &trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256,
            custom_trust_root_certificates_der,
            certificate_profile_options: trust::TzapCertificateProfileOptions::default(),
            intermediate_resolver: Some(&intermediate_resolver),
        };
        let mut store = new_identity_store(&context.state_dir, &context.account_key)?;
        let accepted_at = request
            .get("accept")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            .then_some(request_u64(&request, "accepted_at_unix_seconds")?.unwrap_or_else(current_unix_seconds));
        let contact =
            crate::contact_card::import_tzap_contact_card(&mut store, &context.account_key, &card, &options, accepted_at).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "contact": contact_summary_json(&contact),
        }))
    })
}

#[must_use]
pub fn tzap_contact_list_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let store = new_identity_store(&context.state_dir, &context.account_key)?;
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

#[must_use]
pub fn tzap_contact_remove_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let contact_id = required_request_string(&request, "contact_id")?;
        let mut store = new_identity_store(&context.state_dir, &context.account_key)?;
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

#[must_use]
pub fn tzap_share_create_json(request_json: &str) -> String {
    with_json_request(request_json, |request| {
        let context = TzapFfiContext::from_request(&request)?;
        let destination = required_request_path(&request, "destination")?;
        let sources = required_request_path_array(&request, "sources")?;
        let contact_ids = request_string_array(&request, "contact_ids")?;
        let now_unix_seconds = request_u64(&request, "now_unix_seconds")?.unwrap_or_else(current_unix_seconds);
        let certificate_id = request_string(&request, "certificate_id")?;
        let store = new_identity_store(&context.state_dir, &context.account_key)?;
        // CR-113: the share endpoint adopts the CLI's engine — resolve the
        // X.509 signing material from the local inventory (when a
        // `certificate_id` is requested) and create through the manifest
        // path with progress, instead of the job path without signing.
        let x509_signing = match certificate_id.as_deref() {
            Some(certificate_id) => Some(
                crate::engine::tzap::tzap_x509_signing_options_from_inventory(&store, &context.account_key, certificate_id, now_unix_seconds)
                    .map_err(|error| error.clone())?,
            ),
            None => None,
        };
        let recipients = crate::contact_card::accepted_contact_recipients(&store, &context.account_key, &contact_ids, now_unix_seconds)
            .map_err(|error| error.to_string())?;
        let recipient_status_caveats = recipients.iter().filter(|recipient| recipient.missing_status_caveat).count();
        let recipient_public_keys = recipients.into_iter().map(|recipient| recipient.recipient_public_key_der).collect();
        let options = TzapCreateOptions {
            key_source: TzapKeySource::RecipientPublicKeys(recipient_public_keys),
            level: TZAP_DEFAULT_COMPRESSION_LEVEL,
            preserve_metadata: true,
            replace_existing: request.get("replace_existing").and_then(Value::as_bool).unwrap_or(false),
            volume_size: None,
            volume_count: None,
            recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
            volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
            x509_signing: x509_signing.map(Into::into),
            emit_bootstrap_sidecar: false,
        };
        let manifest = crate::manifest::plan_archives(&sources, &PlanOptions::default()).map_err(|error| error.to_string())?;
        let token = CancellationToken::new();
        let mut event_sink = |_event: JobEvent| {};
        let mut job_context = crate::jobs::JobContext::new_with_progress_total(&token, &mut event_sink, Some(manifest.total_bytes));
        let request = crate::engine::CreateRequest::new(manifest, &destination, crate::engine::CreateOptions::Tzap(options));
        let engine = crate::engine::create_default_engine().map_err(|error| error.to_string())?;
        let report = engine.create(&request, &mut job_context).map_err(|error| error.to_string())?;
        job_context.flush_progress();
        let mut response = json!({
            "ok": true,
            "archive": destination.display().to_string(),
            "format": "tzap",
            "entries": report.written_entries,
            "bytes": report.written_bytes,
            "recipients": contact_ids.len(),
            "recipient_status_caveats": recipient_status_caveats,
            "volume_count": report.volume_count,
        });
        if let Some(certificate_id) = certificate_id {
            response["signed"] = json!(true);
            response["certificate_id"] = json!(certificate_id);
        }
        Ok(response)
    })
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic)]
mod tests {
    use super::*;

    fn test_temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("zm-tzap-test-{name}-{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&path);
        path
    }

    /// With the `keyring` feature on, the pending hosted-auth handoff and the
    /// session records live in process-wide keyring entries rather than under
    /// `state_dir`, so a per-test directory does not isolate them. Tests that
    /// touch that state take this lock instead of racing each other.
    static HOSTED_AUTH_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_hosted_auth_state() -> std::sync::MutexGuard<'static, ()> {
        HOSTED_AUTH_STATE_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn test_self_signed_identity_creation() {
        let temp = test_temp_dir("id");
        let identity_p12 = temp.join("identity.p12");
        let cert_pem = temp.join("cert.pem");

        let res = create_tzap_self_signed_identity(&identity_p12.display().to_string(), Some(&cert_pem.display().to_string()), "Test Identity", "password123");
        let val: Value = serde_json::from_str(&res).unwrap();
        assert_eq!(val["ok"], true);
        assert!(val["certificate"]["subject"].as_str().unwrap().contains("Test Identity"));
        assert!(identity_p12.exists());
        assert!(cert_pem.exists());
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn test_tzap_service_recipient_key_lifecycle() {
        let temp = test_temp_dir("key");
        let state_dir = temp.display().to_string();

        // 1. Generate recipient key
        let gen_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
            "label": "My Recipient Key",
            "created_at_unix_seconds": 1700000000,
        });
        let gen_res_str = tzap_recipient_key_generate_json(&gen_req.to_string());
        let gen_res: Value = serde_json::from_str(&gen_res_str).unwrap();
        assert_eq!(gen_res["ok"], true);
        let key_id = gen_res["recipient_key"]["key_id"].as_str().unwrap();

        // 2. Inventory check
        let inv_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
        });
        let inv_res: Value = serde_json::from_str(&tzap_certificate_inventory_json(&inv_req.to_string())).unwrap();
        assert_eq!(inv_res["ok"], true);
        assert_eq!(inv_res["inventory"]["recipient_encryption_keys"].as_array().unwrap().len(), 1);

        // 3. Remove recipient key
        let rem_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
            "key_id": key_id,
        });
        let rem_res: Value = serde_json::from_str(&tzap_recipient_key_remove_json(&rem_req.to_string())).unwrap();
        assert_eq!(rem_res["ok"], true);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn test_tzap_service_contact_lifecycle() {
        let temp = test_temp_dir("contact");
        let state_dir = temp.display().to_string();

        // 1. List contacts (initially empty)
        let list_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
        });
        let list_res: Value = serde_json::from_str(&tzap_contact_list_json(&list_req.to_string())).unwrap();
        assert_eq!(list_res["ok"], true);
        assert!(list_res["contacts"].as_array().unwrap().is_empty());

        // 2. Export contact card with mock payload
        let export_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
        });
        let export_res: Value = serde_json::from_str(&tzap_contact_export_json(&export_req.to_string())).unwrap();
        assert!(export_res.is_object());

        // 3. Remove contact
        let rem_req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
            "contact_id": "non_existent_contact",
        });
        let rem_res: Value = serde_json::from_str(&tzap_contact_remove_json(&rem_req.to_string())).unwrap();
        assert_eq!(rem_res["ok"], true);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn test_tzap_auth_endpoints() {
        let _hosted_auth_state = lock_hosted_auth_state();
        let temp = test_temp_dir("auth");
        let state_dir = temp.display().to_string();

        let req = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
        });
        let status_res: Value = serde_json::from_str(&tzap_auth_status_json(&req.to_string())).unwrap();
        assert_eq!(status_res["ok"], true);

        let forget_res: Value = serde_json::from_str(&tzap_auth_forget_json(&req.to_string())).unwrap();
        assert_eq!(forget_res["ok"], true);

        let account_url_res: Value = serde_json::from_str(&tzap_auth_account_url_json(&req.to_string())).unwrap();
        assert_eq!(account_url_res["ok"], true);

        let login_request = json!({
            "state_dir": state_dir,
            "account_key": "test_acc_login",
            "audience": crate::auth_client::SESSION_AUDIENCE_LOGIN_TZAP,
        });
        let login_response: Value = serde_json::from_str(&tzap_auth_login_json(&login_request.to_string())).unwrap();
        assert_eq!(login_response["ok"], true);
        assert!(login_response["launch_url"].as_str().unwrap().contains("audience=login.tzap.org"));
        let cleanup: Value = serde_json::from_str(&tzap_auth_forget_json(&login_request.to_string())).unwrap();
        assert_eq!(cleanup["ok"], true);

        let invalid_audience_request = json!({
            "state_dir": state_dir,
            "account_key": "test_acc_invalid_audience",
            "audience": "unexpected.example",
        });
        let invalid_audience_response: Value = serde_json::from_str(&tzap_auth_login_json(&invalid_audience_request.to_string())).unwrap();
        assert_eq!(invalid_audience_response["ok"], false);
        assert!(invalid_audience_response["message"].as_str().unwrap().contains("unsupported hosted session audience"));
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn hosted_auth_callback_rejects_legacy_relay_body_input() {
        let _hosted_auth_state = lock_hosted_auth_state();
        let temp = test_temp_dir("auth-relay-rejection");
        let state_dir = temp.display().to_string();
        let begin_request = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
            "client_id": "test-client",
            "redirect_uri": "tzap://auth/callback",
        });
        let begin_response: Value = serde_json::from_str(&tzap_auth_login_json(&begin_request.to_string())).unwrap();
        assert_eq!(begin_response["ok"], true);

        let callback_request = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
            "state": begin_response["state"],
            "relay_body": "{\"status\":\"ok\"}",
        });
        let callback_response: Value = serde_json::from_str(&tzap_auth_callback_json(&callback_request.to_string())).unwrap();
        assert_eq!(callback_response["ok"], false);
        assert!(callback_response["message"].as_str().unwrap().contains("relay_body is not supported"));

        // The refusal leaves the pending handoff in place; clear the shared
        // entry so it cannot leak into a later test or run.
        let forget_request = json!({
            "state_dir": state_dir,
            "account_key": "test_acc",
        });
        let forget_response: Value = serde_json::from_str(&tzap_auth_forget_json(&forget_request.to_string())).unwrap();
        assert_eq!(forget_response["ok"], true);
        let _ = fs::remove_dir_all(temp);
    }

    #[cfg(feature = "reqwest-transport")]
    #[test]
    fn hosted_auth_callback_invalid_bindings_never_send_the_verifier_to_exchange() {
        use std::io::{Read as _, Write as _};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let _hosted_auth_state = lock_hosted_auth_state();
        for scenario in [
            "state",
            "redirect",
            "expiry",
            "future",
            "url-token",
            "issuer",
            "client",
            "encoded-token",
            "duplicate",
            "url-state",
            "url-redirect",
            "url-fragment",
            "mixed",
            "code",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(AtomicUsize::new(0));
            let stopped = Arc::new(AtomicBool::new(false));
            let count = requests.clone();
            let stop = stopped.clone();
            let server = std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            count.fetch_add(1, Ordering::SeqCst);
                            stream.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
                            let mut buffer = [0; 1024];
                            let _ = stream.read(&mut buffer);
                            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                        Err(error) => panic!("exchange fixture failed: {error}"),
                    }
                }
            });
            let temp = test_temp_dir("auth-binding-preflight");
            let begin: Value = serde_json::from_str(&tzap_auth_login_json(
                &json!({
                    "state_dir": temp, "account_key": "guard-test", "environment": "local", "auth_base_url": base,
                    "client_id": "guard-test-client", "redirect_uri": "tzap://auth/callback", "now_unix_seconds": 100,
                })
                .to_string(),
            ))
            .unwrap();
            let mut callback = json!({
                "state_dir": temp, "account_key": "guard-test", "state": begin["state"],
                "redirect_uri": "tzap://auth/callback", "handoff_code": "tzap_handoff_fixture_code_only", "now_unix_seconds": 101,
            });
            match scenario {
                "state" => callback["state"] = json!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
                "redirect" => callback["redirect_uri"] = json!("tzap://wrong/callback"),
                "expiry" => callback["now_unix_seconds"] = json!(701),
                "future" => callback["now_unix_seconds"] = json!(99),
                "url-token" => callback["callback_url"] = json!("tzap://auth/callback?access_token=fixture-token-only"),
                "issuer" => callback["auth_base_url"] = json!(format!("{base}/another-issuer")),
                "client" => callback["client_id"] = json!("another-client"),
                "code" => callback["handoff_code"] = json!("fixture-code%2520invalid"),
                "encoded-token" | "duplicate" | "url-state" | "url-redirect" | "url-fragment" | "mixed" => {
                    let state = begin["state"].as_str().unwrap();
                    let url = format!("tzap://auth/callback?state={state}&handoff_code=tzap_handoff_fixture_only");
                    callback["callback_url"] = json!(match scenario {
                        "encoded-token" => format!("{url}&%61ccess_token=fixture_only"),
                        "duplicate" => format!("{url}&st%61te={state}"),
                        "url-state" => url.replace(state, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
                        "url-redirect" => url.replace("auth/callback", "wrong/callback"),
                        "url-fragment" => format!("{url}#"),
                        "mixed" => url,
                        _ => unreachable!(),
                    });
                    if scenario != "mixed" {
                        callback.as_object_mut().unwrap().remove("state");
                        callback.as_object_mut().unwrap().remove("handoff_code");
                    }
                }
                _ => unreachable!(),
            }
            let result: Value = serde_json::from_str(&tzap_auth_callback_json(&callback.to_string())).unwrap();
            stopped.store(true, Ordering::SeqCst);
            server.join().unwrap();
            let pending = TzapAuthSlot::acquire(&temp, "guard-test", "cli").unwrap().load().unwrap().pending;
            let _ = tzap_auth_forget_json(&json!({"state_dir": temp, "account_key": "guard-test"}).to_string());
            let _ = fs::remove_dir_all(&temp);
            assert_eq!(result["ok"], false, "{scenario}");
            assert_eq!(requests.load(Ordering::SeqCst), 0, "{scenario} must fail before HTTP exchange");
            assert_eq!(pending.state, begin["state"].as_str().unwrap());
        }
    }

    #[test]
    fn hosted_auth_pending_accounts_and_contexts_are_isolated_without_importing_legacy_files() {
        let _hosted_auth_state = lock_hosted_auth_state();
        let temp = test_temp_dir("auth-context-isolation");
        let first_dir = temp.join("one");
        let second_dir = temp.join("two");
        fs::create_dir_all(&first_dir).unwrap();
        let legacy = br#"{"pkce_verifier":"legacy-fixture-must-never-be-imported"}"#;
        fs::write(first_dir.join("auth-pending.json"), legacy).unwrap();
        let first = json!({"state_dir": first_dir, "account_key": "isolated-one", "environment": "staging", "now_unix_seconds": 100});
        let second = json!({"state_dir": second_dir, "account_key": "isolated-two", "environment": "staging", "now_unix_seconds": 100});
        let first_result: Value = serde_json::from_str(&tzap_auth_login_json(&first.to_string())).unwrap();
        let second_result: Value = serde_json::from_str(&tzap_auth_login_json(&second.to_string())).unwrap();
        assert_eq!(first_result["ok"], true);
        assert_eq!(second_result["ok"], true);
        assert_ne!(first_result["state"], second_result["state"]);
        let wrong_context = json!({"state_dir": second_dir, "account_key": "isolated-one", "environment": "staging", "now_unix_seconds": 101});
        let third: Value = serde_json::from_str(&tzap_auth_login_json(&wrong_context.to_string())).unwrap();
        assert_eq!(third["ok"], false);
        assert!(third["message"].as_str().unwrap().contains("pending_login_exists"));
        let wrong_cleanup: Value = serde_json::from_str(&tzap_auth_forget_json(&wrong_context.to_string())).unwrap();
        assert_eq!(wrong_cleanup["ok"], false);
        let second_cleanup: Value = serde_json::from_str(&tzap_auth_forget_json(&second.to_string())).unwrap();
        assert_eq!(second_cleanup["ok"], true);
        let preserved = TzapAuthSlot::acquire(&first_dir, "isolated-one", "cli").unwrap().load().unwrap();
        assert_eq!(preserved.pending.state, first_result["state"].as_str().unwrap());
        let first_cleanup: Value = serde_json::from_str(&tzap_auth_forget_json(&first.to_string())).unwrap();
        assert_eq!(first_cleanup["ok"], true);
        assert_eq!(fs::read(first_dir.join("auth-pending.json")).unwrap(), legacy);
        assert!(!second_dir.join("auth-pending.json").exists());
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn auth_commit_survives_a_crash_before_pending_cleanup_without_reexchanging_expired_handoff() {
        let _hosted_auth_state = lock_hosted_auth_state();
        let temp = test_temp_dir("auth-commit-recovery");
        let login = json!({"state_dir": temp, "account_key": "commit-recovery", "environment": "staging", "now_unix_seconds": 100});
        let begin: Value = serde_json::from_str(&tzap_auth_login_json(&login.to_string())).unwrap();
        assert_eq!(begin["ok"], true);
        let slot = TzapAuthSlot::acquire(&temp, "commit-recovery", "cli").unwrap();
        let mut flow = slot.load().unwrap();
        slot.begin_exchange(&mut flow).unwrap();
        let mut session = crate::auth_client::TzapSessionRecord {
            user_id: Some("user_fixture_one".to_owned()),
            provenance: None,
            audience: "sign.tzap.org".to_owned(),
            access_token: crate::auth_client::TzapBearerToken::new("fixture-committed-token-never-printed").unwrap(),
            expires_at_unix_seconds: 9_999_999_999,
            identity_assurance: crate::trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("fixture-committed-session".to_owned()),
        };
        session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&flow.config, &flow.flow_id).unwrap()).unwrap();
        TzapFfiSessionStore::new(&temp).save_session("commit-recovery", session).unwrap();
        // No phase update or pending deletion: restart at the exact crash gap.
        drop(slot);
        let request = json!({
            "state_dir": temp, "account_key": "commit-recovery", "now_unix_seconds": 1000,
            "state": begin["state"], "handoff_code": "fixture-code-already-used",
        });
        let completion = tzap_auth_callback_json(&request.to_string());
        let result: Value = serde_json::from_str(&completion).unwrap();
        // This also runs without reqwest-transport. Success proves recovery
        // never enters the network exchange path or requires a live server.
        assert_eq!(result["ok"], true);
        assert_eq!(result["authenticated"], true);
        assert!(!completion.contains("fixture-committed-token-never-printed"));
        assert!(TzapAuthSlot::acquire(&temp, "commit-recovery", "cli").unwrap().load().is_err());
        let _ = tzap_auth_forget_json(&login.to_string());
        fs::remove_dir_all(temp).unwrap();
    }

    #[cfg(feature = "reqwest-transport")]
    #[test]
    fn hosted_auth_code_exchange_uses_saved_binding_and_returns_only_redacted_session_data() {
        use std::io::{Read as _, Write as _};
        let _hosted_auth_state = lock_hosted_auth_state();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        const TOKEN: &str = "fixture-session-token-never-returned-to-cli";
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut request = Vec::new();
            let body = loop {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0 && request.len() < 16384);
                request.extend_from_slice(&chunk[..read]);
                if let Some(boundary) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..boundary]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("content-length")).map(|(_, value)| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= boundary + 4 + length {
                        break serde_json::from_slice::<Value>(&request[boundary + 4..boundary + 4 + length]).unwrap();
                    }
                }
            };
            let response = json!({"session_token": TOKEN, "session_id": "fixture-session", "audience": "sign.tzap.org", "expires_at": "2099-01-01T00:00:00Z", "user_id": "fixture-user"}).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response)
                .unwrap();
            body
        });
        let temp = test_temp_dir("auth-code-exchange");
        let begin: Value = serde_json::from_str(&tzap_auth_login_json(
            &json!({
                "state_dir": temp, "account_key": "exchange-test", "environment": "local", "auth_base_url": base,
                "client_id": "zmanager-cli", "redirect_uri": "tzap://auth/callback", "now_unix_seconds": 100,
            })
            .to_string(),
        ))
        .unwrap();
        let challenge = TzapAuthSlot::acquire(&temp, "exchange-test", "cli").unwrap().load().unwrap().pending.pkce.challenge;
        let callback = json!({"state_dir": temp, "account_key": "exchange-test", "callback_url": format!("tzap://auth/callback?state={}&handoff_code=tzap_handoff_fixture_only", begin["state"].as_str().unwrap()), "now_unix_seconds": 101});
        let response = tzap_auth_callback_json(&callback.to_string());
        let exchange = server.join().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["ok"], true);
        assert_eq!(exchange["client_id"], "zmanager-cli");
        assert_eq!(exchange["redirect_uri"], "tzap://auth/callback");
        assert_eq!(exchange["state"], begin["state"]);
        assert_eq!(exchange["required_audience"], "sign.tzap.org");
        let verifier = exchange["code_verifier"].as_str().unwrap();
        assert!(crate::auth_client::pkce_s256_challenge(verifier) == challenge);
        assert!(!response.contains(TOKEN) && !response.contains(verifier));
        assert!(TzapAuthSlot::acquire(&temp, "exchange-test", "cli").unwrap().load().is_err());
        let replay: Value = serde_json::from_str(&tzap_auth_callback_json(&callback.to_string())).unwrap();
        assert_eq!(replay["ok"], false);
        let status: Value = serde_json::from_str(&tzap_auth_status_json(&json!({"state_dir": temp, "account_key": "exchange-test"}).to_string())).unwrap();
        assert_eq!(status["authenticated"], true);
        let _ = tzap_auth_forget_json(&json!({"state_dir": temp, "account_key": "exchange-test"}).to_string());
        let _ = fs::remove_dir_all(temp);
    }
}
