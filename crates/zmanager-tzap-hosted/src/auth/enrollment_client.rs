//! Client-side TZAP certificate enrollment flow.

use crate::auth_client::{SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpTransport, TzapBearerToken, TzapSessionRecord};
use crate::device_identity::csr_fingerprint;
use crate::http_client::{http_error_body, require_success, send_json_request};
use crate::jcs;
use crate::json_util::{JsonFieldError, json_object, optional_string, optional_u64, required_field, required_string, required_u64};
use crate::local_identity_store::{
    TzapCertificateOperationKind, TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityStore,
    TzapLocalIdentityStoreError, TzapPendingCertificateOperation, TzapSignDeviceRouting,
};
use crate::p256_signature;
use crate::secrets::SecretBytes;
use crate::trust::{self, TzapCertificateProfileOptions, TzapCertificatePublicMetadata};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openssl::pkey::{PKey, Private};
use serde_json::{Map, Number, Value, json};
use std::fmt::{self, Write as _};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::prelude::{FromDer as _, X509Certificate};

pub const ENROLLMENT_CHALLENGES_PATH: &str = "/v1/certificates/enrollment-challenges";
pub const ENROLL_CERTIFICATES_PATH: &str = "/v1/certificates/enroll";
pub const CERTIFICATES_PATH: &str = "/v1/certificates";
pub const CERTIFICATE_DETAIL_PATH_PREFIX: &str = "/v1/certificates/";
pub const ENROLL_OPERATION: &str = "enroll";
pub const ENROLLMENT_CHALLENGE_CANONICALIZATION: &str = "JCS-JSON";
pub const LOCAL_STAGING_ENROLLMENT_AUDIENCE: &str = "tzap.enrollment";
pub const DEFAULT_ENROLLMENT_DEVICE_NAME: &str = "ZManager CLI";
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEnrollmentRequest {
    pub account_key: String,
    pub org_id: Option<String>,
    pub requested_validity_seconds: u64,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEnrollmentChallenge {
    pub challenge_id: String,
    pub payload: Value,
    pub canonicalization: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEnrollmentCertificatePayload {
    pub certificate_id: String,
    pub leaf_certificate_der: Vec<u8>,
    pub intermediate_chain_der: Vec<Vec<u8>>,
    pub issuer_certificate_sha256: String,
    pub issuer_key_identifier: String,
    pub serial_number: String,
    pub certificate_sha256: String,
    pub not_before_unix_seconds: u64,
    pub not_after_unix_seconds: u64,
    /// S1 (mobile-tzap-archive-signing-tracker.md), sourced from the server's
    /// `renewal_grace_period_days`/`renewal_recommended_within_days`. `None`
    /// when the responding server predates S1.
    pub renewal_grace_period_days: Option<u64>,
    pub renewal_recommended_within_days: Option<u64>,
    pub sign_device_id: String,
    pub login_organization_device_id: Option<String>,
    /// Present on renewal responses/list entries when the server can identify
    /// the certificate that was superseded. Reconciliation must use this (or
    /// the predecessor fingerprint) before installing an uncertain result.
    pub predecessor_certificate_id: Option<String>,
    pub predecessor_certificate_sha256: Option<String>,
    pub lifecycle_state: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapEnrollmentDenialKind {
    EnrollmentDenied,
    DeviceApprovalRequired,
    DeviceLinkagePending,
    DeviceLinkageConflict,
    DeviceLinkageNotAllowed,
    AlgorithmNotAllowed,
}

impl TzapEnrollmentDenialKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EnrollmentDenied => "enrollment_denied",
            Self::DeviceApprovalRequired => "device_approval_required",
            Self::DeviceLinkagePending => "device_linkage_pending",
            Self::DeviceLinkageConflict => "device_linkage_conflict",
            Self::DeviceLinkageNotAllowed => "device_linkage_not_allowed",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
        }
    }

    #[must_use]
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "enrollment_denied" => Some(Self::EnrollmentDenied),
            "device_approval_required" => Some(Self::DeviceApprovalRequired),
            "device_linkage_pending" => Some(Self::DeviceLinkagePending),
            "device_linkage_conflict" => Some(Self::DeviceLinkageConflict),
            "device_linkage_not_allowed" => Some(Self::DeviceLinkageNotAllowed),
            "algorithm_not_allowed" => Some(Self::AlgorithmNotAllowed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapEnrollmentDenial {
    pub kind: TzapEnrollmentDenialKind,
    pub retry_after_unix_seconds: Option<u64>,
    pub support_reference: Option<String>,
}

#[derive(Debug)]
pub enum TzapEnrollmentError {
    Auth(TzapAuthError),
    Store(TzapLocalIdentityStoreError),
    InvalidJson(serde_json::Error),
    InvalidField { field: &'static str },
    SessionOrgMismatch,
    SessionExpired,
    ChallengeMismatch { field: &'static str },
    ChallengeExpired,
    Denied(TzapEnrollmentDenial),
    HttpStatus { status_code: u16, body: Option<String> },
    CertificateChain(String),
    CertificateOperationPending,
    Crypto(String),
    Canonicalization(String),
}

impl fmt::Display for TzapEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "enrollment auth failed: {error}"),
            Self::Store(error) => write!(f, "enrollment store update failed: {error}"),
            Self::InvalidJson(error) => write!(f, "enrollment JSON is invalid: {error}"),
            Self::InvalidField { field } => write!(f, "enrollment field is invalid: {field}"),
            Self::SessionOrgMismatch => {
                write!(f, "enrollment organization does not match selected session organization")
            }
            Self::SessionExpired => write!(f, "enrollment requires a current authenticated session"),
            Self::ChallengeMismatch { field } => {
                write!(f, "enrollment challenge field does not match request: {field}")
            }
            Self::ChallengeExpired => write!(f, "enrollment challenge expired"),
            Self::Denied(denial) => write!(f, "enrollment denied: {}", denial.kind.as_str()),
            Self::HttpStatus { status_code, body } => match body {
                Some(body) if !body.is_empty() => {
                    write!(f, "enrollment HTTP request failed with status {status_code}: {body}")
                }
                _ => write!(f, "enrollment HTTP request failed with status {status_code}"),
            },
            Self::CertificateChain(reason) => {
                write!(f, "enrollment certificate chain rejected: {reason}")
            }
            Self::CertificateOperationPending => write!(f, "certificate issuance outcome is still being reconciled"),
            Self::Crypto(reason) => write!(f, "enrollment crypto failed: {reason}"),
            Self::Canonicalization(reason) => {
                write!(f, "enrollment canonicalization failed: {reason}")
            }
        }
    }
}

impl std::error::Error for TzapEnrollmentError {}

impl From<TzapAuthError> for TzapEnrollmentError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<TzapLocalIdentityStoreError> for TzapEnrollmentError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<serde_json::Error> for TzapEnrollmentError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

pub trait TzapEnrollmentCertificateValidator {
    fn validate_certificate_chain(&self, chain_der: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError>;

    fn validate_and_complete_certificate_chain(&self, chain_der: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, TzapCertificatePublicMetadata), TzapEnrollmentError> {
        self.validate_certificate_chain(chain_der).map(|metadata| (chain_der.to_vec(), metadata))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct TzapCustomEnrollmentCertificateValidator {
    pub options: TzapCertificateProfileOptions,
}

impl TzapEnrollmentCertificateValidator for TzapCustomEnrollmentCertificateValidator {
    fn validate_certificate_chain(&self, chain_der: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
        trust::validate_custom_tzap_certificate_chain_der(chain_der, &self.options)
            .map(|validation| validation.public_metadata)
            .map_err(|error| TzapEnrollmentError::CertificateChain(error.to_string()))
    }
}

pub struct TzapEnrollmentClient<'a, T> {
    sign_base_url: String,
    transport: &'a T,
    wire_profile: crate::wire_profile::TzapWireProfile,
    device_name: String,
    clock: fn() -> u64,
}

impl<'a, T: TzapAuthHttpTransport> TzapEnrollmentClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::with_device_name(sign_base_url, transport, DEFAULT_ENROLLMENT_DEVICE_NAME)
    }

    #[must_use]
    pub fn with_device_name(sign_base_url: impl Into<String>, transport: &'a T, device_name: impl Into<String>) -> Self {
        Self::with_wire_profile(sign_base_url, transport, crate::wire_profile::TzapWireProfile::Spec, device_name)
    }

    #[must_use]
    pub fn local_staging_server(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::local_staging_server_with_device_name(sign_base_url, transport, DEFAULT_ENROLLMENT_DEVICE_NAME)
    }

    #[must_use]
    pub fn local_staging_server_with_device_name(sign_base_url: impl Into<String>, transport: &'a T, device_name: impl Into<String>) -> Self {
        Self::with_wire_profile(sign_base_url, transport, crate::wire_profile::TzapWireProfile::LocalStagingServer, device_name)
    }

    #[must_use]
    pub(crate) fn with_wire_profile(
        sign_base_url: impl Into<String>,
        transport: &'a T,
        wire_profile: crate::wire_profile::TzapWireProfile,
        device_name: impl Into<String>,
    ) -> Self {
        Self { sign_base_url: sign_base_url.into(), transport, wire_profile, device_name: device_name.into(), clock: crate::clock::unix_seconds }
    }

    /// Supplies the operation clock, normally only needed by deterministic tests.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    pub(crate) fn authorize_session(&self, session: &TzapSessionRecord) -> Result<(), TzapEnrollmentError> {
        require_enrollment_session(session, self.now())?;
        if session.provenance.is_some() {
            session.require_signing_origin(&self.sign_base_url)?;
        }
        Ok(())
    }

    pub fn request_enrollment_challenge(
        &self,
        session: &TzapSessionRecord,
        request: &TzapEnrollmentRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrollmentChallenge, TzapEnrollmentError> {
        validate_enrollment_org_context(session, request)?;
        self.authorize_session(session)?;
        validate_signing_key_and_csr(signing_key, csr_der)?;
        let body = match self.wire_profile {
            crate::wire_profile::TzapWireProfile::Spec => json!({
                "operation": ENROLL_OPERATION,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "csr_sha256": crate::device_identity::csr_fingerprint(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_seconds": request.requested_validity_seconds,
                "renewal_of_certificate_sha256": Value::Null,
            }),
            crate::wire_profile::TzapWireProfile::LocalStagingServer => json!({
                "operation": ENROLL_OPERATION,
                "csr_sha256": crate::device_identity::csr_fingerprint(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_days": requested_validity_days(request.requested_validity_seconds)?,
                "renewal_of_certificate_sha256": Value::Null,
            }),
        };
        let response = self.send_json(TzapAuthHttpMethod::Post, ENROLLMENT_CHALLENGES_PATH, Some(session.access_token.clone()), Some(body))?;
        let challenge = parse_challenge_response::<TzapEnrollmentError>(&response.body)?;
        let mut current_request = request.clone();
        current_request.now_unix_seconds = self.now();
        validate_challenge_payload(self.wire_profile, session, &current_request, signing_key, csr_der, &challenge)?;
        Ok(challenge)
    }

    pub fn submit_enrollment(
        &self,
        session: &TzapSessionRecord,
        challenge: &TzapEnrollmentChallenge,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
        self.authorize_session(session)?;
        validate_signing_key_and_csr(signing_key, csr_der)?;
        let challenge_bytes = match self.wire_profile {
            crate::wire_profile::TzapWireProfile::Spec => {
                jcs::canonicalize_json_bytes(&challenge.payload).map_err(|error| TzapEnrollmentError::Canonicalization(format!("{error:?}")))?
            }
            crate::wire_profile::TzapWireProfile::LocalStagingServer => canonicalize_local_staging_server_json_bytes(&challenge.payload)?,
        };
        let signature = sign_challenge(signing_key, &challenge_bytes)?;
        let body = match self.wire_profile {
            crate::wire_profile::TzapWireProfile::Spec => json!({
                "operation": ENROLL_OPERATION,
                "challenge_id": challenge.challenge_id,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "challenge_signature_p1363": URL_SAFE_NO_PAD.encode(signature),
                "renewal_of_certificate_sha256": Value::Null,
            }),
            crate::wire_profile::TzapWireProfile::LocalStagingServer => json!({
                "operation": ENROLL_OPERATION,
                "challenge_id": challenge.challenge_id,
                "renewal_of_certificate_sha256": Value::Null,
                "challenge_signature": URL_SAFE_NO_PAD.encode(signature),
                "old_certificate_signature": Value::Null,
                "csr_pem": csr_der_to_pem(csr_der),
                "device_name": self.device_name,
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": optional_string::<TzapEnrollmentError>(json_object::<TzapEnrollmentError>(&challenge.payload, "challenge_payload")?, "org_id")?,
                "requested_validity_days": required_u64::<TzapEnrollmentError>(json_object::<TzapEnrollmentError>(&challenge.payload, "challenge_payload")?, "requested_validity_days")?,
            }),
        };
        let response = self.send_json(TzapAuthHttpMethod::Post, ENROLL_CERTIFICATES_PATH, Some(session.access_token.clone()), Some(body))?;
        parse_enrollment_response(&response.body)
    }

    pub fn list_certificates(&self, session: &TzapSessionRecord) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
        self.authorize_session(session)?;
        let response = self.send_json(TzapAuthHttpMethod::Get, CERTIFICATES_PATH, Some(session.access_token.clone()), None)?;
        parse_certificate_list_response(&response.body)
    }

    pub fn list_organization_certificates(
        &self,
        session: &TzapSessionRecord,
        org_id: &str,
    ) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
        self.authorize_session(session)?;
        let path = format!("/v1/orgs/{}/certificates", trust::percent_encode_path_param(org_id));
        let response = self.send_json(TzapAuthHttpMethod::Get, &path, Some(session.access_token.clone()), None)?;
        parse_certificate_list_response(&response.body)
    }

    pub fn get_certificate(&self, session: &TzapSessionRecord, certificate_id: &str) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
        self.authorize_session(session)?;
        if certificate_id.is_empty() || certificate_id.contains('/') {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_id" });
        }
        let path = format!("{CERTIFICATE_DETAIL_PATH_PREFIX}{certificate_id}");
        let response = self.send_json(TzapAuthHttpMethod::Get, &path, Some(session.access_token.clone()), None)?;
        parse_enrollment_response(&response.body)
    }

    pub fn get_organization_certificate(
        &self,
        session: &TzapSessionRecord,
        org_id: &str,
        certificate_id: &str,
    ) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
        self.authorize_session(session)?;
        if certificate_id.is_empty() || certificate_id.contains('/') {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_id" });
        }
        let path = format!("/v1/orgs/{}/certificates/{certificate_id}", trust::percent_encode_path_param(org_id));
        let response = self.send_json(TzapAuthHttpMethod::Get, &path, Some(session.access_token.clone()), None)?;
        parse_enrollment_response(&response.body)
    }

    fn send_json(
        &self,
        method: TzapAuthHttpMethod,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapEnrollmentError> {
        let response = send_json_request(self.transport, method, &self.sign_base_url, path, bearer_token, body)?;
        require_success(response, |status_code, response| TzapEnrollmentError::HttpStatus { status_code, body: http_error_body(&response.body) })
    }
}

pub fn enroll_device_certificate(
    client: &TzapEnrollmentClient<'_, impl TzapAuthHttpTransport>,
    validator: &impl TzapEnrollmentCertificateValidator,
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    signing_key: &TzapDeviceSigningKeyRecord,
    csr_der: &[u8],
) -> Result<TzapEnrolledCertificateRecord, TzapEnrollmentError> {
    client.authorize_session(session)?;
    let csr_sha256 = csr_fingerprint(csr_der);
    let inventory = store.load_inventory(&request.account_key)?;
    validate_stored_signing_key(&inventory, signing_key)?;
    if let Some(pending) = inventory.pending_certificate_operations.iter().find(|operation| operation.signing_key_id == signing_key.key_id) {
        if pending.kind != TzapCertificateOperationKind::Enrollment || pending.csr_sha256 != csr_sha256 || pending.org_id != request.org_id {
            return Err(TzapEnrollmentError::CertificateOperationPending);
        }
        if let Some(record) = reconcile_pending_enrollment(client, validator, store, session, request, signing_key, pending)? {
            return Ok(record);
        }
    }
    let challenge = client.request_enrollment_challenge(session, request, signing_key, csr_der)?;
    let operation = TzapPendingCertificateOperation {
        operation_id: crate::identity_catalog::TzapSecretRef::generate().as_str().to_owned(),
        kind: TzapCertificateOperationKind::Enrollment,
        signing_key_id: signing_key.key_id.clone(),
        public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
        csr_sha256,
        org_id: request.org_id.clone(),
        requested_validity_seconds: request.requested_validity_seconds,
        created_at_unix_seconds: client.now(),
        previous_signing_key_id: None,
        renewal_policy: None,
        predecessor_certificate_id: None,
        predecessor_certificate_sha256: None,
    };
    let mut inventory = store.load_inventory(&request.account_key)?;
    validate_stored_signing_key(&inventory, signing_key)?;
    if inventory.pending_certificate_operations.iter().any(|pending| pending.signing_key_id == signing_key.key_id) {
        return Err(TzapEnrollmentError::CertificateOperationPending);
    }
    inventory.pending_certificate_operations.push(operation.clone());
    store.save_inventory(&request.account_key, inventory)?;

    let result = (|| {
        let mut payload = client.submit_enrollment(session, &challenge, signing_key, csr_der)?;
        let public_metadata = payload.validate_for_key(validator, signing_key, client.now())?;
        payload.into_store_record(request, &signing_key.key_id, public_metadata)
    })();
    let record = match result {
        Ok(record) => record,
        Err(original_error) => {
            return match reconcile_pending_enrollment(client, validator, store, session, request, signing_key, &operation) {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Err(original_error),
                Err(recovery_error) => Err(recovery_error),
            };
        }
    };
    let mut inventory = store.load_inventory(&request.account_key)?;
    validate_stored_signing_key(&inventory, signing_key)?;
    if !inventory.enrolled_certificates.iter().any(|certificate| certificate.certificate_id == record.certificate_id) {
        inventory.enrolled_certificates.push(record.clone());
    }
    inventory.pending_certificate_operations.retain(|pending| pending.operation_id != operation.operation_id);
    match store.save_inventory(&request.account_key, inventory) {
        Ok(()) => Ok(record),
        Err(_) => match reconcile_pending_enrollment(client, validator, store, session, request, signing_key, &operation) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(TzapEnrollmentError::CertificateOperationPending),
            Err(error) => Err(error),
        },
    }
}

fn reconcile_pending_enrollment(
    client: &TzapEnrollmentClient<'_, impl TzapAuthHttpTransport>,
    validator: &impl TzapEnrollmentCertificateValidator,
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    signing_key: &TzapDeviceSigningKeyRecord,
    operation: &TzapPendingCertificateOperation,
) -> Result<Option<TzapEnrolledCertificateRecord>, TzapEnrollmentError> {
    let listed = list_certificates_for_request(client, session, request).map_err(|_| TzapEnrollmentError::CertificateOperationPending)?;
    let expected_fingerprint = signing_key_public_fingerprint(signing_key)?;
    let mut candidate: Option<TzapEnrolledCertificateRecord> = None;
    for listed_certificate in listed {
        let Ok(leaf_fingerprint) = certificate_leaf_public_key_fingerprint(&listed_certificate.leaf_certificate_der) else { continue };
        if listed_certificate.lifecycle_state.as_deref() != Some("active")
            || listed_certificate.certificate_id.is_empty()
            || listed_certificate.certificate_sha256.is_empty()
            || leaf_fingerprint != expected_fingerprint
        {
            continue;
        }

        let (_, listed_metadata) = validator.validate_and_complete_certificate_chain(&listed_certificate.certificate_chain_der())?;
        if listed_metadata.public_org_id != request.org_id {
            continue;
        }
        if signing_key
            .hosted_binding
            .as_ref()
            .and_then(|binding| binding.public_device_id.as_ref())
            .is_some_and(|device_id| &listed_metadata.public_device_id != device_id)
        {
            continue;
        }
        let detail = get_certificate_for_request(client, session, request, &listed_certificate.certificate_id)
            .map_err(|_| TzapEnrollmentError::CertificateOperationPending)?;
        if detail.certificate_id != listed_certificate.certificate_id
            || detail.certificate_sha256 != listed_certificate.certificate_sha256
            || detail.lifecycle_state.as_deref() != Some("active")
        {
            continue;
        }
        let mut detail = detail;
        let detail_metadata = detail.validate_for_key(validator, signing_key, client.now())?;
        if detail_metadata != listed_metadata || detail_metadata.public_org_id != request.org_id {
            continue;
        }
        let recovered = detail.into_store_record(request, &signing_key.key_id, detail_metadata)?;
        if candidate.as_ref().is_some_and(|existing| existing.certificate_id != recovered.certificate_id) {
            return Err(TzapEnrollmentError::CertificateOperationPending);
        }
        candidate = Some(recovered);
    }

    let mut inventory = store.load_inventory(&request.account_key)?;
    validate_stored_signing_key(&inventory, signing_key)?;
    if let Some(record) = candidate {
        if !inventory.enrolled_certificates.iter().any(|certificate| certificate.certificate_id == record.certificate_id) {
            inventory.enrolled_certificates.push(record.clone());
        }
        inventory.pending_certificate_operations.retain(|pending| pending.operation_id != operation.operation_id);
        store.save_inventory(&request.account_key, inventory)?;
        return Ok(Some(record));
    }

    inventory.pending_certificate_operations.retain(|pending| pending.operation_id != operation.operation_id);
    store.save_inventory(&request.account_key, inventory)?;
    Ok(None)
}

fn list_certificates_for_request(
    client: &TzapEnrollmentClient<'_, impl TzapAuthHttpTransport>,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
    if let Some(org_id) = &request.org_id { client.list_organization_certificates(session, org_id) } else { client.list_certificates(session) }
}

fn get_certificate_for_request(
    client: &TzapEnrollmentClient<'_, impl TzapAuthHttpTransport>,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    certificate_id: &str,
) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    if let Some(org_id) = &request.org_id {
        client.get_organization_certificate(session, org_id, certificate_id)
    } else {
        client.get_certificate(session, certificate_id)
    }
}

fn certificate_leaf_public_key_fingerprint(leaf_der: &[u8]) -> Result<String, TzapEnrollmentError> {
    let key_der = openssl::x509::X509::from_der(leaf_der)
        .and_then(|certificate| certificate.public_key())
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| TzapEnrollmentError::InvalidField { field: "leaf_certificate_der" })?;
    Ok(trust::sha256_identifier(&key_der))
}

impl TzapEnrollmentCertificatePayload {
    /// Every issuance path completes the chain, validates its public wire
    /// metadata, and binds the leaf to the durable key before publication.
    pub(crate) fn validate_for_key(
        &mut self,
        validator: &impl TzapEnrollmentCertificateValidator,
        signing_key: &TzapDeviceSigningKeyRecord,
        now_unix_seconds: u64,
    ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
        if self.leaf_certificate_der.is_empty() || self.intermediate_chain_der.iter().any(Vec::is_empty) {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_chain_der" });
        }
        let (chain, metadata) = validator.validate_and_complete_certificate_chain(&self.certificate_chain_der())?;
        self.replace_certificate_chain_der(&chain)?;
        self.validate_certificate_metadata(now_unix_seconds)?;
        let leaf_key = openssl::x509::X509::from_der(&self.leaf_certificate_der)
            .and_then(|certificate| certificate.public_key())
            .and_then(|key| key.public_key_to_der())
            .map_err(|_| TzapEnrollmentError::InvalidField { field: "leaf_certificate_der" })?;
        if trust::sha256_identifier(&leaf_key) != signing_key_public_fingerprint(signing_key)? {
            return Err(TzapEnrollmentError::CertificateChain("issued certificate public key does not match the device key".to_owned()));
        }
        Ok(metadata)
    }

    fn validate_certificate_metadata(&self, now_unix_seconds: u64) -> Result<(), TzapEnrollmentError> {
        let issuer = self.intermediate_chain_der.first().ok_or(TzapEnrollmentError::InvalidField { field: "certificate_chain_der" })?;
        for der in self.certificate_chain_der() {
            let (remaining, _) = X509Certificate::from_der(&der).map_err(|_| TzapEnrollmentError::InvalidField { field: "certificate_chain_der" })?;
            if !remaining.is_empty() {
                return Err(TzapEnrollmentError::InvalidField { field: "certificate_chain_der" });
            }
        }
        if self.certificate_sha256 != trust::sha256_identifier(&self.leaf_certificate_der) {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_sha256" });
        }
        if self.issuer_certificate_sha256 != trust::sha256_identifier(issuer) {
            return Err(TzapEnrollmentError::InvalidField { field: "issuer_certificate_sha256" });
        }
        let (_, parsed) =
            X509Certificate::from_der(&self.leaf_certificate_der).map_err(|_| TzapEnrollmentError::InvalidField { field: "leaf_certificate_der" })?;
        if trust::canonical_serial_hex(parsed.raw_serial()).ok().as_deref() != Some(self.serial_number.as_str()) {
            return Err(TzapEnrollmentError::InvalidField { field: "serial_number" });
        }
        let authority =
            trust::extract_authority_key_identifier(&self.leaf_certificate_der).ok_or(TzapEnrollmentError::InvalidField { field: "issuer_key_identifier" })?;
        if Some(authority.clone()) != trust::extract_subject_key_identifier(issuer) || URL_SAFE_NO_PAD.encode(authority) != self.issuer_key_identifier {
            return Err(TzapEnrollmentError::InvalidField { field: "issuer_key_identifier" });
        }
        let (not_before, not_after) = certificate_validity_unix_seconds(&self.leaf_certificate_der)?;
        if self.not_before_unix_seconds != not_before {
            return Err(TzapEnrollmentError::InvalidField { field: "not_before_unix_seconds" });
        }
        if self.not_after_unix_seconds != not_after {
            return Err(TzapEnrollmentError::InvalidField { field: "not_after_unix_seconds" });
        }
        if now_unix_seconds < not_before || now_unix_seconds >= not_after {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_validity" });
        }
        Ok(())
    }

    #[must_use]
    pub fn certificate_chain_der(&self) -> Vec<Vec<u8>> {
        let mut chain = vec![self.leaf_certificate_der.clone()];
        chain.extend(self.intermediate_chain_der.clone());
        chain
    }

    pub(crate) fn replace_certificate_chain_der(&mut self, chain_der: &[Vec<u8>]) -> Result<(), TzapEnrollmentError> {
        let Some((leaf, intermediates)) = chain_der.split_first() else {
            return Err(TzapEnrollmentError::InvalidField { field: "certificate_chain_der" });
        };
        if leaf.is_empty() || intermediates.iter().any(Vec::is_empty) || leaf != &self.leaf_certificate_der {
            return Err(TzapEnrollmentError::CertificateChain("validated certificate chain leaf does not match enrollment response".to_owned()));
        }
        self.intermediate_chain_der = intermediates.to_vec();
        Ok(())
    }

    pub fn into_store_record(
        self,
        request: &TzapEnrollmentRequest,
        signing_key_id: &str,
        public_metadata: TzapCertificatePublicMetadata,
    ) -> Result<TzapEnrolledCertificateRecord, TzapEnrollmentError> {
        let sign_device_routing = match &request.org_id {
            Some(org_id) => TzapSignDeviceRouting::Organization {
                org_id: org_id.clone(),
                login_organization_device_id: self
                    .login_organization_device_id
                    .ok_or(TzapEnrollmentError::InvalidField { field: "login_organization_device_id" })?,
            },
            None => TzapSignDeviceRouting::Personal,
        };
        Ok(TzapEnrolledCertificateRecord {
            certificate_id: self.certificate_id,
            certificate_sha256: self.certificate_sha256,
            issuer_certificate_sha256: self.issuer_certificate_sha256,
            issuer_key_identifier: self.issuer_key_identifier,
            serial_number: self.serial_number,
            leaf_certificate_der: self.leaf_certificate_der,
            intermediate_chain_der: self.intermediate_chain_der,
            not_before_unix_seconds: self.not_before_unix_seconds,
            not_after_unix_seconds: self.not_after_unix_seconds,
            renewal_grace_period_days: self.renewal_grace_period_days,
            renewal_recommended_within_days: self.renewal_recommended_within_days,
            public_metadata,
            sign_device_id: self.sign_device_id,
            sign_device_routing,
            signing_key_id: signing_key_id.to_owned(),
            state: TzapLocalCertificateState::Active,
        })
    }
}

pub(crate) fn require_enrollment_session(session: &TzapSessionRecord, now_unix_seconds: u64) -> Result<(), TzapEnrollmentError> {
    session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
    if session.is_expired_at(now_unix_seconds) {
        return Err(TzapEnrollmentError::SessionExpired);
    }
    Ok(())
}

pub(crate) fn signing_key_public_fingerprint(signing_key: &TzapDeviceSigningKeyRecord) -> Result<String, TzapEnrollmentError> {
    let public_key = PKey::private_key_from_der(signing_key.private_key_der.expose_secret())
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| TzapEnrollmentError::Crypto("device signing key is invalid".to_owned()))?;
    let fingerprint = trust::sha256_identifier(&public_key);
    if fingerprint != signing_key.public_key_fingerprint {
        return Err(TzapEnrollmentError::Crypto("device signing key fingerprint does not match its private material".to_owned()));
    }
    Ok(fingerprint)
}

pub(crate) fn validate_signing_key_and_csr(signing_key: &TzapDeviceSigningKeyRecord, csr_der: &[u8]) -> Result<(), TzapEnrollmentError> {
    let expected = signing_key_public_fingerprint(signing_key)?;
    let csr = openssl::x509::X509Req::from_der(csr_der).map_err(|_| TzapEnrollmentError::InvalidField { field: "csr_der" })?;
    let public_key = csr.public_key().map_err(|_| TzapEnrollmentError::InvalidField { field: "csr_der" })?;
    let public_der = public_key.public_key_to_der().map_err(|_| TzapEnrollmentError::InvalidField { field: "csr_der" })?;
    if trust::sha256_identifier(&public_der) != expected || !csr.verify(&public_key).unwrap_or(false) {
        return Err(TzapEnrollmentError::InvalidField { field: "csr_der" });
    }
    Ok(())
}

pub(crate) fn validate_stored_signing_key(
    inventory: &crate::local_identity_store::TzapLocalIdentityInventory,
    signing_key: &TzapDeviceSigningKeyRecord,
) -> Result<(), TzapEnrollmentError> {
    let stored = inventory
        .device_signing_keys
        .iter()
        .find(|key| key.key_id == signing_key.key_id)
        .ok_or(TzapEnrollmentError::InvalidField { field: "signing_key_id" })?;
    if signing_key_public_fingerprint(stored)? != signing_key_public_fingerprint(signing_key)? {
        return Err(TzapEnrollmentError::InvalidField { field: "signing_key_id" });
    }
    Ok(())
}

fn validate_enrollment_org_context(session: &TzapSessionRecord, request: &TzapEnrollmentRequest) -> Result<(), TzapEnrollmentError> {
    if let (Some(selected_org_id), Some(request_org_id)) = (&session.selected_org_id, &request.org_id)
        && selected_org_id != request_org_id
    {
        return Err(TzapEnrollmentError::SessionOrgMismatch);
    }
    Ok(())
}

fn validate_challenge_payload(
    wire_profile: crate::wire_profile::TzapWireProfile,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    signing_key: &TzapDeviceSigningKeyRecord,
    csr_der: &[u8],
    challenge: &TzapEnrollmentChallenge,
) -> Result<(), TzapEnrollmentError> {
    let object = json_object::<TzapEnrollmentError>(&challenge.payload, "challenge_payload")?;
    match wire_profile {
        crate::wire_profile::TzapWireProfile::Spec => {
            expect_string(object, "canonicalization", ENROLLMENT_CHALLENGE_CANONICALIZATION)?;
            expect_string(object, "audience", SESSION_AUDIENCE_SIGN_TZAP)?;
            expect_u64(object, "requested_validity_seconds", request.requested_validity_seconds)?;
        }
        crate::wire_profile::TzapWireProfile::LocalStagingServer => {
            if challenge.canonicalization.as_deref() != Some(ENROLLMENT_CHALLENGE_CANONICALIZATION) {
                return Err(TzapEnrollmentError::ChallengeMismatch { field: "canonicalization" });
            }
            expect_string(object, "audience", LOCAL_STAGING_ENROLLMENT_AUDIENCE)?;
            expect_u64(object, "requested_validity_days", requested_validity_days(request.requested_validity_seconds)?)?;
        }
    }
    validate_challenge_profile_metadata(wire_profile, object, request.now_unix_seconds)?;
    expect_string(object, "operation", ENROLL_OPERATION)?;
    expect_string(object, "challenge_id", &challenge.challenge_id)?;
    expect_optional_string(object, "session_id", session.login_session_id.as_deref())?;
    expect_string(object, "csr_sha256", &crate::device_identity::csr_fingerprint(csr_der))?;
    expect_string(object, "device_public_key_fingerprint", &signing_key.public_key_fingerprint)?;
    expect_optional_string(object, "org_id", request.org_id.as_deref())?;
    expect_null(object, "renewal_of_certificate_sha256")?;
    Ok(())
}

pub(crate) fn validate_challenge_profile_metadata(
    wire_profile: crate::wire_profile::TzapWireProfile,
    object: &Map<String, Value>,
    now_unix_seconds: u64,
) -> Result<(), TzapEnrollmentError> {
    match wire_profile {
        crate::wire_profile::TzapWireProfile::Spec => {
            let expires_at = required_u64::<TzapEnrollmentError>(object, "expires_at_unix_seconds")?;
            if now_unix_seconds >= expires_at {
                return Err(TzapEnrollmentError::ChallengeExpired);
            }
        }
        crate::wire_profile::TzapWireProfile::LocalStagingServer => {
            expect_u64(object, "version", 1)?;
            let nonce = required_string::<TzapEnrollmentError>(object, "nonce")?;
            if decode_base64url(&nonce).map_err(|_| TzapEnrollmentError::InvalidField { field: "nonce" })?.is_empty() {
                return Err(TzapEnrollmentError::InvalidField { field: "nonce" });
            }
            let issued_at = required_rfc3339_datetime(object, "issued_at")?;
            let expires_at = required_rfc3339_datetime(object, "expires_at")?;
            if expires_at <= issued_at {
                return Err(TzapEnrollmentError::InvalidField { field: "expires_at" });
            }
            let now = OffsetDateTime::from_unix_timestamp(i64::try_from(now_unix_seconds).unwrap_or(i64::MAX))
                .map_err(|_| TzapEnrollmentError::InvalidField { field: "expires_at" })?;
            if now >= expires_at {
                return Err(TzapEnrollmentError::ChallengeExpired);
            }
        }
    }
    Ok(())
}

fn required_rfc3339_datetime(object: &Map<String, Value>, field: &'static str) -> Result<OffsetDateTime, TzapEnrollmentError> {
    let value = required_string::<TzapEnrollmentError>(object, field)?;
    OffsetDateTime::parse(&value, &Rfc3339).map_err(|_| TzapEnrollmentError::InvalidField { field })
}

fn sign_challenge(
    signing_key: &TzapDeviceSigningKeyRecord,
    challenge_bytes: &[u8],
) -> Result<[u8; p256_signature::P256_P1363_SIGNATURE_LENGTH], TzapEnrollmentError> {
    sign_p256_challenge(&signing_key.private_key_der, challenge_bytes)
}

/// Error types that can report a p256 challenge-signing failure.
pub(crate) trait ChallengeCryptoError: Sized {
    fn crypto(reason: String) -> Self;
}

impl ChallengeCryptoError for TzapEnrollmentError {
    fn crypto(reason: String) -> Self {
        Self::Crypto(reason)
    }
}

impl ChallengeCryptoError for crate::certificate_lifecycle::TzapCertificateLifecycleError {
    fn crypto(reason: String) -> Self {
        Self::Crypto(reason)
    }
}

/// Signs a canonicalized challenge payload with the p256 key encoded in
/// `secret_der`, shared by the enrollment and certificate-lifecycle clients.
///
/// The secret DER comes from [`crate::local_identity_store`] records in both
/// clients, so a single implementation keeps the signing paths identical.
pub(crate) fn sign_p256_challenge<E: ChallengeCryptoError>(
    secret_der: &SecretBytes,
    canonical_bytes: &[u8],
) -> Result<[u8; p256_signature::P256_P1363_SIGNATURE_LENGTH], E> {
    let private_key = PKey::<Private>::private_key_from_der(secret_der.expose_secret()).map_err(|error| E::crypto(error.to_string()))?;
    p256_signature::sign_p256_sha256_p1363(&private_key, canonical_bytes).map_err(|error| E::crypto(format!("{error:?}")))
}

/// Parses a challenge response body into [`TzapEnrollmentChallenge`], shared
/// by the enrollment and certificate-lifecycle clients.
///
/// The response shape is identical for enrollment and renewal challenges;
/// only the caller's error type differs, so the parser is generic over it.
pub(crate) fn parse_challenge_response<E>(bytes: &[u8]) -> Result<TzapEnrollmentChallenge, E>
where
    E: JsonFieldError + From<serde_json::Error>,
{
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object::<E>(&value, "$")?;
    Ok(TzapEnrollmentChallenge {
        challenge_id: required_string::<E>(object, "challenge_id")?,
        payload: required_field::<E>(object, "challenge_payload")?.clone(),
        canonicalization: optional_string::<E>(object, "canonicalization")?,
    })
}

pub(crate) fn parse_enrollment_response(bytes: &[u8]) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object::<TzapEnrollmentError>(&value, "$")?;
    if let Some(denial) = object.get("denial") {
        return Err(TzapEnrollmentError::Denied(parse_denial(denial)?));
    }
    if let Some(certificate) = object.get("certificate") {
        return parse_certificate_payload(certificate);
    }
    parse_certificate_payload(&value)
}

fn parse_certificate_list_response(bytes: &[u8]) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object::<TzapEnrollmentError>(&value, "$")?;
    let certificates =
        required_field::<TzapEnrollmentError>(object, "certificates")?.as_array().ok_or(TzapEnrollmentError::InvalidField { field: "certificates" })?;
    certificates.iter().map(parse_certificate_payload).collect::<Result<Vec<_>, _>>()
}

fn parse_certificate_payload(value: &Value) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let object = json_object::<TzapEnrollmentError>(value, "certificate")?;
    if object.contains_key("certificate_pem") {
        return parse_pem_certificate_payload(object);
    }
    Ok(TzapEnrollmentCertificatePayload {
        certificate_id: required_string::<TzapEnrollmentError>(object, "certificate_id")?,
        leaf_certificate_der: decode_base64url(&required_string::<TzapEnrollmentError>(object, "leaf_certificate_der")?)?,
        intermediate_chain_der: required_field::<TzapEnrollmentError>(object, "intermediate_chain_der")?
            .as_array()
            .ok_or(TzapEnrollmentError::InvalidField { field: "intermediate_chain_der" })?
            .iter()
            .map(|value| {
                let encoded = value.as_str().ok_or(TzapEnrollmentError::InvalidField { field: "intermediate_chain_der" })?;
                decode_base64url(encoded)
            })
            .collect::<Result<Vec<_>, _>>()?,
        issuer_certificate_sha256: required_string::<TzapEnrollmentError>(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: required_string::<TzapEnrollmentError>(object, "issuer_key_identifier")?,
        serial_number: required_string::<TzapEnrollmentError>(object, "serial_number")?,
        certificate_sha256: required_string::<TzapEnrollmentError>(object, "certificate_sha256")?,
        not_before_unix_seconds: required_u64::<TzapEnrollmentError>(object, "not_before_unix_seconds")?,
        not_after_unix_seconds: required_u64::<TzapEnrollmentError>(object, "not_after_unix_seconds")?,
        renewal_grace_period_days: optional_u64::<TzapEnrollmentError>(object, "renewal_grace_period_days")?,
        renewal_recommended_within_days: optional_u64::<TzapEnrollmentError>(object, "renewal_recommended_within_days")?,
        sign_device_id: required_string::<TzapEnrollmentError>(object, "sign_device_id")?,
        login_organization_device_id: optional_string::<TzapEnrollmentError>(object, "login_organization_device_id")?,
        predecessor_certificate_id: optional_string::<TzapEnrollmentError>(object, "predecessor_certificate_id")?
            .or(optional_string::<TzapEnrollmentError>(object, "renewed_from_certificate_id")?)
            .or(optional_string::<TzapEnrollmentError>(object, "renewal_of_certificate_id")?),
        predecessor_certificate_sha256: optional_string::<TzapEnrollmentError>(object, "predecessor_certificate_sha256")?
            .or(optional_string::<TzapEnrollmentError>(object, "renewed_from_certificate_sha256")?)
            .or(optional_string::<TzapEnrollmentError>(object, "renewal_of_certificate_sha256")?),
        lifecycle_state: optional_string::<TzapEnrollmentError>(object, "status")?,
    })
}

fn parse_pem_certificate_payload(object: &Map<String, Value>) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let leaf_certificate_der = certificate_pem_to_der(&required_string::<TzapEnrollmentError>(object, "certificate_pem")?, "certificate_pem")?;
    let intermediate_chain_der = required_field::<TzapEnrollmentError>(object, "chain_pem")?
        .as_array()
        .ok_or(TzapEnrollmentError::InvalidField { field: "chain_pem" })?
        .iter()
        .map(|value| {
            let pem = value.as_str().ok_or(TzapEnrollmentError::InvalidField { field: "chain_pem" })?;
            certificate_pem_to_der(pem, "chain_pem")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (not_before_unix_seconds, not_after_unix_seconds) = certificate_validity_unix_seconds(&leaf_certificate_der)?;
    Ok(TzapEnrollmentCertificatePayload {
        certificate_id: required_string::<TzapEnrollmentError>(object, "certificate_id")?,
        leaf_certificate_der,
        intermediate_chain_der,
        issuer_certificate_sha256: required_string::<TzapEnrollmentError>(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: required_string::<TzapEnrollmentError>(object, "issuer_key_identifier")?,
        serial_number: required_string::<TzapEnrollmentError>(object, "serial_number")?,
        certificate_sha256: required_string::<TzapEnrollmentError>(object, "certificate_sha256")?,
        not_before_unix_seconds,
        not_after_unix_seconds,
        renewal_grace_period_days: optional_u64::<TzapEnrollmentError>(object, "renewal_grace_period_days")?,
        renewal_recommended_within_days: optional_u64::<TzapEnrollmentError>(object, "renewal_recommended_within_days")?,
        sign_device_id: required_string::<TzapEnrollmentError>(object, "sign_device_id")?,
        login_organization_device_id: optional_string::<TzapEnrollmentError>(object, "login_organization_device_id")?,
        predecessor_certificate_id: optional_string::<TzapEnrollmentError>(object, "predecessor_certificate_id")?
            .or(optional_string::<TzapEnrollmentError>(object, "renewed_from_certificate_id")?)
            .or(optional_string::<TzapEnrollmentError>(object, "renewal_of_certificate_id")?),
        predecessor_certificate_sha256: optional_string::<TzapEnrollmentError>(object, "predecessor_certificate_sha256")?
            .or(optional_string::<TzapEnrollmentError>(object, "renewed_from_certificate_sha256")?)
            .or(optional_string::<TzapEnrollmentError>(object, "renewal_of_certificate_sha256")?),
        lifecycle_state: optional_string::<TzapEnrollmentError>(object, "status")?,
    })
}

fn parse_denial(value: &Value) -> Result<TzapEnrollmentDenial, TzapEnrollmentError> {
    let object = json_object::<TzapEnrollmentError>(value, "denial")?;
    let reason = required_string::<TzapEnrollmentError>(object, "reason")?;
    let kind = TzapEnrollmentDenialKind::from_wire_value(&reason).ok_or(TzapEnrollmentError::InvalidField { field: "denial.reason" })?;
    Ok(TzapEnrollmentDenial {
        kind,
        retry_after_unix_seconds: optional_u64::<TzapEnrollmentError>(object, "retry_after")?,
        support_reference: optional_string::<TzapEnrollmentError>(object, "support_reference")?,
    })
}

pub(crate) fn decode_base64url(value: &str) -> Result<Vec<u8>, TzapEnrollmentError> {
    crate::trust::decode_base64url_no_padding(value).map_err(|_| TzapEnrollmentError::InvalidField { field: "base64url" })
}

pub(crate) fn requested_validity_days(requested_validity_seconds: u64) -> Result<u64, TzapEnrollmentError> {
    if requested_validity_seconds == 0 {
        return Err(TzapEnrollmentError::InvalidField { field: "requested_validity_seconds" });
    }
    Ok(requested_validity_seconds.div_ceil(SECONDS_PER_DAY))
}

pub(crate) fn csr_der_to_pem(csr_der: &[u8]) -> String {
    pem_block("CERTIFICATE REQUEST", csr_der)
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    writeln!(pem, "-----END {label}-----").expect("writing to String cannot fail");
    pem
}

fn certificate_pem_to_der(pem: &str, field: &'static str) -> Result<Vec<u8>, TzapEnrollmentError> {
    trust::certificate_pem_or_der_to_der(pem.as_bytes()).map_err(|_| TzapEnrollmentError::InvalidField { field })
}

pub(crate) fn certificate_validity_unix_seconds(der: &[u8]) -> Result<(u64, u64), TzapEnrollmentError> {
    let (remaining, certificate) = X509Certificate::from_der(der).map_err(|_| TzapEnrollmentError::InvalidField { field: "certificate_pem" })?;
    if !remaining.is_empty() {
        return Err(TzapEnrollmentError::InvalidField { field: "certificate_pem" });
    }
    let validity = certificate.validity();
    let not_before = u64::try_from(validity.not_before.timestamp()).map_err(|_| TzapEnrollmentError::InvalidField { field: "not_before" })?;
    let not_after = u64::try_from(validity.not_after.timestamp()).map_err(|_| TzapEnrollmentError::InvalidField { field: "not_after" })?;
    Ok((not_before, not_after))
}

pub(crate) fn canonicalize_local_staging_server_json_bytes(value: &Value) -> Result<Vec<u8>, TzapEnrollmentError> {
    let mut output = String::new();
    write_local_staging_canonical_json(value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_local_staging_canonical_json(value: &Value, output: &mut String) -> Result<(), TzapEnrollmentError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&local_staging_canonical_number(value)),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(|error| TzapEnrollmentError::Canonicalization(error.to_string()))?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_local_staging_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|error| TzapEnrollmentError::Canonicalization(error.to_string()))?);
                output.push(':');
                write_local_staging_canonical_json(object.get(key).ok_or(TzapEnrollmentError::InvalidField { field: "challenge_payload" })?, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn local_staging_canonical_number(value: &Number) -> String {
    if let Some(number) = value.as_u64() {
        return local_staging_canonical_integer(&number.to_string());
    }
    if let Some(number) = value.as_i64() {
        return if number < 0 {
            format!("-{}", local_staging_canonical_integer(&number.unsigned_abs().to_string()))
        } else {
            local_staging_canonical_integer(&number.to_string())
        };
    }
    value.to_string().replace('E', "e")
}

fn local_staging_canonical_integer(digits: &str) -> String {
    if digits == "0" {
        return "0".to_owned();
    }
    let trimmed = digits.trim_end_matches('0');
    let zero_count = digits.len() - trimmed.len();
    if zero_count == 0 { digits.to_owned() } else { format!("{trimmed}e+{zero_count}") }
}

fn expect_string(object: &Map<String, Value>, field: &'static str, expected: &str) -> Result<(), TzapEnrollmentError> {
    let actual = required_string::<TzapEnrollmentError>(object, field)?;
    if actual == expected { Ok(()) } else { Err(TzapEnrollmentError::ChallengeMismatch { field }) }
}

fn expect_optional_string(object: &Map<String, Value>, field: &'static str, expected: Option<&str>) -> Result<(), TzapEnrollmentError> {
    let actual = optional_string::<TzapEnrollmentError>(object, field)?;
    if actual.as_deref() == expected { Ok(()) } else { Err(TzapEnrollmentError::ChallengeMismatch { field }) }
}

fn expect_u64(object: &Map<String, Value>, field: &'static str, expected: u64) -> Result<(), TzapEnrollmentError> {
    let actual = required_u64::<TzapEnrollmentError>(object, field)?;
    if actual == expected { Ok(()) } else { Err(TzapEnrollmentError::ChallengeMismatch { field }) }
}

fn expect_null(object: &Map<String, Value>, field: &'static str) -> Result<(), TzapEnrollmentError> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        _ => Err(TzapEnrollmentError::ChallengeMismatch { field }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CERTIFICATES_PATH, DEFAULT_ENROLLMENT_DEVICE_NAME, ENROLL_OPERATION, ENROLLMENT_CHALLENGE_CANONICALIZATION, LOCAL_STAGING_ENROLLMENT_AUDIENCE,
        TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentDenialKind, TzapEnrollmentError, TzapEnrollmentRequest,
        enroll_device_certificate,
    };
    use crate::auth_client::{
        SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken,
        TzapSessionRecord,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapLocalCertificateState, TzapLocalIdentityInventory,
        TzapLocalIdentityStore,
    };
    use crate::secrets::SecretBytes;
    use crate::trust::{self, TzapCertificatePublicMetadata};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use std::cell::RefCell;

    #[test]
    fn enrollment_validates_at_network_completion_instead_of_the_request_snapshot() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NOW: AtomicU64 = AtomicU64::new(100);
        fn clock() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        struct AdvancingTransport(FakeEnrollmentTransport);
        impl TzapAuthHttpTransport for AdvancingTransport {
            fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
                if request.url.ends_with("/enroll") {
                    NOW.store(150, Ordering::SeqCst);
                }
                self.0.send(request)
            }
        }
        NOW.store(100, Ordering::SeqCst);
        let fixture = EnrollmentFixture::new(None, None);
        let certificate = crate::local_tzap_service::test_enrollment_certificate_json(&fixture.signing_key, "issued-later", 150);
        let transport = AdvancingTransport(FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            TzapAuthHttpResponse { status_code: 200, body: certificate.to_string().into_bytes(), headers: Vec::new() },
        ]));
        let client = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(clock);
        let mut store = store_with_signing_key(&fixture.signing_key);
        let record = enroll_device_certificate(
            &client,
            &AcceptingCertificateValidator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap();
        assert_eq!(record.not_before_unix_seconds, 150);
        assert_eq!(fixture.request.now_unix_seconds, 100);
    }

    #[test]
    fn enrollment_checks_the_csr_key_before_sending_a_challenge_request() {
        let fixture = EnrollmentFixture::new(None, None);
        let other = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(Vec::new());
        let client = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 100);
        assert!(matches!(
            client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &other.csr_der),
            Err(TzapEnrollmentError::InvalidField { field: "csr_der" })
        ));
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn enrollment_rejects_a_valid_certificate_for_another_device_key() {
        let fixture = EnrollmentFixture::new(None, None);
        let other = EnrollmentFixture::new(None, None);
        let transport =
            FakeEnrollmentTransport::new(vec![challenge_response(&fixture, ChallengeOverride::default()), certificate_response(&other.signing_key, None)]);
        let client = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 100);
        let mut store = store_with_signing_key(&fixture.signing_key);
        let result = enroll_device_certificate(
            &client,
            &AcceptingCertificateValidator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        );
        assert!(result.is_err(), "a certificate for another SPKI must not become active");
        assert!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().enrolled_certificates.is_empty());
    }

    #[test]
    fn enrollment_lost_response_reconciles_active_certificate_instead_of_reissuing() {
        let fixture = EnrollmentFixture::new(None, None);
        let mut listed = certificate_json(&fixture.signing_key, None);
        listed["status"] = json!("active");
        let detail = json!({"certificate": listed.clone()});
        let transport = FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            TzapAuthHttpResponse { status_code: 500, body: b"{}".to_vec(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificates": [listed]}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: detail.to_string().into_bytes(), headers: Vec::new() },
        ]);
        let client = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 100);
        let mut store = store_with_signing_key(&fixture.signing_key);

        let recovered = enroll_device_certificate(
            &client,
            &AcceptingCertificateValidator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap();

        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(recovered.certificate_id, "cert_123");
        assert_eq!(inventory.enrolled_certificates.len(), 1);
        assert!(inventory.pending_certificate_operations.is_empty());
        assert_eq!(transport.requests().len(), 4);
        assert!(transport.requests().iter().all(|request| !request.url.contains("secret-token")));
    }

    #[test]
    fn enrollment_restart_recovers_durable_operation_before_challenge_creation() {
        let fixture = EnrollmentFixture::new(None, None);
        let first_transport = FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            TzapAuthHttpResponse { status_code: 500, body: b"{}".to_vec(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 503, body: b"{}".to_vec(), headers: Vec::new() },
        ]);
        let first_client = TzapEnrollmentClient::new("https://staging.tzap.org", &first_transport).with_clock(|| 100);
        let mut store = store_with_signing_key(&fixture.signing_key);
        let first = enroll_device_certificate(
            &first_client,
            &AcceptingCertificateValidator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        );
        assert!(matches!(first, Err(TzapEnrollmentError::CertificateOperationPending)));
        let pending = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(pending.pending_certificate_operations.len(), 1);

        let mut listed = certificate_json(&fixture.signing_key, None);
        listed["status"] = json!("active");
        let second_transport = FakeEnrollmentTransport::new(vec![
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificates": [listed.clone()]}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificate": listed}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let second_client = TzapEnrollmentClient::new("https://staging.tzap.org", &second_transport).with_clock(|| 100);

        let recovered = enroll_device_certificate(
            &second_client,
            &AcceptingCertificateValidator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap();
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(recovered.certificate_id, "cert_123");
        assert_eq!(inventory.enrolled_certificates.len(), 1);
        assert!(inventory.pending_certificate_operations.is_empty());
        assert_eq!(second_transport.requests().len(), 2, "restart recovery must not create a second challenge or issuance");
    }

    #[test]
    fn enrollment_rejects_wire_metadata_that_disagrees_with_the_certificate() {
        for (field, value) in [
            ("certificate_sha256", json!(trust::format_certificate_sha256(&[0x99; 32]))),
            ("issuer_certificate_sha256", json!(trust::format_certificate_sha256(&[0x99; 32]))),
            ("serial_number", json!("DEADBEEF")),
            ("issuer_key_identifier", json!("AQIDBA")),
            ("not_before_unix_seconds", json!(101)),
            ("not_after_unix_seconds", json!(200)),
        ] {
            let fixture = EnrollmentFixture::new(None, None);
            let mut certificate = certificate_json(&fixture.signing_key, None);
            certificate[field] = value;
            let transport = FakeEnrollmentTransport::new(vec![
                challenge_response(&fixture, ChallengeOverride::default()),
                TzapAuthHttpResponse { status_code: 200, body: certificate.to_string().into_bytes(), headers: Vec::new() },
            ]);
            let client = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 100);
            let mut store = store_with_signing_key(&fixture.signing_key);
            let result = enroll_device_certificate(
                &client,
                &AcceptingCertificateValidator,
                &mut store,
                &fixture.session,
                &fixture.request,
                &fixture.signing_key,
                &fixture.csr_der,
            );
            assert!(result.is_err(), "mismatched {field} must not be stored");
            assert!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().enrolled_certificates.is_empty());
        }
    }

    #[test]
    fn fake_sign_service_completes_enrollment_end_to_end() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport =
            FakeEnrollmentTransport::new(vec![challenge_response(&fixture, ChallengeOverride::default()), certificate_response(&fixture.signing_key, None)]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let record =
            enroll_device_certificate(&client, &validator, &mut store, &fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap();

        assert_eq!(record.certificate_id, "cert_123");
        assert_eq!(record.sign_device_id, "sign-device-123");
        assert_eq!(record.signing_key_id, fixture.signing_key.key_id);
        assert_eq!(record.state, TzapLocalCertificateState::Active);
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 1);

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, TzapAuthHttpMethod::Post);
        assert_eq!(requests[0].url, "https://sign.tzap.org/v1/certificates/enrollment-challenges");
        assert!(!requests[0].body.as_ref().unwrap().as_object().unwrap().contains_key("requested_signing_algorithm"));
        assert_eq!(requests[1].method, TzapAuthHttpMethod::Post);
        assert_eq!(requests[1].url, "https://sign.tzap.org/v1/certificates/enroll");
    }

    #[test]
    fn local_staging_server_profile_uses_pem_wire_contract() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport =
            FakeEnrollmentTransport::new(vec![local_staging_challenge_response(&fixture), local_staging_certificate_response(&fixture.signing_key)]);
        let client = TzapEnrollmentClient::local_staging_server("http://localhost:8080", &transport).with_clock(|| 100);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let record =
            enroll_device_certificate(&client, &validator, &mut store, &fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap();

        assert_eq!(record.certificate_id, "cert_local_123");
        let requests = transport.requests();
        let challenge_body = requests[0].body.as_ref().unwrap().as_object().unwrap();
        assert!(!challenge_body.contains_key("csr_der"));
        assert_eq!(challenge_body["requested_validity_days"], json!(90));

        let enroll_body = requests[1].body.as_ref().unwrap().as_object().unwrap();
        assert!(enroll_body["csr_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE REQUEST"));
        assert!(enroll_body.contains_key("challenge_signature"));
        assert!(!enroll_body.contains_key("challenge_signature_p1363"));
        assert_eq!(enroll_body["device_name"], DEFAULT_ENROLLMENT_DEVICE_NAME);
    }

    #[test]
    fn local_staging_profile_rejects_expired_and_malformed_challenge_times() {
        let fixture = EnrollmentFixture::new(None, None);
        for (expires_at, expired) in [("1970-01-01T00:01:40Z", true), ("not-rfc3339", false)] {
            let mut response = local_staging_challenge_response(&fixture);
            let mut body: Value = serde_json::from_slice(&response.body).unwrap();
            body["challenge_payload"]["expires_at"] = json!(expires_at);
            response.body = serde_json::to_vec(&body).unwrap();
            let transport = FakeEnrollmentTransport::new(vec![response]);
            let client = TzapEnrollmentClient::local_staging_server("http://localhost:8080", &transport).with_clock(|| 100);

            let error = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();
            if expired {
                assert!(matches!(error, TzapEnrollmentError::ChallengeExpired));
            } else {
                assert!(matches!(error, TzapEnrollmentError::InvalidField { field: "expires_at" }));
            }
            assert_eq!(transport.requests().len(), 1, "invalid challenge must not be submitted");
        }

        let mut response = local_staging_challenge_response(&fixture);
        let mut body: Value = serde_json::from_slice(&response.body).unwrap();
        body["challenge_payload"]["expires_at"] = json!("1970-01-01T00:01:40.500Z");
        response.body = serde_json::to_vec(&body).unwrap();
        let transport = FakeEnrollmentTransport::new(vec![response]);
        let client = TzapEnrollmentClient::local_staging_server("http://localhost:8080", &transport).with_clock(|| 100);
        assert!(client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).is_ok());

        let mut response = local_staging_challenge_response(&fixture);
        let mut body: Value = serde_json::from_slice(&response.body).unwrap();
        body["challenge_payload"]["issued_at"] = json!("invalid");
        response.body = serde_json::to_vec(&body).unwrap();
        let transport = FakeEnrollmentTransport::new(vec![response]);
        let client = TzapEnrollmentClient::local_staging_server("http://localhost:8080", &transport).with_clock(|| 100);
        let error = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();
        assert!(matches!(error, TzapEnrollmentError::InvalidField { field: "issued_at" }));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn local_staging_server_canonicalization_matches_current_server_numbers() {
        let payload = json!({
            "requested_validity_days": 90,
            "version": 1,
            "nested": {
                "ten": 10,
                "zero": 0
            }
        });

        let canonical = super::canonicalize_local_staging_server_json_bytes(&payload).unwrap();

        assert_eq!(String::from_utf8(canonical).unwrap(), r#"{"nested":{"ten":1e+1,"zero":0},"requested_validity_days":9e+1,"version":1}"#);
    }

    #[test]
    fn mismatched_csr_challenge_is_rejected_before_signing() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![challenge_response(
            &fixture,
            ChallengeOverride { csr_sha256: Some(trust::format_csr_sha256(&[0x42; 32])), ..ChallengeOverride::default() },
        )]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);

        let error = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();

        assert!(matches!(
            error,
            TzapEnrollmentError::ChallengeMismatch { field } if field == "csr_sha256"
        ));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn different_session_challenge_is_rejected_before_signing() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![challenge_response(
            &fixture,
            ChallengeOverride { session_id: Some(Some("other-session".to_owned())), ..ChallengeOverride::default() },
        )]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);

        let error = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();

        assert!(matches!(
            error,
            TzapEnrollmentError::ChallengeMismatch { field } if field == "session_id"
        ));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn selected_org_mismatch_rejects_but_missing_org_stays_personal() {
        let fixture = EnrollmentFixture::new(Some("org_a".to_owned()), Some("org_b".to_owned()));
        let transport = FakeEnrollmentTransport::new(Vec::new());
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);

        let error = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();
        assert!(matches!(error, TzapEnrollmentError::SessionOrgMismatch));
        assert!(transport.requests().is_empty());

        let fixture = EnrollmentFixture::new(Some("org_a".to_owned()), None);
        let transport = FakeEnrollmentTransport::new(vec![challenge_response(&fixture, ChallengeOverride::default())]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);
        client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap();

        let body = transport.requests()[0].body.clone().unwrap();
        assert!(body.get("org_id").unwrap().is_null());
    }

    #[test]
    fn malformed_certificate_chain_is_not_stored_as_active() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            certificate_response(&fixture.signing_key, Some(Vec::new())),
        ]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let error =
            enroll_device_certificate(&client, &validator, &mut store, &fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap_err();

        assert!(matches!(error, TzapEnrollmentError::CertificateOperationPending));
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert!(inventory.enrolled_certificates.is_empty());
        assert_eq!(inventory.pending_certificate_operations.len(), 1);
    }

    #[test]
    fn safe_enrollment_denials_are_typed() {
        for (reason, kind) in [
            ("device_approval_required", TzapEnrollmentDenialKind::DeviceApprovalRequired),
            ("device_linkage_pending", TzapEnrollmentDenialKind::DeviceLinkagePending),
            ("algorithm_not_allowed", TzapEnrollmentDenialKind::AlgorithmNotAllowed),
        ] {
            let fixture = EnrollmentFixture::new(None, None);
            let transport = FakeEnrollmentTransport::new(vec![challenge_response(&fixture, ChallengeOverride::default()), denial_response(reason)]);
            let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);
            let challenge = client.request_enrollment_challenge(&fixture.session, &fixture.request, &fixture.signing_key, &fixture.csr_der).unwrap();

            let error = client.submit_enrollment(&fixture.session, &challenge, &fixture.signing_key, &fixture.csr_der).unwrap_err();

            assert!(matches!(
                error,
                TzapEnrollmentError::Denied(denial) if denial.kind == kind
            ));
        }
    }

    #[test]
    fn certificate_listing_and_lookup_use_typed_paths() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"certificates": [certificate_json(&fixture.signing_key, None)]}).to_string().into_bytes(),
                headers: Vec::new(),
            },
            certificate_response(&fixture.signing_key, None),
        ]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 100);

        let listed = client.list_certificates(&fixture.session).unwrap();
        let fetched = client.get_certificate(&fixture.session, "cert_123").unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(fetched.certificate_id, "cert_123");
        let requests = transport.requests();
        assert_eq!(requests[0].url, format!("https://sign.tzap.org{CERTIFICATES_PATH}"));
        assert_eq!(requests[1].url, "https://sign.tzap.org/v1/certificates/cert_123");
    }

    struct EnrollmentFixture {
        session: TzapSessionRecord,
        request: TzapEnrollmentRequest,
        signing_key: TzapDeviceSigningKeyRecord,
        csr_der: Vec<u8>,
    }

    impl EnrollmentFixture {
        fn new(selected_org_id: Option<String>, request_org_id: Option<String>) -> Self {
            let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
            let signing_key = TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: material.public_key_fingerprint.clone(),
                private_key_der: material.private_key_der.clone(),
                created_at_unix_seconds: 100,
                label: None,
                hosted_binding: None,
            };
            Self {
                session: TzapSessionRecord {
                    user_id: None,
                    provenance: None,
                    audience: SESSION_AUDIENCE_SIGN_TZAP.to_owned(),
                    access_token: TzapBearerToken::new("secret-token").unwrap(),
                    expires_at_unix_seconds: 500,
                    identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
                    selected_org_id,
                    login_session_id: Some("login-session-1".to_owned()),
                },
                request: TzapEnrollmentRequest {
                    account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
                    org_id: request_org_id,
                    requested_validity_seconds: 90 * 24 * 60 * 60,
                    now_unix_seconds: 100,
                },
                signing_key,
                csr_der: material.csr_der,
            }
        }
    }

    #[derive(Default)]
    struct ChallengeOverride {
        csr_sha256: Option<String>,
        #[allow(clippy::option_option)]
        session_id: Option<Option<String>>,
    }

    fn challenge_response(fixture: &EnrollmentFixture, override_values: ChallengeOverride) -> TzapAuthHttpResponse {
        let csr_sha256 = override_values.csr_sha256.unwrap_or_else(|| crate::device_identity::csr_fingerprint(&fixture.csr_der));
        let session_id = override_values.session_id.unwrap_or_else(|| fixture.session.login_session_id.clone());
        let payload = json!({
            "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
            "audience": SESSION_AUDIENCE_SIGN_TZAP,
            "operation": ENROLL_OPERATION,
            "challenge_id": "challenge_123",
            "session_id": session_id,
            "csr_sha256": csr_sha256,
            "device_public_key_fingerprint": fixture.signing_key.public_key_fingerprint,
            "org_id": fixture.request.org_id,
            "requested_validity_seconds": fixture.request.requested_validity_seconds,
            "renewal_of_certificate_sha256": Value::Null,
            "expires_at_unix_seconds": 200
        });
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({
                "challenge_id": "challenge_123",
                "challenge_payload": payload
            })
            .to_string()
            .into_bytes(),
            headers: Vec::new(),
        }
    }

    fn local_staging_challenge_response(fixture: &EnrollmentFixture) -> TzapAuthHttpResponse {
        let payload = json!({
            "version": 1,
            "audience": LOCAL_STAGING_ENROLLMENT_AUDIENCE,
            "operation": ENROLL_OPERATION,
            "challenge_id": "challenge_local_123",
            "session_id": fixture.session.login_session_id,
            "csr_sha256": crate::device_identity::csr_fingerprint(&fixture.csr_der),
            "device_public_key_fingerprint": fixture.signing_key.public_key_fingerprint,
            "org_id": fixture.request.org_id,
            "requested_validity_days": 90,
            "renewal_of_certificate_sha256": Value::Null,
            "nonce": "bG9jYWxfbm9uY2U",
            "issued_at": "1970-01-01T00:00:10Z",
            "expires_at": "1970-01-01T00:05:00Z"
        });
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({
                "challenge_id": "challenge_local_123",
                "challenge_payload": payload,
                "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION
            })
            .to_string()
            .into_bytes(),
            headers: Vec::new(),
        }
    }

    fn certificate_response(key: &TzapDeviceSigningKeyRecord, intermediate_chain_der: Option<Vec<Vec<u8>>>) -> TzapAuthHttpResponse {
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({"certificate": certificate_json(key, intermediate_chain_der)}).to_string().into_bytes(),
            headers: Vec::new(),
        }
    }

    fn local_staging_certificate_response(key: &TzapDeviceSigningKeyRecord) -> TzapAuthHttpResponse {
        let mut certificate = certificate_json(key, None);
        let payload = super::parse_enrollment_response(&certificate.to_string().into_bytes()).unwrap();
        let object = certificate.as_object_mut().unwrap();
        object.remove("leaf_certificate_der");
        object.remove("intermediate_chain_der");
        object.insert("certificate_id".to_owned(), json!("cert_local_123"));
        object.insert("certificate_pem".to_owned(), json!(super::pem_block("CERTIFICATE", &payload.leaf_certificate_der)));
        object.insert("chain_pem".to_owned(), json!(payload.intermediate_chain_der.iter().map(|der| super::pem_block("CERTIFICATE", der)).collect::<Vec<_>>()));
        TzapAuthHttpResponse { status_code: 200, body: certificate.to_string().into_bytes(), headers: Vec::new() }
    }

    fn certificate_json(key: &TzapDeviceSigningKeyRecord, intermediate_chain_der: Option<Vec<Vec<u8>>>) -> Value {
        let mut certificate = crate::local_tzap_service::test_enrollment_certificate_json(key, "cert_123", 100);
        certificate["sign_device_id"] = json!("sign-device-123");
        if let Some(chain) = intermediate_chain_der {
            certificate["intermediate_chain_der"] = json!(chain.iter().map(|der| URL_SAFE_NO_PAD.encode(der)).collect::<Vec<_>>());
        }
        certificate
    }

    fn denial_response(reason: &str) -> TzapAuthHttpResponse {
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({
                "denial": {
                    "reason": reason,
                    "retry_after": 300,
                    "support_reference": "support-123"
                }
            })
            .to_string()
            .into_bytes(),
            headers: Vec::new(),
        }
    }

    fn store_with_signing_key(signing_key: &TzapDeviceSigningKeyRecord) -> InMemoryTzapLocalIdentityStore {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(TzapDeviceSigningKeyRecord {
            key_id: signing_key.key_id.clone(),
            public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
            private_key_der: SecretBytes::from(signing_key.private_key_der.expose_secret().to_vec()),
            created_at_unix_seconds: signing_key.created_at_unix_seconds,
            label: signing_key.label.clone(),
            hosted_binding: signing_key.hosted_binding.clone(),
        });
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
        store
    }

    struct AcceptingCertificateValidator;

    impl TzapEnrollmentCertificateValidator for AcceptingCertificateValidator {
        fn validate_certificate_chain(&self, chain_der: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            if chain_der.len() < 2 {
                return Err(TzapEnrollmentError::CertificateChain("malformed chain".to_owned()));
            }
            Ok(TzapCertificatePublicMetadata {
                version: 1,
                public_signer_id: "psign_0123456789ABCDEFGH".to_owned(),
                public_org_id: None,
                public_device_id: "pdev_0123456789ABCDEFGH".to_owned(),
                assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
                policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
            })
        }
    }

    struct FakeEnrollmentTransport {
        responses: RefCell<Vec<TzapAuthHttpResponse>>,
        requests: RefCell<Vec<TzapAuthHttpRequest>>,
    }

    impl FakeEnrollmentTransport {
        fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
            Self { responses: RefCell::new(responses.into_iter().rev().collect()), requests: RefCell::new(Vec::new()) }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeEnrollmentTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses.borrow_mut().pop().ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }
}
