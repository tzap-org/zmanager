//! Client-side TZAP certificate enrollment flow.

use crate::auth_client::{
    SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest,
    TzapAuthHttpTransport, TzapBearerToken, TzapSessionRecord,
};
use crate::jcs;
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityStore, TzapLocalIdentityStoreError, TzapSignDeviceRouting,
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
use sha2::{Digest as _, Sha256};
use std::fmt;
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
    pub sign_device_id: String,
    pub login_organization_device_id: Option<String>,
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TzapEnrollmentWireProfile {
    Spec,
    LocalStagingServer,
}

#[derive(Debug)]
pub enum TzapEnrollmentError {
    Auth(TzapAuthError),
    Store(TzapLocalIdentityStoreError),
    InvalidJson(serde_json::Error),
    InvalidField {
        field: &'static str,
    },
    SessionOrgMismatch,
    ChallengeMismatch {
        field: &'static str,
    },
    ChallengeExpired,
    Denied(TzapEnrollmentDenial),
    HttpStatus {
        status_code: u16,
        body: Option<String>,
    },
    CertificateChain(String),
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
            Self::SessionOrgMismatch => write!(
                f,
                "enrollment organization does not match selected session organization"
            ),
            Self::ChallengeMismatch { field } => {
                write!(
                    f,
                    "enrollment challenge field does not match request: {field}"
                )
            }
            Self::ChallengeExpired => write!(f, "enrollment challenge expired"),
            Self::Denied(denial) => write!(f, "enrollment denied: {}", denial.kind.as_str()),
            Self::HttpStatus { status_code, body } => match body {
                Some(body) if !body.is_empty() => write!(
                    f,
                    "enrollment HTTP request failed with status {status_code}: {body}"
                ),
                _ => write!(
                    f,
                    "enrollment HTTP request failed with status {status_code}"
                ),
            },
            Self::CertificateChain(reason) => {
                write!(f, "enrollment certificate chain rejected: {reason}")
            }
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
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError>;

    fn validate_and_complete_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, TzapCertificatePublicMetadata), TzapEnrollmentError> {
        self.validate_certificate_chain(chain_der)
            .map(|metadata| (chain_der.to_vec(), metadata))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct TzapCustomEnrollmentCertificateValidator {
    pub options: TzapCertificateProfileOptions,
}

impl TzapEnrollmentCertificateValidator for TzapCustomEnrollmentCertificateValidator {
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
        trust::validate_custom_tzap_certificate_chain_der(chain_der, &self.options)
            .map(|validation| validation.public_metadata)
            .map_err(|error| TzapEnrollmentError::CertificateChain(error.to_string()))
    }
}

pub struct TzapEnrollmentClient<'a, T> {
    sign_base_url: String,
    transport: &'a T,
    wire_profile: TzapEnrollmentWireProfile,
}

impl<'a, T: TzapAuthHttpTransport> TzapEnrollmentClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::with_wire_profile(sign_base_url, transport, TzapEnrollmentWireProfile::Spec)
    }

    #[must_use]
    pub fn local_staging_server(sign_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::with_wire_profile(
            sign_base_url,
            transport,
            TzapEnrollmentWireProfile::LocalStagingServer,
        )
    }

    #[must_use]
    pub fn with_wire_profile(
        sign_base_url: impl Into<String>,
        transport: &'a T,
        wire_profile: TzapEnrollmentWireProfile,
    ) -> Self {
        Self {
            sign_base_url: sign_base_url.into(),
            transport,
            wire_profile,
        }
    }

    pub fn request_enrollment_challenge(
        &self,
        session: &TzapSessionRecord,
        request: &TzapEnrollmentRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrollmentChallenge, TzapEnrollmentError> {
        validate_enrollment_org_context(session, request)?;
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let body = match self.wire_profile {
            TzapEnrollmentWireProfile::Spec => json!({
                "operation": ENROLL_OPERATION,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "csr_sha256": csr_fingerprint(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_seconds": request.requested_validity_seconds,
                "renewal_of_certificate_sha256": Value::Null,
            }),
            TzapEnrollmentWireProfile::LocalStagingServer => json!({
                "operation": ENROLL_OPERATION,
                "csr_sha256": csr_fingerprint(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_days": requested_validity_days(request.requested_validity_seconds)?,
                "renewal_of_certificate_sha256": Value::Null,
            }),
        };
        let response = self.send_json(
            TzapAuthHttpMethod::Post,
            ENROLLMENT_CHALLENGES_PATH,
            Some(session.access_token.clone()),
            Some(body),
        )?;
        let challenge = parse_challenge_response(&response.body)?;
        validate_challenge_payload(
            self.wire_profile,
            session,
            request,
            signing_key,
            csr_der,
            &challenge,
        )?;
        Ok(challenge)
    }

    pub fn submit_enrollment(
        &self,
        session: &TzapSessionRecord,
        challenge: &TzapEnrollmentChallenge,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let challenge_bytes = match self.wire_profile {
            TzapEnrollmentWireProfile::Spec => jcs::canonicalize_json_bytes(&challenge.payload)
                .map_err(|error| TzapEnrollmentError::Canonicalization(format!("{error:?}")))?,
            TzapEnrollmentWireProfile::LocalStagingServer => {
                canonicalize_local_staging_server_json_bytes(&challenge.payload)?
            }
        };
        let signature = sign_challenge(signing_key, &challenge_bytes)?;
        let body = match self.wire_profile {
            TzapEnrollmentWireProfile::Spec => json!({
                "operation": ENROLL_OPERATION,
                "challenge_id": challenge.challenge_id,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "challenge_signature_p1363": URL_SAFE_NO_PAD.encode(signature),
                "renewal_of_certificate_sha256": Value::Null,
            }),
            TzapEnrollmentWireProfile::LocalStagingServer => json!({
                "operation": ENROLL_OPERATION,
                "challenge_id": challenge.challenge_id,
                "renewal_of_certificate_sha256": Value::Null,
                "challenge_signature": URL_SAFE_NO_PAD.encode(signature),
                "old_certificate_signature": Value::Null,
                "csr_pem": csr_der_to_pem(csr_der),
                "device_name": DEFAULT_ENROLLMENT_DEVICE_NAME,
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": optional_string(json_object(&challenge.payload, "challenge_payload")?, "org_id")?,
                "requested_validity_days": required_u64(json_object(&challenge.payload, "challenge_payload")?, "requested_validity_days")?,
            }),
        };
        let response = self.send_json(
            TzapAuthHttpMethod::Post,
            ENROLL_CERTIFICATES_PATH,
            Some(session.access_token.clone()),
            Some(body),
        )?;
        parse_enrollment_response(&response.body)
    }

    pub fn list_certificates(
        &self,
        session: &TzapSessionRecord,
    ) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let response = self.send_json(
            TzapAuthHttpMethod::Get,
            CERTIFICATES_PATH,
            Some(session.access_token.clone()),
            None,
        )?;
        parse_certificate_list_response(&response.body)
    }

    pub fn get_certificate(
        &self,
        session: &TzapSessionRecord,
        certificate_id: &str,
    ) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        if certificate_id.is_empty() || certificate_id.contains('/') {
            return Err(TzapEnrollmentError::InvalidField {
                field: "certificate_id",
            });
        }
        let path = format!("{CERTIFICATE_DETAIL_PATH_PREFIX}{certificate_id}");
        let response = self.send_json(
            TzapAuthHttpMethod::Get,
            &path,
            Some(session.access_token.clone()),
            None,
        )?;
        parse_enrollment_response(&response.body)
    }

    fn send_json(
        &self,
        method: TzapAuthHttpMethod,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<crate::auth_client::TzapAuthHttpResponse, TzapEnrollmentError> {
        let response = self.transport.send(&TzapAuthHttpRequest {
            method,
            url: format!("{}{}", trim_trailing_slash(&self.sign_base_url), path),
            bearer_token,
            body,
        })?;
        if !(200..=299).contains(&response.status_code) {
            return Err(TzapEnrollmentError::HttpStatus {
                status_code: response.status_code,
                body: http_error_body(&response.body),
            });
        }
        Ok(response)
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
    let challenge = client.request_enrollment_challenge(session, request, signing_key, csr_der)?;
    let mut payload = client.submit_enrollment(session, &challenge, signing_key, csr_der)?;
    let chain = payload.certificate_chain_der();
    let (complete_chain, public_metadata) =
        validator.validate_and_complete_certificate_chain(&chain)?;
    payload.replace_certificate_chain_der(complete_chain)?;
    let record = payload.into_store_record(request, &signing_key.key_id, public_metadata)?;
    let mut inventory = store.load_inventory(&request.account_key)?;
    inventory.enrolled_certificates.push(record.clone());
    store.save_inventory(&request.account_key, inventory)?;
    Ok(record)
}

impl TzapEnrollmentCertificatePayload {
    #[must_use]
    pub fn certificate_chain_der(&self) -> Vec<Vec<u8>> {
        let mut chain = vec![self.leaf_certificate_der.clone()];
        chain.extend(self.intermediate_chain_der.clone());
        chain
    }

    fn replace_certificate_chain_der(
        &mut self,
        chain_der: Vec<Vec<u8>>,
    ) -> Result<(), TzapEnrollmentError> {
        let Some((leaf, intermediates)) = chain_der.split_first() else {
            return Err(TzapEnrollmentError::InvalidField {
                field: "certificate_chain_der",
            });
        };
        if leaf != &self.leaf_certificate_der {
            return Err(TzapEnrollmentError::CertificateChain(
                "validated certificate chain leaf does not match enrollment response".to_owned(),
            ));
        }
        self.intermediate_chain_der = intermediates.to_vec();
        Ok(())
    }

    pub(crate) fn into_store_record(
        self,
        request: &TzapEnrollmentRequest,
        signing_key_id: &str,
        public_metadata: TzapCertificatePublicMetadata,
    ) -> Result<TzapEnrolledCertificateRecord, TzapEnrollmentError> {
        let sign_device_routing = match &request.org_id {
            Some(org_id) => TzapSignDeviceRouting::Organization {
                org_id: org_id.clone(),
                login_organization_device_id: self.login_organization_device_id.ok_or(
                    TzapEnrollmentError::InvalidField {
                        field: "login_organization_device_id",
                    },
                )?,
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
            public_metadata,
            sign_device_id: self.sign_device_id,
            sign_device_routing,
            signing_key_id: signing_key_id.to_owned(),
            state: TzapLocalCertificateState::Active,
        })
    }
}

fn validate_enrollment_org_context(
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
) -> Result<(), TzapEnrollmentError> {
    if let (Some(selected_org_id), Some(request_org_id)) =
        (&session.selected_org_id, &request.org_id)
        && selected_org_id != request_org_id
    {
        return Err(TzapEnrollmentError::SessionOrgMismatch);
    }
    Ok(())
}

fn validate_challenge_payload(
    wire_profile: TzapEnrollmentWireProfile,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    signing_key: &TzapDeviceSigningKeyRecord,
    csr_der: &[u8],
    challenge: &TzapEnrollmentChallenge,
) -> Result<(), TzapEnrollmentError> {
    let object = json_object(&challenge.payload, "challenge_payload")?;
    match wire_profile {
        TzapEnrollmentWireProfile::Spec => {
            expect_string(
                object,
                "canonicalization",
                ENROLLMENT_CHALLENGE_CANONICALIZATION,
            )?;
            expect_string(object, "audience", SESSION_AUDIENCE_SIGN_TZAP)?;
            expect_u64(
                object,
                "requested_validity_seconds",
                request.requested_validity_seconds,
            )?;
            let expires_at = required_u64(object, "expires_at_unix_seconds")?;
            if request.now_unix_seconds >= expires_at {
                return Err(TzapEnrollmentError::ChallengeExpired);
            }
        }
        TzapEnrollmentWireProfile::LocalStagingServer => {
            if challenge.canonicalization.as_deref() != Some(ENROLLMENT_CHALLENGE_CANONICALIZATION)
            {
                return Err(TzapEnrollmentError::ChallengeMismatch {
                    field: "canonicalization",
                });
            }
            expect_string(object, "audience", LOCAL_STAGING_ENROLLMENT_AUDIENCE)?;
            expect_u64(
                object,
                "requested_validity_days",
                requested_validity_days(request.requested_validity_seconds)?,
            )?;
            let _ = required_string(object, "expires_at")?;
        }
    }
    expect_string(object, "operation", ENROLL_OPERATION)?;
    expect_string(object, "challenge_id", &challenge.challenge_id)?;
    expect_optional_string(object, "session_id", session.login_session_id.as_deref())?;
    expect_string(object, "csr_sha256", &csr_fingerprint(csr_der))?;
    expect_string(
        object,
        "device_public_key_fingerprint",
        &signing_key.public_key_fingerprint,
    )?;
    expect_optional_string(object, "org_id", request.org_id.as_deref())?;
    expect_null(object, "renewal_of_certificate_sha256")?;
    Ok(())
}

fn sign_challenge(
    signing_key: &TzapDeviceSigningKeyRecord,
    challenge_bytes: &[u8],
) -> Result<[u8; p256_signature::P256_P1363_SIGNATURE_LENGTH], TzapEnrollmentError> {
    let private_key = p256_private_key_from_secret(&signing_key.private_key_der)?;
    p256_signature::sign_p256_sha256_p1363(&private_key, challenge_bytes)
        .map_err(|error| TzapEnrollmentError::Crypto(format!("{error:?}")))
}

fn p256_private_key_from_secret(
    private_key_der: &SecretBytes,
) -> Result<PKey<Private>, TzapEnrollmentError> {
    PKey::private_key_from_der(private_key_der.expose_secret())
        .map_err(|error| TzapEnrollmentError::Crypto(error.to_string()))
}

fn parse_challenge_response(bytes: &[u8]) -> Result<TzapEnrollmentChallenge, TzapEnrollmentError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    Ok(TzapEnrollmentChallenge {
        challenge_id: required_string(object, "challenge_id")?,
        payload: required_field(object, "challenge_payload")?.clone(),
        canonicalization: optional_string(object, "canonicalization")?,
    })
}

pub(crate) fn parse_enrollment_response(
    bytes: &[u8],
) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    if let Some(denial) = object.get("denial") {
        return Err(TzapEnrollmentError::Denied(parse_denial(denial)?));
    }
    if let Some(certificate) = object.get("certificate") {
        return parse_certificate_payload(certificate);
    }
    parse_certificate_payload(&value)
}

fn parse_certificate_list_response(
    bytes: &[u8],
) -> Result<Vec<TzapEnrollmentCertificatePayload>, TzapEnrollmentError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    let certificates = required_field(object, "certificates")?.as_array().ok_or(
        TzapEnrollmentError::InvalidField {
            field: "certificates",
        },
    )?;
    certificates
        .iter()
        .map(parse_certificate_payload)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_certificate_payload(
    value: &Value,
) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let object = json_object(value, "certificate")?;
    if object.contains_key("certificate_pem") {
        return parse_pem_certificate_payload(object);
    }
    Ok(TzapEnrollmentCertificatePayload {
        certificate_id: required_string(object, "certificate_id")?,
        leaf_certificate_der: decode_base64url(required_string(object, "leaf_certificate_der")?)?,
        intermediate_chain_der: required_field(object, "intermediate_chain_der")?
            .as_array()
            .ok_or(TzapEnrollmentError::InvalidField {
                field: "intermediate_chain_der",
            })?
            .iter()
            .map(|value| {
                let encoded = value
                    .as_str()
                    .ok_or(TzapEnrollmentError::InvalidField {
                        field: "intermediate_chain_der",
                    })?
                    .to_owned();
                decode_base64url(encoded)
            })
            .collect::<Result<Vec<_>, _>>()?,
        issuer_certificate_sha256: required_string(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: required_string(object, "issuer_key_identifier")?,
        serial_number: required_string(object, "serial_number")?,
        certificate_sha256: required_string(object, "certificate_sha256")?,
        not_before_unix_seconds: required_u64(object, "not_before_unix_seconds")?,
        not_after_unix_seconds: required_u64(object, "not_after_unix_seconds")?,
        sign_device_id: required_string(object, "sign_device_id")?,
        login_organization_device_id: optional_string(object, "login_organization_device_id")?,
    })
}

fn parse_pem_certificate_payload(
    object: &Map<String, Value>,
) -> Result<TzapEnrollmentCertificatePayload, TzapEnrollmentError> {
    let leaf_certificate_der = certificate_pem_to_der(
        &required_string(object, "certificate_pem")?,
        "certificate_pem",
    )?;
    let intermediate_chain_der = required_field(object, "chain_pem")?
        .as_array()
        .ok_or(TzapEnrollmentError::InvalidField { field: "chain_pem" })?
        .iter()
        .map(|value| {
            let pem = value
                .as_str()
                .ok_or(TzapEnrollmentError::InvalidField { field: "chain_pem" })?;
            certificate_pem_to_der(pem, "chain_pem")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (not_before_unix_seconds, not_after_unix_seconds) =
        certificate_validity_unix_seconds(&leaf_certificate_der)?;
    Ok(TzapEnrollmentCertificatePayload {
        certificate_id: required_string(object, "certificate_id")?,
        leaf_certificate_der,
        intermediate_chain_der,
        issuer_certificate_sha256: required_string(object, "issuer_certificate_sha256")?,
        issuer_key_identifier: required_string(object, "issuer_key_identifier")?,
        serial_number: required_string(object, "serial_number")?,
        certificate_sha256: required_string(object, "certificate_sha256")?,
        not_before_unix_seconds,
        not_after_unix_seconds,
        sign_device_id: required_string(object, "sign_device_id")?,
        login_organization_device_id: optional_string(object, "login_organization_device_id")?,
    })
}

fn parse_denial(value: &Value) -> Result<TzapEnrollmentDenial, TzapEnrollmentError> {
    let object = json_object(value, "denial")?;
    let reason = required_string(object, "reason")?;
    let kind = TzapEnrollmentDenialKind::from_wire_value(&reason).ok_or(
        TzapEnrollmentError::InvalidField {
            field: "denial.reason",
        },
    )?;
    Ok(TzapEnrollmentDenial {
        kind,
        retry_after_unix_seconds: optional_u64(object, "retry_after")?,
        support_reference: optional_string(object, "support_reference")?,
    })
}

fn csr_fingerprint(csr_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(csr_der).into();
    trust::format_csr_sha256(&digest)
}

fn decode_base64url(value: String) -> Result<Vec<u8>, TzapEnrollmentError> {
    trust::validate_base64url_no_padding(&value)
        .map_err(|_| TzapEnrollmentError::InvalidField { field: "base64url" })?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TzapEnrollmentError::InvalidField { field: "base64url" })
}

fn requested_validity_days(requested_validity_seconds: u64) -> Result<u64, TzapEnrollmentError> {
    if requested_validity_seconds == 0 {
        return Err(TzapEnrollmentError::InvalidField {
            field: "requested_validity_seconds",
        });
    }
    Ok(requested_validity_seconds.div_ceil(SECONDS_PER_DAY))
}

fn csr_der_to_pem(csr_der: &[u8]) -> String {
    pem_block("CERTIFICATE REQUEST", csr_der)
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn certificate_pem_to_der(pem: &str, field: &'static str) -> Result<Vec<u8>, TzapEnrollmentError> {
    trust::certificate_pem_or_der_to_der(pem.as_bytes())
        .map_err(|_| TzapEnrollmentError::InvalidField { field })
}

fn certificate_validity_unix_seconds(der: &[u8]) -> Result<(u64, u64), TzapEnrollmentError> {
    let (remaining, certificate) =
        X509Certificate::from_der(der).map_err(|_| TzapEnrollmentError::InvalidField {
            field: "certificate_pem",
        })?;
    if !remaining.is_empty() {
        return Err(TzapEnrollmentError::InvalidField {
            field: "certificate_pem",
        });
    }
    let validity = certificate.validity();
    let not_before = u64::try_from(validity.not_before.timestamp()).map_err(|_| {
        TzapEnrollmentError::InvalidField {
            field: "not_before",
        }
    })?;
    let not_after = u64::try_from(validity.not_after.timestamp())
        .map_err(|_| TzapEnrollmentError::InvalidField { field: "not_after" })?;
    Ok((not_before, not_after))
}

fn canonicalize_local_staging_server_json_bytes(
    value: &Value,
) -> Result<Vec<u8>, TzapEnrollmentError> {
    let mut output = String::new();
    write_local_staging_canonical_json(value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_local_staging_canonical_json(
    value: &Value,
    output: &mut String,
) -> Result<(), TzapEnrollmentError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&local_staging_canonical_number(value)?),
        Value::String(value) => {
            output.push_str(
                &serde_json::to_string(value)
                    .map_err(|error| TzapEnrollmentError::Canonicalization(error.to_string()))?,
            );
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
                output.push_str(
                    &serde_json::to_string(key).map_err(|error| {
                        TzapEnrollmentError::Canonicalization(error.to_string())
                    })?,
                );
                output.push(':');
                write_local_staging_canonical_json(
                    object.get(key).ok_or(TzapEnrollmentError::InvalidField {
                        field: "challenge_payload",
                    })?,
                    output,
                )?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn local_staging_canonical_number(value: &Number) -> Result<String, TzapEnrollmentError> {
    if let Some(number) = value.as_u64() {
        return Ok(local_staging_canonical_integer(&number.to_string()));
    }
    if let Some(number) = value.as_i64() {
        return Ok(if number < 0 {
            format!(
                "-{}",
                local_staging_canonical_integer(&number.unsigned_abs().to_string())
            )
        } else {
            local_staging_canonical_integer(&number.to_string())
        });
    }
    Ok(value.to_string().replace('E', "e"))
}

fn local_staging_canonical_integer(digits: &str) -> String {
    if digits == "0" {
        return "0".to_owned();
    }
    let trimmed = digits.trim_end_matches('0');
    let zero_count = digits.len() - trimmed.len();
    if zero_count == 0 {
        digits.to_owned()
    } else {
        format!("{trimmed}e+{zero_count}")
    }
}

fn json_object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, TzapEnrollmentError> {
    value
        .as_object()
        .ok_or(TzapEnrollmentError::InvalidField { field })
}

fn required_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, TzapEnrollmentError> {
    object
        .get(field)
        .ok_or(TzapEnrollmentError::InvalidField { field })
}

fn required_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, TzapEnrollmentError> {
    required_field(object, field)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(TzapEnrollmentError::InvalidField { field })
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, TzapEnrollmentError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty())
            .map(|value| Some(value.to_owned()))
            .ok_or(TzapEnrollmentError::InvalidField { field }),
    }
}

fn required_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<u64, TzapEnrollmentError> {
    required_field(object, field)?
        .as_u64()
        .ok_or(TzapEnrollmentError::InvalidField { field })
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, TzapEnrollmentError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(TzapEnrollmentError::InvalidField { field }),
    }
}

fn expect_string(
    object: &Map<String, Value>,
    field: &'static str,
    expected: &str,
) -> Result<(), TzapEnrollmentError> {
    let actual = required_string(object, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(TzapEnrollmentError::ChallengeMismatch { field })
    }
}

fn expect_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
    expected: Option<&str>,
) -> Result<(), TzapEnrollmentError> {
    let actual = optional_string(object, field)?;
    if actual.as_deref() == expected {
        Ok(())
    } else {
        Err(TzapEnrollmentError::ChallengeMismatch { field })
    }
}

fn expect_u64(
    object: &Map<String, Value>,
    field: &'static str,
    expected: u64,
) -> Result<(), TzapEnrollmentError> {
    let actual = required_u64(object, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(TzapEnrollmentError::ChallengeMismatch { field })
    }
}

fn expect_null(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<(), TzapEnrollmentError> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        _ => Err(TzapEnrollmentError::ChallengeMismatch { field }),
    }
}

fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

fn http_error_body(bytes: &[u8]) -> Option<String> {
    let value = String::from_utf8_lossy(bytes).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::{
        CERTIFICATES_PATH, DEFAULT_ENROLLMENT_DEVICE_NAME, ENROLL_OPERATION,
        ENROLLMENT_CHALLENGE_CANONICALIZATION, LOCAL_STAGING_ENROLLMENT_AUDIENCE,
        TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentDenialKind,
        TzapEnrollmentError, TzapEnrollmentRequest, enroll_device_certificate,
    };
    use crate::auth_client::{
        SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest,
        TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken, TzapSessionRecord,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore,
        TzapDeviceSigningKeyRecord, TzapLocalCertificateState, TzapLocalIdentityInventory,
        TzapLocalIdentityStore,
    };
    use crate::secrets::SecretBytes;
    use crate::trust::{self, TzapCertificatePublicMetadata};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};
    use serde_json::{Value, json};
    use std::cell::RefCell;

    #[test]
    fn fake_sign_service_completes_enrollment_end_to_end() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            certificate_response(None),
        ]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let record = enroll_device_certificate(
            &client,
            &validator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap();

        assert_eq!(record.certificate_id, "cert_123");
        assert_eq!(record.sign_device_id, "sign-device-123");
        assert_eq!(record.signing_key_id, fixture.signing_key.key_id);
        assert_eq!(record.state, TzapLocalCertificateState::Active);
        let inventory = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 1);

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, TzapAuthHttpMethod::Post);
        assert_eq!(
            requests[0].url,
            "https://sign.tzap.org/v1/certificates/enrollment-challenges"
        );
        assert!(
            !requests[0]
                .body
                .as_ref()
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("requested_signing_algorithm")
        );
        assert_eq!(requests[1].method, TzapAuthHttpMethod::Post);
        assert_eq!(
            requests[1].url,
            "https://sign.tzap.org/v1/certificates/enroll"
        );
    }

    #[test]
    fn local_staging_server_profile_uses_pem_wire_contract() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![
            local_staging_challenge_response(&fixture),
            local_staging_certificate_response(),
        ]);
        let client =
            TzapEnrollmentClient::local_staging_server("http://localhost:8080", &transport);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let record = enroll_device_certificate(
            &client,
            &validator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap();

        assert_eq!(record.certificate_id, "cert_local_123");
        let requests = transport.requests();
        let challenge_body = requests[0].body.as_ref().unwrap().as_object().unwrap();
        assert!(!challenge_body.contains_key("csr_der"));
        assert_eq!(challenge_body["requested_validity_days"], json!(90));

        let enroll_body = requests[1].body.as_ref().unwrap().as_object().unwrap();
        assert!(
            enroll_body["csr_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE REQUEST")
        );
        assert!(enroll_body.contains_key("challenge_signature"));
        assert!(!enroll_body.contains_key("challenge_signature_p1363"));
        assert_eq!(enroll_body["device_name"], DEFAULT_ENROLLMENT_DEVICE_NAME);
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

        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"nested":{"ten":1e+1,"zero":0},"requested_validity_days":9e+1,"version":1}"#
        );
    }

    #[test]
    fn mismatched_csr_challenge_is_rejected_before_signing() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![challenge_response(
            &fixture,
            ChallengeOverride {
                csr_sha256: Some(trust::format_csr_sha256(&[0x42; 32])),
                ..ChallengeOverride::default()
            },
        )]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);

        let error = client
            .request_enrollment_challenge(
                &fixture.session,
                &fixture.request,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap_err();

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
            ChallengeOverride {
                session_id: Some(Some("other-session".to_owned())),
                ..ChallengeOverride::default()
            },
        )]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);

        let error = client
            .request_enrollment_challenge(
                &fixture.session,
                &fixture.request,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap_err();

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
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);

        let error = client
            .request_enrollment_challenge(
                &fixture.session,
                &fixture.request,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap_err();
        assert!(matches!(error, TzapEnrollmentError::SessionOrgMismatch));
        assert!(transport.requests().is_empty());

        let fixture = EnrollmentFixture::new(Some("org_a".to_owned()), None);
        let transport = FakeEnrollmentTransport::new(vec![challenge_response(
            &fixture,
            ChallengeOverride::default(),
        )]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
        client
            .request_enrollment_challenge(
                &fixture.session,
                &fixture.request,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap();

        let body = transport.requests()[0].body.clone().unwrap();
        assert!(body.get("org_id").unwrap().is_null());
    }

    #[test]
    fn malformed_certificate_chain_is_not_stored_as_active() {
        let fixture = EnrollmentFixture::new(None, None);
        let transport = FakeEnrollmentTransport::new(vec![
            challenge_response(&fixture, ChallengeOverride::default()),
            certificate_response(Some(Vec::new())),
        ]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
        let validator = AcceptingCertificateValidator;
        let mut store = store_with_signing_key(&fixture.signing_key);

        let error = enroll_device_certificate(
            &client,
            &validator,
            &mut store,
            &fixture.session,
            &fixture.request,
            &fixture.signing_key,
            &fixture.csr_der,
        )
        .unwrap_err();

        assert!(matches!(error, TzapEnrollmentError::CertificateChain(_)));
        let inventory = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert!(inventory.enrolled_certificates.is_empty());
    }

    #[test]
    fn safe_enrollment_denials_are_typed() {
        for (reason, kind) in [
            (
                "device_approval_required",
                TzapEnrollmentDenialKind::DeviceApprovalRequired,
            ),
            (
                "device_linkage_pending",
                TzapEnrollmentDenialKind::DeviceLinkagePending,
            ),
            (
                "algorithm_not_allowed",
                TzapEnrollmentDenialKind::AlgorithmNotAllowed,
            ),
        ] {
            let fixture = EnrollmentFixture::new(None, None);
            let transport = FakeEnrollmentTransport::new(vec![
                challenge_response(&fixture, ChallengeOverride::default()),
                denial_response(reason),
            ]);
            let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
            let challenge = client
                .request_enrollment_challenge(
                    &fixture.session,
                    &fixture.request,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap();

            let error = client
                .submit_enrollment(
                    &fixture.session,
                    &challenge,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap_err();

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
                body: json!({"certificates": [certificate_json(None)]})
                    .to_string()
                    .into_bytes(),
            },
            certificate_response(None),
        ]);
        let client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);

        let listed = client.list_certificates(&fixture.session).unwrap();
        let fetched = client
            .get_certificate(&fixture.session, "cert_123")
            .unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(fetched.certificate_id, "cert_123");
        let requests = transport.requests();
        assert_eq!(
            requests[0].url,
            format!("https://sign.tzap.org{CERTIFICATES_PATH}")
        );
        assert_eq!(
            requests[1].url,
            "https://sign.tzap.org/v1/certificates/cert_123"
        );
    }

    struct EnrollmentFixture {
        session: TzapSessionRecord,
        request: TzapEnrollmentRequest,
        signing_key: TzapDeviceSigningKeyRecord,
        csr_der: Vec<u8>,
    }

    impl EnrollmentFixture {
        fn new(selected_org_id: Option<String>, request_org_id: Option<String>) -> Self {
            let material =
                generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
            let signing_key = TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: material.public_key_fingerprint.clone(),
                private_key_der: material.private_key_der.clone(),
                created_at_unix_seconds: 100,
                label: None,
            };
            Self {
                session: TzapSessionRecord {
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
        session_id: Option<Option<String>>,
    }

    fn challenge_response(
        fixture: &EnrollmentFixture,
        override_values: ChallengeOverride,
    ) -> TzapAuthHttpResponse {
        let csr_sha256 = override_values
            .csr_sha256
            .unwrap_or_else(|| super::csr_fingerprint(&fixture.csr_der));
        let session_id = override_values
            .session_id
            .unwrap_or_else(|| fixture.session.login_session_id.clone());
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
        }
    }

    fn local_staging_challenge_response(fixture: &EnrollmentFixture) -> TzapAuthHttpResponse {
        let payload = json!({
            "version": 1,
            "audience": LOCAL_STAGING_ENROLLMENT_AUDIENCE,
            "operation": ENROLL_OPERATION,
            "challenge_id": "challenge_local_123",
            "session_id": fixture.session.login_session_id,
            "csr_sha256": super::csr_fingerprint(&fixture.csr_der),
            "device_public_key_fingerprint": fixture.signing_key.public_key_fingerprint,
            "org_id": fixture.request.org_id,
            "requested_validity_days": 90,
            "renewal_of_certificate_sha256": Value::Null,
            "nonce": "local_nonce",
            "issued_at": "2026-06-26T00:00:00Z",
            "expires_at": "2026-06-26T00:05:00Z"
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
        }
    }

    fn certificate_response(intermediate_chain_der: Option<Vec<Vec<u8>>>) -> TzapAuthHttpResponse {
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({"certificate": certificate_json(intermediate_chain_der)})
                .to_string()
                .into_bytes(),
        }
    }

    fn local_staging_certificate_response() -> TzapAuthHttpResponse {
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({
                "certificate_id": "cert_local_123",
                "sign_device_id": "sign-device-local-123",
                "certificate_pem": test_certificate_pem("local leaf", 1),
                "chain_pem": [test_certificate_pem("local intermediate", 2)],
                "issuer_id": "issuer-local-123",
                "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
                "issuer_key_identifier": "AQIDBA",
                "serial_number": "01ABCDEF",
                "certificate_sha256": trust::format_certificate_sha256(&[0x03; 32]),
                "not_before": "2026-06-26T00:00:00Z",
                "not_after": "2026-09-24T00:00:00Z",
                "expires_at": "2026-09-24T00:00:00Z"
            })
            .to_string()
            .into_bytes(),
        }
    }

    fn certificate_json(intermediate_chain_der: Option<Vec<Vec<u8>>>) -> serde_json::Value {
        let intermediate_chain_der =
            intermediate_chain_der.unwrap_or_else(|| vec![vec![0x30, 0x02]]);
        json!({
            "certificate_id": "cert_123",
            "leaf_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x01]),
            "intermediate_chain_der": intermediate_chain_der
                .into_iter()
                .map(|der| URL_SAFE_NO_PAD.encode(der))
                .collect::<Vec<_>>(),
            "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
            "issuer_key_identifier": "AQIDBA",
            "serial_number": "01ABCDEF",
            "certificate_sha256": trust::format_certificate_sha256(&[0x03; 32]),
            "not_before_unix_seconds": 100,
            "not_after_unix_seconds": 200,
            "sign_device_id": "sign-device-123",
            "login_organization_device_id": Value::Null
        })
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
        }
    }

    fn test_certificate_pem(common_name: &str, serial: u32) -> String {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec_key).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();
        let serial = BigNum::from_u32(serial).unwrap();
        let serial = Asn1Integer::from_bn(&serial).unwrap();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(1_782_432_000).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(1_790_208_000).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    fn store_with_signing_key(
        signing_key: &TzapDeviceSigningKeyRecord,
    ) -> InMemoryTzapLocalIdentityStore {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory
            .device_signing_keys
            .push(TzapDeviceSigningKeyRecord {
                key_id: signing_key.key_id.clone(),
                public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
                private_key_der: SecretBytes::from(
                    signing_key.private_key_der.expose_secret().to_vec(),
                ),
                created_at_unix_seconds: signing_key.created_at_unix_seconds,
                label: signing_key.label.clone(),
            });
        store
            .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
            .unwrap();
        store
    }

    struct AcceptingCertificateValidator;

    impl TzapEnrollmentCertificateValidator for AcceptingCertificateValidator {
        fn validate_certificate_chain(
            &self,
            chain_der: &[Vec<u8>],
        ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            if chain_der.len() < 2 {
                return Err(TzapEnrollmentError::CertificateChain(
                    "malformed chain".to_owned(),
                ));
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
            Self {
                responses: RefCell::new(responses.into_iter().rev().collect()),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeEnrollmentTransport {
        fn send(
            &self,
            request: &TzapAuthHttpRequest,
        ) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses
                .borrow_mut()
                .pop()
                .ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }
}
