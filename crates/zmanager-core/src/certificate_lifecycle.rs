//! Certificate renewal, revocation, and local device-retirement flows.

use crate::auth_client::{
    SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod,
    TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken,
    TzapSessionRecord,
};
use crate::enrollment_client::{
    ENROLLMENT_CHALLENGE_CANONICALIZATION, ENROLLMENT_CHALLENGES_PATH,
    TzapEnrollmentCertificateValidator, TzapEnrollmentError, TzapEnrollmentRequest,
    parse_enrollment_response,
};
use crate::jcs;
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityStore, TzapLocalIdentityStoreError, TzapOrganizationDeviceRetirement,
};
use crate::p256_signature;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::pkey::{PKey, Private};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt;

pub const RENEW_OPERATION: &str = "renew";
pub const RENEWAL_GRACE_MAX_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const CERTIFICATE_REVOKE_PATH_SUFFIX: &str = "/revoke";
pub const CERTIFICATE_RENEW_PATH_SUFFIX: &str = "/renew";
pub const SIGN_DEVICE_REVOKE_PATH_PREFIX: &str = "/v1/devices/";
pub const LOGIN_ORG_DEVICES_PATH_PREFIX: &str = "/v1/orgs/";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapRenewalPolicy {
    SameKeyRequired,
    KeyRotationAllowed,
}

impl TzapRenewalPolicy {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SameKeyRequired => "same_key_required",
            Self::KeyRotationAllowed => "key_rotation_allowed",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRenewalRequest {
    pub account_key: String,
    pub previous_certificate_id: String,
    pub previous_certificate_sha256: String,
    pub org_id: Option<String>,
    pub requested_validity_seconds: u64,
    pub renewal_policy: TzapRenewalPolicy,
    pub now_unix_seconds: u64,
    pub server_grace_seconds: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapRetirementCompletion {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRetirementReport {
    pub completion: TzapRetirementCompletion,
    pub attempted_sign_device_ids: Vec<String>,
    pub incomplete_reasons: Vec<String>,
}

#[derive(Debug)]
pub enum TzapCertificateLifecycleError {
    Auth(TzapAuthError),
    Enrollment(TzapEnrollmentError),
    Store(TzapLocalIdentityStoreError),
    InvalidJson(serde_json::Error),
    InvalidField { field: &'static str },
    CertificateNotFound,
    CertificateNotRenewable,
    RenewalTargetMismatch,
    RenewalPendingApproval,
    DeviceLinkagePending,
    DeviceLinkageConflict,
    HttpStatus { status_code: u16 },
    Crypto(String),
}

impl fmt::Display for TzapCertificateLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "certificate lifecycle auth failed: {error}"),
            Self::Enrollment(error) => write!(f, "certificate renewal enrollment failed: {error}"),
            Self::Store(error) => write!(f, "certificate lifecycle store update failed: {error}"),
            Self::InvalidJson(error) => write!(f, "certificate lifecycle JSON is invalid: {error}"),
            Self::InvalidField { field } => {
                write!(f, "certificate lifecycle field is invalid: {field}")
            }
            Self::CertificateNotFound => write!(f, "certificate was not found locally"),
            Self::CertificateNotRenewable => write!(f, "certificate is not locally renewable"),
            Self::RenewalTargetMismatch => {
                write!(f, "renewal challenge target does not match certificate")
            }
            Self::RenewalPendingApproval => write!(f, "renewal is pending device approval"),
            Self::DeviceLinkagePending => write!(f, "device linkage is pending"),
            Self::DeviceLinkageConflict => write!(f, "device linkage conflict"),
            Self::HttpStatus { status_code } => {
                write!(
                    f,
                    "certificate lifecycle HTTP request failed with status {status_code}"
                )
            }
            Self::Crypto(reason) => write!(f, "certificate lifecycle crypto failed: {reason}"),
        }
    }
}

impl std::error::Error for TzapCertificateLifecycleError {}

impl From<TzapAuthError> for TzapCertificateLifecycleError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<TzapEnrollmentError> for TzapCertificateLifecycleError {
    fn from(error: TzapEnrollmentError) -> Self {
        Self::Enrollment(error)
    }
}

impl From<TzapLocalIdentityStoreError> for TzapCertificateLifecycleError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<serde_json::Error> for TzapCertificateLifecycleError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

pub struct TzapCertificateLifecycleClient<'a, T> {
    sign_base_url: String,
    login_base_url: String,
    transport: &'a T,
}

impl<'a, T: TzapAuthHttpTransport> TzapCertificateLifecycleClient<'a, T> {
    #[must_use]
    pub fn new(
        sign_base_url: impl Into<String>,
        login_base_url: impl Into<String>,
        transport: &'a T,
    ) -> Self {
        Self {
            sign_base_url: sign_base_url.into(),
            login_base_url: login_base_url.into(),
            transport,
        }
    }

    pub fn renew_certificate(
        &self,
        validator: &impl TzapEnrollmentCertificateValidator,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        new_signing_key: &TzapDeviceSigningKeyRecord,
        previous_signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
        let previous = self.precheck_renewal(store, request)?;
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let challenge =
            self.request_renewal_challenge(session, request, new_signing_key, csr_der)?;
        validate_renewal_challenge(request, &challenge.payload)?;
        let old_signature = match request.renewal_policy {
            TzapRenewalPolicy::SameKeyRequired => Some(sign_old_certificate_challenge(
                previous_signing_key,
                &challenge.payload,
            )?),
            TzapRenewalPolicy::KeyRotationAllowed => None,
        };
        let response = self.submit_renewal(
            session,
            request,
            new_signing_key,
            csr_der,
            &challenge.challenge_id,
            old_signature.as_deref(),
        )?;
        parse_renewal_barriers(&response.body)?;
        let payload = parse_enrollment_response(&response.body)?;
        let chain = payload.certificate_chain_der();
        let public_metadata = validator
            .validate_certificate_chain(&chain)
            .map_err(TzapCertificateLifecycleError::Enrollment)?;
        let enrollment_request = TzapEnrollmentRequest {
            account_key: request.account_key.clone(),
            org_id: request.org_id.clone(),
            requested_validity_seconds: request.requested_validity_seconds,
            now_unix_seconds: request.now_unix_seconds,
        };
        let new_record = payload
            .into_store_record(
                &enrollment_request,
                &new_signing_key.key_id,
                public_metadata,
            )
            .map_err(TzapCertificateLifecycleError::Enrollment)?;
        let mut inventory = store.load_inventory(&request.account_key)?;
        inventory.enrolled_certificates.push(new_record.clone());
        store.save_inventory(&request.account_key, inventory)?;
        let mut inventory = store.load_inventory(&request.account_key)?;
        if !inventory
            .enrolled_certificates
            .iter()
            .any(|record| record.certificate_sha256 == previous.certificate_sha256)
        {
            inventory.enrolled_certificates.push(previous);
            store.save_inventory(&request.account_key, inventory)?;
        }
        Ok(new_record)
    }

    pub fn revoke_personal_certificate(
        &self,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        account_key: &str,
        certificate_id: &str,
    ) -> Result<TzapRetirementCompletion, TzapCertificateLifecycleError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let path = format!("/v1/certificates/{certificate_id}{CERTIFICATE_REVOKE_PATH_SUFFIX}");
        let response = self.send(
            TzapAuthHttpMethod::Post,
            &self.sign_base_url,
            &path,
            Some(session.access_token.clone()),
            None,
        )?;
        let completion = revocation_completion(&response)?;
        if matches!(completion, TzapRetirementCompletion::Complete) {
            mark_certificate_revoked(store, account_key, certificate_id)?;
        }
        Ok(completion)
    }

    pub fn retire_personal_devices(
        &self,
        store: &impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        account_key: &str,
    ) -> Result<TzapRetirementReport, TzapCertificateLifecycleError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let inventory = store.load_inventory(account_key)?;
        let sign_device_ids = inventory
            .active_personal_sign_device_ids()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let mut incomplete_reasons = Vec::new();
        for sign_device_id in &sign_device_ids {
            let path = format!("{SIGN_DEVICE_REVOKE_PATH_PREFIX}{sign_device_id}/revoke");
            let response = self.send(
                TzapAuthHttpMethod::Post,
                &self.sign_base_url,
                &path,
                Some(session.access_token.clone()),
                None,
            )?;
            if !matches!(
                revocation_completion(&response)?,
                TzapRetirementCompletion::Complete
            ) {
                incomplete_reasons.push(sign_device_id.clone());
            }
        }
        Ok(TzapRetirementReport {
            completion: if incomplete_reasons.is_empty() {
                TzapRetirementCompletion::Complete
            } else {
                TzapRetirementCompletion::Incomplete
            },
            attempted_sign_device_ids: sign_device_ids,
            incomplete_reasons,
        })
    }

    pub fn retire_organization_devices(
        &self,
        store: &impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        account_key: &str,
    ) -> Result<TzapRetirementReport, TzapCertificateLifecycleError> {
        session.require_audience(SESSION_AUDIENCE_LOGIN_TZAP)?;
        let inventory = store.load_inventory(account_key)?;
        let routes = inventory.active_organization_device_retirements();
        let mut incomplete_reasons = Vec::new();
        for route in &routes {
            let lookup = self.lookup_organization_device(session, route)?;
            match lookup {
                OrganizationDeviceLookup::Found(login_device_id) => {
                    let path = format!(
                        "{LOGIN_ORG_DEVICES_PATH_PREFIX}{}/devices/{login_device_id}/revoke",
                        route.org_id
                    );
                    let response = self.send(
                        TzapAuthHttpMethod::Post,
                        &self.login_base_url,
                        &path,
                        Some(session.access_token.clone()),
                        None,
                    )?;
                    if !matches!(
                        revocation_completion(&response)?,
                        TzapRetirementCompletion::Complete
                    ) {
                        incomplete_reasons.push(route.sign_device_id.clone());
                    }
                }
                OrganizationDeviceLookup::Incomplete(reason) => incomplete_reasons.push(reason),
            }
        }
        Ok(TzapRetirementReport {
            completion: if incomplete_reasons.is_empty() {
                TzapRetirementCompletion::Complete
            } else {
                TzapRetirementCompletion::Incomplete
            },
            attempted_sign_device_ids: routes
                .into_iter()
                .map(|route| route.sign_device_id)
                .collect(),
            incomplete_reasons,
        })
    }

    fn request_renewal_challenge(
        &self,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<crate::enrollment_client::TzapEnrollmentChallenge, TzapCertificateLifecycleError>
    {
        let body = json!({
            "operation": RENEW_OPERATION,
            "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
            "device_public_key_fingerprint": signing_key.public_key_fingerprint,
            "org_id": request.org_id,
            "requested_validity_seconds": request.requested_validity_seconds,
            "renewal_of_certificate_sha256": request.previous_certificate_sha256,
        });
        let response = self.send(
            TzapAuthHttpMethod::Post,
            &self.sign_base_url,
            ENROLLMENT_CHALLENGES_PATH,
            Some(session.access_token.clone()),
            Some(body),
        )?;
        parse_renewal_challenge_response(&response.body)
    }

    fn submit_renewal(
        &self,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
        challenge_id: &str,
        old_certificate_signature: Option<&str>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        let path = format!(
            "/v1/certificates/{}{}",
            request.previous_certificate_id, CERTIFICATE_RENEW_PATH_SUFFIX
        );
        let body = json!({
            "operation": RENEW_OPERATION,
            "challenge_id": challenge_id,
            "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
            "device_public_key_fingerprint": signing_key.public_key_fingerprint,
            "renewal_of_certificate_sha256": request.previous_certificate_sha256,
            "old_certificate_signature": old_certificate_signature,
        });
        self.send(
            TzapAuthHttpMethod::Post,
            &self.sign_base_url,
            &path,
            Some(session.access_token.clone()),
            Some(body),
        )
    }

    fn precheck_renewal(
        &self,
        store: &impl TzapLocalIdentityStore,
        request: &TzapRenewalRequest,
    ) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
        let inventory = store.load_inventory(&request.account_key)?;
        let certificate = inventory
            .enrolled_certificates
            .iter()
            .find(|record| {
                record.certificate_id == request.previous_certificate_id
                    && record.certificate_sha256 == request.previous_certificate_sha256
            })
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        let root_sha256 = certificate
            .intermediate_chain_der
            .last()
            .map(|der| sha256_identifier(der));
        if inventory
            .emergency_blocklist
            .blocked_issuer_sha256
            .iter()
            .any(|issuer| issuer == &certificate.issuer_certificate_sha256)
            || root_sha256.is_some_and(|root| {
                inventory
                    .emergency_blocklist
                    .blocked_root_sha256
                    .iter()
                    .any(|blocked| blocked == &root)
            })
        {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        if !matches!(certificate.state, TzapLocalCertificateState::Active) {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        let grace = request.server_grace_seconds.min(RENEWAL_GRACE_MAX_SECONDS);
        if request.now_unix_seconds > certificate.not_after_unix_seconds.saturating_add(grace) {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        Ok(certificate.clone())
    }

    fn lookup_organization_device(
        &self,
        session: &TzapSessionRecord,
        route: &TzapOrganizationDeviceRetirement,
    ) -> Result<OrganizationDeviceLookup, TzapCertificateLifecycleError> {
        let path = format!(
            "{LOGIN_ORG_DEVICES_PATH_PREFIX}{}/devices?sign_device_id={}",
            route.org_id, route.sign_device_id
        );
        let response = self.send_raw(
            TzapAuthHttpMethod::Get,
            &self.login_base_url,
            &path,
            Some(session.access_token.clone()),
            None,
        )?;
        if response.status_code == 404 {
            return Ok(OrganizationDeviceLookup::Incomplete(format!(
                "{}:not_found",
                route.sign_device_id
            )));
        }
        if response.status_code == 409
            && body_error_code(&response.body)? == "device_linkage_pending"
        {
            return Ok(OrganizationDeviceLookup::Incomplete(format!(
                "{}:device_linkage_pending",
                route.sign_device_id
            )));
        }
        if !(200..=299).contains(&response.status_code) {
            return Err(TzapCertificateLifecycleError::HttpStatus {
                status_code: response.status_code,
            });
        }
        let value: Value = serde_json::from_slice(&response.body)?;
        let object = json_object(&value, "$")?;
        let login_device_id = optional_string(object, "organization_device_id")?
            .unwrap_or_else(|| route.login_organization_device_id.clone());
        Ok(OrganizationDeviceLookup::Found(login_device_id))
    }

    fn send(
        &self,
        method: TzapAuthHttpMethod,
        base_url: &str,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        let response = self.send_raw(method, base_url, path, bearer_token, body)?;
        if !(200..=299).contains(&response.status_code) {
            return Err(TzapCertificateLifecycleError::HttpStatus {
                status_code: response.status_code,
            });
        }
        Ok(response)
    }

    fn send_raw(
        &self,
        method: TzapAuthHttpMethod,
        base_url: &str,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        Ok(self.transport.send(&TzapAuthHttpRequest {
            method,
            url: format!("{}{}", trim_trailing_slash(base_url), path),
            bearer_token,
            body,
        })?)
    }
}

enum OrganizationDeviceLookup {
    Found(String),
    Incomplete(String),
}

fn validate_renewal_challenge(
    request: &TzapRenewalRequest,
    payload: &Value,
) -> Result<(), TzapCertificateLifecycleError> {
    let object = json_object(payload, "challenge_payload")?;
    expect_string(
        object,
        "canonicalization",
        ENROLLMENT_CHALLENGE_CANONICALIZATION,
    )?;
    expect_string(object, "operation", RENEW_OPERATION)?;
    expect_string(
        object,
        "renewal_of_certificate_sha256",
        &request.previous_certificate_sha256,
    )?;
    expect_string(object, "certificate_id", &request.previous_certificate_id)?;
    expect_optional_string(object, "org_id", request.org_id.as_deref())?;
    Ok(())
}

fn parse_renewal_challenge_response(
    bytes: &[u8],
) -> Result<crate::enrollment_client::TzapEnrollmentChallenge, TzapCertificateLifecycleError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    Ok(crate::enrollment_client::TzapEnrollmentChallenge {
        challenge_id: optional_string(object, "challenge_id")?.ok_or(
            TzapCertificateLifecycleError::InvalidField {
                field: "challenge_id",
            },
        )?,
        payload: object
            .get("challenge_payload")
            .ok_or(TzapCertificateLifecycleError::InvalidField {
                field: "challenge_payload",
            })?
            .clone(),
    })
}

fn sign_old_certificate_challenge(
    previous_signing_key: &TzapDeviceSigningKeyRecord,
    challenge_payload: &Value,
) -> Result<String, TzapCertificateLifecycleError> {
    let canonical = jcs::canonicalize_json_bytes(challenge_payload)
        .map_err(|error| TzapCertificateLifecycleError::Crypto(format!("{error:?}")))?;
    let private_key =
        PKey::<Private>::private_key_from_der(previous_signing_key.private_key_der.expose_secret())
            .map_err(|error| TzapCertificateLifecycleError::Crypto(error.to_string()))?;
    let signature = p256_signature::sign_p256_sha256_p1363(&private_key, &canonical)
        .map_err(|error| TzapCertificateLifecycleError::Crypto(format!("{error:?}")))?;
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn parse_renewal_barriers(bytes: &[u8]) -> Result<(), TzapCertificateLifecycleError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    match optional_string(object, "status")?.as_deref() {
        Some("device_approval_required") => {
            Err(TzapCertificateLifecycleError::RenewalPendingApproval)
        }
        Some("device_linkage_pending") => Err(TzapCertificateLifecycleError::DeviceLinkagePending),
        Some("device_linkage_conflict") => {
            Err(TzapCertificateLifecycleError::DeviceLinkageConflict)
        }
        _ => Ok(()),
    }
}

fn revocation_completion(
    response: &TzapAuthHttpResponse,
) -> Result<TzapRetirementCompletion, TzapCertificateLifecycleError> {
    if response.status_code == 202 {
        return Ok(TzapRetirementCompletion::Incomplete);
    }
    let value: Value = serde_json::from_slice(&response.body)?;
    let object = json_object(&value, "$")?;
    match optional_string(object, "result")?.as_deref() {
        Some("revoked" | "already_revoked") => Ok(TzapRetirementCompletion::Complete),
        Some("revocation_pending_sync") => Ok(TzapRetirementCompletion::Incomplete),
        _ => Ok(TzapRetirementCompletion::Complete),
    }
}

fn mark_certificate_revoked(
    store: &mut impl TzapLocalIdentityStore,
    account_key: &str,
    certificate_id: &str,
) -> Result<(), TzapCertificateLifecycleError> {
    let mut inventory = store.load_inventory(account_key)?;
    for certificate in &mut inventory.enrolled_certificates {
        if certificate.certificate_id == certificate_id {
            certificate.state = TzapLocalCertificateState::Revoked;
        }
    }
    store.save_inventory(account_key, inventory)?;
    Ok(())
}

fn body_error_code(bytes: &[u8]) -> Result<String, TzapCertificateLifecycleError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object(&value, "$")?;
    Ok(optional_string(object, "error")?.unwrap_or_default())
}

fn sha256_identifier(bytes: &[u8]) -> String {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    crate::trust::format_sha256_identifier(&digest)
}

fn json_object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, TzapCertificateLifecycleError> {
    value
        .as_object()
        .ok_or(TzapCertificateLifecycleError::InvalidField { field })
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, TzapCertificateLifecycleError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty())
            .map(|value| Some(value.to_owned()))
            .ok_or(TzapCertificateLifecycleError::InvalidField { field }),
    }
}

fn expect_string(
    object: &Map<String, Value>,
    field: &'static str,
    expected: &str,
) -> Result<(), TzapCertificateLifecycleError> {
    match optional_string(object, field)?.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(TzapCertificateLifecycleError::RenewalTargetMismatch),
    }
}

fn expect_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
    expected: Option<&str>,
) -> Result<(), TzapCertificateLifecycleError> {
    let actual = optional_string(object, field)?;
    if actual.as_deref() == expected {
        Ok(())
    } else {
        Err(TzapCertificateLifecycleError::RenewalTargetMismatch)
    }
}

fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::{
        RENEW_OPERATION, TzapCertificateLifecycleClient, TzapCertificateLifecycleError,
        TzapRenewalPolicy, TzapRenewalRequest, TzapRetirementCompletion,
    };
    use crate::auth_client::{
        SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError,
        TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken,
        TzapSessionRecord,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::enrollment_client::{TzapEnrollmentCertificateValidator, TzapEnrollmentError};
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore,
        TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord,
        TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
        TzapSignDeviceRouting,
    };
    use crate::trust::{self, TzapCertificatePublicMetadata};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::cell::RefCell;

    #[test]
    fn renewal_same_key_submits_old_certificate_signature_and_appends_new_certificate() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            renewal_certificate_response(),
        ]);
        let client = TzapCertificateLifecycleClient::new(
            "https://sign.tzap.org",
            "https://login.tzap.org",
            &transport,
        );
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let renewed = client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &fixture.renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap();

        assert_eq!(renewed.certificate_id, "cert_new");
        let inventory = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 2);
        let requests = transport.requests();
        assert_eq!(
            requests[1].url,
            "https://sign.tzap.org/v1/certificates/cert_old/renew"
        );
        assert!(
            requests[1]
                .body
                .as_ref()
                .unwrap()
                .get("old_certificate_signature")
                .unwrap()
                .as_str()
                .is_some()
        );
    }

    #[test]
    fn rotated_key_renewal_omits_old_signature_and_keeps_old_certificate() {
        let fixture = LifecycleFixture::new();
        let rotated = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            renewal_certificate_response(),
        ]);
        let client = TzapCertificateLifecycleClient::new(
            "https://sign.tzap.org",
            "https://login.tzap.org",
            &transport,
        );
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &fixture.renewal_request(TzapRenewalPolicy::KeyRotationAllowed),
                &rotated.signing_key,
                &fixture.signing_key,
                &rotated.csr_der,
            )
            .unwrap();

        let body = transport.requests()[1].body.clone().unwrap();
        assert!(body.get("old_certificate_signature").unwrap().is_null());
        let inventory = store
            .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
            .unwrap();
        assert!(
            inventory
                .enrolled_certificates
                .iter()
                .any(|record| record.certificate_id == "cert_old")
        );
        assert!(
            inventory
                .enrolled_certificates
                .iter()
                .any(|record| record.certificate_id == "cert_new")
        );
    }

    #[test]
    fn renewal_rejects_pending_linkage_conflict_and_target_mismatch() {
        for (status, expected) in [
            ("device_approval_required", "approval"),
            ("device_linkage_pending", "pending"),
            ("device_linkage_conflict", "conflict"),
        ] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(vec![
                renewal_challenge_response(&fixture, None),
                TzapAuthHttpResponse {
                    status_code: 200,
                    body: json!({"status": status}).to_string().into_bytes(),
                },
            ]);
            let client = TzapCertificateLifecycleClient::new(
                "https://sign.tzap.org",
                "https://login.tzap.org",
                &transport,
            );
            let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
            let error = client
                .renew_certificate(
                    &AcceptingLifecycleValidator,
                    &mut store,
                    &fixture.sign_session,
                    &fixture.renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap_err();
            match expected {
                "approval" => assert!(matches!(
                    error,
                    TzapCertificateLifecycleError::RenewalPendingApproval
                )),
                "pending" => assert!(matches!(
                    error,
                    TzapCertificateLifecycleError::DeviceLinkagePending
                )),
                "conflict" => assert!(matches!(
                    error,
                    TzapCertificateLifecycleError::DeviceLinkageConflict
                )),
                _ => unreachable!(),
            }
        }

        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(
            &fixture,
            Some(trust::format_certificate_sha256(&[0x99; 32])),
        )]);
        let client = TzapCertificateLifecycleClient::new(
            "https://sign.tzap.org",
            "https://login.tzap.org",
            &transport,
        );
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let error = client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &fixture.renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            TzapCertificateLifecycleError::RenewalTargetMismatch
        ));
    }

    #[test]
    fn renewal_precheck_rejects_blocked_issuer_and_root() {
        for block in ["issuer", "root"] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(Vec::new());
            let client = TzapCertificateLifecycleClient::new(
                "https://sign.tzap.org",
                "https://login.tzap.org",
                &transport,
            );
            let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
            let mut inventory = store
                .load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT)
                .unwrap();
            let cert = inventory.enrolled_certificates.first().unwrap();
            match block {
                "issuer" => {
                    inventory
                        .emergency_blocklist
                        .blocked_issuer_sha256
                        .push(cert.issuer_certificate_sha256.clone());
                }
                "root" => {
                    let root_der = cert.intermediate_chain_der.last().unwrap();
                    inventory.emergency_blocklist.blocked_root_sha256.push(
                        trust::format_sha256_identifier(&Sha256::digest(root_der).into()),
                    );
                }
                _ => unreachable!(),
            }
            store
                .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
                .unwrap();

            let error = client
                .renew_certificate(
                    &AcceptingLifecycleValidator,
                    &mut store,
                    &fixture.sign_session,
                    &fixture.renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap_err();

            assert!(matches!(
                error,
                TzapCertificateLifecycleError::CertificateNotRenewable
            ));
            assert!(transport.requests().is_empty());
        }
    }

    #[test]
    fn personal_revocation_and_retirement_keep_pending_sync_incomplete() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"result": "already_revoked"})
                    .to_string()
                    .into_bytes(),
            },
            TzapAuthHttpResponse {
                status_code: 202,
                body: json!({"result": "revocation_pending_sync"})
                    .to_string()
                    .into_bytes(),
            },
        ]);
        let client = TzapCertificateLifecycleClient::new(
            "https://sign.tzap.org",
            "https://login.tzap.org",
            &transport,
        );
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let cert_completion = client
            .revoke_personal_certificate(
                &mut store,
                &fixture.sign_session,
                DEFAULT_IDENTITY_INVENTORY_ACCOUNT,
                "cert_old",
            )
            .unwrap();
        assert_eq!(cert_completion, TzapRetirementCompletion::Complete);
        let store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let device_report = client
            .retire_personal_devices(
                &store,
                &fixture.sign_session,
                DEFAULT_IDENTITY_INVENTORY_ACCOUNT,
            )
            .unwrap();
        assert_eq!(
            device_report.completion,
            TzapRetirementCompletion::Incomplete
        );
        assert_eq!(
            device_report.attempted_sign_device_ids,
            vec!["sign-device-old"]
        );
    }

    #[test]
    fn organization_retirement_uses_login_routes_and_keeps_404_and_linkage_pending_incomplete() {
        for response in [
            TzapAuthHttpResponse {
                status_code: 404,
                body: b"{}".to_vec(),
            },
            TzapAuthHttpResponse {
                status_code: 409,
                body: json!({"error": "device_linkage_pending"})
                    .to_string()
                    .into_bytes(),
            },
        ] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(vec![response]);
            let client = TzapCertificateLifecycleClient::new(
                "https://sign.tzap.org",
                "https://login.tzap.org",
                &transport,
            );
            let store = fixture.store_with_certificate(TzapSignDeviceRouting::Organization {
                org_id: "org_123".to_owned(),
                login_organization_device_id: "login-org-device-1".to_owned(),
            });

            let report = client
                .retire_organization_devices(
                    &store,
                    &fixture.login_session,
                    DEFAULT_IDENTITY_INVENTORY_ACCOUNT,
                )
                .unwrap();
            assert_eq!(report.completion, TzapRetirementCompletion::Incomplete);
            let urls = transport
                .requests()
                .into_iter()
                .map(|request| request.url)
                .collect::<Vec<_>>();
            assert_eq!(urls.len(), 1);
            assert!(urls[0].starts_with(
                "https://login.tzap.org/v1/orgs/org_123/devices?sign_device_id=sign-device-old"
            ));
            assert!(!urls[0].contains("https://sign.tzap.org/v1/devices"));
        }
    }

    struct LifecycleFixture {
        sign_session: TzapSessionRecord,
        login_session: TzapSessionRecord,
        signing_key: TzapDeviceSigningKeyRecord,
        csr_der: Vec<u8>,
    }

    impl LifecycleFixture {
        fn new() -> Self {
            let material =
                generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
            let signing_key = TzapDeviceSigningKeyRecord {
                key_id: "device-key-1".to_owned(),
                public_key_fingerprint: material.public_key_fingerprint,
                private_key_der: material.private_key_der,
                created_at_unix_seconds: 100,
                label: None,
            };
            Self {
                sign_session: session(SESSION_AUDIENCE_SIGN_TZAP),
                login_session: session(SESSION_AUDIENCE_LOGIN_TZAP),
                signing_key,
                csr_der: material.csr_der,
            }
        }

        fn renewal_request(&self, policy: TzapRenewalPolicy) -> TzapRenewalRequest {
            TzapRenewalRequest {
                account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
                previous_certificate_id: "cert_old".to_owned(),
                previous_certificate_sha256: trust::format_certificate_sha256(&[0x03; 32]),
                org_id: None,
                requested_validity_seconds: 90 * 24 * 60 * 60,
                renewal_policy: policy,
                now_unix_seconds: 150,
                server_grace_seconds: 30 * 24 * 60 * 60,
            }
        }

        fn store_with_certificate(
            &self,
            routing: TzapSignDeviceRouting,
        ) -> InMemoryTzapLocalIdentityStore {
            let mut store = InMemoryTzapLocalIdentityStore::new();
            let mut inventory = TzapLocalIdentityInventory::empty();
            inventory.device_signing_keys.push(self.signing_key.clone());
            inventory
                .enrolled_certificates
                .push(certificate_record(routing));
            inventory.emergency_blocklist = TzapEmergencyBlocklistState::default();
            store
                .save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory)
                .unwrap();
            store
        }
    }

    fn session(audience: &str) -> TzapSessionRecord {
        TzapSessionRecord {
            audience: audience.to_owned(),
            access_token: TzapBearerToken::new("secret-token").unwrap(),
            expires_at_unix_seconds: 300,
            identity_assurance: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            selected_org_id: None,
            login_session_id: Some("login-session-1".to_owned()),
        }
    }

    fn certificate_record(routing: TzapSignDeviceRouting) -> TzapEnrolledCertificateRecord {
        TzapEnrolledCertificateRecord {
            certificate_id: "cert_old".to_owned(),
            certificate_sha256: trust::format_certificate_sha256(&[0x03; 32]),
            issuer_certificate_sha256: trust::format_certificate_sha256(&[0x04; 32]),
            issuer_key_identifier: "AQIDBA".to_owned(),
            serial_number: "01ABCDEF".to_owned(),
            leaf_certificate_der: vec![0x30, 0x01],
            intermediate_chain_der: vec![vec![0x30, 0x02]],
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            public_metadata: public_metadata(),
            sign_device_id: "sign-device-old".to_owned(),
            sign_device_routing: routing,
            signing_key_id: "device-key-1".to_owned(),
            state: TzapLocalCertificateState::Active,
        }
    }

    fn renewal_challenge_response(
        fixture: &LifecycleFixture,
        target_override: Option<String>,
    ) -> TzapAuthHttpResponse {
        let target =
            target_override.unwrap_or_else(|| trust::format_certificate_sha256(&[0x03; 32]));
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({
                "challenge_id": "renew-challenge-1",
                "challenge_payload": {
                    "canonicalization": "JCS-JSON",
                    "operation": RENEW_OPERATION,
                    "certificate_id": "cert_old",
                    "renewal_of_certificate_sha256": target,
                    "org_id": Value::Null,
                    "device_public_key_fingerprint": fixture.signing_key.public_key_fingerprint,
                }
            })
            .to_string()
            .into_bytes(),
        }
    }

    fn renewal_certificate_response() -> TzapAuthHttpResponse {
        TzapAuthHttpResponse {
            status_code: 200,
            body: json!({"certificate": {
                "certificate_id": "cert_new",
                "leaf_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x03]),
                "intermediate_chain_der": [URL_SAFE_NO_PAD.encode([0x30, 0x04])],
                "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
                "issuer_key_identifier": "AQIDBA",
                "serial_number": "02ABCDEF",
                "certificate_sha256": trust::format_certificate_sha256(&[0x05; 32]),
                "not_before_unix_seconds": 150,
                "not_after_unix_seconds": 250,
                "sign_device_id": "sign-device-new",
                "login_organization_device_id": Value::Null
            }})
            .to_string()
            .into_bytes(),
        }
    }

    fn public_metadata() -> TzapCertificatePublicMetadata {
        TzapCertificatePublicMetadata {
            version: 1,
            public_signer_id: "psign_0123456789ABCDEFGH".to_owned(),
            public_org_id: None,
            public_device_id: "pdev_0123456789ABCDEFGH".to_owned(),
            assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
            policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
        }
    }

    struct AcceptingLifecycleValidator;

    impl TzapEnrollmentCertificateValidator for AcceptingLifecycleValidator {
        fn validate_certificate_chain(
            &self,
            _chain_der: &[Vec<u8>],
        ) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            Ok(public_metadata())
        }
    }

    struct FakeLifecycleTransport {
        responses: RefCell<Vec<TzapAuthHttpResponse>>,
        requests: RefCell<Vec<TzapAuthHttpRequest>>,
    }

    impl FakeLifecycleTransport {
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

    impl TzapAuthHttpTransport for FakeLifecycleTransport {
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
