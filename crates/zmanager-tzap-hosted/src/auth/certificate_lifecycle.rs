//! Certificate renewal, revocation, and local device-retirement flows.

use crate::auth_client::{
    SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken,
    TzapSessionRecord,
};
use crate::device_identity::{TzapDeviceCsrOptions, csr_fingerprint, generate_device_csr_from_private_key, generate_device_signing_key_and_csr};
use crate::enrollment_client::{
    ENROLLMENT_CHALLENGE_CANONICALIZATION, ENROLLMENT_CHALLENGES_PATH, TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentError,
    TzapEnrollmentRequest, canonicalize_local_staging_server_json_bytes, csr_der_to_pem, enroll_device_certificate, parse_challenge_response,
    parse_enrollment_response, requested_validity_days, sign_p256_challenge,
};
use crate::http_client::{require_success, send_json_request};
use crate::jcs;
use crate::json_util::{json_object, optional_string};
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityStore, TzapLocalIdentityStoreError,
    TzapOrganizationDeviceRetirement,
};
use crate::trust;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use std::fmt;

pub const RENEW_OPERATION: &str = "renew";
pub const RENEWAL_GRACE_MAX_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const CERTIFICATE_REVOKE_PATH_SUFFIX: &str = "/revoke";
pub const CERTIFICATE_RENEW_PATH_SUFFIX: &str = "/renew";
pub const SIGN_DEVICE_REVOKE_PATH_PREFIX: &str = "/v1/devices/";
pub const LOGIN_ORG_DEVICES_PATH_PREFIX: &str = "/v1/orgs/";
pub const DEFAULT_RENEWAL_DEVICE_NAME: &str = "ZManager CLI";

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
    /// Devices whose server-side revocation completed during this attempt.
    /// This is intentionally separate from `completion`: a mixed personal /
    /// organization retirement can complete one audience while waiting for a
    /// second audience or approval.
    pub completed_sign_device_ids: Vec<String>,
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
    RevocationSyncFailed,
    /// Revoking a personal certificate or device needs a fresh MFA step-up
    /// (403 `admin_mfa_required`). The sign server began requiring this for the personal
    /// revoke paths so that a stolen session cookie alone cannot destroy a user's
    /// certificates; the organization revoke path has always required it. Callers should
    /// drive a step-up and retry rather than reporting a generic failure.
    AdminMfaRequired,
    ActiveCertificateExists,
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
            Self::RevocationSyncFailed => write!(f, "device revocation synchronization failed"),
            Self::AdminMfaRequired => write!(f, "MFA step-up is required to revoke"),
            Self::ActiveCertificateExists => write!(f, "an active certificate already exists for this device"),
            Self::HttpStatus { status_code } => {
                write!(f, "certificate lifecycle HTTP request failed with status {status_code}")
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
        match &error {
            TzapEnrollmentError::HttpStatus { body: Some(body), .. }
                if body_error_code_from_bytes(body.as_bytes()).as_deref() == Some("active_certificate_exists") =>
            {
                Self::ActiveCertificateExists
            }
            _ => Self::Enrollment(error),
        }
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
    wire_profile: crate::wire_profile::TzapWireProfile,
    device_name: String,
}

impl<'a, T: TzapAuthHttpTransport> TzapCertificateLifecycleClient<'a, T> {
    #[must_use]
    pub fn new(sign_base_url: impl Into<String>, login_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::with_device_name(sign_base_url, login_base_url, transport, DEFAULT_RENEWAL_DEVICE_NAME)
    }

    #[must_use]
    pub fn with_device_name(sign_base_url: impl Into<String>, login_base_url: impl Into<String>, transport: &'a T, device_name: impl Into<String>) -> Self {
        Self::with_wire_profile(sign_base_url, login_base_url, transport, crate::wire_profile::TzapWireProfile::Spec, device_name)
    }

    #[must_use]
    pub fn local_staging_server(sign_base_url: impl Into<String>, login_base_url: impl Into<String>, transport: &'a T) -> Self {
        Self::local_staging_server_with_device_name(sign_base_url, login_base_url, transport, DEFAULT_RENEWAL_DEVICE_NAME)
    }

    #[must_use]
    pub fn local_staging_server_with_device_name(
        sign_base_url: impl Into<String>,
        login_base_url: impl Into<String>,
        transport: &'a T,
        device_name: impl Into<String>,
    ) -> Self {
        Self::with_wire_profile(sign_base_url, login_base_url, transport, crate::wire_profile::TzapWireProfile::LocalStagingServer, device_name)
    }

    #[must_use]
    pub(crate) fn with_wire_profile(
        sign_base_url: impl Into<String>,
        login_base_url: impl Into<String>,
        transport: &'a T,
        wire_profile: crate::wire_profile::TzapWireProfile,
        device_name: impl Into<String>,
    ) -> Self {
        Self { sign_base_url: sign_base_url.into(), login_base_url: login_base_url.into(), transport, wire_profile, device_name: device_name.into() }
    }

    #[allow(clippy::too_many_arguments)]
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
        Self::precheck_renewal(store, request)?;
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let challenge = self.request_renewal_challenge(session, request, new_signing_key, csr_der)?;
        validate_renewal_challenge(self.wire_profile, challenge.canonicalization.as_deref(), request, &challenge.payload)?;
        let old_signature = match request.renewal_policy {
            TzapRenewalPolicy::SameKeyRequired => Some(sign_old_certificate_challenge(self.wire_profile, previous_signing_key, &challenge.payload)?),
            TzapRenewalPolicy::KeyRotationAllowed => None,
        };
        let response = self.submit_renewal(session, request, new_signing_key, csr_der, &challenge, old_signature.as_deref())?;
        parse_renewal_barriers(&response.body)?;
        let payload = parse_enrollment_response(&response.body)?;
        let chain = payload.certificate_chain_der();
        let public_metadata = validator.validate_certificate_chain(&chain).map_err(TzapCertificateLifecycleError::Enrollment)?;
        let enrollment_request = TzapEnrollmentRequest {
            account_key: request.account_key.clone(),
            org_id: request.org_id.clone(),
            requested_validity_seconds: request.requested_validity_seconds,
            now_unix_seconds: request.now_unix_seconds,
        };
        let new_record =
            payload.into_store_record(&enrollment_request, &new_signing_key.key_id, public_metadata).map_err(TzapCertificateLifecycleError::Enrollment)?;
        let mut inventory = store.load_inventory(&request.account_key)?;
        let predecessor = inventory
            .enrolled_certificates
            .iter_mut()
            .find(|certificate| certificate.certificate_id == request.previous_certificate_id)
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        // The server revokes the predecessor transactionally with issuance of
        // the replacement. Keep the local inventory in the same state so a
        // later automatic renewal cannot select the already-revoked record.
        predecessor.state = TzapLocalCertificateState::Revoked;
        inventory.enrolled_certificates.push(new_record.clone());
        store.save_inventory(&request.account_key, inventory)?;
        Ok(new_record)
    }

    /// Runs renewal recovery after an uncertain response. A transport or
    /// server failure may occur after the service has committed the
    /// replacement, so retrying the renewal blindly could mint a second
    /// certificate. The list/detail sequence proves device, scope, and
    /// predecessor lineage before mutating the local inventory.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_certificate_with_reconciliation(
        &self,
        validator: &impl TzapEnrollmentCertificateValidator,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        new_signing_key: &TzapDeviceSigningKeyRecord,
        previous_signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
        match self.renew_certificate(validator, store, session, request, new_signing_key, previous_signing_key, csr_der) {
            Ok(record) => Ok(record),
            Err(error) if is_reconcilable_renewal_failure(&error) => match self.reconcile_uncertain_renewal(validator, store, session, request)? {
                Some(record) => Ok(record),
                None => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    fn reconcile_uncertain_renewal(
        &self,
        validator: &impl TzapEnrollmentCertificateValidator,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
    ) -> Result<Option<TzapEnrolledCertificateRecord>, TzapCertificateLifecycleError> {
        let enrollment_client = TzapEnrollmentClient::with_wire_profile(&self.sign_base_url, self.transport, self.wire_profile, self.device_name.clone());
        let inventory = store.load_inventory(&request.account_key)?;
        let predecessor = inventory
            .enrolled_certificates
            .iter()
            .find(|certificate| {
                certificate.certificate_id == request.previous_certificate_id
                    && certificate.certificate_sha256 == request.previous_certificate_sha256
                    && certificate.state == TzapLocalCertificateState::Active
            })
            .cloned()
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;

        for listed in enrollment_client.list_certificates(session)? {
            if listed.certificate_id == request.previous_certificate_id || !matches_predecessor(&listed, request) {
                continue;
            }
            let listed_chain = listed.certificate_chain_der();
            let (_, listed_metadata) = validator.validate_and_complete_certificate_chain(&listed_chain).map_err(TzapCertificateLifecycleError::Enrollment)?;
            if !matches_replacement_scope(&listed_metadata, &predecessor, request) {
                continue;
            }

            // The list entry is only a candidate. Fetch the full detail before
            // installing it so a partial/stale list response cannot alter the
            // local catalog.
            let mut detail = enrollment_client.get_certificate(session, &listed.certificate_id)?;
            if detail.certificate_id != listed.certificate_id || !matches_predecessor(&detail, request) {
                continue;
            }
            let detail_chain = detail.certificate_chain_der();
            let (detail_chain, detail_metadata) =
                validator.validate_and_complete_certificate_chain(&detail_chain).map_err(TzapCertificateLifecycleError::Enrollment)?;
            if detail_metadata != listed_metadata || !matches_replacement_scope(&detail_metadata, &predecessor, request) {
                continue;
            }
            detail.replace_certificate_chain_der(&detail_chain).map_err(TzapCertificateLifecycleError::Enrollment)?;
            let enrollment_request = TzapEnrollmentRequest {
                account_key: request.account_key.clone(),
                org_id: request.org_id.clone(),
                requested_validity_seconds: request.requested_validity_seconds,
                now_unix_seconds: request.now_unix_seconds,
            };
            let replacement = detail
                .into_store_record(&enrollment_request, &predecessor.signing_key_id, detail_metadata)
                .map_err(TzapCertificateLifecycleError::Enrollment)?;
            install_reconciled_replacement(store, request, replacement.clone())?;
            return Ok(Some(replacement));
        }
        Ok(None)
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
        let response = self.send_revocation(TzapAuthHttpMethod::Post, &self.sign_base_url, &path, Some(session.access_token.clone()), None)?;
        let completion = revocation_completion(&response)?;
        if matches!(completion, TzapRetirementCompletion::Complete) {
            mark_certificate_revoked(store, account_key, certificate_id)?;
        }
        Ok(completion)
    }

    pub fn revoke_personal_device(&self, session: &TzapSessionRecord, sign_device_id: &str) -> Result<TzapRetirementCompletion, TzapCertificateLifecycleError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let path = format!("{SIGN_DEVICE_REVOKE_PATH_PREFIX}{sign_device_id}/revoke");
        let response = self.send(TzapAuthHttpMethod::Post, &self.sign_base_url, &path, Some(session.access_token.clone()), None)?;
        revocation_completion(&response)
    }

    pub fn retire_personal_devices(
        &self,
        store: &impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        account_key: &str,
    ) -> Result<TzapRetirementReport, TzapCertificateLifecycleError> {
        session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
        let inventory = store.load_inventory(account_key)?;
        let sign_device_ids = inventory.active_personal_sign_device_ids().into_iter().map(ToOwned::to_owned).collect::<Vec<_>>();
        let mut completed_sign_device_ids = Vec::new();
        let mut incomplete_reasons = Vec::new();
        for sign_device_id in &sign_device_ids {
            let path = format!("{SIGN_DEVICE_REVOKE_PATH_PREFIX}{sign_device_id}/revoke");
            let response = self.send_revocation(TzapAuthHttpMethod::Post, &self.sign_base_url, &path, Some(session.access_token.clone()), None)?;
            if matches!(revocation_completion(&response)?, TzapRetirementCompletion::Complete) {
                completed_sign_device_ids.push(sign_device_id.clone());
            } else {
                incomplete_reasons.push(sign_device_id.clone());
            }
        }
        Ok(TzapRetirementReport {
            completion: if incomplete_reasons.is_empty() { TzapRetirementCompletion::Complete } else { TzapRetirementCompletion::Incomplete },
            attempted_sign_device_ids: sign_device_ids,
            completed_sign_device_ids,
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
        let mut completed_sign_device_ids = Vec::new();
        let mut incomplete_reasons = Vec::new();
        for route in &routes {
            let lookup = self.lookup_organization_device(session, route)?;
            match lookup {
                OrganizationDeviceLookup::Found(login_device_id) => {
                    let path = format!("{LOGIN_ORG_DEVICES_PATH_PREFIX}{}/devices/{login_device_id}/revoke", route.org_id);
                    let response = self.send_revocation(TzapAuthHttpMethod::Post, &self.login_base_url, &path, Some(session.access_token.clone()), None)?;
                    if matches!(revocation_completion(&response)?, TzapRetirementCompletion::Complete) {
                        completed_sign_device_ids.push(route.sign_device_id.clone());
                    } else {
                        incomplete_reasons.push(route.sign_device_id.clone());
                    }
                }
                OrganizationDeviceLookup::Incomplete(reason) => incomplete_reasons.push(reason),
            }
        }
        Ok(TzapRetirementReport {
            completion: if incomplete_reasons.is_empty() { TzapRetirementCompletion::Complete } else { TzapRetirementCompletion::Incomplete },
            attempted_sign_device_ids: routes.into_iter().map(|route| route.sign_device_id).collect(),
            completed_sign_device_ids,
            incomplete_reasons,
        })
    }

    fn request_renewal_challenge(
        &self,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
    ) -> Result<crate::enrollment_client::TzapEnrollmentChallenge, TzapCertificateLifecycleError> {
        let body = match self.wire_profile {
            crate::wire_profile::TzapWireProfile::Spec => json!({
                "operation": RENEW_OPERATION,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_seconds": request.requested_validity_seconds,
                "renewal_of_certificate_sha256": request.previous_certificate_sha256,
            }),
            crate::wire_profile::TzapWireProfile::LocalStagingServer => json!({
                "operation": RENEW_OPERATION,
                "csr_sha256": csr_fingerprint(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "org_id": request.org_id,
                "requested_validity_days": requested_validity_days(request.requested_validity_seconds)
                    .map_err(TzapCertificateLifecycleError::Enrollment)?,
                "renewal_of_certificate_sha256": request.previous_certificate_sha256,
            }),
        };
        let response = self.send(TzapAuthHttpMethod::Post, &self.sign_base_url, ENROLLMENT_CHALLENGES_PATH, Some(session.access_token.clone()), Some(body))?;
        parse_challenge_response::<TzapCertificateLifecycleError>(&response.body)
    }

    fn submit_renewal(
        &self,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        csr_der: &[u8],
        challenge: &crate::enrollment_client::TzapEnrollmentChallenge,
        old_certificate_signature: Option<&str>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        let path = format!("/v1/certificates/{}{}", request.previous_certificate_id, CERTIFICATE_RENEW_PATH_SUFFIX);
        let body = match self.wire_profile {
            crate::wire_profile::TzapWireProfile::Spec => json!({
                "operation": RENEW_OPERATION,
                "challenge_id": challenge.challenge_id,
                "csr_der": URL_SAFE_NO_PAD.encode(csr_der),
                "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                "renewal_of_certificate_sha256": request.previous_certificate_sha256,
                "old_certificate_signature": old_certificate_signature,
            }),
            crate::wire_profile::TzapWireProfile::LocalStagingServer => {
                let challenge_signature = sign_new_key_challenge_staging(signing_key, &challenge.payload)?;
                let org_id = optional_string_from_payload(&challenge.payload, "org_id")?;
                json!({
                    "operation": RENEW_OPERATION,
                    "challenge_id": challenge.challenge_id,
                    "renewal_of_certificate_sha256": request.previous_certificate_sha256,
                    "challenge_signature": challenge_signature,
                    "old_certificate_signature": old_certificate_signature,
                    "csr_pem": csr_der_to_pem(csr_der),
                    "device_name": self.device_name,
                    "device_public_key_fingerprint": signing_key.public_key_fingerprint,
                    "org_id": org_id,
                    "requested_validity_days": requested_validity_days(request.requested_validity_seconds)
                        .map_err(TzapCertificateLifecycleError::Enrollment)?,
                })
            }
        };
        self.send(TzapAuthHttpMethod::Post, &self.sign_base_url, &path, Some(session.access_token.clone()), Some(body))
    }

    fn precheck_renewal(
        store: &impl TzapLocalIdentityStore,
        request: &TzapRenewalRequest,
    ) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
        let inventory = store.load_inventory(&request.account_key)?;
        let certificate = inventory
            .enrolled_certificates
            .iter()
            .find(|record| record.certificate_id == request.previous_certificate_id && record.certificate_sha256 == request.previous_certificate_sha256)
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        let root_sha256 = certificate.intermediate_chain_der.last().map(|der| crate::trust::sha256_identifier(der));
        if inventory.emergency_blocklist.blocked_issuer_sha256.iter().any(|issuer| issuer == &certificate.issuer_certificate_sha256)
            || root_sha256.is_some_and(|root| inventory.emergency_blocklist.blocked_root_sha256.iter().any(|blocked| blocked == &root))
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
        // Both values are caller-controlled identifiers and must be encoded
        // before interpolation; a raw value could smuggle query parameters or
        // path segments into the request URL.
        let path = format!(
            "{LOGIN_ORG_DEVICES_PATH_PREFIX}{}/devices?sign_device_id={}",
            trust::percent_encode_path_param(&route.org_id),
            trust::percent_encode_path_param(&route.sign_device_id)
        );
        let response = self.send_raw(TzapAuthHttpMethod::Get, &self.login_base_url, &path, Some(session.access_token.clone()), None)?;
        if response.status_code == 404 {
            return Ok(OrganizationDeviceLookup::Incomplete(format!("{}:not_found", route.sign_device_id)));
        }
        if response.status_code == 409 && body_error_code(&response.body)? == "device_linkage_pending" {
            return Ok(OrganizationDeviceLookup::Incomplete(format!("{}:device_linkage_pending", route.sign_device_id)));
        }
        if !(200..=299).contains(&response.status_code) {
            return Err(TzapCertificateLifecycleError::HttpStatus { status_code: response.status_code });
        }
        let value: Value = serde_json::from_slice(&response.body)?;
        let object = json_object::<TzapCertificateLifecycleError>(&value, "$")?;
        let login_device_id =
            optional_string::<TzapCertificateLifecycleError>(object, "organization_device_id")?.unwrap_or_else(|| route.login_organization_device_id.clone());
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
        require_success(response, |status_code, response| {
            if body_error_code_from_bytes(&response.body).as_deref() == Some("active_certificate_exists") {
                TzapCertificateLifecycleError::ActiveCertificateExists
            } else {
                TzapCertificateLifecycleError::HttpStatus { status_code }
            }
        })
    }

    fn send_revocation(
        &self,
        method: TzapAuthHttpMethod,
        base_url: &str,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        let response = self.send_raw(method, base_url, path, bearer_token, body)?;
        if response.status_code == 409 && body_error_code_from_bytes(&response.body).as_deref() == Some("device_linkage_pending") {
            return Ok(response);
        }
        require_success(response, |status_code, response| {
            if body_error_code_from_bytes(&response.body).as_deref() == Some("revocation_sync_failed")
                || body_status_from_bytes(&response.body).as_deref() == Some("revocation_sync_failed")
            {
                TzapCertificateLifecycleError::RevocationSyncFailed
            } else if status_code == 403 && body_error_code_from_bytes(&response.body).as_deref() == Some("admin_mfa_required") {
                TzapCertificateLifecycleError::AdminMfaRequired
            } else {
                TzapCertificateLifecycleError::HttpStatus { status_code }
            }
        })
    }

    fn send_raw(
        &self,
        method: TzapAuthHttpMethod,
        base_url: &str,
        path: &str,
        bearer_token: Option<TzapBearerToken>,
        body: Option<Value>,
    ) -> Result<TzapAuthHttpResponse, TzapCertificateLifecycleError> {
        Ok(send_json_request(self.transport, method, base_url, path, bearer_token, body)?)
    }
}

/// Enrolls a device certificate the way a client should: reusing the
/// existing device signing key for `label` if one exists, and renewing
/// (same key, proof of continuity via the old certificate's signature)
/// instead of enrolling fresh whenever that key already holds an active
/// certificate.
///
/// Fixes the *Identity proliferation* defect (mobile TZAP secret-store
/// cutover plan): the naive enroll path mints a new key on every call
/// unless it happens to find an orphaned key from a previously-failed
/// enrollment, so two enrollments of the same device produce two keys, two
/// device rows, and two certificates even with local state fully
/// preserved. `public_device_id` asserts "this device" — device identity
/// must stay stable across a certificate refresh, which is what renewal
/// exists for.
#[allow(clippy::too_many_arguments)]
pub fn enroll_or_renew_device_certificate<T: TzapAuthHttpTransport>(
    enrollment_client: &TzapEnrollmentClient<'_, T>,
    lifecycle_client: &TzapCertificateLifecycleClient<'_, T>,
    validator: &impl TzapEnrollmentCertificateValidator,
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    label: &str,
) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
    let mut inventory = store.load_inventory(&request.account_key)?;
    let existing_key = inventory.device_signing_keys.iter().find(|record| record.label.as_deref() == Some(label)).cloned();

    let signing_key = if let Some(record) = existing_key {
        record
    } else {
        let material =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).map_err(|error| TzapCertificateLifecycleError::Crypto(error.to_string()))?;
        let record = TzapDeviceSigningKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            public_key_fingerprint: material.public_key_fingerprint,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: request.now_unix_seconds,
            label: Some(label.to_owned()),
        };
        inventory.device_signing_keys.push(record.clone());
        store.save_inventory(&request.account_key, inventory)?;
        record
    };

    let csr_der = generate_device_csr_from_private_key(&signing_key.private_key_der, &TzapDeviceCsrOptions::default())
        .map_err(|error| TzapCertificateLifecycleError::Crypto(error.to_string()))?;

    let active_certificate = store.load_inventory(&request.account_key)?.enrolled_certificates.into_iter().find(|certificate| {
        certificate.signing_key_id == signing_key.key_id
            && certificate.state == TzapLocalCertificateState::Active
            && match (&request.org_id, &certificate.sign_device_routing) {
                (None, crate::local_identity_store::TzapSignDeviceRouting::Personal) => true,
                (Some(requested_org_id), crate::local_identity_store::TzapSignDeviceRouting::Organization { org_id, .. }) => requested_org_id == org_id,
                _ => false,
            }
    });

    match active_certificate {
        Some(certificate) => {
            let renewal_request = TzapRenewalRequest {
                account_key: request.account_key.clone(),
                previous_certificate_id: certificate.certificate_id.clone(),
                previous_certificate_sha256: certificate.certificate_sha256.clone(),
                org_id: request.org_id.clone(),
                requested_validity_seconds: request.requested_validity_seconds,
                renewal_policy: TzapRenewalPolicy::SameKeyRequired,
                now_unix_seconds: request.now_unix_seconds,
                server_grace_seconds: RENEWAL_GRACE_MAX_SECONDS,
            };
            lifecycle_client.renew_certificate_with_reconciliation(validator, store, session, &renewal_request, &signing_key, &signing_key, &csr_der)
        }
        None => enroll_device_certificate(enrollment_client, validator, store, session, request, &signing_key, &csr_der)
            .map_err(TzapCertificateLifecycleError::from),
    }
}

fn optional_string_from_payload(payload: &Value, field: &'static str) -> Result<Option<String>, TzapCertificateLifecycleError> {
    let object = json_object::<TzapCertificateLifecycleError>(payload, "challenge_payload")?;
    optional_string::<TzapCertificateLifecycleError>(object, field)
}

enum OrganizationDeviceLookup {
    Found(String),
    Incomplete(String),
}

fn validate_renewal_challenge(
    wire_profile: crate::wire_profile::TzapWireProfile,
    canonicalization: Option<&str>,
    request: &TzapRenewalRequest,
    payload: &Value,
) -> Result<(), TzapCertificateLifecycleError> {
    let object = json_object::<TzapCertificateLifecycleError>(payload, "challenge_payload")?;
    match wire_profile {
        crate::wire_profile::TzapWireProfile::Spec => {
            expect_string(object, "canonicalization", ENROLLMENT_CHALLENGE_CANONICALIZATION)?;
        }
        crate::wire_profile::TzapWireProfile::LocalStagingServer => {
            if canonicalization != Some(ENROLLMENT_CHALLENGE_CANONICALIZATION) {
                return Err(TzapCertificateLifecycleError::RenewalTargetMismatch);
            }
        }
    }
    expect_string(object, "operation", RENEW_OPERATION)?;
    expect_string(object, "renewal_of_certificate_sha256", &request.previous_certificate_sha256)?;
    expect_string(object, "certificate_id", &request.previous_certificate_id)?;
    expect_optional_string(object, "org_id", request.org_id.as_deref())?;
    Ok(())
}

fn sign_old_certificate_challenge(
    wire_profile: crate::wire_profile::TzapWireProfile,
    previous_signing_key: &TzapDeviceSigningKeyRecord,
    challenge_payload: &Value,
) -> Result<String, TzapCertificateLifecycleError> {
    let canonical = match wire_profile {
        crate::wire_profile::TzapWireProfile::Spec => {
            jcs::canonicalize_json_bytes(challenge_payload).map_err(|error| TzapCertificateLifecycleError::Crypto(format!("{error:?}")))?
        }
        crate::wire_profile::TzapWireProfile::LocalStagingServer => {
            canonicalize_local_staging_server_json_bytes(challenge_payload).map_err(|error| TzapCertificateLifecycleError::Crypto(format!("{error:?}")))?
        }
    };
    let signature = sign_p256_challenge::<TzapCertificateLifecycleError>(&previous_signing_key.private_key_der, &canonical)?;
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn sign_new_key_challenge_staging(signing_key: &TzapDeviceSigningKeyRecord, challenge_payload: &Value) -> Result<String, TzapCertificateLifecycleError> {
    let canonical =
        canonicalize_local_staging_server_json_bytes(challenge_payload).map_err(|error| TzapCertificateLifecycleError::Crypto(format!("{error:?}")))?;
    let signature = sign_p256_challenge::<TzapCertificateLifecycleError>(&signing_key.private_key_der, &canonical)?;
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn parse_renewal_barriers(bytes: &[u8]) -> Result<(), TzapCertificateLifecycleError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let object = json_object::<TzapCertificateLifecycleError>(&value, "$")?;
    match optional_string::<TzapCertificateLifecycleError>(object, "status")?.as_deref() {
        Some("device_approval_required") => Err(TzapCertificateLifecycleError::RenewalPendingApproval),
        Some("device_linkage_pending") => Err(TzapCertificateLifecycleError::DeviceLinkagePending),
        Some("device_linkage_conflict") => Err(TzapCertificateLifecycleError::DeviceLinkageConflict),
        _ => Ok(()),
    }
}

fn is_reconcilable_renewal_failure(error: &TzapCertificateLifecycleError) -> bool {
    match error {
        TzapCertificateLifecycleError::Auth(TzapAuthError::Transport { .. }) => true,
        TzapCertificateLifecycleError::Auth(TzapAuthError::HttpStatus { status_code })
        | TzapCertificateLifecycleError::HttpStatus { status_code }
        | TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::HttpStatus { status_code, .. }) => *status_code != 401,
        _ => false,
    }
}

fn matches_predecessor(payload: &crate::enrollment_client::TzapEnrollmentCertificatePayload, request: &TzapRenewalRequest) -> bool {
    payload.predecessor_certificate_id.as_deref() == Some(request.previous_certificate_id.as_str())
        || payload.predecessor_certificate_sha256.as_deref() == Some(request.previous_certificate_sha256.as_str())
}

fn matches_replacement_scope(
    metadata: &crate::trust::TzapCertificatePublicMetadata,
    predecessor: &TzapEnrolledCertificateRecord,
    request: &TzapRenewalRequest,
) -> bool {
    metadata.public_device_id == predecessor.public_metadata.public_device_id
        && metadata.public_signer_id == predecessor.public_metadata.public_signer_id
        && metadata.public_org_id.as_deref() == request.org_id.as_deref()
}

fn install_reconciled_replacement(
    store: &mut impl TzapLocalIdentityStore,
    request: &TzapRenewalRequest,
    replacement: TzapEnrolledCertificateRecord,
) -> Result<(), TzapCertificateLifecycleError> {
    let mut inventory = store.load_inventory(&request.account_key)?;
    if inventory
        .enrolled_certificates
        .iter()
        .any(|certificate| certificate.certificate_id == replacement.certificate_id && certificate.state == TzapLocalCertificateState::Active)
    {
        return Ok(());
    }
    let predecessor = inventory
        .enrolled_certificates
        .iter_mut()
        .find(|certificate| {
            certificate.certificate_id == request.previous_certificate_id && certificate.certificate_sha256 == request.previous_certificate_sha256
        })
        .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
    predecessor.state = TzapLocalCertificateState::Revoked;
    inventory.enrolled_certificates.push(replacement);
    store.save_inventory(&request.account_key, inventory)?;
    Ok(())
}

fn body_error_code_from_bytes(bytes: &[u8]) -> Option<String> {
    body_field_from_bytes(bytes, "error")
}

fn body_status_from_bytes(bytes: &[u8]) -> Option<String> {
    body_field_from_bytes(bytes, "status")
}

fn body_field_from_bytes(bytes: &[u8], field: &str) -> Option<String> {
    serde_json::from_slice::<Value>(bytes).ok()?.get(field)?.as_str().map(str::to_owned)
}

fn revocation_completion(response: &TzapAuthHttpResponse) -> Result<TzapRetirementCompletion, TzapCertificateLifecycleError> {
    if response.status_code == 202 {
        return Ok(TzapRetirementCompletion::Incomplete);
    }
    let value: Value = serde_json::from_slice(&response.body)?;
    let object = json_object::<TzapCertificateLifecycleError>(&value, "$")?;
    if response.status_code == 409 && optional_string::<TzapCertificateLifecycleError>(object, "error")?.as_deref() == Some("device_linkage_pending") {
        return Ok(TzapRetirementCompletion::Incomplete);
    }
    let result = optional_string::<TzapCertificateLifecycleError>(object, "result")?;
    let status = optional_string::<TzapCertificateLifecycleError>(object, "status")?;
    let Some(result_or_status) = result.or(status) else {
        // A 2xx without a revocation result is not evidence of completion;
        // treating it as such would mark a possibly-failed revocation as
        // done (e.g. an error JSON the server returned with 200).
        return Err(TzapCertificateLifecycleError::InvalidField { field: "result or status" });
    };
    match result_or_status.as_str() {
        "already_revoked" | "revoked" | "complete" => Ok(TzapRetirementCompletion::Complete),
        "revocation_pending_sync" => Ok(TzapRetirementCompletion::Incomplete),
        "revocation_sync_failed" => Err(TzapCertificateLifecycleError::RevocationSyncFailed),
        _ => Err(TzapCertificateLifecycleError::InvalidField { field: "result or status" }),
    }
}

fn mark_certificate_revoked(store: &mut impl TzapLocalIdentityStore, account_key: &str, certificate_id: &str) -> Result<(), TzapCertificateLifecycleError> {
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
    let object = json_object::<TzapCertificateLifecycleError>(&value, "$")?;
    Ok(optional_string::<TzapCertificateLifecycleError>(object, "error")?.unwrap_or_default())
}

// See `crate::trust::sha256_identifier` (CR-124).
fn expect_string(object: &Map<String, Value>, field: &'static str, expected: &str) -> Result<(), TzapCertificateLifecycleError> {
    match optional_string::<TzapCertificateLifecycleError>(object, field)?.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(TzapCertificateLifecycleError::RenewalTargetMismatch),
    }
}

fn expect_optional_string(object: &Map<String, Value>, field: &'static str, expected: Option<&str>) -> Result<(), TzapCertificateLifecycleError> {
    let actual = optional_string::<TzapCertificateLifecycleError>(object, field)?;
    if actual.as_deref() == expected { Ok(()) } else { Err(TzapCertificateLifecycleError::RenewalTargetMismatch) }
}

#[cfg(test)]
mod tests {
    use super::{
        OrganizationDeviceLookup, RENEW_OPERATION, TzapCertificateLifecycleClient, TzapCertificateLifecycleError, TzapRenewalPolicy, TzapRenewalRequest,
        TzapRetirementCompletion, revocation_completion,
    };
    use crate::auth_client::{
        SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport,
        TzapBearerToken, TzapSessionRecord,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::enrollment_client::{TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentError, TzapEnrollmentRequest};
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState,
        TzapEnrolledCertificateRecord, TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapOrganizationDeviceRetirement,
        TzapSignDeviceRouting,
    };
    use crate::trust::{self, TzapCertificatePublicMetadata};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use std::cell::RefCell;

    #[test]
    fn renewal_same_key_submits_old_certificate_signature_and_appends_new_certificate() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, None), renewal_certificate_response()]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let renewed = client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap();

        assert_eq!(renewed.certificate_id, "cert_new");
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 2);
        let requests = transport.requests();
        assert_eq!(requests[1].url, "https://sign.tzap.org/v1/certificates/cert_old/renew");
        assert!(requests[1].body.as_ref().unwrap().get("old_certificate_signature").unwrap().as_str().is_some());
    }

    #[test]
    fn renewal_lost_response_reconciles_by_list_and_detail_before_installing() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            TzapAuthHttpResponse { status_code: 503, body: Vec::new(), headers: Vec::new() },
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"certificates": [reconciled_certificate_json()]}).to_string().into_bytes(),
                headers: Vec::new(),
            },
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"certificate": reconciled_certificate_json()}).to_string().into_bytes(),
                headers: Vec::new(),
            },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let renewed = client
            .renew_certificate_with_reconciliation(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap();

        assert_eq!(renewed.certificate_id, "cert_reconciled");
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 2);
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::Revoked);
        assert_eq!(inventory.enrolled_certificates[1].state, TzapLocalCertificateState::Active);
        let requests = transport.requests();
        assert_eq!(requests[2].url, "https://sign.tzap.org/v1/certificates");
        assert_eq!(requests[3].url, "https://sign.tzap.org/v1/certificates/cert_reconciled");
    }

    #[test]
    fn active_certificate_exists_is_a_typed_lifecycle_error() {
        let error = TzapCertificateLifecycleError::from(TzapEnrollmentError::HttpStatus {
            status_code: 409,
            body: Some(json!({"error": "active_certificate_exists"}).to_string()),
        });
        assert!(matches!(error, TzapCertificateLifecycleError::ActiveCertificateExists));
    }

    #[test]
    fn rotated_key_renewal_omits_old_signature_and_keeps_old_certificate() {
        let fixture = LifecycleFixture::new();
        let rotated = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, None), renewal_certificate_response()]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &LifecycleFixture::renewal_request(TzapRenewalPolicy::KeyRotationAllowed),
                &rotated.signing_key,
                &fixture.signing_key,
                &rotated.csr_der,
            )
            .unwrap();

        let body = transport.requests()[1].body.clone().unwrap();
        assert!(body.get("old_certificate_signature").unwrap().is_null());
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert!(inventory.enrolled_certificates.iter().any(|record| record.certificate_id == "cert_old"));
        assert!(inventory.enrolled_certificates.iter().any(|record| record.certificate_id == "cert_new"));
    }

    #[test]
    fn renewal_rejects_pending_linkage_conflict_and_target_mismatch() {
        for (status, expected) in [("device_approval_required", "approval"), ("device_linkage_pending", "pending"), ("device_linkage_conflict", "conflict")] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(vec![
                renewal_challenge_response(&fixture, None),
                TzapAuthHttpResponse { status_code: 200, body: json!({"status": status}).to_string().into_bytes(), headers: Vec::new() },
            ]);
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
            let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
            let error = client
                .renew_certificate(
                    &AcceptingLifecycleValidator,
                    &mut store,
                    &fixture.sign_session,
                    &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap_err();
            match expected {
                "approval" => assert!(matches!(error, TzapCertificateLifecycleError::RenewalPendingApproval)),
                "pending" => assert!(matches!(error, TzapCertificateLifecycleError::DeviceLinkagePending)),
                "conflict" => assert!(matches!(error, TzapCertificateLifecycleError::DeviceLinkageConflict)),
                _ => unreachable!(),
            }
        }

        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, Some(trust::format_certificate_sha256(&[0x99; 32])))]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let error = client
            .renew_certificate(
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap_err();
        assert!(matches!(error, TzapCertificateLifecycleError::RenewalTargetMismatch));
    }

    #[test]
    fn renewal_precheck_rejects_blocked_issuer_and_root() {
        for block in ["issuer", "root"] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(Vec::new());
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
            let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
            let mut inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
            let cert = inventory.enrolled_certificates.first().unwrap();
            match block {
                "issuer" => {
                    inventory.emergency_blocklist.blocked_issuer_sha256.push(cert.issuer_certificate_sha256.clone());
                }
                "root" => {
                    let root_der = cert.intermediate_chain_der.last().unwrap();
                    inventory.emergency_blocklist.blocked_root_sha256.push(crate::trust::sha256_identifier(root_der));
                }
                _ => unreachable!(),
            }
            store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

            let error = client
                .renew_certificate(
                    &AcceptingLifecycleValidator,
                    &mut store,
                    &fixture.sign_session,
                    &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der,
                )
                .unwrap_err();

            assert!(matches!(error, TzapCertificateLifecycleError::CertificateNotRenewable));
            assert!(transport.requests().is_empty());
        }
    }

    #[test]
    fn personal_revocation_and_retirement_keep_pending_sync_incomplete() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse { status_code: 200, body: json!({"result": "already_revoked"}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 202, body: json!({"result": "revocation_pending_sync"}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let cert_completion = client.revoke_personal_certificate(&mut store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert_old").unwrap();
        assert_eq!(cert_completion, TzapRetirementCompletion::Complete);
        let store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let device_report = client.retire_personal_devices(&store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(device_report.completion, TzapRetirementCompletion::Incomplete);
        assert_eq!(device_report.attempted_sign_device_ids, vec!["sign-device-old"]);
        assert!(device_report.completed_sign_device_ids.is_empty());
    }

    #[test]
    fn personal_retirement_reports_each_server_confirmed_device_for_partial_runs() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse { status_code: 200, body: json!({"result": "already_revoked"}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 202, body: json!({"result": "revocation_pending_sync"}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let mut inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        let mut second = inventory.enrolled_certificates[0].clone();
        second.certificate_id = "cert_second".to_owned();
        second.certificate_sha256 = trust::format_certificate_sha256(&[0x06; 32]);
        second.sign_device_id = "sign-device-second".to_owned();
        inventory.enrolled_certificates.push(second);
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let report = client.retire_personal_devices(&store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();

        assert_eq!(report.completion, TzapRetirementCompletion::Incomplete);
        assert_eq!(report.attempted_sign_device_ids, vec!["sign-device-old", "sign-device-second"]);
        assert_eq!(report.completed_sign_device_ids, vec!["sign-device-old"]);
        assert_eq!(report.incomplete_reasons, vec!["sign-device-second"]);
    }

    #[test]
    fn personal_retirement_accepts_server_status_and_keeps_linkage_pending_incomplete() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"sign_device_id": "sign-device-old", "status": "revoked", "revoked_at": "2026-09-09T00:00:00Z" }).to_string().into_bytes(),
                headers: Vec::new(),
            },
            TzapAuthHttpResponse {
                status_code: 409,
                body: json!({"error": "device_linkage_pending", "denial_reason": "missing_login_user_device_id", "retryable": true }).to_string().into_bytes(),
                headers: Vec::new(),
            },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let mut inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        let mut second = inventory.enrolled_certificates[0].clone();
        second.certificate_id = "cert_second".to_owned();
        second.certificate_sha256 = trust::format_certificate_sha256(&[0x06; 32]);
        second.sign_device_id = "sign-device-second".to_owned();
        inventory.enrolled_certificates.push(second);
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let report = client.retire_personal_devices(&store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();

        assert_eq!(report.completion, TzapRetirementCompletion::Incomplete);
        assert_eq!(report.completed_sign_device_ids, vec!["sign-device-old"]);
        assert_eq!(report.incomplete_reasons, vec!["sign-device-second"]);
    }

    #[test]
    fn revocation_sync_failure_is_reported_as_a_typed_error() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![TzapAuthHttpResponse {
            status_code: 409,
            body: json!({"status": "revocation_sync_failed"}).to_string().into_bytes(),
            headers: Vec::new(),
        }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let error = client.retire_personal_devices(&store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap_err();

        assert!(matches!(error, TzapCertificateLifecycleError::RevocationSyncFailed));
    }

    #[test]
    fn personal_revocation_maps_403_admin_mfa_required_distinctly_from_other_403s() {
        // The sign server now requires a fresh MFA step-up for the personal revoke paths, the
        // same way the organization revoke path and the key-backup read always have. A caller
        // has to be able to tell "step up and retry" apart from a flat authorization failure,
        // otherwise the desktop app reports an unrecoverable error for a recoverable state.
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![TzapAuthHttpResponse {
            status_code: 403,
            body: json!({"error": "admin_mfa_required", "message": "Verify with an admin MFA factor to continue."})
                .to_string()
                .into_bytes(),
            headers: Vec::new(),
        }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let error = client
            .revoke_personal_certificate(&mut store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert_old")
            .unwrap_err();

        assert!(
            matches!(error, TzapCertificateLifecycleError::AdminMfaRequired),
            "expected AdminMfaRequired, got {error:?}"
        );
    }

    #[test]
    fn personal_revocation_keeps_a_plain_403_as_an_http_status() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![TzapAuthHttpResponse {
            status_code: 403,
            body: json!({"error": "forbidden"}).to_string().into_bytes(),
            headers: Vec::new(),
        }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let error = client
            .revoke_personal_certificate(&mut store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert_old")
            .unwrap_err();

        assert!(
            matches!(error, TzapCertificateLifecycleError::HttpStatus { status_code: 403 }),
            "expected HttpStatus 403, got {error:?}"
        );
    }

    #[test]
    fn revocation_completion_requires_a_known_result_or_status_field() {
        // A 2xx with an unrelated body (e.g. an error JSON) must not count as
        // completion.
        let error = revocation_completion(&TzapAuthHttpResponse {
            status_code: 200,
            body: json!({"error": "internal_error"}).to_string().into_bytes(),
            headers: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(error, TzapCertificateLifecycleError::InvalidField { field: "result or status" }));

        // Non-JSON bodies are rejected too.
        assert!(revocation_completion(&TzapAuthHttpResponse { status_code: 200, body: b"not json".to_vec(), headers: Vec::new() }).is_err());

        // The pending marker stays incomplete and a known completion stays
        // complete.
        let pending = revocation_completion(&TzapAuthHttpResponse {
            status_code: 202,
            body: json!({"result": "revocation_pending_sync"}).to_string().into_bytes(),
            headers: Vec::new(),
        })
        .unwrap();
        assert_eq!(pending, TzapRetirementCompletion::Incomplete);
        let complete = revocation_completion(&TzapAuthHttpResponse {
            status_code: 200,
            body: json!({"result": "already_revoked"}).to_string().into_bytes(),
            headers: Vec::new(),
        })
        .unwrap();
        assert_eq!(complete, TzapRetirementCompletion::Complete);

        let server_complete =
            revocation_completion(&TzapAuthHttpResponse { status_code: 200, body: json!({"status": "revoked"}).to_string().into_bytes(), headers: Vec::new() })
                .unwrap();
        assert_eq!(server_complete, TzapRetirementCompletion::Complete);

        let linkage_pending = revocation_completion(&TzapAuthHttpResponse {
            status_code: 409,
            body: json!({"error": "device_linkage_pending"}).to_string().into_bytes(),
            headers: Vec::new(),
        })
        .unwrap();
        assert_eq!(linkage_pending, TzapRetirementCompletion::Incomplete);
    }

    #[test]
    fn organization_retirement_uses_login_routes_and_keeps_404_and_linkage_pending_incomplete() {
        for response in [
            TzapAuthHttpResponse { status_code: 404, body: b"{}".to_vec(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 409, body: json!({"error": "device_linkage_pending"}).to_string().into_bytes(), headers: Vec::new() },
        ] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(vec![response]);
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
            let store = fixture.store_with_certificate(TzapSignDeviceRouting::Organization {
                org_id: "org_123".to_owned(),
                login_organization_device_id: "login-org-device-1".to_owned(),
            });

            let report = client.retire_organization_devices(&store, &fixture.login_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
            assert_eq!(report.completion, TzapRetirementCompletion::Incomplete);
            assert!(report.completed_sign_device_ids.is_empty());
            let urls = transport.requests().into_iter().map(|request| request.url).collect::<Vec<_>>();
            assert_eq!(urls.len(), 1);
            assert!(urls[0].starts_with("https://login.tzap.org/v1/orgs/org_123/devices?sign_device_id=sign-device-old"));
            assert!(!urls[0].contains("https://sign.tzap.org/v1/devices"));
        }
    }

    #[test]
    fn organization_retirement_percent_encodes_route_identifiers() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![TzapAuthHttpResponse { status_code: 200, body: b"{}".to_vec(), headers: Vec::new() }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let route = TzapOrganizationDeviceRetirement {
            org_id: "org/../admin".to_owned(),
            sign_device_id: "dev?admin=true&x=1".to_owned(),
            login_organization_device_id: "login-org-device".to_owned(),
        };

        let lookup = client.lookup_organization_device(&fixture.login_session, &route).unwrap();
        assert!(matches!(lookup, OrganizationDeviceLookup::Found(_)));

        let url = transport.requests()[0].url.clone();
        // The device id must not be able to smuggle query parameters into the
        // request URL.
        assert!(url.contains("sign_device_id=dev%3Fadmin%3Dtrue%26x%3D1"), "raw characters leaked into URL: {url}");
        assert!(!url.contains("?admin=true"), "query injection succeeded: {url}");
    }

    /// Regression test for *Identity proliferation*: a second call for the
    /// same device label must reuse the existing key and renew, not mint a
    /// fresh key and enroll — the pre-fix bug produced a brand-new key,
    /// device row, and certificate on every enrollment.
    #[test]
    fn enroll_or_renew_reuses_the_labeled_key_and_renews_when_it_already_has_an_active_certificate() {
        let fixture = LifecycleFixture::new();
        let mut labeled_key = fixture.signing_key.clone();
        labeled_key.label = Some("device-label".to_owned());
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(labeled_key.clone());
        inventory.enrolled_certificates.push(certificate_record(TzapSignDeviceRouting::Personal));
        inventory.emergency_blocklist = TzapEmergencyBlocklistState::default();
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, None), renewal_certificate_response()]);
        let enrollment_client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
        let lifecycle_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 24 * 60 * 60,
            now_unix_seconds: 150,
        };

        let record = super::enroll_or_renew_device_certificate(
            &enrollment_client,
            &lifecycle_client,
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &request,
            "device-label",
        )
        .unwrap();

        assert_eq!(record.certificate_id, "cert_new");
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        // No new key generated: still exactly the one key this device had.
        assert_eq!(inventory.device_signing_keys.len(), 1);
        assert_eq!(inventory.device_signing_keys[0].key_id, labeled_key.key_id);
        assert_eq!(inventory.enrolled_certificates.len(), 2);
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::Revoked);
        assert_eq!(inventory.enrolled_certificates[1].state, TzapLocalCertificateState::Active);
        let requests = transport.requests();
        assert_eq!(requests[1].url, "https://sign.tzap.org/v1/certificates/cert_old/renew");
        assert!(requests[1].body.as_ref().unwrap().get("old_certificate_signature").unwrap().as_str().is_some());
    }

    /// The other half of the same fix: with no existing key for the label,
    /// this generates one and enrolls fresh (unchanged prior behavior) —
    /// makes sure the renewal branch above didn't come at the cost of
    /// breaking first-time enrollment.
    #[test]
    fn enroll_or_renew_generates_a_new_key_and_enrolls_when_no_key_exists_for_the_label() {
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, TzapLocalIdentityInventory::empty()).unwrap();
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 24 * 60 * 60,
            now_unix_seconds: 100,
        };
        let session = session(SESSION_AUDIENCE_SIGN_TZAP);
        // The challenge response's csr_sha256/device_public_key_fingerprint
        // must match whatever key this call ends up generating, which isn't
        // known ahead of time, so the challenge is built after a first
        // (failing) attempt only to read back the generated key — instead,
        // sidestep that by using a validator/transport pairing that doesn't
        // check those fields: FakeLifecycleTransport records the request
        // and returns responses positionally regardless of body content,
        // and AcceptingLifecycleValidator accepts any chain, so only the
        // challenge response's own self-consistency (payload echo) matters.
        let transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"challenge_id": "challenge_1", "challenge_payload": Value::Null}).to_string().into_bytes(),
                headers: Vec::new(),
            },
            TzapAuthHttpResponse {
                status_code: 200,
                body: json!({"certificate": enrollment_certificate_json()}).to_string().into_bytes(),
                headers: Vec::new(),
            },
        ]);
        let enrollment_client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport);
        let lifecycle_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport);

        // A null challenge_payload fails `validate_challenge_payload`, so
        // this exercises exactly as far as confirming the *enroll* (not
        // renew) endpoint is the one called — the deeper wire contract is
        // already covered by `enrollment_client`'s own tests.
        let error = super::enroll_or_renew_device_certificate(
            &enrollment_client,
            &lifecycle_client,
            &AcceptingLifecycleValidator,
            &mut store,
            &session,
            &request,
            "device-label",
        )
        .unwrap_err();

        assert!(matches!(error, TzapCertificateLifecycleError::Enrollment(_)));
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        // A new key was generated and persisted even though enrollment
        // itself failed past the challenge step.
        assert_eq!(inventory.device_signing_keys.len(), 1);
        assert_eq!(inventory.device_signing_keys[0].label.as_deref(), Some("device-label"));
        let requests = transport.requests();
        assert_eq!(requests[0].url, "https://sign.tzap.org/v1/certificates/enrollment-challenges");
    }

    fn enrollment_certificate_json() -> Value {
        json!({
            "certificate_id": "cert_enrolled",
            "leaf_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x01]),
            "intermediate_chain_der": [URL_SAFE_NO_PAD.encode([0x30, 0x02])],
            "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
            "issuer_key_identifier": "AQIDBA",
            "serial_number": "01ABCDEF",
            "certificate_sha256": trust::format_certificate_sha256(&[0x03; 32]),
            "not_before_unix_seconds": 100,
            "not_after_unix_seconds": 200,
            "sign_device_id": "sign-device-enrolled",
            "login_organization_device_id": Value::Null
        })
    }

    struct LifecycleFixture {
        sign_session: TzapSessionRecord,
        login_session: TzapSessionRecord,
        signing_key: TzapDeviceSigningKeyRecord,
        csr_der: Vec<u8>,
    }

    impl LifecycleFixture {
        fn new() -> Self {
            let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
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

        fn renewal_request(policy: TzapRenewalPolicy) -> TzapRenewalRequest {
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

        fn store_with_certificate(&self, routing: TzapSignDeviceRouting) -> InMemoryTzapLocalIdentityStore {
            let mut store = InMemoryTzapLocalIdentityStore::new();
            let mut inventory = TzapLocalIdentityInventory::empty();
            inventory.device_signing_keys.push(self.signing_key.clone());
            inventory.enrolled_certificates.push(certificate_record(routing));
            inventory.emergency_blocklist = TzapEmergencyBlocklistState::default();
            store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
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
            renewal_grace_period_days: None,
            renewal_recommended_within_days: None,
            public_metadata: public_metadata(),
            sign_device_id: "sign-device-old".to_owned(),
            sign_device_routing: routing,
            signing_key_id: "device-key-1".to_owned(),
            state: TzapLocalCertificateState::Active,
        }
    }

    fn renewal_challenge_response(fixture: &LifecycleFixture, target_override: Option<String>) -> TzapAuthHttpResponse {
        let target = target_override.unwrap_or_else(|| trust::format_certificate_sha256(&[0x03; 32]));
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
            headers: Vec::new(),
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
            headers: Vec::new(),
        }
    }

    fn reconciled_certificate_json() -> Value {
        json!({
            "certificate_id": "cert_reconciled",
            "leaf_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x03]),
            "intermediate_chain_der": [URL_SAFE_NO_PAD.encode([0x30, 0x04])],
            "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
            "issuer_key_identifier": "AQIDBA",
            "serial_number": "02ABCDEF",
            "certificate_sha256": trust::format_certificate_sha256(&[0x05; 32]),
            "not_before_unix_seconds": 150,
            "not_after_unix_seconds": 250,
            "sign_device_id": "sign-device-new",
            "login_organization_device_id": Value::Null,
            "predecessor_certificate_id": "cert_old",
            "predecessor_certificate_sha256": trust::format_certificate_sha256(&[0x03; 32])
        })
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
        fn validate_certificate_chain(&self, _chain_der: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            Ok(public_metadata())
        }
    }

    struct FakeLifecycleTransport {
        responses: RefCell<Vec<TzapAuthHttpResponse>>,
        requests: RefCell<Vec<TzapAuthHttpRequest>>,
    }

    impl FakeLifecycleTransport {
        fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
            Self { responses: RefCell::new(responses.into_iter().rev().collect()), requests: RefCell::new(Vec::new()) }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeLifecycleTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses.borrow_mut().pop().ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }
}
