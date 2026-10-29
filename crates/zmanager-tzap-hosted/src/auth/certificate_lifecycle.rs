//! Certificate renewal, revocation, and local device-retirement flows.

use crate::auth_client::{
    SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken,
    TzapSessionRecord,
};
use crate::device_identity::{TzapDeviceCsrOptions, csr_fingerprint, generate_device_csr_from_private_key, generate_device_signing_key_and_csr};
use crate::enrollment_client::{
    ENROLLMENT_CHALLENGE_CANONICALIZATION, ENROLLMENT_CHALLENGES_PATH, TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentError,
    TzapEnrollmentRequest, canonicalize_local_staging_server_json_bytes, csr_der_to_pem, enroll_device_certificate, parse_challenge_response,
    parse_enrollment_response, requested_validity_days, require_enrollment_session, sign_p256_challenge, validate_signing_key_and_csr,
    validate_stored_signing_key,
};
use crate::http_client::{require_success, send_json_request};
use crate::jcs;
use crate::json_util::{json_object, optional_string};
use crate::local_identity_store::{
    TzapCertificateOperationKind, TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapHostedDeviceBinding, TzapLocalCertificateState,
    TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError, TzapOrganizationDeviceRetirement, TzapPendingCertificateOperation,
    TzapSignDeviceRouting,
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
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

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
    InvalidField {
        field: &'static str,
    },
    CertificateNotFound,
    CertificateNotRenewable,
    RenewalTargetMismatch,
    ReconciliationConflict,
    CertificateOperationPending,
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
    AmbiguousSigningKey,
    HostedDeviceBindingMismatch,
    HttpStatus {
        status_code: u16,
    },
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
            Self::ReconciliationConflict => write!(f, "renewal reconciliation found conflicting issued certificates"),
            Self::CertificateOperationPending => write!(f, "certificate issuance outcome is still being reconciled"),
            Self::RenewalPendingApproval => write!(f, "renewal is pending device approval"),
            Self::DeviceLinkagePending => write!(f, "device linkage is pending"),
            Self::DeviceLinkageConflict => write!(f, "device linkage conflict"),
            Self::RevocationSyncFailed => write!(f, "device revocation synchronization failed"),
            Self::AdminMfaRequired => write!(f, "MFA step-up is required to revoke"),
            Self::ActiveCertificateExists => write!(f, "an active certificate already exists for this device"),
            Self::AmbiguousSigningKey => write!(f, "more than one eligible device signing key; select an identity explicitly"),
            Self::HostedDeviceBindingMismatch => write!(f, "hosted device key ownership or server device binding does not match this session"),
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
        if matches!(&error, TzapEnrollmentError::CertificateOperationPending) {
            return Self::CertificateOperationPending;
        }
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
    clock: fn() -> u64,
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
        Self {
            sign_base_url: sign_base_url.into(),
            login_base_url: login_base_url.into(),
            transport,
            wire_profile,
            device_name: device_name.into(),
            clock: crate::clock::unix_seconds,
        }
    }

    /// Supplies the operation clock, normally only needed by deterministic tests.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    fn now(&self) -> u64 {
        (self.clock)()
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
        require_enrollment_session(session, self.now())?;
        if session.provenance.is_some() {
            session.require_signing_origin(&self.sign_base_url)?;
        }
        validate_signing_key_and_csr(new_signing_key, csr_der)?;
        let mut current_request = request.clone();
        current_request.now_unix_seconds = self.now();
        let mut inventory = Self::precheck_renewal(store, &current_request)?;
        validate_stored_signing_key(&inventory, previous_signing_key)?;
        validate_stored_signing_key(&inventory, new_signing_key)?;
        let predecessor = inventory
            .enrolled_certificates
            .iter()
            .find(|certificate| certificate.certificate_id == request.previous_certificate_id)
            .cloned()
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        if predecessor.signing_key_id != previous_signing_key.key_id
            || (request.renewal_policy == TzapRenewalPolicy::SameKeyRequired
                && previous_signing_key.public_key_fingerprint != new_signing_key.public_key_fingerprint)
        {
            return Err(TzapCertificateLifecycleError::RenewalTargetMismatch);
        }
        let challenge = self.request_renewal_challenge(session, &current_request, new_signing_key, csr_der)?;
        validate_renewal_challenge(self.wire_profile, session, &current_request, new_signing_key, csr_der, &challenge, self.now())?;
        let old_signature = match request.renewal_policy {
            TzapRenewalPolicy::SameKeyRequired => Some(sign_old_certificate_challenge(self.wire_profile, previous_signing_key, &challenge.payload)?),
            TzapRenewalPolicy::KeyRotationAllowed => None,
        };
        let pending_operation = TzapPendingCertificateOperation {
            operation_id: crate::identity_catalog::TzapSecretRef::generate().as_str().to_owned(),
            kind: TzapCertificateOperationKind::Renewal,
            signing_key_id: new_signing_key.key_id.clone(),
            public_key_fingerprint: new_signing_key.public_key_fingerprint.clone(),
            csr_sha256: csr_fingerprint(csr_der),
            csr_der: Some(csr_der.to_vec()),
            org_id: request.org_id.clone(),
            requested_validity_seconds: request.requested_validity_seconds,
            created_at_unix_seconds: self.now(),
            previous_signing_key_id: Some(previous_signing_key.key_id.clone()),
            renewal_policy: Some(request.renewal_policy.as_str().to_owned()),
            predecessor_certificate_id: Some(request.previous_certificate_id.clone()),
            predecessor_certificate_sha256: Some(request.previous_certificate_sha256.clone()),
        };
        let predecessor_index = inventory
            .enrolled_certificates
            .iter()
            .position(|certificate| {
                certificate.certificate_id == request.previous_certificate_id && certificate.certificate_sha256 == request.previous_certificate_sha256
            })
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        inventory.enrolled_certificates[predecessor_index].state = TzapLocalCertificateState::RenewalPending;
        inventory.pending_certificate_operations.push(pending_operation.clone());
        store.save_inventory(&request.account_key, inventory.clone())?;

        let response = self.submit_renewal(session, request, new_signing_key, csr_der, &challenge, old_signature.as_deref())?;
        parse_renewal_barriers(&response.body)?;
        let mut payload = parse_enrollment_response(&response.body)?;
        let public_metadata = payload.validate_for_key(validator, new_signing_key, self.now())?;
        if !matches_replacement_scope(&public_metadata, &predecessor)
            || (request.renewal_policy == TzapRenewalPolicy::SameKeyRequired && payload.sign_device_id != predecessor.sign_device_id)
        {
            return Err(TzapCertificateLifecycleError::RenewalTargetMismatch);
        }
        let enrollment_request = TzapEnrollmentRequest {
            account_key: request.account_key.clone(),
            org_id: request.org_id.clone(),
            requested_validity_seconds: request.requested_validity_seconds,
            now_unix_seconds: request.now_unix_seconds,
        };
        let new_record =
            payload.into_store_record(&enrollment_request, &new_signing_key.key_id, public_metadata).map_err(TzapCertificateLifecycleError::Enrollment)?;
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
        inventory.pending_certificate_operations.retain(|operation| operation.operation_id != pending_operation.operation_id);
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
            Err(error) if is_reconcilable_renewal_failure(&error) => {
                match self.reconcile_uncertain_renewal(validator, store, session, request, new_signing_key, previous_signing_key) {
                    Ok(Some(record)) => Ok(record),
                    Ok(None) | Err(TzapCertificateLifecycleError::CertificateNotFound) => Err(error),
                    Err(recovery_error) => Err(recovery_error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Resumes a renewal journal left by a previous process before the caller
    /// considers the predecessor for signing or submits another issuance.
    pub fn resume_pending_renewal(
        &self,
        validator: &impl TzapEnrollmentCertificateValidator,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        enrollment_request: &TzapEnrollmentRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
    ) -> Result<Option<TzapEnrolledCertificateRecord>, TzapCertificateLifecycleError> {
        let inventory = store.load_inventory(&enrollment_request.account_key)?;
        let Some(operation) = inventory
            .pending_certificate_operations
            .iter()
            .find(|operation| operation.kind == TzapCertificateOperationKind::Renewal && operation.signing_key_id == signing_key.key_id)
        else {
            return Ok(None);
        };
        if operation.org_id != enrollment_request.org_id {
            return Err(TzapCertificateLifecycleError::CertificateOperationPending);
        }
        let previous_signing_key_id = operation.previous_signing_key_id.as_deref().ok_or(TzapCertificateLifecycleError::CertificateOperationPending)?;
        let previous_signing_key = inventory
            .device_signing_keys
            .iter()
            .find(|key| key.key_id == previous_signing_key_id)
            .ok_or(TzapCertificateLifecycleError::CertificateOperationPending)?;
        let renewal_policy = match operation.renewal_policy.as_deref() {
            Some("same_key_required") => TzapRenewalPolicy::SameKeyRequired,
            Some("key_rotation_allowed") => TzapRenewalPolicy::KeyRotationAllowed,
            _ => return Err(TzapCertificateLifecycleError::CertificateOperationPending),
        };
        let request = TzapRenewalRequest {
            account_key: enrollment_request.account_key.clone(),
            previous_certificate_id: operation.predecessor_certificate_id.clone().ok_or(TzapCertificateLifecycleError::CertificateOperationPending)?,
            previous_certificate_sha256: operation.predecessor_certificate_sha256.clone().ok_or(TzapCertificateLifecycleError::CertificateOperationPending)?,
            org_id: operation.org_id.clone(),
            requested_validity_seconds: operation.requested_validity_seconds,
            renewal_policy,
            now_unix_seconds: self.now(),
            server_grace_seconds: RENEWAL_GRACE_MAX_SECONDS,
        };
        self.reconcile_uncertain_renewal(validator, store, session, &request, signing_key, previous_signing_key)
    }

    fn reconcile_uncertain_renewal(
        &self,
        validator: &impl TzapEnrollmentCertificateValidator,
        store: &mut impl TzapLocalIdentityStore,
        session: &TzapSessionRecord,
        request: &TzapRenewalRequest,
        signing_key: &TzapDeviceSigningKeyRecord,
        previous_signing_key: &TzapDeviceSigningKeyRecord,
    ) -> Result<Option<TzapEnrolledCertificateRecord>, TzapCertificateLifecycleError> {
        let enrollment_client =
            TzapEnrollmentClient::with_wire_profile(&self.sign_base_url, self.transport, self.wire_profile, self.device_name.clone()).with_clock(self.clock);
        let inventory = store.load_inventory(&request.account_key)?;
        validate_stored_signing_key(&inventory, signing_key)?;
        validate_stored_signing_key(&inventory, previous_signing_key)?;
        let predecessor = inventory
            .enrolled_certificates
            .iter()
            .find(|certificate| {
                certificate.certificate_id == request.previous_certificate_id
                    && certificate.certificate_sha256 == request.previous_certificate_sha256
                    && certificate.state == TzapLocalCertificateState::RenewalPending
            })
            .cloned()
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        if predecessor.signing_key_id != previous_signing_key.key_id {
            return Err(TzapCertificateLifecycleError::RenewalTargetMismatch);
        }

        let mut replacement: Option<TzapEnrolledCertificateRecord> = None;
        let listed_certificates = if let Some(org_id) = &request.org_id {
            enrollment_client.list_organization_certificates(session, org_id)?
        } else {
            enrollment_client.list_certificates(session)?
        };
        let predecessor_was_superseded = listed_certificates
            .iter()
            .any(|listed| listed.certificate_id == request.previous_certificate_id && listed.revocation_category.as_deref() == Some("supersession"));
        let mut predecessor_is_active = false;
        for listed in listed_certificates {
            if listed.certificate_id == request.previous_certificate_id && listed.certificate_sha256 == request.previous_certificate_sha256 {
                if listed.lifecycle_state.as_deref() == Some("active") {
                    let mut detail = if let Some(org_id) = &request.org_id {
                        enrollment_client.get_organization_certificate(session, org_id, &listed.certificate_id)?
                    } else {
                        enrollment_client.get_certificate(session, &listed.certificate_id)?
                    };
                    if detail.certificate_id == listed.certificate_id
                        && detail.certificate_sha256 == listed.certificate_sha256
                        && detail.lifecycle_state.as_deref() == Some("active")
                    {
                        let detail_metadata = detail.validate_for_key(validator, previous_signing_key, self.now())?;
                        predecessor_is_active = matches_replacement_scope(&detail_metadata, &predecessor)
                            && detail.sign_device_id == predecessor.sign_device_id
                            && detail.login_organization_device_id.as_deref()
                                == match &predecessor.sign_device_routing {
                                    TzapSignDeviceRouting::Personal => None,
                                    TzapSignDeviceRouting::Organization { login_organization_device_id, .. } => Some(login_organization_device_id.as_str()),
                                };
                    }
                } else if listed.revocation_category.as_deref() == Some("supersession") {
                    // The server marks only renewal replacements as supersession.
                }
                continue;
            }
            if listed.lifecycle_state.as_deref() != Some("active")
                || listed.public_device_id.as_deref() != Some(predecessor.public_metadata.public_device_id.as_str())
                || listed.public_org_id.as_deref() != predecessor.public_metadata.public_org_id.as_deref()
                || listed.public_signer_id.as_deref().is_some_and(|signer| signer != predecessor.public_metadata.public_signer_id)
            {
                continue;
            }

            // The list entry is only a candidate. Fetch the full detail before
            // installing it so a partial/stale list response cannot alter the
            // local catalog.
            let mut detail = if let Some(org_id) = &request.org_id {
                enrollment_client.get_organization_certificate(session, org_id, &listed.certificate_id)?
            } else {
                enrollment_client.get_certificate(session, &listed.certificate_id)?
            };
            if detail.certificate_id != listed.certificate_id
                || detail.certificate_sha256 != listed.certificate_sha256
                || detail.lifecycle_state.as_deref() != Some("active")
                || detail.sign_device_id != listed.sign_device_id
            {
                continue;
            }
            let detail_metadata = detail.validate_for_key(validator, signing_key, self.now())?;
            let explicit_predecessor = matches_predecessor(&detail, request)
                || (listed.predecessor_certificate_id.as_deref() == Some(request.previous_certificate_id.as_str())
                    && listed.predecessor_certificate_sha256.as_deref().is_none_or(|hash| hash == request.previous_certificate_sha256));
            if !matches_replacement_scope(&detail_metadata, &predecessor)
                || (request.renewal_policy == TzapRenewalPolicy::SameKeyRequired && detail.sign_device_id != predecessor.sign_device_id)
                || (!explicit_predecessor && !predecessor_was_superseded)
            {
                continue;
            }
            let enrollment_request = TzapEnrollmentRequest {
                account_key: request.account_key.clone(),
                org_id: request.org_id.clone(),
                requested_validity_seconds: request.requested_validity_seconds,
                now_unix_seconds: request.now_unix_seconds,
            };
            let candidate =
                detail.into_store_record(&enrollment_request, &signing_key.key_id, detail_metadata).map_err(TzapCertificateLifecycleError::Enrollment)?;
            if replacement
                .as_ref()
                .is_some_and(|previous| previous.certificate_sha256 != candidate.certificate_sha256 || previous.certificate_id != candidate.certificate_id)
            {
                return Err(TzapCertificateLifecycleError::ReconciliationConflict);
            }
            replacement = Some(candidate);
        }
        if let Some(record) = &replacement {
            install_reconciled_replacement(store, request, record.clone())?;
        } else if predecessor_is_active {
            restore_pending_renewal(store, request)?;
        } else {
            return Err(TzapCertificateLifecycleError::CertificateOperationPending);
        }
        Ok(replacement)
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

    /// Validates the predecessor certificate against the local inventory and
    /// returns that inventory so the caller can reuse it for the eventual
    /// commit instead of loading it from disk and the OS keychain a second
    /// time for the same account.
    fn precheck_renewal(
        store: &impl TzapLocalIdentityStore,
        request: &TzapRenewalRequest,
    ) -> Result<TzapLocalIdentityInventory, TzapCertificateLifecycleError> {
        let inventory = store.load_inventory(&request.account_key)?;
        let certificate = inventory
            .enrolled_certificates
            .iter()
            .find(|record| record.certificate_id == request.previous_certificate_id && record.certificate_sha256 == request.previous_certificate_sha256)
            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
        let scope_matches = match (&request.org_id, &certificate.sign_device_routing) {
            (None, crate::local_identity_store::TzapSignDeviceRouting::Personal) => true,
            (Some(org), crate::local_identity_store::TzapSignDeviceRouting::Organization { org_id, .. }) => org == org_id,
            _ => false,
        };
        if !scope_matches {
            return Err(TzapCertificateLifecycleError::RenewalTargetMismatch);
        }
        let root_sha256 = certificate.intermediate_chain_der.last().map(|der| crate::trust::sha256_identifier(der));
        if inventory.emergency_blocklist.blocked_issuer_sha256.iter().any(|issuer| issuer == &certificate.issuer_certificate_sha256)
            || root_sha256.is_some_and(|root| inventory.emergency_blocklist.blocked_root_sha256.iter().any(|blocked| blocked == &root))
        {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        if !matches!(certificate.state, TzapLocalCertificateState::Active) || request.now_unix_seconds < certificate.not_before_unix_seconds {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        let grace = request.server_grace_seconds.min(RENEWAL_GRACE_MAX_SECONDS);
        if request.now_unix_seconds > certificate.not_after_unix_seconds.saturating_add(grace) {
            return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
        }
        Ok(inventory)
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

fn authenticated_device_scope(
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
) -> Result<Option<TzapHostedDeviceBinding>, TzapCertificateLifecycleError> {
    let Some(provenance) = &session.provenance else { return Ok(None) };
    provenance.validate()?;
    if provenance.environment == crate::auth_client::TzapHostedAuthEnvironment::Local {
        return Ok(None);
    }
    let owner_user_id = session.user_id.clone().ok_or(TzapCertificateLifecycleError::Auth(TzapAuthError::MissingSessionProvenance))?;
    let binding = TzapHostedDeviceBinding {
        owner_user_id,
        environment: crate::session_provenance::environment_name(provenance.environment).to_owned(),
        auth_origin: provenance.auth_origin.clone(),
        signing_origin: provenance.signing_origin.clone(),
        org_id: request.org_id.clone(),
        sign_device_id: None,
        public_device_id: None,
        binding_signature: None,
    };
    binding.validate()?;
    Ok(Some(binding))
}

/// Enrolls or renews a device certificate. Hosted sessions select an existing
/// key by authenticated owner/environment/org scope; `label` is display-only.
/// Local sessions without hosted provenance retain label-based selection.
/// Renewal proves continuity with the same key instead of enrolling fresh.
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
#[allow(clippy::too_many_lines, clippy::if_not_else)]
pub fn enroll_or_renew_device_certificate<T: TzapAuthHttpTransport>(
    enrollment_client: &TzapEnrollmentClient<'_, T>,
    lifecycle_client: &TzapCertificateLifecycleClient<'_, T>,
    validator: &impl TzapEnrollmentCertificateValidator,
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    request: &TzapEnrollmentRequest,
    label: &str,
) -> Result<TzapEnrolledCertificateRecord, TzapCertificateLifecycleError> {
    enrollment_client.authorize_session(session)?;
    let hosted_scope = authenticated_device_scope(session, request)?;
    let mut inventory = store.load_inventory(&request.account_key)?;
    let matching_keys = if let Some(scope) = &hosted_scope {
        inventory
            .device_signing_keys
            .iter()
            .filter(|record| record.hosted_binding.as_ref().is_some_and(|binding| binding.same_scope(scope)))
            .collect::<Vec<_>>()
    } else {
        inventory.device_signing_keys.iter().filter(|record| record.label.as_deref() == Some(label)).collect::<Vec<_>>()
    };
    let fingerprints =
        matching_keys.iter().map(|key| crate::enrollment_client::signing_key_public_fingerprint(key)).collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if fingerprints.len() > 1 {
        return Err(TzapCertificateLifecycleError::AmbiguousSigningKey);
    }
    let existing_key = matching_keys
        .into_iter()
        .max_by_key(|key| {
            let current = inventory
                .enrolled_certificates
                .iter()
                .filter(|certificate| certificate.signing_key_id == key.key_id && certificate.state == TzapLocalCertificateState::Active)
                .map(|certificate| certificate.not_before_unix_seconds)
                .max();
            (current, &key.key_id)
        })
        .cloned();

    let signing_key = if let Some(record) = existing_key {
        record
    } else {
        let material =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).map_err(|error| TzapCertificateLifecycleError::Crypto(error.to_string()))?;
        let record = TzapDeviceSigningKeyRecord {
            key_id: material.public_key_fingerprint.clone(),
            public_key_fingerprint: material.public_key_fingerprint,
            private_key_der: material.private_key_der,
            created_at_unix_seconds: enrollment_client.now(),
            label: Some(label.to_owned()),
            hosted_binding: hosted_scope.clone(),
        };
        inventory.device_signing_keys.push(record.clone());
        store.save_inventory(&request.account_key, inventory)?;
        record
    };

    let csr_der = generate_device_csr_from_private_key(&signing_key.private_key_der, &TzapDeviceCsrOptions::default())
        .map_err(|error| TzapCertificateLifecycleError::Crypto(error.to_string()))?;

    let resumed_certificate = lifecycle_client.resume_pending_renewal(validator, store, session, request, &signing_key)?;
    let active_certificate = if resumed_certificate.is_some() {
        None
    } else {
        store
            .load_inventory(&request.account_key)?
            .enrolled_certificates
            .into_iter()
            .filter(|certificate| {
                certificate.signing_key_id == signing_key.key_id
                    && certificate.state == TzapLocalCertificateState::Active
                    && match (&request.org_id, &certificate.sign_device_routing) {
                        (None, crate::local_identity_store::TzapSignDeviceRouting::Personal) => true,
                        (Some(requested_org_id), crate::local_identity_store::TzapSignDeviceRouting::Organization { org_id, .. }) => requested_org_id == org_id,
                        _ => false,
                    }
            })
            .max_by_key(|certificate| (certificate.not_before_unix_seconds, certificate.certificate_sha256.clone()))
    };

    let certificate = if let Some(certificate) = resumed_certificate {
        Ok(certificate)
    } else {
        match active_certificate {
            Some(mut certificate) => {
                if !certificate_is_due_for_renewal(&certificate, request.now_unix_seconds) {
                    if request.now_unix_seconds < certificate.not_before_unix_seconds {
                        return Err(TzapCertificateLifecycleError::CertificateNotRenewable);
                    }
                    let mut chain = Vec::with_capacity(1 + certificate.intermediate_chain_der.len());
                    chain.push(certificate.leaf_certificate_der.clone());
                    chain.extend(certificate.intermediate_chain_der.iter().cloned());
                    let (completed_chain, metadata) =
                        validator.validate_and_complete_certificate_chain(&chain).map_err(TzapCertificateLifecycleError::Enrollment)?;
                    if completed_chain.first() != Some(&certificate.leaf_certificate_der) || completed_chain.iter().any(Vec::is_empty) {
                        return Err(TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::CertificateChain(
                            "stored certificate chain is incomplete or changed its leaf".to_owned(),
                        )));
                    }
                    if metadata != certificate.public_metadata {
                        return Err(TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::CertificateChain(
                            "stored certificate metadata does not match its validated chain".to_owned(),
                        )));
                    }
                    if trust::sha256_identifier(&certificate.leaf_certificate_der) != certificate.certificate_sha256 {
                        return Err(TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::CertificateChain(
                            "stored certificate fingerprint does not match its leaf".to_owned(),
                        )));
                    }
                    let (leaf_not_before, leaf_not_after) = crate::enrollment_client::certificate_validity_unix_seconds(&certificate.leaf_certificate_der)
                        .map_err(TzapCertificateLifecycleError::Enrollment)?;
                    if leaf_not_before != certificate.not_before_unix_seconds || leaf_not_after != certificate.not_after_unix_seconds {
                        return Err(TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::CertificateChain(
                            "stored certificate validity does not match its leaf".to_owned(),
                        )));
                    }
                    let leaf_key_fingerprint = openssl::x509::X509::from_der(&certificate.leaf_certificate_der)
                        .and_then(|leaf| leaf.public_key())
                        .and_then(|key| key.public_key_to_der())
                        .map(|der| trust::sha256_identifier(&der))
                        .map_err(|_| TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::InvalidField { field: "leaf_certificate_der" }))?;
                    if leaf_key_fingerprint != crate::enrollment_client::signing_key_public_fingerprint(&signing_key)? {
                        return Err(TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::CertificateChain(
                            "stored certificate is not bound to the selected device key".to_owned(),
                        )));
                    }
                    if completed_chain.len() != chain.len() || completed_chain.iter().zip(&chain).any(|(completed, stored)| completed != stored) {
                        let mut inventory = store.load_inventory(&request.account_key)?;
                        let stored = inventory
                            .enrolled_certificates
                            .iter_mut()
                            .find(|stored| stored.certificate_id == certificate.certificate_id)
                            .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
                        stored.leaf_certificate_der.clone_from(&completed_chain[0]);
                        stored.intermediate_chain_der = completed_chain[1..].to_vec();
                        store.save_inventory(&request.account_key, inventory)?;
                        certificate.leaf_certificate_der.clone_from(&completed_chain[0]);
                        certificate.intermediate_chain_der = completed_chain[1..].to_vec();
                    }
                    Ok(certificate)
                } else {
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
            }
            None => enroll_device_certificate(enrollment_client, validator, store, session, request, &signing_key, &csr_der)
                .map_err(TzapCertificateLifecycleError::from),
        }
    }?;

    if let Some(mut binding) = hosted_scope {
        if let Some(existing) = &signing_key.hosted_binding {
            if !existing.same_scope(&binding) {
                return Err(TzapCertificateLifecycleError::HostedDeviceBindingMismatch);
            }
            if let (Some(sign_device_id), Some(public_device_id)) = (&existing.sign_device_id, &existing.public_device_id) {
                binding.bind_device(sign_device_id, public_device_id)?;
            }
        }
        binding.bind_device(&certificate.sign_device_id, &certificate.public_metadata.public_device_id)?;
        let mut inventory = store.load_inventory(&request.account_key)?;
        let stored_key = inventory
            .device_signing_keys
            .iter_mut()
            .find(|key| key.key_id == signing_key.key_id)
            .ok_or(TzapCertificateLifecycleError::HostedDeviceBindingMismatch)?;
        stored_key.hosted_binding = Some(binding);
        store.save_inventory(&request.account_key, inventory)?;
    }
    Ok(certificate)
}

fn certificate_is_due_for_renewal(certificate: &TzapEnrolledCertificateRecord, now_unix_seconds: u64) -> bool {
    let recommendation_window = certificate.renewal_recommended_within_days.unwrap_or(0).saturating_mul(SECONDS_PER_DAY);
    now_unix_seconds >= certificate.not_after_unix_seconds.saturating_sub(recommendation_window)
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
    session: &TzapSessionRecord,
    request: &TzapRenewalRequest,
    signing_key: &TzapDeviceSigningKeyRecord,
    csr_der: &[u8],
    challenge: &crate::enrollment_client::TzapEnrollmentChallenge,
    now_unix_seconds: u64,
) -> Result<(), TzapCertificateLifecycleError> {
    let object = json_object::<TzapCertificateLifecycleError>(&challenge.payload, "challenge_payload")?;
    match wire_profile {
        crate::wire_profile::TzapWireProfile::Spec => {
            expect_string(object, "canonicalization", ENROLLMENT_CHALLENGE_CANONICALIZATION)?;
            expect_string(object, "audience", SESSION_AUDIENCE_SIGN_TZAP)?;
            expect_u64(object, "requested_validity_seconds", request.requested_validity_seconds)?;
        }
        crate::wire_profile::TzapWireProfile::LocalStagingServer => {
            if challenge.canonicalization.as_deref() != Some(ENROLLMENT_CHALLENGE_CANONICALIZATION) {
                return Err(TzapEnrollmentError::ChallengeMismatch { field: "canonicalization" }.into());
            }
            expect_string(object, "audience", crate::enrollment_client::LOCAL_STAGING_ENROLLMENT_AUDIENCE)?;
            expect_u64(object, "requested_validity_days", requested_validity_days(request.requested_validity_seconds)?)?;
        }
    }
    expect_string(object, "operation", RENEW_OPERATION)?;
    expect_string(object, "challenge_id", &challenge.challenge_id)?;
    expect_string(object, "renewal_of_certificate_sha256", &request.previous_certificate_sha256)?;
    expect_string(object, "certificate_id", &request.previous_certificate_id)?;
    expect_optional_string(object, "org_id", request.org_id.as_deref())?;
    expect_optional_string(object, "session_id", session.login_session_id.as_deref())?;
    expect_string(object, "csr_sha256", &csr_fingerprint(csr_der))?;
    expect_string(object, "device_public_key_fingerprint", &signing_key.public_key_fingerprint)?;
    crate::enrollment_client::validate_challenge_profile_metadata(wire_profile, object, now_unix_seconds)?;
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
        TzapCertificateLifecycleError::Auth(TzapAuthError::HttpStatus { status_code })
        | TzapCertificateLifecycleError::HttpStatus { status_code }
        | TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::HttpStatus { status_code, .. }) => *status_code != 401,
        TzapCertificateLifecycleError::Auth(TzapAuthError::Transport { .. })
        | TzapCertificateLifecycleError::Store(_)
        | TzapCertificateLifecycleError::Enrollment(
            TzapEnrollmentError::InvalidJson(_)
            | TzapEnrollmentError::InvalidField { .. }
            | TzapEnrollmentError::CertificateChain(_)
            | TzapEnrollmentError::Denied(_),
        ) => true,
        _ => false,
    }
}

fn matches_predecessor(payload: &crate::enrollment_client::TzapEnrollmentCertificatePayload, request: &TzapRenewalRequest) -> bool {
    (payload.predecessor_certificate_id.is_some() || payload.predecessor_certificate_sha256.is_some())
        && payload.predecessor_certificate_id.as_ref().is_none_or(|id| id == &request.previous_certificate_id)
        && payload.predecessor_certificate_sha256.as_ref().is_none_or(|hash| hash == &request.previous_certificate_sha256)
}

fn matches_replacement_scope(metadata: &crate::trust::TzapCertificatePublicMetadata, predecessor: &TzapEnrolledCertificateRecord) -> bool {
    metadata.public_device_id == predecessor.public_metadata.public_device_id
        && metadata.public_signer_id == predecessor.public_metadata.public_signer_id
        && metadata.public_org_id == predecessor.public_metadata.public_org_id
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
    inventory.pending_certificate_operations.retain(|operation| {
        operation.kind != TzapCertificateOperationKind::Renewal
            || operation.predecessor_certificate_id.as_deref() != Some(request.previous_certificate_id.as_str())
            || operation.predecessor_certificate_sha256.as_deref() != Some(request.previous_certificate_sha256.as_str())
    });
    store.save_inventory(&request.account_key, inventory)?;
    Ok(())
}

fn restore_pending_renewal(store: &mut impl TzapLocalIdentityStore, request: &TzapRenewalRequest) -> Result<(), TzapCertificateLifecycleError> {
    let mut inventory = store.load_inventory(&request.account_key)?;
    let predecessor = inventory
        .enrolled_certificates
        .iter_mut()
        .find(|certificate| {
            certificate.certificate_id == request.previous_certificate_id
                && certificate.certificate_sha256 == request.previous_certificate_sha256
                && certificate.state == TzapLocalCertificateState::RenewalPending
        })
        .ok_or(TzapCertificateLifecycleError::CertificateNotFound)?;
    predecessor.state = TzapLocalCertificateState::Active;
    inventory.pending_certificate_operations.retain(|operation| {
        operation.kind != TzapCertificateOperationKind::Renewal
            || operation.predecessor_certificate_id.as_deref() != Some(request.previous_certificate_id.as_str())
            || operation.predecessor_certificate_sha256.as_deref() != Some(request.previous_certificate_sha256.as_str())
    });
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
        _ => Err(TzapEnrollmentError::ChallengeMismatch { field }.into()),
    }
}

fn expect_u64(object: &Map<String, Value>, field: &'static str, expected: u64) -> Result<(), TzapCertificateLifecycleError> {
    if object.get(field).and_then(Value::as_u64) == Some(expected) { Ok(()) } else { Err(TzapEnrollmentError::ChallengeMismatch { field }.into()) }
}

fn expect_optional_string(object: &Map<String, Value>, field: &'static str, expected: Option<&str>) -> Result<(), TzapCertificateLifecycleError> {
    let actual = optional_string::<TzapCertificateLifecycleError>(object, field)?;
    if actual.as_deref() == expected { Ok(()) } else { Err(TzapEnrollmentError::ChallengeMismatch { field }.into()) }
}

#[cfg(test)]
mod tests {
    use super::{
        OrganizationDeviceLookup, RENEW_OPERATION, TzapCertificateLifecycleClient, TzapCertificateLifecycleError, TzapRenewalPolicy, TzapRenewalRequest,
        TzapRetirementCompletion, csr_fingerprint, revocation_completion,
    };
    use crate::auth_client::{
        SESSION_AUDIENCE_LOGIN_TZAP, SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport,
        TzapBearerToken, TzapSessionRecord,
    };
    use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
    use crate::enrollment_client::{
        ENROLLMENT_CHALLENGE_CANONICALIZATION, ENROLLMENT_CHALLENGES_PATH, TzapEnrollmentCertificateValidator, TzapEnrollmentClient, TzapEnrollmentError,
        TzapEnrollmentRequest,
    };
    use crate::local_identity_store::{
        DEFAULT_IDENTITY_INVENTORY_ACCOUNT, InMemoryTzapLocalIdentityStore, TzapDeviceSigningKeyRecord, TzapEmergencyBlocklistState,
        TzapEnrolledCertificateRecord, TzapHostedDeviceBinding, TzapLocalCertificateState, TzapLocalIdentityInventory, TzapLocalIdentityStore,
        TzapOrganizationDeviceRetirement, TzapSignDeviceRouting,
    };
    use crate::trust::{self, TzapCertificatePublicMetadata};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use std::cell::RefCell;

    #[test]
    fn provisioning_expired_session_does_not_generate_or_store_a_key() {
        let mut fixture = LifecycleFixture::new();
        fixture.sign_session.expires_at_unix_seconds = 149;
        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };
        let mut store = InMemoryTzapLocalIdentityStore::new();
        assert!(
            super::enroll_or_renew_device_certificate(
                &enrollment,
                &lifecycle,
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &request,
                "device"
            )
            .is_err()
        );
        assert!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().device_signing_keys.is_empty());
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn provisioning_at_another_origin_fails_before_key_generation_or_http() {
        let mut fixture = LifecycleFixture::new();
        fixture.sign_session.user_id = Some("user_fixture_one".to_owned());
        let config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            crate::auth_client::TzapHostedAuthEnvironment::Staging,
            "zmanager-cli",
            "tzap://auth/callback",
        );
        fixture.sign_session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&config, "fixture-flow").unwrap()).unwrap();
        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://fixture-wrong-origin.invalid", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://fixture-wrong-origin.invalid", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let error = super::enroll_or_renew_device_certificate(
            &enrollment,
            &lifecycle,
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &request,
            "device",
        )
        .unwrap_err();
        assert!(matches!(error, TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::Auth(TzapAuthError::SessionOriginMismatch))));
        assert!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().device_signing_keys.is_empty());
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn hosted_provisioning_never_reuses_a_same_label_key_from_another_owner() {
        let mut fixture = LifecycleFixture::new();
        fixture.sign_session.user_id = Some("user_new_owner".to_owned());
        let config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            crate::auth_client::TzapHostedAuthEnvironment::Staging,
            "zmanager-cli",
            "tzap://auth/callback",
        );
        fixture.sign_session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&config, "flow-owner-test").unwrap()).unwrap();

        let mut old_key = fixture.signing_key.clone();
        old_key.label = Some("same display label".to_owned());
        old_key.hosted_binding = Some(TzapHostedDeviceBinding {
            owner_user_id: "user_old_owner".to_owned(),
            environment: "staging".to_owned(),
            auth_origin: "https://staging.tzap.org".to_owned(),
            signing_origin: "https://staging.tzap.org".to_owned(),
            org_id: None,
            sign_device_id: None,
            public_device_id: None,
            binding_signature: None,
        });
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(old_key.clone());
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };

        assert!(
            super::enroll_or_renew_device_certificate(
                &enrollment,
                &lifecycle,
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &request,
                "same display label",
            )
            .is_err()
        );
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.device_signing_keys.len(), 2);
        assert_eq!(inventory.device_signing_keys.iter().find(|key| key.key_id == old_key.key_id).unwrap().hosted_binding, old_key.hosted_binding);
        let new_key = inventory.device_signing_keys.iter().find(|key| key.key_id != old_key.key_id).unwrap();
        assert_eq!(new_key.hosted_binding.as_ref().map(|binding| binding.owner_user_id.as_str()), Some("user_new_owner"));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn hosted_provisioning_reuses_a_key_bound_to_the_same_owner_and_scope() {
        let mut fixture = LifecycleFixture::new();
        fixture.sign_session.user_id = Some("user_new_owner".to_owned());
        let config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            crate::auth_client::TzapHostedAuthEnvironment::Staging,
            "zmanager-cli",
            "tzap://auth/callback",
        );
        fixture.sign_session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&config, "flow-same-owner-test").unwrap()).unwrap();

        let mut key = fixture.signing_key.clone();
        key.hosted_binding = Some(TzapHostedDeviceBinding {
            owner_user_id: "user_new_owner".to_owned(),
            environment: "staging".to_owned(),
            auth_origin: "https://staging.tzap.org".to_owned(),
            signing_origin: "https://staging.tzap.org".to_owned(),
            org_id: None,
            sign_device_id: None,
            public_device_id: None,
            binding_signature: None,
        });
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(key.clone());
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };

        assert!(
            super::enroll_or_renew_device_certificate(
                &enrollment,
                &lifecycle,
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &request,
                "a different label",
            )
            .is_err()
        );
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.device_signing_keys.len(), 1);
        assert_eq!(inventory.device_signing_keys[0].key_id, key.key_id);
        assert_eq!(inventory.device_signing_keys[0].hosted_binding, key.hosted_binding);
    }

    #[test]
    fn hosted_provisioning_ignores_an_unbound_key_and_creates_a_scoped_key() {
        let mut fixture = LifecycleFixture::new();
        fixture.sign_session.user_id = Some("user_new_owner".to_owned());
        let config = crate::auth_client::TzapHostedAuthLaunchConfig::for_environment(
            crate::auth_client::TzapHostedAuthEnvironment::Staging,
            "zmanager-cli",
            "tzap://auth/callback",
        );
        fixture.sign_session.bind_provenance(crate::session_provenance::TzapSessionProvenance::from_launch(&config, "flow-unbound-test").unwrap()).unwrap();
        fixture.signing_key.label = Some("legacy hosted key".to_owned());
        let mut store = InMemoryTzapLocalIdentityStore::new();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(fixture.signing_key.clone());
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };

        assert!(
            super::enroll_or_renew_device_certificate(
                &enrollment,
                &lifecycle,
                &AcceptingLifecycleValidator,
                &mut store,
                &fixture.sign_session,
                &request,
                "legacy hosted key",
            )
            .is_err()
        );
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.device_signing_keys.len(), 2);
        assert!(inventory.device_signing_keys.iter().any(|key| key.hosted_binding.is_none()));
        assert!(
            inventory.device_signing_keys.iter().any(|key| {
                key.hosted_binding.as_ref().is_some_and(|binding| binding.owner_user_id == "user_new_owner" && binding.environment == "staging")
            })
        );
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn provisioning_reuses_valid_active_certificate_outside_server_recommended_window() {
        let x509 = zmanager_core::backend_test_support::x509_factory::certificate_fixture_at(Default::default(), 100, 2_000_000);
        let private_key_der = x509.leaf_key.private_key_to_der().unwrap();
        let public_key_fingerprint = x509.leaf_key.public_key_to_der().map(|der| trust::sha256_identifier(&der)).unwrap();
        let signing_key = TzapDeviceSigningKeyRecord {
            key_id: public_key_fingerprint.clone(),
            public_key_fingerprint,
            private_key_der: private_key_der.into(),
            created_at_unix_seconds: 100,
            label: Some("device".to_owned()),
            hosted_binding: None,
        };
        let mut certificate = certificate_record(TzapSignDeviceRouting::Personal);
        certificate.certificate_sha256 = trust::sha256_identifier(&x509.chain_der[0]);
        certificate.leaf_certificate_der = x509.chain_der[0].clone();
        certificate.intermediate_chain_der = x509.chain_der[1..].to_vec();
        certificate.not_before_unix_seconds = 100;
        certificate.not_after_unix_seconds = 2_000_000;
        certificate.renewal_recommended_within_days = Some(14);
        certificate.signing_key_id = signing_key.key_id.clone();

        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(signing_key);
        inventory.enrolled_certificates.push(certificate.clone());
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };

        let reused = super::enroll_or_renew_device_certificate(
            &enrollment,
            &lifecycle,
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &request,
            "device",
        )
        .unwrap();

        assert_eq!(reused.certificate_id, certificate.certificate_id);
        assert!(transport.requests().is_empty(), "a certificate outside its renewal window must not trigger HTTP");
    }

    #[test]
    fn renewal_window_uses_server_recommendation_and_defaults_missing_policy_to_expiry() {
        let mut certificate = certificate_record(TzapSignDeviceRouting::Personal);
        certificate.not_after_unix_seconds = 2_000_000;
        certificate.renewal_recommended_within_days = Some(14);
        assert!(!super::certificate_is_due_for_renewal(&certificate, 2_000_000 - 14 * 86400 - 1));
        assert!(super::certificate_is_due_for_renewal(&certificate, 2_000_000 - 14 * 86400));
        certificate.renewal_recommended_within_days = None;
        assert!(!super::certificate_is_due_for_renewal(&certificate, 2_000_000 - 1));
        assert!(super::certificate_is_due_for_renewal(&certificate, 2_000_000));
    }

    #[test]
    fn provisioning_duplicate_labels_do_not_select_the_first_key() {
        let mut fixture = LifecycleFixture::new();
        let mut other = LifecycleFixture::new();
        fixture.signing_key.label = Some("device".to_owned());
        other.signing_key.label = Some("device".to_owned());
        other.signing_key.key_id = "other-key".to_owned();
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys = vec![fixture.signing_key.clone(), other.signing_key];
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
        let transport = FakeLifecycleTransport::new(Vec::new());
        let enrollment = TzapEnrollmentClient::new("https://staging.tzap.org", &transport).with_clock(|| 150);
        let lifecycle = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 86400,
            now_unix_seconds: 150,
        };
        let error = super::enroll_or_renew_device_certificate(
            &enrollment,
            &lifecycle,
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &request,
            "device",
        )
        .unwrap_err();
        assert!(error.to_string().contains("more than one"), "{error}");
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn issued_renewal_rejects_another_keys_certificate_without_replacing_the_predecessor() {
        let fixture = LifecycleFixture::new();
        let other = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, None), renewal_certificate_response(&other.signing_key)]);
        let client = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let result = client.renew_certificate(
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
            &fixture.signing_key,
            &fixture.signing_key,
            &fixture.csr_der,
        );
        assert!(result.is_err());
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates.len(), 1);
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::RenewalPending);
        assert_eq!(inventory.pending_certificate_operations.len(), 1);
        assert!(inventory.active_personal_sign_device_ids().is_empty());
    }

    #[test]
    fn renewal_rejects_expired_and_wrong_session_challenges_before_submission() {
        let fixture = LifecycleFixture::new();
        for (mut response, expired) in [(renewal_challenge_response(&fixture, None), false), (renewal_challenge_response(&fixture, None), true)] {
            let mut body: Value = serde_json::from_slice(&response.body).unwrap();
            if expired {
                body["challenge_payload"]["expires_at_unix_seconds"] = json!(150);
            } else {
                body["challenge_payload"]["session_id"] = json!("another-session");
            }
            response.body = serde_json::to_vec(&body).unwrap();
            let transport = FakeLifecycleTransport::new(vec![response]);
            let client = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
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
            if expired {
                assert!(matches!(error, TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::ChallengeExpired)));
            } else {
                assert!(matches!(error, TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::ChallengeMismatch { field: "session_id" })));
            }
            assert_eq!(transport.requests().len(), 1, "invalid challenge must not be submitted");
        }
    }

    #[test]
    fn issued_renewal_persists_the_completed_chain() {
        let fixture = LifecycleFixture::new();
        let mut response = renewal_certificate_response(&fixture.signing_key);
        let mut body: Value = serde_json::from_slice(&response.body).unwrap();
        let chain = body["certificate"]["intermediate_chain_der"].as_array_mut().unwrap();
        let root = URL_SAFE_NO_PAD.decode(chain.pop().unwrap().as_str().unwrap()).unwrap();
        response.body = body.to_string().into_bytes();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&fixture, None), response]);
        let client = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let record = client
            .renew_certificate(
                &CompletingValidator { root: root.clone() },
                &mut store,
                &fixture.sign_session,
                &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                &fixture.signing_key,
                &fixture.signing_key,
                &fixture.csr_der,
            )
            .unwrap();
        assert_eq!(record.intermediate_chain_der.last(), Some(&root));
        assert_eq!(record.intermediate_chain_der.len(), 2);
    }

    #[test]
    fn issued_renewal_rejects_an_empty_completed_chain() {
        let fixture = LifecycleFixture::new();
        let session_id = fixture.sign_session.login_session_id.clone();
        let certificate_response = renewal_certificate_response(&fixture.signing_key);
        let transport = FakeLifecycleTransport::with_handler(move |request| {
            if request.url.ends_with(ENROLLMENT_CHALLENGES_PATH) {
                let body = request.body.as_ref().and_then(Value::as_object).ok_or(TzapAuthError::ExpectedObject { path: "challenge_request" })?;
                let csr_der = URL_SAFE_NO_PAD
                    .decode(body["csr_der"].as_str().ok_or(TzapAuthError::ExpectedObject { path: "csr_der" })?)
                    .map_err(|_| TzapAuthError::ExpectedObject { path: "csr_der" })?;
                let payload = json!({
                    "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
                    "audience": SESSION_AUDIENCE_SIGN_TZAP,
                    "operation": RENEW_OPERATION,
                    "challenge_id": "renew-challenge-1",
                    "certificate_id": "cert_old",
                    "renewal_of_certificate_sha256": body["renewal_of_certificate_sha256"],
                    "org_id": body["org_id"],
                    "session_id": session_id,
                    "csr_sha256": csr_fingerprint(&csr_der),
                    "device_public_key_fingerprint": body["device_public_key_fingerprint"],
                    "requested_validity_seconds": body["requested_validity_seconds"],
                    "expires_at_unix_seconds": 200,
                });
                Ok(TzapAuthHttpResponse {
                    status_code: 200,
                    body: json!({"challenge_id": "renew-challenge-1", "challenge_payload": payload}).to_string().into_bytes(),
                    headers: Vec::new(),
                })
            } else {
                Ok(certificate_response.clone())
            }
        });
        let client = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        assert!(
            client
                .renew_certificate(
                    &EmptyCompletionValidator,
                    &mut store,
                    &fixture.sign_session,
                    &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der
                )
                .is_err()
        );
        assert_eq!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().enrolled_certificates.len(), 1);
    }

    #[test]
    fn issued_renewal_reconciliation_checks_the_requested_public_key() {
        let fixture = LifecycleFixture::new();
        let other = LifecycleFixture::new();
        let wrong = reconciled_certificate_json(&other.signing_key);
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            TzapAuthHttpResponse { status_code: 503, body: Vec::new(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificates": [wrong.clone()]}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificate": wrong}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://staging.tzap.org", "https://staging.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        assert!(
            client
                .renew_certificate_with_reconciliation(
                    &AcceptingLifecycleValidator,
                    &mut store,
                    &fixture.sign_session,
                    &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
                    &fixture.signing_key,
                    &fixture.signing_key,
                    &fixture.csr_der
                )
                .is_err()
        );
        assert_eq!(store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap().enrolled_certificates.len(), 1);
    }

    struct CompletingValidator {
        root: Vec<u8>,
    }
    impl TzapEnrollmentCertificateValidator for CompletingValidator {
        fn validate_certificate_chain(&self, chain: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            crate::enrollment_client::TzapCustomEnrollmentCertificateValidator::default().validate_certificate_chain(chain)
        }
        fn validate_and_complete_certificate_chain(&self, chain: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, TzapCertificatePublicMetadata), TzapEnrollmentError> {
            let mut completed = chain.to_vec();
            completed.push(self.root.clone());
            let metadata = self.validate_certificate_chain(&completed)?;
            Ok((completed, metadata))
        }
    }

    struct EmptyCompletionValidator;
    impl TzapEnrollmentCertificateValidator for EmptyCompletionValidator {
        fn validate_certificate_chain(&self, _chain: &[Vec<u8>]) -> Result<TzapCertificatePublicMetadata, TzapEnrollmentError> {
            Ok(public_metadata())
        }
        fn validate_and_complete_certificate_chain(&self, _chain: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, TzapCertificatePublicMetadata), TzapEnrollmentError> {
            Ok((Vec::new(), public_metadata()))
        }
    }

    #[test]
    fn renewal_same_key_submits_old_certificate_signature_and_appends_new_certificate() {
        let fixture = LifecycleFixture::new();
        let session_id = fixture.sign_session.login_session_id.clone();
        let certificate_response = renewal_certificate_response(&fixture.signing_key);
        let transport = FakeLifecycleTransport::with_handler(move |request| {
            if request.url.ends_with(ENROLLMENT_CHALLENGES_PATH) {
                let body = request.body.as_ref().and_then(Value::as_object).expect("challenge request body");
                let csr_der = URL_SAFE_NO_PAD.decode(body["csr_der"].as_str().expect("CSR encoding")).expect("CSR bytes");
                let payload = json!({
                    "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
                    "audience": SESSION_AUDIENCE_SIGN_TZAP,
                    "operation": RENEW_OPERATION,
                    "challenge_id": "renew-challenge-1",
                    "certificate_id": "cert_old",
                    "renewal_of_certificate_sha256": body["renewal_of_certificate_sha256"],
                    "org_id": body["org_id"],
                    "session_id": session_id,
                    "csr_sha256": csr_fingerprint(&csr_der),
                    "device_public_key_fingerprint": body["device_public_key_fingerprint"],
                    "requested_validity_seconds": body["requested_validity_seconds"],
                    "expires_at_unix_seconds": 200,
                });
                Ok(TzapAuthHttpResponse {
                    status_code: 200,
                    body: json!({"challenge_id": "renew-challenge-1", "challenge_payload": payload}).to_string().into_bytes(),
                    headers: Vec::new(),
                })
            } else {
                Ok(certificate_response.clone())
            }
        });
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let reconciled = reconciled_certificate_json(&fixture.signing_key);
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            TzapAuthHttpResponse { status_code: 503, body: Vec::new(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: renewal_reconciliation_list(&reconciled).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificate": reconciled}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
    fn renewal_restart_keeps_predecessor_blocked_until_list_detail_recovery() {
        let fixture = LifecycleFixture::new();
        let first_transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, None),
            TzapAuthHttpResponse { status_code: 503, body: Vec::new(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 503, body: Vec::new(), headers: Vec::new() },
        ]);
        let first_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &first_transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let first = first_client.renew_certificate_with_reconciliation(
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired),
            &fixture.signing_key,
            &fixture.signing_key,
            &fixture.csr_der,
        );
        assert!(first.is_err());
        let blocked = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(blocked.enrolled_certificates[0].state, TzapLocalCertificateState::RenewalPending);
        assert_eq!(blocked.pending_certificate_operations.len(), 1);

        let replacement = reconciled_certificate_json(&fixture.signing_key);
        let recovery_transport = FakeLifecycleTransport::new(vec![
            TzapAuthHttpResponse { status_code: 200, body: renewal_reconciliation_list(&replacement).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificate": replacement}).to_string().into_bytes(), headers: Vec::new() },
        ]);
        let recovery_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &recovery_transport).with_clock(|| 151);
        let enrollment_request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 24 * 60 * 60,
            now_unix_seconds: 151,
        };
        let recovered = recovery_client
            .resume_pending_renewal(&AcceptingLifecycleValidator, &mut store, &fixture.sign_session, &enrollment_request, &fixture.signing_key)
            .unwrap()
            .unwrap();

        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(recovered.certificate_id, "cert_reconciled");
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::Revoked);
        assert_eq!(inventory.enrolled_certificates[1].state, TzapLocalCertificateState::Active);
        assert!(inventory.pending_certificate_operations.is_empty());
        assert_eq!(recovery_transport.requests().len(), 2, "recovery must not submit another renewal");
    }

    #[test]
    fn renewal_rejection_restores_predecessor_only_after_server_confirms_it_active() {
        let fixture = LifecycleFixture::new();
        let mut predecessor = crate::local_tzap_service::test_enrollment_certificate_json(&fixture.signing_key, "cert_old", 100);
        predecessor["status"] = json!("active");
        let (mut store, renewal_request) = store_with_wire_predecessor(&fixture, &predecessor);
        let predecessor_sha256 = renewal_request.previous_certificate_sha256.clone();
        let predecessor_detail = predecessor.clone();
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, Some(predecessor_sha256)),
            TzapAuthHttpResponse { status_code: 400, body: json!({"error": "renewal_rejected"}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificates": [predecessor]}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: serde_json::to_vec(&predecessor_detail).unwrap(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);

        let result = client.renew_certificate_with_reconciliation(
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &renewal_request,
            &fixture.signing_key,
            &fixture.signing_key,
            &fixture.csr_der,
        );

        assert!(result.is_err());
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::Active);
        assert!(inventory.pending_certificate_operations.is_empty());
    }

    #[test]
    fn stale_active_list_does_not_restore_predecessor_when_detail_is_revoked() {
        let fixture = LifecycleFixture::new();
        let mut listed_predecessor = crate::local_tzap_service::test_enrollment_certificate_json(&fixture.signing_key, "cert_old", 100);
        listed_predecessor["status"] = json!("active");
        let (mut store, renewal_request) = store_with_wire_predecessor(&fixture, &listed_predecessor);
        let predecessor_sha256 = renewal_request.previous_certificate_sha256.clone();
        let mut detail_predecessor = listed_predecessor.clone();
        detail_predecessor["status"] = json!("revoked");
        let transport = FakeLifecycleTransport::new(vec![
            renewal_challenge_response(&fixture, Some(predecessor_sha256)),
            TzapAuthHttpResponse { status_code: 400, body: json!({"error": "renewal_rejected"}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: json!({"certificates": [listed_predecessor]}).to_string().into_bytes(), headers: Vec::new() },
            TzapAuthHttpResponse { status_code: 200, body: serde_json::to_vec(&detail_predecessor).unwrap(), headers: Vec::new() },
        ]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);

        let result = client.renew_certificate_with_reconciliation(
            &AcceptingLifecycleValidator,
            &mut store,
            &fixture.sign_session,
            &renewal_request,
            &fixture.signing_key,
            &fixture.signing_key,
            &fixture.csr_der,
        );

        assert!(matches!(result, Err(TzapCertificateLifecycleError::CertificateOperationPending)));
        let inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        assert_eq!(inventory.enrolled_certificates[0].state, TzapLocalCertificateState::RenewalPending);
        assert_eq!(inventory.pending_certificate_operations.len(), 1);
        assert!(inventory.active_personal_sign_device_ids().is_empty());
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
        let mut rotated = LifecycleFixture::new();
        rotated.signing_key.key_id = "device-key-rotated".to_owned();
        let transport = FakeLifecycleTransport::new(vec![renewal_challenge_response(&rotated, None), renewal_certificate_response(&rotated.signing_key)]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);
        let mut inventory = store.load_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT).unwrap();
        inventory.device_signing_keys.push(rotated.signing_key.clone());
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

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
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        assert!(matches!(error, TzapCertificateLifecycleError::Enrollment(TzapEnrollmentError::ChallengeMismatch { field: "renewal_of_certificate_sha256" })));
    }

    #[test]
    fn renewal_precheck_rejects_blocked_issuer_and_root() {
        for block in ["issuer", "root"] {
            let fixture = LifecycleFixture::new();
            let transport = FakeLifecycleTransport::new(Vec::new());
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
            body: json!({"error": "admin_mfa_required", "message": "Verify with an admin MFA factor to continue."}).to_string().into_bytes(),
            headers: Vec::new(),
        }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let error = client.revoke_personal_certificate(&mut store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert_old").unwrap_err();

        assert!(matches!(error, TzapCertificateLifecycleError::AdminMfaRequired), "expected AdminMfaRequired, got {error:?}");
    }

    #[test]
    fn personal_revocation_keeps_a_plain_403_as_an_http_status() {
        let fixture = LifecycleFixture::new();
        let transport = FakeLifecycleTransport::new(vec![TzapAuthHttpResponse {
            status_code: 403,
            body: json!({"error": "forbidden"}).to_string().into_bytes(),
            headers: Vec::new(),
        }]);
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
        let mut store = fixture.store_with_certificate(TzapSignDeviceRouting::Personal);

        let error = client.revoke_personal_certificate(&mut store, &fixture.sign_session, DEFAULT_IDENTITY_INVENTORY_ACCOUNT, "cert_old").unwrap_err();

        assert!(matches!(error, TzapCertificateLifecycleError::HttpStatus { status_code: 403 }), "expected HttpStatus 403, got {error:?}");
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
            let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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

    /// An active certificate inside its renewal window renews with the
    /// existing key, rather than minting a second key and enrolling again.
    #[test]
    fn enroll_or_renew_reuses_the_labeled_key_and_renews_when_certificate_is_expired() {
        let fixture = LifecycleFixture::new();
        let mut labeled_key = fixture.signing_key.clone();
        labeled_key.label = Some("device-label".to_owned());
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(labeled_key.clone());
        let mut expired_certificate = certificate_record(TzapSignDeviceRouting::Personal);
        expired_certificate.not_after_unix_seconds = 149;
        inventory.enrolled_certificates.push(expired_certificate);
        inventory.emergency_blocklist = TzapEmergencyBlocklistState::default();
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();

        let session_id = fixture.sign_session.login_session_id.clone();
        let certificate_response = renewal_certificate_response(&fixture.signing_key);
        let transport = FakeLifecycleTransport::with_handler(move |request| {
            if request.url.ends_with(ENROLLMENT_CHALLENGES_PATH) {
                let body = request.body.as_ref().and_then(Value::as_object).expect("challenge request body");
                let csr_der = URL_SAFE_NO_PAD.decode(body["csr_der"].as_str().expect("CSR encoding")).expect("CSR bytes");
                let payload = json!({
                    "canonicalization": ENROLLMENT_CHALLENGE_CANONICALIZATION,
                    "audience": SESSION_AUDIENCE_SIGN_TZAP,
                    "operation": RENEW_OPERATION,
                    "challenge_id": "renew-challenge-1",
                    "certificate_id": "cert_old",
                    "renewal_of_certificate_sha256": body["renewal_of_certificate_sha256"],
                    "org_id": body["org_id"],
                    "session_id": session_id,
                    "csr_sha256": csr_fingerprint(&csr_der),
                    "device_public_key_fingerprint": body["device_public_key_fingerprint"],
                    "requested_validity_seconds": body["requested_validity_seconds"],
                    "expires_at_unix_seconds": 200,
                });
                Ok(TzapAuthHttpResponse {
                    status_code: 200,
                    body: json!({"challenge_id": "renew-challenge-1", "challenge_payload": payload}).to_string().into_bytes(),
                    headers: Vec::new(),
                })
            } else {
                Ok(certificate_response.clone())
            }
        });
        let enrollment_client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 150);
        let lifecycle_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);
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
        let enrollment_client = TzapEnrollmentClient::new("https://sign.tzap.org", &transport).with_clock(|| 150);
        let lifecycle_client = TzapCertificateLifecycleClient::new("https://sign.tzap.org", "https://login.tzap.org", &transport).with_clock(|| 150);

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
                hosted_binding: None,
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
            user_id: None,
            provenance: None,
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
                    "audience": SESSION_AUDIENCE_SIGN_TZAP,
                    "operation": RENEW_OPERATION,
                    "challenge_id": "renew-challenge-1",
                    "certificate_id": "cert_old",
                    "renewal_of_certificate_sha256": target,
                    "org_id": Value::Null,
                    "session_id": fixture.sign_session.login_session_id,
                    "csr_sha256": crate::device_identity::csr_fingerprint(&fixture.csr_der),
                    "device_public_key_fingerprint": fixture.signing_key.public_key_fingerprint,
                    "requested_validity_seconds": 90 * 24 * 60 * 60,
                    "expires_at_unix_seconds": 200,
                }
            })
            .to_string()
            .into_bytes(),
            headers: Vec::new(),
        }
    }

    fn renewal_certificate_response(key: &TzapDeviceSigningKeyRecord) -> TzapAuthHttpResponse {
        let mut certificate = crate::local_tzap_service::test_enrollment_certificate_json(key, "cert_new", 150);
        certificate["sign_device_id"] = json!("sign-device-old");
        TzapAuthHttpResponse { status_code: 200, body: json!({"certificate": certificate}).to_string().into_bytes(), headers: Vec::new() }
    }

    fn store_with_wire_predecessor(fixture: &LifecycleFixture, certificate: &Value) -> (InMemoryTzapLocalIdentityStore, TzapRenewalRequest) {
        let mut payload = super::parse_enrollment_response(&json!({"certificate": certificate}).to_string().into_bytes()).unwrap();
        let metadata = payload.validate_for_key(&AcceptingLifecycleValidator, &fixture.signing_key, 150).unwrap();
        let enrollment_request = TzapEnrollmentRequest {
            account_key: DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
            org_id: None,
            requested_validity_seconds: 90 * 24 * 60 * 60,
            now_unix_seconds: 150,
        };
        let mut record = payload.into_store_record(&enrollment_request, &fixture.signing_key.key_id, metadata).unwrap();
        record.state = TzapLocalCertificateState::Active;
        let mut inventory = TzapLocalIdentityInventory::empty();
        inventory.device_signing_keys.push(fixture.signing_key.clone());
        inventory.enrolled_certificates.push(record);
        let mut store = InMemoryTzapLocalIdentityStore::new();
        store.save_inventory(DEFAULT_IDENTITY_INVENTORY_ACCOUNT, inventory).unwrap();
        let mut renewal_request = LifecycleFixture::renewal_request(TzapRenewalPolicy::SameKeyRequired);
        renewal_request.previous_certificate_sha256 = certificate["certificate_sha256"].as_str().unwrap().to_owned();
        (store, renewal_request)
    }

    fn reconciled_certificate_json(key: &TzapDeviceSigningKeyRecord) -> Value {
        let mut certificate = crate::local_tzap_service::test_enrollment_certificate_json(key, "cert_reconciled", 150);
        certificate["sign_device_id"] = json!("sign-device-old");
        certificate["predecessor_certificate_id"] = json!("cert_old");
        certificate["predecessor_certificate_sha256"] = json!(trust::format_certificate_sha256(&[0x03; 32]));
        certificate["status"] = json!("active");
        certificate
    }

    fn renewal_reconciliation_list(replacement: &Value) -> Value {
        let metadata = public_metadata();
        let previous = json!({
            "certificate_id": "cert_old",
            "certificate_sha256": trust::format_certificate_sha256(&[0x03; 32]),
            "issuer_certificate_sha256": trust::format_certificate_sha256(&[0x04; 32]),
            "issuer_key_identifier": "AQIDBA",
            "sign_device_id": "sign-device-old",
            "public_signer_id": metadata.public_signer_id,
            "public_org_id": Value::Null,
            "public_device_id": metadata.public_device_id,
            "status": "revoked",
            "revocation_category": "supersession",
        });
        let replacement = json!({
            "certificate_id": replacement["certificate_id"],
            "certificate_sha256": replacement["certificate_sha256"],
            "issuer_certificate_sha256": replacement["issuer_certificate_sha256"],
            "issuer_key_identifier": replacement["issuer_key_identifier"],
            "sign_device_id": replacement["sign_device_id"],
            "public_signer_id": metadata.public_signer_id,
            "public_org_id": Value::Null,
            "public_device_id": metadata.public_device_id,
            "status": "valid",
        });
        json!([previous, replacement])
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
        handler: Option<Box<dyn Fn(&TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError>>>,
    }

    impl FakeLifecycleTransport {
        fn new(responses: Vec<TzapAuthHttpResponse>) -> Self {
            Self { responses: RefCell::new(responses.into_iter().rev().collect()), requests: RefCell::new(Vec::new()), handler: None }
        }

        fn with_handler(handler: impl Fn(&TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> + 'static) -> Self {
            Self { responses: RefCell::new(Vec::new()), requests: RefCell::new(Vec::new()), handler: Some(Box::new(handler)) }
        }

        fn requests(&self) -> Vec<TzapAuthHttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl TzapAuthHttpTransport for FakeLifecycleTransport {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.borrow_mut().push(request.clone());
            if let Some(handler) = &self.handler {
                return handler(request);
            }
            self.responses.borrow_mut().pop().ok_or(TzapAuthError::HttpStatus { status_code: 599 })
        }
    }
}
