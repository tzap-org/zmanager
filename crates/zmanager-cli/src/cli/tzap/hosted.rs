#![cfg_attr(not(feature = "tzap-online"), allow(dead_code, unused_imports))]

use super::NativeTzapLocalIdentityStore;
#[cfg(feature = "tzap-online")]
use super::support::CliHttpJsonTransport;
use super::support::{certificate_summary_value, current_unix_seconds, parse_tzap_context_option, print_stable_tzap_error};
use super::{DEFAULT_TZAP_CERT_VALIDITY_SECONDS, MISSING_TZAP_SESSION, STAGING_ENROLLMENT_KEY_LABEL, TzapCliContext};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{command_usage_error, print_error_line, print_success_line};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_core::local_identity_store::TzapLocalIdentityStore;
#[cfg(feature = "tzap-online")]
use zmanager_tzap_hosted::auth_client::TzapSessionStore as _;

#[derive(Debug)]

pub(super) struct HostedCertOptions {
    pub(super) context: TzapCliContext,
    pub(super) certificate_id: Option<String>,
    pub(super) service_base_url: Option<String>,
    pub(super) trusted_root_cert_paths: Vec<PathBuf>,
    pub(super) org_id: Option<String>,
    pub(super) requested_validity_seconds: u64,
}

pub(super) fn parse_hosted_cert_renew_args(args: &[String], global: &mut GlobalOptions) -> Result<HostedCertOptions, ExitCode> {
    parse_hosted_cert_args(args, global, true)
}

pub(super) fn parse_cert_enroll_args(args: &[String], global: &mut GlobalOptions) -> Result<HostedCertOptions, ExitCode> {
    parse_hosted_cert_args(args, global, false)
}

pub(super) fn parse_hosted_cert_args(args: &[String], global: &mut GlobalOptions, require_certificate_id: bool) -> Result<HostedCertOptions, ExitCode> {
    let mut options = HostedCertOptions {
        context: TzapCliContext::default(),
        certificate_id: None,
        service_base_url: None,
        trusted_root_cert_paths: Vec::new(),
        org_id: None,
        requested_validity_seconds: DEFAULT_TZAP_CERT_VALIDITY_SECONDS,
    };
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error("cert", &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut options.context, "cert", global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        match args[index].as_str() {
            "--certificate-id" if require_certificate_id => {
                options.certificate_id = Some(take_value(args, &mut index, "--certificate-id").map_err(|error| command_usage_error("cert", &error, global))?);
            }
            "--certificate-id" => {
                return Err(command_usage_error("cert", "unknown cert option: --certificate-id", global));
            }
            "--service-base-url" => {
                options.service_base_url =
                    Some(take_value(args, &mut index, "--service-base-url").map_err(|error| command_usage_error("cert", &error, global))?);
            }
            "--trusted-root-cert" => {
                options
                    .trusted_root_cert_paths
                    .push(PathBuf::from(take_value(args, &mut index, "--trusted-root-cert").map_err(|error| command_usage_error("cert", &error, global))?));
            }
            "--org-id" => {
                options.org_id = Some(take_value(args, &mut index, "--org-id").map_err(|error| command_usage_error("cert", &error, global))?);
            }
            "--requested-validity-seconds" => {
                let value = take_value(args, &mut index, "--requested-validity-seconds").map_err(|error| command_usage_error("cert", &error, global))?;
                options.requested_validity_seconds =
                    value.parse::<u64>().map_err(|_| command_usage_error("cert", "--requested-validity-seconds must be an integer", global))?;
            }
            other => {
                return Err(command_usage_error("cert", &format!("unknown cert option: {other}"), global));
            }
        }
    }
    if require_certificate_id && options.certificate_id.as_deref().unwrap_or("").is_empty() {
        return Err(command_usage_error("cert", "missing --certificate-id", global));
    }
    if options.service_base_url.is_none() && !options.trusted_root_cert_paths.is_empty() {
        return Err(command_usage_error("cert", "--trusted-root-cert requires --service-base-url", global));
    }
    if options.service_base_url.is_none() && options.org_id.is_some() {
        return Err(command_usage_error("cert", "--org-id requires --service-base-url", global));
    }
    Ok(options)
}

#[derive(Debug)]
pub(super) enum HostedCertOperationError {
    Operation(String),
    Message(String),
}

#[cfg(feature = "tzap-online")]
#[allow(clippy::too_many_arguments)]
pub(super) fn run_hosted_cert_operation<F>(
    operation: &'static str,
    hosted_kind_label: &'static str,
    error_prefix: &'static str,
    options: &HostedCertOptions,
    global: &GlobalOptions,
    run: F,
) -> ExitCode
where
    F: FnOnce(
        &str,
        &zmanager_tzap_hosted::auth_client::TzapSessionRecord,
        &mut NativeTzapLocalIdentityStore,
        Vec<String>,
        Vec<Vec<u8>>,
    ) -> Result<zmanager_core::local_identity_store::TzapEnrolledCertificateRecord, HostedCertOperationError>,
{
    let Some(service_base_url) = options.service_base_url.as_deref() else { unreachable!("hosted operation checked by caller") };
    if options.trusted_root_cert_paths.is_empty() {
        return command_usage_error("cert", &format!("hosted {hosted_kind_label} requires at least one --trusted-root-cert"), global);
    }
    let session_store = zmanager_tzap_hosted::tzap_service_auth::TzapFfiSessionStore::new(&options.context.state_dir);
    let Some(session) = session_store.load_session(&options.context.account_key) else {
        print_stable_tzap_error(operation, MISSING_TZAP_SESSION, global);
        return ExitCode::FAILURE;
    };
    let mut trusted_root_sha256 = Vec::new();
    let trusted_root_der = match zmanager_core::trust::load_custom_root_certificate_files(&options.trusted_root_cert_paths, &mut trusted_root_sha256) {
        Ok(roots) => roots,
        Err(error) => {
            print_error_line(global, format_args!("{error_prefix}{error}"));
            return ExitCode::FAILURE;
        }
    };
    let mut identity_store = match NativeTzapLocalIdentityStore::new(&options.context.state_dir, &options.context.account_key) {
        Ok(store) => store,
        Err(error) => {
            print_error_line(global, format_args!("{error_prefix}{error}"));
            return ExitCode::FAILURE;
        }
    };
    match run(service_base_url, &session, &mut identity_store, trusted_root_sha256, trusted_root_der) {
        Ok(certificate) => {
            if global.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "operation": operation,
                        "service_base_url": service_base_url,
                        "certificate": certificate_summary_value(&certificate),
                    })
                );
            } else {
                print_success_line(global, format_args!("{operation} complete"));
            }
            ExitCode::SUCCESS
        }
        Err(HostedCertOperationError::Operation(message)) => {
            print_stable_tzap_error(operation, &message, global);
            ExitCode::FAILURE
        }
        Err(HostedCertOperationError::Message(message)) => {
            print_error_line(global, format_args!("{error_prefix}{message}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "tzap-online")]
pub(super) fn run_hosted_cert_enroll(options: &HostedCertOptions, global: &GlobalOptions) -> ExitCode {
    run_hosted_cert_operation(
        "cert_enroll",
        "enrollment",
        "cert enroll failed: ",
        options,
        global,
        |service_base_url, session, identity_store, trusted_root_sha256, trusted_root_der| {
            let now_unix_seconds = current_unix_seconds();
            let request = zmanager_tzap_hosted::enrollment_client::TzapEnrollmentRequest {
                account_key: options.context.account_key.clone(),
                org_id: options.org_id.clone().or_else(|| session.selected_org_id.clone()),
                requested_validity_seconds: options.requested_validity_seconds,
                now_unix_seconds,
            };
            let (signing_key, csr_der) = match create_and_store_staging_enrollment_key(identity_store, &request, now_unix_seconds) {
                Ok(material) => material,
                Err(error) => return Err(HostedCertOperationError::Message(error)),
            };
            let transport = CliHttpJsonTransport;
            let client = zmanager_tzap_hosted::enrollment_client::TzapEnrollmentClient::local_staging_server(service_base_url, &transport);
            let validator = CliTrustedEnrollmentCertificateValidator {
                trusted_root_sha256,
                trusted_root_der,
                options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
            };
            zmanager_tzap_hosted::enrollment_client::enroll_device_certificate(&client, &validator, identity_store, session, &request, &signing_key, &csr_der)
                .map_err(|error| HostedCertOperationError::Operation(error.to_string()))
        },
    )
}

#[cfg(feature = "tzap-online")]
pub(super) fn run_hosted_cert_renew(options: &HostedCertOptions, global: &GlobalOptions) -> ExitCode {
    let certificate_id = options.certificate_id.as_deref().unwrap_or_default();
    run_hosted_cert_operation(
        "cert_renew",
        "renewal",
        "cert renew failed: ",
        options,
        global,
        |service_base_url, session, identity_store, trusted_root_sha256, trusted_root_der| {
            let inventory = match identity_store.load_inventory(&options.context.account_key) {
                Ok(inventory) => inventory,
                Err(error) => {
                    return Err(HostedCertOperationError::Message(format!("cannot load identity store: {error}")));
                }
            };
            let previous_certificate = if let Some(certificate) = inventory.enrolled_certificates.iter().find(|record| record.certificate_id == certificate_id)
            {
                certificate.clone()
            } else {
                return Err(HostedCertOperationError::Message(format!("certificate {certificate_id} not found locally")));
            };
            let signing_key = if let Some(record) = inventory.device_signing_keys.iter().find(|record| record.key_id == previous_certificate.signing_key_id) {
                record.clone()
            } else {
                return Err(HostedCertOperationError::Message(format!("signing key {} not found", previous_certificate.signing_key_id)));
            };
            let csr_der = match zmanager_core::device_identity::generate_device_csr_from_private_key(
                &signing_key.private_key_der,
                &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
            ) {
                Ok(csr) => csr,
                Err(error) => return Err(HostedCertOperationError::Message(format!("cannot generate CSR: {error}"))),
            };
            let now_unix_seconds = current_unix_seconds();
            let login_base_url = zmanager_tzap_hosted::auth_client::LOGIN_TZAP_BASE_URL;
            let transport = CliHttpJsonTransport;
            let lifecycle =
                zmanager_tzap_hosted::certificate_lifecycle::TzapCertificateLifecycleClient::local_staging_server(service_base_url, login_base_url, &transport);
            let validator = CliTrustedEnrollmentCertificateValidator {
                trusted_root_sha256,
                trusted_root_der,
                options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
            };
            let org_id = options.org_id.clone().or_else(|| session.selected_org_id.clone());
            let renewal_request = zmanager_tzap_hosted::certificate_lifecycle::TzapRenewalRequest {
                account_key: options.context.account_key.clone(),
                previous_certificate_id: previous_certificate.certificate_id,
                previous_certificate_sha256: previous_certificate.certificate_sha256,
                org_id,
                requested_validity_seconds: options.requested_validity_seconds,
                renewal_policy: zmanager_tzap_hosted::certificate_lifecycle::TzapRenewalPolicy::SameKeyRequired,
                now_unix_seconds,
                server_grace_seconds: zmanager_tzap_hosted::certificate_lifecycle::RENEWAL_GRACE_MAX_SECONDS,
            };
            lifecycle
                .renew_certificate(&validator, identity_store, session, &renewal_request, &signing_key, &signing_key, &csr_der)
                .map_err(|error| HostedCertOperationError::Operation(error.to_string()))
        },
    )
}

pub(crate) fn create_and_store_staging_enrollment_key<S: TzapLocalIdentityStore>(
    store: &mut S,
    request: &zmanager_tzap_hosted::enrollment_client::TzapEnrollmentRequest,
    now_unix_seconds: u64,
) -> Result<(zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord, Vec<u8>), String> {
    let mut inventory = store.load_inventory(&request.account_key).map_err(|error| error.to_string())?;
    let label = staging_enrollment_key_label(request.org_id.as_deref());
    if let Some(record) = inventory.device_signing_keys.iter().find(|record| record.label.as_deref() == Some(label.as_str())) {
        if inventory.enrolled_certificates.iter().any(|certificate| certificate.signing_key_id == record.key_id) {
            return Err(format!("an enrollment key already has a certificate for {label}; use `zm auth cert renew --certificate-id <id>`"));
        }
        let csr_der = zmanager_core::device_identity::generate_device_csr_from_private_key(
            &record.private_key_der,
            &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
        )
        .map_err(|error| error.to_string())?;
        return Ok((record.clone(), csr_der));
    }

    let material = zmanager_core::device_identity::generate_device_signing_key_and_csr(&zmanager_core::device_identity::TzapDeviceCsrOptions::default())
        .map_err(|error| error.to_string())?;
    let record = zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord {
        key_id: material.public_key_fingerprint.clone(),
        public_key_fingerprint: material.public_key_fingerprint,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: now_unix_seconds,
        label: Some(label),
    };
    inventory.device_signing_keys.push(record.clone());
    store.save_inventory(&request.account_key, inventory).map_err(|error| error.to_string())?;
    Ok((record, material.csr_der))
}

pub(super) fn staging_enrollment_key_label(org_id: Option<&str>) -> String {
    match org_id {
        Some(org_id) => format!("{STAGING_ENROLLMENT_KEY_LABEL} (org:{org_id})"),
        None => format!("{STAGING_ENROLLMENT_KEY_LABEL} (personal)"),
    }
}

pub(super) struct CliTrustedEnrollmentCertificateValidator {
    trusted_root_sha256: Vec<String>,
    trusted_root_der: Vec<Vec<u8>>,
    options: zmanager_core::trust::TzapCertificateProfileOptions,
}

impl zmanager_tzap_hosted::enrollment_client::TzapEnrollmentCertificateValidator for CliTrustedEnrollmentCertificateValidator {
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<zmanager_core::trust::TzapCertificatePublicMetadata, zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError> {
        self.validate_custom_chain_with_root_pin(chain_der).map(|validation| validation.public_metadata)
    }

    fn validate_and_complete_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, zmanager_core::trust::TzapCertificatePublicMetadata), zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError> {
        let mut last_error = match self.validate_completed_chain(chain_der) {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        for root_der in &self.trusted_root_der {
            let mut completed_chain = chain_der.to_vec();
            completed_chain.push(root_der.clone());
            match self.validate_completed_chain(&completed_chain) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}

impl CliTrustedEnrollmentCertificateValidator {
    fn validate_completed_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, zmanager_core::trust::TzapCertificatePublicMetadata), zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError> {
        self.validate_custom_chain_with_root_pin(chain_der).map(|validation| (chain_der.to_vec(), validation.public_metadata))
    }

    fn validate_custom_chain_with_root_pin(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<zmanager_core::trust::TzapCertificateProfileValidation, zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError> {
        let validation = zmanager_core::trust::validate_custom_tzap_certificate_chain_der(chain_der, &self.options)
            .map_err(|error| zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError::CertificateChain(error.to_string()))?;
        if !self.trusted_root_sha256.iter().any(|trusted| trusted == &validation.root_certificate_sha256) {
            return Err(zmanager_tzap_hosted::enrollment_client::TzapEnrollmentError::CertificateChain(format!(
                "root certificate is not in the temporary trust store: {}",
                validation.root_certificate_sha256
            )));
        }
        Ok(validation)
    }
}
