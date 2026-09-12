#![cfg_attr(not(feature = "tzap-online"), allow(dead_code))]

//! TZAP command surface (CR-113, medium option), split by what needs the
//! network and what does not.
//!
//! [`sign`], [`contacts`], [`share`] and [`certs`] are always built: they
//! read the local identity catalogue and need no hosted transport. [`auth`],
//! [`cert`], [`device`] and the hosted-cert operations in [`hosted`] need a
//! session or a live service and are gated behind `tzap-online`. [`support`]
//! holds the helpers shared by both. [`tzap_command`] dispatches the always
//! built group (`zm tzap …`); [`auth_command`] dispatches the online-only
//! group (`zm auth …`).

#[cfg(feature = "tzap-online")]
#[allow(clippy::module_inception)]
mod auth;
#[cfg(feature = "tzap-online")]
mod cert;
mod certs;
mod contacts;
#[cfg(feature = "tzap-online")]
mod device;
#[cfg(feature = "tzap-online")]
mod hosted;
mod share;
mod sign;
mod support;
#[cfg(test)]
mod tests;

#[cfg(feature = "tzap-online")]
pub(crate) use auth::auth_command as hosted_auth_command;
#[cfg(feature = "tzap-online")]
pub(crate) use cert::cert_command;
#[cfg(feature = "tzap-online")]
pub(crate) use cert::me_command;
pub(crate) use certs::certs_command;
pub(crate) use contacts::contact_command;
#[cfg(test)]
pub(crate) use contacts::contact_keygen_command;
#[cfg(feature = "tzap-online")]
pub(crate) use device::device_command;
pub(crate) use share::share_command;
pub(crate) use sign::{sign_command, verify_command};
pub(crate) use zmanager_tzap_hosted::keyring_store::NativeTzapLocalIdentityStore;
#[cfg(all(test, feature = "tzap-online"))]
pub(crate) use {hosted::create_and_store_staging_enrollment_key, support::build_hosted_http_request};

use std::path::PathBuf;

#[cfg(feature = "tzap-online")]
pub(super) const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
#[cfg(feature = "tzap-online")]
pub(crate) const DEFAULT_TZAP_REDIRECT_URI: &str = "tzap://auth/callback";
#[cfg(feature = "tzap-online")]
pub(super) const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
#[cfg(feature = "tzap-online")]
pub(super) const AUTH_PENDING_FILE: &str = "auth-pending.json";
#[cfg(feature = "tzap-online")]
pub(super) const AUTH_SESSION_EXCHANGE_PATH: &str = "/auth/session/exchange";
pub(super) const MISSING_TZAP_SESSION: &str = "no local TZAP session";
/// The sign server requires a recent admin MFA step-up on the *calling session* before it will
/// revoke a personal certificate or device, so that a stolen session alone cannot destroy a
/// user's signing identities. The CLI has no way to satisfy that: there is no TOTP prompt here,
/// and a step-up performed elsewhere is bound to a different session. Rather than emit an opaque
/// 403, the revoke and retire commands say where the operation now lives.
pub(super) const REVOCATION_REQUIRES_HOSTED_CONSOLE: &str =
    "revocation requires an MFA step-up that the CLI cannot perform; revoke this device or certificate in the hosted console at https://staging.tzap.org/app";
pub(super) const DEFAULT_TZAP_CERT_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
pub(super) const STAGING_ENROLLMENT_KEY_LABEL: &str = "Hosted TZAP enrollment signing key";

#[derive(Debug, Clone)]
pub(super) struct TzapCliContext {
    pub(super) state_dir: PathBuf,
    pub(super) account_key: String,
}

impl Default for TzapCliContext {
    fn default() -> Self {
        Self { state_dir: default_offline_tzap_state_dir(), account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned() }
    }
}

/// Resolves the TZAP state directory for offline CLI commands.
///
/// This must agree with the FFI and hosted layers exactly: they read the same
/// keys and certificates out of it, so a second copy of the resolution order
/// would silently split CLI state from hosted state the moment either changed.
/// `zmanager-tzap-hosted` is a non-optional dependency and
/// `tzap_service_auth` carries no feature gate, so the shared definition is
/// available to the offline build as well.
pub(crate) fn default_offline_tzap_state_dir() -> PathBuf {
    zmanager_tzap_hosted::tzap_service_auth::default_tzap_state_dir()
}

#[cfg(feature = "tzap-online")]
#[derive(Debug, Clone)]
pub(super) struct AuthEndpointOptions {
    pub(super) environment: zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment,
    pub(super) auth_base_url: Option<String>,
    pub(super) account_base_url: Option<String>,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) provider_id: String,
    pub(super) org_id: Option<String>,
}

#[cfg(feature = "tzap-online")]
impl Default for AuthEndpointOptions {
    fn default() -> Self {
        Self {
            environment: zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Prod,
            auth_base_url: None,
            account_base_url: None,
            client_id: DEFAULT_TZAP_CLIENT_ID.to_owned(),
            redirect_uri: DEFAULT_TZAP_REDIRECT_URI.to_owned(),
            provider_id: DEFAULT_TZAP_PROVIDER_ID.to_owned(),
            org_id: None,
        }
    }
}

#[cfg(feature = "tzap-online")]
pub(crate) fn auth_command(args: &[String], global: crate::cli::options::GlobalOptions) -> std::process::ExitCode {
    hosted_auth_command(args, global)
}

/// Dispatches the always-built, offline-capable TZAP surface (`zm tzap …`).
/// Signing, verification, contacts, sharing, and reading the local
/// certificate catalogue need no network — see the CLI command-structure
/// plan's command tree.
pub(crate) fn tzap_command(args: &[String], global: crate::cli::options::GlobalOptions) -> std::process::ExitCode {
    use crate::cli::usage::{TZAP_MENU_HELP, command_usage_error, print_help_stdout, wants_help};
    if wants_help(args) || args.is_empty() {
        print_help_stdout(TZAP_MENU_HELP, &global);
        return if args.is_empty() { std::process::ExitCode::from(2) } else { std::process::ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "sign" => sign_command(&args[1..], global),
        "verify" => verify_command(&args[1..], global),
        "contact" => contact_command(&args[1..], global),
        "share" => share_command(&args[1..], global),
        "certs" => certs_command(&args[1..], global),
        command => command_usage_error("tzap", &format!("unknown tzap command: {command}"), &global),
    }
}
