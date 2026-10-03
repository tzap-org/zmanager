use super::support::parse_tzap_context_args;
use crate::cli::options::GlobalOptions;
use crate::cli::usage::{CERTS_HELP, print_error_line, print_help_stdout, wants_help};
use std::process::ExitCode;
use zmanager_core::identity_catalog::{FileTzapIdentityCatalogStore, TzapIdentityCatalogStore as _};
use zmanager_core::local_identity_store::{FileTzapLocalIdentityStore, TzapLocalIdentityStore as _};

/// Reads the local TZAP certificate catalogue (`zm tzap certs`) — no
/// network, so it stays available in the default offline build and is the
/// way `--signing-identity` resolvers and scripts discover a certificate id.
pub(crate) fn certs_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CERTS_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let context = match parse_tzap_context_args(args, &mut global, "certs") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let certificates = match local_certificates(&context.state_dir, &context.account_key) {
        Ok(certificates) => certificates,
        Err(error) => {
            print_error_line(&global, format_args!("tzap certs failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if global.json {
        println!("{{\"certificates\":{}}}", serde_json::to_string(&certificates).unwrap_or_else(|_| "[]".to_owned()));
    } else if certificates.is_empty() {
        println!("no local certificates");
        println!("Document signing and contact export require an enrolled identity from the Full build or desktop/mobile app.");
        println!("To sign an archive with your own certificate files, see 'zm create --help'.");
    } else {
        for certificate in &certificates {
            println!(
                "{} {} {}",
                certificate["certificate_id"].as_str().unwrap_or_default(),
                certificate["state"].as_str().unwrap_or_default(),
                certificate["certificate_sha256"].as_str().unwrap_or_default()
            );
        }
    }
    ExitCode::SUCCESS
}

// Certificate discovery needs public metadata only. Loading the native inventory
// resolves every private key and can prompt for Keychain access on macOS.
fn local_certificates(state_dir: &std::path::Path, account_key: &str) -> Result<Vec<serde_json::Value>, String> {
    if let Some(catalog) = FileTzapIdentityCatalogStore::new(state_dir).load_catalog(account_key).map_err(|error| error.to_string())? {
        return Ok(catalog
            .signing_identities
            .iter()
            .filter_map(|identity| {
                Some(serde_json::json!({
                    "certificate_id": identity.certificate_id.as_ref()?,
                    "state": identity.lifecycle,
                    "certificate_sha256": identity.certificate_sha256.as_ref()?,
                }))
            })
            .collect());
    }
    // Preserve compatibility with inventories predating the public catalogue.
    // This file-backed migration never accesses the OS keyring.
    let inventory = FileTzapLocalIdentityStore::new(state_dir).load_inventory(account_key).map_err(|error| error.to_string())?;
    Ok(inventory
        .enrolled_certificates
        .iter()
        .map(|certificate| {
            serde_json::json!({
                "certificate_id": certificate.certificate_id,
                "state": certificate.state.as_str(),
                "certificate_sha256": certificate.certificate_sha256,
            })
        })
        .collect())
}
