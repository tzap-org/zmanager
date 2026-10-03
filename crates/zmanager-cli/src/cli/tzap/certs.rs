use super::NativeTzapLocalIdentityStore;
use super::support::parse_tzap_context_args;
use crate::cli::options::GlobalOptions;
use crate::cli::usage::{CERTS_HELP, print_error_line, print_help_stdout, wants_help};
use std::process::ExitCode;
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;

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
    let store = match NativeTzapLocalIdentityStore::new(&context.state_dir, &context.account_key) {
        Ok(store) => store,
        Err(error) => {
            print_error_line(&global, format_args!("tzap certs failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let inventory = match store.load_inventory(&context.account_key) {
        Ok(inventory) => inventory,
        Err(error) => {
            print_error_line(&global, format_args!("tzap certs failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if global.json {
        let certificates = inventory
            .enrolled_certificates
            .iter()
            .map(|certificate| {
                serde_json::json!({
                    "certificate_id": certificate.certificate_id,
                    "state": certificate.state.as_str(),
                    "certificate_sha256": certificate.certificate_sha256,
                })
            })
            .collect::<Vec<_>>();
        println!("{{\"certificates\":{}}}", serde_json::to_string(&certificates).unwrap_or_else(|_| "[]".to_owned()));
    } else if inventory.enrolled_certificates.is_empty() {
        println!("no local certificates");
        println!("Document signing and contact export require an enrolled identity from the Full build or desktop/mobile app.");
        println!("To sign an archive with your own certificate files, see 'zm create --help'.");
    } else {
        for certificate in &inventory.enrolled_certificates {
            println!("{} {} {}", certificate.certificate_id, certificate.state.as_str(), certificate.certificate_sha256);
        }
    }
    ExitCode::SUCCESS
}
