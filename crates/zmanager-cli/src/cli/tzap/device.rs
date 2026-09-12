use super::support::{
    CliHttpJsonTransport, parse_tzap_context_args, parse_tzap_context_option, print_stable_tzap_error, retirement_completion_label, service_envelope,
    service_request,
};
use super::{MISSING_TZAP_SESSION, REVOCATION_REQUIRES_HOSTED_CONSOLE, TzapCliContext};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{DEVICE_HELP, command_usage_error, print_help_stdout, print_success_line, wants_help};
use serde_json::json;
use std::process::ExitCode;
use zmanager_tzap_hosted::auth_client::TzapSessionStore as _;
use zmanager_tzap_hosted::tzap_service::tzap_device_retire_json;

pub(crate) fn device_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(DEVICE_HELP, &global);
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "retire" => device_retire_command(&args[1..], global),
        "revoke" => device_revoke_command(&args[1..], global),
        command => command_usage_error("device", &format!("unknown device command: {command}"), &global),
    }
}

pub(super) fn device_retire_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    // Retirement revokes every active personal device server-side, so it is gated by the same
    // MFA step-up as an explicit revoke. See REVOCATION_REQUIRES_HOSTED_CONSOLE.
    if !cfg!(feature = "hosted-revocation") {
        print_stable_tzap_error("device_retire", REVOCATION_REQUIRES_HOSTED_CONSOLE, &global);
        return ExitCode::FAILURE;
    }
    let context = match parse_tzap_context_args(args, &mut global, "device") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    match service_envelope(&tzap_device_retire_json(&request.to_string())) {
        Ok(response) => {
            if global.json {
                println!("{response}");
            } else {
                print_success_line(&global, format_args!("device_retire complete"));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error("device_retire", &message, &global);
            ExitCode::FAILURE
        }
    }
}

pub(super) fn device_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if !cfg!(feature = "hosted-revocation") {
        print_stable_tzap_error("device_revoke", REVOCATION_REQUIRES_HOSTED_CONSOLE, &global);
        return ExitCode::FAILURE;
    }
    let mut context = TzapCliContext::default();
    let mut sign_device_id = None;
    let mut service_base_url = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("device", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "device", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--device-id" => {
                sign_device_id = Some(match take_value(args, &mut index, "--device-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("device", &error, &global),
                });
            }
            "--service-base-url" => {
                service_base_url = Some(match take_value(args, &mut index, "--service-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("device", &error, &global),
                });
            }
            other => {
                return command_usage_error("device", &format!("unknown device option: {other}"), &global);
            }
        }
    }
    let Some(sign_device_id) = sign_device_id else {
        return command_usage_error("device", "missing --device-id", &global);
    };
    let sign_base_url = service_base_url.unwrap_or_else(|| zmanager_tzap_hosted::auth_client::SIGN_TZAP_BASE_URL.to_owned());
    let session_store = zmanager_tzap_hosted::tzap_service_auth::TzapFfiSessionStore::new(&context.state_dir);
    let Some(session) = session_store.load_session(&context.account_key) else {
        print_stable_tzap_error("device_revoke", MISSING_TZAP_SESSION, &global);
        return ExitCode::FAILURE;
    };
    let transport = CliHttpJsonTransport;
    let lifecycle = zmanager_tzap_hosted::certificate_lifecycle::TzapCertificateLifecycleClient::new(
        &sign_base_url,
        zmanager_tzap_hosted::auth_client::LOGIN_TZAP_BASE_URL,
        &transport,
    );
    match lifecycle.revoke_personal_device(&session, &sign_device_id) {
        Ok(completion) => {
            if global.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "operation": "device_revoke",
                        "completion": retirement_completion_label(completion),
                    })
                );
            } else {
                print_success_line(&global, format_args!("device_revoke complete"));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("device_revoke", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}
