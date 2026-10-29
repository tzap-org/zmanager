use super::support::{
    parse_environment_option, parse_tzap_context_args, parse_tzap_context_option, print_session_summary_json, print_stable_tzap_error, service_envelope,
    service_request,
};
use super::{AuthEndpointOptions, TzapCliContext};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{AUTH_MENU_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line};
use serde_json::{Value, json};
use std::process::ExitCode;
use zmanager_tzap_hosted::tzap_service::{
    tzap_auth_account_url_json, tzap_auth_callback_json, tzap_auth_forget_json, tzap_auth_login_json, tzap_auth_status_json,
};

pub(crate) fn auth_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if args.is_empty() {
        print_help_stdout(AUTH_MENU_HELP, &global);
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "--help" | "-h" => {
            print_help_stdout(AUTH_MENU_HELP, &global);
            ExitCode::SUCCESS
        }
        "login" => auth_login_command(&args[1..], global),
        "callback" => auth_callback_command(&args[1..], global),
        "status" => auth_status_command(&args[1..], global),
        "forget" => auth_forget_command(&args[1..], global),
        "account" => auth_account_command(&args[1..], global),
        "me" => super::me_command(&args[1..], global),
        "cert" => super::cert_command(&args[1..], global),
        "device" => super::device_command(&args[1..], global),
        command => command_usage_error("auth", &format!("unknown auth command: {command}"), &global),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn auth_login_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut endpoints = AuthEndpointOptions::default();
    let mut print_url = false;
    let mut restart = false;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "auth", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--restart" => {
                restart = true;
                index += 1;
            }
            "--print-url" => {
                print_url = true;
                index += 1;
            }
            "--environment" => {
                if let Err(code) = parse_environment_option(args, &mut index, &mut endpoints.environment, &global) {
                    return code;
                }
            }
            "--auth-base-url" => {
                endpoints.auth_base_url = Some(match take_value(args, &mut index, "--auth-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--account-base-url" => {
                endpoints.account_base_url = Some(match take_value(args, &mut index, "--account-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--signing-base-url" => {
                endpoints.signing_base_url = Some(match take_value(args, &mut index, "--signing-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                endpoints.client_id = match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--provider" => {
                endpoints.provider_id = match take_value(args, &mut index, "--provider") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--org-id" => {
                endpoints.org_id = Some(match take_value(args, &mut index, "--org-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }

    let request = service_request(
        &context,
        json!({
            "environment": match endpoints.environment {
                zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Local => "local",
                zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Staging => "staging",
                zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Prod => "prod",
            },
            "restart": restart,
            "client_id": endpoints.client_id,
            "redirect_uri": endpoints.redirect_uri,
            "provider_id": endpoints.provider_id,
            "auth_base_url": endpoints.auth_base_url,
            "account_base_url": endpoints.account_base_url,
            "signing_base_url": endpoints.signing_base_url,
            "org_id": endpoints.org_id,
        }),
    );
    let response = match service_envelope(&tzap_auth_login_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth login failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let url = response["launch_url"].as_str().unwrap_or_default().to_owned();
    let state = response["state"].as_str().unwrap_or_default().to_owned();
    let expires_at_unix_seconds = response["expires_at_unix_seconds"].as_u64().unwrap_or(0);
    if global.json {
        println!(
            "{{\"status\":\"pending\",\"launch_url\":\"{}\",\"state\":\"{}\",\"expires_at_unix_seconds\":{}}}",
            json_escape(&url),
            json_escape(&state),
            expires_at_unix_seconds
        );
    } else if print_url {
        println!("{url}");
    } else {
        match open_browser(&url) {
            Ok(()) => println!("opened the login page in your browser (use --print-url to print the URL instead)"),
            Err(error) => {
                // Never strand the user: fall back to printing the URL.
                println!("{url}");
                eprintln!("note: could not open a browser ({error})");
            }
        }
    }
    ExitCode::SUCCESS
}

/// Hands a URL to the platform's default browser.
pub(super) fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        browser_launcher_result(std::process::Command::new("open").arg(url).status()?)
    }
    #[cfg(target_os = "windows")]
    {
        super::windows_browser::open(url)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        browser_launcher_result(std::process::Command::new("xdg-open").arg(url).status()?)
    }
}

#[cfg(not(target_os = "windows"))]
fn browser_launcher_result(status: std::process::ExitStatus) -> std::io::Result<()> {
    if status.success() { Ok(()) } else { Err(std::io::Error::other("browser launcher returned an unsuccessful exit status")) }
}

#[allow(clippy::too_many_lines)]
pub(super) fn auth_callback_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut state = None;
    let mut redirect_uri = None;
    let mut callback_url = None;
    let mut handoff_code = None;
    let mut auth_base_url = None;
    let mut client_id = None;
    let mut stdin_input = false;
    let mut seen_inputs = std::collections::HashSet::new();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "auth", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        let option = args[index].as_str();
        if matches!(option, "--state" | "--handoff-code" | "--callback-url" | "--stdin") && !seen_inputs.insert(option) {
            return command_usage_error("auth", "callback input options must not be repeated", &global);
        }
        match option {
            "--stdin" => {
                stdin_input = true;
                index += 1;
            }
            "--state" => {
                state = Some(match take_value(args, &mut index, "--state") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--redirect-uri" => {
                redirect_uri = Some(match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--auth-base-url" => {
                auth_base_url = Some(match take_value(args, &mut index, "--auth-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                client_id = Some(match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--callback-url" => {
                callback_url = Some(match take_value(args, &mut index, "--callback-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--handoff-code" => {
                handoff_code = Some(match take_value(args, &mut index, "--handoff-code") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }
    if (stdin_input && (callback_url.is_some() || state.is_some() || handoff_code.is_some()))
        || (callback_url.is_some() && (state.is_some() || handoff_code.is_some()))
    {
        return command_usage_error("auth", "use one callback input: --stdin, --callback-url, or --state with --handoff-code", &global);
    }
    if stdin_input {
        callback_url = Some(match read_callback_stdin() {
            Ok(url) => url,
            Err(error) => {
                print_error_line(&global, format_args!("auth callback failed: {error}"));
                return ExitCode::FAILURE;
            }
        });
    } else if callback_url.is_none() && (state.is_none() || handoff_code.is_none()) {
        return command_usage_error("auth", "use --stdin, --callback-url, or --state with --handoff-code", &global);
    }
    let request = service_request(
        &context,
        json!({
            "state": state,
            "redirect_uri": redirect_uri,
            "callback_url": callback_url,
            "handoff_code": handoff_code,
            "auth_base_url": auth_base_url,
            "client_id": client_id,
        }),
    );
    let response = match service_envelope(&tzap_auth_callback_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_stable_tzap_error("auth_callback", &message, &global);
            return ExitCode::FAILURE;
        }
    };
    if response.get("cleanup_warning").and_then(Value::as_str).is_some() {
        eprintln!("note: authentication was saved, but pending sign-in cleanup needs a retry; use --restart when starting another login");
    }
    if let Some(session) = response.get("session") {
        print_session_summary_json(session, &global);
        ExitCode::SUCCESS
    } else {
        print_stable_tzap_error("auth_callback", "service response is missing the session", &global);
        ExitCode::FAILURE
    }
}

fn read_callback_stdin() -> Result<String, String> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        let value = rpassword::prompt_password("Paste callback: ").map_err(|_| "could not read callback from terminal".to_owned())?;
        if value.len() > zmanager_tzap_hosted::browser_callback::MAX_CALLBACK_URL_BYTES {
            return Err("callback input is too long".to_owned());
        }
        Ok(value)
    } else {
        read_callback_line(std::io::stdin().lock())
    }
}

fn read_callback_line(reader: impl std::io::Read) -> Result<String, String> {
    use std::io::BufRead as _;
    let limit = zmanager_tzap_hosted::browser_callback::MAX_CALLBACK_URL_BYTES;
    let mut bytes = Vec::new();
    std::io::BufReader::new(reader.take((limit + 3) as u64)).read_until(b'\n', &mut bytes).map_err(|_| "could not read callback input".to_owned())?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() || bytes.len() > limit {
        return Err("callback input is empty or too long".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "callback input must be UTF-8".to_owned())
}

#[cfg(test)]
mod callback_input_tests {
    use super::*;

    #[test]
    fn callback_pipe_input_is_bounded_and_does_not_echo_input_in_errors() {
        let limit = zmanager_tzap_hosted::browser_callback::MAX_CALLBACK_URL_BYTES;
        assert_eq!(read_callback_line(&b"fixture-callback\r\nignored-second-line"[..]).unwrap(), "fixture-callback");
        assert_eq!(read_callback_line(&b"fixture-callback"[..]).unwrap(), "fixture-callback");
        assert!(read_callback_line(&b""[..]).is_err());
        assert!(read_callback_line(&[0xff][..]).is_err());
        let error = read_callback_line(&vec![b'x'; limit + 100][..]).unwrap_err();
        assert_eq!(error, "callback input is empty or too long");
    }

    #[test]
    fn mixed_or_duplicate_inputs_fail_before_secure_store_access() {
        for args in [
            vec!["--stdin", "--callback-url", "fixture"],
            vec!["--callback-url", "fixture", "--state", "fixture"],
            vec!["--callback-url", "fixture", "--handoff-code", "fixture"],
            vec!["--state", "fixture", "--state", "fixture"],
            vec!["--stdin", "--stdin"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(auth_callback_command(&args, GlobalOptions::default()), ExitCode::from(2));
        }
    }
}

pub(super) fn auth_status_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    let response = match service_envelope(&tzap_auth_status_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth status failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    if let Some(session) = response.get("session") {
        print_session_summary_json(session, &global);
        ExitCode::SUCCESS
    } else {
        if global.json {
            println!("{{\"authenticated\":false}}");
        } else {
            println!("not signed in");
        }
        ExitCode::SUCCESS
    }
}

pub(super) fn auth_forget_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    let response = match service_envelope(&tzap_auth_forget_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_stable_tzap_error("auth_forget", &message, &global);
            return ExitCode::FAILURE;
        }
    };
    if response.get("forgotten").and_then(Value::as_bool).unwrap_or(false) {
        if global.json {
            println!("{{\"forgotten\":true}}");
        } else {
            print_success_line(&global, format_args!("local auth material forgotten"));
        }
    } else if global.json {
        println!("{{\"forgotten\":false}}");
    } else {
        println!("no local auth material to forget");
    }
    ExitCode::SUCCESS
}

pub(super) fn auth_account_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut endpoints = AuthEndpointOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match args[index].as_str() {
            "--environment" => {
                if let Err(code) = parse_environment_option(args, &mut index, &mut endpoints.environment, &global) {
                    return code;
                }
            }
            "--account-base-url" => {
                endpoints.account_base_url = Some(match take_value(args, &mut index, "--account-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                endpoints.client_id = match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }
    let request = json!({
        "environment": match endpoints.environment {
            zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Local => "local",
            zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Staging => "staging",
            zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Prod => "prod",
        },
        "client_id": endpoints.client_id,
        "redirect_uri": endpoints.redirect_uri,
        "account_base_url": endpoints.account_base_url,
        "org_id": endpoints.org_id,
    });
    let response = match service_envelope(&tzap_auth_account_url_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth account failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let url = response["account_url"].as_str().unwrap_or_default();
    if global.json {
        println!("{{\"account_url\":\"{}\"}}", json_escape(url));
    } else {
        println!("{url}");
    }
    ExitCode::SUCCESS
}
