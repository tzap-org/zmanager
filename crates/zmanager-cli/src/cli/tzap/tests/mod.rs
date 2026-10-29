use crate::cli::options::GlobalOptions;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::auth::auth_command;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::cert::cert_command;
use crate::cli::tzap::certs::certs_command;
use crate::cli::tzap::contacts::contact_command;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::device::device_command;
use crate::cli::tzap::share::share_command;
use crate::cli::tzap::sign::sign_command;
use std::process::ExitCode;

#[test]
fn test_cli_tzap_subcommands_help_and_errors() {
    // Share command
    assert_eq!(share_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(share_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(share_command(&["out.tzap".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Contact command
    assert_eq!(contact_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(contact_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(contact_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(contact_command(&["remove".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Sign command
    assert_eq!(sign_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(sign_command(&[], GlobalOptions::default()), ExitCode::from(2));

    // Certs command (reads the local catalogue, no network)
    assert_eq!(certs_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
}

#[cfg(feature = "tzap-online")]
#[test]
fn test_cli_auth_subcommands_help_and_errors() {
    // Device command
    assert_eq!(device_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(device_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(device_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(device_command(&["revoke".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Auth command
    assert_eq!(auth_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(auth_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(auth_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Cert command
    assert_eq!(cert_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(cert_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(cert_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
}
