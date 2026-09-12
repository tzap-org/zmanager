use crate::cli::app::{GenericEntry, ListRequest, PlanRequest, TestRequest, expand_short_options};
use crate::cli::format::{FORMAT_TZAP, TZAP_SINGLE_VOLUME_LOSS_TOLERANCE, TZAP_SPLIT_VOLUME_LOSS_TOLERANCE, is_apple_archive, is_tzap_archive};
use crate::cli::options::{
    GlobalOptions, parse_archive_format, parse_global_option, read_optional_password_stdin, resolve_input_path, take_value, validate_recipient_key_open_option,
};
use crate::cli::planning::{append_files_from, append_stdin_paths, apply_manifest_filters, plan_sources};
use crate::cli::usage::{
    LIST_HELP, PLAN_HELP, TEST_HELP, command_usage_error, hex_lower, json_escape, print_entries_json, print_entries_tree, print_error_line, print_help_stdout,
    print_manifest, print_success_line, print_warning_stderr, retry_password_required, usage_failure, wants_help,
};
use crate::output::{self, StyleRole};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::safety::archive_pattern_matches;
pub(crate) fn list_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(LIST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    list_command_from_expanded(&expanded, global)
}

pub(crate) fn list_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(LIST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = ListRequest::default();
    match parse_list_request(args, &mut global, &mut request) {
        Ok(()) => run_list_request(&request, &global),
        Err(error) => command_usage_error("list", &error, &global),
    }
}

pub(crate) fn parse_list_request(args: &[String], global: &mut GlobalOptions, request: &mut ListRequest) -> Result<(), String> {
    let mut index = 0usize;
    let mut positional = Vec::new();
    while index < args.len() {
        let arg = &args[index];
        if parse_global_option(args, &mut index, global)? {
            continue;
        }
        match arg.as_str() {
            "-t" | "--list" => index += 1,
            "-f" | "--file" => request.archive = take_value(args, &mut index, arg)?,
            "-l" | "--long" => {
                request.long = true;
                index += 1;
            }
            "--name-only" => {
                request.name_only = true;
                index += 1;
            }
            "--tree" => {
                request.tree = true;
                index += 1;
            }
            "-i" | "--include" => {
                request.include.push(take_value(args, &mut index, arg)?);
            }
            "--exclude" => {
                request.exclude.push(take_value(args, &mut index, arg)?);
            }
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            "--recipient-key" => {
                request.recipient_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--" => {
                positional.extend(args[index + 1..].iter().cloned());
                break;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown list option: {arg}")),
            _ => {
                positional.push(arg.clone());
                index += 1;
            }
        }
    }
    if request.archive.is_empty()
        && let Some(archive) = positional.first()
    {
        request.archive.clone_from(archive);
    }
    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_list_request(request: &ListRequest, global: &GlobalOptions) -> ExitCode {
    if let Some(code) = validate_recipient_key_open_option("list", &request.archive, request.password_stdin, request.recipient_key.as_ref(), global) {
        return code;
    }
    if request.password_stdin && zmanager_core::engine::is_raw_stream_path(&request.archive) {
        print_error_line(global, format_args!("list failed: raw streams are not encrypted; remove --password-stdin"));
        return ExitCode::from(2);
    }
    if is_apple_archive(&request.archive) && request.password_stdin {
        print_error_line(global, format_args!("list failed: AAR archives are not encrypted; remove --password-stdin"));
        return ExitCode::from(2);
    }
    let password = match read_optional_password_stdin(request.password_stdin, global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    match list_entries_with_password(&request.archive, password.as_deref(), request.recipient_key.as_deref()) {
        Ok(mut entries) => {
            filter_entries(&mut entries, &request.include, &request.exclude);
            if !global.quiet {
                for entry in &entries {
                    for diagnostic in &entry.metadata_diagnostics {
                        print_warning_stderr(global, format_args!("metadata {}: {diagnostic}", entry.name));
                    }
                }
            }
            if global.json {
                print_entries_json(&entries);
            } else if request.tree {
                print_entries_tree(&entries, global);
            } else if request.name_only {
                for entry in entries {
                    println!("{}", entry.name);
                }
            } else if request.long {
                output::stdout_line(
                    global.color,
                    format_args!("{}", output::styled(StyleRole::Heading, format_args!("TYPE\tMODE\tSIZE\tCOMPRESSED\tMODIFIED\tPATH"))),
                );
                for entry in entries {
                    output::stdout_line(
                        global.color,
                        format_args!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            output::styled(StyleRole::Label, format_args!("{}", entry.kind)),
                            entry.mode.map_or_else(|| "-".to_owned(), |mode| format!("{mode:04o}")),
                            entry.size,
                            entry.compressed_size.map_or_else(|| "-".to_owned(), |size| size.to_string()),
                            entry.modified.as_deref().unwrap_or("-"),
                            output::styled(StyleRole::Path, format_args!("{}", entry.name))
                        ),
                    );
                }
            } else {
                for entry in entries {
                    output::stdout_line(
                        global.color,
                        format_args!(
                            "{}\t{}\t{} bytes",
                            output::styled(StyleRole::Label, format_args!("{}", entry.kind)),
                            output::styled(StyleRole::Path, format_args!("{}", entry.name)),
                            entry.size
                        ),
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("list failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
pub(crate) fn test_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(TEST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    test_command_from_expanded(&expanded, global)
}

pub(crate) fn test_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(TEST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = TestRequest::default();
    match parse_test_request(args, &mut global, &mut request) {
        Ok(()) => run_test_request(&request, &global),
        Err(error) => command_usage_error("test", &error, &global),
    }
}

pub(crate) fn parse_test_request(args: &[String], global: &mut GlobalOptions, request: &mut TestRequest) -> Result<(), String> {
    let mut index = 0usize;
    let mut positional = Vec::new();
    while index < args.len() {
        let arg = &args[index];
        if parse_global_option(args, &mut index, global)? {
            continue;
        }
        match arg.as_str() {
            "-T" | "--test" => index += 1,
            "-f" | "--file" => request.archive = take_value(args, &mut index, arg)?,
            "-i" | "--include" => request.include.push(take_value(args, &mut index, arg)?),
            "--exclude" => request.exclude.push(take_value(args, &mut index, arg)?),
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            "--recipient-key" => {
                request.recipient_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--public-no-key" => {
                request.public_no_key = true;
                index += 1;
            }
            "--trusted-ca-cert" => {
                request.trusted_ca_certs.push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--trusted-system-roots" => {
                request.trusted_system_roots = true;
                index += 1;
            }
            "--" => {
                positional.extend(args[index + 1..].iter().cloned());
                break;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown test option: {arg}")),
            _ => {
                positional.push(arg.clone());
                index += 1;
            }
        }
    }
    if request.archive.is_empty()
        && let Some(archive) = positional.first()
    {
        request.archive.clone_from(archive);
    }
    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_test_request(request: &TestRequest, global: &GlobalOptions) -> ExitCode {
    if request.public_no_key && !is_tzap_archive(&request.archive) {
        return usage_failure(global, format_args!("test failed: --public-no-key is supported only for TZAP archives"));
    }
    if let Some(code) = validate_recipient_key_open_option("test", &request.archive, request.password_stdin, request.recipient_key.as_ref(), global) {
        return code;
    }
    if test_request_has_x509_trust(request) && !is_tzap_archive(&request.archive) {
        return usage_failure(global, format_args!("test failed: X.509 trust options are supported only for TZAP archives"));
    }
    if request.public_no_key && request.password_stdin {
        return usage_failure(global, format_args!("test failed: --public-no-key cannot be combined with --password-stdin"));
    }
    if request.public_no_key && request.recipient_key.is_some() {
        return usage_failure(global, format_args!("test failed: --public-no-key cannot be combined with --recipient-key"));
    }
    if request.public_no_key && (!request.include.is_empty() || !request.exclude.is_empty()) {
        return usage_failure(global, format_args!("test failed: --public-no-key cannot be combined with path filters"));
    }
    if request.public_no_key {
        return run_tzap_public_no_key_test(&request.archive, request, global);
    }
    if request.password_stdin && zmanager_core::engine::is_raw_stream_path(&request.archive) {
        print_error_line(global, format_args!("test failed: raw streams are not encrypted; remove --password-stdin"));
        return ExitCode::from(2);
    }
    if is_apple_archive(&request.archive) && request.password_stdin {
        print_error_line(global, format_args!("test failed: AAR archives are not encrypted; remove --password-stdin"));
        return ExitCode::from(2);
    }
    let password = match read_optional_password_stdin(request.password_stdin, global) {
        Ok(password) => password,
        Err(code) => return code,
    };

    match run_engine_test(request, password.as_ref().map(zmanager_core::secrets::SecretString::expose_secret)) {
        Ok((format, report)) => {
            print_data_test_success(&format, report.tested_entries, report.skipped_entries, report.tested_bytes, global);
            for warning in report.warnings {
                print_warning_stderr(global, format_args!("test warning: {warning}"));
            }
            ExitCode::SUCCESS
        }
        Err(error) if error.kind == zmanager_core::engine::ErrorKind::PasswordRequired && password.is_none() => retry_password_required(
            global,
            "test failed: ",
            Some("Archive password: "),
            |message| print_error_line(global, format_args!("{message}")),
            |password| match run_engine_test(request, Some(password.expose_secret())) {
                Ok((format, report)) => {
                    print_data_test_success(&format, report.tested_entries, report.skipped_entries, report.tested_bytes, global);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    print_error_line(global, format_args!("test failed: {error}"));
                    ExitCode::FAILURE
                }
            },
        ),
        Err(error) if error.kind == zmanager_core::engine::ErrorKind::UnsupportedOperation => {
            print_warning_stderr(global, format_args!("test unavailable: {}", error.message));
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_engine_test(request: &TestRequest, password: Option<&str>) -> Result<(String, zmanager_core::engine::TestReport), zmanager_core::engine::ArchiveError> {
    let engine = zmanager_core::engine::create_default_engine()?;
    let mut handle = engine.open(
        zmanager_core::engine::ArchiveSource::from_path_autodetect(&request.archive),
        zmanager_core::engine::OpenOptions { password: password.map(str::to_owned), recipient_key: request.recipient_key.clone(), ..Default::default() },
    )?;
    let selected_paths = if request.include.is_empty() && request.exclude.is_empty() {
        Vec::new()
    } else {
        handle.list()?.entries.into_iter().filter(|entry| entry_selected(&entry.path, &request.include, &request.exclude)).map(|entry| entry.path).collect()
    };
    let report = handle.test(&zmanager_core::engine::TestOptions {
        selected_paths,
        recipient_key: request.recipient_key.clone(),
        recipient_key_bytes: None,
        tzap_x509_trust: is_tzap_archive(&request.archive).then(|| test_request_x509_trust(request)),
        cancellation: None,
    })?;
    let format =
        if handle.detected().format == zmanager_core::engine::FormatId::SPLIT_ZIP { "zip".to_owned() } else { handle.detected().format.as_str().to_owned() };
    handle.close()?;
    Ok((format, report))
}

fn test_request_has_x509_trust(request: &TestRequest) -> bool {
    !request.trusted_ca_certs.is_empty() || request.trusted_system_roots
}

pub(crate) fn tzap_default_volume_loss_tolerance(volume_size: Option<u64>) -> u8 {
    if volume_size.is_some() { TZAP_SPLIT_VOLUME_LOSS_TOLERANCE } else { TZAP_SINGLE_VOLUME_LOSS_TOLERANCE }
}

fn test_request_x509_trust(request: &TestRequest) -> zmanager_core::engine::TzapX509TrustOptions {
    zmanager_core::engine::TzapX509TrustOptions {
        trusted_ca_certificates: request.trusted_ca_certs.clone(),
        trusted_system_roots: request.trusted_system_roots,
        include_official_tzap_root: !test_request_has_x509_trust(request),
    }
}

fn run_tzap_public_no_key_test(archive: &str, request: &TestRequest, global: &GlobalOptions) -> ExitCode {
    let trust = test_request_x509_trust(request);
    match zmanager_core::engine::verify_tzap_x509_public_no_key(archive, &trust) {
        Ok(report) => {
            print_tzap_public_no_key_success(&report, archive, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("tzap test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn print_data_test_success(format: &str, tested_entries: u64, skipped_entries: u64, bytes: u64, global: &GlobalOptions) {
    if global.json {
        println!(
            "{{\"status\":\"ok\",\"format\":\"{}\",\"entries\":{},\"tested_entries\":{},\"skipped_entries\":{},\"bytes\":{bytes}}}",
            json_escape(format),
            tested_entries,
            tested_entries,
            skipped_entries
        );
    } else if skipped_entries == 0 {
        print_success_line(global, format_args!("{format} test ok: {tested_entries} entries, {bytes} bytes"));
    } else {
        print_success_line(global, format_args!("{format} test ok: {tested_entries} entries, {skipped_entries} skipped, {bytes} bytes"));
    }
}

fn print_tzap_public_no_key_success(root_auth: &zmanager_core::engine::TzapX509VerificationReport, archive: &str, global: &GlobalOptions) {
    if global.json {
        print!(
            "{{\"status\":\"ok\",\"format\":\"{}\",\"verification_mode\":\"public-no-key\",\"archive\":\"{}\",\"root_auth\":",
            FORMAT_TZAP,
            json_escape(archive)
        );
        print_tzap_x509_root_auth_json(root_auth);
        print!(",\"public_diagnostics\":");
        print!("{}", crate::cli::usage::json_string_array(&root_auth.diagnostics));
        println!("}}");
    } else {
        print_success_line(global, format_args!("{FORMAT_TZAP} test ok: public no-key, {} data blocks", root_auth.total_data_block_count));
        print_tzap_x509_root_auth_text(root_auth, true, global);
        print_tzap_x509_diagnostics_text(root_auth, "public-no-key", global);
    }
}

fn print_tzap_x509_root_auth_json(root_auth: &zmanager_core::engine::TzapX509VerificationReport) {
    let status = root_auth.diagnostics.first().map_or("root_auth_content_verified", String::as_str);
    print!("{{\"status\":\"{}\",\"diagnostics\":", json_escape(status));
    print!("{}", crate::cli::usage::json_string_array(&root_auth.diagnostics));
    print!(
        ",\"authenticator\":\"x509\",\"archive_root\":\"{}\",\"authenticator_id\":{},\"signer_identity_type\":{},\"total_data_block_count\":{},\"subject\":\"{}\",\"issuer\":\"{}\",\"serial_number\":\"{}\",\"certificate_sha256\":\"{}\",\"signed_at_unix_seconds\":{},\"verified_chain_subjects\":[",
        hex_lower(&root_auth.archive_root),
        root_auth.authenticator_id,
        root_auth.signer_identity_type,
        root_auth.total_data_block_count,
        json_escape(&root_auth.subject),
        json_escape(&root_auth.issuer),
        json_escape(&root_auth.serial_number_hex),
        hex_lower(&root_auth.certificate_sha256),
        root_auth.signed_at_unix_seconds
    );
    for (index, subject) in root_auth.verified_chain_subjects.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!("\"{}\"", json_escape(subject));
    }
    print!("],\"trust_anchor_subject\":");
    match root_auth.trust_anchor_subject.as_deref() {
        Some(subject) => print!("\"{}\"", json_escape(subject)),
        None => print!("null"),
    }
    print!("}}");
}

fn print_tzap_x509_root_auth_text(root_auth: &zmanager_core::engine::TzapX509VerificationReport, public_no_key: bool, global: &GlobalOptions) {
    let mode = if public_no_key { "public-no-key x509" } else { "x509" };
    print_success_line(global, format_args!("root-auth: OK {mode} {}", hex_lower(&root_auth.archive_root)));
    print_success_line(global, format_args!("root-auth signer: {}", root_auth.subject));
    print_success_line(global, format_args!("root-auth issuer: {}", root_auth.issuer));
    if let Some(trust_anchor) = &root_auth.trust_anchor_subject {
        print_success_line(global, format_args!("root-auth trust-anchor: {trust_anchor}"));
    }
    print_tzap_x509_diagnostics_text(root_auth, "root-auth", global);
}

fn print_tzap_x509_diagnostics_text(root_auth: &zmanager_core::engine::TzapX509VerificationReport, prefix: &str, global: &GlobalOptions) {
    for diagnostic in &root_auth.diagnostics {
        print_success_line(global, format_args!("{prefix}: {diagnostic}"));
    }
}

pub(crate) fn plan_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(PLAN_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    let mut global = global;
    let mut request = PlanRequest::default();
    match parse_plan_request(&expanded, &mut global, &mut request) {
        Ok(()) => run_plan_request(&request, &global),
        Err(error) => command_usage_error("plan", &error, &global),
    }
}

fn parse_plan_request(args: &[String], global: &mut GlobalOptions, request: &mut PlanRequest) -> Result<(), String> {
    let mut index = 0usize;
    let mut current_dir: Option<PathBuf> = None;
    while index < args.len() {
        let arg = &args[index];
        if parse_global_option(args, &mut index, global)? {
            continue;
        }
        match arg.as_str() {
            "--format" => {
                request.format = Some(parse_archive_format(&take_value(args, &mut index, arg)?)?);
            }
            "-C" | "--directory" => {
                current_dir = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "-@" => {
                request.stdin_paths = true;
                index += 1;
            }
            "--files-from" => request.files_from.push(take_value(args, &mut index, arg)?),
            "--null" => {
                request.null_paths = true;
                index += 1;
            }
            "--clean" => {
                request.clean = true;
                index += 1;
            }
            "--no-ignore" => {
                request.no_ignore = true;
                index += 1;
            }
            "-i" | "--include" => request.include.push(take_value(args, &mut index, arg)?),
            "--exclude" => request.exclude.push(take_value(args, &mut index, arg)?),
            "--exclude-from" => request.exclude_from.push(PathBuf::from(take_value(args, &mut index, arg)?)),
            "--" => {
                for value in &args[index + 1..] {
                    request.sources.push(resolve_input_path(value, current_dir.as_deref()));
                }
                break;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown plan option: {arg}")),
            _ => {
                request.sources.push(resolve_input_path(arg, current_dir.as_deref()));
                index += 1;
            }
        }
    }
    append_files_from(&mut request.sources, &request.files_from, request.null_paths)?;
    if request.stdin_paths {
        append_stdin_paths(&mut request.sources, request.null_paths)?;
    }
    if request.sources.is_empty() {
        return Err("missing source path".to_owned());
    }
    Ok(())
}

fn run_plan_request(request: &PlanRequest, global: &GlobalOptions) -> ExitCode {
    match plan_sources(&request.sources, request.clean, request.no_ignore, false) {
        Ok(mut manifest) => {
            if let Err(error) = apply_manifest_filters(&mut manifest, &request.include, &request.exclude, &request.exclude_from, false) {
                print_error_line(global, format_args!("plan failed: {error}"));
                return ExitCode::FAILURE;
            }
            print_manifest(&manifest, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("plan failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
fn list_entries_with_password(archive: &str, password: Option<&str>, recipient_key: Option<&Path>) -> Result<Vec<GenericEntry>, String> {
    let options = zmanager_core::archive_browser::BrowserListOptions { password, recipient_key, recipient_key_bytes: None, temp_root: None };
    let listing = zmanager_core::archive_browser::list_entries_with_options(archive, options).map_err(|error| error.to_string())?;

    let generic_entries = listing
        .entries
        .into_iter()
        .map(|entry| GenericEntry {
            kind: match entry.kind {
                zmanager_core::archive_browser::BrowserEntryKind::File => "file",
                zmanager_core::archive_browser::BrowserEntryKind::Directory => "directory",
                zmanager_core::archive_browser::BrowserEntryKind::Symlink => "symlink",
                zmanager_core::archive_browser::BrowserEntryKind::Hardlink => "hardlink",
                zmanager_core::archive_browser::BrowserEntryKind::FileCopy => "filecopy",
                zmanager_core::archive_browser::BrowserEntryKind::Special => "special",
            }
            .to_owned(),
            name: entry.path,
            size: entry.size.unwrap_or(0),
            compressed_size: entry.compressed_size,
            mode: entry.mode,
            modified: entry.modified,
            created: entry.created,
            accessed: entry.accessed,
            encrypted: entry.encrypted,
            method: entry.method,
            solid: entry.solid,
            link_target: entry.link_target,
            attributes: entry.attributes,
            uid: entry.uid,
            gid: entry.gid,
            owner: entry.owner,
            group: entry.group,
            metadata_diagnostics: entry.metadata_diagnostics,
        })
        .collect();

    Ok(generic_entries)
}

fn filter_entries(entries: &mut Vec<GenericEntry>, includes: &[String], excludes: &[String]) {
    entries.retain(|entry| entry_selected(&entry.name, includes, excludes));
}

pub(crate) fn entry_selected(path: &str, includes: &[String], excludes: &[String]) -> bool {
    let matches_include = includes.is_empty() || includes.iter().any(|pattern| archive_pattern_matches(pattern, path));
    let matches_exclude = excludes.iter().any(|pattern| archive_pattern_matches(pattern, path));

    matches_include && !matches_exclude
}
