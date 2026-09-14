use crate::cli::app::{
    ArchiveFormat, CreateOutcome, CreateRequest, ProgressReporter, TestRequest, create_progress_kind, create_test_archive_path, expand_short_options,
    publish_archive, temp_archive_path,
};
use crate::cli::format::FORMAT_APPLE_ARCHIVE;
use crate::cli::format::{
    FORMAT_SEVEN_Z, FORMAT_TAR_ZST, FORMAT_TGZ, FORMAT_TZAP, FORMAT_ZIP, TZAP_DEFAULT_RECOVERY_PERCENTAGE, ZIP_CREATE_EXTENSIONS, path_has_known_extension,
};
use crate::cli::open::{run_test_request, tzap_default_volume_loss_tolerance};
use crate::cli::options::{
    GlobalOptions, infer_create_format, parse_archive_format, parse_global_option, parse_i32, parse_volume_size, resolve_input_path, take_value,
};
use crate::cli::planning::{append_files_from, append_stdin_paths, apply_junk_paths, apply_manifest_filters, manifest_has_symlinks, plan_sources};
use crate::cli::usage::{
    CREATE_HELP, command_usage_error, normalize_prompted_password, print_create_summary, print_error_line, print_help_stdout, print_manifest,
    print_optional_error_line, prompt_password, wants_help,
};
use crate::output::{self, StyleRole};
use std::fs;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent};
use zmanager_core::secrets::SecretString;
pub(crate) fn create_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CREATE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    create_command_from_expanded(&expanded, global)
}

pub(crate) fn create_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CREATE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = CreateRequest::default();
    match parse_create_request(args, &mut global, &mut request) {
        Ok(()) => run_create_request(&request, &global),
        Err(error) => command_usage_error("create", &error, &global),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_create_request(args: &[String], global: &mut GlobalOptions, request: &mut CreateRequest) -> Result<(), String> {
    let mut index = 0usize;
    let mut current_dir: Option<PathBuf> = None;
    let mut positional_after_double_dash = false;

    while index < args.len() {
        let arg = &args[index];
        if positional_after_double_dash {
            push_create_positional(request, arg, current_dir.as_deref());
            index += 1;
            continue;
        }
        if arg == "--" {
            positional_after_double_dash = true;
            index += 1;
            continue;
        }
        if parse_global_option(args, &mut index, global)? {
            continue;
        }

        match arg.as_str() {
            "-c" | "--create" | "-r" | "--recursive" | "--hidden" | "--preserve-metadata" => {
                index += 1;
            }
            "-X" | "--no-metadata" => {
                request.no_metadata = true;
                index += 1;
            }
            "-y" | "--preserve-symlinks" => {
                request.preserve_symlinks = true;
                index += 1;
            }
            "-f" | "--file" => {
                request.archive = take_value(args, &mut index, arg)?;
            }
            "--format" => {
                request.format = Some(parse_archive_format(&take_value(args, &mut index, arg)?)?);
            }
            "--method" => {
                request.method = Some(take_value(args, &mut index, arg)?);
            }
            "--level" => {
                request.level = Some(parse_i32(&take_value(args, &mut index, arg)?, arg)?);
            }
            "-0" => {
                request.compression = zmanager_core::engine::ZipCompression::Store;
                request.level = Some(0);
                index += 1;
            }
            "-1" | "-2" | "-3" | "-4" | "-5" | "-6" | "-7" | "-8" | "-9" => {
                request.level = Some(parse_i32(&arg[1..], arg)?);
                request.compression = zmanager_core::engine::ZipCompression::Deflate;
                index += 1;
            }
            "-C" | "--directory" => {
                current_dir = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "-@" => {
                request.stdin_paths = true;
                index += 1;
            }
            "--files-from" => {
                request.files_from.push(take_value(args, &mut index, arg)?);
            }
            "--null" => {
                request.null_paths = true;
                index += 1;
            }
            "-i" | "--include" => {
                request.include.push(take_value(args, &mut index, arg)?);
            }
            "--exclude" => {
                request.exclude.push(take_value(args, &mut index, arg)?);
            }
            "--exclude-from" => {
                request.exclude_from.push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--store" => {
                request.compression = zmanager_core::engine::ZipCompression::Store;
                index += 1;
            }
            "--solid" => {
                request.solid = true;
                index += 1;
            }
            "--no-solid" => {
                request.solid = false;
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
            "--no-hidden" => {
                request.no_hidden = true;
                index += 1;
            }
            "-j" | "--junk-paths" => {
                request.junk_paths = true;
                index += 1;
            }
            "--follow-symlinks" => {
                request.follow_symlinks = true;
                index += 1;
            }
            "--force" => {
                request.force = true;
                index += 1;
            }
            "--encrypt" => {
                request.encrypt = true;
                index += 1;
            }
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            "--volume-size" => {
                request.volume_size = Some(parse_volume_size(&take_value(args, &mut index, arg)?, arg)?);
            }
            "--recipient-cert" => {
                request.tzap_recipient_cert = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-cert" => {
                request.tzap_signing_cert = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-private-key" => {
                request.tzap_signing_private_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-chain" => {
                request.tzap_signing_chain.push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-identity" => {
                let certificate_id = match args.get(index + 1) {
                    Some(next) if !next.starts_with('-') => {
                        index += 1;
                        Some(args[index].clone())
                    }
                    _ => None,
                };
                request.tzap_signing_identity = Some(certificate_id);
                index += 1;
            }
            "--sidecar" => {
                request.tzap_sidecar = true;
                index += 1;
            }
            "--no-sidecar" => {
                request.tzap_sidecar = false;
                index += 1;
            }
            "--dry-run" => {
                request.dry_run = true;
                index += 1;
            }
            "-T" | "--test-after" | "--test" => {
                request.test_after = true;
                index += 1;
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(format!("unknown create option: {arg}"));
            }
            _ => {
                push_create_positional(request, arg, current_dir.as_deref());
                index += 1;
            }
        }
    }

    append_files_from(&mut request.sources, &request.files_from, request.null_paths)?;
    if request.stdin_paths {
        append_stdin_paths(&mut request.sources, request.null_paths)?;
    }

    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    if request.sources.is_empty() {
        return Err("missing source path".to_owned());
    }

    Ok(())
}
/// Resolves `--signing-identity [certificate-id]` against the local TZAP
/// identity catalogue. With no id, the local signing key's newest usable
/// certificate is used (Z8: `resolve_default_signing_certificate_id`, the
/// same resolution rule mobile's default-identity selection uses — active,
/// time-valid, not locally blocklisted, and free of a cached non-valid
/// status); with more than one local signing key, the caller must
/// disambiguate explicitly.
fn resolve_tzap_signing_identity(certificate_id: Option<&str>) -> Result<zmanager_core::engine::TzapX509SigningOptions, String> {
    use zmanager_core::engine::tzap::resolve_default_signing_certificate_id;
    use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;

    let state_dir = crate::cli::tzap::default_offline_tzap_state_dir();
    let account_key = zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT;
    let store = crate::cli::tzap::NativeTzapLocalIdentityStore::new(&state_dir, account_key).map_err(|error| error.to_string())?;
    let now_unix_seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_secs());

    let certificate_id = if let Some(certificate_id) = certificate_id {
        certificate_id.to_owned()
    } else {
        let inventory = store.load_inventory(account_key).map_err(|error| error.to_string())?;
        let mut signing_key_ids: Vec<&str> = inventory.enrolled_certificates.iter().map(|certificate| certificate.signing_key_id.as_str()).collect();
        signing_key_ids.sort_unstable();
        signing_key_ids.dedup();
        let signing_key_id = match signing_key_ids.as_slice() {
            [] => return Err("no local certificate found for --signing-identity; enroll one with `zm auth cert enroll` or the desktop/mobile app".to_owned()),
            [signing_key_id] => *signing_key_id,
            _ => return Err("more than one local signing key; disambiguate with --signing-identity <certificate-id> (see `zm tzap certs`)".to_owned()),
        };
        resolve_default_signing_certificate_id(&inventory, signing_key_id, now_unix_seconds)?
    };
    zmanager_core::engine::tzap::tzap_x509_signing_options_from_inventory(&store, account_key, &certificate_id, now_unix_seconds).map(Into::into)
}

fn push_create_positional(request: &mut CreateRequest, value: &str, current_dir: Option<&Path>) {
    if request.archive.is_empty() {
        value.clone_into(&mut request.archive);
    } else {
        request.sources.push(resolve_input_path(value, current_dir));
    }
}

#[allow(clippy::too_many_lines)]
fn run_create_request(request: &CreateRequest, global: &GlobalOptions) -> ExitCode {
    let Some(format) = request.format.or_else(|| infer_create_format(&request.archive)) else {
        print_error_line(global, format_args!("could not infer archive format; pass --format <zip|tar.zst|tzap|aar|7z|tgz>"));
        return ExitCode::from(2);
    };

    if let Err(error) = validate_create_options(format, request) {
        print_error_line(global, format_args!("{error}"));
        return ExitCode::from(2);
    }

    let password = match create_password(format, request, global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    let follow_symlinks = follow_symlinks_for_create(format, request);
    if request.follow_symlinks && request.preserve_symlinks {
        print_error_line(global, format_args!("create failed: --follow-symlinks conflicts with --preserve-symlinks"));
        return ExitCode::from(2);
    }

    let manifest = match plan_sources(&request.sources, request.clean, request.no_ignore, follow_symlinks) {
        Ok(mut manifest) => {
            if let Err(error) = apply_manifest_filters(&mut manifest, &request.include, &request.exclude, &request.exclude_from, request.no_hidden) {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if request.junk_paths
                && let Err(error) = apply_junk_paths(&mut manifest)
            {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if format == ArchiveFormat::SevenZ && request.preserve_symlinks && manifest_has_symlinks(&manifest) {
                print_error_line(global, format_args!("create failed: 7z symlink preservation is not supported by the current backend; use --follow-symlinks"));
                return ExitCode::from(2);
            }
            manifest
        }
        Err(error) => {
            print_error_line(global, format_args!("create failed: {error}"));
            return ExitCode::FAILURE;
        }
    };

    if request.dry_run {
        print_manifest(&manifest, global);
        return ExitCode::SUCCESS;
    }

    if request.archive == "-" {
        return create_stream(format, &manifest, request, password, global);
    }

    let destination = PathBuf::from(&request.archive);
    if destination.exists() && !request.force {
        print_error_line(global, format_args!("create failed: destination exists: {}; pass --force to replace it", destination.display()));
        return ExitCode::FAILURE;
    }

    let split_output = request.volume_size.is_some();
    let temp = temp_archive_path(&destination);
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = fs::create_dir_all(parent)
    {
        print_error_line(global, format_args!("create failed: failed to create {}: {error}", parent.display()));
        return ExitCode::FAILURE;
    }

    let mut progress = ProgressReporter::from_global(Some(global));
    progress.emit(JobEvent::Started { kind: create_progress_kind(format), total_bytes: Some(manifest.total_bytes) });
    let token = CancellationToken::new();
    let create_destination = if split_output { destination.as_path() } else { temp.as_path() };
    let backend_replace_existing = split_output && request.force;
    let options = match build_engine_create_options(format, request, password, backend_replace_existing, global) {
        Ok(options) => options,
        Err(code) => return code,
    };
    let outcome_result = run_engine_create_backend(&manifest, create_destination, options, &temp, split_output, &mut progress, &token, global);
    let outcome = match outcome_result {
        Ok(outcome) => outcome,
        Err(code) => return code,
    };

    if !split_output {
        let temp_sidecar = zmanager_core::engine::tzap::tzap_bootstrap_sidecar_path(&temp);
        if let Err(error) = publish_archive(&temp, &destination, request.force) {
            let _ = fs::remove_file(&temp);
            let _ = fs::remove_file(&temp_sidecar);
            progress.emit(JobEvent::Failed { message: error.to_string() });
            print_error_line(global, format_args!("create failed: failed to move {} to {}: {error}", temp.display(), destination.display()));
            return ExitCode::FAILURE;
        }
        if temp_sidecar.exists() {
            let dest_sidecar = zmanager_core::engine::tzap::tzap_bootstrap_sidecar_path(&destination);
            if let Err(error) = publish_archive(&temp_sidecar, &dest_sidecar, request.force) {
                let _ = fs::remove_file(&temp_sidecar);
                progress.emit(JobEvent::Failed { message: error.to_string() });
                print_error_line(global, format_args!("create failed: failed to move {} to {}: {error}", temp_sidecar.display(), dest_sidecar.display()));
                return ExitCode::FAILURE;
            }
        }
    }
    progress.emit(JobEvent::Completed { entries: outcome.entries, bytes: outcome.bytes });
    print_create_summary(&destination, &outcome, global);
    if request.test_after {
        let archive = create_test_archive_path(&destination, format, split_output).to_string_lossy().into_owned();
        return run_test_request(&TestRequest { archive, ..TestRequest::default() }, global);
    }
    // The archive exists and is valid, but does not contain everything that was
    // asked for. 7-Zip exits 1 here and GNU tar exits 2; a script that only looks
    // at the exit code would otherwise believe the backup was complete.
    if outcome.warnings > 0 {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn build_engine_create_options(
    format: ArchiveFormat,
    request: &CreateRequest,
    password: Option<SecretString>,
    replace_existing: bool,
    global: &GlobalOptions,
) -> Result<zmanager_core::engine::CreateOptions, ExitCode> {
    let options = match format {
        ArchiveFormat::Zip => {
            let (compression, level) = zip_compression_options(request).map_err(|error| {
                print_error_line(global, format_args!("{error}"));
                ExitCode::from(2)
            })?;
            zmanager_core::engine::CreateOptions::Zip(zmanager_core::engine::ZipCreateOptions {
                compression,
                level,
                preserve_metadata: !request.no_metadata,
                replace_existing,
                password,
                volume_size: request.volume_size,
            })
        }
        ArchiveFormat::TarZst => zmanager_core::engine::CreateOptions::TarZstd(zmanager_core::engine::TarZstdCreateOptions {
            level: request.level.unwrap_or_else(|| zmanager_core::engine::TarZstdCreateOptions::default().level),
            preserve_metadata: !request.no_metadata,
            replace_existing,
            ..zmanager_core::engine::TarZstdCreateOptions::default()
        }),
        ArchiveFormat::Tgz => zmanager_core::engine::CreateOptions::TarGz(zmanager_core::engine::TarGzCreateOptions {
            level: request.level.unwrap_or_else(|| zmanager_core::engine::TarGzCreateOptions::default().level),
            preserve_metadata: !request.no_metadata,
            replace_existing,
        }),
        ArchiveFormat::Tzap => {
            let key_source = if let Some(recipient_certificate) = &request.tzap_recipient_cert {
                zmanager_core::engine::TzapKeySource::RecipientCertificate(recipient_certificate.clone())
            } else {
                password.map_or(zmanager_core::engine::TzapKeySource::NoPassword, zmanager_core::engine::TzapKeySource::Passphrase)
            };
            let x509_signing = match (&request.tzap_signing_cert, &request.tzap_signing_identity) {
                (Some(certificate), _) => {
                    let Some(private_key) = &request.tzap_signing_private_key else {
                        print_error_line(global, format_args!("create failed: --signing-cert and --signing-private-key must be used together"));
                        return Err(ExitCode::from(2));
                    };
                    Some(zmanager_core::engine::TzapX509SigningOptions::CertificateAndKey {
                        signing_certificate: certificate.clone(),
                        signing_private_key: private_key.clone(),
                        signing_chain: request.tzap_signing_chain.clone(),
                    })
                }
                (None, Some(certificate_id)) => match resolve_tzap_signing_identity(certificate_id.as_deref()) {
                    Ok(options) => Some(options),
                    Err(error) => {
                        print_error_line(global, format_args!("create failed: {error}"));
                        return Err(ExitCode::FAILURE);
                    }
                },
                (None, None) => None,
            };
            zmanager_core::engine::CreateOptions::Tzap(zmanager_core::engine::TzapCreateOptions {
                key_source,
                level: request.level.unwrap_or(3),
                preserve_metadata: !request.no_metadata,
                replace_existing,
                volume_size: request.volume_size,
                volume_count: None,
                recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
                volume_loss_tolerance: tzap_default_volume_loss_tolerance(request.volume_size),
                x509_signing,
                emit_bootstrap_sidecar: request.tzap_sidecar,
            })
        }
        ArchiveFormat::AppleArchive => {
            let compression = apple_archive_compression(request).map_err(|error| {
                print_error_line(global, format_args!("{error}"));
                ExitCode::from(2)
            })?;
            zmanager_core::engine::CreateOptions::AppleArchive(zmanager_core::engine::AppleArchiveCreateOptions {
                compression,
                preserve_metadata: !request.no_metadata,
                replace_existing,
                ..zmanager_core::engine::AppleArchiveCreateOptions::default()
            })
        }
        ArchiveFormat::SevenZ => zmanager_core::engine::CreateOptions::SevenZ(zmanager_core::engine::SevenZCreateOptions {
            solid: request.solid,
            level: sevenz_level(request),
            preserve_metadata: !request.no_metadata,
            password,
            encrypt_file_names: true,
            replace_existing,
            volume_size: request.volume_size,
            ..zmanager_core::engine::SevenZCreateOptions::default()
        }),
    };
    Ok(options)
}

#[allow(clippy::too_many_arguments)]
fn run_engine_create_backend(
    manifest: &zmanager_core::manifest::ArchiveManifest,
    destination: &Path,
    options: zmanager_core::engine::CreateOptions,
    temp: &Path,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let request = zmanager_core::engine::CreateRequest::new(manifest.clone(), destination, options);
    let result = {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new_with_progress_total(token, &mut sink, Some(manifest.total_bytes));
        let result = zmanager_core::engine::create_default_engine().and_then(|engine| engine.create(&request, &mut context));
        context.flush_progress();
        result
    };
    let report = match result {
        Ok(report) => report,
        Err(error) => return Err(fail_create(progress, global, temp, split_output, &error.to_string())),
    };
    let format = match report.format {
        zmanager_core::engine::FormatId::ZIP | zmanager_core::engine::FormatId::SPLIT_ZIP => FORMAT_ZIP,
        zmanager_core::engine::FormatId::SEVEN_Z => FORMAT_SEVEN_Z,
        zmanager_core::engine::FormatId::TAR_ZST => FORMAT_TAR_ZST,
        zmanager_core::engine::FormatId::TAR_GZ => FORMAT_TGZ,
        zmanager_core::engine::FormatId::TZAP => FORMAT_TZAP,
        zmanager_core::engine::FormatId::APPLE_ARCHIVE => FORMAT_APPLE_ARCHIVE,
        _ => "unknown",
    };
    Ok(CreateOutcome {
        summary: format!("created {format}: {} entries, {} bytes, {} warnings", report.written_entries, report.written_bytes, report.warnings.len()),
        format,
        backend: format,
        entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX),
        bytes: report.written_bytes,
        warnings: report.warnings.len(),
        warning_texts: report.warnings.clone(),
        encrypted: report.encrypted,
        solid: report.solid,
        volume_size: report.volume_size,
        volume_count: usize::try_from(report.volume_count).unwrap_or(usize::MAX),
    })
}

/// Shared create-failure path: cleans up the temp archive and reports the
/// error (CR-144).
fn fail_create(progress: &mut ProgressReporter, global: &GlobalOptions, temp: &Path, split_output: bool, error: &str) -> ExitCode {
    if !split_output {
        let _ = fs::remove_file(temp);
    }
    progress.emit(JobEvent::Failed { message: error.to_string() });
    print_error_line(global, format_args!("create failed: {error}"));
    ExitCode::FAILURE
}

fn create_stream(
    format: ArchiveFormat,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    request: &CreateRequest,
    password: Option<SecretString>,
    global: &GlobalOptions,
) -> ExitCode {
    if format != ArchiveFormat::Zip {
        print_error_line(global, format_args!("create failed: stdout output is currently supported only for ZIP"));
        return ExitCode::from(2);
    }

    let (compression, level) = match zip_compression_options(request) {
        Ok(options) => options,
        Err(error) => {
            print_error_line(global, format_args!("{error}"));
            return ExitCode::from(2);
        }
    };
    let options = zmanager_core::engine::ZipCreateOptions {
        compression,
        level,
        preserve_metadata: !request.no_metadata,
        replace_existing: false,
        password,
        volume_size: None,
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let token = CancellationToken::new();
    let mut sink = |_event: JobEvent| {};
    let mut context = JobContext::new(&token, &mut sink);
    let request = zmanager_core::engine::CreateRequest::new(manifest.clone(), PathBuf::from("-"), zmanager_core::engine::CreateOptions::Zip(options));
    match zmanager_core::engine::create_default_engine().and_then(|engine| engine.create_to_writer(&request, &mut output, &mut context)) {
        Ok(report) => {
            output::stderr_line(
                global.color,
                format_args!(
                    "{} streaming zip: {} entries, {} bytes, {} warnings",
                    output::styled(StyleRole::Success, format_args!("created")),
                    report.written_entries,
                    report.written_bytes,
                    report.warnings.len(),
                ),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("create failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_create_options(format: ArchiveFormat, request: &CreateRequest) -> Result<(), String> {
    if request.tzap_recipient_cert.is_some() {
        if format != ArchiveFormat::Tzap {
            return Err("recipient certificates are supported only for TZAP archives".to_owned());
        }
        if request.encrypt || request.password_stdin {
            return Err("--recipient-cert cannot be combined with --encrypt or --password-stdin".to_owned());
        }
        if request.tzap_signing_cert.is_some()
            || request.tzap_signing_private_key.is_some()
            || !request.tzap_signing_chain.is_empty()
            || request.tzap_signing_identity.is_some()
        {
            return Err("--recipient-cert cannot be combined with X.509 signing options".to_owned());
        }
        if request.volume_size.is_some() {
            return Err("--recipient-cert is supported only for single-volume TZAP create".to_owned());
        }
    }

    if request.tzap_signing_cert.is_some() || request.tzap_signing_private_key.is_some() || !request.tzap_signing_chain.is_empty() {
        if format != ArchiveFormat::Tzap {
            return Err("certificate signing is supported only for TZAP archives".to_owned());
        }
        if request.tzap_signing_identity.is_some() {
            return Err("--signing-identity cannot be combined with --signing-cert, --signing-private-key, or --signing-chain".to_owned());
        }
        match (request.tzap_signing_cert.as_ref(), request.tzap_signing_private_key.as_ref()) {
            (Some(_), Some(_)) => {}
            (None, None) if !request.tzap_signing_chain.is_empty() => {
                return Err("--signing-chain requires --signing-cert".to_owned());
            }
            _ => {
                return Err("--signing-cert and --signing-private-key must be used together".to_owned());
            }
        }
    }

    if request.tzap_signing_identity.is_some() && format != ArchiveFormat::Tzap {
        return Err("certificate signing is supported only for TZAP archives".to_owned());
    }

    if request.tzap_sidecar {
        if format != ArchiveFormat::Tzap {
            return Err("--sidecar is supported only for TZAP archives".to_owned());
        }
        if request.archive == "-" {
            return Err("--sidecar cannot be used with stdout archive output".to_owned());
        }
    }

    if request.volume_size.is_some() {
        if request.archive == "-" {
            return Err("--volume-size cannot be used with stdout archive output".to_owned());
        }
        match format {
            ArchiveFormat::Zip => {
                if !path_has_known_extension(&request.archive, ZIP_CREATE_EXTENSIONS) {
                    return Err("split ZIP output must use a .zip archive path".to_owned());
                }
            }
            ArchiveFormat::SevenZ | ArchiveFormat::Tzap | ArchiveFormat::AppleArchive => {}
            ArchiveFormat::TarZst | ArchiveFormat::Tgz => {
                return Err("--volume-size is supported only for ZIP, TZAP, and 7z archives".to_owned());
            }
        }
    }

    if let Some(method) = request.method.as_deref() {
        match (format, method) {
            (ArchiveFormat::Zip, "deflate" | "store")
            | (ArchiveFormat::TarZst | ArchiveFormat::Tzap, "zstd" | "zst")
            | (ArchiveFormat::SevenZ, "lzma2")
            | (ArchiveFormat::Tgz, "gzip" | "gz")
            | (ArchiveFormat::AppleArchive, "lzfse" | "lz4" | "zlib" | "lzma" | "raw") => {}
            _ => {
                return Err(format!("unsupported method for selected archive format: {method}"));
            }
        }
    }

    if let Some(level) = request.level {
        match format {
            ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::Tzap | ArchiveFormat::Tgz if !(0..=9).contains(&level) => {
                return Err(format!("unsupported compression level for selected archive format: {level}"));
            }
            ArchiveFormat::Zip if request.compression == zmanager_core::engine::ZipCompression::Store && level != 0 => {
                return Err(format!("cannot combine ZIP store compression with compression level {level}"));
            }
            ArchiveFormat::AppleArchive => {
                return Err("compression levels are not supported for AAR archives".to_owned());
            }
            _ => {}
        }
    }

    Ok(())
}

fn apple_archive_compression(request: &CreateRequest) -> Result<zmanager_core::engine::AppleArchiveCompression, String> {
    use zmanager_core::engine::AppleArchiveCompression;

    match request.method.as_deref() {
        None => Ok(AppleArchiveCompression::default()),
        Some("lzfse") => Ok(AppleArchiveCompression::Lzfse),
        Some("lz4") => Ok(AppleArchiveCompression::Lz4),
        Some("zlib") => Ok(AppleArchiveCompression::Zlib),
        Some("lzma") => Ok(AppleArchiveCompression::Lzma),
        Some("raw") => Ok(AppleArchiveCompression::None),
        Some(method) => Err(format!("unsupported method for selected archive format: {method}")),
    }
}

fn zip_compression_options(request: &CreateRequest) -> Result<(zmanager_core::engine::ZipCompression, Option<i64>), String> {
    let mut compression = request.compression;
    if let Some(method) = request.method.as_deref() {
        compression = match method {
            "store" => zmanager_core::engine::ZipCompression::Store,
            "deflate" => zmanager_core::engine::ZipCompression::Deflate,
            _ => compression,
        };
    }

    let Some(level) = request.level else {
        return Ok((compression, None));
    };
    if !(0..=9).contains(&level) {
        return Err(format!("unsupported compression level for selected archive format: {level}"));
    }
    if compression == zmanager_core::engine::ZipCompression::Store {
        if level == 0 {
            return Ok((compression, None));
        }
        return Err(format!("cannot combine ZIP store compression with compression level {level}"));
    }
    if level == 0 {
        return Ok((zmanager_core::engine::ZipCompression::Store, None));
    }

    Ok((compression, Some(i64::from(level))))
}

fn sevenz_level(request: &CreateRequest) -> Option<u32> {
    request.level.and_then(|level| u32::try_from(level).ok())
}

fn follow_symlinks_for_create(format: ArchiveFormat, request: &CreateRequest) -> bool {
    request.follow_symlinks || (!request.preserve_symlinks && matches!(format, ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::Tzap))
}

fn create_password(format: ArchiveFormat, request: &CreateRequest, global: &GlobalOptions) -> Result<Option<SecretString>, ExitCode> {
    if !request.encrypt && !request.password_stdin {
        return Ok(None);
    }
    if matches!(format, ArchiveFormat::TarZst | ArchiveFormat::Tgz) {
        print_error_line(global, format_args!("encryption is not supported for this archive format"));
        return Err(ExitCode::from(2));
    }
    if request.password_stdin {
        return prompt_password_from_stdin(Some(global)).map(Some);
    }
    if global.no_password_prompt {
        print_error_line(global, format_args!("password prompt disabled; use --password-stdin"));
        return Err(ExitCode::from(2));
    }
    if global.quiet || !io::stdin().is_terminal() {
        print_error_line(global, format_args!("password prompt requires an interactive terminal; use --password-stdin"));
        return Err(ExitCode::from(2));
    }
    let prompt = match format {
        ArchiveFormat::SevenZ => "7z password: ",
        ArchiveFormat::Tzap => "tzap password: ",
        ArchiveFormat::TarZst | ArchiveFormat::Tgz | ArchiveFormat::AppleArchive => "archive password: ",
        ArchiveFormat::Zip => "ZIP password: ",
    };
    prompt_password(prompt).map(Some)
}

pub(crate) fn prompt_password_from_stdin(global: Option<&GlobalOptions>) -> Result<SecretString, ExitCode> {
    let mut password = String::new();
    match io::stdin().read_line(&mut password) {
        Ok(bytes_read) => {
            if let Some(password) = normalize_prompted_password(password, bytes_read) {
                Ok(SecretString::from(password))
            } else {
                print_optional_error_line(global, format_args!("password prompt cancelled"));
                Err(ExitCode::FAILURE)
            }
        }
        Err(error) => {
            print_optional_error_line(global, format_args!("failed to read password: {error}"));
            Err(ExitCode::FAILURE)
        }
    }
}
