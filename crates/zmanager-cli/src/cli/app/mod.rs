use crate::cli::create::{create_command, create_command_from_expanded};
use crate::cli::extract::{extract_command, extract_command_from_expanded};
use crate::cli::format::{
    APPLE_ARCHIVE_EXTENSIONS, CREATE_FORMATS, DEB_EXTENSIONS, EXTRACT_FORMATS, FormatDescriptor, RAR_EXTENSIONS, SEVEN_Z_EXTENSIONS, TAR_ZST_EXTENSIONS,
    TEMP_ARCHIVE_MARKER, TEMP_ARCHIVE_PREFIX, ZIP_FAMILY_EXTENSIONS, strip_suffix_ignore_ascii_case,
};
use crate::cli::open::{list_command, list_command_from_expanded, plan_command, test_command, test_command_from_expanded};
use crate::cli::options::{GlobalOptions, parse_global_option, parse_output_mode};
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::auth_command;
use crate::cli::tzap::tzap_command;
use crate::cli::usage::{
    COMPLETION_BASH_SCRIPT, COMPLETION_FISH_SCRIPT, COMPLETION_POWERSHELL_SCRIPT, COMPLETION_ZSH_SCRIPT, COMPLETIONS_HELP, DOCTOR_HELP, FORMATS_HELP, USAGE,
    command_usage_error, help_command, json_escape, print_help_stderr, print_help_stdout, usage_error, wants_help,
};
use crate::output::{self, OutputMode, StyleRole};
use std::env;
use std::fs;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::archive_format::{ArchiveFormatKind, BackendStatus, FORMAT_CAPABILITIES, format_status};
use zmanager_core::jobs::{JobEvent, JobKind};
use zmanager_core::safety::{OverwriteConflict, OverwriteDecision, OverwriteResolver};

const PROGRESS_PREFIX: &str = "progress";
const PROGRESS_PERCENT_STEP: u64 = 5;
const PROGRESS_BYTE_STEP: u64 = 1024 * 1024;
const OVERWRITE_PROMPT_SUFFIX: &str = " [y]es/[n]o/[a]ll/[r]ename/[q]uit: ";
const OVERWRITE_INVALID_CHOICE: &str = "please answer yes, no, all, rename, or quit";
#[must_use]
pub fn run_from_env() -> ExitCode {
    let mut raw_args = env::args().skip(1).collect::<Vec<_>>();
    let mut global = GlobalOptions::default();
    if let Err(error) = peel_leading_global_options(&mut raw_args, &mut global) {
        return usage_error(&error, &global);
    }

    let Some(command) = raw_args.first().cloned() else {
        print_help_stdout(USAGE, &global);
        return ExitCode::SUCCESS;
    };

    match command.as_str() {
        "--version" | "-V" => {
            if raw_args.len() > 1 {
                print_help_stderr(USAGE, &global);
                return ExitCode::from(2);
            }
            let version = env!("CARGO_PKG_VERSION");
            let rev = option_env!("ZMANAGER_BUILD_REV").unwrap_or("");
            let flavor = if cfg!(feature = "tzap-online") { "full" } else { "offline" };
            if rev.is_empty() {
                println!("zm {version} ({flavor})");
            } else {
                println!("zm {version} ({flavor}, {rev})");
            }
            ExitCode::SUCCESS
        }
        "help" => help_command(&raw_args[1..], &global),
        "doctor" | "healthcheck" => doctor_command(&raw_args[1..], global),
        "completions" | "completion" => completions_command(&raw_args[1..], global),
        "formats" => formats_command(&raw_args[1..], global),
        "tzap" => tzap_command(&raw_args[1..], global),
        #[cfg(feature = "tzap-online")]
        "auth" => auth_command(&raw_args[1..], global),
        "create" | "c" => create_command(&raw_args[1..], global),
        "extract" | "x" => extract_command(&raw_args[1..], global),
        "list" | "ls" => list_command(&raw_args[1..], global),
        "test" => test_command(&raw_args[1..], global),
        "plan" => plan_command(&raw_args[1..], global),
        "--help" | "-h" => {
            if raw_args.len() > 1 {
                return help_command(&raw_args[1..], &global);
            }
            print_help_stdout(USAGE, &global);
            ExitCode::SUCCESS
        }
        _ => {
            if has_classic_action(&raw_args) {
                run_classic_command(&raw_args, global)
            } else {
                print_help_stderr(USAGE, &global);
                ExitCode::from(2)
            }
        }
    }
}
#[derive(Debug)]
pub(crate) struct ProgressReporter {
    enabled: bool,
    color: OutputMode,
    total_bytes: Option<u64>,
    last_percent: Option<u64>,
    last_reported_bytes: u64,
}

impl ProgressReporter {
    pub(crate) fn from_global(global: Option<&GlobalOptions>) -> Self {
        let stderr_is_terminal = io::stderr().is_terminal();
        let enabled = global.is_some_and(|global| {
            matches!(global.progress, OutputMode::Always) || matches!(global.progress, OutputMode::Auto) && !global.quiet && stderr_is_terminal
        });
        let color = global.map_or(OutputMode::Never, |global| global.color);

        Self { enabled, color, total_bytes: None, last_percent: None, last_reported_bytes: 0 }
    }

    pub(crate) fn emit(&mut self, event: JobEvent) {
        if !self.enabled {
            return;
        }

        match event {
            JobEvent::Started { kind, total_bytes } => {
                self.total_bytes = total_bytes;
                self.last_percent = None;
                self.last_reported_bytes = 0;
                match total_bytes {
                    Some(total_bytes) => {
                        self.emit_line(format_args!("{} started ({total_bytes} bytes)", progress_job_label(kind)));
                    }
                    None => {
                        self.emit_line(format_args!("{} started", progress_job_label(kind)));
                    }
                }
            }
            JobEvent::BytesProcessed { total_bytes_processed, .. } => {
                if let Some(total_bytes) = self.total_bytes {
                    self.emit_percent(total_bytes_processed, total_bytes);
                } else {
                    self.emit_byte_count(total_bytes_processed);
                }
            }
            JobEvent::Completed { entries, bytes } => {
                self.emit_line(format_args!("complete ({entries} entries, {bytes} bytes)"));
            }
            JobEvent::Failed { message } => {
                self.emit_line(format_args!("failed: {message}"));
            }
            JobEvent::Cancelled { message } => {
                self.emit_line(format_args!("cancelled: {message}"));
            }
            JobEvent::EntryStarted { .. }
            | JobEvent::EntryFinished { .. }
            | JobEvent::PhaseStarted { .. }
            | JobEvent::PhaseBytesProcessed { .. }
            | JobEvent::Warning { .. } => {}
        }
    }

    fn emit_line(&self, message: std::fmt::Arguments<'_>) {
        output::stderr_line(self.color, format_args!("{}: {message}", output::styled(StyleRole::Progress, format_args!("{PROGRESS_PREFIX}"))));
    }

    fn emit_percent(&mut self, total_bytes_processed: u64, total_bytes: u64) {
        let percent = total_bytes_processed.saturating_mul(100).checked_div(total_bytes).unwrap_or(100).clamp(1, 100);

        let should_emit = self.last_percent.is_none_or(|last| percent == 100 || percent >= last + PROGRESS_PERCENT_STEP);
        if should_emit {
            self.last_percent = Some(percent);
            self.emit_line(format_args!("{percent}% ({total_bytes_processed}/{total_bytes} bytes)"));
        }
    }

    fn emit_byte_count(&mut self, total_bytes_processed: u64) {
        let should_emit = self.last_reported_bytes == 0 || total_bytes_processed.saturating_sub(self.last_reported_bytes) >= PROGRESS_BYTE_STEP;
        if should_emit {
            self.last_reported_bytes = total_bytes_processed;
            self.emit_line(format_args!("{total_bytes_processed} bytes"));
        }
    }
}

impl zmanager_core::jobs::JobEventSink for ProgressReporter {
    fn emit(&mut self, event: JobEvent) {
        self.emit(event);
    }
}

fn progress_job_label(kind: JobKind) -> &'static str {
    match kind {
        JobKind::ZipCreate => "zip create",
        JobKind::ZipExtract => "zip extract",
        JobKind::SevenZCreate => "7z create",
        JobKind::SevenZExtract => "7z extract",
        JobKind::RarExtract => "rar extract",
        JobKind::TarZstdCreate => "tar.zst create",
        JobKind::TarGzCreate => "tgz create",
        JobKind::TarZstdExtract => "tar.zst extract",
        JobKind::TzapCreate => "tzap create",
        JobKind::TzapExtract => "tzap extract",
        JobKind::AppleArchiveCreate => "aar create",
        JobKind::AppleArchiveExtract => "aar extract",
        JobKind::ArchiveExtract => "archive extract",
        JobKind::RawStreamExtract => "raw stream extract",
    }
}
#[derive(Debug)]
pub(crate) struct InteractiveOverwriteResolver<R, W> {
    input: R,
    output: W,
    replace_all: bool,
}

impl<R, W> InteractiveOverwriteResolver<R, W>
where
    R: io::BufRead,
    W: io::Write,
{
    pub(crate) fn new(input: R, output: W) -> Self {
        Self { input, output, replace_all: false }
    }

    fn read_decision(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
        if self.replace_all {
            return OverwriteDecision::Replace;
        }

        let mut answer = String::new();
        loop {
            answer.clear();
            if write!(self.output, "overwrite {} from {}?{OVERWRITE_PROMPT_SUFFIX}", conflict.destination_path.display(), conflict.archive_path)
                .and_then(|()| self.output.flush())
                .is_err()
            {
                return OverwriteDecision::Quit;
            }
            match self.input.read_line(&mut answer) {
                Ok(0) | Err(_) => return OverwriteDecision::Quit,
                Ok(_) => match normalize_overwrite_answer(&answer) {
                    Some((decision, replace_all)) => {
                        if replace_all {
                            self.replace_all = true;
                        }
                        return decision;
                    }
                    None => {
                        let _ = writeln!(self.output, "{OVERWRITE_INVALID_CHOICE}");
                    }
                },
            }
        }
    }
}

impl<R, W> OverwriteResolver for InteractiveOverwriteResolver<R, W>
where
    R: io::BufRead,
    W: io::Write,
{
    fn decide(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
        self.read_decision(conflict)
    }
}

fn normalize_overwrite_answer(answer: &str) -> Option<(OverwriteDecision, bool)> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some((OverwriteDecision::Replace, false)),
        "n" | "no" => Some((OverwriteDecision::Skip, false)),
        "a" | "all" => Some((OverwriteDecision::Replace, true)),
        "r" | "rename" => Some((OverwriteDecision::Rename, false)),
        "q" | "quit" => Some((OverwriteDecision::Quit, false)),
        _ => None,
    }
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ArchiveFormat {
    Zip,
    TarZst,
    Tzap,
    AppleArchive,
    SevenZ,
    Tgz,
}

#[derive(Debug)]
pub(crate) struct CreateOutcome {
    pub(crate) summary: String,
    pub(crate) format: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) entries: usize,
    pub(crate) bytes: u64,
    pub(crate) warnings: usize,
    /// What each warning actually said. A count alone tells someone that
    /// something was left out without telling them what, which is the part they
    /// need -- 7-Zip names every file it could not read.
    pub(crate) warning_texts: Vec<String>,
    pub(crate) encrypted: Option<bool>,
    pub(crate) solid: Option<bool>,
    pub(crate) volume_size: Option<u64>,
    pub(crate) volume_count: usize,
}

#[derive(Debug)]
pub(crate) struct ExtractOutcome {
    pub(crate) label: &'static str,
    pub(crate) format: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) written_entries: usize,
    pub(crate) skipped_entries: usize,
    pub(crate) written_bytes: u64,
    pub(crate) warnings: Vec<String>,
}

pub(crate) fn create_progress_kind(format: ArchiveFormat) -> JobKind {
    match format {
        ArchiveFormat::Zip => JobKind::ZipCreate,
        ArchiveFormat::TarZst => JobKind::TarZstdCreate,
        ArchiveFormat::Tzap => JobKind::TzapCreate,
        ArchiveFormat::AppleArchive => JobKind::AppleArchiveCreate,
        ArchiveFormat::SevenZ => JobKind::SevenZCreate,
        ArchiveFormat::Tgz => JobKind::TarGzCreate,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Action {
    Create,
    Extract,
    List,
    Test,
}
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct CreateRequest {
    pub(crate) archive: String,
    pub(crate) sources: Vec<PathBuf>,
    pub(crate) format: Option<ArchiveFormat>,
    pub(crate) method: Option<String>,
    pub(crate) level: Option<i32>,
    pub(crate) compression: zmanager_core::engine::ZipCompression,
    pub(crate) solid: bool,
    pub(crate) clean: bool,
    pub(crate) no_ignore: bool,
    pub(crate) no_hidden: bool,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) exclude_from: Vec<PathBuf>,
    pub(crate) files_from: Vec<String>,
    pub(crate) stdin_paths: bool,
    pub(crate) null_paths: bool,
    pub(crate) force: bool,
    pub(crate) dry_run: bool,
    pub(crate) test_after: bool,
    pub(crate) encrypt: bool,
    pub(crate) password_stdin: bool,
    pub(crate) volume_size: Option<u64>,
    pub(crate) junk_paths: bool,
    pub(crate) preserve_symlinks: bool,
    pub(crate) follow_symlinks: bool,
    pub(crate) no_metadata: bool,
    pub(crate) tzap_recipient_cert: Option<PathBuf>,
    pub(crate) tzap_signing_cert: Option<PathBuf>,
    pub(crate) tzap_signing_private_key: Option<PathBuf>,
    pub(crate) tzap_signing_chain: Vec<PathBuf>,
    /// `--signing-identity [certificate-id]`: `Some(None)` selects the single
    /// active local certificate; `Some(Some(id))` disambiguates when more
    /// than one is active. Mutually exclusive with the file-based signing
    /// flags above.
    #[allow(clippy::option_option)]
    pub(crate) tzap_signing_identity: Option<Option<String>>,
    pub(crate) tzap_sidecar: bool,
}

impl Default for CreateRequest {
    fn default() -> Self {
        Self {
            archive: String::new(),
            sources: Vec::new(),
            format: None,
            method: None,
            level: None,
            compression: zmanager_core::engine::ZipCompression::Deflate,
            solid: true,
            clean: false,
            no_ignore: false,
            no_hidden: false,
            include: Vec::new(),
            exclude: Vec::new(),
            exclude_from: Vec::new(),
            files_from: Vec::new(),
            stdin_paths: false,
            null_paths: false,
            force: false,
            dry_run: false,
            test_after: false,
            encrypt: false,
            password_stdin: false,
            volume_size: None,
            junk_paths: false,
            preserve_symlinks: false,
            follow_symlinks: false,
            no_metadata: false,
            tzap_recipient_cert: None,
            tzap_signing_cert: None,
            tzap_signing_private_key: None,
            tzap_signing_chain: Vec::new(),
            tzap_signing_identity: None,
            tzap_sidecar: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ExtractRequest {
    pub(crate) archive: String,
    pub(crate) destination: Option<PathBuf>,
    pub(crate) overwrite: Option<String>,
    pub(crate) strip_components: usize,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) to_stdout: bool,
    pub(crate) extract_nested: bool,
    pub(crate) password_stdin: bool,
    pub(crate) recipient_key: Option<PathBuf>,
    pub(crate) tzap_restore_policy: zmanager_core::engine::TzapRestorePolicy,
    pub(crate) tzap_allow_degraded: bool,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ListRequest {
    pub(crate) archive: String,
    pub(crate) long: bool,
    pub(crate) name_only: bool,
    pub(crate) tree: bool,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) password_stdin: bool,
    pub(crate) recipient_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct TestRequest {
    pub(crate) archive: String,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) password_stdin: bool,
    pub(crate) recipient_key: Option<PathBuf>,
    pub(crate) public_no_key: bool,
    pub(crate) trusted_ca_certs: Vec<PathBuf>,
    pub(crate) trusted_system_roots: bool,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct PlanRequest {
    pub(crate) sources: Vec<PathBuf>,
    pub(crate) format: Option<ArchiveFormat>,
    pub(crate) clean: bool,
    pub(crate) no_ignore: bool,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) exclude_from: Vec<PathBuf>,
    pub(crate) files_from: Vec<String>,
    pub(crate) stdin_paths: bool,
    pub(crate) null_paths: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GenericEntry {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) compressed_size: Option<u64>,
    pub(crate) mode: Option<u32>,
    pub(crate) modified: Option<String>,
    pub(crate) created: Option<String>,
    pub(crate) accessed: Option<String>,
    pub(crate) encrypted: Option<bool>,
    pub(crate) method: Option<String>,
    pub(crate) solid: Option<bool>,
    pub(crate) link_target: Option<String>,
    pub(crate) attributes: Option<String>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) owner: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) metadata_diagnostics: Vec<String>,
}
fn peel_leading_global_options(args: &mut Vec<String>, global: &mut GlobalOptions) -> Result<(), String> {
    let mut consumed = 0usize;
    while consumed < args.len() {
        match args[consumed].as_str() {
            "--json" => global.json = true,
            "-q" | "--quiet" => global.quiet = true,
            "-v" | "--verbose" => global.verbose = global.verbose.saturating_add(1),
            "--no-color" => global.color = OutputMode::Never,
            "--no-progress" => global.progress = OutputMode::Never,
            "--no-password-prompt" => global.no_password_prompt = true,
            "--color" | "--progress" => {
                let option = args[consumed].clone();
                consumed = consumed.saturating_add(1);
                if consumed >= args.len() {
                    return Err(format!("missing value for {option}"));
                }
                let mode = parse_output_mode(&args[consumed], &option)?;
                if option == "--color" {
                    global.color = mode;
                } else {
                    global.progress = mode;
                }
            }
            _ => break,
        }
        consumed = consumed.saturating_add(1);
    }

    if consumed > 0 {
        args.drain(0..consumed);
    }

    Ok(())
}

fn has_classic_action(args: &[String]) -> bool {
    expand_short_options(args).iter().any(|arg| matches!(arg.as_str(), "-c" | "--create" | "-x" | "--extract" | "-t" | "--list" | "-T" | "--test"))
}

fn run_classic_command(args: &[String], global: GlobalOptions) -> ExitCode {
    let expanded = expand_short_options(args);
    let mut action = None;
    let mut create_seen = false;

    for arg in &expanded {
        match arg.as_str() {
            "-c" | "--create" => {
                action = Some(Action::Create);
                create_seen = true;
            }
            "-x" | "--extract" => action = Some(Action::Extract),
            "-t" | "--list" => action = Some(Action::List),
            "-T" | "--test" if !create_seen => action = Some(Action::Test),
            _ => {}
        }
    }

    match action {
        Some(Action::Create) => create_command_from_expanded(&expanded, global),
        Some(Action::Extract) => extract_command_from_expanded(&expanded, global),
        Some(Action::List) => list_command_from_expanded(&expanded, global),
        Some(Action::Test) => test_command_from_expanded(&expanded, global),
        None => {
            print_help_stderr(USAGE, &global);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn expand_short_options(args: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();
    let mut after_double_dash = false;

    for arg in args {
        if after_double_dash {
            expanded.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            expanded.push(arg.clone());
            continue;
        }
        if !arg.starts_with('-') || arg == "-" || arg.starts_with("--") || arg.len() <= 2 {
            expanded.push(arg.clone());
            continue;
        }

        let chars = arg[1..].chars().collect::<Vec<_>>();
        if chars.iter().all(|ch| matches!(ch, 'c' | 'x' | 't' | 'T' | 'f' | 'r' | 'j' | 'y' | 'X' | '0'..='9')) {
            expanded.extend(chars.into_iter().map(|ch| format!("-{ch}")));
        } else {
            expanded.push(arg.clone());
        }
    }

    expanded
}
fn formats_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(FORMATS_HELP, &global);
        return ExitCode::SUCCESS;
    }
    // --contract is a data flag, not a global option; handle it before
    // parse_global_only (which rejects unknown arguments).
    if args.iter().any(|arg| arg == "--contract") {
        print_formats_contract();
        return ExitCode::SUCCESS;
    }
    if let Err(error) = parse_global_only(args, &mut global) {
        return command_usage_error("formats", &error, &global);
    }
    if global.json {
        print_formats_json();
    } else {
        print_formats_table(&global);
    }
    ExitCode::SUCCESS
}

fn print_formats_json() {
    print!("{{\"create\":");
    print_format_descriptors_json(CREATE_FORMATS);
    print!(",\"extract\":");
    print_format_descriptors_json(EXTRACT_FORMATS);
    print!(",\"capabilities\":");
    print_formats_capabilities_json(true);
    println!("}}");
}

/// Emits the byte-stable capability contract consumed by downstream projects
/// (the desktop manifest generator and mobile snapshots). Platform-independent
/// on purpose: it carries kind/label/extensions only — never status or
/// capability flags, which flip per build target. Regenerate with
/// scripts/refresh-format-contract.sh.
fn print_formats_contract() {
    println!("{{\"schemaVersion\":1,\"formats\":");
    print_formats_capabilities_json(false);
    println!("}}");
}

fn print_formats_capabilities_json(include_runtime: bool) {
    let engine_snapshot = if include_runtime {
        zmanager_core::engine::create_default_engine().ok().map_or_else(Vec::new, |engine| engine.capability_snapshot())
    } else {
        Vec::new()
    };
    print!("[");
    for (index, capability) in FORMAT_CAPABILITIES.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        let kind_name = format!("{:?}", capability.kind);
        print!("{{\"kind\":\"{}\",\"label\":\"{}\",\"extensions\":", json_escape(&kind_name), json_escape(&kind_name));
        print!("{}", crate::cli::usage::json_string_array(capability.extensions));
        if include_runtime {
            let status = format_status(capability.kind);
            let engine_capability = zmanager_core::engine::FormatId::from_archive_format_kind(capability.kind)
                .and_then(|format| engine_snapshot.iter().find(|snapshot| snapshot.format == format));
            let platform_available = engine_capability.is_some_and(|snapshot| snapshot.platform_available);
            let recognized = !matches!(capability.kind, ArchiveFormatKind::Unknown);
            let can_list = engine_capability.is_some_and(|snapshot| snapshot.operations.contains(&zmanager_core::engine::ArchiveOperation::List));
            let available = status == BackendStatus::Available && platform_available;
            let can_create = cli_can_create(capability.kind) && available;
            let unavailable_reason = engine_capability.and_then(|snapshot| snapshot.unavailable_reason.as_deref()).unwrap_or("");
            let source_access = engine_capability.and_then(|snapshot| snapshot.source_access).map_or("", |source_access| match source_access {
                zmanager_core::engine::SourceAccess::Seekable => "seekable",
                zmanager_core::engine::SourceAccess::SequentialOnly => "sequential_only",
                zmanager_core::engine::SourceAccess::MultiVolumeSet => "multi_volume_set",
            });
            let encryption_supported = engine_capability.is_some_and(|snapshot| snapshot.encryption_supported);
            print!(
                ",\"status\":\"{}\",\"recognized\":{recognized},\"platform_available\":{platform_available},\"can_list\":{},\"can_extract\":{available},\"can_create\":{can_create},\"source_access\":\"{}\",\"encryption_supported\":{encryption_supported}",
                backend_status_string(status),
                can_list && available,
                source_access,
            );
            if unavailable_reason.is_empty() {
                print!(",\"unavailable_reason\":null");
            } else {
                print!(",\"unavailable_reason\":\"{}\"", json_escape(unavailable_reason));
            }
        }
        print!("}}");
    }
    print!("]");
}

/// The CLI can create a format when a create descriptor exists for its kind.
fn cli_can_create(kind: ArchiveFormatKind) -> bool {
    CREATE_FORMATS.iter().any(|format| format.kind == kind)
}

fn print_format_descriptors_json(formats: &[FormatDescriptor]) {
    print!("[");
    for (index, format) in formats.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!("{{\"format\":\"{}\",\"extensions\":", json_escape(format.name));
        print!("{}", crate::cli::usage::json_string_array(format.extensions));
        print!(",\"status\":\"{}\"}}", backend_status_string(format_status(format.kind)));
    }
    print!("]");
}

fn backend_status_string(status: BackendStatus) -> &'static str {
    match status {
        BackendStatus::Available => "available",
        BackendStatus::UnsupportedPlatform => "unsupported_platform",
        BackendStatus::Unavailable { .. } => "unavailable",
    }
}

/// Annotation appended to recognized-but-unsupported format rows: the
/// capability-table reason for placeholder formats (for example "native
/// grzip decoder not implemented yet"), or the platform gate message for
/// Apple Archive / MTREE outside their native targets.
fn unsupported_annotation(format: &FormatDescriptor) -> String {
    match format_status(format.kind) {
        BackendStatus::Available => String::new(),
        BackendStatus::UnsupportedPlatform => " (not supported on this platform)".to_owned(),
        BackendStatus::Unavailable { reason } => format!(" ({reason})"),
    }
}

fn print_formats_table(global: &GlobalOptions) {
    output::stdout_line(global.color, format_args!("{}", output::styled(StyleRole::Heading, format_args!("Create:"))));
    for format in CREATE_FORMATS {
        let padding = " ".repeat(9usize.saturating_sub(format.name.len()));
        output::stdout_line(
            global.color,
            format_args!(
                "  {}{} {}{}",
                output::styled(StyleRole::Command, format_args!("{}", format.name)),
                padding,
                format.extensions.join(", "),
                unsupported_annotation(format)
            ),
        );
    }
    output::stdout_line(global.color, format_args!(""));
    output::stdout_line(global.color, format_args!("{}", output::styled(StyleRole::Heading, format_args!("Extract:"))));
    for format in EXTRACT_FORMATS {
        let padding = " ".repeat(9usize.saturating_sub(format.name.len()));
        output::stdout_line(
            global.color,
            format_args!(
                "  {}{} {}{}",
                output::styled(StyleRole::Command, format_args!("{}", format.name)),
                padding,
                format.extensions.join(", "),
                unsupported_annotation(format)
            ),
        );
    }
}

fn parse_global_only(args: &[String], global: &mut GlobalOptions) -> Result<(), String> {
    let expanded = expand_short_options(args);
    let mut index = 0usize;
    while index < expanded.len() {
        if parse_global_option(&expanded, &mut index, global)? {
            continue;
        }
        return Err(format!("unexpected argument: {}", expanded[index]));
    }
    Ok(())
}

fn doctor_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(DOCTOR_HELP, &global);
        return ExitCode::SUCCESS;
    }
    if let Err(error) = parse_global_only(args, &mut global) {
        return command_usage_error("doctor", &error, &global);
    }
    let report = zmanager_core::healthcheck();
    if global.json {
        println!("{{\"engine\":\"{}\",\"version\":\"{}\",\"ready\":{}}}", json_escape(report.engine), json_escape(report.version), report.ready);
    } else {
        let role = if report.ready { StyleRole::Success } else { StyleRole::Warning };
        output::stdout_line(global.color, format_args!("{}", output::styled(role, format_args!("{}", report.summary()))));
    }
    ExitCode::SUCCESS
}

fn completions_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(COMPLETIONS_HELP, &global);
        return ExitCode::SUCCESS;
    }

    let expanded = expand_short_options(args);
    let mut index = 0usize;
    let mut shell = None;
    while index < expanded.len() {
        if let Err(error) = parse_global_option(&expanded, &mut index, &mut global) {
            return command_usage_error("completions", &error, &global);
        }
        if index >= expanded.len() {
            break;
        }
        let arg = &expanded[index];
        match arg.as_str() {
            "--" => {
                index += 1;
            }
            _ if arg.starts_with('-') => {
                return command_usage_error("completions", &format!("unknown completions option: {arg}"), &global);
            }
            _ if shell.is_none() => {
                shell = Some(arg.as_str());
                index += 1;
            }
            _ => {
                return command_usage_error("completions", "too many arguments", &global);
            }
        }
    }

    let Some(shell) = shell else {
        return command_usage_error("completions", "missing shell", &global);
    };

    let script = match shell {
        "bash" => COMPLETION_BASH_SCRIPT,
        "zsh" => COMPLETION_ZSH_SCRIPT,
        "fish" => COMPLETION_FISH_SCRIPT,
        "powershell" => COMPLETION_POWERSHELL_SCRIPT,
        _ => {
            return command_usage_error("completions", &format!("unsupported shell: {shell}; use bash, zsh, fish, or powershell"), &global);
        }
    };
    print!("{script}");
    ExitCode::SUCCESS
}
pub(crate) fn temp_archive_path(destination: &Path) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    let file_name = destination.file_name().and_then(|name| name.to_str()).unwrap_or("archive");
    destination.with_file_name(format!("{TEMP_ARCHIVE_PREFIX}{file_name}{TEMP_ARCHIVE_MARKER}-{}-{now}", std::process::id()))
}

pub(crate) fn create_test_archive_path(destination: &Path, format: ArchiveFormat, split_output: bool) -> PathBuf {
    if split_output && format == ArchiveFormat::SevenZ {
        let mut path = destination.as_os_str().to_os_string();
        path.push(".001");
        PathBuf::from(path)
    } else {
        destination.to_path_buf()
    }
}

pub(crate) fn publish_archive(temp: &Path, destination: &Path, force: bool) -> io::Result<()> {
    if force {
        remove_file_destination_for_publish(destination)?;
    }

    fs::hard_link(temp, destination)?;
    let _ = fs::remove_file(temp);
    Ok(())
}

fn remove_file_destination_for_publish(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())));
    }

    fs::remove_file(path)
}

pub(crate) fn default_extract_destination(archive: &str) -> PathBuf {
    let path = Path::new(archive);
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("archive");
    let stem = strip_known_archive_suffix(name).unwrap_or(name);
    path.parent().unwrap_or_else(|| Path::new(".")).join(stem)
}

fn strip_known_archive_suffix(name: &str) -> Option<&str> {
    let mut extensions: Vec<&str> = TAR_ZST_EXTENSIONS.iter().chain(ZIP_FAMILY_EXTENSIONS).chain(SEVEN_Z_EXTENSIONS).copied().collect();
    extensions.extend_from_slice(APPLE_ARCHIVE_EXTENSIONS);
    extensions.extend_from_slice(RAR_EXTENSIONS);
    extensions.extend_from_slice(DEB_EXTENSIONS);
    extensions.into_iter().find_map(|suffix| strip_suffix_ignore_ascii_case(name, suffix))
}

pub(crate) fn default_raw_stream_destination(archive: &str) -> PathBuf {
    let path = Path::new(archive);
    let Some(parent) = path.parent() else {
        return PathBuf::from(".");
    };
    if parent.as_os_str().is_empty() { PathBuf::from(".") } else { parent.to_path_buf() }
}

#[cfg(test)]
mod tests;
