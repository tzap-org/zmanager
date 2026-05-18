use crate::output::{self, OutputMode, StyleRole};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent, JobKind};
use zmanager_core::safety::{
    OverwriteConflict, OverwriteDecision, OverwritePolicy, OverwriteResolver,
};
use zmanager_core::secrets::SecretString;

const PROGRESS_PREFIX: &str = "progress";
const PROGRESS_PERCENT_STEP: u64 = 5;
const PROGRESS_BYTE_STEP: u64 = 1024 * 1024;
const OVERWRITE_PROMPT_SUFFIX: &str = " [y]es/[n]o/[a]ll/[r]ename/[q]uit: ";
const OVERWRITE_INVALID_CHOICE: &str = "please answer yes, no, all, rename, or quit";

const USAGE: &str = "\
Z-Manager archive utility

Usage:
  zm [options] <command>
  zm -cf <archive> [create-options] <paths...>
  zm -xf <archive> [extract-options]
  zm -tf <archive> [list-options]
  zm -Tf <archive> [test-options]

Commands:
  create <archive> <paths...>    Create an archive
  extract <archive> [-C dir]     Extract an archive
  list <archive>                 List archive contents
  test <archive>                 Test archive readability
  plan <paths...>                Show planned archive entries
  formats                        Show supported formats
  doctor                         Verify the Rust engine
  completions <shell>            Print shell completion scripts
  help [command]                 Show help for a command

Action options:
  -c, --create                   Create an archive
  -x, --extract                  Extract an archive
  -t, --list                     List archive contents
  -T, --test                     Test archive integrity; with create, test after writing
  -f, --file <archive>           Archive file path

Global options:
  -h, --help                     Show help
  -V, --version                  Show version
  -q, --quiet                    Reduce output
  -v, --verbose                  Increase diagnostics
      --json                     Emit JSON where supported
      --color <auto|always|never>
                                  Control color output; auto honors NO_COLOR
      --no-color                 Alias for --color never
      --progress <auto|always|never>
                                  Control progress output
      --no-progress              Alias for --progress never
      --no-password-prompt       Fail instead of prompting interactively

Examples:
  zm -cf project.zip project/
  zm -xf project.zip -C out/
  zm -tf project.zip
  zm -Tf project.zip
  zm formats

Run 'zm help <command>' for command-specific examples and flags.
Run 'zm help legacy' for old development commands.
";

const LEGACY_HELP: &str = "\
Legacy development commands

These commands remain accepted for development compatibility. New scripts and
user documentation should use the public `zm` commands instead.

Usage:
  zmanager-cli job-zip-create <source> <destination> [store|deflate] [-]
  zmanager-cli job-source-fast <source> <destination> [level]
  zmanager-cli zip-create <source> <destination> [store|deflate] [-]
  zmanager-cli zip-create-stream <source> [store|deflate]
  zmanager-cli zip-list <archive>
  zmanager-cli zip-test <archive> [-]
  zmanager-cli zip-extract <archive> <destination> [-]
  zmanager-cli tar-zst-create <source> <destination> [level]
  zmanager-cli source-fast <source> <destination> [level]
  zmanager-cli tar-zst-extract <archive> <destination>
  zmanager-cli 7z-create <source> <destination> [solid|non-solid] [-]
  zmanager-cli source-small <source> <destination> [solid|non-solid] [-]
  zmanager-cli 7z-list <archive> [-]
  zmanager-cli 7z-extract <archive> <destination> [-]
  zmanager-cli libarchive-list <archive>
  zmanager-cli libarchive-extract <archive> <destination>
";

const CREATE_HELP: &str = "\
Create ZIP, TAR.ZST, or 7z archives

Usage:
  zm create <archive> <paths...> [options]
  zm -cf <archive> [create-options] <paths...>

Examples:
  zm create project.zip project/
  zm -cf project.zip project/
  zm -9cf source.zip README.md src/ docs/
  zm -cf source.zip -C project src README.md
  find src -type f -print0 | zm -cf source.zip --files-from - --null
  zm -jcf flat.zip src/main.rs docs/guide.md
  printf '%s\\n' \"$ZM_PASSWORD\" | zm create secret.7z private/ --encrypt --password-stdin

Input:
  <paths...>                     Files and folders to archive
  -r, --recursive                Accepted for zip familiarity; directories recurse by default
  -C, --directory <dir>          Use dir as the base for following input paths
  -@                             Read input paths from stdin
      --files-from <file|->      Read input paths from a file, or stdin with -
      --null                     Read NUL-delimited path lists with -@/--files-from
      --clean                    Apply clean source exclusions
      --no-ignore                Ignore .gitignore/default exclusion rules
      --hidden                   Accepted for compatibility; hidden files are included by default
      --no-hidden                Exclude hidden dotfiles

Selection:
  -i, --include <glob>           Include archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --exclude-from <file>      Read exclude globs from file
  -x always means extract. Use --exclude for filtering.
  Glob patterns match archive paths after -C processing. Quote patterns so the
  shell does not expand them first. Use dir/** for a whole tree; * can match /.

Archive format and compression:
      --format <zip|tar.zst|7z>  Override format inference from extension
      --method <method>          Select method: zip store/deflate, tar.zst zstd, 7z lzma2
      --level <level>            Compression level; use 0..9 where supported
  -0 .. -9                       Compression presets; -0 stores ZIP entries
      --store                    Store ZIP entries without compression
      --solid                    Use solid 7z mode
      --no-solid                 Disable solid 7z mode

Paths, links, and metadata:
  -j, --junk-paths               Store basenames only; fail if flattened names collide
  -y, --preserve-symlinks        Store symlink entries where backend supports them
      --follow-symlinks          Archive symlink target contents
      --preserve-metadata        Preserve portable metadata where supported
  -X, --no-metadata              Omit portable metadata where supported

Output and safety:
  -f, --file <archive>           Archive file path in classic mode
      --force                    Replace an existing output archive
      --dry-run                  Print planned entries without writing the archive
  -T, --test-after               Test the archive after writing
      --encrypt                  Prompt for an archive password where supported
      --password-stdin           Read one password line from stdin
";

const EXTRACT_HELP: &str = "\
Extract supported archives

Usage:
  zm extract <archive> [-C dir] [options]
  zm -xf <archive> [extract-options]

Examples:
  zm extract project.zip -C out/
  zm -xf project.zip -C out/
  zm extract project.zip -C out/ --include 'docs/**'
  zm extract project.tar.zst --strip-components 1 -C out/
  zm extract file.txt.zst
  zm extract package.deb -C out/ --extract-nested
  printf '%s\\n' \"$RAR_PASSWORD\" | zm extract secret.rar -C out/ --password-stdin

Destination:
  -C, -d, --directory <dir>      Extract into dir
      --here                     Extract into the current directory
      --overwrite <never|always|ask|rename>
                                  Existing file policy; default is never

Selection and output:
  -i, --include <glob>           Extract archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --strip-components <n>     Remove n leading path components before writing
      --to-stdout                Write selected regular file bytes to stdout
      --extract-nested           Expand known package payloads; currently .deb
      --password-stdin           Read one password line from stdin
  Glob patterns match archive paths. Quote patterns so the shell does not
  expand them first. Use dir/** for a whole tree; * can match /.

Safety:
  Extraction rejects traversal paths, absolute paths, unsafe links, duplicate
  normalized paths, and unsafe overwrites.
";

const LIST_HELP: &str = "\
List archive contents

Usage:
  zm list <archive> [options]
  zm -tf <archive> [list-options]

Examples:
  zm list project.zip
  zm -tf project.zip
  zm list project.zip --tree
  zm list project.zip --name-only --include 'docs/**'
  printf '%s\\n' \"$RAR_PASSWORD\" | zm list secret.rar --password-stdin

Options:
  -f, --file <archive>           Archive file path in classic mode
  -l, --long                     Show type, size, compressed size, and path
      --name-only                Print archive paths only
      --tree                     Print a simple hierarchical tree
  -i, --include <glob>           List archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --password-stdin           Read one password line from stdin
      --json                     Emit machine-readable JSON
  Glob patterns match archive paths. Quote patterns so the shell does not
  expand them first. Use dir/** for a whole tree; * can match /.

In classic archive syntax, -t means list/table-of-contents.
";

const TEST_HELP: &str = "\
Verify archive readability or integrity

Usage:
  zm test <archive> [options]
  zm -Tf <archive> [test-options]

Examples:
  zm test project.zip
  zm -Tf project.zip
  zm test project.zip --include 'docs/**'
  printf '%s\\n' \"$ZM_PASSWORD\" | zm test secret.7z --password-stdin

Options:
  -f, --file <archive>           Archive file path in classic mode
  -i, --include <glob>           Test archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --password-stdin           Read one password line from stdin
      --json                     Emit machine-readable JSON
  Glob patterns match archive paths. Quote patterns so the shell does not
  expand them first. Use dir/** for a whole tree; * can match /.

ZIP receives a real integrity test. Other readable formats are validated through
their backend when full checksum verification is unavailable.
";

const PLAN_HELP: &str = "\
Show what create would archive

Usage:
  zm plan <paths...> [options]

Examples:
  zm plan project/
  zm plan README.md src/ --format zip
  zm plan -C project src README.md --exclude 'src/target/**'
  zm plan project/ --json

Options:
      --format <zip|tar.zst|7z>  Plan for a specific archive format
  -C, --directory <dir>          Use dir as the base for following input paths
  -@                             Read input paths from stdin
      --files-from <file|->      Read input paths from a file, or stdin with -
      --null                     Read NUL-delimited path lists with -@/--files-from
      --clean                    Apply clean source exclusions
      --no-ignore                Ignore .gitignore/default exclusion rules
  -i, --include <glob>           Include archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --exclude-from <file>      Read exclude globs from file
      --json                     Emit machine-readable JSON
  Glob patterns match archive paths after -C processing. Quote patterns so the
  shell does not expand them first. Use dir/** for a whole tree; * can match /.
";

const FORMATS_HELP: &str = "\
Show supported archive formats

Usage:
  zm formats [--json]

Examples:
  zm formats
  zm formats --json

Create:
  zip       .zip
  tar.zst   .tar.zst, .tzst
  7z        .7z

Extract/List/Test:
  zip       .zip, .zipx, .jar, .war, .ipa, .apk, .appx, .xpi
  tar.zst   .tar.zst, .tzst
  7z        .7z
  raw       .zst, .gz, .bz2, .xz, .lzma, .lz, .br, .lz4, .lzo, .Z, .lrz
  rar       .rar, .cbr; passworded list/extract uses bundled UnRAR with --password-stdin
  fallback  libarchive-supported archive formats

raw single-file streams decompress to one file. TAR-wrapped streams such as
project.tar.zst extract as archives.
";

const DOCTOR_HELP: &str = "\
Verify the installed CLI and archive engine

Usage:
  zm doctor [--json]

Examples:
  zm doctor
  zm doctor --json

Use --json in scripts and bug reports.
";

const COMPLETIONS_HELP: &str = "\
Print shell completion scripts

Usage:
  zm completions <bash|zsh|fish|powershell>

Examples:
  source <(zm completions bash)
  zm completions zsh > ~/.zfunc/_zm
  zm completions fish > ~/.config/fish/completions/zm.fish
  zm completions powershell > zm.ps1

The release packages install completion files automatically where package
managers support it. This command is for manual shell setup and troubleshooting.
";

const COMPLETION_BASH_SCRIPT: &str = include_str!("../../../completions/zm.bash");
const COMPLETION_ZSH_SCRIPT: &str = include_str!("../../../completions/_zm");
const COMPLETION_FISH_SCRIPT: &str = include_str!("../../../completions/zm.fish");
const COMPLETION_POWERSHELL_SCRIPT: &str = include_str!("../../../completions/zm.ps1");

const FORMAT_ZIP: &str = "zip";
const FORMAT_TAR_ZST: &str = "tar.zst";
const FORMAT_SEVEN_Z: &str = "7z";
const FORMAT_RAR: &str = "rar";
const FORMAT_DEB: &str = "deb";
const FORMAT_RAW_STREAM: &str = "raw-stream";
const FORMAT_LIBARCHIVE: &str = "libarchive";
const BACKEND_DEB_NESTED: &str = "deb-nested";

const TEMP_ARCHIVE_PREFIX: &str = ".";
const TEMP_ARCHIVE_MARKER: &str = ".tmp";

const TAR_ZST_FORMAT_ALIASES: &[&str] = &[FORMAT_TAR_ZST, "tzst", "zst"];

const ZIP_CREATE_EXTENSIONS: &[&str] = &[".zip"];
const ZIP_FAMILY_EXTENSIONS: &[&str] = &[
    ".zip", ".zipx", ".jar", ".war", ".ipa", ".apk", ".appx", ".xpi",
];
const TAR_ZST_EXTENSIONS: &[&str] = &[".tar.zst", ".tzst"];
const SEVEN_Z_EXTENSIONS: &[&str] = &[".7z"];
const RAR_EXTENSIONS: &[&str] = &[".rar", ".cbr"];
const DEB_EXTENSIONS: &[&str] = &[".deb"];
const LIBARCHIVE_FALLBACK_EXTENSIONS: &[&str] = &["fallback"];

#[derive(Clone, Copy)]
struct FormatDescriptor {
    name: &'static str,
    extensions: &'static [&'static str],
}

const CREATE_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor {
        name: FORMAT_ZIP,
        extensions: ZIP_CREATE_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_TAR_ZST,
        extensions: TAR_ZST_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_SEVEN_Z,
        extensions: SEVEN_Z_EXTENSIONS,
    },
];

const EXTRACT_FORMATS: &[FormatDescriptor] = &[
    FormatDescriptor {
        name: FORMAT_ZIP,
        extensions: ZIP_FAMILY_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_TAR_ZST,
        extensions: TAR_ZST_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_SEVEN_Z,
        extensions: SEVEN_Z_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_RAW_STREAM,
        extensions: zmanager_core::raw_stream_backend::RAW_STREAM_SUFFIXES,
    },
    FormatDescriptor {
        name: FORMAT_LIBARCHIVE,
        extensions: LIBARCHIVE_FALLBACK_EXTENSIONS,
    },
];

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
            println!("zm {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" => help_command(&raw_args[1..], &global),
        "doctor" | "healthcheck" => doctor_command(&raw_args[1..], global),
        "completions" | "completion" => completions_command(&raw_args[1..], global),
        "formats" => new_formats_command(&raw_args[1..], global),
        "create" | "c" => new_create_command(&raw_args[1..], global),
        "extract" | "x" => new_extract_command(&raw_args[1..], global),
        "list" | "ls" => new_list_command(&raw_args[1..], global),
        "test" => new_test_command(&raw_args[1..], global),
        "plan" => new_plan_command(&raw_args[1..], global),
        "job-zip-create" => job_zip_create_command(raw_args.into_iter().skip(1)),
        "job-source-fast" => job_tar_zst_create_command(raw_args.into_iter().skip(1)),
        "zip-create" => zip_create_command(raw_args.into_iter().skip(1)),
        "zip-create-stream" => zip_create_stream_command(raw_args.into_iter().skip(1)),
        "zip-list" => zip_list_command(raw_args.into_iter().skip(1)),
        "zip-test" => zip_test_command(raw_args.into_iter().skip(1)),
        "zip-extract" => zip_extract_command(raw_args.into_iter().skip(1)),
        "tar-zst-create" | "source-fast" => tar_zst_create_command(raw_args.into_iter().skip(1)),
        "tar-zst-extract" => tar_zst_extract_command(raw_args.into_iter().skip(1)),
        "7z-create" | "source-small" => seven_z_create_command(raw_args.into_iter().skip(1)),
        "7z-list" => seven_z_list_command(raw_args.into_iter().skip(1)),
        "7z-extract" => seven_z_extract_command(raw_args.into_iter().skip(1)),
        "libarchive-list" => libarchive_list_command(raw_args.into_iter().skip(1)),
        "libarchive-extract" => libarchive_extract_command(raw_args.into_iter().skip(1)),
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

#[derive(Debug, Clone, Default)]
struct GlobalOptions {
    json: bool,
    quiet: bool,
    verbose: u8,
    color: OutputMode,
    progress: OutputMode,
    no_password_prompt: bool,
}

#[derive(Debug)]
struct ProgressReporter {
    enabled: bool,
    color: OutputMode,
    total_bytes: Option<u64>,
    last_percent: Option<u64>,
    last_reported_bytes: u64,
}

impl ProgressReporter {
    fn from_global(global: Option<&GlobalOptions>) -> Self {
        let stderr_is_terminal = io::stderr().is_terminal();
        let enabled = global.is_some_and(|global| {
            matches!(global.progress, OutputMode::Always)
                || matches!(global.progress, OutputMode::Auto)
                    && !global.quiet
                    && stderr_is_terminal
        });
        let color = global.map_or(OutputMode::Never, |global| global.color);

        Self {
            enabled,
            color,
            total_bytes: None,
            last_percent: None,
            last_reported_bytes: 0,
        }
    }

    fn emit(&mut self, event: JobEvent) {
        if !self.enabled {
            return;
        }

        match event {
            JobEvent::Started { kind, total_bytes } => {
                self.total_bytes = total_bytes;
                self.last_percent = None;
                self.last_reported_bytes = 0;
                match total_bytes {
                    Some(total_bytes) => self.emit_line(format_args!(
                        "{} started ({total_bytes} bytes)",
                        progress_job_label(kind)
                    )),
                    None => {
                        self.emit_line(format_args!("{} started", progress_job_label(kind)));
                    }
                }
            }
            JobEvent::BytesProcessed {
                total_bytes_processed,
                ..
            } => {
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
            | JobEvent::Warning { .. } => {}
        }
    }

    fn emit_line(&self, message: std::fmt::Arguments<'_>) {
        output::stderr_line(
            self.color,
            format_args!(
                "{}: {message}",
                output::styled(StyleRole::Progress, format_args!("{PROGRESS_PREFIX}"))
            ),
        );
    }

    fn emit_percent(&mut self, total_bytes_processed: u64, total_bytes: u64) {
        let percent = total_bytes_processed
            .saturating_mul(100)
            .checked_div(total_bytes)
            .unwrap_or(100)
            .clamp(1, 100);

        let should_emit = self
            .last_percent
            .is_none_or(|last| percent == 100 || percent >= last + PROGRESS_PERCENT_STEP);
        if should_emit {
            self.last_percent = Some(percent);
            self.emit_line(format_args!(
                "{percent}% ({total_bytes_processed}/{total_bytes} bytes)"
            ));
        }
    }

    fn emit_byte_count(&mut self, total_bytes_processed: u64) {
        let should_emit = self.last_reported_bytes == 0
            || total_bytes_processed.saturating_sub(self.last_reported_bytes) >= PROGRESS_BYTE_STEP;
        if should_emit {
            self.last_reported_bytes = total_bytes_processed;
            self.emit_line(format_args!("{total_bytes_processed} bytes"));
        }
    }
}

fn progress_job_label(kind: JobKind) -> &'static str {
    match kind {
        JobKind::ZipCreate => "zip create",
        JobKind::ZipExtract => "zip extract",
        JobKind::SevenZCreate => "7z create",
        JobKind::SevenZExtract => "7z extract",
        JobKind::TarZstdCreate => "tar.zst create",
        JobKind::TarZstdExtract => "tar.zst extract",
        JobKind::ArchiveExtract => "archive extract",
    }
}

#[derive(Debug)]
struct InteractiveOverwriteResolver<R, W> {
    input: R,
    output: W,
    replace_all: bool,
}

impl<R, W> InteractiveOverwriteResolver<R, W>
where
    R: io::BufRead,
    W: io::Write,
{
    fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            replace_all: false,
        }
    }

    fn read_decision(&mut self, conflict: &OverwriteConflict) -> OverwriteDecision {
        if self.replace_all {
            return OverwriteDecision::Replace;
        }

        let mut answer = String::new();
        loop {
            answer.clear();
            if write!(
                self.output,
                "overwrite {} from {}?{OVERWRITE_PROMPT_SUFFIX}",
                conflict.destination_path.display(),
                conflict.archive_path
            )
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
enum ArchiveFormat {
    Zip,
    TarZst,
    SevenZ,
}

#[derive(Debug)]
struct CreateOutcome {
    summary: String,
    format: &'static str,
    backend: &'static str,
    entries: usize,
    bytes: u64,
    warnings: usize,
    encrypted: Option<bool>,
    solid: Option<bool>,
}

#[derive(Debug)]
struct ExtractOutcome {
    label: &'static str,
    format: &'static str,
    backend: &'static str,
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    warnings: Vec<String>,
}

fn create_progress_kind(format: ArchiveFormat) -> JobKind {
    match format {
        ArchiveFormat::Zip => JobKind::ZipCreate,
        ArchiveFormat::TarZst => JobKind::TarZstdCreate,
        ArchiveFormat::SevenZ => JobKind::SevenZCreate,
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
struct CreateRequest {
    archive: String,
    sources: Vec<PathBuf>,
    format: Option<ArchiveFormat>,
    method: Option<String>,
    level: Option<i32>,
    compression: zmanager_core::zip_backend::ZipCompression,
    solid: bool,
    clean: bool,
    no_ignore: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    exclude_from: Vec<PathBuf>,
    files_from: Vec<String>,
    stdin_paths: bool,
    null_paths: bool,
    force: bool,
    dry_run: bool,
    test_after: bool,
    encrypt: bool,
    password_stdin: bool,
    junk_paths: bool,
    preserve_symlinks: bool,
    follow_symlinks: bool,
    no_metadata: bool,
}

impl Default for CreateRequest {
    fn default() -> Self {
        Self {
            archive: String::new(),
            sources: Vec::new(),
            format: None,
            method: None,
            level: None,
            compression: zmanager_core::zip_backend::ZipCompression::Deflate,
            solid: true,
            clean: false,
            no_ignore: false,
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
            junk_paths: false,
            preserve_symlinks: false,
            follow_symlinks: false,
            no_metadata: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ExtractRequest {
    archive: String,
    destination: Option<PathBuf>,
    overwrite: Option<String>,
    strip_components: usize,
    include: Vec<String>,
    exclude: Vec<String>,
    to_stdout: bool,
    extract_nested: bool,
    password_stdin: bool,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct ListRequest {
    archive: String,
    long: bool,
    name_only: bool,
    tree: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    password_stdin: bool,
}

#[derive(Debug, Clone, Default)]
struct TestRequest {
    archive: String,
    include: Vec<String>,
    exclude: Vec<String>,
    password_stdin: bool,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct PlanRequest {
    sources: Vec<PathBuf>,
    format: Option<ArchiveFormat>,
    clean: bool,
    no_ignore: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    exclude_from: Vec<PathBuf>,
    files_from: Vec<String>,
    stdin_paths: bool,
    null_paths: bool,
}

#[derive(Debug, Clone)]
struct GenericEntry {
    kind: String,
    name: String,
    size: u64,
    compressed_size: Option<u64>,
}

fn peel_leading_global_options(
    args: &mut Vec<String>,
    global: &mut GlobalOptions,
) -> Result<(), String> {
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
    expand_short_options(args).iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-c" | "--create" | "-x" | "--extract" | "-t" | "--list" | "-T" | "--test"
        )
    })
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
        Some(Action::Create) => new_create_command_from_expanded(&expanded, global),
        Some(Action::Extract) => new_extract_command_from_expanded(&expanded, global),
        Some(Action::List) => new_list_command_from_expanded(&expanded, global),
        Some(Action::Test) => new_test_command_from_expanded(&expanded, global),
        None => {
            print_help_stderr(USAGE, &global);
            ExitCode::from(2)
        }
    }
}

fn expand_short_options(args: &[String]) -> Vec<String> {
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
        if chars.iter().all(|ch| {
            matches!(
                ch,
                'c' | 'x' | 't' | 'T' | 'f' | 'r' | 'j' | 'y' | 'X' | '0'..='9'
            )
        }) {
            expanded.extend(chars.into_iter().map(|ch| format!("-{ch}")));
        } else {
            expanded.push(arg.clone());
        }
    }

    expanded
}

fn wants_help(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
}

fn help_command(args: &[String], global: &GlobalOptions) -> ExitCode {
    if args.is_empty() {
        print_help_stdout(USAGE, global);
        return ExitCode::SUCCESS;
    }
    if args.len() > 1 {
        print_error_line(global, format_args!("error: too many help topics"));
        output::stderr_line(global.color, format_args!("Try 'zm help <command>'."));
        return ExitCode::from(2);
    }
    let topic = &args[0];
    let Some(help) = command_help(topic) else {
        print_error_line(global, format_args!("error: unknown help topic: {topic}"));
        output::stderr_line(
            global.color,
            format_args!("Try 'zm --help' for available commands."),
        );
        return ExitCode::from(2);
    };
    print_help_stdout(help, global);
    ExitCode::SUCCESS
}

fn command_help(command: &str) -> Option<&'static str> {
    match command {
        "create" | "c" => Some(CREATE_HELP),
        "extract" | "x" => Some(EXTRACT_HELP),
        "list" | "ls" => Some(LIST_HELP),
        "test" => Some(TEST_HELP),
        "plan" => Some(PLAN_HELP),
        "formats" => Some(FORMATS_HELP),
        "doctor" | "healthcheck" => Some(DOCTOR_HELP),
        "completions" | "completion" => Some(COMPLETIONS_HELP),
        "legacy" => Some(LEGACY_HELP),
        _ => None,
    }
}

fn print_help_stdout(help: &str, global: &GlobalOptions) {
    output::stdout_write(global.color, format_args!("{}", output::render_help(help)));
}

fn print_help_stderr(help: &str, global: &GlobalOptions) {
    output::stderr_write(global.color, format_args!("{}", output::render_help(help)));
}

fn print_error_line(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stderr_line(
        global.color,
        format_args!("{}", output::styled(StyleRole::Error, message)),
    );
}

fn print_optional_error_line(global: Option<&GlobalOptions>, message: std::fmt::Arguments<'_>) {
    if let Some(global) = global {
        print_error_line(global, message);
    } else {
        eprintln!("{message}");
    }
}

fn usage_failure(global: &GlobalOptions, message: std::fmt::Arguments<'_>) -> ExitCode {
    print_error_line(global, message);
    ExitCode::from(2)
}

fn print_success_line(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stdout_line(
        global.color,
        format_args!("{}", output::styled(StyleRole::Success, message)),
    );
}

fn print_warning_stdout(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stdout_line(
        global.color,
        format_args!("{}", output::styled(StyleRole::Warning, message)),
    );
}

fn new_formats_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(FORMATS_HELP, &global);
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
    println!("}}");
}

fn print_format_descriptors_json(formats: &[FormatDescriptor]) {
    print!("[");
    for (index, format) in formats.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!(
            "{{\"format\":\"{}\",\"extensions\":",
            json_escape(format.name)
        );
        print_string_array_json(format.extensions);
        print!("}}");
    }
    print!("]");
}

fn print_string_array_json(values: &[&str]) {
    print!("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!("\"{}\"", json_escape(value));
    }
    print!("]");
}

fn print_formats_table(global: &GlobalOptions) {
    output::stdout_line(
        global.color,
        format_args!(
            "{}",
            output::styled(StyleRole::Heading, format_args!("Create:"))
        ),
    );
    for format in CREATE_FORMATS {
        let padding = " ".repeat(9usize.saturating_sub(format.name.len()));
        output::stdout_line(
            global.color,
            format_args!(
                "  {}{} {}",
                output::styled(StyleRole::Command, format_args!("{}", format.name)),
                padding,
                format.extensions.join(", ")
            ),
        );
    }
    output::stdout_line(global.color, format_args!(""));
    output::stdout_line(
        global.color,
        format_args!(
            "{}",
            output::styled(StyleRole::Heading, format_args!("Extract:"))
        ),
    );
    for format in EXTRACT_FORMATS {
        let padding = " ".repeat(9usize.saturating_sub(format.name.len()));
        if format.name == FORMAT_LIBARCHIVE {
            output::stdout_line(
                global.color,
                format_args!(
                    "  {}{} fallback for supported archive formats",
                    output::styled(StyleRole::Command, format_args!("{}", format.name)),
                    padding
                ),
            );
        } else {
            output::stdout_line(
                global.color,
                format_args!(
                    "  {}{} {}",
                    output::styled(StyleRole::Command, format_args!("{}", format.name)),
                    padding,
                    format.extensions.join(", ")
                ),
            );
        }
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
        println!(
            "{{\"engine\":\"{}\",\"version\":\"{}\",\"ready\":{}}}",
            json_escape(report.engine),
            json_escape(report.version),
            report.ready
        );
    } else {
        let role = if report.ready {
            StyleRole::Success
        } else {
            StyleRole::Warning
        };
        output::stdout_line(
            global.color,
            format_args!(
                "{}",
                output::styled(role, format_args!("{}", report.summary()))
            ),
        );
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
                return command_usage_error(
                    "completions",
                    &format!("unknown completions option: {arg}"),
                    &global,
                );
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
            return command_usage_error(
                "completions",
                &format!("unsupported shell: {shell}; use bash, zsh, fish, or powershell"),
                &global,
            );
        }
    };
    print!("{script}");
    ExitCode::SUCCESS
}

fn new_create_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CREATE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    new_create_command_from_expanded(&expanded, global)
}

fn new_create_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
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
fn parse_create_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut CreateRequest,
) -> Result<(), String> {
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
                request.compression = zmanager_core::zip_backend::ZipCompression::Store;
                request.level = Some(0);
                index += 1;
            }
            "-1" | "-2" | "-3" | "-4" | "-5" | "-6" | "-7" | "-8" | "-9" => {
                request.level = Some(parse_i32(&arg[1..], arg)?);
                request.compression = zmanager_core::zip_backend::ZipCompression::Deflate;
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
                request
                    .exclude_from
                    .push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--store" => {
                request.compression = zmanager_core::zip_backend::ZipCompression::Store;
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
                request.exclude.push(".*".to_owned());
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
            "--dry-run" => {
                request.dry_run = true;
                index += 1;
            }
            "-T" | "--test-after" | "--test" => {
                request.test_after = true;
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown create option: {arg}")),
            _ => {
                push_create_positional(request, arg, current_dir.as_deref());
                index += 1;
            }
        }
    }

    append_files_from(
        &mut request.sources,
        &request.files_from,
        request.null_paths,
    )?;
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

fn push_create_positional(request: &mut CreateRequest, value: &str, current_dir: Option<&Path>) {
    if request.archive.is_empty() {
        value.clone_into(&mut request.archive);
    } else {
        request.sources.push(resolve_input_path(value, current_dir));
    }
}

#[allow(clippy::too_many_lines)]
fn run_create_request(request: &CreateRequest, global: &GlobalOptions) -> ExitCode {
    let Some(format) = request
        .format
        .or_else(|| infer_create_format(&request.archive))
    else {
        print_error_line(
            global,
            format_args!("could not infer archive format; pass --format <zip|tar.zst|7z>"),
        );
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
        print_error_line(
            global,
            format_args!("create failed: --follow-symlinks conflicts with --preserve-symlinks"),
        );
        return ExitCode::from(2);
    }

    let manifest = match plan_sources(
        &request.sources,
        request.clean,
        request.no_ignore,
        follow_symlinks,
    ) {
        Ok(mut manifest) => {
            if let Err(error) = apply_manifest_filters(
                &mut manifest,
                &request.include,
                &request.exclude,
                &request.exclude_from,
            ) {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if request.junk_paths
                && let Err(error) = apply_junk_paths(&mut manifest)
            {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if format == ArchiveFormat::SevenZ
                && request.preserve_symlinks
                && manifest_has_symlinks(&manifest)
            {
                print_error_line(
                    global,
                    format_args!(
                        "create failed: 7z symlink preservation is not supported by the current backend; use --follow-symlinks"
                    ),
                );
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
        print_error_line(
            global,
            format_args!(
                "create failed: destination exists: {}; pass --force to replace it",
                destination.display()
            ),
        );
        return ExitCode::FAILURE;
    }

    let temp = temp_archive_path(&destination);
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = fs::create_dir_all(parent)
    {
        print_error_line(
            global,
            format_args!(
                "create failed: failed to create {}: {error}",
                parent.display()
            ),
        );
        return ExitCode::FAILURE;
    }

    let mut progress = ProgressReporter::from_global(Some(global));
    progress.emit(JobEvent::Started {
        kind: create_progress_kind(format),
        total_bytes: Some(manifest.total_bytes),
    });
    let token = CancellationToken::new();

    let result = match format {
        ArchiveFormat::Zip => {
            let (compression, level) = match zip_compression_options(request) {
                Ok(options) => options,
                Err(error) => {
                    print_error_line(global, format_args!("{error}"));
                    return ExitCode::from(2);
                }
            };
            let options = zmanager_core::zip_backend::ZipCreateOptions {
                compression,
                level,
                preserve_metadata: !request.no_metadata,
                password,
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new(&token, &mut sink);
                zmanager_core::zip_backend::create_zip_from_manifest_with_context(
                    &manifest,
                    &temp,
                    &options,
                    &mut context,
                )
            };
            result
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created zip: {} entries, {} bytes, encrypted {}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        report.encrypted,
                        report.warnings.len()
                    ),
                    format: FORMAT_ZIP,
                    backend: FORMAT_ZIP,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: Some(report.encrypted),
                    solid: None,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::TarZst => {
            let options = zmanager_core::tar_zst_backend::TarZstdCreateOptions {
                level: request.level.unwrap_or_else(|| {
                    zmanager_core::tar_zst_backend::TarZstdCreateOptions::default().level
                }),
                preserve_metadata: !request.no_metadata,
                ..zmanager_core::tar_zst_backend::TarZstdCreateOptions::default()
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new(&token, &mut sink);
                zmanager_core::tar_zst_backend::create_tar_zst_from_manifest_with_context(
                    &manifest,
                    &temp,
                    &options,
                    &mut context,
                )
            };
            result
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created tar.zst: {} entries, {} bytes, level {}, threads {:?}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        report.level,
                        report.threads,
                        report.warnings.len()
                    ),
                    format: FORMAT_TAR_ZST,
                    backend: FORMAT_TAR_ZST,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: None,
                    solid: None,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::SevenZ => {
            let options = zmanager_core::sevenz_backend::SevenZCreateOptions {
                solid: request.solid,
                level: sevenz_level(request),
                preserve_metadata: !request.no_metadata,
                password,
            };
            zmanager_core::sevenz_backend::create_7z_from_manifest(&manifest, &temp, &options)
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created 7z: {} entries, {} bytes, solid {}, encrypted {}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        report.solid,
                        report.encrypted,
                        report.warnings.len()
                    ),
                    format: FORMAT_SEVEN_Z,
                    backend: FORMAT_SEVEN_Z,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: Some(report.encrypted),
                    solid: Some(report.solid),
                })
                .map_err(|error| error.to_string())
        }
    };

    match result {
        Ok(outcome) => {
            if let Err(error) = fs::rename(&temp, &destination) {
                let _ = fs::remove_file(&temp);
                progress.emit(JobEvent::Failed {
                    message: error.to_string(),
                });
                print_error_line(
                    global,
                    format_args!(
                        "create failed: failed to move {} to {}: {error}",
                        temp.display(),
                        destination.display()
                    ),
                );
                return ExitCode::FAILURE;
            }
            progress.emit(JobEvent::Completed {
                entries: outcome.entries,
                bytes: outcome.bytes,
            });
            print_create_summary(&destination, &outcome, global);
            if request.test_after {
                let archive = destination.to_string_lossy().into_owned();
                return run_test_request(
                    &TestRequest {
                        archive,
                        ..TestRequest::default()
                    },
                    global,
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = fs::remove_file(&temp);
            progress.emit(JobEvent::Failed {
                message: error.clone(),
            });
            print_error_line(global, format_args!("create failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn create_stream(
    format: ArchiveFormat,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    request: &CreateRequest,
    password: Option<SecretString>,
    global: &GlobalOptions,
) -> ExitCode {
    if format != ArchiveFormat::Zip {
        print_error_line(
            global,
            format_args!("create failed: stdout output is currently supported only for ZIP"),
        );
        return ExitCode::from(2);
    }

    let (compression, level) = match zip_compression_options(request) {
        Ok(options) => options,
        Err(error) => {
            print_error_line(global, format_args!("{error}"));
            return ExitCode::from(2);
        }
    };
    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level,
        preserve_metadata: !request.no_metadata,
        password,
    };
    let stdout = io::stdout();
    match zmanager_core::zip_backend::create_zip_stream_from_manifest(
        manifest,
        stdout.lock(),
        &options,
    ) {
        Ok((_output, report)) => {
            output::stderr_line(
                global.color,
                format_args!(
                    "{} streaming zip: {} entries, {} bytes, {} warnings",
                    output::styled(StyleRole::Success, format_args!("created")),
                    report.written_entries,
                    report.written_bytes,
                    report.warnings.len()
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

fn validate_create_options(format: ArchiveFormat, request: &CreateRequest) -> Result<(), String> {
    if let Some(method) = request.method.as_deref() {
        match (format, method) {
            (ArchiveFormat::Zip, "deflate" | "store")
            | (ArchiveFormat::TarZst, "zstd" | "zst")
            | (ArchiveFormat::SevenZ, "lzma2") => {}
            _ => {
                return Err(format!(
                    "unsupported method for selected archive format: {method}"
                ));
            }
        }
    }

    if let Some(level) = request.level {
        match format {
            ArchiveFormat::Zip | ArchiveFormat::SevenZ if !(0..=9).contains(&level) => {
                return Err(format!(
                    "unsupported compression level for selected archive format: {level}"
                ));
            }
            ArchiveFormat::Zip
                if request.compression == zmanager_core::zip_backend::ZipCompression::Store
                    && level != 0 =>
            {
                return Err(format!(
                    "cannot combine ZIP store compression with compression level {level}"
                ));
            }
            _ => {}
        }
    }

    Ok(())
}

fn zip_compression_options(
    request: &CreateRequest,
) -> Result<(zmanager_core::zip_backend::ZipCompression, Option<i64>), String> {
    let mut compression = request.compression;
    if let Some(method) = request.method.as_deref() {
        compression = match method {
            "store" => zmanager_core::zip_backend::ZipCompression::Store,
            "deflate" => zmanager_core::zip_backend::ZipCompression::Deflate,
            _ => compression,
        };
    }

    let Some(level) = request.level else {
        return Ok((compression, None));
    };
    if !(0..=9).contains(&level) {
        return Err(format!(
            "unsupported compression level for selected archive format: {level}"
        ));
    }
    if compression == zmanager_core::zip_backend::ZipCompression::Store {
        if level == 0 {
            return Ok((compression, None));
        }
        return Err(format!(
            "cannot combine ZIP store compression with compression level {level}"
        ));
    }
    if level == 0 {
        return Ok((zmanager_core::zip_backend::ZipCompression::Store, None));
    }

    Ok((compression, Some(i64::from(level))))
}

fn sevenz_level(request: &CreateRequest) -> Option<u32> {
    request.level.and_then(|level| u32::try_from(level).ok())
}

fn follow_symlinks_for_create(format: ArchiveFormat, request: &CreateRequest) -> bool {
    request.follow_symlinks
        || (!request.preserve_symlinks
            && matches!(format, ArchiveFormat::Zip | ArchiveFormat::SevenZ))
}

fn create_password(
    format: ArchiveFormat,
    request: &CreateRequest,
    global: &GlobalOptions,
) -> Result<Option<SecretString>, ExitCode> {
    if !request.encrypt && !request.password_stdin {
        return Ok(None);
    }
    if format == ArchiveFormat::TarZst {
        print_error_line(
            global,
            format_args!("encryption is not supported for tar.zst"),
        );
        return Err(ExitCode::from(2));
    }
    if request.password_stdin {
        return prompt_password_from_stdin(Some(global)).map(Some);
    }
    if global.no_password_prompt {
        print_error_line(
            global,
            format_args!("password prompt disabled; use --password-stdin"),
        );
        return Err(ExitCode::from(2));
    }
    if global.quiet || !io::stdin().is_terminal() {
        print_error_line(
            global,
            format_args!("password prompt requires an interactive terminal; use --password-stdin"),
        );
        return Err(ExitCode::from(2));
    }
    let prompt = if format == ArchiveFormat::SevenZ {
        "7z password: "
    } else {
        "ZIP password: "
    };
    prompt_password(prompt).map(Some)
}

fn prompt_password_from_stdin(global: Option<&GlobalOptions>) -> Result<SecretString, ExitCode> {
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

fn new_extract_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(EXTRACT_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    new_extract_command_from_expanded(&expanded, global)
}

fn new_extract_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(EXTRACT_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = ExtractRequest::default();
    match parse_extract_request(args, &mut global, &mut request) {
        Ok(()) => run_extract_request(request, &global),
        Err(error) => command_usage_error("extract", &error, &global),
    }
}

fn parse_extract_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut ExtractRequest,
) -> Result<(), String> {
    let mut index = 0usize;
    let mut positional = Vec::new();
    let mut after_double_dash = false;
    while index < args.len() {
        let arg = &args[index];
        if after_double_dash {
            positional.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            index += 1;
            continue;
        }
        if parse_global_option(args, &mut index, global)? {
            continue;
        }
        match arg.as_str() {
            "-x" | "--extract" => index += 1,
            "-f" | "--file" => request.archive = take_value(args, &mut index, arg)?,
            "-C" | "-d" | "--directory" => {
                request.destination = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--here" => {
                request.destination = Some(env::current_dir().map_err(|error| error.to_string())?);
                index += 1;
            }
            "--overwrite" => {
                request.overwrite = Some(take_value(args, &mut index, arg)?);
            }
            "--strip-components" => {
                let value = take_value(args, &mut index, arg)?;
                request.strip_components = parse_usize(&value, arg)?;
            }
            "-i" | "--include" => {
                request.include.push(take_value(args, &mut index, arg)?);
            }
            "--exclude" => {
                request.exclude.push(take_value(args, &mut index, arg)?);
            }
            "--to-stdout" => {
                request.to_stdout = true;
                index += 1;
            }
            "--extract-nested" => {
                request.extract_nested = true;
                index += 1;
            }
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown extract option: {arg}")),
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
    if request.destination.is_none()
        && let Some(destination) = positional.get(1)
    {
        request.destination = Some(PathBuf::from(destination));
    }
    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    Ok(())
}

fn run_extract_request(request: ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if request.to_stdout {
        return run_extract_to_stdout(request, global);
    }
    let policy = match extraction_policy(&request) {
        Ok(policy) => policy,
        Err(error) => return command_usage_error("extract", &error, global),
    };
    if request.extract_nested {
        if request.password_stdin {
            return usage_failure(
                global,
                format_args!("extract failed: nested package extraction does not use passwords"),
            );
        }
        if !is_deb_archive(&request.archive) {
            return usage_failure(
                global,
                format_args!(
                    "extract failed: --extract-nested is currently supported only for .deb packages"
                ),
            );
        }
        let destination = request
            .destination
            .unwrap_or_else(|| default_extract_destination(&request.archive));
        return run_deb_nested_extract(&request.archive, &destination, policy, global);
    }
    if let Some(format) =
        zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive)
    {
        if request.password_stdin {
            return usage_failure(
                global,
                format_args!(
                    "extract failed: raw streams are not encrypted; remove --password-stdin"
                ),
            );
        }
        let destination = request
            .destination
            .unwrap_or_else(|| default_raw_stream_destination(&request.archive));
        return run_raw_stream_extract(&request.archive, format, &destination, policy, global);
    }
    let destination = request
        .destination
        .unwrap_or_else(|| default_extract_destination(&request.archive));
    if is_zip_family_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "ZIP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_zip_extract_with_policy(
            request.archive,
            destination,
            password.as_deref(),
            policy,
            global.no_password_prompt,
            Some(global),
        )
    } else if is_7z_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "7z", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_7z_extract_with_policy(
            request.archive,
            destination,
            password.as_deref(),
            policy,
            global.no_password_prompt,
            Some(global),
        )
    } else if is_rar_archive(&request.archive) && request.password_stdin {
        let password = match read_optional_password_stdin(request.password_stdin, "RAR", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_rar_extract_with_policy(
            request.archive,
            destination,
            policy,
            password.as_deref(),
            Some(global),
        )
    } else if is_tar_zst_archive(&request.archive) {
        run_tar_zst_extract_with_policy(request.archive, destination, policy, Some(global))
    } else {
        let password = match read_optional_password_stdin(request.password_stdin, "archive", global)
        {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_libarchive_extract_with_policy(
            request.archive,
            destination,
            policy,
            password.as_deref(),
            Some(global),
        )
    }
}

fn run_deb_nested_extract(
    archive: &str,
    destination: &Path,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::deb_backend::extract_deb_nested_with_overwrite_resolver(
            archive,
            destination,
            policy,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::deb_backend::extract_deb_nested(archive, destination, policy)
    };
    match result {
        Ok(report) => {
            let outcome = ExtractOutcome {
                label: "deb nested",
                format: FORMAT_DEB,
                backend: BACKEND_DEB_NESTED,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(Path::new(archive), destination, &outcome, Some(global));
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("extract failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_raw_stream_extract(
    archive: &str,
    format: zmanager_core::raw_stream_backend::RawStreamFormat,
    destination: &Path,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::raw_stream_backend::extract_raw_stream_with_overwrite_resolver(
            archive,
            format,
            destination,
            policy,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::raw_stream_backend::extract_raw_stream(archive, format, destination, policy)
    };
    match result {
        Ok(report) => {
            print_raw_stream_extract_summary(Path::new(archive), format, &report, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("extract failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_extract_to_stdout(request: ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if request.extract_nested {
        print_error_line(
            global,
            format_args!("extract failed: --extract-nested cannot be combined with --to-stdout"),
        );
        return ExitCode::from(2);
    }
    if request.destination.is_some() {
        print_error_line(
            global,
            format_args!(
                "extract failed: --to-stdout cannot be combined with an extraction directory"
            ),
        );
        return ExitCode::from(2);
    }
    if request.strip_components > 0 {
        print_error_line(
            global,
            format_args!("extract failed: --strip-components is not meaningful with --to-stdout"),
        );
        return ExitCode::from(2);
    }

    let mut stdout = io::stdout().lock();
    if is_zip_family_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "ZIP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::zip_backend::copy_zip_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired)
                if password.is_none() =>
            {
                if global.no_password_prompt {
                    print_error_line(
                        global,
                        format_args!(
                            "extract to stdout failed: password required and prompts are disabled"
                        ),
                    );
                    return ExitCode::from(2);
                }
                let password = match prompt_password("ZIP password: ") {
                    Ok(password) => password,
                    Err(code) => return code,
                };
                let retry = ExtractRequest {
                    password_stdin: false,
                    ..request
                };
                match zmanager_core::zip_backend::copy_zip_files_to_writer(
                    &retry.archive,
                    Some(password.expose_secret()),
                    |name| entry_selected(name, &retry.include, &retry.exclude),
                    &mut stdout,
                ) {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        print_error_line(global, format_args!("extract to stdout failed: {error}"));
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_tar_zst_archive(&request.archive) {
        match zmanager_core::tar_zst_backend::copy_tar_zst_files_to_writer(
            &request.archive,
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_7z_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "7z", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::sevenz_backend::copy_7z_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired)
                if password.is_none() =>
            {
                if global.no_password_prompt {
                    print_error_line(
                        global,
                        format_args!(
                            "extract to stdout failed: password required and prompts are disabled"
                        ),
                    );
                    return ExitCode::from(2);
                }
                let password = match prompt_password("7z password: ") {
                    Ok(password) => password,
                    Err(code) => return code,
                };
                let retry = ExtractRequest {
                    password_stdin: false,
                    ..request
                };
                match zmanager_core::sevenz_backend::copy_7z_files_to_writer(
                    &retry.archive,
                    Some(password.expose_secret()),
                    |name| entry_selected(name, &retry.include, &retry.exclude),
                    &mut stdout,
                ) {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        print_error_line(global, format_args!("extract to stdout failed: {error}"));
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if let Some(format) =
        zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive)
    {
        if request.password_stdin {
            print_error_line(
                global,
                format_args!(
                    "extract to stdout failed: raw streams are not encrypted; remove --password-stdin"
                ),
            );
            return ExitCode::from(2);
        }
        let Some(output_name) =
            zmanager_core::raw_stream_backend::output_name_for_raw_stream(&request.archive, format)
        else {
            print_error_line(
                global,
                format_args!("extract to stdout failed: could not derive raw stream output name"),
            );
            return ExitCode::FAILURE;
        };
        if !entry_selected(&output_name, &request.include, &request.exclude) {
            if global.verbose > 0 && !global.quiet {
                output::stderr_line(
                    global.color,
                    format_args!(
                        "{} to stdout ok: 0 entries, 1 skipped, 0 bytes",
                        output::styled(StyleRole::Success, format_args!("extract"))
                    ),
                );
            }
            return ExitCode::SUCCESS;
        }
        match zmanager_core::raw_stream_backend::copy_raw_stream_to_writer(
            &request.archive,
            format,
            &mut stdout,
        ) {
            Ok(written_bytes) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: 1 entry, 0 skipped, {written_bytes} bytes",
                            output::styled(StyleRole::Success, format_args!("extract"))
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else {
        let password = match read_optional_password_stdin(request.password_stdin, "archive", global)
        {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::libarchive_backend::copy_archive_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    }
}

fn extraction_policy(
    request: &ExtractRequest,
) -> Result<zmanager_core::safety::ExtractionPolicy, String> {
    let overwrite = match request.overwrite.as_deref().unwrap_or("never") {
        "never" => OverwritePolicy::Refuse,
        "always" => OverwritePolicy::Replace,
        "rename" => OverwritePolicy::Rename,
        "ask" if io::stdin().is_terminal() => OverwritePolicy::Ask,
        "ask" => return Err("--overwrite ask requires an interactive terminal".to_owned()),
        value => return Err(format!("unsupported overwrite policy: {value}")),
    };

    Ok(zmanager_core::safety::ExtractionPolicy {
        overwrite,
        include_patterns: request.include.clone(),
        exclude_patterns: request.exclude.clone(),
        strip_components: request.strip_components,
        ..zmanager_core::safety::ExtractionPolicy::default()
    })
}

fn new_list_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(LIST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    new_list_command_from_expanded(&expanded, global)
}

fn new_list_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn parse_list_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut ListRequest,
) -> Result<(), String> {
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

fn run_list_request(request: &ListRequest, global: &GlobalOptions) -> ExitCode {
    if request.password_stdin
        && zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some()
    {
        print_error_line(
            global,
            format_args!("list failed: raw streams are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    let password = match if request.password_stdin {
        Some(prompt_password_from_stdin(Some(global)))
    } else {
        None
    } {
        Some(Ok(password)) => Some(password),
        Some(Err(code)) => return code,
        None => None,
    };
    match list_entries_with_password(&request.archive, password.as_deref()) {
        Ok(mut entries) => {
            filter_entries(&mut entries, &request.include, &request.exclude);
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
                    format_args!(
                        "{}",
                        output::styled(
                            StyleRole::Heading,
                            format_args!("TYPE\tSIZE\tCOMPRESSED\tPATH")
                        )
                    ),
                );
                for entry in entries {
                    output::stdout_line(
                        global.color,
                        format_args!(
                            "{}\t{}\t{}\t{}",
                            output::styled(StyleRole::Label, format_args!("{}", entry.kind)),
                            entry.size,
                            entry
                                .compressed_size
                                .map_or_else(|| "-".to_owned(), |size| size.to_string()),
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

fn new_test_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(TEST_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    new_test_command_from_expanded(&expanded, global)
}

fn new_test_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn parse_test_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut TestRequest,
) -> Result<(), String> {
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

fn run_test_request(request: &TestRequest, global: &GlobalOptions) -> ExitCode {
    if request.password_stdin
        && zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some()
    {
        print_error_line(
            global,
            format_args!("test failed: raw streams are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    let password = match if request.password_stdin {
        Some(prompt_password_from_stdin(Some(global)))
    } else {
        None
    } {
        Some(Ok(password)) => Some(password),
        Some(Err(code)) => return code,
        None => None,
    };

    if is_zip_family_archive(&request.archive) {
        return run_zip_test_new(
            &request.archive,
            password.as_deref(),
            &request.include,
            &request.exclude,
            global,
        );
    }
    if let Some(format) =
        zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive)
    {
        if password.is_some() {
            print_error_line(
                global,
                format_args!("test failed: raw streams are not encrypted; remove --password-stdin"),
            );
            return ExitCode::from(2);
        }
        return run_raw_stream_test(
            &request.archive,
            format,
            &request.include,
            &request.exclude,
            global,
        );
    }
    if is_tar_zst_archive(&request.archive) {
        return run_tar_zst_test_new(&request.archive, &request.include, &request.exclude, global);
    }
    if is_7z_archive(&request.archive) {
        return run_7z_test_new(
            &request.archive,
            password.as_deref(),
            &request.include,
            &request.exclude,
            global,
        );
    }

    match list_entries_with_password(&request.archive, password.as_deref()) {
        Ok(mut entries) => {
            let total_entries = entries.len();
            filter_entries(&mut entries, &request.include, &request.exclude);
            let skipped_entries = total_entries.saturating_sub(entries.len());
            if global.json {
                println!(
                    "{{\"status\":\"ok\",\"entries\":{},\"tested_entries\":{},\"skipped_entries\":{},\"archive\":\"{}\"}}",
                    entries.len(),
                    entries.len(),
                    skipped_entries,
                    json_escape(&request.archive)
                );
            } else if skipped_entries == 0 {
                print_success_line(
                    global,
                    format_args!("archive readable: {} entries", entries.len()),
                );
            } else {
                print_success_line(
                    global,
                    format_args!(
                        "archive readable: {} entries, {} skipped",
                        entries.len(),
                        skipped_entries
                    ),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_tar_zst_test_new(
    archive: &str,
    includes: &[String],
    excludes: &[String],
    global: &GlobalOptions,
) -> ExitCode {
    let mut sink = io::sink();
    match zmanager_core::tar_zst_backend::copy_tar_zst_files_to_writer(
        archive,
        |name| entry_selected(name, includes, excludes),
        &mut sink,
    ) {
        Ok(report) => {
            print_data_test_success(
                FORMAT_TAR_ZST,
                report.written_entries,
                report.skipped_entries,
                report.written_bytes,
                global,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("tar.zst test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_7z_test_new(
    archive: &str,
    password: Option<&str>,
    includes: &[String],
    excludes: &[String],
    global: &GlobalOptions,
) -> ExitCode {
    let mut sink = io::sink();
    match zmanager_core::sevenz_backend::copy_7z_files_to_writer(
        archive,
        password,
        |name| entry_selected(name, includes, excludes),
        &mut sink,
    ) {
        Ok(report) => {
            print_data_test_success(
                FORMAT_SEVEN_Z,
                report.written_entries,
                report.skipped_entries,
                report.written_bytes,
                global,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("7z test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn print_data_test_success(
    format: &str,
    tested_entries: usize,
    skipped_entries: usize,
    bytes: u64,
    global: &GlobalOptions,
) {
    if global.json {
        println!(
            "{{\"status\":\"ok\",\"format\":\"{}\",\"entries\":{},\"tested_entries\":{},\"skipped_entries\":{},\"bytes\":{bytes}}}",
            json_escape(format),
            tested_entries,
            tested_entries,
            skipped_entries
        );
    } else if skipped_entries == 0 {
        print_success_line(
            global,
            format_args!("{format} test ok: {tested_entries} entries, {bytes} bytes"),
        );
    } else {
        print_success_line(
            global,
            format_args!(
                "{format} test ok: {tested_entries} entries, {skipped_entries} skipped, {bytes} bytes"
            ),
        );
    }
}

fn run_raw_stream_test(
    archive: &str,
    format: zmanager_core::raw_stream_backend::RawStreamFormat,
    includes: &[String],
    excludes: &[String],
    global: &GlobalOptions,
) -> ExitCode {
    let output_name =
        zmanager_core::raw_stream_backend::output_name_for_raw_stream(archive, format)
            .unwrap_or_else(|| archive.to_owned());
    if !entry_selected(&output_name, includes, excludes) {
        if global.json {
            println!(
                "{{\"status\":\"ok\",\"entries\":1,\"tested_entries\":0,\"skipped_entries\":1,\"archive\":\"{}\"}}",
                json_escape(archive)
            );
        } else {
            print_success_line(
                global,
                format_args!("archive readable: 0 entries, 1 skipped"),
            );
        }
        return ExitCode::SUCCESS;
    }
    match zmanager_core::raw_stream_backend::test_raw_stream(archive, format) {
        Ok(bytes) => {
            if global.json {
                println!(
                    "{{\"status\":\"ok\",\"entries\":1,\"tested_entries\":1,\"skipped_entries\":0,\"bytes\":{bytes},\"archive\":\"{}\"}}",
                    json_escape(archive)
                );
            } else {
                print_success_line(
                    global,
                    format_args!("archive readable: 1 entry, {bytes} bytes"),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_zip_test_new(
    archive: &str,
    password: Option<&str>,
    includes: &[String],
    excludes: &[String],
    global: &GlobalOptions,
) -> ExitCode {
    match zmanager_core::zip_backend::test_zip_with_password_filter(archive, password, |name| {
        entry_selected(name, includes, excludes)
    }) {
        Ok(report) => {
            if global.json {
                println!(
                    "{{\"status\":\"ok\",\"entries\":{},\"tested_entries\":{},\"skipped_entries\":{},\"bytes\":{}}}",
                    report.tested_entries,
                    report.tested_entries,
                    report.skipped_entries,
                    report.tested_bytes
                );
            } else if report.skipped_entries == 0 {
                print_success_line(
                    global,
                    format_args!(
                        "zip test ok: {} entries, {} bytes",
                        report.tested_entries, report.tested_bytes
                    ),
                );
            } else {
                print_success_line(
                    global,
                    format_args!(
                        "zip test ok: {} entries, {} skipped, {} bytes",
                        report.tested_entries, report.skipped_entries, report.tested_bytes
                    ),
                );
            }
            ExitCode::SUCCESS
        }
        Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired)
            if password.is_none() =>
        {
            if global.no_password_prompt {
                print_error_line(
                    global,
                    format_args!("zip test failed: password required and prompts are disabled"),
                );
                return ExitCode::from(2);
            }
            let password = match prompt_password("ZIP password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_zip_test_new(
                archive,
                Some(password.expose_secret()),
                includes,
                excludes,
                global,
            )
        }
        Err(error) => {
            print_error_line(global, format_args!("zip test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn new_plan_command(args: &[String], global: GlobalOptions) -> ExitCode {
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

fn parse_plan_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut PlanRequest,
) -> Result<(), String> {
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
            "--exclude-from" => request
                .exclude_from
                .push(PathBuf::from(take_value(args, &mut index, arg)?)),
            "--" => {
                for value in &args[index + 1..] {
                    request
                        .sources
                        .push(resolve_input_path(value, current_dir.as_deref()));
                }
                break;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown plan option: {arg}")),
            _ => {
                request
                    .sources
                    .push(resolve_input_path(arg, current_dir.as_deref()));
                index += 1;
            }
        }
    }
    append_files_from(
        &mut request.sources,
        &request.files_from,
        request.null_paths,
    )?;
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
            if let Err(error) = apply_manifest_filters(
                &mut manifest,
                &request.include,
                &request.exclude,
                &request.exclude_from,
            ) {
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

fn parse_global_option(
    args: &[String],
    index: &mut usize,
    global: &mut GlobalOptions,
) -> Result<bool, String> {
    match args[*index].as_str() {
        "--json" => global.json = true,
        "-q" | "--quiet" => global.quiet = true,
        "-v" | "--verbose" => global.verbose = global.verbose.saturating_add(1),
        "--no-color" => global.color = OutputMode::Never,
        "--no-progress" => global.progress = OutputMode::Never,
        "--no-password-prompt" => global.no_password_prompt = true,
        "--color" | "--progress" => {
            let option = args[*index].clone();
            let mode = parse_output_mode(&take_value(args, index, &option)?, &option)?;
            if option == "--color" {
                global.color = mode;
            } else {
                global.progress = mode;
            }
            return Ok(true);
        }
        _ => return Ok(false),
    }
    *index += 1;
    Ok(true)
}

fn parse_output_mode(value: &str, option: &str) -> Result<OutputMode, String> {
    match value {
        "auto" => Ok(OutputMode::Auto),
        "always" => Ok(OutputMode::Always),
        "never" => Ok(OutputMode::Never),
        _ => Err(format!(
            "invalid value for {option}: {value}; expected auto, always, or never"
        )),
    }
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    let value_index = index.saturating_add(1);
    let Some(value) = args.get(value_index) else {
        return Err(format!("missing value for {option}"));
    };
    *index += 2;
    Ok(value.clone())
}

fn parse_i32(value: &str, option: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("invalid integer for {option}: {value}"))
}

fn parse_usize(value: &str, option: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid integer for {option}: {value}"))
}

fn parse_archive_format(raw: &str) -> Result<ArchiveFormat, String> {
    match raw {
        FORMAT_ZIP => Ok(ArchiveFormat::Zip),
        raw if TAR_ZST_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::TarZst),
        FORMAT_SEVEN_Z => Ok(ArchiveFormat::SevenZ),
        _ => Err(format!("unsupported archive format: {raw}")),
    }
}

fn infer_create_format(path: &str) -> Option<ArchiveFormat> {
    if path == "-" {
        return None;
    }
    if is_zip_family_archive(path) {
        Some(ArchiveFormat::Zip)
    } else if is_tar_zst_archive(path) {
        Some(ArchiveFormat::TarZst)
    } else if is_7z_archive(path) {
        Some(ArchiveFormat::SevenZ)
    } else {
        None
    }
}

fn resolve_input_path(value: &str, current_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else if let Some(current_dir) = current_dir {
        current_dir.join(path)
    } else {
        path
    }
}

fn append_files_from(
    sources: &mut Vec<PathBuf>,
    files_from: &[String],
    null_paths: bool,
) -> Result<(), String> {
    for list in files_from {
        if list == "-" {
            append_stdin_paths(sources, null_paths)?;
        } else {
            let bytes =
                fs::read(list).map_err(|error| format!("failed to read {list}: {error}"))?;
            append_path_bytes(sources, &bytes, null_paths)?;
        }
    }
    Ok(())
}

fn append_stdin_paths(sources: &mut Vec<PathBuf>, null_paths: bool) -> Result<(), String> {
    let mut bytes = Vec::new();
    io::read_to_string(io::stdin())
        .map(|value| bytes = value.into_bytes())
        .map_err(|error| format!("failed to read path list from stdin: {error}"))?;
    append_path_bytes(sources, &bytes, null_paths)
}

fn append_path_bytes(
    sources: &mut Vec<PathBuf>,
    bytes: &[u8],
    null_paths: bool,
) -> Result<(), String> {
    if null_paths {
        for part in bytes.split(|byte| *byte == 0) {
            if part.is_empty() {
                continue;
            }
            let value = std::str::from_utf8(part)
                .map_err(|error| format!("path list is not valid UTF-8: {error}"))?;
            sources.push(PathBuf::from(value));
        }
    } else {
        let value = std::str::from_utf8(bytes)
            .map_err(|error| format!("path list is not valid UTF-8: {error}"))?;
        for line in value.lines().filter(|line| !line.is_empty()) {
            sources.push(PathBuf::from(line));
        }
    }
    Ok(())
}

fn plan_sources(
    sources: &[PathBuf],
    clean: bool,
    no_ignore: bool,
    follow_symlinks: bool,
) -> Result<zmanager_core::manifest::ArchiveManifest, zmanager_core::manifest::PlanError> {
    let mut options = if clean {
        zmanager_core::manifest::PlanOptions::clean_source()
    } else {
        zmanager_core::manifest::PlanOptions::default()
    };
    if no_ignore {
        options.default_exclusions = false;
        options.clean_source_exclusions = false;
        options.respect_gitignore = false;
    }
    options.follow_symlinks = follow_symlinks;
    zmanager_core::manifest::plan_archives(sources, &options)
}

fn manifest_has_symlinks(manifest: &zmanager_core::manifest::ArchiveManifest) -> bool {
    manifest
        .entries
        .iter()
        .any(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::Symlink)
}

fn apply_manifest_filters(
    manifest: &mut zmanager_core::manifest::ArchiveManifest,
    includes: &[String],
    excludes: &[String],
    exclude_from: &[PathBuf],
) -> Result<(), String> {
    let mut exclude_patterns = excludes.to_vec();
    for file in exclude_from {
        let contents = fs::read_to_string(file)
            .map_err(|error| format!("failed to read {}: {error}", file.display()))?;
        exclude_patterns.extend(
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned),
        );
    }

    manifest
        .entries
        .retain(|entry| entry_selected(&entry.archive_path, includes, &exclude_patterns));
    manifest.total_bytes = manifest
        .entries
        .iter()
        .filter(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::File)
        .map(|entry| entry.size)
        .sum();
    Ok(())
}

fn apply_junk_paths(manifest: &mut zmanager_core::manifest::ArchiveManifest) -> Result<(), String> {
    let mut seen = HashMap::new();
    let mut flattened = Vec::new();

    for mut entry in std::mem::take(&mut manifest.entries) {
        if entry.file_type == zmanager_core::manifest::ManifestFileType::Directory {
            continue;
        }

        let Some(name) = entry
            .archive_path
            .trim_end_matches('/')
            .rsplit('/')
            .find(|part| !part.is_empty())
            .map(ToOwned::to_owned)
        else {
            return Err(format!(
                "cannot derive junk path for archive entry {}",
                entry.archive_path
            ));
        };
        let source_path = entry.source_path.display().to_string();
        if let Some(previous) = seen.insert(name.clone(), source_path.clone()) {
            return Err(format!(
                "duplicate junk path {name}: {previous} and {source_path} both flatten to {name}"
            ));
        }
        entry.archive_path = name;
        flattened.push(entry);
    }

    flattened.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    manifest.entries = flattened;
    manifest.total_bytes = manifest
        .entries
        .iter()
        .filter(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::File)
        .map(|entry| entry.size)
        .sum();
    Ok(())
}

fn archive_pattern_matches(pattern: &str, path: &str) -> bool {
    pattern == path
        || (pattern.ends_with("/**") && path.starts_with(pattern.trim_end_matches("**")))
        || wildcard_matches(pattern.as_bytes(), path.as_bytes())
}

fn wildcard_matches(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern[0] == b'*' {
        return wildcard_matches(&pattern[1..], value)
            || (!value.is_empty() && wildcard_matches(pattern, &value[1..]));
    }
    if !value.is_empty() && (pattern[0] == b'?' || pattern[0] == value[0]) {
        return wildcard_matches(&pattern[1..], &value[1..]);
    }
    false
}

fn temp_archive_path(destination: &Path) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("archive");
    destination.with_file_name(format!(
        "{TEMP_ARCHIVE_PREFIX}{file_name}{TEMP_ARCHIVE_MARKER}-{}-{now}",
        std::process::id()
    ))
}

fn default_extract_destination(archive: &str) -> PathBuf {
    let path = Path::new(archive);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("archive");
    let stem = strip_known_archive_suffix(name).unwrap_or(name);
    path.parent().unwrap_or_else(|| Path::new(".")).join(stem)
}

fn strip_known_archive_suffix(name: &str) -> Option<&str> {
    TAR_ZST_EXTENSIONS
        .iter()
        .chain(ZIP_FAMILY_EXTENSIONS)
        .chain(SEVEN_Z_EXTENSIONS)
        .chain(RAR_EXTENSIONS)
        .chain(DEB_EXTENSIONS)
        .find_map(|suffix| strip_suffix_ignore_ascii_case(name, suffix))
}

fn default_raw_stream_destination(archive: &str) -> PathBuf {
    let path = Path::new(archive);
    let Some(parent) = path.parent() else {
        return PathBuf::from(".");
    };
    if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    }
}

fn read_optional_password_stdin(
    enabled: bool,
    label: &str,
    global: &GlobalOptions,
) -> Result<Option<SecretString>, ExitCode> {
    if enabled {
        prompt_password_from_stdin(Some(global)).map(Some)
    } else {
        let _ = label;
        Ok(None)
    }
}

fn list_entries_with_password(
    archive: &str,
    password: Option<&str>,
) -> Result<Vec<GenericEntry>, String> {
    if is_zip_family_archive(archive) {
        zmanager_core::zip_backend::list_zip(archive)
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: format!("{:?}", entry.kind).to_lowercase(),
                        name: entry.name,
                        size: entry.size,
                        compressed_size: Some(entry.compressed_size),
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    } else if is_7z_archive(archive) {
        zmanager_core::sevenz_backend::list_7z(archive, password)
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: format!("{:?}", entry.kind).to_lowercase(),
                        name: entry.name,
                        size: entry.size,
                        compressed_size: Some(entry.compressed_size),
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    } else if let Some(format) =
        zmanager_core::raw_stream_backend::detect_raw_stream_format(archive)
    {
        let name = zmanager_core::raw_stream_backend::output_name_for_raw_stream(archive, format)
            .ok_or_else(|| "could not derive raw stream output name".to_owned())?;
        let size = zmanager_core::raw_stream_backend::test_raw_stream(archive, format)
            .map_err(|error| error.to_string())?;
        let compressed_size = fs::metadata(archive).ok().map(|metadata| metadata.len());

        Ok(vec![GenericEntry {
            kind: "file".to_owned(),
            name,
            size,
            compressed_size,
        }])
    } else if is_rar_archive(archive) && password.is_some() {
        zmanager_core::rar_backend::list_rar_with_password(archive, password)
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: format!("{:?}", entry.kind).to_lowercase(),
                        name: entry.path,
                        size: entry.size,
                        compressed_size: None,
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    } else {
        zmanager_core::libarchive_backend::list_archive_with_password(archive, password)
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: format!("{:?}", entry.kind).to_lowercase(),
                        name: entry.path,
                        size: u64::try_from(entry.size).unwrap_or(0),
                        compressed_size: None,
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    }
}

fn filter_entries(entries: &mut Vec<GenericEntry>, includes: &[String], excludes: &[String]) {
    entries.retain(|entry| entry_selected(&entry.name, includes, excludes));
}

fn entry_selected(path: &str, includes: &[String], excludes: &[String]) -> bool {
    let matches_include = includes.is_empty()
        || includes
            .iter()
            .any(|pattern| archive_pattern_matches(pattern, path));
    let matches_exclude = excludes
        .iter()
        .any(|pattern| archive_pattern_matches(pattern, path));

    matches_include && !matches_exclude
}

fn print_entries_tree(entries: &[GenericEntry], global: &GlobalOptions) {
    let mut printed = BTreeSet::new();
    let mut names = entries.iter().collect::<Vec<_>>();
    names.sort_by(|left, right| left.name.cmp(&right.name));

    for entry in names {
        let trimmed = entry.name.trim_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        let parts = trimmed
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        for depth in 0..parts.len() {
            let prefix = parts[..=depth].join("/");
            if !printed.insert(prefix) {
                continue;
            }
            let is_leaf = depth + 1 == parts.len();
            let is_directory = !is_leaf || entry.kind == "directory";
            output::stdout_line(
                global.color,
                format_args!(
                    "{}{}{}",
                    "  ".repeat(depth),
                    output::styled(StyleRole::Path, format_args!("{}", parts[depth])),
                    if is_directory { "/" } else { "" }
                ),
            );
        }
    }
}

fn print_entries_json(entries: &[GenericEntry]) {
    print!("{{\"entries\":[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        match entry.compressed_size {
            Some(compressed_size) => print!(
                "{{\"kind\":\"{}\",\"name\":\"{}\",\"size\":{},\"compressed_size\":{}}}",
                json_escape(&entry.kind),
                json_escape(&entry.name),
                entry.size,
                compressed_size
            ),
            None => print!(
                "{{\"kind\":\"{}\",\"name\":\"{}\",\"size\":{},\"compressed_size\":null}}",
                json_escape(&entry.kind),
                json_escape(&entry.name),
                entry.size
            ),
        }
    }
    println!("]}}");
}

fn print_create_summary(archive: &Path, outcome: &CreateOutcome, global: &GlobalOptions) {
    if global.json {
        print_create_summary_json(archive, outcome);
    } else if !global.quiet {
        print_success_line(global, format_args!("{}", outcome.summary));
    }
}

fn print_create_summary_json(archive: &Path, outcome: &CreateOutcome) {
    print!(
        "{{\"status\":\"ok\",\"operation\":\"create\",\"archive\":\"{}\",\"format\":\"{}\",\"backend\":\"{}\",\"written_entries\":{},\"written_bytes\":{},\"warnings\":{}",
        json_escape(&archive.display().to_string()),
        json_escape(outcome.format),
        json_escape(outcome.backend),
        outcome.entries,
        outcome.bytes,
        outcome.warnings
    );
    if let Some(encrypted) = outcome.encrypted {
        print!(",\"encrypted\":{encrypted}");
    }
    if let Some(solid) = outcome.solid {
        print!(",\"solid\":{solid}");
    }
    println!("}}");
}

fn print_extract_summary(
    archive: &Path,
    destination: &Path,
    outcome: &ExtractOutcome,
    global: Option<&GlobalOptions>,
) {
    match global {
        Some(global) if global.json => print_extract_summary_json(archive, destination, outcome),
        Some(global) if global.quiet => {}
        Some(global) => print_extract_summary_text(outcome, global),
        None => {
            println!(
                "{} extract ok: {} written, {} skipped, {} bytes",
                outcome.label,
                outcome.written_entries,
                outcome.skipped_entries,
                outcome.written_bytes
            );
            for warning in &outcome.warnings {
                println!("warning\t{warning}");
            }
        }
    }
}

fn print_extract_summary_text(outcome: &ExtractOutcome, global: &GlobalOptions) {
    print_success_line(
        global,
        format_args!(
            "{} extract ok: {} written, {} skipped, {} bytes",
            outcome.label, outcome.written_entries, outcome.skipped_entries, outcome.written_bytes
        ),
    );
    for warning in &outcome.warnings {
        print_warning_stdout(global, format_args!("warning\t{warning}"));
    }
}

fn print_extract_summary_json(archive: &Path, destination: &Path, outcome: &ExtractOutcome) {
    println!(
        "{{\"status\":\"ok\",\"operation\":\"extract\",\"archive\":\"{}\",\"destination\":\"{}\",\"format\":\"{}\",\"backend\":\"{}\",\"written_entries\":{},\"skipped_entries\":{},\"written_bytes\":{},\"warnings\":{}}}",
        json_escape(&archive.display().to_string()),
        json_escape(&destination.display().to_string()),
        json_escape(outcome.format),
        json_escape(outcome.backend),
        outcome.written_entries,
        outcome.skipped_entries,
        outcome.written_bytes,
        outcome.warnings.len()
    );
}

fn print_raw_stream_extract_summary(
    archive: &Path,
    format: zmanager_core::raw_stream_backend::RawStreamFormat,
    report: &zmanager_core::raw_stream_backend::RawStreamExtractReport,
    global: &GlobalOptions,
) {
    if global.json {
        print!(
            "{{\"status\":\"ok\",\"operation\":\"extract\",\"archive\":\"{}\",\"format\":\"{}\",\"backend\":\"{}\",\"written_entries\":{},\"skipped_entries\":{},\"written_bytes\":{},\"warnings\":{},\"output_path\":",
            json_escape(&archive.display().to_string()),
            json_escape(format.name()),
            FORMAT_RAW_STREAM,
            usize::from(report.output_path.is_some()),
            report.skipped_entries,
            report.written_bytes,
            report.warnings.len()
        );
        match &report.output_path {
            Some(output_path) => print!("\"{}\"", json_escape(&output_path.display().to_string())),
            None => print!("null"),
        }
        println!("}}");
    } else if !global.quiet {
        if let Some(output_path) = &report.output_path {
            output::stdout_line(
                global.color,
                format_args!(
                    "{} {} stream: {} bytes -> {}",
                    output::styled(StyleRole::Success, format_args!("extracted")),
                    format.name(),
                    report.written_bytes,
                    output::styled(StyleRole::Path, format_args!("{}", output_path.display()))
                ),
            );
        } else {
            output::stdout_line(
                global.color,
                format_args!(
                    "{} {} stream: {} entries skipped",
                    output::styled(StyleRole::Success, format_args!("extracted")),
                    format.name(),
                    report.skipped_entries
                ),
            );
        }
        for warning in &report.warnings {
            print_warning_stdout(global, format_args!("warning\t{warning}"));
        }
    }
}

fn print_manifest(manifest: &zmanager_core::manifest::ArchiveManifest, global: &GlobalOptions) {
    if global.json {
        print!(
            "{{\"included_entries\":{},\"included_bytes\":{},\"excluded_entries\":{},\"excluded_bytes\":{},\"warnings\":{},\"entries\":[",
            manifest.included_count(),
            manifest.total_bytes,
            manifest.excluded_count(),
            manifest.excluded_bytes,
            manifest.warnings.len()
        );
        for (index, entry) in manifest.entries.iter().enumerate() {
            if index > 0 {
                print!(",");
            }
            print!(
                "{{\"path\":\"{}\",\"size\":{}}}",
                json_escape(&entry.archive_path),
                entry.size
            );
        }
        println!("]}}");
    } else {
        print_success_line(global, format_args!("{}", manifest.summary()));
        for entry in &manifest.entries {
            output::stdout_line(
                global.color,
                format_args!(
                    "{}\t{}\t{} bytes",
                    output::styled(StyleRole::Label, format_args!("include")),
                    output::styled(StyleRole::Path, format_args!("{}", entry.archive_path)),
                    entry.size
                ),
            );
        }
        for excluded in &manifest.excluded_entries {
            output::stdout_line(
                global.color,
                format_args!(
                    "{}\t{}\t{}\t{} bytes",
                    output::styled(StyleRole::Warning, format_args!("exclude")),
                    output::styled(StyleRole::Path, format_args!("{}", excluded.archive_path)),
                    excluded.reason,
                    excluded.size
                ),
            );
        }
        for warning in &manifest.warnings {
            print_warning_stdout(
                global,
                format_args!(
                    "warning\t{}\t{}",
                    warning.source_path.display(),
                    warning.message
                ),
            );
        }
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", ch as u32);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn command_usage_error(command: &str, message: &str, global: &GlobalOptions) -> ExitCode {
    let (formatted, unknown_option) = format_command_error(command, message);
    print_error_line(global, format_args!("error: {formatted}"));
    if let Some(option) = unknown_option
        && let Some(suggestion) = option_suggestion(command, option)
    {
        output::stderr_line(global.color, format_args!(""));
        output::stderr_line(
            global.color,
            format_args!(
                "Did you mean '{}'?",
                output::styled(StyleRole::Option, format_args!("{suggestion}"))
            ),
        );
    }
    output::stderr_line(global.color, format_args!(""));
    output::stderr_write(
        global.color,
        format_args!("{}", output::render_help(command_usage_snippet(command))),
    );
    output::stderr_line(global.color, format_args!(""));
    if unknown_option.is_some() {
        output::stderr_line(
            global.color,
            format_args!(
                "Try '{}' for usage.",
                output::styled(StyleRole::Command, format_args!("zm {command} --help"))
            ),
        );
    } else {
        output::stderr_line(
            global.color,
            format_args!(
                "Try '{}' for examples.",
                output::styled(StyleRole::Command, format_args!("zm {command} --help"))
            ),
        );
    }
    ExitCode::from(2)
}

fn format_command_error<'a>(command: &str, message: &'a str) -> (String, Option<&'a str>) {
    let prefix = format!("unknown {command} option: ");
    if let Some(option) = message.strip_prefix(&prefix) {
        (
            format!("unknown option '{option}' for 'zm {command}'"),
            Some(option),
        )
    } else if let Some(argument) = message.strip_prefix("unexpected argument: ") {
        (
            format!("unexpected argument '{argument}' for 'zm {command}'"),
            None,
        )
    } else {
        (message.to_owned(), None)
    }
}

fn command_usage_snippet(command: &str) -> &'static str {
    match command {
        "create" => {
            "\
Usage:
  zm create <archive> <paths...>
  zm -cf <archive> [create-options] <paths...>
"
        }
        "extract" => {
            "\
Usage:
  zm extract <archive> [-C dir]
  zm -xf <archive> [extract-options]
"
        }
        "list" => {
            "\
Usage:
  zm list <archive>
  zm -tf <archive> [list-options]
"
        }
        "test" => {
            "\
Usage:
  zm test <archive>
  zm -Tf <archive> [test-options]
"
        }
        "plan" => {
            "\
Usage:
  zm plan <paths...> [plan-options]
"
        }
        "formats" => {
            "\
Usage:
  zm formats [--json]
"
        }
        "doctor" => {
            "\
Usage:
  zm doctor [--json]
"
        }
        "completions" => {
            "\
Usage:
  zm completions <bash|zsh|fish|powershell>
"
        }
        _ => USAGE,
    }
}

fn option_suggestion(command: &str, unknown: &str) -> Option<&'static str> {
    let mut best = None;
    let mut best_distance = usize::MAX;
    for candidate in command_options(command) {
        let distance = levenshtein_distance(unknown, candidate);
        if distance < best_distance {
            best = Some(*candidate);
            best_distance = distance;
        }
    }
    if best_distance <= 3 { best } else { None }
}

const CREATE_OPTIONS: &[&str] = &[
    "-c",
    "--create",
    "-r",
    "--recursive",
    "--hidden",
    "--preserve-metadata",
    "-X",
    "--no-metadata",
    "-y",
    "--preserve-symlinks",
    "-f",
    "--file",
    "--format",
    "--method",
    "--level",
    "-0",
    "-1",
    "-2",
    "-3",
    "-4",
    "-5",
    "-6",
    "-7",
    "-8",
    "-9",
    "-C",
    "--directory",
    "-@",
    "--files-from",
    "--null",
    "-i",
    "--include",
    "--exclude",
    "--exclude-from",
    "--store",
    "--solid",
    "--no-solid",
    "--clean",
    "--no-ignore",
    "--no-hidden",
    "-j",
    "--junk-paths",
    "--follow-symlinks",
    "--force",
    "--encrypt",
    "--password-stdin",
    "--dry-run",
    "-T",
    "--test-after",
    "--test",
];

const EXTRACT_OPTIONS: &[&str] = &[
    "-x",
    "--extract",
    "-f",
    "--file",
    "-C",
    "-d",
    "--directory",
    "--here",
    "--overwrite",
    "--strip-components",
    "-i",
    "--include",
    "--exclude",
    "--to-stdout",
    "--extract-nested",
    "--password-stdin",
];

const LIST_OPTIONS: &[&str] = &[
    "-t",
    "--list",
    "-f",
    "--file",
    "-l",
    "--long",
    "--name-only",
    "--tree",
    "-i",
    "--include",
    "--exclude",
    "--password-stdin",
];

const TEST_OPTIONS: &[&str] = &[
    "-T",
    "--test",
    "-f",
    "--file",
    "-i",
    "--include",
    "--exclude",
    "--password-stdin",
];

const PLAN_OPTIONS: &[&str] = &[
    "--format",
    "-C",
    "--directory",
    "-@",
    "--files-from",
    "--null",
    "--clean",
    "--no-ignore",
    "-i",
    "--include",
    "--exclude",
    "--exclude-from",
];

const GLOBAL_COMMAND_OPTIONS: &[&str] = &["--json"];
const COMPLETIONS_OPTIONS: &[&str] = &["--help", "-h"];

fn command_options(command: &str) -> &'static [&'static str] {
    match command {
        "create" => CREATE_OPTIONS,
        "extract" => EXTRACT_OPTIONS,
        "list" => LIST_OPTIONS,
        "test" => TEST_OPTIONS,
        "plan" => PLAN_OPTIONS,
        "formats" | "doctor" => GLOBAL_COMMAND_OPTIONS,
        "completions" | "completion" => COMPLETIONS_OPTIONS,
        _ => &[],
    }
}

fn levenshtein_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut current = vec![0; right_chars.len() + 1];
    for (left_index, left_char) in left.chars().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_char) in right_chars.iter().enumerate() {
            let deletion = previous[right_index + 1] + 1;
            let insertion = current[right_index] + 1;
            let substitution = previous[right_index] + usize::from(left_char != *right_char);
            current[right_index + 1] = deletion.min(insertion).min(substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right_chars.len()]
}

fn usage_error(message: &str, global: &GlobalOptions) -> ExitCode {
    print_error_line(global, format_args!("{message}"));
    print_help_stderr(USAGE, global);
    ExitCode::from(2)
}

fn parse_zstd_level(raw: Option<String>) -> Result<i32, ExitCode> {
    match raw {
        None => Ok(zmanager_core::tar_zst_backend::TarZstdCreateOptions::default().level),
        Some(level) => level.parse::<i32>().map_err(|_| {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }),
    }
}

fn parse_zip_compression(raw: Option<&str>) -> Option<zmanager_core::zip_backend::ZipCompression> {
    match raw {
        None | Some("deflate") => Some(zmanager_core::zip_backend::ZipCompression::Deflate),
        Some("store") => Some(zmanager_core::zip_backend::ZipCompression::Store),
        Some(_) => None,
    }
}

fn parse_7z_solid(raw: Option<&str>) -> Option<bool> {
    match raw {
        None | Some("solid") => Some(true),
        Some("non-solid" | "nonsolid") => Some(false),
        Some(_) => None,
    }
}

fn password_arg_or_prompt(
    raw: Option<&str>,
    prompt: &str,
) -> Result<Option<SecretString>, ExitCode> {
    match raw {
        Some("-") => prompt_password(prompt).map(Some),
        Some(_) => {
            eprintln!("password arguments are disabled; use '-' to read from stdin");
            Err(ExitCode::from(2))
        }
        None => Ok(None),
    }
}

fn prompt_password(prompt: &str) -> Result<SecretString, ExitCode> {
    match rpassword::prompt_password(prompt) {
        Ok(password) => {
            if password.is_empty() {
                eprintln!("password prompt cancelled");
                return Err(ExitCode::FAILURE);
            }
            Ok(SecretString::from(password))
        }
        Err(error) => {
            eprintln!("failed to read password: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn normalize_prompted_password(mut password: String, bytes_read: usize) -> Option<String> {
    if bytes_read == 0 {
        return None;
    }

    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }

    (!password.is_empty()).then_some(password)
}

fn is_zip_family_archive(path: &str) -> bool {
    path_has_known_extension(path, ZIP_FAMILY_EXTENSIONS)
}

fn is_7z_archive(path: &str) -> bool {
    path_has_known_extension(path, SEVEN_Z_EXTENSIONS)
}

fn is_rar_archive(path: &str) -> bool {
    path_has_known_extension(path, RAR_EXTENSIONS)
}

fn is_tar_zst_archive(path: &str) -> bool {
    path_has_known_extension(path, TAR_ZST_EXTENSIONS)
}

fn is_deb_archive(path: &str) -> bool {
    path_has_known_extension(path, DEB_EXTENSIONS)
}

fn path_has_known_extension(path: &str, extensions: &[&str]) -> bool {
    extensions
        .iter()
        .any(|extension| path_ends_with_ignore_ascii_case(path, extension))
}

fn path_ends_with_ignore_ascii_case(path: &str, suffix: &str) -> bool {
    let path = path.as_bytes();
    let suffix = suffix.as_bytes();
    path.len() >= suffix.len() && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn strip_suffix_ignore_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    if path_ends_with_ignore_ascii_case(value, suffix) {
        value.get(..value.len() - suffix.len())
    } else {
        None
    }
}

#[allow(dead_code)]
fn list_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    if is_zip_family_archive(&archive) {
        run_zip_list(archive)
    } else if is_7z_archive(&archive) {
        run_7z_list(archive, None)
    } else {
        run_libarchive_list(archive)
    }
}

#[allow(dead_code)]
fn extract_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    if is_zip_family_archive(&archive) {
        run_zip_extract(archive, destination, None)
    } else if is_7z_archive(&archive) {
        run_7z_extract(archive, destination, None)
    } else if is_tar_zst_archive(&archive) {
        run_tar_zst_extract(archive, destination)
    } else {
        run_libarchive_extract(archive, destination)
    }
}

fn job_zip_create_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(compression) = parse_zip_compression(args.next().as_deref()) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "ZIP password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level: None,
        preserve_metadata: true,
        password,
    };
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = |event| println!("event\t{event:?}");
    match zmanager_core::jobs::run_zip_create_job(source, destination, &options, &token, &mut sink)
    {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("job zip create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn job_tar_zst_create_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let level = match parse_zstd_level(args.next()) {
        Ok(level) => level,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let options = zmanager_core::tar_zst_backend::TarZstdCreateOptions {
        level,
        ..zmanager_core::tar_zst_backend::TarZstdCreateOptions::default()
    };
    let token = zmanager_core::jobs::CancellationToken::new();
    let mut sink = |event| println!("event\t{event:?}");
    match zmanager_core::jobs::run_tar_zst_create_job(
        source,
        destination,
        &options,
        &token,
        &mut sink,
    ) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("job tar.zst create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn zip_create_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(compression) = parse_zip_compression(args.next().as_deref()) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "ZIP password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level: None,
        preserve_metadata: true,
        password,
    };
    match zmanager_core::zip_backend::create_zip_from_path(source, destination, &options) {
        Ok(report) => {
            println!(
                "created zip: {} entries, {} bytes, encrypted {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.encrypted,
                report.warnings.len()
            );
            for warning in report.warnings {
                println!("warning\t{warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("zip create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn zip_create_stream_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(compression) = parse_zip_compression(args.next().as_deref()) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level: None,
        preserve_metadata: true,
        password: None,
    };
    let stdout = io::stdout();
    let output = stdout.lock();
    match zmanager_core::zip_backend::create_zip_stream_from_path(source, output, &options) {
        Ok((_output, report)) => {
            eprintln!(
                "created streaming zip: {} entries, {} bytes, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.warnings.len()
            );
            for warning in report.warnings {
                eprintln!("warning\t{warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("zip stream create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn zip_list_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_zip_list(archive)
}

fn run_zip_list(archive: impl AsRef<std::path::Path>) -> ExitCode {
    match zmanager_core::zip_backend::list_zip(archive) {
        Ok(listing) => {
            println!("zip entries: {}", listing.entries.len());
            for entry in listing.entries {
                println!(
                    "{:?}\t{}\t{} bytes\t{} compressed",
                    entry.kind, entry.name, entry.size, entry.compressed_size
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("zip list failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn zip_test_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "ZIP password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_zip_test(archive, password.as_deref())
}

fn run_zip_test(archive: impl AsRef<std::path::Path>, password: Option<&str>) -> ExitCode {
    match zmanager_core::zip_backend::test_zip_with_password(archive.as_ref(), password) {
        Ok(report) => {
            println!(
                "zip test ok: {} entries, {} bytes",
                report.tested_entries, report.tested_bytes
            );
            ExitCode::SUCCESS
        }
        Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired)
            if password.is_none() =>
        {
            let password = match prompt_password("ZIP password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_zip_test(archive, Some(password.expose_secret()))
        }
        Err(error) => {
            eprintln!("zip test failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn zip_extract_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "ZIP password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_zip_extract(archive, destination, password.as_deref())
}

fn run_zip_extract(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
) -> ExitCode {
    run_zip_extract_with_policy(
        archive,
        destination,
        password,
        zmanager_core::safety::ExtractionPolicy::default(),
        false,
        None,
    )
}

fn run_zip_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    no_password_prompt: bool,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::ZipExtract,
        total_bytes: None,
    });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::zip_backend::extract_zip_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy.clone(),
            password,
            &mut overwrite_resolver,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        zmanager_core::zip_backend::extract_zip_with_context_and_password(
            &archive_path,
            &destination_path,
            policy.clone(),
            password,
            &mut context,
        )
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_ZIP,
                format: FORMAT_ZIP,
                backend: FORMAT_ZIP,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired)
            if password.is_none() =>
        {
            if no_password_prompt {
                let message = "zip extract failed: password required and prompts are disabled";
                progress.emit(JobEvent::Failed {
                    message: message.to_owned(),
                });
                eprintln!("{message}");
                return ExitCode::from(2);
            }
            let password = match prompt_password("ZIP password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_zip_extract_with_policy(
                archive,
                destination,
                Some(password.expose_secret()),
                policy,
                no_password_prompt,
                global,
            )
        }
        Err(error) => {
            progress.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            eprintln!("zip extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn tar_zst_create_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let level = match parse_zstd_level(args.next()) {
        Ok(level) => level,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let options = zmanager_core::tar_zst_backend::TarZstdCreateOptions {
        level,
        ..zmanager_core::tar_zst_backend::TarZstdCreateOptions::default()
    };
    match zmanager_core::tar_zst_backend::create_tar_zst_from_path(source, destination, &options) {
        Ok(report) => {
            println!(
                "created tar.zst: {} entries, {} bytes, level {}, threads {:?}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.level,
                report.threads,
                report.warnings.len()
            );
            for warning in report.warnings {
                println!("warning\t{warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("tar.zst create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn tar_zst_extract_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_tar_zst_extract(archive, destination)
}

fn run_tar_zst_extract(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
) -> ExitCode {
    run_tar_zst_extract_with_policy(
        archive,
        destination,
        zmanager_core::safety::ExtractionPolicy::default(),
        None,
    )
}

fn run_tar_zst_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::TarZstdExtract,
        total_bytes: None,
    });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::tar_zst_backend::extract_tar_zst_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            policy,
            &mut overwrite_resolver,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        zmanager_core::tar_zst_backend::extract_tar_zst_with_context(
            &archive_path,
            &destination_path,
            policy,
            &mut context,
        )
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_TAR_ZST,
                format: FORMAT_TAR_ZST,
                backend: FORMAT_TAR_ZST,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            eprintln!("tar.zst extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn seven_z_create_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(source) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(solid) = parse_7z_solid(args.next().as_deref()) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "7z password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_7z_create(source, destination, solid, password)
}

fn run_7z_create(
    source: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    solid: bool,
    password: Option<SecretString>,
) -> ExitCode {
    let options = zmanager_core::sevenz_backend::SevenZCreateOptions {
        solid,
        level: None,
        preserve_metadata: true,
        password,
    };
    match zmanager_core::sevenz_backend::create_7z_from_path(source, destination, &options) {
        Ok(report) => {
            println!(
                "created 7z: {} entries, {} bytes, solid {}, encrypted {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.solid,
                report.encrypted,
                report.warnings.len()
            );
            for warning in report.warnings {
                println!("warning\t{warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("7z create failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn seven_z_list_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "7z password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_7z_list(archive, password.as_deref())
}

fn run_7z_list(archive: impl AsRef<std::path::Path>, password: Option<&str>) -> ExitCode {
    match zmanager_core::sevenz_backend::list_7z(archive.as_ref(), password) {
        Ok(listing) => {
            println!(
                "7z entries: {}, solid {}",
                listing.entries.len(),
                listing.solid
            );
            for entry in listing.entries {
                println!(
                    "{:?}\t{}\t{} bytes\t{} compressed",
                    entry.kind, entry.name, entry.size, entry.compressed_size
                );
            }
            ExitCode::SUCCESS
        }
        Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired) if password.is_none() => {
            let password = match prompt_password("7z password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_7z_list(archive, Some(password.expose_secret()))
        }
        Err(error) => {
            eprintln!("7z list failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn seven_z_extract_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let raw_password = args.next();
    let password = match password_arg_or_prompt(raw_password.as_deref(), "7z password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_7z_extract(archive, destination, password.as_deref())
}

fn run_7z_extract(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
) -> ExitCode {
    run_7z_extract_with_policy(
        archive,
        destination,
        password,
        zmanager_core::safety::ExtractionPolicy::default(),
        false,
        None,
    )
}

fn run_7z_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    no_password_prompt: bool,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::SevenZExtract,
        total_bytes: None,
    });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::sevenz_backend::extract_7z_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            password,
            policy.clone(),
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::sevenz_backend::extract_7z(
            &archive_path,
            &destination_path,
            password,
            policy.clone(),
        )
    };
    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_SEVEN_Z,
                format: FORMAT_SEVEN_Z,
                backend: FORMAT_SEVEN_Z,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired) if password.is_none() => {
            if no_password_prompt {
                let message = "7z extract failed: password required and prompts are disabled";
                progress.emit(JobEvent::Failed {
                    message: message.to_owned(),
                });
                eprintln!("{message}");
                return ExitCode::from(2);
            }
            let password = match prompt_password("7z password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_7z_extract_with_policy(
                archive,
                destination,
                Some(password.expose_secret()),
                policy,
                no_password_prompt,
                global,
            )
        }
        Err(error) => {
            progress.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            eprintln!("7z extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn libarchive_list_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_libarchive_list(archive)
}

fn run_libarchive_list(archive: impl AsRef<std::path::Path>) -> ExitCode {
    match zmanager_core::libarchive_backend::list_archive(archive) {
        Ok(listing) => {
            println!("libarchive entries: {}", listing.entries.len());
            for entry in listing.entries {
                println!("{:?}\t{}\t{} bytes", entry.kind, entry.path, entry.size);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("libarchive list failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn libarchive_extract_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(archive) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(destination) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    run_libarchive_extract(archive, destination)
}

fn run_libarchive_extract(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
) -> ExitCode {
    run_libarchive_extract_with_policy(
        archive,
        destination,
        zmanager_core::safety::ExtractionPolicy::default(),
        None,
        None,
    )
}

fn run_rar_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::rar_backend::extract_rar_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy,
            password,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::rar_backend::extract_rar_with_password(
            &archive_path,
            &destination_path,
            policy,
            password,
        )
    };
    match result {
        Ok(report) => {
            let outcome = ExtractOutcome {
                label: FORMAT_RAR,
                format: FORMAT_RAR,
                backend: FORMAT_RAR,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rar extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_libarchive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::ArchiveExtract,
        total_bytes: None,
    });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::libarchive_backend::extract_archive_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy,
            password,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::libarchive_backend::extract_archive_with_password(
            &archive_path,
            &destination_path,
            policy,
            password,
        )
    };
    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_LIBARCHIVE,
                format: FORMAT_LIBARCHIVE,
                backend: FORMAT_LIBARCHIVE,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            eprintln!("libarchive extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(dead_code)]
fn plan_command(mut args: impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    match zmanager_core::manifest::plan_archive(
        path,
        &zmanager_core::manifest::PlanOptions::default(),
    ) {
        Ok(manifest) => {
            println!("{}", manifest.summary());
            for entry in manifest.entries {
                println!("include\t{}\t{} bytes", entry.archive_path, entry.size);
            }
            for excluded in manifest.excluded_entries {
                println!("exclude\t{}\t{}", excluded.archive_path, excluded.reason);
            }
            for warning in manifest.warnings {
                println!(
                    "warning\t{}\t{}",
                    warning.source_path.display(),
                    warning.message
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("plan failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InteractiveOverwriteResolver, normalize_prompted_password, password_arg_or_prompt,
    };
    use std::io::Cursor;
    use std::path::PathBuf;
    use zmanager_core::safety::{OverwriteConflict, OverwriteDecision, OverwriteResolver};

    #[test]
    fn password_prompt_treats_eof_as_cancelled() {
        assert_eq!(normalize_prompted_password(String::new(), 0), None);
    }

    #[test]
    fn password_prompt_treats_empty_line_as_cancelled() {
        assert_eq!(normalize_prompted_password("\n".to_owned(), 1), None);
    }

    #[test]
    fn password_prompt_strips_line_endings_without_logging_secret() {
        assert_eq!(
            normalize_prompted_password("secret\r\n".to_owned(), 8),
            Some("secret".to_owned())
        );
    }

    #[test]
    fn direct_password_arguments_are_rejected() {
        assert!(password_arg_or_prompt(Some("secret"), "Password: ").is_err());
    }

    #[test]
    fn overwrite_prompt_maps_single_entry_choices() {
        assert_eq!(overwrite_decision_for("yes\n"), OverwriteDecision::Replace);
        assert_eq!(overwrite_decision_for("no\n"), OverwriteDecision::Skip);
        assert_eq!(
            overwrite_decision_for("rename\n"),
            OverwriteDecision::Rename
        );
        assert_eq!(overwrite_decision_for("quit\n"), OverwriteDecision::Quit);
    }

    #[test]
    fn overwrite_prompt_all_replaces_subsequent_conflicts_without_prompting() {
        let input = Cursor::new("all\n");
        let output = Vec::new();
        let mut resolver = InteractiveOverwriteResolver::new(input, output);
        let first = overwrite_conflict("first.txt");
        let second = overwrite_conflict("second.txt");

        assert_eq!(resolver.decide(&first), OverwriteDecision::Replace);
        assert_eq!(resolver.decide(&second), OverwriteDecision::Replace);

        let output = String::from_utf8(resolver.output).unwrap();
        assert_eq!(output.matches("overwrite ").count(), 1);
    }

    #[test]
    fn overwrite_prompt_retries_invalid_answers() {
        let input = Cursor::new("maybe\ny\n");
        let output = Vec::new();
        let mut resolver = InteractiveOverwriteResolver::new(input, output);

        assert_eq!(
            resolver.decide(&overwrite_conflict("file.txt")),
            OverwriteDecision::Replace
        );

        let output = String::from_utf8(resolver.output).unwrap();
        assert!(output.contains("please answer yes, no, all, rename, or quit"));
    }

    fn overwrite_decision_for(input: &str) -> OverwriteDecision {
        let input = Cursor::new(input.as_bytes());
        let output = Vec::new();
        let mut resolver = InteractiveOverwriteResolver::new(input, output);
        resolver.decide(&overwrite_conflict("file.txt"))
    }

    fn overwrite_conflict(path: &str) -> OverwriteConflict {
        OverwriteConflict {
            archive_path: path.to_owned(),
            destination_path: PathBuf::from(path),
        }
    }
}
