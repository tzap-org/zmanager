use crate::output::{self, OutputMode, StyleRole};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use zmanager_core::auth_client::TzapSessionStore as _;
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent, JobKind};
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;
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
ZManager is a universal file archiver built for high-performance compression,
safe extraction, and seamless handling of virtually any archive format.

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
  auth <command>                 Hosted TZAP auth handoff helpers
  me                             Show the local TZAP session summary
  cert <command>                 Manage local TZAP certificate inventory
  device retire                  Retire local TZAP device material
  sign <input>                   Sign a TZAP document JSON payload
  verify <input>                 Verify a TZAP document envelope
  contact <command>              Manage TZAP contact cards
  share <archive> <paths...>     Create a TZAP archive for contacts
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
Run 'zm completions --help' to enable shell tab completion.
";

const CREATE_HELP: &str = "\
Create ZIP, TAR.ZST, TZAP, AAR, or 7z archives

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
  printf '%s\\n' \"$ZM_PASSWORD\" | zm create signed.tzap private/ --format tzap \\
      --password-stdin --signing-cert signer.pem --signing-private-key signer.key
  zm create sealed.tzap private/ --format tzap --recipient-cert recipient.pem

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
      --format <zip|tar.zst|tzap|aar|7z|tgz>
                                  Override format inference from extension
      --method <method>          Select method: zip store/deflate, tar.zst/tzap zstd,
                                  aar lzfse/lz4/zlib/lzma/raw, 7z lzma2
      --level <level>            Compression level; use 0..9 where supported
  -0 .. -9                       Compression presets; -0 stores ZIP entries
      --store                    Store ZIP entries without compression
      --solid                    Use solid 7z mode
      --no-solid                 Disable solid 7z mode
      --volume-size <size>       Split ZIP/TZAP/7z output; accepts bytes or k/m/g/t suffixes
                                  ZIP writes .z01/.zip sets; TZAP writes .vol000.tzap sets; 7z writes .7z.001 sets

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
      --recipient-cert <file>    Encrypt TZAP to one X.509 recipient certificate
      --signing-cert <file>      Sign TZAP RootAuth with an X.509 cert or PEM bundle
      --signing-private-key <file>
                                  Private key for --signing-cert
      --signing-chain <file>     Extra intermediate certificate chain for --signing-cert
  TZAP without a password uses tzap's unencrypted mode.
  Use --encrypt or --password-stdin when confidentiality is required.
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
  zm extract sealed.tzap -C out/ --recipient-key recipient.key

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
      --recipient-key <file>     Open TZAP RecipientWrap archives with a private key
      --restore <content|portable|same-os|system>
                                  TZAP metadata restore policy; default is portable
      --allow-degraded           Permit unsupported requested TZAP metadata to be
                                  skipped with diagnostics
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
  zm list sealed.tzap --recipient-key recipient.key

Options:
  -f, --file <archive>           Archive file path in classic mode
  -l, --long                     Show type, size, compressed size, and path
      --name-only                Print archive paths only
      --tree                     Print a simple hierarchical tree
  -i, --include <glob>           List archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --password-stdin           Read one password line from stdin
      --recipient-key <file>     Open TZAP RecipientWrap archives with a private key
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
  printf '%s\\n' \"$ZM_PASSWORD\" | zm test signed.tzap --password-stdin
  zm test signed.tzap --public-no-key
  zm test sealed.tzap --recipient-key recipient.key

Options:
  -f, --file <archive>           Archive file path in classic mode
  -i, --include <glob>           Test archive paths matching glob
      --exclude <glob>           Exclude archive paths matching glob
      --password-stdin           Read one password line from stdin
      --recipient-key <file>     Open TZAP RecipientWrap archives with a private key
      --public-no-key            Verify TZAP X.509 RootAuth without the archive key
      --trusted-ca-cert <file>   Verify TZAP X.509 RootAuth with a trusted CA certificate
      --trusted-system-roots     Verify TZAP X.509 RootAuth with system trust roots
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
      --format <zip|tar.zst|tzap|aar|7z|tgz>
                                  Plan for a specific archive format
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
  tzap      .tzap
  aar       .aar
  7z        .7z

Extract/List/Test:
  zip       .zip, .zipx, .jar, .war, .ipa, .apk, .appx, .xpi
  tar.zst   .tar.zst, .tzst
  tzap      .tzap
  aar       .aar (macOS/iOS)
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

const AUTH_HELP: &str = "\
Hosted TZAP auth handoff helpers

Usage:
  zm auth login [--print-url] [options]
  zm auth callback --state <state> --relay-body <file|->
  zm auth callback --callback-url <url> [--auth-base-url <url>]
  zm auth status [options]
  zm auth forget [options]
  zm auth account [options]

Examples:
  zm auth login --print-url
  zm auth callback --state \"$STATE\" --relay-body relay.json
  zm auth status --json

Options:
      --state-dir <dir>          Store local auth/session state in dir
      --account-key <key>        Local account inventory key; default is default
      --environment <local|dev|prod>
                                  Select named hosted endpoints
      --auth-base-url <url>      Override hosted Auth base URL
      --account-base-url <url>   Override hosted Account base URL
      --client-id <id>           Hosted Auth client id
      --redirect-uri <uri>       Registered app callback URI
      --provider <id>            Hosted provider id to launch
      --org-id <id>              Optional organization id for launch
      --callback-url <url>       Full callback URL, checked for leaked tokens
      --handoff-code <code>      One-time hosted Auth handoff code
      --relay-body <file|->      Relay JSON from hosted Auth callback
      --json                     Emit machine-readable JSON

The CLI only handles launch and registered handoff material. It does not collect
provider credentials, OTPs, or OAuth secrets.
";

const ME_HELP: &str = "\
Show the local TZAP session summary

Usage:
  zm me [options]

Options:
      --state-dir <dir>          Read local auth/session state from dir
      --account-key <key>        Local account inventory key; default is default
      --json                     Emit machine-readable JSON
";

const CERT_HELP: &str = "\
Manage local TZAP certificate inventory

Usage:
  zm cert list [options]
  zm cert enroll [options]
  zm cert renew [options]
  zm cert revoke [options]

Options:
      --state-dir <dir>          Store local identity/session state in dir
      --account-key <key>        Local account inventory key; default is default
      --certificate-id <id>      Certificate id for renew/revoke
      --service-base-url <url>   Enroll through a hosted TZAP sign API instead of the local fake profile
      --trusted-root-cert <file> Trust a staging root PEM/DER certificate for hosted enrollment
      --org-id <id>              Optional organization id for hosted enrollment
      --requested-validity-seconds <n>
                                  Requested hosted enrollment certificate lifetime
      --json                     Emit machine-readable JSON

`cert list` reads local inventory. Enroll, renew, and revoke use the local fake
TZAP service profile by default for deterministic harness runs.
";

const DEVICE_HELP: &str = "\
Retire local TZAP device material

Usage:
  zm device retire [options]

Options:
      --state-dir <dir>          Store local identity/session state in dir
      --account-key <key>        Local account inventory key; default is default
      --json                     Emit machine-readable JSON
";

const SIGN_HELP: &str = "\
Sign a TZAP document JSON payload

Usage:
  zm sign <input.json> --certificate-id <id> --output <envelope.json> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --certificate-id <id>      Local enrolled certificate id
      --output <file>            Destination envelope JSON file
      --claimed-signing-time <text>
                                  Optional claimed signing time string
      --json                     Emit machine-readable JSON
";

const VERIFY_HELP: &str = "\
Verify a TZAP document envelope

Usage:
  zm verify <envelope.json> [options]

Options:
      --custom-trust-root <sha256:id>
                                  Trust a custom root fingerprint explicitly
      --custom-trust-root-cert <file>
                                  Trust a custom root PEM/DER certificate file
      --status-response <file|->  Apply a fresh status JSON response and
                                  return valid_now only when it permits it
      --time <unix-seconds>      Verification time; default is now
      --json                     Emit machine-readable JSON

Offline verification reports `cryptographically_intact_offline`, not fully
valid-now status. `--status-response` enables explicit online-status
verification. Custom trust is reported as custom trust, never official TZAP.
";

const CONTACT_HELP: &str = "\
Manage TZAP contact cards

Usage:
  zm contact export --recipient-key-id <id> --certificate-id <id> --display-name <name> --output <file>
  zm contact import <card.json> --accept [options]
  zm contact list [options]
  zm contact remove <contact-id> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --recipient-key-id <id>    Local recipient key id for export
      --certificate-id <id>      Local signing certificate id for export
      --display-name <name>      Contact card display name
      --device-label <label>     Contact card device label
      --output <file>            Destination contact-card JSON file
      --accept                   Explicitly accept an imported card
      --custom-trust-root <sha256:id>
                                  Trust a custom root fingerprint explicitly
      --custom-trust-root-cert <file>
                                  Trust a custom root PEM/DER certificate file
      --json                     Emit machine-readable JSON
";

const SHARE_HELP: &str = "\
Create a TZAP archive for accepted contacts

Usage:
  zm share <archive.tzap> <paths...> --contact <id> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --contact <id>             Accepted contact id; repeat for multiple recipients
      --force                    Replace an existing output archive
      --json                     Emit machine-readable JSON
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

`source <(zm completions bash)` enables completion in the current Bash session;
add it to ~/.bashrc to enable it in future sessions. Completion scripts suggest
commands, options, values, and paths when Tab is pressed. History-based inline
autosuggestions are a separate shell feature.

Release packages install completion files automatically where package managers
support it. Source and snapshot installs may require the manual setup above.
";

const COMPLETION_BASH_SCRIPT: &str = include_str!("../completions/zm.bash");
const COMPLETION_ZSH_SCRIPT: &str = include_str!("../completions/_zm");
const COMPLETION_FISH_SCRIPT: &str = include_str!("../completions/zm.fish");
const COMPLETION_POWERSHELL_SCRIPT: &str = include_str!("../completions/zm.ps1");

const FORMAT_ZIP: &str = "zip";
const FORMAT_TAR_ZST: &str = "tar.zst";
const FORMAT_TZAP: &str = "tzap";
const FORMAT_APPLE_ARCHIVE: &str = "aar";
const FORMAT_SEVEN_Z: &str = "7z";
const FORMAT_TGZ: &str = "tgz";
const FORMAT_RAR: &str = "rar";
const FORMAT_DEB: &str = "deb";
const FORMAT_RAW_STREAM: &str = "raw-stream";
const FORMAT_LIBARCHIVE: &str = "libarchive";
const BACKEND_DEB_NESTED: &str = "deb-nested";
const TZAP_DEFAULT_RECOVERY_PERCENTAGE: u8 = 5;
const TZAP_SINGLE_VOLUME_LOSS_TOLERANCE: u8 = 0;
const TZAP_SPLIT_VOLUME_LOSS_TOLERANCE: u8 = 1;

const TEMP_ARCHIVE_PREFIX: &str = ".";
const TEMP_ARCHIVE_MARKER: &str = ".tmp";
const SIZE_UNIT_KIB: u64 = 1024;
const SIZE_UNIT_MIB: u64 = SIZE_UNIT_KIB * 1024;
const SIZE_UNIT_GIB: u64 = SIZE_UNIT_MIB * 1024;
const SIZE_UNIT_TIB: u64 = SIZE_UNIT_GIB * 1024;

const TAR_ZST_FORMAT_ALIASES: &[&str] = &[FORMAT_TAR_ZST, "tzst", "zst"];
const TZAP_FORMAT_ALIASES: &[&str] = &[FORMAT_TZAP];
const APPLE_ARCHIVE_FORMAT_ALIASES: &[&str] = &[FORMAT_APPLE_ARCHIVE, "apple-archive"];
const TGZ_FORMAT_ALIASES: &[&str] = &[FORMAT_TGZ, "tar.gz", "gz"];

const ZIP_CREATE_EXTENSIONS: &[&str] = &[".zip"];
const ZIP_FAMILY_EXTENSIONS: &[&str] = &[
    ".zip", ".zipx", ".jar", ".war", ".ipa", ".apk", ".appx", ".xpi",
];
const TAR_ZST_EXTENSIONS: &[&str] = &[".tar.zst", ".tzst"];
const TZAP_EXTENSIONS: &[&str] = &[".tzap"];
const APPLE_ARCHIVE_EXTENSIONS: &[&str] = &[".aar"];
const TGZ_EXTENSIONS: &[&str] = &[".tgz", ".tar.gz"];
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
        name: FORMAT_TZAP,
        extensions: TZAP_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_APPLE_ARCHIVE,
        extensions: APPLE_ARCHIVE_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_SEVEN_Z,
        extensions: SEVEN_Z_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_TGZ,
        extensions: TGZ_EXTENSIONS,
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
        name: FORMAT_TZAP,
        extensions: TZAP_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_APPLE_ARCHIVE,
        extensions: APPLE_ARCHIVE_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_SEVEN_Z,
        extensions: SEVEN_Z_EXTENSIONS,
    },
    FormatDescriptor {
        name: FORMAT_TGZ,
        extensions: TGZ_EXTENSIONS,
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
        "auth" => auth_command(&raw_args[1..], global),
        "me" => me_command(&raw_args[1..], global),
        "cert" => cert_command(&raw_args[1..], global),
        "device" => device_command(&raw_args[1..], global),
        "sign" => sign_command(&raw_args[1..], global),
        "verify" => verify_command(&raw_args[1..], global),
        "contact" => contact_command(&raw_args[1..], global),
        "share" => share_command(&raw_args[1..], global),
        "create" | "c" => new_create_command(&raw_args[1..], global),
        "extract" | "x" => new_extract_command(&raw_args[1..], global),
        "list" | "ls" => new_list_command(&raw_args[1..], global),
        "test" => new_test_command(&raw_args[1..], global),
        "plan" => new_plan_command(&raw_args[1..], global),
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
            | JobEvent::PhaseStarted { .. }
            | JobEvent::PhaseBytesProcessed { .. }
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
    Tzap,
    AppleArchive,
    SevenZ,
    Tgz,
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
    volume_size: Option<u64>,
    volume_count: usize,
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
    volume_size: Option<u64>,
    junk_paths: bool,
    preserve_symlinks: bool,
    follow_symlinks: bool,
    no_metadata: bool,
    tzap_recipient_cert: Option<PathBuf>,
    tzap_signing_cert: Option<PathBuf>,
    tzap_signing_private_key: Option<PathBuf>,
    tzap_signing_chain: Vec<PathBuf>,
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
            volume_size: None,
            junk_paths: false,
            preserve_symlinks: false,
            follow_symlinks: false,
            no_metadata: false,
            tzap_recipient_cert: None,
            tzap_signing_cert: None,
            tzap_signing_private_key: None,
            tzap_signing_chain: Vec::new(),
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
    recipient_key: Option<PathBuf>,
    tzap_restore_policy: zmanager_core::tzap_backend::TzapRestorePolicy,
    tzap_allow_degraded: bool,
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
    recipient_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct TestRequest {
    archive: String,
    include: Vec<String>,
    exclude: Vec<String>,
    password_stdin: bool,
    recipient_key: Option<PathBuf>,
    public_no_key: bool,
    trusted_ca_certs: Vec<PathBuf>,
    trusted_system_roots: bool,
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

#[derive(Debug, Clone, Default)]
struct GenericEntry {
    kind: String,
    name: String,
    size: u64,
    compressed_size: Option<u64>,
    mode: Option<u32>,
    modified: Option<String>,
    metadata_diagnostics: Vec<String>,
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
        "auth" => Some(AUTH_HELP),
        "me" => Some(ME_HELP),
        "cert" => Some(CERT_HELP),
        "device" => Some(DEVICE_HELP),
        "sign" => Some(SIGN_HELP),
        "verify" => Some(VERIFY_HELP),
        "contact" => Some(CONTACT_HELP),
        "share" => Some(SHARE_HELP),
        "doctor" | "healthcheck" => Some(DOCTOR_HELP),
        "completions" | "completion" => Some(COMPLETIONS_HELP),
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

fn print_warning_stderr(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stderr_line(
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

const DEFAULT_TZAP_STATE_DIR_ENV: &str = "ZM_TZAP_STATE_DIR";
const DEFAULT_TZAP_STATE_HOME_CHILD: &str = ".zmanager/tzap";
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
const DEFAULT_TZAP_REDIRECT_URI: &str = "zmanager://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";
const AUTH_SESSION_EXCHANGE_PATH: &str = "/auth/session/exchange";
const HTTP_DEFAULT_PORT: u16 = 80;
const MISSING_TZAP_SESSION: &str = "no local TZAP session";
const DEFAULT_TZAP_CERT_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
const STAGING_ENROLLMENT_KEY_LABEL: &str = "Hosted TZAP enrollment signing key";

#[derive(Debug, Clone)]
struct TzapCliContext {
    state_dir: PathBuf,
    account_key: String,
}

impl Default for TzapCliContext {
    fn default() -> Self {
        Self {
            state_dir: default_tzap_state_dir(),
            account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT
                .to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
struct AuthEndpointOptions {
    environment: zmanager_core::auth_client::TzapHostedAuthEnvironment,
    auth_base_url: Option<String>,
    account_base_url: Option<String>,
    client_id: String,
    redirect_uri: String,
    provider_id: String,
    org_id: Option<String>,
}

impl Default for AuthEndpointOptions {
    fn default() -> Self {
        Self {
            environment: zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod,
            auth_base_url: None,
            account_base_url: None,
            client_id: DEFAULT_TZAP_CLIENT_ID.to_owned(),
            redirect_uri: DEFAULT_TZAP_REDIRECT_URI.to_owned(),
            provider_id: DEFAULT_TZAP_PROVIDER_ID.to_owned(),
            org_id: None,
        }
    }
}

#[derive(Debug, Clone)]
struct FileTzapSessionStore {
    path: PathBuf,
}

impl FileTzapSessionStore {
    fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(AUTH_SESSION_FILE),
        }
    }
}

impl zmanager_core::auth_client::TzapSessionStore for FileTzapSessionStore {
    fn save_session(
        &mut self,
        account_key: &str,
        session: zmanager_core::auth_client::TzapSessionRecord,
    ) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
        if !root.is_object() {
            root = json!({ "sessions": {} });
        }
        root["sessions"][account_key] = session_to_json(&session, true);
        write_secret_json_file(&self.path, &root).map_err(|error| {
            zmanager_core::auth_client::TzapAuthError::Storage {
                message: format!("could not write {}: {error}", self.path.display()),
            }
        })
    }

    fn load_session(
        &self,
        account_key: &str,
    ) -> Option<zmanager_core::auth_client::TzapSessionRecord> {
        let root = read_json_file(&self.path)?;
        session_from_json(root.get("sessions")?.get(account_key)?).ok()
    }

    fn clear_session(
        &mut self,
        account_key: &str,
    ) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let Some(mut root) = read_json_file(&self.path) else {
            return Ok(());
        };
        if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
            sessions.remove(account_key);
        }
        write_secret_json_file(&self.path, &root).map_err(|error| {
            zmanager_core::auth_client::TzapAuthError::Storage {
                message: format!("could not write {}: {error}", self.path.display()),
            }
        })
    }
}

fn auth_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(AUTH_HELP, &global);
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match args[0].as_str() {
        "login" => auth_login_command(&args[1..], global),
        "callback" => auth_callback_command(&args[1..], global),
        "status" => auth_status_command(&args[1..], global),
        "forget" => auth_forget_command(&args[1..], global),
        "account" => auth_account_command(&args[1..], global),
        command => {
            command_usage_error("auth", &format!("unknown auth command: {command}"), &global)
        }
    }
}

fn auth_login_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut endpoints = AuthEndpointOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--print-url" => index += 1,
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap());
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap();
            }
            "--environment" => {
                let value = take_value(args, &mut index, "--environment").unwrap();
                endpoints.environment = match value.as_str() {
                    "local" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Local,
                    "dev" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Dev,
                    "prod" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod,
                    _ => {
                        return command_usage_error(
                            "auth",
                            "environment must be local, dev, or prod",
                            &global,
                        );
                    }
                };
            }
            "--auth-base-url" => {
                endpoints.auth_base_url =
                    Some(take_value(args, &mut index, "--auth-base-url").unwrap());
            }
            "--account-base-url" => {
                endpoints.account_base_url =
                    Some(take_value(args, &mut index, "--account-base-url").unwrap());
            }
            "--client-id" => {
                endpoints.client_id = take_value(args, &mut index, "--client-id").unwrap()
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = take_value(args, &mut index, "--redirect-uri").unwrap();
            }
            "--provider" => {
                endpoints.provider_id = take_value(args, &mut index, "--provider").unwrap()
            }
            "--org-id" => {
                endpoints.org_id = Some(take_value(args, &mut index, "--org-id").unwrap())
            }
            other => {
                return command_usage_error(
                    "auth",
                    &format!("unknown auth option: {other}"),
                    &global,
                );
            }
        }
    }

    let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
    let pending = tracker.begin(
        endpoints.provider_id.clone(),
        endpoints.redirect_uri.clone(),
        current_unix_seconds(),
    );
    let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
        endpoints.environment,
        endpoints.client_id,
        endpoints.redirect_uri,
    );
    if let Some(auth_base_url) = endpoints.auth_base_url {
        config.hosted_auth_base_url = auth_base_url;
    }
    if let Some(account_base_url) = endpoints.account_base_url {
        config.hosted_account_base_url = account_base_url;
    }
    config.selected_org_id = endpoints.org_id;
    if let Err(error) = save_pending_auth(&context.state_dir, &pending, &config) {
        print_error_line(&global, format_args!("auth login failed: {error}"));
        return ExitCode::FAILURE;
    }
    let url = match config.launch_url(&pending) {
        Ok(url) => url,
        Err(error) => {
            print_error_line(&global, format_args!("auth login failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if global.json {
        println!(
            "{{\"status\":\"pending\",\"launch_url\":\"{}\",\"state\":\"{}\",\"expires_at_unix_seconds\":{}}}",
            json_escape(&url),
            json_escape(&pending.state),
            pending
                .created_at_unix_seconds
                .saturating_add(zmanager_core::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS)
        );
    } else {
        println!("{url}");
    }
    ExitCode::SUCCESS
}

fn auth_callback_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut state = None;
    let mut redirect_uri = None;
    let mut callback_url = None;
    let mut handoff_code = None;
    let mut relay_body_path = None;
    let mut auth_base_url = None;
    let mut client_id = None;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap())
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap()
            }
            "--state" => state = Some(take_value(args, &mut index, "--state").unwrap()),
            "--redirect-uri" => {
                redirect_uri = Some(take_value(args, &mut index, "--redirect-uri").unwrap())
            }
            "--auth-base-url" => {
                auth_base_url = Some(take_value(args, &mut index, "--auth-base-url").unwrap())
            }
            "--client-id" => client_id = Some(take_value(args, &mut index, "--client-id").unwrap()),
            "--callback-url" => {
                callback_url = Some(take_value(args, &mut index, "--callback-url").unwrap())
            }
            "--handoff-code" => {
                handoff_code = Some(take_value(args, &mut index, "--handoff-code").unwrap())
            }
            "--relay-body" => {
                relay_body_path = Some(take_value(args, &mut index, "--relay-body").unwrap())
            }
            other => {
                return command_usage_error(
                    "auth",
                    &format!("unknown auth option: {other}"),
                    &global,
                );
            }
        }
    }
    let pending = match load_pending_auth(&context.state_dir) {
        Ok(pending) => pending,
        Err(error) => {
            print_error_line(&global, format_args!("auth callback failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let pending_metadata = load_pending_auth_metadata(&context.state_dir);
    if state.is_none() {
        state = callback_url
            .as_deref()
            .and_then(|url| callback_url_parameter(url, "state"));
    }
    if handoff_code.is_none() {
        handoff_code = callback_url
            .as_deref()
            .and_then(|url| callback_url_parameter(url, "handoff_code"));
    }
    let Some(state) = state else {
        return command_usage_error("auth", "missing --state or callback URL state", &global);
    };
    let redirect_uri = redirect_uri.unwrap_or_else(|| pending.redirect_uri.clone());
    let pkce_verifier = pending.pkce.verifier.clone();
    let relay_body = if let Some(relay_body_path) = relay_body_path {
        match read_bytes_argument(&relay_body_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_error_line(&global, format_args!("auth callback failed: {error}"));
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(handoff_code) = handoff_code {
        let exchange_base_url = auth_base_url
            .or(pending_metadata.auth_base_url)
            .unwrap_or_else(|| zmanager_core::auth_client::LOCAL_HOSTED_AUTH_BASE_URL.to_owned());
        let exchange_client_id = client_id
            .or(pending_metadata.client_id)
            .unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.to_owned());
        match exchange_handoff_code(
            &exchange_base_url,
            &exchange_client_id,
            &redirect_uri,
            &state,
            &pkce_verifier,
            &handoff_code,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_stable_tzap_error("auth_callback", &error, &global);
                return ExitCode::FAILURE;
            }
        }
    } else {
        return command_usage_error("auth", "missing --relay-body or handoff code", &global);
    };
    let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
    if let Err(error) = tracker.insert_pending(pending) {
        print_error_line(&global, format_args!("auth callback failed: {error}"));
        return ExitCode::FAILURE;
    }
    let callback = zmanager_core::auth_client::TzapHostedAuthCallback {
        state,
        redirect_uri,
        pkce_verifier,
        callback_url,
        relay_body,
    };
    let mut session_store = FileTzapSessionStore::new(&context.state_dir);
    match zmanager_core::auth_client::complete_hosted_auth_handoff(
        &mut tracker,
        &mut session_store,
        &context.account_key,
        &callback,
        current_unix_seconds(),
    ) {
        Ok(session) => {
            let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
            print_session_summary(&session, &global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("auth_callback", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

fn auth_status_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store = FileTzapSessionStore::new(&context.state_dir);
    match store.load_session(&context.account_key) {
        Some(session) => {
            print_session_summary(&session, &global);
            ExitCode::SUCCESS
        }
        None => {
            if global.json {
                println!("{{\"authenticated\":false}}");
            } else {
                println!("not signed in");
            }
            ExitCode::SUCCESS
        }
    }
}

fn auth_forget_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let mut store = FileTzapSessionStore::new(&context.state_dir);
    if let Err(error) = store.clear_session(&context.account_key) {
        print_stable_tzap_error("auth_forget", &error.to_string(), &global);
        return ExitCode::FAILURE;
    }
    let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
    if global.json {
        println!("{{\"forgotten\":true}}");
    } else {
        print_success_line(&global, format_args!("local auth material forgotten"));
    }
    ExitCode::SUCCESS
}

fn auth_account_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut endpoints = AuthEndpointOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--environment" => {
                let value = take_value(args, &mut index, "--environment").unwrap();
                endpoints.environment = match value.as_str() {
                    "local" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Local,
                    "dev" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Dev,
                    "prod" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod,
                    _ => {
                        return command_usage_error(
                            "auth",
                            "environment must be local, dev, or prod",
                            &global,
                        );
                    }
                };
            }
            "--account-base-url" => {
                endpoints.account_base_url =
                    Some(take_value(args, &mut index, "--account-base-url").unwrap());
            }
            "--client-id" => {
                endpoints.client_id = take_value(args, &mut index, "--client-id").unwrap()
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = take_value(args, &mut index, "--redirect-uri").unwrap()
            }
            other => {
                return command_usage_error(
                    "auth",
                    &format!("unknown auth option: {other}"),
                    &global,
                );
            }
        }
    }
    let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
        endpoints.environment,
        endpoints.client_id,
        endpoints.redirect_uri,
    );
    if let Some(account_base_url) = endpoints.account_base_url {
        config.hosted_account_base_url = account_base_url;
    }
    let url = config.account_url();
    if global.json {
        println!("{{\"account_url\":\"{}\"}}", json_escape(&url));
    } else {
        println!("{url}");
    }
    ExitCode::SUCCESS
}

fn me_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(ME_HELP, &global);
        return ExitCode::SUCCESS;
    }
    auth_status_command(args, global)
}

fn cert_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(CERT_HELP, &global);
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match args[0].as_str() {
        "list" => cert_list_command(&args[1..], global),
        "enroll" => cert_enroll_command(&args[1..], global),
        "renew" => cert_renew_command(&args[1..], global),
        "revoke" => cert_revoke_command(&args[1..], global),
        command => {
            command_usage_error("cert", &format!("unknown cert command: {command}"), &global)
        }
    }
}

fn cert_enroll_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let options = match parse_cert_enroll_args(args, &mut global) {
        Ok(options) => options,
        Err(code) => return code,
    };
    if options.service_base_url.is_some() {
        return run_hosted_cert_enroll(&options, &global);
    }
    run_fake_cert_operation(
        "cert_enroll",
        &options.context,
        &global,
        |store, session, options| {
            zmanager_core::local_fake_tzap::enroll_local_fake_certificate(store, session, options)
                .map(|certificate| {
                    json!({
                        "ok": true,
                        "operation": "cert_enroll",
                        "certificate": certificate_summary_value(&certificate),
                    })
                })
        },
    )
}

fn cert_renew_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let (context, certificate_id) = match parse_cert_id_operation_args(args, &mut global, "cert") {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    run_fake_cert_operation(
        "cert_renew",
        &context,
        &global,
        |store, session, options| {
            zmanager_core::local_fake_tzap::renew_local_fake_certificate(
                store,
                session,
                options,
                &certificate_id,
            )
            .map(|certificate| {
                json!({
                    "ok": true,
                    "operation": "cert_renew",
                    "certificate": certificate_summary_value(&certificate),
                })
            })
        },
    )
}

fn cert_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let (context, certificate_id) = match parse_cert_id_operation_args(args, &mut global, "cert") {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    run_fake_cert_operation(
        "cert_revoke",
        &context,
        &global,
        |store, session, options| {
            zmanager_core::local_fake_tzap::revoke_local_fake_certificate(
                store,
                session,
                options,
                &certificate_id,
            )
            .map(|completion| {
                json!({
                    "ok": true,
                    "operation": "cert_revoke",
                    "completion": retirement_completion_label(completion),
                })
            })
        },
    )
}

fn cert_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "cert") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(inventory) => {
            if global.json {
                print!("{{\"certificates\":[");
                for (index, cert) in inventory.enrolled_certificates.iter().enumerate() {
                    if index > 0 {
                        print!(",");
                    }
                    print_certificate_json(cert);
                }
                println!("]}}");
            } else if inventory.enrolled_certificates.is_empty() {
                println!("no local certificates");
            } else {
                for cert in inventory.enrolled_certificates {
                    println!(
                        "{} {} {}",
                        cert.certificate_id,
                        cert.state.as_str(),
                        cert.certificate_sha256
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("cert list failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn device_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(DEVICE_HELP, &global);
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match args[0].as_str() {
        "retire" => device_retire_command(&args[1..], global),
        command => command_usage_error(
            "device",
            &format!("unknown device command: {command}"),
            &global,
        ),
    }
}

fn device_retire_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "device") {
        Ok(context) => context,
        Err(code) => return code,
    };
    run_fake_cert_operation(
        "device_retire",
        &context,
        &global,
        |store, session, options| {
            zmanager_core::local_fake_tzap::retire_local_fake_device(store, session, options).map(
                |report| {
                    json!({
                        "ok": true,
                        "operation": "device_retire",
                        "completion": retirement_completion_label(report.completion),
                        "attempted_sign_device_ids": report.attempted_sign_device_ids,
                    })
                },
            )
        },
    )
}

fn sign_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(SIGN_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut context = TzapCliContext::default();
    let mut input = None;
    let mut output = None;
    let mut certificate_id = None;
    let mut claimed_signing_time = None;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap())
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap()
            }
            "--certificate-id" => {
                certificate_id = Some(take_value(args, &mut index, "--certificate-id").unwrap())
            }
            "--output" => {
                output = Some(PathBuf::from(
                    take_value(args, &mut index, "--output").unwrap(),
                ))
            }
            "--claimed-signing-time" => {
                claimed_signing_time =
                    Some(take_value(args, &mut index, "--claimed-signing-time").unwrap())
            }
            value if value.starts_with('-') => {
                return command_usage_error(
                    "sign",
                    &format!("unknown sign option: {value}"),
                    &global,
                );
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("sign", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("sign", "missing input", &global);
    };
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("sign", "missing --certificate-id", &global);
    };
    let Some(output) = output else {
        return command_usage_error("sign", "missing --output", &global);
    };
    let payload = match read_json_argument(&input) {
        Ok(payload) => payload,
        Err(error) => {
            print_error_line(&global, format_args!("sign failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let mut request = zmanager_core::document_signing::TzapDocumentSigningRequest::new(
        context.account_key,
        certificate_id,
        current_unix_seconds(),
    );
    request.claimed_signing_time = claimed_signing_time;
    match zmanager_core::document_signing::sign_tzap_document_payload(&store, &request, payload) {
        Ok(envelope) => {
            if let Err(error) = write_json_file(&output, &envelope) {
                print_error_line(&global, format_args!("sign failed: {error}"));
                return ExitCode::FAILURE;
            }
            if global.json {
                println!(
                    "{{\"signed\":true,\"output\":\"{}\"}}",
                    json_escape(&output.display().to_string())
                );
            } else {
                print_success_line(&global, format_args!("signed {}", output.display()));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("sign", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

fn verify_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(VERIFY_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut input = None;
    let mut custom_roots = Vec::new();
    let mut custom_root_cert_paths = Vec::new();
    let mut status_response_path = None;
    let mut verifier_time = current_unix_seconds() as i64;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--custom-trust-root" => {
                custom_roots.push(take_value(args, &mut index, "--custom-trust-root").unwrap())
            }
            "--custom-trust-root-cert" => {
                custom_root_cert_paths.push(PathBuf::from(
                    take_value(args, &mut index, "--custom-trust-root-cert").unwrap(),
                ));
            }
            "--status-response" => {
                status_response_path =
                    Some(take_value(args, &mut index, "--status-response").unwrap());
            }
            "--time" => {
                let value = take_value(args, &mut index, "--time").unwrap();
                verifier_time = match value.parse::<i64>() {
                    Ok(value) => value,
                    Err(_) => {
                        return command_usage_error(
                            "verify",
                            "--time must be a unix timestamp",
                            &global,
                        );
                    }
                };
            }
            value if value.starts_with('-') => {
                return command_usage_error(
                    "verify",
                    &format!("unknown verify option: {value}"),
                    &global,
                );
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("verify", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("verify", "missing input", &global);
    };
    let bytes = match read_bytes_argument(&input) {
        Ok(bytes) => bytes,
        Err(error) => {
            print_error_line(&global, format_args!("verify failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let custom_root_certificates_der =
        match load_custom_root_certificates(&custom_root_cert_paths, &mut custom_roots) {
            Ok(certificates) => certificates,
            Err(error) => {
                print_error_line(&global, format_args!("verify failed: {error}"));
                return ExitCode::FAILURE;
            }
        };
    let options = zmanager_core::document_verification::TzapOfflineVerificationOptions {
        verifier_time_unix_seconds: verifier_time,
        official_root_pins: &zmanager_core::trust::OFFICIAL_TZAP_ROOT_PINS,
        official_root_certificates_der: Vec::new(),
        custom_trust_root_sha256: custom_roots,
        custom_trust_root_certificates_der: custom_root_certificates_der,
        certificate_profile_options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
    };
    let result = verify_document_bytes_with_optional_status(
        &bytes,
        &options,
        status_response_path.as_deref(),
        &global,
    );
    print_verification_result(&result, &global);
    if result.state == zmanager_core::trust::TzapVerificationState::Invalid {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn verify_document_bytes_with_optional_status(
    bytes: &[u8],
    options: &zmanager_core::document_verification::TzapOfflineVerificationOptions<'_>,
    status_response_path: Option<&str>,
    global: &GlobalOptions,
) -> zmanager_core::document_verification::TzapDocumentVerificationResult {
    let offline = zmanager_core::document_verification::verify_tzap_document_envelope_offline_json(
        bytes, options,
    );
    let Some(status_response_path) = status_response_path else {
        return offline;
    };
    if offline.state == zmanager_core::trust::TzapVerificationState::Invalid {
        return offline;
    }

    let envelope = match zmanager_core::document_envelope::parse_tzap_document_envelope_json(bytes)
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return zmanager_core::document_verification::TzapDocumentVerificationResult {
                state: zmanager_core::trust::TzapVerificationState::Invalid,
                trust_anchor_type: zmanager_core::trust::TzapTrustAnchorType::Untrusted,
                reason: Some(error.to_string()),
                root_certificate_sha256: None,
                public_metadata: None,
            };
        }
    };
    let status_value = match read_json_argument(status_response_path) {
        Ok(value) => value,
        Err(error) => {
            print_error_line(global, format_args!("verify status failed: {error}"));
            return zmanager_core::document_verification::TzapDocumentVerificationResult {
                state: zmanager_core::trust::TzapVerificationState::Invalid,
                reason: Some("status response JSON is invalid".to_owned()),
                ..offline
            };
        }
    };
    let status =
        match zmanager_core::status_client::TzapStatusResponse::from_json_value(&status_value) {
            Ok(status) => status,
            Err(error) => {
                print_error_line(global, format_args!("verify status failed: {error}"));
                return zmanager_core::document_verification::TzapDocumentVerificationResult {
                    state: zmanager_core::trust::TzapVerificationState::Invalid,
                    reason: Some(error.to_string()),
                    ..offline
                };
            }
        };
    zmanager_core::status_client::verify_tzap_document_envelope_valid_now(
        &envelope, options, &status,
    )
}

fn contact_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(CONTACT_HELP, &global);
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match args[0].as_str() {
        "list" => contact_list_command(&args[1..], global),
        "remove" => contact_remove_command(&args[1..], global),
        "import" => contact_import_command(&args[1..], global),
        "export" => contact_export_command(&args[1..], global),
        command => command_usage_error(
            "contact",
            &format!("unknown contact command: {command}"),
            &global,
        ),
    }
}

fn contact_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "contact") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(inventory) => {
            if global.json {
                print!("{{\"contacts\":[");
                for (index, contact) in inventory.contacts.iter().enumerate() {
                    if index > 0 {
                        print!(",");
                    }
                    print_contact_json(contact);
                }
                println!("]}}");
            } else if inventory.contacts.is_empty() {
                println!("no contacts");
            } else {
                for contact in inventory.contacts {
                    println!("{} {}", contact.contact_id, contact.display_name);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("contact list failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn contact_remove_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut contact_id = None;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap());
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap();
            }
            value if value.starts_with('-') => {
                return command_usage_error(
                    "contact",
                    &format!("unknown contact option: {value}"),
                    &global,
                );
            }
            value if contact_id.is_none() => {
                contact_id = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("contact", "too many arguments", &global),
        }
    }
    let Some(contact_id) = contact_id else {
        return command_usage_error("contact", "missing contact id", &global);
    };
    let mut store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(mut inventory) => {
            let before = inventory.contacts.len();
            inventory
                .contacts
                .retain(|contact| contact.contact_id != contact_id);
            if let Err(error) = store.save_inventory(&context.account_key, inventory) {
                print_error_line(&global, format_args!("contact remove failed: {error}"));
                return ExitCode::FAILURE;
            }
            let removed = before
                > store
                    .load_inventory(&context.account_key)
                    .map_or(0, |inventory| inventory.contacts.len());
            if global.json {
                println!("{{\"removed\":{removed}}}");
            } else if removed {
                print_success_line(&global, format_args!("removed contact {contact_id}"));
            } else {
                println!("contact not found: {contact_id}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("contact remove failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn contact_import_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut input = None;
    let mut accepted = false;
    let mut custom_roots = Vec::new();
    let mut custom_root_cert_paths = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap())
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap()
            }
            "--accept" => {
                accepted = true;
                index += 1;
            }
            "--custom-trust-root" => {
                custom_roots.push(take_value(args, &mut index, "--custom-trust-root").unwrap())
            }
            "--custom-trust-root-cert" => {
                custom_root_cert_paths.push(PathBuf::from(
                    take_value(args, &mut index, "--custom-trust-root-cert").unwrap(),
                ));
            }
            value if value.starts_with('-') => {
                return command_usage_error(
                    "contact",
                    &format!("unknown contact option: {value}"),
                    &global,
                );
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("contact", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("contact", "missing contact card", &global);
    };
    let card = match read_json_argument(&input) {
        Ok(card) => card,
        Err(error) => {
            print_error_line(&global, format_args!("contact import failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let custom_root_certificates_der =
        match load_custom_root_certificates(&custom_root_cert_paths, &mut custom_roots) {
            Ok(certificates) => certificates,
            Err(error) => {
                print_error_line(&global, format_args!("contact import failed: {error}"));
                return ExitCode::FAILURE;
            }
        };
    let options = zmanager_core::contact_card::TzapContactCardImportOptions {
        verifier_time_unix_seconds: current_unix_seconds() as i64,
        official_root_pins: &zmanager_core::trust::OFFICIAL_TZAP_ROOT_PINS,
        official_root_certificates_der: Vec::new(),
        custom_trust_root_sha256: custom_roots,
        custom_trust_root_certificates_der: custom_root_certificates_der,
        certificate_profile_options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
    };
    let mut store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match zmanager_core::contact_card::import_tzap_contact_card(
        &mut store,
        &context.account_key,
        &card,
        &options,
        accepted.then(current_unix_seconds),
    ) {
        Ok(contact) => {
            if global.json {
                print_contact_json_line(&contact);
            } else {
                print_success_line(
                    &global,
                    format_args!("imported contact {}", contact.display_name),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("contact_import", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

fn contact_export_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut recipient_key_id = None;
    let mut certificate_id = None;
    let mut display_name = None;
    let mut device_label = "ZManager".to_owned();
    let mut output = None;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap())
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap()
            }
            "--recipient-key-id" => {
                recipient_key_id = Some(take_value(args, &mut index, "--recipient-key-id").unwrap())
            }
            "--certificate-id" => {
                certificate_id = Some(take_value(args, &mut index, "--certificate-id").unwrap())
            }
            "--display-name" => {
                display_name = Some(take_value(args, &mut index, "--display-name").unwrap())
            }
            "--device-label" => {
                device_label = take_value(args, &mut index, "--device-label").unwrap()
            }
            "--output" => {
                output = Some(PathBuf::from(
                    take_value(args, &mut index, "--output").unwrap(),
                ))
            }
            value => {
                return command_usage_error(
                    "contact",
                    &format!("unknown contact option: {value}"),
                    &global,
                );
            }
        }
    }
    let Some(recipient_key_id) = recipient_key_id else {
        return command_usage_error("contact", "missing --recipient-key-id", &global);
    };
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("contact", "missing --certificate-id", &global);
    };
    let Some(display_name) = display_name else {
        return command_usage_error("contact", "missing --display-name", &global);
    };
    let Some(output) = output else {
        return command_usage_error("contact", "missing --output", &global);
    };
    let store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let request = zmanager_core::contact_card::TzapContactCardExportRequest {
        account_key: context.account_key,
        recipient_key_id,
        certificate_id,
        display_name,
        device_label,
        created_at_unix_seconds: current_unix_seconds(),
        expires_at_unix_seconds: None,
    };
    match zmanager_core::contact_card::export_tzap_contact_card(&store, &request) {
        Ok(card) => {
            if let Err(error) = write_json_file(&output, &card) {
                print_error_line(&global, format_args!("contact export failed: {error}"));
                return ExitCode::FAILURE;
            }
            if global.json {
                println!(
                    "{{\"exported\":true,\"output\":\"{}\"}}",
                    json_escape(&output.display().to_string())
                );
            } else {
                print_success_line(&global, format_args!("exported {}", output.display()));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("contact_export", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

fn share_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(SHARE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut context = TzapCliContext::default();
    let mut archive = None;
    let mut sources = Vec::new();
    let mut contact_ids = Vec::new();
    let mut force = false;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, &mut global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir =
                    PathBuf::from(take_value(args, &mut index, "--state-dir").unwrap())
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key").unwrap()
            }
            "--contact" => contact_ids.push(take_value(args, &mut index, "--contact").unwrap()),
            "--force" => {
                force = true;
                index += 1;
            }
            value if value.starts_with('-') => {
                return command_usage_error(
                    "share",
                    &format!("unknown share option: {value}"),
                    &global,
                );
            }
            value if archive.is_none() => {
                archive = Some(PathBuf::from(value));
                index += 1;
            }
            value => {
                sources.push(PathBuf::from(value));
                index += 1;
            }
        }
    }
    let Some(archive) = archive else {
        return command_usage_error("share", "missing archive", &global);
    };
    if sources.is_empty() {
        return command_usage_error("share", "missing source path", &global);
    }
    let store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let recipients = match zmanager_core::contact_card::accepted_contact_recipients(
        &store,
        &context.account_key,
        &contact_ids,
        current_unix_seconds(),
    ) {
        Ok(recipients) => recipients,
        Err(error) => {
            print_stable_tzap_error("share", &error.to_string(), &global);
            return ExitCode::FAILURE;
        }
    };
    let recipient_warning_count = recipients
        .iter()
        .filter(|recipient| recipient.missing_status_caveat)
        .count();
    let recipient_public_keys = recipients
        .into_iter()
        .map(|recipient| recipient.recipient_public_key_der)
        .collect();
    let manifest = match plan_sources(&sources, false, false, false) {
        Ok(manifest) => manifest,
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if archive.exists() && !force {
        print_error_line(
            &global,
            format_args!("share failed: destination exists: {}", archive.display()),
        );
        return ExitCode::FAILURE;
    }
    let token = CancellationToken::new();
    let mut progress = ProgressReporter::from_global(Some(&global));
    let options = zmanager_core::tzap_backend::TzapCreateOptions {
        key_source: zmanager_core::tzap_backend::TzapKeySource::RecipientPublicKeys(
            recipient_public_keys,
        ),
        level: 3,
        preserve_metadata: true,
        replace_existing: force,
        volume_size: None,
        recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
        volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
        x509_signing: None,
    };
    let result = {
        let mut sink = |event| progress.emit(event);
        let mut job_context =
            JobContext::new_with_progress_total(&token, &mut sink, Some(manifest.total_bytes));
        let result = zmanager_core::tzap_backend::create_tzap_from_manifest_with_context(
            &manifest,
            &archive,
            &options,
            &mut job_context,
        );
        job_context.flush_progress();
        result
    };
    match result {
        Ok(report) => {
            if global.json {
                println!(
                    "{{\"archive\":\"{}\",\"format\":\"tzap\",\"entries\":{},\"bytes\":{},\"recipients\":{},\"recipient_status_caveats\":{}}}",
                    json_escape(&archive.display().to_string()),
                    report.written_entries,
                    report.written_bytes,
                    contact_ids.len(),
                    recipient_warning_count
                );
            } else {
                if recipient_warning_count > 0 {
                    print_error_line(
                        &global,
                        format_args!(
                            "{recipient_warning_count} recipient contact(s) have offline-only status caveats"
                        ),
                    );
                }
                print_success_line(
                    &global,
                    format_args!("created shared tzap {}", archive.display()),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn parse_tzap_context_args(
    args: &[String],
    global: &mut GlobalOptions,
    command: &str,
) -> Result<TzapCliContext, ExitCode> {
    let mut context = TzapCliContext::default();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error(command, &error, global)),
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir = PathBuf::from(
                    take_value(args, &mut index, "--state-dir")
                        .map_err(|error| command_usage_error(command, &error, global))?,
                );
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key")
                    .map_err(|error| command_usage_error(command, &error, global))?;
            }
            other => {
                return Err(command_usage_error(
                    command,
                    &format!("unknown {command} option: {other}"),
                    global,
                ));
            }
        }
    }
    Ok(context)
}

fn parse_cert_id_operation_args(
    args: &[String],
    global: &mut GlobalOptions,
    command: &str,
) -> Result<(TzapCliContext, String), ExitCode> {
    let mut context = TzapCliContext::default();
    let mut certificate_id = None;
    let mut index = 0usize;
    while index < args.len() {
        if parse_global_option(args, &mut index, global).unwrap_or(false) {
            continue;
        }
        match args[index].as_str() {
            "--state-dir" => {
                context.state_dir = PathBuf::from(
                    take_value(args, &mut index, "--state-dir")
                        .map_err(|error| command_usage_error(command, &error, global))?,
                );
            }
            "--account-key" => {
                context.account_key = take_value(args, &mut index, "--account-key")
                    .map_err(|error| command_usage_error(command, &error, global))?;
            }
            "--certificate-id" => {
                certificate_id = Some(
                    take_value(args, &mut index, "--certificate-id")
                        .map_err(|error| command_usage_error(command, &error, global))?,
                );
            }
            other => {
                return Err(command_usage_error(
                    command,
                    &format!("unknown {command} option: {other}"),
                    global,
                ));
            }
        }
    }
    let Some(certificate_id) = certificate_id else {
        return Err(command_usage_error(
            command,
            "missing --certificate-id",
            global,
        ));
    };
    Ok((context, certificate_id))
}

#[derive(Debug)]
struct CertEnrollOptions {
    context: TzapCliContext,
    service_base_url: Option<String>,
    trusted_root_cert_paths: Vec<PathBuf>,
    org_id: Option<String>,
    requested_validity_seconds: u64,
}

fn parse_cert_enroll_args(
    args: &[String],
    global: &mut GlobalOptions,
) -> Result<CertEnrollOptions, ExitCode> {
    let mut options = CertEnrollOptions {
        context: TzapCliContext::default(),
        service_base_url: None,
        trusted_root_cert_paths: Vec::new(),
        org_id: None,
        requested_validity_seconds: DEFAULT_TZAP_CERT_VALIDITY_SECONDS,
    };
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error("cert", &error, global)),
        }
        match args[index].as_str() {
            "--state-dir" => {
                options.context.state_dir = PathBuf::from(
                    take_value(args, &mut index, "--state-dir")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--account-key" => {
                options.context.account_key = take_value(args, &mut index, "--account-key")
                    .map_err(|error| command_usage_error("cert", &error, global))?;
            }
            "--service-base-url" => {
                options.service_base_url = Some(
                    take_value(args, &mut index, "--service-base-url")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--trusted-root-cert" => {
                options.trusted_root_cert_paths.push(PathBuf::from(
                    take_value(args, &mut index, "--trusted-root-cert")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                ));
            }
            "--org-id" => {
                options.org_id = Some(
                    take_value(args, &mut index, "--org-id")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--requested-validity-seconds" => {
                let value = take_value(args, &mut index, "--requested-validity-seconds")
                    .map_err(|error| command_usage_error("cert", &error, global))?;
                options.requested_validity_seconds = value.parse::<u64>().map_err(|_| {
                    command_usage_error(
                        "cert",
                        "--requested-validity-seconds must be an integer",
                        global,
                    )
                })?;
            }
            other => {
                return Err(command_usage_error(
                    "cert",
                    &format!("unknown cert option: {other}"),
                    global,
                ));
            }
        }
    }
    if options.service_base_url.is_none() && !options.trusted_root_cert_paths.is_empty() {
        return Err(command_usage_error(
            "cert",
            "--trusted-root-cert requires --service-base-url",
            global,
        ));
    }
    if options.service_base_url.is_none() && options.org_id.is_some() {
        return Err(command_usage_error(
            "cert",
            "--org-id requires --service-base-url",
            global,
        ));
    }
    Ok(options)
}

fn run_hosted_cert_enroll(options: &CertEnrollOptions, global: &GlobalOptions) -> ExitCode {
    let Some(service_base_url) = options.service_base_url.as_deref() else {
        unreachable!("hosted enrollment checked by caller")
    };
    if options.trusted_root_cert_paths.is_empty() {
        return command_usage_error(
            "cert",
            "hosted enrollment requires at least one --trusted-root-cert",
            global,
        );
    }
    let session_store = FileTzapSessionStore::new(&options.context.state_dir);
    let Some(session) = session_store.load_session(&options.context.account_key) else {
        print_stable_tzap_error("cert_enroll", MISSING_TZAP_SESSION, global);
        return ExitCode::FAILURE;
    };
    let mut trusted_root_sha256 = Vec::new();
    let trusted_root_der = match load_custom_root_certificates(
        &options.trusted_root_cert_paths,
        &mut trusted_root_sha256,
    ) {
        Ok(roots) => roots,
        Err(error) => {
            print_error_line(global, format_args!("cert enroll failed: {error}"));
            return ExitCode::FAILURE;
        }
    };

    let mut identity_store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(
        &options.context.state_dir,
    );
    let now_unix_seconds = current_unix_seconds();
    let (signing_key, csr_der) = match create_and_store_staging_enrollment_key(
        &mut identity_store,
        options,
        now_unix_seconds,
    ) {
        Ok(material) => material,
        Err(error) => {
            print_error_line(global, format_args!("cert enroll failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let request = zmanager_core::enrollment_client::TzapEnrollmentRequest {
        account_key: options.context.account_key.clone(),
        org_id: options
            .org_id
            .clone()
            .or_else(|| session.selected_org_id.clone()),
        requested_validity_seconds: options.requested_validity_seconds,
        now_unix_seconds,
    };
    let transport = CliHttpJsonTransport;
    let client = zmanager_core::enrollment_client::TzapEnrollmentClient::local_staging_server(
        service_base_url,
        &transport,
    );
    let validator = CliTrustedEnrollmentCertificateValidator {
        trusted_root_sha256,
        trusted_root_der,
        options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
    };
    match zmanager_core::enrollment_client::enroll_device_certificate(
        &client,
        &validator,
        &mut identity_store,
        &session,
        &request,
        &signing_key,
        &csr_der,
    ) {
        Ok(certificate) => {
            if global.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "operation": "cert_enroll",
                        "service_base_url": service_base_url,
                        "certificate": certificate_summary_value(&certificate),
                    })
                );
            } else {
                print_success_line(global, format_args!("cert_enroll complete"));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = remove_staging_enrollment_key(
                &mut identity_store,
                &options.context.account_key,
                &signing_key.key_id,
            );
            print_stable_tzap_error("cert_enroll", &error.to_string(), global);
            ExitCode::FAILURE
        }
    }
}

fn create_and_store_staging_enrollment_key(
    store: &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
    options: &CertEnrollOptions,
    now_unix_seconds: u64,
) -> Result<
    (
        zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord,
        Vec<u8>,
    ),
    String,
> {
    let material = zmanager_core::device_identity::generate_device_signing_key_and_csr(
        &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
    )
    .map_err(|error| error.to_string())?;
    let record = zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord {
        key_id: material.public_key_fingerprint.clone(),
        public_key_fingerprint: material.public_key_fingerprint,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: now_unix_seconds,
        label: Some(STAGING_ENROLLMENT_KEY_LABEL.to_owned()),
    };
    let mut inventory = store
        .load_inventory(&options.context.account_key)
        .map_err(|error| error.to_string())?;
    inventory.device_signing_keys.push(record.clone());
    store
        .save_inventory(&options.context.account_key, inventory)
        .map_err(|error| error.to_string())?;
    Ok((record, material.csr_der))
}

fn remove_staging_enrollment_key(
    store: &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
    account_key: &str,
    key_id: &str,
) -> Result<(), String> {
    let mut inventory = store
        .load_inventory(account_key)
        .map_err(|error| error.to_string())?;
    inventory
        .device_signing_keys
        .retain(|record| record.key_id != key_id);
    store
        .save_inventory(account_key, inventory)
        .map_err(|error| error.to_string())
}

struct CliTrustedEnrollmentCertificateValidator {
    trusted_root_sha256: Vec<String>,
    trusted_root_der: Vec<Vec<u8>>,
    options: zmanager_core::trust::TzapCertificateProfileOptions,
}

impl zmanager_core::enrollment_client::TzapEnrollmentCertificateValidator
    for CliTrustedEnrollmentCertificateValidator
{
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        zmanager_core::trust::TzapCertificatePublicMetadata,
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        let validation = zmanager_core::trust::validate_custom_tzap_certificate_chain_der(
            chain_der,
            &self.options,
        )
        .map_err(|error| {
            zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(
                error.to_string(),
            )
        })?;
        if !self
            .trusted_root_sha256
            .iter()
            .any(|trusted| trusted == &validation.root_certificate_sha256)
        {
            return Err(
                zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(format!(
                    "root certificate is not in the temporary trust store: {}",
                    validation.root_certificate_sha256
                )),
            );
        }
        Ok(validation.public_metadata)
    }

    fn validate_and_complete_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        (
            Vec<Vec<u8>>,
            zmanager_core::trust::TzapCertificatePublicMetadata,
        ),
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        let mut last_error = match self.validate_completed_chain(chain_der) {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        for root_der in &self.trusted_root_der {
            let mut completed_chain = chain_der.to_vec();
            completed_chain.push(root_der.clone());
            match self.validate_completed_chain(&completed_chain) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}

impl CliTrustedEnrollmentCertificateValidator {
    fn validate_completed_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        (
            Vec<Vec<u8>>,
            zmanager_core::trust::TzapCertificatePublicMetadata,
        ),
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        let validation = zmanager_core::trust::validate_custom_tzap_certificate_chain_der(
            chain_der,
            &self.options,
        )
        .map_err(|error| {
            zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(
                error.to_string(),
            )
        })?;
        if !self
            .trusted_root_sha256
            .iter()
            .any(|trusted| trusted == &validation.root_certificate_sha256)
        {
            return Err(
                zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(format!(
                    "root certificate is not in the temporary trust store: {}",
                    validation.root_certificate_sha256
                )),
            );
        }
        Ok((chain_der.to_vec(), validation.public_metadata))
    }
}

fn run_fake_cert_operation<F>(
    operation: &str,
    context: &TzapCliContext,
    global: &GlobalOptions,
    action: F,
) -> ExitCode
where
    F: FnOnce(
        &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
        &zmanager_core::auth_client::TzapSessionRecord,
        &zmanager_core::local_fake_tzap::TzapLocalFakeServiceOptions,
    ) -> Result<
        serde_json::Value,
        zmanager_core::local_fake_tzap::TzapLocalFakeServiceError,
    >,
{
    let session_store = FileTzapSessionStore::new(&context.state_dir);
    let Some(session) = session_store.load_session(&context.account_key) else {
        print_stable_tzap_error(operation, MISSING_TZAP_SESSION, global);
        return ExitCode::FAILURE;
    };
    let mut identity_store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let options = zmanager_core::local_fake_tzap::TzapLocalFakeServiceOptions {
        account_key: context.account_key.clone(),
        now_unix_seconds: current_unix_seconds(),
    };
    match action(&mut identity_store, &session, &options) {
        Ok(value) => {
            if global.json {
                println!("{value}");
            } else {
                print_success_line(global, format_args!("{operation} complete"));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error(operation, &error.to_string(), global);
            ExitCode::FAILURE
        }
    }
}

fn print_stable_tzap_error(operation: &str, message: &str, global: &GlobalOptions) {
    if global.json {
        println!(
            "{{\"ok\":false,\"operation\":\"{}\",\"error\":\"{}\"}}",
            json_escape(operation),
            json_escape(message)
        );
    } else {
        print_error_line(global, format_args!("{operation} failed: {message}"));
    }
}

fn certificate_summary_value(
    cert: &zmanager_core::local_identity_store::TzapEnrolledCertificateRecord,
) -> serde_json::Value {
    json!({
        "certificate_id": cert.certificate_id,
        "certificate_sha256": cert.certificate_sha256,
        "state": cert.state.as_str(),
        "not_before_unix_seconds": cert.not_before_unix_seconds,
        "not_after_unix_seconds": cert.not_after_unix_seconds,
        "public_signer_id": cert.public_metadata.public_signer_id,
        "public_org_id": cert.public_metadata.public_org_id,
        "public_device_id": cert.public_metadata.public_device_id,
        "assurance_level": cert.public_metadata.assurance_level.as_str(),
    })
}

fn retirement_completion_label(
    completion: zmanager_core::certificate_lifecycle::TzapRetirementCompletion,
) -> &'static str {
    match completion {
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
}

fn default_tzap_state_dir() -> PathBuf {
    if let Some(path) = env::var_os(DEFAULT_TZAP_STATE_DIR_ENV)
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    env::var_os("HOME").map_or_else(
        || PathBuf::from(".").join(DEFAULT_TZAP_STATE_HOME_CHILD),
        |home| PathBuf::from(home).join(DEFAULT_TZAP_STATE_HOME_CHILD),
    )
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn read_bytes_argument(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::stdin(), &mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

fn read_json_argument(path: &str) -> Result<Value, String> {
    let bytes = read_bytes_argument(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn load_custom_root_certificates(
    paths: &[PathBuf],
    custom_roots: &mut Vec<String>,
) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let der = zmanager_core::trust::certificate_pem_or_der_to_der(&bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let fingerprint = zmanager_core::trust::certificate_sha256_identifier_for_der(&der);
            if !custom_roots.iter().any(|root| root == &fingerprint) {
                custom_roots.push(fingerprint);
            }
            Ok(der)
        })
        .collect()
}

fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    fs::write(path, bytes)
}

fn write_secret_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    write_secret_file(path, &bytes)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

fn save_pending_auth(
    state_dir: &Path,
    pending: &zmanager_core::auth_client::TzapPendingAuthState,
    config: &zmanager_core::auth_client::TzapHostedAuthLaunchConfig,
) -> io::Result<()> {
    write_secret_json_file(
        &state_dir.join(AUTH_PENDING_FILE),
        &json!({
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "pkce_verifier": pending.pkce.verifier,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
            "client_id": config.client_id,
            "auth_base_url": config.hosted_auth_base_url,
        }),
    )
}

#[derive(Debug, Default)]
struct PendingAuthMetadata {
    client_id: Option<String>,
    auth_base_url: Option<String>,
}

fn load_pending_auth_metadata(state_dir: &Path) -> PendingAuthMetadata {
    let Some(value) = read_json_file(&state_dir.join(AUTH_PENDING_FILE)) else {
        return PendingAuthMetadata::default();
    };
    PendingAuthMetadata {
        client_id: json_optional_string_field(&value, "client_id")
            .ok()
            .flatten(),
        auth_base_url: json_optional_string_field(&value, "auth_base_url")
            .ok()
            .flatten(),
    }
}

fn load_pending_auth(
    state_dir: &Path,
) -> Result<zmanager_core::auth_client::TzapPendingAuthState, String> {
    let value = read_json_file(&state_dir.join(AUTH_PENDING_FILE))
        .ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
    let verifier = json_string_field(&value, "pkce_verifier")?;
    let pkce = zmanager_core::auth_client::TzapPkcePair::from_verifier(&verifier)
        .map_err(|error| error.to_string())?;
    Ok(zmanager_core::auth_client::TzapPendingAuthState {
        state: json_string_field(&value, "state")?,
        provider_id: json_string_field(&value, "provider_id")?,
        redirect_uri: json_string_field(&value, "redirect_uri")?,
        pkce,
        created_at_unix_seconds: json_u64_field(&value, "created_at_unix_seconds")?,
    })
}

fn callback_url_parameter(callback_url: &str, key: &str) -> Option<String> {
    let (_, query) = callback_url.split_once('?')?;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    for parameter in query.split('&') {
        let (parameter_key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if percent_decode_url_component(parameter_key).ok().as_deref() == Some(key) {
            return percent_decode_url_component(value).ok();
        }
    }
    None
}

fn exchange_handoff_code(
    auth_base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce_verifier: &str,
    handoff_code: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "{}{}",
        auth_base_url.trim_end_matches('/'),
        AUTH_SESSION_EXCHANGE_PATH
    );
    let exchange = http_post_json(
        &url,
        &json!({
            "handoff_code": handoff_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_verifier": pkce_verifier,
            "required_audience": zmanager_core::auth_client::SESSION_AUDIENCE_SIGN_TZAP,
        }),
    )?;
    let session_token = json_string_field(&exchange, "session_token")?;
    let session_id = json_string_field(&exchange, "session_id")?;
    let audience = json_string_field(&exchange, "audience")
        .unwrap_or_else(|_| zmanager_core::auth_client::SESSION_AUDIENCE_SIGN_TZAP.to_owned());
    let expires_at_unix_seconds = exchange
        .get("expires_at_unix_seconds")
        .and_then(Value::as_u64)
        .map_or_else(
            || {
                json_string_field(&exchange, "expires_at")
                    .and_then(|expires_at| rfc3339_utc_to_unix_seconds(&expires_at))
            },
            Ok,
        )?;
    let identity_assurance = json_string_field(&exchange, "identity_assurance")
        .or_else(|_| json_string_field(&exchange, "identity_assurance_level"))
        .unwrap_or_else(|_| {
            zmanager_core::trust::TzapIdentityAssurance::OauthVerifiedEmail
                .as_str()
                .to_owned()
        });
    serde_json::to_vec(&json!({
        "status": "ok",
        "session": {
            "audience": audience,
            "access_token": session_token,
            "expires_at_unix_seconds": expires_at_unix_seconds,
            "identity_assurance": identity_assurance,
            "selected_org_id": exchange.get("selected_org_id").cloned().unwrap_or(Value::Null),
            "login_session_id": session_id,
        }
    }))
    .map_err(|error| error.to_string())
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let response = http_json_request("POST", url, None, Some(body))?;
    if !(200..=299).contains(&response.status_code) {
        return Err(format!(
            "hosted auth exchange failed with HTTP {}",
            response.status_code
        ));
    }
    serde_json::from_slice(&response.body).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Copy)]
struct CliHttpJsonTransport;

impl zmanager_core::auth_client::TzapAuthHttpTransport for CliHttpJsonTransport {
    fn send(
        &self,
        request: &zmanager_core::auth_client::TzapAuthHttpRequest,
    ) -> Result<
        zmanager_core::auth_client::TzapAuthHttpResponse,
        zmanager_core::auth_client::TzapAuthError,
    > {
        let method = match request.method {
            zmanager_core::auth_client::TzapAuthHttpMethod::Get => "GET",
            zmanager_core::auth_client::TzapAuthHttpMethod::Post => "POST",
        };
        http_json_request(
            method,
            &request.url,
            request
                .bearer_token
                .as_ref()
                .map(zmanager_core::auth_client::TzapBearerToken::expose),
            request.body.as_ref(),
        )
        .map_err(|message| zmanager_core::auth_client::TzapAuthError::Transport { message })
    }
}

fn http_json_request(
    method: &str,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&Value>,
) -> Result<zmanager_core::auth_client::TzapAuthHttpResponse, String> {
    let target = HttpUrl::parse(url)?;
    let body = body
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut stream = TcpStream::connect((target.host.as_str(), target.port)).map_err(|error| {
        format!(
            "could not connect to {}:{}: {error}",
            target.host, target.port
        )
    })?;
    write!(
        stream,
        "{method} {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n",
        target.path, target.host
    )
    .map_err(|error| error.to_string())?;
    if let Some(token) = bearer_token {
        write!(stream, "Authorization: Bearer {token}\r\n").map_err(|error| error.to_string())?;
    }
    if let Some(body) = &body {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
        .map_err(|error| error.to_string())?;
    }
    stream
        .write_all(b"\r\n")
        .map_err(|error| error.to_string())?;
    if let Some(body) = body {
        stream.write_all(&body).map_err(|error| error.to_string())?;
    }
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let (status_code, response_body) = parse_http_response(&response)?;
    Ok(zmanager_core::auth_client::TzapAuthHttpResponse {
        status_code,
        body: response_body,
    })
}

#[derive(Debug)]
struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl HttpUrl {
    fn parse(url: &str) -> Result<Self, String> {
        let without_scheme = url
            .strip_prefix("http://")
            .ok_or_else(|| "hosted auth exchange currently requires an http:// URL".to_owned())?;
        let (authority, path) = without_scheme
            .split_once('/')
            .map_or((without_scheme, "/"), |(authority, path)| (authority, path));
        if authority.is_empty() {
            return Err("hosted auth exchange URL is missing a host".to_owned());
        }
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            let port = port.parse::<u16>().map_err(|error| error.to_string())?;
            (host, port)
        } else {
            (authority, HTTP_DEFAULT_PORT)
        };
        if host.is_empty() {
            return Err("hosted auth exchange URL is missing a host".to_owned());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            path: format!("/{path}"),
        })
    }
}

fn parse_http_response(response: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let separator = b"\r\n\r\n";
    let header_end = response
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| "hosted auth exchange response was malformed".to_owned())?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let mut header_lines = headers.lines();
    let status_line = header_lines
        .next()
        .ok_or_else(|| "hosted auth exchange response was missing a status line".to_owned())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "hosted auth exchange response status was malformed".to_owned())?
        .parse::<u16>()
        .map_err(|error| error.to_string())?;
    let chunked = header_lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = response[header_end + separator.len()..].to_vec();
    if chunked {
        decode_chunked_body(&body).map(|decoded| (status_code, decoded))
    } else {
        Ok((status_code, body))
    }
}

fn decode_chunked_body(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut index = 0usize;
    let mut output = Vec::new();
    loop {
        let remaining = bytes
            .get(index..)
            .ok_or_else(|| "chunked response is truncated".to_owned())?;
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "chunked response is malformed".to_owned())?
            + index;
        let size_text = std::str::from_utf8(&bytes[index..line_end])
            .map_err(|error| error.to_string())?
            .split_once(';')
            .map_or_else(
                || std::str::from_utf8(&bytes[index..line_end]).unwrap_or(""),
                |(size, _)| size,
            );
        let size =
            usize::from_str_radix(size_text.trim(), 16).map_err(|error| error.to_string())?;
        index = line_end + 2;
        if size == 0 {
            return Ok(output);
        }
        let end = index
            .checked_add(size)
            .ok_or_else(|| "chunked response is too large".to_owned())?;
        let trailer_end = end
            .checked_add(2)
            .ok_or_else(|| "chunked response is too large".to_owned())?;
        if bytes.get(end..trailer_end) != Some(b"\r\n") {
            return Err("chunked response body is truncated".to_owned());
        }
        output.extend_from_slice(&bytes[index..end]);
        index = trailer_end;
    }
}

fn percent_decode_url_component(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .map_err(|error| error.to_string())?;
                output.push(u8::from_str_radix(hex, 16).map_err(|error| error.to_string())?);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|error| error.to_string())
}

fn rfc3339_utc_to_unix_seconds(value: &str) -> Result<u64, String> {
    let without_z = value
        .strip_suffix('Z')
        .ok_or_else(|| "expires_at must be a UTC RFC3339 timestamp".to_owned())?;
    let (date, time) = without_z
        .split_once('T')
        .ok_or_else(|| "expires_at must include a date and time".to_owned())?;
    let mut date_parts = date.split('-');
    let year = parse_i64_part(date_parts.next(), "year")?;
    let month = parse_i64_part(date_parts.next(), "month")?;
    let day = parse_i64_part(date_parts.next(), "day")?;
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut time_parts = time.split(':');
    let hour = parse_i64_part(time_parts.next(), "hour")?;
    let minute = parse_i64_part(time_parts.next(), "minute")?;
    let second = parse_i64_part(time_parts.next(), "second")?;
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| "expires_at is out of range".to_owned())?;
    u64::try_from(seconds).map_err(|_| "expires_at is before the Unix epoch".to_owned())
}

fn parse_i64_part(value: Option<&str>, field: &str) -> Result<i64, String> {
    value
        .ok_or_else(|| format!("expires_at is missing {field}"))?
        .parse::<i64>()
        .map_err(|error| error.to_string())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn session_to_json(
    session: &zmanager_core::auth_client::TzapSessionRecord,
    include_token: bool,
) -> Value {
    let mut value = json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    });
    if include_token {
        value["access_token"] = json!(session.access_token.expose());
    }
    value
}

fn session_from_json(
    value: &Value,
) -> Result<zmanager_core::auth_client::TzapSessionRecord, String> {
    let assurance = json_string_field(value, "identity_assurance")?;
    let identity_assurance = zmanager_core::trust::TzapIdentityAssurance::from_str(&assurance)
        .ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(zmanager_core::auth_client::TzapSessionRecord {
        audience: json_string_field(value, "audience")?,
        access_token: zmanager_core::auth_client::TzapBearerToken::new(json_string_field(
            value,
            "access_token",
        )?)
        .map_err(|error| error.to_string())?,
        expires_at_unix_seconds: json_u64_field(value, "expires_at_unix_seconds")?,
        identity_assurance,
        selected_org_id: json_optional_string_field(value, "selected_org_id")?,
        login_session_id: json_optional_string_field(value, "login_session_id")?,
    })
}

fn json_string_field(value: &Value, field: &'static str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn json_optional_string_field(
    value: &Value,
    field: &'static str,
) -> Result<Option<String>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn json_u64_field(value: &Value, field: &'static str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn print_session_summary(
    session: &zmanager_core::auth_client::TzapSessionRecord,
    global: &GlobalOptions,
) {
    let expired = session.is_expired_at(current_unix_seconds());
    if global.json {
        println!(
            "{{\"authenticated\":true,\"audience\":\"{}\",\"expires_at_unix_seconds\":{},\"expired\":{},\"identity_assurance\":\"{}\",\"selected_org_id\":{},\"login_session_id\":{}}}",
            json_escape(&session.audience),
            session.expires_at_unix_seconds,
            expired,
            json_escape(session.identity_assurance.as_str()),
            optional_json_string(session.selected_org_id.as_deref()),
            optional_json_string(session.login_session_id.as_deref())
        );
    } else {
        let status = if expired { "expired" } else { "active" };
        println!(
            "{status} session for {} ({})",
            session.audience,
            session.identity_assurance.as_str()
        );
    }
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", json_escape(value)),
    )
}

fn print_certificate_json(
    cert: &zmanager_core::local_identity_store::TzapEnrolledCertificateRecord,
) {
    print!(
        "{{\"certificate_id\":\"{}\",\"certificate_sha256\":\"{}\",\"state\":\"{}\",\"not_before_unix_seconds\":{},\"not_after_unix_seconds\":{},\"public_signer_id\":\"{}\",\"public_org_id\":{},\"public_device_id\":\"{}\",\"assurance_level\":\"{}\"}}",
        json_escape(&cert.certificate_id),
        json_escape(&cert.certificate_sha256),
        json_escape(cert.state.as_str()),
        cert.not_before_unix_seconds,
        cert.not_after_unix_seconds,
        json_escape(&cert.public_metadata.public_signer_id),
        optional_json_string(cert.public_metadata.public_org_id.as_deref()),
        json_escape(&cert.public_metadata.public_device_id),
        json_escape(cert.public_metadata.assurance_level.as_str())
    );
}

fn print_verification_result(
    result: &zmanager_core::document_verification::TzapDocumentVerificationResult,
    global: &GlobalOptions,
) {
    if global.json {
        println!(
            "{{\"state\":\"{}\",\"trust_anchor_type\":\"{}\",\"reason\":{},\"root_certificate_sha256\":{}}}",
            json_escape(result.state.as_str()),
            json_escape(result.trust_anchor_type.as_str()),
            optional_json_string(result.reason.as_deref()),
            optional_json_string(result.root_certificate_sha256.as_deref())
        );
    } else {
        println!(
            "{} ({})",
            result.state.as_str(),
            result.trust_anchor_type.as_str()
        );
        if let Some(reason) = &result.reason {
            println!("{reason}");
        }
    }
}

fn print_contact_json(contact: &zmanager_core::local_identity_store::TzapContactRecord) {
    print!(
        "{{\"contact_id\":\"{}\",\"display_name\":\"{}\",\"signing_certificate_sha256\":\"{}\",\"recipient_public_key_fingerprint\":\"{}\",\"trust_anchor_type\":\"{}\",\"verification_state\":\"{}\",\"missing_status_caveat\":{},\"accepted_at_unix_seconds\":{}}}",
        json_escape(&contact.contact_id),
        json_escape(&contact.display_name),
        json_escape(&contact.signing_certificate_sha256),
        json_escape(&contact.recipient_public_key_fingerprint),
        contact.trust_anchor_type.as_str(),
        contact.verification_state.as_str(),
        contact.missing_status_caveat,
        contact.accepted_at_unix_seconds
    );
}

fn print_contact_json_line(contact: &zmanager_core::local_identity_store::TzapContactRecord) {
    print!("{{\"contact\":");
    print_contact_json(contact);
    println!("}}");
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
            "--volume-size" => {
                request.volume_size =
                    Some(parse_volume_size(&take_value(args, &mut index, arg)?, arg)?);
            }
            "--recipient-cert" => {
                request.tzap_recipient_cert =
                    Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-cert" => {
                request.tzap_signing_cert = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-private-key" => {
                request.tzap_signing_private_key =
                    Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-chain" => {
                request
                    .tzap_signing_chain
                    .push(PathBuf::from(take_value(args, &mut index, arg)?));
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
            format_args!("could not infer archive format; pass --format <zip|tar.zst|tzap|aar|7z>"),
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
            if format == ArchiveFormat::Tzap
                && request.preserve_symlinks
                && manifest_has_symlinks(&manifest)
            {
                print_error_line(
                    global,
                    format_args!(
                        "create failed: tzap symlink preservation is not supported by the current backend; use --follow-symlinks"
                    ),
                );
                return ExitCode::from(2);
            }
            if format == ArchiveFormat::AppleArchive
                && !zmanager_core::apple_archive_backend::apple_archive_supported()
            {
                print_error_line(
                    global,
                    format_args!("create failed: AAR archives are supported only on macOS and iOS"),
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

    let split_output = request.volume_size.is_some();
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
    let create_destination = if split_output {
        destination.as_path()
    } else {
        temp.as_path()
    };
    let backend_replace_existing = split_output && request.force;

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
                replace_existing: backend_replace_existing,
                password,
                volume_size: request.volume_size,
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new_with_progress_total(
                    &token,
                    &mut sink,
                    Some(manifest.total_bytes),
                );
                let result = zmanager_core::zip_backend::create_zip_from_manifest_with_context(
                    &manifest,
                    create_destination,
                    &options,
                    &mut context,
                );
                context.flush_progress();
                result
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
                    volume_size: report.volume_size,
                    volume_count: report.volume_count,
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
                let mut context = JobContext::new_with_progress_total(
                    &token,
                    &mut sink,
                    Some(manifest.total_bytes),
                );
                let result =
                    zmanager_core::tar_zst_backend::create_tar_zst_from_manifest_with_context(
                        &manifest,
                        &temp,
                        &options,
                        &mut context,
                    );
                context.flush_progress();
                result
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
                    volume_size: None,
                    volume_count: 1,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::Tgz => {
            let options = zmanager_core::tar_gz_backend::TarGzCreateOptions {
                level: request.level.unwrap_or_else(|| {
                    zmanager_core::tar_gz_backend::TarGzCreateOptions::default().level
                }),
                preserve_metadata: !request.no_metadata,
                replace_existing: backend_replace_existing,
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new_with_progress_total(
                    &token,
                    &mut sink,
                    Some(manifest.total_bytes),
                );
                let result =
                    zmanager_core::tar_gz_backend::create_tar_gz_from_manifest_with_context(
                        &manifest,
                        &temp,
                        &options,
                        &mut context,
                    );
                context.flush_progress();
                result
            };
            result
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created tar.gz: {} entries, {} bytes, level {}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        report.level,
                        report.warnings.len()
                    ),
                    format: FORMAT_TGZ,
                    backend: FORMAT_TGZ,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: None,
                    solid: None,
                    volume_size: None,
                    volume_count: 1,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::Tzap => {
            let uses_secret_key = password.is_some() || request.tzap_recipient_cert.is_some();
            let key_source = if let Some(recipient_certificate) = &request.tzap_recipient_cert {
                zmanager_core::tzap_backend::TzapKeySource::RecipientCertificate(
                    recipient_certificate.clone(),
                )
            } else {
                password.map_or(
                    zmanager_core::tzap_backend::TzapKeySource::NoPassword,
                    zmanager_core::tzap_backend::TzapKeySource::Passphrase,
                )
            };
            let options = zmanager_core::tzap_backend::TzapCreateOptions {
                key_source,
                level: request.level.unwrap_or(3),
                preserve_metadata: !request.no_metadata,
                replace_existing: backend_replace_existing,
                volume_size: request.volume_size,
                recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
                volume_loss_tolerance: tzap_default_volume_loss_tolerance(request.volume_size),
                x509_signing: request.tzap_signing_cert.as_ref().map(|certificate| {
                    zmanager_core::tzap_backend::TzapX509SigningOptions::CertificateAndKey {
                        signing_certificate: certificate.clone(),
                        signing_private_key: request
                            .tzap_signing_private_key
                            .clone()
                            .expect("validated with signing certificate"),
                        signing_chain: request.tzap_signing_chain.clone(),
                    }
                }),
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new_with_progress_total(
                    &token,
                    &mut sink,
                    Some(manifest.total_bytes),
                );
                let result = zmanager_core::tzap_backend::create_tzap_from_manifest_with_context(
                    &manifest,
                    create_destination,
                    &options,
                    &mut context,
                );
                context.flush_progress();
                result
            };
            result
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created tzap: {} entries, {} bytes, encrypted {}, level {}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        uses_secret_key,
                        report.level,
                        report.warnings.len()
                    ),
                    format: FORMAT_TZAP,
                    backend: FORMAT_TZAP,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: Some(uses_secret_key),
                    solid: None,
                    volume_size: report.volume_size,
                    volume_count: report.volume_count,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::AppleArchive => {
            let compression = match apple_archive_compression(request) {
                Ok(compression) => compression,
                Err(error) => {
                    print_error_line(global, format_args!("{error}"));
                    return ExitCode::from(2);
                }
            };
            let options = zmanager_core::apple_archive_backend::AppleArchiveCreateOptions {
                compression,
                preserve_metadata: !request.no_metadata,
                replace_existing: backend_replace_existing,
                ..zmanager_core::apple_archive_backend::AppleArchiveCreateOptions::default()
            };
            let result = {
                let mut sink = |event| progress.emit(event);
                let mut context = JobContext::new_with_progress_total(
                    &token,
                    &mut sink,
                    Some(manifest.total_bytes),
                );
                let result = zmanager_core::apple_archive_backend::create_apple_archive_from_manifest_with_context(
                    &manifest,
                    &temp,
                    &options,
                    &mut context,
                );
                context.flush_progress();
                result
            };
            result
                .map(|report| CreateOutcome {
                    summary: format!(
                        "created aar: {} entries, {} bytes, compression {:?}, {} warnings",
                        report.written_entries,
                        report.written_bytes,
                        options.compression,
                        report.warnings.len()
                    ),
                    format: FORMAT_APPLE_ARCHIVE,
                    backend: FORMAT_APPLE_ARCHIVE,
                    entries: report.written_entries,
                    bytes: report.written_bytes,
                    warnings: report.warnings.len(),
                    encrypted: None,
                    solid: None,
                    volume_size: None,
                    volume_count: 1,
                })
                .map_err(|error| error.to_string())
        }
        ArchiveFormat::SevenZ => {
            let options = zmanager_core::sevenz_backend::SevenZCreateOptions {
                solid: request.solid,
                level: sevenz_level(request),
                preserve_metadata: !request.no_metadata,
                password,
                encrypt_file_names: true,
                replace_existing: backend_replace_existing,
                volume_size: request.volume_size,
                ..zmanager_core::sevenz_backend::SevenZCreateOptions::default()
            };
            zmanager_core::sevenz_backend::create_7z_from_manifest(
                &manifest,
                create_destination,
                &options,
            )
            .map(|report| CreateOutcome {
                summary: format!(
                    "created 7z: {} entries, {} bytes, solid {}, threads {:?}, encrypted {}, {} warnings",
                    report.written_entries,
                    report.written_bytes,
                    report.solid,
                    report.threads,
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
                volume_size: report.volume_size,
                volume_count: report.volume_count,
            })
            .map_err(|error| error.to_string())
        }
    };

    match result {
        Ok(outcome) => {
            if !split_output && let Err(error) = publish_archive(&temp, &destination, request.force)
            {
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
                let archive = create_test_archive_path(&destination, format, split_output)
                    .to_string_lossy()
                    .into_owned();
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
            if !split_output {
                let _ = fs::remove_file(&temp);
            }
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
        replace_existing: false,
        password,
        volume_size: None,
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
    if request.tzap_recipient_cert.is_some() {
        if format != ArchiveFormat::Tzap {
            return Err("recipient certificates are supported only for TZAP archives".to_owned());
        }
        if request.encrypt || request.password_stdin {
            return Err(
                "--recipient-cert cannot be combined with --encrypt or --password-stdin".to_owned(),
            );
        }
        if request.tzap_signing_cert.is_some()
            || request.tzap_signing_private_key.is_some()
            || !request.tzap_signing_chain.is_empty()
        {
            return Err(
                "--recipient-cert cannot be combined with X.509 signing options".to_owned(),
            );
        }
        if request.volume_size.is_some() {
            return Err(
                "--recipient-cert is supported only for single-volume TZAP create".to_owned(),
            );
        }
    }

    if request.tzap_signing_cert.is_some()
        || request.tzap_signing_private_key.is_some()
        || !request.tzap_signing_chain.is_empty()
    {
        if format != ArchiveFormat::Tzap {
            return Err("certificate signing is supported only for TZAP archives".to_owned());
        }
        match (
            request.tzap_signing_cert.as_ref(),
            request.tzap_signing_private_key.as_ref(),
        ) {
            (Some(_), Some(_)) => {}
            (None, None) if !request.tzap_signing_chain.is_empty() => {
                return Err("--signing-chain requires --signing-cert".to_owned());
            }
            _ => {
                return Err(
                    "--signing-cert and --signing-private-key must be used together".to_owned(),
                );
            }
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
            ArchiveFormat::SevenZ | ArchiveFormat::Tzap => {}
            ArchiveFormat::TarZst | ArchiveFormat::AppleArchive | ArchiveFormat::Tgz => {
                return Err(
                    "--volume-size is supported only for ZIP, TZAP, and 7z archives".to_owned(),
                );
            }
        }
    }

    if let Some(method) = request.method.as_deref() {
        match (format, method) {
            (ArchiveFormat::Zip, "deflate" | "store")
            | (ArchiveFormat::TarZst | ArchiveFormat::Tzap, "zstd" | "zst")
            | (ArchiveFormat::AppleArchive, "lzfse" | "lz4" | "zlib" | "lzma" | "raw")
            | (ArchiveFormat::SevenZ, "lzma2")
            | (ArchiveFormat::Tgz, "gzip" | "gz") => {}
            _ => {
                return Err(format!(
                    "unsupported method for selected archive format: {method}"
                ));
            }
        }
    }

    if let Some(level) = request.level {
        match format {
            ArchiveFormat::Zip
            | ArchiveFormat::SevenZ
            | ArchiveFormat::Tzap
            | ArchiveFormat::Tgz
                if !(0..=9).contains(&level) =>
            {
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
            ArchiveFormat::AppleArchive => {
                return Err("compression levels are not supported for AAR archives".to_owned());
            }
            _ => {}
        }
    }

    Ok(())
}

fn apple_archive_compression(
    request: &CreateRequest,
) -> Result<zmanager_core::apple_archive_backend::AppleArchiveCompression, String> {
    use zmanager_core::apple_archive_backend::AppleArchiveCompression;

    match request.method.as_deref() {
        None => Ok(AppleArchiveCompression::default()),
        Some("lzfse") => Ok(AppleArchiveCompression::Lzfse),
        Some("lz4") => Ok(AppleArchiveCompression::Lz4),
        Some("zlib") => Ok(AppleArchiveCompression::Zlib),
        Some("lzma") => Ok(AppleArchiveCompression::Lzma),
        Some("raw") => Ok(AppleArchiveCompression::None),
        Some(method) => Err(format!(
            "unsupported method for selected archive format: {method}"
        )),
    }
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
            && matches!(
                format,
                ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::Tzap
            ))
}

fn create_password(
    format: ArchiveFormat,
    request: &CreateRequest,
    global: &GlobalOptions,
) -> Result<Option<SecretString>, ExitCode> {
    if !request.encrypt && !request.password_stdin {
        return Ok(None);
    }
    if matches!(
        format,
        ArchiveFormat::TarZst | ArchiveFormat::AppleArchive | ArchiveFormat::Tgz
    ) {
        print_error_line(
            global,
            format_args!("encryption is not supported for this archive format"),
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
    let prompt = match format {
        ArchiveFormat::SevenZ => "7z password: ",
        ArchiveFormat::Tzap => "tzap password: ",
        ArchiveFormat::AppleArchive | ArchiveFormat::TarZst | ArchiveFormat::Tgz => {
            "archive password: "
        }
        ArchiveFormat::Zip => "ZIP password: ",
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
            "--recipient-key" => {
                request.recipient_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--restore" => {
                let value = take_value(args, &mut index, arg)?;
                request.tzap_restore_policy = parse_tzap_restore_policy(&value)?;
            }
            "--allow-degraded" => {
                request.tzap_allow_degraded = true;
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

#[allow(clippy::too_many_lines)]
fn run_extract_request(request: ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if let Some(code) = validate_recipient_key_open_option(
        "extract",
        &request.archive,
        request.password_stdin,
        request.recipient_key.as_ref(),
        global,
    ) {
        return code;
    }
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
    if is_zip_family_archive(&request.archive) && !is_split_zip_archive_path(&request.archive) {
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
    } else if is_apple_archive(&request.archive) {
        if request.password_stdin {
            return usage_failure(
                global,
                format_args!(
                    "extract failed: AAR archives are not encrypted; remove --password-stdin"
                ),
            );
        }
        run_apple_archive_extract_with_policy(request.archive, destination, policy, Some(global))
    } else if is_tzap_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "TZAP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_tzap_extract_with_policy(
            request.archive,
            destination,
            policy,
            password.as_deref(),
            request.recipient_key.as_deref(),
            zmanager_core::tzap_backend::TzapRestoreOptions {
                policy: request.tzap_restore_policy,
                allow_degraded: request.tzap_allow_degraded,
            },
            Some(global),
        )
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
    if is_zip_family_archive(&request.archive) && !is_split_zip_archive_path(&request.archive) {
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
    } else if is_tzap_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "TZAP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        let result = if let Some(recipient_key) = request.recipient_key.as_deref() {
            zmanager_core::tzap_backend::copy_tzap_files_to_writer_with_recipient_key(
                &request.archive,
                recipient_key,
                |name| entry_selected(name, &request.include, &request.exclude),
                &mut stdout,
            )
        } else {
            zmanager_core::tzap_backend::copy_tzap_files_to_writer_with_optional_password(
                &request.archive,
                password.as_deref(),
                |name| entry_selected(name, &request.include, &request.exclude),
                &mut stdout,
            )
        };
        match result {
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
    } else if is_apple_archive(&request.archive) {
        if request.password_stdin {
            print_error_line(
                global,
                format_args!(
                    "extract to stdout failed: AAR archives are not encrypted; remove --password-stdin"
                ),
            );
            return ExitCode::from(2);
        }
        match zmanager_core::apple_archive_backend::copy_apple_archive_files_to_writer(
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

fn parse_tzap_restore_policy(
    value: &str,
) -> Result<zmanager_core::tzap_backend::TzapRestorePolicy, String> {
    match value {
        "content" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::Content),
        "portable" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::Portable),
        "same-os" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::SameOs),
        "system" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::System),
        _ => Err(format!(
            "unsupported TZAP restore policy: {value}; expected content, portable, same-os, or system"
        )),
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

fn run_list_request(request: &ListRequest, global: &GlobalOptions) -> ExitCode {
    if let Some(code) = validate_recipient_key_open_option(
        "list",
        &request.archive,
        request.password_stdin,
        request.recipient_key.as_ref(),
        global,
    ) {
        return code;
    }
    if request.password_stdin
        && zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some()
    {
        print_error_line(
            global,
            format_args!("list failed: raw streams are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    if request.password_stdin && is_apple_archive(&request.archive) {
        print_error_line(
            global,
            format_args!("list failed: AAR archives are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    let password = match read_optional_password_stdin(request.password_stdin, "archive", global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    match list_entries_with_password(
        &request.archive,
        password.as_deref(),
        request.recipient_key.as_deref(),
    ) {
        Ok(mut entries) => {
            filter_entries(&mut entries, &request.include, &request.exclude);
            if !global.quiet {
                for entry in &entries {
                    for diagnostic in &entry.metadata_diagnostics {
                        print_warning_stderr(
                            global,
                            format_args!("metadata {}: {diagnostic}", entry.name),
                        );
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
                    format_args!(
                        "{}",
                        output::styled(
                            StyleRole::Heading,
                            format_args!("TYPE\tMODE\tSIZE\tCOMPRESSED\tMODIFIED\tPATH")
                        )
                    ),
                );
                for entry in entries {
                    output::stdout_line(
                        global.color,
                        format_args!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            output::styled(StyleRole::Label, format_args!("{}", entry.kind)),
                            entry
                                .mode
                                .map_or_else(|| "-".to_owned(), |mode| format!("{mode:04o}")),
                            entry.size,
                            entry
                                .compressed_size
                                .map_or_else(|| "-".to_owned(), |size| size.to_string()),
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
            "--recipient-key" => {
                request.recipient_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--public-no-key" => {
                request.public_no_key = true;
                index += 1;
            }
            "--trusted-ca-cert" => {
                request
                    .trusted_ca_certs
                    .push(PathBuf::from(take_value(args, &mut index, arg)?));
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
fn run_test_request(request: &TestRequest, global: &GlobalOptions) -> ExitCode {
    if request.public_no_key && !is_tzap_archive(&request.archive) {
        return usage_failure(
            global,
            format_args!("test failed: --public-no-key is supported only for TZAP archives"),
        );
    }
    if let Some(code) = validate_recipient_key_open_option(
        "test",
        &request.archive,
        request.password_stdin,
        request.recipient_key.as_ref(),
        global,
    ) {
        return code;
    }
    if test_request_has_x509_trust(request) && !is_tzap_archive(&request.archive) {
        return usage_failure(
            global,
            format_args!("test failed: X.509 trust options are supported only for TZAP archives"),
        );
    }
    if request.public_no_key && request.password_stdin {
        return usage_failure(
            global,
            format_args!("test failed: --public-no-key cannot be combined with --password-stdin"),
        );
    }
    if request.public_no_key && request.recipient_key.is_some() {
        return usage_failure(
            global,
            format_args!("test failed: --public-no-key cannot be combined with --recipient-key"),
        );
    }
    if request.public_no_key && (!request.include.is_empty() || !request.exclude.is_empty()) {
        return usage_failure(
            global,
            format_args!("test failed: --public-no-key cannot be combined with path filters"),
        );
    }
    if request.public_no_key {
        return run_tzap_public_no_key_test(&request.archive, request, global);
    }
    if request.password_stdin
        && zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some()
    {
        print_error_line(
            global,
            format_args!("test failed: raw streams are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    if request.password_stdin && is_apple_archive(&request.archive) {
        print_error_line(
            global,
            format_args!("test failed: AAR archives are not encrypted; remove --password-stdin"),
        );
        return ExitCode::from(2);
    }
    let password = match read_optional_password_stdin(request.password_stdin, "archive", global) {
        Ok(password) => password,
        Err(code) => return code,
    };

    if is_zip_family_archive(&request.archive) && !is_split_zip_archive_path(&request.archive) {
        return run_zip_test_new(
            &request.archive,
            password.as_deref(),
            &request.include,
            &request.exclude,
            global,
        );
    }
    if is_split_zip_archive_path(&request.archive) {
        return run_libarchive_data_test_new(
            &request.archive,
            password.as_deref(),
            &request.include,
            &request.exclude,
            FORMAT_ZIP,
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
    if is_apple_archive(&request.archive) {
        return run_apple_archive_test_new(
            &request.archive,
            &request.include,
            &request.exclude,
            global,
        );
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
    if is_tzap_archive(&request.archive) {
        return run_tzap_test_new(
            &request.archive,
            password.as_deref(),
            &request.include,
            &request.exclude,
            request,
            global,
        );
    }

    match list_entries_with_password(&request.archive, password.as_deref(), None) {
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

fn test_request_has_x509_trust(request: &TestRequest) -> bool {
    !request.trusted_ca_certs.is_empty() || request.trusted_system_roots
}

fn tzap_default_volume_loss_tolerance(volume_size: Option<u64>) -> u8 {
    if volume_size.is_some() {
        TZAP_SPLIT_VOLUME_LOSS_TOLERANCE
    } else {
        TZAP_SINGLE_VOLUME_LOSS_TOLERANCE
    }
}

fn test_request_x509_trust(
    request: &TestRequest,
) -> zmanager_core::tzap_backend::TzapX509TrustOptions {
    zmanager_core::tzap_backend::TzapX509TrustOptions {
        trusted_ca_certificates: request.trusted_ca_certs.clone(),
        trusted_system_roots: request.trusted_system_roots,
        include_official_tzap_root: !test_request_has_x509_trust(request),
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

fn run_apple_archive_test_new(
    archive: &str,
    includes: &[String],
    excludes: &[String],
    global: &GlobalOptions,
) -> ExitCode {
    match zmanager_core::apple_archive_backend::test_apple_archive_filter(archive, |name| {
        entry_selected(name, includes, excludes)
    }) {
        Ok(report) => {
            print_data_test_success(
                FORMAT_APPLE_ARCHIVE,
                report.tested_entries,
                report.skipped_entries,
                report.tested_bytes,
                global,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("aar test failed: {error}"));
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

fn run_tzap_test_new(
    archive: &str,
    password: Option<&str>,
    includes: &[String],
    excludes: &[String],
    request: &TestRequest,
    global: &GlobalOptions,
) -> ExitCode {
    let x509_trust = is_tzap_archive(archive).then(|| test_request_x509_trust(request));
    let result = if let Some(recipient_key) = request.recipient_key.as_deref() {
        zmanager_core::tzap_backend::test_tzap_with_recipient_key_filter_and_x509_trust(
            archive,
            recipient_key,
            |name| entry_selected(name, includes, excludes),
            x509_trust.as_ref(),
        )
    } else {
        zmanager_core::tzap_backend::test_tzap_with_optional_password_filter_and_x509_trust(
            archive,
            password,
            |name| entry_selected(name, includes, excludes),
            x509_trust.as_ref(),
        )
    };
    match result {
        Ok(report) => {
            print_tzap_test_success(&report, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("tzap test failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_tzap_public_no_key_test(
    archive: &str,
    request: &TestRequest,
    global: &GlobalOptions,
) -> ExitCode {
    let trust = test_request_x509_trust(request);
    match zmanager_core::tzap_backend::verify_tzap_x509_public_no_key(archive, &trust) {
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

fn run_libarchive_data_test_new(
    archive: &str,
    password: Option<&str>,
    includes: &[String],
    excludes: &[String],
    format: &str,
    global: &GlobalOptions,
) -> ExitCode {
    match zmanager_core::libarchive_backend::test_archive_with_password_filter(
        archive,
        password,
        |name| entry_selected(name, includes, excludes),
    ) {
        Ok(report) => {
            print_data_test_success(
                format,
                report.tested_entries,
                report.skipped_entries,
                report.tested_bytes,
                global,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("{format} test failed: {error}"));
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

fn print_tzap_test_success(
    report: &zmanager_core::tzap_backend::TzapTestReport,
    global: &GlobalOptions,
) {
    if global.json {
        print!(
            "{{\"status\":\"ok\",\"format\":\"{}\",\"entries\":{},\"tested_entries\":{},\"skipped_entries\":{},\"bytes\":{}",
            FORMAT_TZAP,
            report.entries,
            report.tested_entries,
            report.skipped_entries,
            report.tested_bytes
        );
        if let Some(root_auth) = &report.x509_root_auth {
            print!(",\"root_auth\":");
            print_tzap_x509_root_auth_json(root_auth);
        }
        println!("}}");
    } else {
        print_data_test_success(
            FORMAT_TZAP,
            report.tested_entries,
            report.skipped_entries,
            report.tested_bytes,
            global,
        );
        if let Some(root_auth) = &report.x509_root_auth {
            print_tzap_x509_root_auth_text(root_auth, false, global);
        }
    }
}

fn print_tzap_public_no_key_success(
    root_auth: &zmanager_core::tzap_backend::TzapX509VerificationReport,
    archive: &str,
    global: &GlobalOptions,
) {
    if global.json {
        print!(
            "{{\"status\":\"ok\",\"format\":\"{}\",\"verification_mode\":\"public-no-key\",\"archive\":\"{}\",\"root_auth\":",
            FORMAT_TZAP,
            json_escape(archive)
        );
        print_tzap_x509_root_auth_json(root_auth);
        print!(",\"public_diagnostics\":");
        print_json_string_array(&root_auth.diagnostics);
        println!("}}");
    } else {
        print_success_line(
            global,
            format_args!(
                "{FORMAT_TZAP} test ok: public no-key, {} data blocks",
                root_auth.total_data_block_count
            ),
        );
        print_tzap_x509_root_auth_text(root_auth, true, global);
        print_tzap_x509_diagnostics_text(root_auth, "public-no-key", global);
    }
}

fn print_tzap_x509_root_auth_json(
    root_auth: &zmanager_core::tzap_backend::TzapX509VerificationReport,
) {
    let status = root_auth
        .diagnostics
        .first()
        .map_or("root_auth_content_verified", String::as_str);
    print!("{{\"status\":\"{}\",\"diagnostics\":", json_escape(status));
    print_json_string_array(&root_auth.diagnostics);
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

fn print_tzap_x509_root_auth_text(
    root_auth: &zmanager_core::tzap_backend::TzapX509VerificationReport,
    public_no_key: bool,
    global: &GlobalOptions,
) {
    let mode = if public_no_key {
        "public-no-key x509"
    } else {
        "x509"
    };
    print_success_line(
        global,
        format_args!(
            "root-auth: OK {mode} {}",
            hex_lower(&root_auth.archive_root)
        ),
    );
    print_success_line(
        global,
        format_args!("root-auth signer: {}", root_auth.subject),
    );
    print_success_line(
        global,
        format_args!("root-auth issuer: {}", root_auth.issuer),
    );
    if let Some(trust_anchor) = &root_auth.trust_anchor_subject {
        print_success_line(
            global,
            format_args!("root-auth trust-anchor: {trust_anchor}"),
        );
    }
    print_tzap_x509_diagnostics_text(root_auth, "root-auth", global);
}

fn print_tzap_x509_diagnostics_text(
    root_auth: &zmanager_core::tzap_backend::TzapX509VerificationReport,
    prefix: &str,
    global: &GlobalOptions,
) {
    for diagnostic in &root_auth.diagnostics {
        print_success_line(global, format_args!("{prefix}: {diagnostic}"));
    }
}

fn print_json_string_array(values: &[String]) {
    print!("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!("\"{}\"", json_escape(value));
    }
    print!("]");
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

fn parse_volume_size(value: &str, option: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("invalid size for {option}: {value}"));
    }

    let split_at = trimmed
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, unit) = trimmed.split_at(split_at);
    if digits.is_empty() {
        return Err(format!("invalid size for {option}: {value}"));
    }
    let amount = digits
        .parse::<u64>()
        .map_err(|_| format!("invalid size for {option}: {value}"))?;
    if amount == 0 {
        return Err(format!(
            "invalid size for {option}: size must be greater than zero"
        ));
    }

    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => SIZE_UNIT_KIB,
        "m" | "mb" | "mib" => SIZE_UNIT_MIB,
        "g" | "gb" | "gib" => SIZE_UNIT_GIB,
        "t" | "tb" | "tib" => SIZE_UNIT_TIB,
        _ => return Err(format!("invalid size unit for {option}: {value}")),
    };

    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size for {option} is too large: {value}"))
}

fn parse_archive_format(raw: &str) -> Result<ArchiveFormat, String> {
    match raw {
        FORMAT_ZIP => Ok(ArchiveFormat::Zip),
        raw if TAR_ZST_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::TarZst),
        raw if TZAP_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::Tzap),
        raw if APPLE_ARCHIVE_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::AppleArchive),
        FORMAT_SEVEN_Z => Ok(ArchiveFormat::SevenZ),
        raw if TGZ_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::Tgz),
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
    } else if is_tgz_archive(path) {
        Some(ArchiveFormat::Tgz)
    } else if is_tzap_archive(path) {
        Some(ArchiveFormat::Tzap)
    } else if is_apple_archive(path) {
        Some(ArchiveFormat::AppleArchive)
    } else if path_has_known_extension(path, SEVEN_Z_EXTENSIONS) {
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

fn create_test_archive_path(
    destination: &Path,
    format: ArchiveFormat,
    split_output: bool,
) -> PathBuf {
    if split_output && format == ArchiveFormat::SevenZ {
        let mut path = destination.as_os_str().to_os_string();
        path.push(".001");
        PathBuf::from(path)
    } else {
        destination.to_path_buf()
    }
}

fn publish_archive(temp: &Path, destination: &Path, force: bool) -> io::Result<()> {
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
        return Err(io::Error::new(
            io::ErrorKind::IsADirectory,
            format!("cannot replace directory {}", path.display()),
        ));
    }

    fs::remove_file(path)
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
        .chain(APPLE_ARCHIVE_EXTENSIONS)
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

fn validate_recipient_key_open_option(
    command: &str,
    archive: &str,
    password_stdin: bool,
    recipient_key: Option<&PathBuf>,
    global: &GlobalOptions,
) -> Option<ExitCode> {
    recipient_key?;
    if !is_tzap_archive(archive) {
        return Some(usage_failure(
            global,
            format_args!("{command} failed: --recipient-key is supported only for TZAP archives"),
        ));
    }
    if password_stdin {
        return Some(usage_failure(
            global,
            format_args!(
                "{command} failed: --recipient-key cannot be combined with --password-stdin"
            ),
        ));
    }
    None
}

fn list_entries_with_password(
    archive: &str,
    password: Option<&str>,
    recipient_key: Option<&Path>,
) -> Result<Vec<GenericEntry>, String> {
    if is_zip_family_archive(archive) && !is_split_zip_archive_path(archive) {
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
                        ..GenericEntry::default()
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
                        ..GenericEntry::default()
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
            ..GenericEntry::default()
        }])
    } else if is_tzap_archive(archive) {
        let listing = if let Some(recipient_key) = recipient_key {
            zmanager_core::tzap_backend::list_tzap_with_recipient_key(archive, recipient_key)
        } else {
            zmanager_core::tzap_backend::list_tzap_with_optional_password(archive, password)
        };
        listing
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: match entry.kind {
                            zmanager_core::tzap_backend::TzapEntryKind::File => "file",
                            zmanager_core::tzap_backend::TzapEntryKind::Directory => "directory",
                            zmanager_core::tzap_backend::TzapEntryKind::Symlink => "symlink",
                            zmanager_core::tzap_backend::TzapEntryKind::Hardlink => "hardlink",
                            zmanager_core::tzap_backend::TzapEntryKind::CharacterDevice => {
                                "character-device"
                            }
                            zmanager_core::tzap_backend::TzapEntryKind::BlockDevice => {
                                "block-device"
                            }
                            zmanager_core::tzap_backend::TzapEntryKind::Fifo => "fifo",
                        }
                        .to_owned(),
                        name: entry.path,
                        size: entry.size,
                        compressed_size: None,
                        mode: Some(entry.mode),
                        modified: tzap_timestamp_string(entry.mtime, entry.mtime_nanoseconds),
                        metadata_diagnostics: entry.metadata_diagnostics,
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    } else if is_apple_archive(archive) {
        zmanager_core::apple_archive_backend::list_apple_archive(archive)
            .map(|listing| {
                listing
                    .entries
                    .into_iter()
                    .map(|entry| GenericEntry {
                        kind: match entry.kind {
                            zmanager_core::apple_archive_backend::AppleArchiveEntryKind::File => {
                                "file"
                            }
                            zmanager_core::apple_archive_backend::AppleArchiveEntryKind::Directory => {
                                "directory"
                            }
                            zmanager_core::apple_archive_backend::AppleArchiveEntryKind::Symlink => {
                                "symlink"
                            }
                            zmanager_core::apple_archive_backend::AppleArchiveEntryKind::Device
                            | zmanager_core::apple_archive_backend::AppleArchiveEntryKind::Special => {
                                "special"
                            }
                        }
                        .to_owned(),
                        name: entry.path,
                        size: entry.size.unwrap_or(0),
                        compressed_size: None,
                        ..GenericEntry::default()
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
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
                        ..GenericEntry::default()
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
                        ..GenericEntry::default()
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
        let compressed_size = entry
            .compressed_size
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let mode = entry
            .mode
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let modified = serde_json::to_string(&entry.modified).unwrap_or_else(|_| "null".to_owned());
        let metadata_diagnostics =
            serde_json::to_string(&entry.metadata_diagnostics).unwrap_or_else(|_| "[]".to_owned());
        print!(
            "{{\"kind\":\"{}\",\"name\":\"{}\",\"size\":{},\"compressed_size\":{compressed_size},\"mode\":{mode},\"modified\":{modified},\"metadata_diagnostics\":{metadata_diagnostics}}}",
            json_escape(&entry.kind),
            json_escape(&entry.name),
            entry.size,
        );
    }
    println!("]}}");
}

fn tzap_timestamp_string(seconds: i64, nanoseconds: u32) -> Option<String> {
    if seconds == 0 && nanoseconds == 0 {
        return None;
    }
    if nanoseconds == 0 {
        return Some(seconds.to_string());
    }
    let fraction = format!("{nanoseconds:09}");
    Some(format!("{seconds}.{}", fraction.trim_end_matches('0')))
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
    if let Some(volume_size) = outcome.volume_size {
        print!(",\"volume_size\":{volume_size}");
    }
    if outcome.volume_count > 1 {
        print!(",\"volume_count\":{}", outcome.volume_count);
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

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
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
    "--volume-size",
    "--clean",
    "--no-ignore",
    "--no-hidden",
    "-j",
    "--junk-paths",
    "--follow-symlinks",
    "--force",
    "--encrypt",
    "--password-stdin",
    "--recipient-cert",
    "--signing-cert",
    "--signing-private-key",
    "--signing-chain",
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
    "--recipient-key",
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
    "--recipient-key",
    "--trusted-ca-cert",
    "--trusted-system-roots",
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
    "--recipient-key",
    "--public-no-key",
    "--trusted-ca-cert",
    "--trusted-system-roots",
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

fn is_split_zip_archive_path(path: &str) -> bool {
    zmanager_core::libarchive_backend::is_split_zip_path(Path::new(path))
}

fn is_7z_archive(path: &str) -> bool {
    path_has_known_extension(path, SEVEN_Z_EXTENSIONS)
        || zmanager_core::sevenz_backend::is_7z_volume_path(Path::new(path))
}

fn is_rar_archive(path: &str) -> bool {
    path_has_known_extension(path, RAR_EXTENSIONS)
}

fn is_tar_zst_archive(path: &str) -> bool {
    path_has_known_extension(path, TAR_ZST_EXTENSIONS)
}

fn is_tgz_archive(path: &str) -> bool {
    path_has_known_extension(path, TGZ_EXTENSIONS)
}

fn is_tzap_archive(path: &str) -> bool {
    path_has_known_extension(path, TZAP_EXTENSIONS) || is_tzap_volume_archive(path)
}

fn is_apple_archive(path: &str) -> bool {
    path_has_known_extension(path, APPLE_ARCHIVE_EXTENSIONS)
}

fn is_tzap_volume_archive(path: &str) -> bool {
    let Some((base_path, volume_index)) = path.rsplit_once('.') else {
        return false;
    };

    volume_index.len() >= 3
        && volume_index
            .chars()
            .all(|character| character.is_ascii_digit())
        && path_has_known_extension(base_path, TZAP_EXTENSIONS)
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
        let result = zmanager_core::zip_backend::extract_zip_with_context_and_password(
            &archive_path,
            &destination_path,
            policy.clone(),
            password,
            &mut context,
        );
        context.flush_progress();
        result
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
        let result = zmanager_core::tar_zst_backend::extract_tar_zst_with_context(
            &archive_path,
            &destination_path,
            policy,
            &mut context,
        );
        context.flush_progress();
        result
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

fn run_apple_archive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::AppleArchiveExtract,
        total_bytes: None,
    });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::apple_archive_backend::extract_apple_archive_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            policy,
            &mut overwrite_resolver,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        let result = zmanager_core::apple_archive_backend::extract_apple_archive_with_context(
            &archive_path,
            &destination_path,
            policy,
            &mut context,
        );
        context.flush_progress();
        result
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_APPLE_ARCHIVE,
                format: FORMAT_APPLE_ARCHIVE,
                backend: FORMAT_APPLE_ARCHIVE,
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
            eprintln!("aar extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_tzap_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    restore_options: zmanager_core::tzap_backend::TzapRestoreOptions,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started {
        kind: JobKind::TzapExtract,
        total_bytes: None,
    });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        if let Some(recipient_key) = recipient_key {
            zmanager_core::tzap_backend::extract_tzap_with_overwrite_resolver_and_recipient_key_and_restore_options(
                &archive_path,
                &destination_path,
                policy,
                recipient_key,
                restore_options,
                &mut overwrite_resolver,
            )
        } else {
            zmanager_core::tzap_backend::extract_tzap_with_overwrite_resolver_and_optional_password_and_restore_options(
                &archive_path,
                &destination_path,
                policy,
                password,
                restore_options,
                &mut overwrite_resolver,
            )
        }
    } else if let Some(recipient_key) = recipient_key {
        zmanager_core::tzap_backend::extract_tzap_with_recipient_key_and_restore_options(
            &archive_path,
            &destination_path,
            policy,
            recipient_key,
            restore_options,
        )
    } else {
        zmanager_core::tzap_backend::extract_tzap_with_optional_password_and_restore_options(
            &archive_path,
            &destination_path,
            policy,
            password,
            restore_options,
        )
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: FORMAT_TZAP,
                format: FORMAT_TZAP,
                backend: FORMAT_TZAP,
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
            eprintln!("tzap extract failed: {error}");
            ExitCode::FAILURE
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{
        ArchiveFormat, CreateRequest, ExtractRequest, GlobalOptions, InteractiveOverwriteResolver,
        ListRequest, TestRequest, normalize_prompted_password, parse_create_request,
        parse_extract_request, parse_list_request, parse_test_request, publish_archive,
        tzap_default_volume_loss_tolerance, validate_create_options,
    };
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
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
    fn create_parser_accepts_tzap_x509_signing_options() {
        let mut request = CreateRequest::default();
        let mut global = GlobalOptions::default();
        let args = strings([
            "signed.tzap",
            "src",
            "--format",
            "tzap",
            "--password-stdin",
            "--signing-cert",
            "signer.pem",
            "--signing-private-key",
            "signer.key",
            "--signing-chain",
            "intermediate.pem",
        ]);

        parse_create_request(&args, &mut global, &mut request).unwrap();

        assert_eq!(request.tzap_signing_cert, Some(PathBuf::from("signer.pem")));
        assert_eq!(
            request.tzap_signing_private_key,
            Some(PathBuf::from("signer.key"))
        );
        assert_eq!(
            request.tzap_signing_chain,
            vec![PathBuf::from("intermediate.pem")]
        );
        assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
    }

    #[test]
    fn create_validation_restricts_x509_signing_to_tzap() {
        let request = CreateRequest {
            archive: "signed.zip".to_owned(),
            sources: vec![PathBuf::from("src")],
            tzap_signing_cert: Some(PathBuf::from("signer.pem")),
            tzap_signing_private_key: Some(PathBuf::from("signer.key")),
            ..CreateRequest::default()
        };

        let error = validate_create_options(ArchiveFormat::Zip, &request).unwrap_err();

        assert!(error.contains("only for TZAP"));
    }

    #[test]
    fn create_parser_accepts_tzap_recipient_certificate() {
        let mut request = CreateRequest::default();
        let mut global = GlobalOptions::default();
        let args = strings([
            "sealed.tzap",
            "src",
            "--format",
            "tzap",
            "--recipient-cert",
            "recipient.pem",
        ]);

        parse_create_request(&args, &mut global, &mut request).unwrap();

        assert_eq!(
            request.tzap_recipient_cert,
            Some(PathBuf::from("recipient.pem"))
        );
        assert!(validate_create_options(ArchiveFormat::Tzap, &request).is_ok());
    }

    #[test]
    fn create_validation_rejects_recipient_certificate_password_mode() {
        let request = CreateRequest {
            archive: "sealed.tzap".to_owned(),
            sources: vec![PathBuf::from("src")],
            format: Some(ArchiveFormat::Tzap),
            password_stdin: true,
            tzap_recipient_cert: Some(PathBuf::from("recipient.pem")),
            ..CreateRequest::default()
        };

        let error = validate_create_options(ArchiveFormat::Tzap, &request).unwrap_err();

        assert!(error.contains("--recipient-cert cannot be combined"));
    }

    #[test]
    fn open_parsers_accept_tzap_recipient_key() {
        let mut global = GlobalOptions::default();

        let mut extract = ExtractRequest::default();
        let extract_args = strings([
            "sealed.tzap",
            "-C",
            "out",
            "--recipient-key",
            "recipient.key",
        ]);
        parse_extract_request(&extract_args, &mut global, &mut extract).unwrap();
        assert_eq!(extract.recipient_key, Some(PathBuf::from("recipient.key")));

        let mut list = ListRequest::default();
        let list_args = strings(["sealed.tzap", "--recipient-key", "recipient.key"]);
        parse_list_request(&list_args, &mut global, &mut list).unwrap();
        assert_eq!(list.recipient_key, Some(PathBuf::from("recipient.key")));

        let mut test = TestRequest::default();
        let test_args = strings(["sealed.tzap", "--recipient-key", "recipient.key"]);
        parse_test_request(&test_args, &mut global, &mut test).unwrap();
        assert_eq!(test.recipient_key, Some(PathBuf::from("recipient.key")));
    }

    #[test]
    fn extract_parser_accepts_tzap_metadata_restore_options() {
        let mut request = ExtractRequest::default();
        let mut global = GlobalOptions::default();
        let args = strings([
            "archive.tzap",
            "-C",
            "out",
            "--restore",
            "same-os",
            "--allow-degraded",
        ]);

        parse_extract_request(&args, &mut global, &mut request).unwrap();

        assert_eq!(
            request.tzap_restore_policy,
            zmanager_core::tzap_backend::TzapRestorePolicy::SameOs
        );
        assert!(request.tzap_allow_degraded);
    }

    #[test]
    fn extract_parser_rejects_unknown_tzap_restore_policy() {
        let mut request = ExtractRequest::default();
        let mut global = GlobalOptions::default();
        let args = strings(["archive.tzap", "--restore", "everything"]);

        let error = parse_extract_request(&args, &mut global, &mut request).unwrap_err();

        assert!(error.contains("content, portable, same-os, or system"));
    }

    #[test]
    fn tzap_split_create_defaults_to_one_volume_loss_tolerance() {
        assert_eq!(tzap_default_volume_loss_tolerance(None), 0);
        assert_eq!(
            tzap_default_volume_loss_tolerance(Some(10 * 1024 * 1024)),
            1
        );
    }

    #[test]
    fn test_parser_accepts_tzap_x509_trust_options() {
        let mut request = TestRequest::default();
        let mut global = GlobalOptions::default();
        let args = strings([
            "signed.tzap",
            "--password-stdin",
            "--public-no-key",
            "--trusted-ca-cert",
            "root.pem",
            "--trusted-system-roots",
        ]);

        parse_test_request(&args, &mut global, &mut request).unwrap();

        assert_eq!(request.trusted_ca_certs, vec![PathBuf::from("root.pem")]);
        assert!(request.trusted_system_roots);
        assert!(request.public_no_key);
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

    #[test]
    fn publish_archive_refuses_existing_destination_without_force() {
        let temp = TestDir::new("publish_refuses_existing");
        let archive_temp = temp.path("archive.tmp");
        let destination = temp.path("archive.zip");
        fs::write(&archive_temp, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();

        let error = publish_archive(&archive_temp, &destination, false).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert_eq!(fs::read(&archive_temp).unwrap(), b"new");
    }

    #[test]
    fn publish_archive_replaces_existing_file_with_force() {
        let temp = TestDir::new("publish_force_replaces");
        let archive_temp = temp.path("archive.tmp");
        let destination = temp.path("archive.zip");
        fs::write(&archive_temp, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();

        publish_archive(&archive_temp, &destination, true).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert!(!archive_temp.exists());
    }

    #[test]
    fn publish_archive_force_refuses_directory_destination() {
        let temp = TestDir::new("publish_force_refuses_directory");
        let archive_temp = temp.path("archive.tmp");
        let destination = temp.path("archive.zip");
        fs::write(&archive_temp, b"new").unwrap();
        fs::create_dir(&destination).unwrap();

        let error = publish_archive(&archive_temp, &destination, true).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
        assert!(destination.is_dir());
        assert_eq!(fs::read(&archive_temp).unwrap(), b"new");
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

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.map(ToOwned::to_owned).to_vec()
    }

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("zmanager-cli-{name}-{}-{now}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
