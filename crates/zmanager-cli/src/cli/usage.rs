use crate::cli::app::{CreateOutcome, ExtractOutcome, GenericEntry};
use crate::cli::options::GlobalOptions;
use crate::output::{self, StyleRole};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use zmanager_core::secrets::SecretString;
// The `auth` command line exists only in the full build; the offline build
// has no online identity surface and its help must not advertise one.
// concat!() requires string literals, so the line is supplied through a
// cfg-selected macro instead of a runtime format.
#[cfg(feature = "tzap-online")]
macro_rules! auth_command_usage_line {
    () => {
        "  auth <command>                 Online identity and certificate enrollment\n"
    };
}
#[cfg(not(feature = "tzap-online"))]
macro_rules! auth_command_usage_line {
    () => {
        ""
    };
}

pub(crate) const USAGE: &str = concat!(
    "\
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
  tzap <command>                 Sign, verify, and share TZAP documents
",
    auth_command_usage_line!(),
    "  doctor                         Verify the archive engine
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
"
);

pub(crate) const CREATE_HELP: &str = "\
Create ZIP, TAR.ZST, TZAP, AAR, 7Z, or TGZ archives

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
      --signing-identity [id]    Sign TZAP RootAuth with a local enrolled certificate;
                                  uses the single active one when id is omitted
                                  (mutually exclusive with --signing-cert)
      --sidecar                  Emit TZAP bootstrap recovery sidecar (.sidecar) file
      --no-sidecar               Disable TZAP bootstrap recovery sidecar (default)
  TZAP without a password uses tzap's unencrypted mode.
  Use --encrypt or --password-stdin when confidentiality is required.
";

pub(crate) const EXTRACT_HELP: &str = "\
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

pub(crate) const LIST_HELP: &str = "\
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

pub(crate) const TEST_HELP: &str = "\
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

pub(crate) const PLAN_HELP: &str = "\
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

pub(crate) const FORMATS_HELP: &str = "\
Show supported archive formats

Usage:
  zm formats [--json]
  zm formats --contract

Examples:
  zm formats
  zm formats --json
  zm formats --contract

--contract prints the byte-stable capability contract (kind/label/extensions
per format, no platform-dependent fields) consumed by downstream projects;
regenerate crates/zmanager-cli/contracts/archive-formats.json with
scripts/refresh-format-contract.sh.

Create:
  zip       .zip
  tar.zst   .tar.zst, .tzst
  tzap      .tzap
  aar       .aar
  7z        .7z
  tgz       .tgz, .tar.gz

Extract/List/Test:
  zip       .zip, .zipx, .jar, .war, .ipa, .apk, .appx, .xpi
  tar.zst   .tar.zst, .tzst
  tzap      .tzap
  aar       .aar, .aea (macOS/iOS)
  7z        .7z
  tgz       .tgz, .tar.gz
  raw       .zst, .gz, .bz2, .xz, .lzma, .lz, .br, .lz4, .lzo, .Z, .uu, .b64
  rar       .rar, .cbr; passworded list/extract uses bundled UnRAR with --password-stdin
raw single-file streams decompress to one file. TAR-wrapped streams such as
project.tar.zst or project.tar.gz extract as archives.
";

pub(crate) const DOCTOR_HELP: &str = "\
Verify the installed CLI and archive engine

Usage:
  zm doctor [--json]

Examples:
  zm doctor
  zm doctor --json

Use --json in scripts and bug reports.
";

pub(crate) const TZAP_MENU_HELP: &str = "\
Sign, verify, and share TZAP documents

Usage:
  zm tzap <command> [options]

Commands:
  sign <input>                   Sign a TZAP document JSON payload
  verify <input>                 Verify a TZAP document envelope
  contact <command>              Manage TZAP contact cards
  share <archive> <paths...>     Create a TZAP archive for contacts
  certs                          List the local TZAP certificate catalogue

Options:
      --json                     Emit machine-readable JSON where supported

`zm tzap` works entirely offline, against certificates and signing keys
already in the local identity catalogue. Use `zm auth cert enroll` (full
build only) or the desktop/mobile app to obtain one.
";

#[cfg(feature = "tzap-online")]
pub(crate) const AUTH_MENU_HELP: &str = "\
Online identity and certificate enrollment

Usage:
  zm auth <command> [options]

Commands:
  login                          Hosted TZAP auth login
  callback                       Process auth callback
  status                         Show auth status
  forget                         Forget local auth material
  account                        Show account URL
  me                             Show the local TZAP session summary
  cert <command>                 Enroll, renew, and revoke TZAP certificates
  device retire                  Retire local TZAP device material
  device revoke                  Revoke a TZAP device remotely

Options:
      --environment <name>       Select a hosted service environment (local|staging|prod)
      --auth-base-url <url>      Override the hosted auth service base URL
      --account-base-url <url>   Override the hosted account service base URL
      --client-id <id>           Override the OAuth client id
      --redirect-uri <url>       Override the OAuth callback redirect URI
      --provider <name>          Require a specific login provider integration
      --org-id <id>              Require a specific login organization
      --state-dir <dir>          Read and write local auth/session state from dir
      --account-key <key>        Local account inventory key; default is default
      --json                     Emit machine-readable JSON (status, account, and sign in/out)

`zm auth` commands manage your identity and certificate enrollment. Once
enrolled, sign documents and share archives with `zm tzap` — it works in
every build, including the offline one.
";

#[cfg(feature = "tzap-online")]
pub(crate) const ME_HELP: &str = "\
Show the local TZAP session summary

Usage:
  zm auth me [options]

Options:
      --state-dir <dir>          Read local auth/session state from dir
      --account-key <key>        Local account inventory key; default is default
      --json                     Emit machine-readable JSON
";

#[cfg(feature = "tzap-online")]
pub(crate) const CERT_HELP: &str = "\
Enroll, renew, and revoke TZAP certificates

Usage:
  zm auth cert enroll [options]
  zm auth cert renew [options]
  zm auth cert revoke [options]

Options:
      --state-dir <dir>          Store local identity/session state in dir
      --account-key <key>        Local account inventory key; default is default
      --certificate-id <id>      Certificate id for renew/revoke
      --service-base-url <url>   Enroll/renew through a hosted TZAP sign API instead of the local fake profile
      --trusted-root-cert <file> Trust a staging root PEM/DER certificate for hosted enrollment/renewal
      --org-id <id>              Optional organization id for hosted enrollment/renewal
      --requested-validity-seconds <n>
                                  Requested hosted enrollment/renewal certificate lifetime
      --json                     Emit machine-readable JSON

Enroll, renew, and revoke use the local fake TZAP service profile by default
for deterministic harness runs. `zm tzap certs` reads the resulting local
inventory read-only, in every build.
";

#[cfg(feature = "tzap-online")]
pub(crate) const DEVICE_HELP: &str = "\
Manage local TZAP device material

Usage:
  zm auth device retire [options]
  zm auth device revoke [options]

Options:
      --state-dir <dir>          Store local identity/session state in dir
      --account-key <key>        Local account inventory key; default is default
      --device-id <id>           Sign device id for revoke
      --service-base-url <url>   Revoke through a hosted TZAP sign API (default: production)
      --json                     Emit machine-readable JSON
";

pub(crate) const SIGN_HELP: &str = "\
Sign a TZAP document JSON payload

Usage:
  zm tzap sign <input.json> --certificate-id <id> --output <envelope.json> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --certificate-id <id>      Local enrolled certificate id
      --output <file>            Destination envelope JSON file
      --claimed-signing-time <text>
                                  Optional claimed signing time string
      --json                     Emit machine-readable JSON
";

pub(crate) const VERIFY_HELP: &str = "\
Verify a TZAP document envelope

Usage:
  zm tzap verify <envelope.json> [options]

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
verification — fetching the status needs the network, using it does not, so
this works in the offline build too. Custom trust is reported as custom
trust, never official TZAP.
";

pub(crate) const CONTACT_HELP: &str = "\
Manage TZAP contact cards

Usage:
  zm tzap contact keygen [--label <name>] [options]
  zm tzap contact export --recipient-key-id <id> --certificate-id <id> --display-name <name> --output <file>
  zm tzap contact import <card.json> --accept [options]
  zm tzap contact list [options]
  zm tzap contact remove <contact-id> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --label <name>             Local label for a newly generated recipient key
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

pub(crate) const SHARE_HELP: &str = "\
Create a TZAP archive for accepted contacts

Usage:
  zm tzap share <archive.tzap> <paths...> --contact <id> --certificate-id <id> [options]

Options:
      --state-dir <dir>          Store local identity state in dir
      --account-key <key>        Local account inventory key; default is default
      --contact <id>             Accepted contact id; repeat for multiple recipients
      --certificate-id <id>      Active local certificate used for RootAuth signing
      --force                    Replace an existing output archive
      --json                     Emit machine-readable JSON
";

pub(crate) const CERTS_HELP: &str = "\
List the local TZAP certificate catalogue

Usage:
  zm tzap certs [options]

Options:
      --state-dir <dir>          Read local identity state from dir
      --account-key <key>        Local account inventory key; default is default
      --json                     Emit machine-readable JSON

Reads the local identity catalogue only — no network access. Use this to find
a --certificate-id for `zm tzap sign` or `zm tzap share`.
";

pub(crate) const COMPLETIONS_HELP: &str = "\
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
pub(crate) const COMPLETION_BASH_SCRIPT: &str = include_str!("../../completions/zm.bash");
pub(crate) const COMPLETION_ZSH_SCRIPT: &str = include_str!("../../completions/_zm");
pub(crate) const COMPLETION_FISH_SCRIPT: &str = include_str!("../../completions/zm.fish");
pub(crate) const COMPLETION_POWERSHELL_SCRIPT: &str = include_str!("../../completions/zm.ps1");
pub(crate) fn wants_help(args: &[String]) -> bool {
    args.iter().take_while(|arg| arg.as_str() != "--").any(|arg| matches!(arg.as_str(), "-h" | "--help"))
}

pub(crate) fn help_command(args: &[String], global: &GlobalOptions) -> ExitCode {
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
        output::stderr_line(global.color, format_args!("Try 'zm --help' for available commands."));
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
        "tzap" => Some(TZAP_MENU_HELP),
        "sign" => Some(SIGN_HELP),
        "verify" => Some(VERIFY_HELP),
        "contact" => Some(CONTACT_HELP),
        "share" => Some(SHARE_HELP),
        "certs" => Some(CERTS_HELP),
        #[cfg(feature = "tzap-online")]
        "auth" => Some(AUTH_MENU_HELP),
        #[cfg(feature = "tzap-online")]
        "me" => Some(ME_HELP),
        #[cfg(feature = "tzap-online")]
        "cert" => Some(CERT_HELP),
        #[cfg(feature = "tzap-online")]
        "device" => Some(DEVICE_HELP),
        "doctor" | "healthcheck" => Some(DOCTOR_HELP),
        "completions" | "completion" => Some(COMPLETIONS_HELP),
        _ => None,
    }
}

pub(crate) fn print_help_stdout(help: &str, global: &GlobalOptions) {
    output::stdout_write(global.color, format_args!("{}", output::render_help(help)));
}

pub(crate) fn print_help_stderr(help: &str, global: &GlobalOptions) {
    output::stderr_write(global.color, format_args!("{}", output::render_help(help)));
}

pub(crate) fn print_error_line(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stderr_line(global.color, format_args!("{}", output::styled(StyleRole::Error, message)));
}

pub(crate) fn print_optional_error_line(global: Option<&GlobalOptions>, message: std::fmt::Arguments<'_>) {
    if let Some(global) = global {
        print_error_line(global, message);
    } else {
        eprintln!("{message}");
    }
}

pub(crate) fn usage_failure(global: &GlobalOptions, message: std::fmt::Arguments<'_>) -> ExitCode {
    print_error_line(global, message);
    ExitCode::from(2)
}

pub(crate) fn print_success_line(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stdout_line(global.color, format_args!("{}", output::styled(StyleRole::Success, message)));
}

pub(crate) fn print_warning_stdout(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stdout_line(global.color, format_args!("{}", output::styled(StyleRole::Warning, message)));
}

pub(crate) fn print_warning_stderr(global: &GlobalOptions, message: std::fmt::Arguments<'_>) {
    output::stderr_line(global.color, format_args!("{}", output::styled(StyleRole::Warning, message)));
}
pub(crate) fn print_entries_tree(entries: &[GenericEntry], global: &GlobalOptions) {
    let mut printed = BTreeSet::new();
    let mut names = entries.iter().collect::<Vec<_>>();
    names.sort_by(|left, right| left.name.cmp(&right.name));

    for entry in names {
        let trimmed = entry.name.trim_matches('/');
        if trimmed.is_empty() {
            continue;
        }
        let parts = trimmed.split('/').filter(|part| !part.is_empty()).collect::<Vec<_>>();
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

pub(crate) fn print_entries_json(entries: &[GenericEntry]) {
    print!("{{\"entries\":[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        let compressed_size = entry.compressed_size.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let mode = entry.mode.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let modified = json_optional_string(entry.modified.as_deref());
        let created = json_optional_string(entry.created.as_deref());
        let accessed = json_optional_string(entry.accessed.as_deref());
        let encrypted = entry.encrypted.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let method = json_optional_string(entry.method.as_deref());
        let solid = entry.solid.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let link_target = json_optional_string(entry.link_target.as_deref());
        let attributes = json_optional_string(entry.attributes.as_deref());
        let uid = entry.uid.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let gid = entry.gid.map_or_else(|| "null".to_owned(), |value| value.to_string());
        let owner = json_optional_string(entry.owner.as_deref());
        let group = json_optional_string(entry.group.as_deref());
        let metadata_diagnostics = json_string_array(&entry.metadata_diagnostics);
        print!(
            "{{\"kind\":\"{}\",\"name\":\"{}\",\"size\":{},\"compressed_size\":{compressed_size},\"mode\":{mode},\"modified\":{modified},\"created\":{created},\"accessed\":{accessed},\"encrypted\":{encrypted},\"method\":{method},\"solid\":{solid},\"link_target\":{link_target},\"attributes\":{attributes},\"uid\":{uid},\"gid\":{gid},\"owner\":{owner},\"group\":{group},\"metadata_diagnostics\":{metadata_diagnostics}}}",
            json_escape(&entry.kind),
            json_escape(&entry.name),
            entry.size,
        );
    }
    println!("]}}");
}

pub(crate) fn json_optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", json_escape(value)))
}

pub(crate) fn json_string_array(values: &[impl AsRef<str>]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let _ = write!(output, "\"{}\"", json_escape(value.as_ref()));
    }
    output.push(']');
    output
}
pub(crate) fn print_create_summary(archive: &Path, outcome: &CreateOutcome, global: &GlobalOptions) {
    if global.json {
        print_create_summary_json(archive, outcome);
    } else if !global.quiet {
        print_success_line(global, format_args!("{}", outcome.summary));
    }
    // Named on stderr even under --quiet and --json: the archive is missing
    // something the caller asked for, and a count in a summary line they may not
    // be reading is not telling them.
    for warning in &outcome.warning_texts {
        eprintln!("warning: {warning}");
    }
}

pub(crate) fn print_create_summary_json(archive: &Path, outcome: &CreateOutcome) {
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

pub(crate) fn print_extract_summary(archive: &Path, destination: &Path, outcome: &ExtractOutcome, global: &GlobalOptions) {
    if global.json {
        print_extract_summary_json(archive, destination, outcome);
    } else if !global.quiet {
        print_extract_summary_text(outcome, global);
    }
}

pub(crate) fn print_extract_summary_text(outcome: &ExtractOutcome, global: &GlobalOptions) {
    print_success_line(
        global,
        format_args!("{} extract ok: {} written, {} skipped, {} bytes", outcome.label, outcome.written_entries, outcome.skipped_entries, outcome.written_bytes),
    );
    for warning in &outcome.warnings {
        print_warning_stdout(global, format_args!("warning\t{warning}"));
    }
}

pub(crate) fn print_extract_summary_json(archive: &Path, destination: &Path, outcome: &ExtractOutcome) {
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

pub(crate) fn print_manifest(manifest: &zmanager_core::manifest::ArchiveManifest, global: &GlobalOptions) {
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
            print!("{{\"path\":\"{}\",\"size\":{}}}", json_escape(&entry.archive_path), entry.size);
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
            print_warning_stdout(global, format_args!("warning\t{}\t{}", warning.source_path.display(), warning.message));
        }
    }
}
pub(crate) fn json_escape(value: &str) -> String {
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

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}
pub(crate) fn command_usage_error(command: &str, message: &str, global: &GlobalOptions) -> ExitCode {
    let (formatted, unknown_option) = format_command_error(command, message);
    print_error_line(global, format_args!("error: {formatted}"));
    if let Some(option) = unknown_option
        && let Some(suggestion) = option_suggestion(command, option)
    {
        output::stderr_line(global.color, format_args!(""));
        output::stderr_line(global.color, format_args!("Did you mean '{}'?", output::styled(StyleRole::Option, format_args!("{suggestion}"))));
    }
    output::stderr_line(global.color, format_args!(""));
    output::stderr_write(global.color, format_args!("{}", output::render_help(command_usage_snippet(command))));
    output::stderr_line(global.color, format_args!(""));
    if unknown_option.is_some() {
        output::stderr_line(global.color, format_args!("Try '{}' for usage.", output::styled(StyleRole::Command, format_args!("zm {command} --help"))));
    } else {
        output::stderr_line(global.color, format_args!("Try '{}' for examples.", output::styled(StyleRole::Command, format_args!("zm {command} --help"))));
    }
    ExitCode::from(2)
}

fn format_command_error<'a>(command: &str, message: &'a str) -> (String, Option<&'a str>) {
    let prefix = format!("unknown {command} option: ");
    if let Some(option) = message.strip_prefix(&prefix) {
        (format!("unknown option '{option}' for 'zm {command}'"), Some(option))
    } else if let Some(argument) = message.strip_prefix("unexpected argument: ") {
        (format!("unexpected argument '{argument}' for 'zm {command}'"), None)
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
    "--signing-identity",
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

const PLAN_OPTIONS: &[&str] =
    &["--format", "-C", "--directory", "-@", "--files-from", "--null", "--clean", "--no-ignore", "-i", "--include", "--exclude", "--exclude-from"];

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
pub(crate) fn usage_error(message: &str, global: &GlobalOptions) -> ExitCode {
    print_error_line(global, format_args!("{message}"));
    print_help_stderr(USAGE, global);
    ExitCode::from(2)
}

pub(crate) fn prompt_password(prompt: &str) -> Result<SecretString, ExitCode> {
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

pub(crate) fn prompt_password_and_retry<T>(prompt: &str, retry: impl FnOnce(SecretString) -> T) -> Result<T, ExitCode> {
    prompt_password(prompt).map(retry)
}

/// Handles a `PasswordRequired` backend error when no password was supplied:
/// fails with `error_prefix` when prompts are disabled or unavailable, or
/// prompts for a password and re-runs `retry` with it.
///
/// `report_failure` receives the final error message so callers keep their
/// own error channel (progress events, styled stderr lines).
pub(crate) fn retry_password_required(
    global: &GlobalOptions,
    error_prefix: &str,
    prompt_label: Option<&str>,
    mut report_failure: impl FnMut(&str),
    retry: impl FnOnce(SecretString) -> ExitCode,
) -> ExitCode {
    if global.no_password_prompt {
        report_failure(&format!("{error_prefix}password required and prompts are disabled"));
        return ExitCode::from(2);
    }
    let Some(prompt_label) = prompt_label else {
        report_failure(&format!("{error_prefix}password required but no prompt is available"));
        return ExitCode::from(2);
    };
    match prompt_password_and_retry(prompt_label, retry) {
        Ok(result) => result,
        Err(code) => code,
    }
}

pub(crate) fn normalize_prompted_password(mut password: String, bytes_read: usize) -> Option<String> {
    if bytes_read == 0 {
        return None;
    }

    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }

    (!password.is_empty()).then_some(password)
}
