use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const COMPLETION_BASH: &str = include_str!("../../../completions/zm.bash");
const COMPLETION_FISH: &str = include_str!("../../../completions/zm.fish");
const COMPLETION_POWERSHELL: &str = include_str!("../../../completions/zm.ps1");
const COMPLETION_ZSH: &str = include_str!("../../../completions/_zm");
const MAN_PAGE: &str = include_str!("../../../docs/man/zm.1");
const INSTALL_DOC: &str = include_str!("../../../docs/INSTALL.md");
const RELEASE_DOC: &str = include_str!("../../../RELEASE.md");
const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");
const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const PACKAGE_PREVIEW_WORKFLOW: &str =
    include_str!("../../../.github/workflows/package-preview.yml");
const RELEASE_NOTES_1_0_4: &str = include_str!("../../../docs/release-notes/1.0.4.md");
const LIBARCHIVE_SYS_BUILD_RS: &str =
    include_str!("../../../crates/zmanager-libarchive-sys/build.rs");
const PACKAGE_RELEASE_SH: &str = include_str!("../../../scripts/package-release.sh");
const PACKAGE_METADATA_SH: &str = include_str!("../../../scripts/generate-package-metadata.sh");
const RELEASE_COMPATIBILITY_SH: &str =
    include_str!("../../../scripts/release-compatibility-check.sh");
const THIRD_PARTY_NOTICE_GENERATOR: &str =
    include_str!("../../../scripts/generate-third-party-notices.py");
const RUNTIME_DEPS_SH: &str = include_str!("../../../scripts/inspect-runtime-deps.sh");
const CI_WINDOWS_PS1: &str = include_str!("../../../scripts/ci-windows.ps1");
const HOMEBREW_TEMPLATE: &str = include_str!("../../../packaging/homebrew/zmanager.rb.template");
const WINGET_INSTALLER_TEMPLATE: &str =
    include_str!("../../../packaging/winget/FrankZhu.ZManagerCLI.installer.yaml.template");
const WINGET_LOCALE_TEMPLATE: &str =
    include_str!("../../../packaging/winget/FrankZhu.ZManagerCLI.locale.en-US.yaml.template");
const PUBLIC_COMMANDS: &[&str] = &[
    "create",
    "extract",
    "list",
    "test",
    "plan",
    "formats",
    "doctor",
    "completions",
    "help",
];
const LEGACY_COMMANDS: &[&str] = &[
    "zip-create",
    "zip-extract",
    "tar-zst-create",
    "7z-create",
    "libarchive-list",
    "libarchive-extract",
];

const TOP_LEVEL_FLAGS: &[&str] = &[
    "-h, --help",
    "-V, --version",
    "-q, --quiet",
    "-v, --verbose",
    "--json",
    "--color <auto|always|never>",
    "--no-color",
    "--progress <auto|always|never>",
    "--no-progress",
    "--no-password-prompt",
    "-c, --create",
    "-x, --extract",
    "-t, --list",
    "-T, --test",
    "-f, --file <archive>",
];

const CREATE_FLAGS: &[&str] = &[
    "--format <zip|tar.zst|tzap|7z>",
    "--method <method>",
    "--level <level>",
    "-0 .. -9",
    "-r, --recursive",
    "-C, --directory <dir>",
    "-@",
    "--files-from <file|->",
    "--null",
    "-i, --include <glob>",
    "--exclude <glob>",
    "--exclude-from <file>",
    "--store",
    "--solid",
    "--no-solid",
    "--volume-size <size>",
    "--clean",
    "--no-ignore",
    "--hidden",
    "--no-hidden",
    "-j, --junk-paths",
    "-y, --preserve-symlinks",
    "--follow-symlinks",
    "--preserve-metadata",
    "-X, --no-metadata",
    "--force",
    "--dry-run",
    "-T, --test-after",
    "--encrypt",
    "--password-stdin",
    "--signing-cert <file>",
    "--signing-private-key <file>",
    "--signing-chain <file>",
];

const EXTRACT_FLAGS: &[&str] = &[
    "-C, -d, --directory <dir>",
    "--here",
    "--overwrite <never|always|ask|rename>",
    "--strip-components <n>",
    "-i, --include <glob>",
    "--exclude <glob>",
    "--to-stdout",
    "--extract-nested",
    "--password-stdin",
];

const LIST_FLAGS: &[&str] = &[
    "-l, --long",
    "--name-only",
    "--tree",
    "-i, --include <glob>",
    "--exclude <glob>",
    "--password-stdin",
];

const TEST_FLAGS: &[&str] = &[
    "-i, --include <glob>",
    "--exclude <glob>",
    "--password-stdin",
    "--public-no-key",
    "--trusted-ca-cert <file>",
    "--trusted-system-roots",
];

const PLAN_FLAGS: &[&str] = &[
    "--format <zip|tar.zst|tzap|7z>",
    "-C, --directory <dir>",
    "-@",
    "--files-from <file|->",
    "--null",
    "--clean",
    "--no-ignore",
    "-i, --include <glob>",
    "--exclude <glob>",
    "--exclude-from <file>",
];

const FILTER_GLOB_NOTE: &str = "Glob patterns match archive paths";

const CREATE_HELP_NEEDLES: &[&str] = &[
    "Create ZIP, TAR.ZST, TZAP, or 7z archives",
    "zm create <archive> <paths...>",
    "--exclude <glob>",
    "--volume-size <size>",
    "-x always means extract",
    FILTER_GLOB_NOTE,
    "printf '%s\\n'",
];

const EXTRACT_HELP_NEEDLES: &[&str] = &[
    "Extract supported archives",
    "zm extract <archive> [-C dir]",
    "--overwrite <never|always|ask|rename>",
    "--extract-nested",
    FILTER_GLOB_NOTE,
    "printf '%s\\n'",
];

const LIST_HELP_NEEDLES: &[&str] = &[
    "List archive contents",
    "zm list <archive>",
    "--name-only",
    "--tree",
    FILTER_GLOB_NOTE,
    "printf '%s\\n'",
];

const TEST_HELP_NEEDLES: &[&str] = &[
    "Verify archive readability",
    "zm test <archive>",
    "--include <glob>",
    "--public-no-key",
    "--json",
    FILTER_GLOB_NOTE,
    "printf '%s\\n'",
];

const PLAN_HELP_NEEDLES: &[&str] = &[
    "Show what create would archive",
    "zm plan <paths...>",
    "--files-from <file|->",
    "--exclude-from <file>",
    FILTER_GLOB_NOTE,
    "zm plan project/",
];

const FORMATS_HELP_NEEDLES: &[&str] = &[
    "Show supported archive formats",
    "Create:",
    "Extract/List/Test:",
    "raw single-file streams",
    "zm formats --json",
    ".tar.zst, .tzst",
    ".tzap",
];

const DOCTOR_HELP_NEEDLES: &[&str] = &[
    "Verify the installed CLI and archive engine",
    "zm doctor",
    "--json",
    "bug reports",
    "zm doctor --json",
    "Use --json",
];

const COMPLETIONS_HELP_NEEDLES: &[&str] = &[
    "Print shell completion scripts",
    "zm completions <bash|zsh|fish|powershell>",
    "source <(zm completions bash)",
    "zm completions zsh > ~/.zfunc/_zm",
    "zm completions powershell > zm.ps1",
];

const COMMAND_HELP_CASES: &[(&str, &[&str])] = &[
    ("create", CREATE_HELP_NEEDLES),
    ("extract", EXTRACT_HELP_NEEDLES),
    ("list", LIST_HELP_NEEDLES),
    ("test", TEST_HELP_NEEDLES),
    ("plan", PLAN_HELP_NEEDLES),
    ("formats", FORMATS_HELP_NEEDLES),
    ("doctor", DOCTOR_HELP_NEEDLES),
    ("completions", COMPLETIONS_HELP_NEEDLES),
];

#[test]
fn top_level_help_is_user_facing_and_hides_legacy_commands() {
    let output = Command::new(zm_path()).arg("--help").output().unwrap();
    assert_success("zm --help", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(
        &stdout,
        "ZManager is a universal file archiver built for high-performance compression",
    );
    assert_contains(&stdout, "Usage:");
    assert_contains(&stdout, "zm [options] <command>");
    assert_contains(&stdout, "zm -cf <archive> [create-options] <paths...>");
    assert_contains(&stdout, "Commands:");
    assert_contains(&stdout, "create");
    assert_contains(&stdout, "extract");
    assert_contains(&stdout, "formats");
    assert_contains(&stdout, "completions");
    assert_contains(&stdout, "Run 'zm help <command>'");
    assert_contains(&stdout, "--color <auto|always|never>");
    assert_contains(&stdout, "--progress <auto|always|never>");
    assert_contains(&stdout, "--no-password-prompt");
    assert!(
        !stdout.contains("zip-create") && !stdout.contains("Legacy development commands"),
        "top-level help should not expose development commands\n{stdout}"
    );
}

#[test]
fn no_args_prints_help_successfully() {
    let output = Command::new(zm_path()).output().unwrap();
    assert_success("zm", &output);
    assert!(
        output.stderr.is_empty(),
        "no-arg help should not emit stderr"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "Usage:");
    assert_contains(&stdout, "zm [options] <command>");
    assert_contains(&stdout, "Commands:");
    assert_contains(&stdout, "Run 'zm help <command>'");
}

#[test]
fn color_always_styles_help_without_changing_text() {
    let output = Command::new(zm_path())
        .arg("--color")
        .arg("always")
        .arg("--help")
        .output()
        .unwrap();
    assert_success("zm --color always --help", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "\x1b[");

    let plain = strip_ansi(&stdout);
    assert_contains(&plain, "Usage:");
    assert_contains(&plain, "Commands:");
    assert_contains(&plain, "--color <auto|always|never>");
}

#[test]
fn color_modes_and_no_color_env_control_help_styling() {
    let never = Command::new(zm_path())
        .arg("--color")
        .arg("never")
        .arg("--help")
        .output()
        .unwrap();
    assert_success("zm --color never --help", &never);
    assert_not_contains(&String::from_utf8_lossy(&never.stdout), "\x1b[");

    let no_color_auto = Command::new(zm_path())
        .env("NO_COLOR", "1")
        .arg("--color")
        .arg("auto")
        .arg("--help")
        .output()
        .unwrap();
    assert_success("NO_COLOR=1 zm --color auto --help", &no_color_auto);
    assert_not_contains(&String::from_utf8_lossy(&no_color_auto.stdout), "\x1b[");

    let no_color_always = Command::new(zm_path())
        .env("NO_COLOR", "1")
        .arg("--color")
        .arg("always")
        .arg("--help")
        .output()
        .unwrap();
    assert_success("NO_COLOR=1 zm --color always --help", &no_color_always);
    assert_contains(&String::from_utf8_lossy(&no_color_always.stdout), "\x1b[");
}

#[test]
fn every_public_command_has_targeted_help() {
    for (command, required) in COMMAND_HELP_CASES {
        let direct = Command::new(zm_path())
            .arg(command)
            .arg("--help")
            .output()
            .unwrap();
        assert_success(&format!("zm {command} --help"), &direct);
        assert!(direct.stderr.is_empty(), "help should not emit stderr");
        let direct_stdout = String::from_utf8_lossy(&direct.stdout);
        for needle in *required {
            assert_contains(&direct_stdout, needle);
        }

        let help_command = Command::new(zm_path())
            .arg("help")
            .arg(command)
            .output()
            .unwrap();
        assert_success(&format!("zm help {command}"), &help_command);
        assert_eq!(
            direct.stdout, help_command.stdout,
            "zm help {command} should match zm {command} --help"
        );
    }
}

#[test]
fn help_covers_public_flag_inventory() {
    assert_help_contains(&["--help"], TOP_LEVEL_FLAGS);
    assert_help_contains(&["create", "--help"], CREATE_FLAGS);
    assert_help_contains(&["extract", "--help"], EXTRACT_FLAGS);
    assert_help_contains(&["list", "--help"], LIST_FLAGS);
    assert_help_contains(&["test", "--help"], TEST_FLAGS);
    assert_help_contains(&["plan", "--help"], PLAN_FLAGS);
}

#[test]
fn completion_files_cover_public_commands_and_hide_legacy_commands() {
    for command in PUBLIC_COMMANDS {
        assert_contains(COMPLETION_BASH, command);
        assert_contains(COMPLETION_FISH, command);
        assert_contains(COMPLETION_POWERSHELL, command);
        assert_contains(COMPLETION_ZSH, command);
    }

    for legacy in LEGACY_COMMANDS {
        assert_not_contains(COMPLETION_BASH, legacy);
        assert_not_contains(COMPLETION_FISH, legacy);
        assert_not_contains(COMPLETION_POWERSHELL, legacy);
        assert_not_contains(COMPLETION_ZSH, legacy);
    }

    for required_flag in [
        "progress",
        "color",
        "format",
        "overwrite",
        "include",
        "exclude",
        "strip-components",
        "to-stdout",
        "password-stdin",
        "public-no-key",
        "volume-size",
        "signing-cert",
        "trusted-ca-cert",
    ] {
        assert_contains(COMPLETION_BASH, &format!("--{required_flag}"));
        assert_contains(COMPLETION_FISH, &format!("-l {required_flag}"));
        assert_contains(COMPLETION_POWERSHELL, &format!("--{required_flag}"));
        assert_contains(COMPLETION_ZSH, &format!("--{required_flag}"));
    }

    for shell in ["bash", "zsh", "fish", "powershell"] {
        assert_contains(COMPLETION_BASH, shell);
        assert_contains(COMPLETION_FISH, shell);
        assert_contains(COMPLETION_POWERSHELL, shell);
        assert_contains(COMPLETION_ZSH, shell);
    }

    assert_not_contains(COMPLETION_BASH, "_init_completion");
    assert_not_contains(COMPLETION_BASH, "_filedir");
    assert_contains(COMPLETION_POWERSHELL, "Register-ArgumentCompleter");
    assert_contains(COMPLETION_POWERSHELL, "$helpTopics");
    assert_contains(COMPLETION_POWERSHELL, "Complete-ZmFiles");
}

#[test]
fn static_completion_files_capture_navigation_contract() {
    for completion in [
        COMPLETION_BASH,
        COMPLETION_FISH,
        COMPLETION_POWERSHELL,
        COMPLETION_ZSH,
    ] {
        assert_contains(completion, "create");
        assert_contains(completion, "volume-size");
        assert_contains(completion, "tzap");
        assert_contains(completion, "completions");
        assert_contains(completion, "help");
        assert_contains(completion, "bash");
        assert_contains(completion, "powershell");
    }

    assert_contains(
        COMPLETION_BASH,
        "local help_topics=\"create extract list test plan formats doctor completions\"",
    );
    assert_contains(
        COMPLETION_FISH,
        "set -l zm_help_topics create extract list test plan formats doctor completions",
    );
    assert_contains(COMPLETION_ZSH, "help_topics=(");
    assert_contains(
        COMPLETION_POWERSHELL,
        "$helpTopics = @(\"create\", \"extract\", \"list\", \"test\", \"plan\", \"formats\", \"doctor\", \"completions\")",
    );
}

#[test]
fn bash_completion_matches_help_navigation_contract() {
    if cfg!(windows) {
        return;
    }

    if !command_available("bash") {
        return;
    }

    let temp = env::temp_dir().join(format!("zm-completion-contract-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    fs::write(temp.join("archive.zip"), b"").unwrap();

    let completion = workspace_root().join("completions/zm.bash");
    let output = Command::new("bash")
        .arg("-lc")
        .arg(
            r#"
source "$1"
run_case() {
  local name="$1"
  shift
  COMP_WORDS=("$@")
  COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
  COMPREPLY=()
  _zm
  printf '%s:' "$name"
  printf ' %s' "${COMPREPLY[@]}"
  printf '\n'
}
run_case top zm h
run_case help_topics zm help ""
run_case list_options zm list --
run_case create_options zm create --
run_case completion_shells zm completions ""
run_case list_files zm list ""
"#,
        )
        .arg("_")
        .arg(completion)
        .current_dir(&temp)
        .output()
        .unwrap();

    let _ = fs::remove_dir_all(&temp);
    assert_success("bash completion contract", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_contains(&stdout, "top: help\n");
    assert_contains(
        &stdout,
        "help_topics: create extract list test plan formats doctor completions\n",
    );
    assert_contains(&stdout, "list_options: --help");
    assert_contains(&stdout, "--tree");
    assert_contains(&stdout, "create_options: --help");
    assert_contains(&stdout, "--exclude-from");
    assert_contains(&stdout, "completion_shells: bash zsh fish powershell\n");
    assert_contains(&stdout, "list_files: archive.zip\n");
    assert_not_contains(
        &stdout,
        "help_topics: create extract list test plan formats doctor completions help",
    );
}

#[test]
fn completions_command_prints_packaged_completion_scripts() {
    for (shell, expected) in [
        ("bash", COMPLETION_BASH),
        ("zsh", COMPLETION_ZSH),
        ("fish", COMPLETION_FISH),
        ("powershell", COMPLETION_POWERSHELL),
    ] {
        let output = Command::new(zm_path())
            .arg("completions")
            .arg(shell)
            .output()
            .unwrap();
        assert_success(&format!("zm completions {shell}"), &output);
        assert!(
            output.stderr.is_empty(),
            "completion output should not use stderr"
        );
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[test]
fn release_packaging_includes_completion_files() {
    for completion in ["zm.bash", "_zm", "zm.fish", "zm.ps1"] {
        assert_contains(PACKAGE_RELEASE_SH, completion);
        assert_contains(CI_WINDOWS_PS1, completion);
    }
}

#[test]
fn release_packaging_generates_third_party_notices() {
    for required in [
        "generate-third-party-notices.py",
        "THIRD_PARTY_NOTICES.md",
        "third-party-licenses",
        "NOTICE",
    ] {
        assert_contains(PACKAGE_RELEASE_SH, required);
        assert_contains(CI_WINDOWS_PS1, required);
    }

    for required in [
        "cargo metadata",
        "vendor/libarchive/libarchive-3.8.7/COPYING",
        "vendor/unrar/license.txt",
        "VCPKG_PORTS",
        "Rust Crate License Inventory",
        "License: Apache-2.0",
        "Notice file: NOTICE",
    ] {
        assert_contains(THIRD_PARTY_NOTICE_GENERATOR, required);
    }

    assert_contains(HOMEBREW_TEMPLATE, "Apache-2.0");
    assert_contains(HOMEBREW_TEMPLATE, "NOTICE");
    assert_contains(WINGET_LOCALE_TEMPLATE, "License: Apache-2.0");
}

#[test]
fn man_page_covers_public_commands_and_release_topics() {
    for command in PUBLIC_COMMANDS {
        assert_contains(MAN_PAGE, command);
    }

    for legacy in LEGACY_COMMANDS {
        assert_not_contains(MAN_PAGE, legacy);
    }

    for required_topic in [
        ".Sh GLOBAL OPTIONS",
        ".Sh CREATE OPTIONS",
        ".Sh EXTRACT OPTIONS",
        ".Sh SUPPORTED FORMATS",
        ".Sh PASSWORD HANDLING",
        ".Sh SHELL COMPLETIONS",
        ".Sh STDOUT AND JSON",
        ".Sh EXIT STATUS",
        "password-stdin",
        "volume-size",
        "to-stdout",
        "strip-components",
    ] {
        assert_contains(MAN_PAGE, required_topic);
    }
}

#[test]
fn release_packaging_includes_man_page() {
    assert_contains(PACKAGE_RELEASE_SH, "docs/man/zm.1");
    assert_contains(PACKAGE_RELEASE_SH, "man/man1");
    assert_contains(CI_WINDOWS_PS1, "docs\\man\\zm.1");
    assert_contains(CI_WINDOWS_PS1, "man\\man1");
}

#[test]
fn package_channel_metadata_uses_release_checksums() {
    for target_constant in [
        "TARGET_AARCH64_APPLE_DARWIN",
        "TARGET_X86_64_APPLE_DARWIN",
        "TARGET_AARCH64_UNKNOWN_LINUX_MUSL",
        "TARGET_X86_64_UNKNOWN_LINUX_MUSL",
        "TARGET_AARCH64_PC_WINDOWS_MSVC",
        "TARGET_X86_64_PC_WINDOWS_MSVC",
    ] {
        assert_contains(PACKAGE_METADATA_SH, target_constant);
    }

    for required in [
        "SHA256SUMS",
        "package-metadata/homebrew/Formula/zmanager.rb",
        "package-metadata\\winget\\FrankZhu.ZManagerCLI",
        "brew install frankmanzhu/zmanager/zmanager",
        "winget validate",
    ] {
        assert_contains(INSTALL_DOC, required);
    }

    assert_contains(HOMEBREW_TEMPLATE, "__SHA_AARCH64_APPLE_DARWIN__");
    assert_contains(HOMEBREW_TEMPLATE, "__SHA_X86_64_UNKNOWN_LINUX_MUSL__");
    assert_contains(HOMEBREW_TEMPLATE, "class Zmanager < Formula");
    assert_contains(WINGET_INSTALLER_TEMPLATE, "__SHA_X86_64_PC_WINDOWS_MSVC__");
    assert_contains(WINGET_INSTALLER_TEMPLATE, "__SHA_AARCH64_PC_WINDOWS_MSVC__");
    assert_contains(WINGET_INSTALLER_TEMPLATE, "PortableCommandAlias: zm");
}

#[test]
fn release_validation_artifacts_are_declared() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.4");

    for required in [
        "*.deps.txt",
        "package-metadata.tar.gz",
        "SHA256SUMS",
        "sha256sum package-metadata.tar.gz >> SHA256SUMS",
        "--notes-file",
    ] {
        assert_contains(RELEASE_WORKFLOW, required);
    }

    for required in [
        "otool -L",
        "readelf -d",
        "no ELF NEEDED entries",
        "zm-$TARGET.deps.txt",
    ] {
        assert_contains(RUNTIME_DEPS_SH, required);
    }

    for required in ["dumpbin /dependents", "zm-$TargetTriple.deps.txt"] {
        assert_contains(CI_WINDOWS_PS1, required);
    }

    for required in [
        "ZManager CLI 1.0.4 Release Notes",
        "Known Backend Limits",
        "SHA256SUMS",
        "zm-aarch64-apple-darwin.tar.gz",
        "zm-x86_64-unknown-linux-musl.tar.gz",
        "zm-x86_64-pc-windows-msvc.zip",
    ] {
        assert_contains(RELEASE_NOTES_1_0_4, required);
    }
}

#[test]
fn package_preview_uploads_artifacts_without_publishing_release() {
    for required in [
        "name: Package Preview",
        "workflow_dispatch:",
        "branches: [main]",
        "scripts/package-release.sh",
        "powershell -ExecutionPolicy Bypass -File scripts/ci-windows.ps1",
        "actions/upload-artifact@v6",
        "name: zm-preview-${{ matrix.target }}",
        "path: dist/zm-${{ matrix.target }}.*",
        "Linux tarballs are static single-binary artifacts.",
        "if-no-files-found: error",
        "retention-days: 14",
        "contents: read",
    ] {
        assert_contains(PACKAGE_PREVIEW_WORKFLOW, required);
    }

    for forbidden in [
        "contents: write",
        "gh release create",
        "actions/download-artifact",
        "scripts/package-deb.sh",
        "dist/zmanager-cli_*.deb",
        "matrix.deb_arch",
    ] {
        assert_not_contains(PACKAGE_PREVIEW_WORKFLOW, forbidden);
    }
}

#[test]
fn tool_dependent_release_compatibility_validation_is_declared() {
    assert_contains(RELEASE_DOC, "scripts/release-compatibility-check.sh");
    assert_contains(RELEASE_DOC, "fully provisioned validation");

    for required in [
        "cargo test -p zmanager-cli --test compat_formats_cli -- --nocapture",
        "require_any_tool \"7zz or 7z\" 7zz 7z",
        "rar",
        "zip",
        "zstd",
        "bsdtar",
        "dpkg-deb",
        "rpmbuild",
    ] {
        assert_contains(RELEASE_COMPATIBILITY_SH, required);
    }
}

#[test]
fn linux_release_artifacts_are_static_tarballs() {
    for required in [
        "*-unknown-linux-musl",
        "zig is required",
        "zig cc -target $musl_abi",
        "CARGO_TARGET_${target_env_upper}_LINKER",
    ] {
        assert_contains(PACKAGE_RELEASE_SH, required);
    }

    for required in [
        "readelf is required to verify static Linux release artifacts",
        "static Linux runtime dependency inspection failed",
    ] {
        assert_contains(RUNTIME_DEPS_SH, required);
    }

    for required in [
        "zm-x86_64-unknown-linux-musl.tar.gz",
        "zm-aarch64-unknown-linux-musl.tar.gz",
        "Linux release archives are statically linked musl builds",
        "without installing extra runtime packages",
    ] {
        assert_contains(INSTALL_DOC, required);
    }

    for required in [
        "target: x86_64-unknown-linux-musl",
        "target: aarch64-unknown-linux-musl",
        "musl-tools",
        "sha256sum *.tar.gz *.zip *.deps.txt > SHA256SUMS",
    ] {
        assert_contains(RELEASE_WORKFLOW, required);
    }

    for forbidden in [
        "scripts/package-deb.sh",
        "deb_arch:",
        "release-artifacts/*.deb",
        "zmanager-cli-${{ matrix.deb_arch }}-deb",
    ] {
        assert_not_contains(RELEASE_WORKFLOW, forbidden);
        assert_not_contains(PACKAGE_PREVIEW_WORKFLOW, forbidden);
    }
}

#[test]
fn libarchive_cmake_vcpkg_toolchain_is_windows_msvc_only() {
    let build_rs = normalize_newlines(LIBARCHIVE_SYS_BUILD_RS);

    for required in [
        "if !target_uses_vcpkg(target) {\n        return;\n    }",
        "fn target_uses_vcpkg(target: &str) -> bool {\n    target.contains(\"windows\") && target.contains(\"msvc\")\n}",
    ] {
        assert_contains(&build_rs, required);
    }
}

#[test]
fn linux_ci_and_release_builds_use_ubuntu_22_04_baseline() {
    let release_workflow = normalize_newlines(RELEASE_WORKFLOW);
    let ci_workflow = normalize_newlines(CI_WORKFLOW);
    let release_package_job = section_between(&release_workflow, "  package:\n", "\n  publish:\n");
    let ci_test_job = section_between(&ci_workflow, "  test:\n", "\n  windows-test:\n");

    for required in [
        "- os: ubuntu-22.04\n            target: x86_64-unknown-linux-musl",
        "- os: ubuntu-22.04-arm\n            target: aarch64-unknown-linux-musl",
    ] {
        assert_contains(&release_package_job, required);
    }

    for required in [
        "name: Linux x86_64\n            os: ubuntu-22.04",
        "name: Linux ARM64\n            os: ubuntu-22.04-arm",
    ] {
        assert_contains(&ci_test_job, required);
    }

    for newer_or_floating_linux_runner in ["ubuntu-latest", "ubuntu-24.04-arm"] {
        assert_not_contains(&release_package_job, newer_or_floating_linux_runner);
        assert_not_contains(&ci_test_job, newer_or_floating_linux_runner);
    }

    assert_contains(
        &release_workflow,
        "  publish:\n    name: Publish GitHub release\n    runs-on: ubuntu-22.04",
    );
    assert_not_contains(&release_workflow, "ubuntu-latest");
    assert_not_contains(&ci_workflow, "ubuntu-latest");
}

#[test]
fn windows_ci_and_release_builds_use_static_crt() {
    for workflow in [CI_WORKFLOW, RELEASE_WORKFLOW, PACKAGE_PREVIEW_WORKFLOW] {
        assert_contains(workflow, "triplet: x64-windows-static");
        assert_contains(workflow, "triplet: arm64-windows-static");
        assert_not_contains(workflow, "triplet: x64-windows-static-md");
        assert_not_contains(workflow, "triplet: arm64-windows-static-md");
    }

    for required in [
        "-C target-feature=+crt-static",
        "RUSTFLAGS",
        "static Windows runtime dependency inspection failed",
        "MSVCP[0-9]+\\.dll",
        "VCRUNTIME[0-9_]*\\.dll",
        "api-ms-win-crt-.*\\.dll",
    ] {
        assert_contains(CI_WINDOWS_PS1, required);
    }
}

#[test]
fn macos_ci_and_release_builds_set_deployment_target() {
    for workflow in [CI_WORKFLOW, PACKAGE_PREVIEW_WORKFLOW, RELEASE_WORKFLOW] {
        assert_contains(workflow, "MACOSX_DEPLOYMENT_TARGET: \"11.0\"");
    }
}

#[test]
fn workflow_section_helpers_tolerate_windows_line_endings() {
    let workflow = "jobs:\r\n  package:\r\n    runs-on: ubuntu-22.04\r\n  publish:\r\n";

    assert_contains(
        &section_between(workflow, "  package:\n", "\n  publish:\n"),
        "runs-on: ubuntu-22.04",
    );
}

#[test]
fn command_usage_errors_point_to_targeted_help() {
    let unknown = Command::new(zm_path())
        .arg("create")
        .arg("--excldue")
        .output()
        .unwrap();
    assert_usage_failure("zm create --excldue", &unknown);
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert_contains(&stderr, "error: unknown option '--excldue' for 'zm create'");
    assert_contains(&stderr, "Did you mean '--exclude'?");
    assert_contains(&stderr, "Try 'zm create --help' for usage.");

    let missing_source = Command::new(zm_path())
        .arg("create")
        .arg("out.zip")
        .output()
        .unwrap();
    assert_usage_failure("zm create out.zip", &missing_source);
    let stderr = String::from_utf8_lossy(&missing_source.stderr);
    assert_contains(&stderr, "error: missing source path");
    assert_contains(&stderr, "Usage:");
    assert_contains(&stderr, "zm create <archive> <paths...>");
    assert_contains(&stderr, "Try 'zm create --help' for examples.");
    assert!(
        !stderr.contains("Legacy development commands"),
        "usage errors should not dump legacy help\n{stderr}"
    );
}

fn help_output(args: &[&str]) -> String {
    let output = Command::new(zm_path()).args(args).output().unwrap();
    assert_success(&format!("zm {}", args.join(" ")), &output);
    String::from_utf8(output.stdout).unwrap()
}

fn assert_help_contains(args: &[&str], needles: &[&str]) {
    let output = help_output(args);
    for needle in needles {
        assert_contains(&output, needle);
    }
}

fn zm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zm"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("zmanager-cli crate should be inside the CLI workspace")
        .to_path_buf()
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_usage_failure(label: &str, output: &std::process::Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{label} did not fail with usage status\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected output to contain {needle:?}\n{haystack}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str) {
    assert!(
        !haystack.contains(needle),
        "expected output not to contain {needle:?}\n{haystack}"
    );
}

fn strip_ansi(input: &str) -> String {
    let mut stripped = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            stripped.push(ch);
        }
    }
    stripped
}

fn normalize_newlines(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\r', "\n")
}

fn section_between(haystack: &str, start: &str, end: &str) -> String {
    let normalized = normalize_newlines(haystack);
    let start_index = normalized
        .find(start)
        .unwrap_or_else(|| panic!("section start not found: {start:?}"));
    let section_start = start_index + start.len();
    let relative_end = normalized[section_start..]
        .find(end)
        .unwrap_or_else(|| panic!("section end not found: {end:?}"));
    normalized[section_start..section_start + relative_end].to_owned()
}
