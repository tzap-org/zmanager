use std::env;
use std::path::PathBuf;
use std::process::Command;

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
    "--format <zip|tar.zst|7z>",
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
];

const PLAN_FLAGS: &[&str] = &[
    "--format <zip|tar.zst|7z>",
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
    "Create ZIP, TAR.ZST, or 7z archives",
    "zm create <archive> <paths...>",
    "--exclude <glob>",
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
];

const DOCTOR_HELP_NEEDLES: &[&str] = &[
    "Verify the installed CLI and archive engine",
    "zm doctor",
    "--json",
    "bug reports",
    "zm doctor --json",
    "Use --json",
];

const COMMAND_HELP_CASES: &[(&str, &[&str])] = &[
    ("create", CREATE_HELP_NEEDLES),
    ("extract", EXTRACT_HELP_NEEDLES),
    ("list", LIST_HELP_NEEDLES),
    ("test", TEST_HELP_NEEDLES),
    ("plan", PLAN_HELP_NEEDLES),
    ("formats", FORMATS_HELP_NEEDLES),
    ("doctor", DOCTOR_HELP_NEEDLES),
];

#[test]
fn top_level_help_is_user_facing_and_hides_legacy_commands() {
    let output = Command::new(zm_path()).arg("--help").output().unwrap();
    assert_success("zm --help", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "Usage:");
    assert_contains(&stdout, "zm [options] <command>");
    assert_contains(&stdout, "zm -cf <archive> [create-options] <paths...>");
    assert_contains(&stdout, "Commands:");
    assert_contains(&stdout, "create");
    assert_contains(&stdout, "extract");
    assert_contains(&stdout, "formats");
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
