//! Explicit sudo retry for a protected extraction destination, before writes.
use super::options::GlobalOptions;
use super::usage::print_error_line;
use rustix::fs::{Access, access};
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

pub(super) const RETRY_COMMAND: &str = "__unix-elevated-extract";
const SUDO: &str = "/usr/bin/sudo";
const SUDO_PROMPT: &str = "[zm] sudo password for %p: ";

pub(super) fn run_elevated_retry(run: impl FnOnce() -> ExitCode) -> ExitCode {
    if !rustix::process::geteuid().is_root() {
        eprintln!("Sudo extraction retry requires a root process.");
        return ExitCode::FAILURE;
    }
    run()
}

pub(super) fn offer_for_destination(destination: &Path, global: &GlobalOptions, allow_elevation: bool) -> Option<ExitCode> {
    if rustix::process::geteuid().is_root() || !destination_needs_privilege(destination) {
        return None;
    }
    if !may_offer([io::stdin().is_terminal(), io::stdout().is_terminal(), io::stderr().is_terminal()], global, allow_elevation) {
        print_error_line(global, format_args!("Extraction destination requires write permission. Choose a writable directory or run extraction with sudo."));
        return Some(ExitCode::FAILURE);
    }
    eprintln!("The extraction destination requires elevated write permission. No files have been extracted.");
    eprintln!("Sudo will request your password if needed. Extracted files may be owned by root. Any archive password will be requested again.");
    let answer = ask_to_elevate(&mut io::stdin().lock(), &mut io::stderr().lock());
    match answer {
        Ok(true) => Some(match sudo_command().and_then(|mut command| command.status()) {
            // The child inherits stderr and prints the precise extraction or
            // sudo authentication error. Preserve its status without adding an
            // ambiguous failure/cancellation message over that diagnostic.
            Ok(status) => ExitCode::from(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)),
            Err(error) => {
                print_error_line(global, format_args!("Could not start sudo extraction: {error}"));
                ExitCode::FAILURE
            }
        }),
        Ok(false) => {
            print_error_line(global, format_args!("Extraction cancelled. No files were extracted."));
            Some(ExitCode::FAILURE)
        }
        Err(error) => {
            print_error_line(global, format_args!("Could not read sudo retry choice: {error}. No files were extracted."));
            Some(ExitCode::FAILURE)
        }
    }
}

fn may_offer(terminals: [bool; 3], global: &GlobalOptions, allow_elevation: bool) -> bool {
    allow_elevation && terminals.into_iter().all(|terminal| terminal) && !global.json && !global.quiet && !global.no_password_prompt
}

fn destination_needs_privilege(destination: &Path) -> bool {
    // Walk up to an existing ancestor for destinations that do not exist yet.
    // access checks Unix permissions and ACLs without creating probe files.
    let Ok(absolute) = absolute_destination(destination) else { return false };
    let mut ancestor = absolute.as_path();
    loop {
        match std::fs::metadata(ancestor) {
            Ok(metadata) => {
                let needed = if metadata.is_dir() { Access::WRITE_OK | Access::EXEC_OK } else { Access::WRITE_OK };
                return access(ancestor, needed).is_err_and(|error| error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::PERM);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(parent) = ancestor.parent() else { return false };
                ancestor = parent;
            }
            Err(error) => return error.kind() == io::ErrorKind::PermissionDenied,
        }
    }
}

fn absolute_destination(destination: &Path) -> io::Result<PathBuf> {
    if destination.is_absolute() { Ok(destination.to_owned()) } else { Ok(std::env::current_dir()?.join(destination)) }
}

fn ask_to_elevate(input: &mut impl io::BufRead, output: &mut impl io::Write) -> io::Result<bool> {
    loop {
        write!(output, "Retry extraction with sudo? [y/N] ")?;
        output.flush()?;
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            return Ok(false);
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => return Ok(false),
            _ => writeln!(output, "Please answer yes or no.")?,
        }
    }
}

fn sudo_command() -> io::Result<Command> {
    let mut command = Command::new(SUDO);
    // No shell, password argument, or environment-preservation flag. Sudo owns
    // authentication on the controlling terminal; the child cannot recurse.
    command.args(["-p", SUDO_PROMPT, "--"]);
    command.arg(std::env::current_exe()?);
    command.arg(RETRY_COMMAND);
    command.args(std::env::args_os().skip(1));
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_modes_never_offer_sudo() {
        let mut global = GlobalOptions::default();
        assert!(may_offer([true; 3], &global, true));
        assert!(!may_offer([true; 3], &global, false));
        for index in 0..3 {
            let mut terminals = [true; 3];
            terminals[index] = false;
            assert!(!may_offer(terminals, &global, true));
        }
        global.json = true;
        assert!(!may_offer([true; 3], &global, true));
        global.json = false;
        global.quiet = true;
        assert!(!may_offer([true; 3], &global, true));
    }

    #[test]
    fn sudo_consent_is_explicit_and_defaults_to_no() {
        for (answer, expected) in [("y\n", true), (" YES \n", true), ("n\n", false), ("\n", false), ("", false), ("maybe\nyes\n", true)] {
            let mut output = Vec::new();
            assert_eq!(ask_to_elevate(&mut io::Cursor::new(answer), &mut output).unwrap(), expected);
            assert!(String::from_utf8(output).unwrap().contains("[y/N]"));
        }
    }

    #[test]
    fn writable_and_missing_destinations_do_not_require_sudo() {
        let temp = std::env::temp_dir();
        assert!(!destination_needs_privilege(&temp));
        assert!(!destination_needs_privilege(&temp.join("zm-missing-parent/missing-child")));
        assert!(!destination_needs_privilege(Path::new("")));
    }
}
