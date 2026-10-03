//! Explicit, interactive UAC retry before TZAP symlink extraction writes files.
// Native Windows elevation/handle APIs require FFI; keep it isolated here.
#![allow(unsafe_code)]
use super::options::GlobalOptions;
use super::usage::{print_error_line, print_success_line};
use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use zmanager_core::archive_browser::{BrowserEntryKind, BrowserListOptions, list_entries_with_options};
use zmanager_core::safety::{ExtractionPolicy, archive_pattern_matches_any};

pub(super) const RETRY_COMMAND: &str = "__windows-elevated-extract";

pub(super) fn run_elevated_retry(run: impl FnOnce() -> ExitCode) -> ExitCode {
    if unsafe { IsUserAnAdmin() } == 0 {
        eprintln!("Administrator extraction retry requires an elevated process.");
        return ExitCode::FAILURE;
    }
    let code = run();
    if code != ExitCode::SUCCESS && io::stdin().is_terminal() && io::stderr().is_terminal() {
        eprintln!("Press Enter to close this administrator window.");
        let _ = io::stdin().read_line(&mut String::new());
    }
    code
}

pub(super) fn offer_for_symlinks(
    archive: &Path,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    policy: &ExtractionPolicy,
    global: &GlobalOptions,
) -> Option<ExitCode> {
    if !may_offer([io::stdin().is_terminal(), io::stdout().is_terminal(), io::stderr().is_terminal()], global.json, global.quiet)
        || policy.ignore_symlinks
        // An elevated child must never offer another elevation retry.
        || unsafe { IsUserAnAdmin() } != 0
        || !lacks_symlink_privilege()
    {
        return None;
    }
    let listing = list_entries_with_options(archive, BrowserListOptions { password, recipient_key, ..BrowserListOptions::default() }).ok()?;
    if !listing.entries.iter().any(|entry| entry.kind == BrowserEntryKind::Symlink && selected_symlink(&entry.path, policy)) {
        return None;
    }
    eprintln!("This archive contains symbolic links. Windows requires Developer Mode or symlink privilege to restore them.");
    eprintln!("Extraction has not started. The administrator process will keep your extraction options and ask again for any archive password.");
    let mut stderr = io::stderr().lock();
    let mut stdin = io::stdin().lock();
    let answer = ask_to_elevate(&mut stdin, &mut stderr);
    drop(stderr);
    drop(stdin);
    match answer {
        Ok(true) => Some(match launch_elevated() {
            Ok(code) => {
                if code != 0 {
                    print_error_line(
                        global,
                        format_args!("Administrator extraction failed (exit code {code}). Details were displayed in the administrator window."),
                    );
                } else {
                    print_success_line(global, format_args!("Administrator extraction completed."));
                }
                ExitCode::from(u8::try_from(code).unwrap_or(1))
            }
            Err(error) => {
                if error.raw_os_error() == Some(ERROR_CANCELLED.cast_signed()) {
                    print_error_line(global, format_args!("Administrator retry cancelled. No files were extracted."));
                } else {
                    print_error_line(global, format_args!("Could not start administrator extraction: {error}"));
                }
                ExitCode::FAILURE
            }
        }),
        Ok(false) => {
            print_error_line(
                global,
                format_args!(
                    "Extraction cancelled. Enable Developer Mode or run your terminal as administrator to restore symbolic links. No files were extracted."
                ),
            );
            Some(ExitCode::FAILURE)
        }
        Err(error) => {
            print_error_line(global, format_args!("Could not read administrator retry choice: {error}. No files were extracted."));
            Some(ExitCode::FAILURE)
        }
    }
}

fn may_offer(terminals: [bool; 3], json: bool, quiet: bool) -> bool {
    terminals.into_iter().all(|terminal| terminal) && !json && !quiet
}

fn selected_symlink(path: &str, policy: &ExtractionPolicy) -> bool {
    !policy.ignore_symlinks
        && archive_pattern_matches_any(path, &policy.include_patterns, &policy.exclude_patterns)
        && path.split('/').count() > policy.strip_components
}

fn ask_to_elevate(input: &mut impl io::BufRead, output: &mut impl io::Write) -> io::Result<bool> {
    loop {
        write!(output, "Retry extraction as administrator? [y/N] ")?;
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

fn lacks_symlink_privilege() -> bool {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let dir = std::env::temp_dir().join(format!("zm-symlink-probe-{}-{nonce}", std::process::id()));
    if std::fs::create_dir(&dir).is_err() {
        return false;
    }
    let link = dir.join("link");
    let result = std::os::windows::fs::symlink_file("target", &link);
    let lacks_privilege = result.as_ref().is_err_and(|error| error.raw_os_error() == Some(1314));
    if result.is_ok() {
        let _ = std::fs::remove_file(link);
    }
    let _ = std::fs::remove_dir(dir);
    lacks_privilege
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

// ShellExecute receives a Windows command line, not a shell expression. Apply
// the CRT rules for quotes and backslashes while preserving non-Unicode paths.
fn quote_argument(value: &OsStr) -> Vec<u16> {
    let mut result = vec![u16::from(b'"')];
    let mut slashes = 0;
    for character in value.encode_wide() {
        if character == u16::from(b'\\') {
            slashes += 1;
            continue;
        }
        let count = if character == u16::from(b'"') { slashes * 2 + 1 } else { slashes };
        result.extend(std::iter::repeat_n(u16::from(b'\\'), count));
        result.push(character);
        slashes = 0;
    }
    result.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
    result.push(u16::from(b'"'));
    result
}

fn command_line(args: impl IntoIterator<Item = OsString>) -> Vec<u16> {
    let mut result = Vec::new();
    for argument in args {
        if !result.is_empty() {
            result.push(u16::from(b' '));
        }
        result.extend(quote_argument(&argument));
    }
    result.push(0);
    result
}

fn launch_elevated() -> io::Result<u32> {
    // Use a fresh STA thread: another library may already have initialized
    // COM differently on the CLI thread. ShellExecute can invoke extensions.
    std::thread::spawn(launch_elevated_on_sta).join().map_err(|_| io::Error::other("administrator launcher thread failed"))?
}

fn launch_elevated_on_sta() -> io::Result<u32> {
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    let initialized = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned()) };
    if initialized < 0 {
        return Err(io::Error::other(format!("Windows COM initialization failed: {initialized}")));
    }
    let _apartment = Apartment;
    let executable = wide(std::env::current_exe()?.as_os_str());
    let directory = wide(std::env::current_dir()?.as_os_str());
    let parameters = command_line(std::iter::once(OsString::from(RETRY_COMMAND)).chain(std::env::args_os().skip(1)));
    let verb = wide(OsStr::new("runas"));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap(),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: directory.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // All UTF-16 buffers remain alive until ShellExecuteExW returns.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.hProcess.is_null() {
        return Err(io::Error::other("Windows did not return an administrator process handle"));
    }
    let mut code = 1;
    let result = unsafe {
        if WaitForSingleObject(info.hProcess, INFINITE) == u32::MAX || GetExitCodeProcess(info.hProcess, &raw mut code) == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(code)
        }
    };
    unsafe { CloseHandle(info.hProcess) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_modes_never_offer_elevation() {
        assert!(may_offer([true, true, true], false, false));
        for mode in [
            (false, true, true, false, false),
            (true, false, true, false, false),
            (true, true, false, false, false),
            (true, true, true, true, false),
            (true, true, true, false, true),
        ] {
            assert!(!may_offer([mode.0, mode.1, mode.2], mode.3, mode.4));
        }
    }

    #[test]
    fn filtered_or_stripped_links_do_not_require_elevation() {
        let mut policy = ExtractionPolicy::default();
        assert!(selected_symlink("project/link.txt", &policy));
        policy.exclude_patterns = vec!["project/link.txt".into()];
        assert!(!selected_symlink("project/link.txt", &policy));
        policy.exclude_patterns.clear();
        policy.include_patterns = vec!["project/file.txt".into()];
        assert!(!selected_symlink("project/link.txt", &policy));
        policy.include_patterns.clear();
        policy.strip_components = 2;
        assert!(!selected_symlink("project/link.txt", &policy));
        policy.strip_components = 0;
        policy.ignore_symlinks = true;
        assert!(!selected_symlink("project/link.txt", &policy));
    }

    #[test]
    fn consent_is_explicit_and_defaults_to_no() {
        for (answer, expected) in [("y\n", true), (" YES \n", true), ("n\n", false), ("\n", false), ("", false), ("maybe\nyes\n", true)] {
            let mut output = Vec::new();
            assert_eq!(ask_to_elevate(&mut io::Cursor::new(answer), &mut output).unwrap(), expected);
            assert!(String::from_utf8(output).unwrap().contains("[y/N]"));
        }
    }

    #[test]
    fn windows_arguments_round_trip_without_changing_options() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
        let args = [
            "zm.exe",
            "-xf",
            "archive with spaces.tzap",
            "-C",
            "C:\\output with spaces\\",
            "--overwrite",
            "never",
            "--include",
            "a/**",
            "--exclude",
            "a/\"quoted\"",
            "",
            "雪.tzap",
            "a\\\"b",
            "--restore",
            "same-os",
        ];
        let command = command_line(args.map(OsString::from));
        let mut count = 0;
        let parsed = unsafe { CommandLineToArgvW(command.as_ptr(), &raw mut count) };
        assert!(!parsed.is_null());
        let values = unsafe { std::slice::from_raw_parts(parsed, usize::try_from(count).unwrap()) };
        for (value, expected) in values.iter().zip(args) {
            let mut length = 0;
            unsafe {
                while *value.add(length) != 0 {
                    length += 1;
                }
            }
            assert_eq!(unsafe { std::slice::from_raw_parts(*value, length) }, expected.encode_utf16().collect::<Vec<_>>());
        }
        assert_eq!(values.len(), args.len());
        unsafe { LocalFree(parsed.cast()) };
    }
}
