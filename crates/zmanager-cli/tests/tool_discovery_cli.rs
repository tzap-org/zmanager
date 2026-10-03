mod common;

use common::{TestDir, find_tool_in_path};
use std::{env, fs};

#[test]
fn tool_discovery_preserves_directory_precedence_and_explicit_extensions() {
    let fixture = TestDir::new("tool-discovery");
    let first = fixture.path("first directory");
    let second = fixture.path("second directory");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("tool.exe"), []).unwrap();
    fs::write(second.join("tool"), []).unwrap();
    fs::write(first.join("script.cmd"), []).unwrap();
    let path = env::join_paths([&first, &second]).unwrap();
    assert_eq!(find_tool_in_path("tool", &path, &[".exe", ".cmd"]), Some(first.join("tool.exe")));
    assert_eq!(find_tool_in_path("tool", &path, &[]), Some(second.join("tool")));
    assert_eq!(find_tool_in_path("tool.exe", &path, &[".exe"]), Some(first.join("tool.exe")));
    assert_eq!(find_tool_in_path("script", &path, &[".cmd"]), Some(first.join("script.cmd")));
    assert!(find_tool_in_path("script.exe", &path, &[".cmd"]).is_none());
}

#[cfg(windows)]
#[test]
fn windows_system_command_is_discoverable_without_extension() {
    let explicit = common::find_on_path("cmd.exe").expect("cmd.exe must be on the Windows test PATH");
    let discovered = common::find_on_path("cmd").expect("Windows executable extensions must participate in tool discovery");
    assert_eq!(fs::canonicalize(explicit).unwrap(), fs::canonicalize(&discovered).unwrap());
    assert!(std::process::Command::new(discovered).args(["/d", "/c", "exit", "0"]).status().unwrap().success());
}
