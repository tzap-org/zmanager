use std::process::Command;

fn get_git_rev() -> Option<String> {
    if let Ok(val) = std::env::var("ZMANAGER_BUILD_REV") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        return None;
    }

    let is_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty());

    if is_dirty {
        Some(format!("{sha}-dirty"))
    } else {
        Some(sha)
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rev = get_git_rev().unwrap_or_default();
    println!("cargo:rustc-env=ZMANAGER_BUILD_REV={rev}");
}
