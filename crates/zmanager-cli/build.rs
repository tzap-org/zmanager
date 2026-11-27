use std::process::Command;

fn git_output(repo_root: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(repo_root).args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8(output.stdout).ok()).flatten().map(|value| value.trim().to_owned())
}

fn emit_rerun_if_changed(path: &std::path::Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn watch_input_tree(path: &std::path::Path, is_repo_root: bool) {
    emit_rerun_if_changed(path);
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        if is_repo_root && matches!(name.to_str(), Some(".git" | "target" | "implementation-docs")) {
            continue;
        }
        let child = entry.path();
        if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            watch_input_tree(&child, false);
        } else {
            emit_rerun_if_changed(&child);
        }
    }
}

fn emit_git_inputs(repo_root: &std::path::Path) {
    // Watch all checkout input files and nested directories so edits to
    // existing source files rerun this build script and refresh the dirty
    // marker. Exclude Cargo output, Git internals (watched explicitly below),
    // and the nested private documentation repository.
    watch_input_tree(repo_root, true);

    // HEAD itself is symbolic during normal branch work, so also watch the
    // resolved branch ref. Packed refs and the index cover detached/packed
    // checkout changes and staged-state changes, respectively.
    for git_path in [
        git_output(repo_root, &["rev-parse", "--git-path", "HEAD"]),
        git_output(repo_root, &["rev-parse", "--git-path", "index"]),
        git_output(repo_root, &["rev-parse", "--git-path", "packed-refs"]),
        git_output(repo_root, &["symbolic-ref", "--quiet", "HEAD"]).and_then(|reference| git_output(repo_root, &["rev-parse", "--git-path", &reference])),
    ]
    .into_iter()
    .flatten()
    {
        let path = std::path::PathBuf::from(&git_path);
        let path = if path.is_absolute() { path } else { repo_root.join(path) };
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn get_git_rev() -> Option<String> {
    if let Ok(val) = std::env::var("ZMANAGER_BUILD_REV") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let repo_root = git_output(&std::env::current_dir().ok()?, &["rev-parse", "--show-toplevel"])?;
    let sha = git_output(std::path::Path::new(&repo_root), &["rev-parse", "--short", "HEAD"])?;
    if sha.is_empty() {
        return None;
    }

    let is_dirty = git_output(std::path::Path::new(&repo_root), &["status", "--porcelain"]).is_some_and(|output| !output.is_empty());

    if is_dirty { Some(format!("{sha}-dirty")) } else { Some(sha) }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ZMANAGER_BUILD_REV");

    if let Some(repo_root) = git_output(&std::env::current_dir().unwrap_or_default(), &["rev-parse", "--show-toplevel"]) {
        emit_git_inputs(std::path::Path::new(&repo_root));
    }

    let rev = get_git_rev().unwrap_or_default();
    println!("cargo:rustc-env=ZMANAGER_BUILD_REV={rev}");
}
