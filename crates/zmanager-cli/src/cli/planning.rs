use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use zmanager_core::safety::{compile_patterns, compiled_pattern_matches_any};
pub(crate) fn append_files_from(sources: &mut Vec<PathBuf>, files_from: &[String], null_paths: bool) -> Result<(), String> {
    for list in files_from {
        if list == "-" {
            append_stdin_paths(sources, null_paths)?;
        } else {
            let bytes = fs::read(list).map_err(|error| format!("failed to read {list}: {error}"))?;
            append_path_bytes(sources, &bytes, null_paths)?;
        }
    }
    Ok(())
}

pub(crate) fn append_stdin_paths(sources: &mut Vec<PathBuf>, null_paths: bool) -> Result<(), String> {
    let mut bytes = Vec::new();
    io::read_to_string(io::stdin()).map(|value| bytes = value.into_bytes()).map_err(|error| format!("failed to read path list from stdin: {error}"))?;
    append_path_bytes(sources, &bytes, null_paths)
}

fn append_path_bytes(sources: &mut Vec<PathBuf>, bytes: &[u8], null_paths: bool) -> Result<(), String> {
    if null_paths {
        for part in bytes.split(|byte| *byte == 0) {
            if part.is_empty() {
                continue;
            }
            let value = std::str::from_utf8(part).map_err(|error| format!("path list is not valid UTF-8: {error}"))?;
            sources.push(PathBuf::from(value));
        }
    } else {
        let value = std::str::from_utf8(bytes).map_err(|error| format!("path list is not valid UTF-8: {error}"))?;
        for line in value.lines().filter(|line| !line.is_empty()) {
            sources.push(PathBuf::from(line));
        }
    }
    Ok(())
}

pub(crate) fn plan_sources(
    sources: &[PathBuf],
    clean: bool,
    no_ignore: bool,
    follow_symlinks: bool,
) -> Result<zmanager_core::manifest::ArchiveManifest, zmanager_core::manifest::PlanError> {
    use zmanager_core::manifest::{ExclusionProfile, PlanOptions};

    let mut options = if no_ignore {
        PlanOptions { exclusion_profile: ExclusionProfile::Unrestricted, ..PlanOptions::default() }
    } else if clean {
        PlanOptions::clean_source()
    } else {
        PlanOptions::default()
    };
    options.follow_symlinks = follow_symlinks;
    zmanager_core::manifest::plan_archives(sources, &options)
}

pub(crate) fn manifest_has_symlinks(manifest: &zmanager_core::manifest::ArchiveManifest) -> bool {
    manifest.entries.iter().any(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::Symlink)
}

pub(crate) fn apply_manifest_filters(
    manifest: &mut zmanager_core::manifest::ArchiveManifest,
    includes: &[String],
    excludes: &[String],
    exclude_from: &[PathBuf],
    exclude_hidden: bool,
) -> Result<(), String> {
    let mut exclude_patterns = excludes.to_vec();
    for file in exclude_from {
        let contents = fs::read_to_string(file).map_err(|error| format!("failed to read {}: {error}", file.display()))?;
        exclude_patterns.extend(contents.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')).map(ToOwned::to_owned));
    }

    let compiled_includes = compile_patterns(includes);
    let compiled_excludes = compile_patterns(&exclude_patterns);
    manifest.entries.retain(|entry| {
        let path = &entry.archive_path;
        // An explicit include also overrides the hidden-file filter, so it is
        // tracked separately from the shared include/exclude rule.
        let explicitly_included = !compiled_includes.is_empty() && compiled_includes.iter().any(|pattern| pattern.matches(path));
        let hidden_excluded = exclude_hidden && archive_path_has_hidden_component(path) && !explicitly_included;
        compiled_pattern_matches_any(path, &compiled_includes, &compiled_excludes) && !hidden_excluded
    });
    manifest.total_bytes =
        manifest.entries.iter().filter(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::File).map(|entry| entry.size).sum();
    Ok(())
}

/// Returns whether any archive path component after the root has a hidden
/// (dot-prefixed) name. The root component is the explicitly named source
/// directory, so a hidden source root (for example `zm create .hidden-dir`)
/// is not itself excluded.
pub(crate) fn archive_path_has_hidden_component(path: &str) -> bool {
    path.split('/').skip(1).any(|component| component.starts_with('.'))
}

pub(crate) fn apply_junk_paths(manifest: &mut zmanager_core::manifest::ArchiveManifest) -> Result<(), String> {
    let mut seen = HashMap::new();
    let mut flattened = Vec::new();

    for mut entry in std::mem::take(&mut manifest.entries) {
        if entry.file_type == zmanager_core::manifest::ManifestFileType::Directory {
            continue;
        }

        let Some(name) = entry.archive_path.trim_end_matches('/').rsplit('/').find(|part| !part.is_empty()).map(ToOwned::to_owned) else {
            return Err(format!("cannot derive junk path for archive entry {}", entry.archive_path));
        };
        let source_path = entry.source_path.display().to_string();
        if let Some(previous) = seen.insert(name.clone(), source_path.clone()) {
            return Err(format!("duplicate junk path {name}: {previous} and {source_path} both flatten to {name}"));
        }
        entry.archive_path = name;
        flattened.push(entry);
    }

    flattened.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    manifest.entries = flattened;
    manifest.total_bytes =
        manifest.entries.iter().filter(|entry| entry.file_type == zmanager_core::manifest::ManifestFileType::File).map(|entry| entry.size).sum();
    Ok(())
}
