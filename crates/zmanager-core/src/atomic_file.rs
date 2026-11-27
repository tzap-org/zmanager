use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TEMP_PREFIX: &str = ".zmanager";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_TEMP_ATTEMPTS: u32 = 100;
type StagedFile = (PathBuf, PathBuf);
type StageFailure = (io::Error, Vec<StagedFile>);

/// Atomically publishes an existing sibling file over a destination file.
/// The source must be on the same filesystem as the destination.
pub fn replace_file_from_path(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", destination.display())));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    replace_file_over_existing(source, destination)
}

pub(crate) struct AtomicOutputFile {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl AtomicOutputFile {
    pub(crate) fn create(final_path: &Path) -> io::Result<Self> {
        if let Some(parent) = final_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path.file_name().and_then(|name| name.to_str()).unwrap_or("archive");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let temp_path = parent.join(format!("{TEMP_PREFIX}-{file_name}-{}-{now}-{attempt}{TEMP_SUFFIX}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&temp_path) {
                Ok(file) => {
                    return Ok(Self { final_path: final_path.to_path_buf(), temp_path, file: Some(file), committed: false });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate temporary output path for {}", final_path.display())))
    }

    pub(crate) fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file.as_mut().ok_or_else(|| io::Error::other(format!("temporary output already finalized for {}", self.final_path.display())))
    }

    pub(crate) fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub(crate) fn close(&mut self) {
        drop(self.file.take());
    }

    pub(crate) fn commit_with_replace(mut self, replace_existing: bool) -> io::Result<()> {
        self.commit_inner(replace_existing)
    }

    pub(crate) fn commit_with_file_replace(mut self, replace_existing: bool) -> io::Result<()> {
        drop(self.file.take());
        if replace_existing {
            replace_file_from_path(&self.temp_path, &self.final_path)?;
        } else {
            atomic_no_clobber_rename(&self.temp_path, &self.final_path)?;
        }
        self.committed = true;
        Ok(())
    }

    /// Commits by renaming over the destination without first removing it:
    /// POSIX `rename` replaces atomically, and Windows uses
    /// `MoveFileExW REPLACE_EXISTING`. Unlike [`Self::commit_with_replace`]
    /// there is no window where the final path is absent, so a crash at any
    /// point leaves either the old or the new file — never neither. Used by
    /// writers whose final file must never disappear (identity catalog).
    #[allow(unsafe_code)]
    pub(crate) fn commit_with_atomic_replace(mut self) -> io::Result<()> {
        drop(self.file.take());
        #[cfg(unix)]
        fs::rename(&self.temp_path, &self.final_path)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};

            let from: Vec<u16> = self.temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = self.final_path.as_os_str().encode_wide().chain(Some(0)).collect();
            let result = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.committed = true;
        Ok(())
    }

    fn commit_inner(&mut self, replace_existing: bool) -> io::Result<()> {
        drop(self.file.take());
        if replace_existing {
            crate::safety::remove_destination_for_replace(&self.final_path)?;
            fs::rename(&self.temp_path, &self.final_path)?;
        } else {
            atomic_no_clobber_rename(&self.temp_path, &self.final_path)?;
        }
        self.committed = true;
        Ok(())
    }
}

/// Publishes a set of prepared sibling files as one recoverable operation.
/// Existing outputs and obsolete siblings are staged under unique backup
/// names before any new output is committed. If a stage or commit fails, new
/// outputs are removed and every staged original is restored.
pub(crate) fn commit_file_set(outputs: Vec<AtomicOutputFile>, previous_paths: &[PathBuf], replace_existing: bool) -> io::Result<()> {
    let output_paths = outputs.iter().map(|output| output.final_path.clone()).collect::<Vec<_>>();
    let mut paths = Vec::new();
    for path in output_paths.iter().chain(previous_paths) {
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }

    let backups = if replace_existing {
        match stage_existing_files(&paths) {
            Ok(backups) => backups,
            Err((error, backups)) => return Err(rollback_file_set(&[], &backups, error)),
        }
    } else {
        Vec::new()
    };

    let mut committed_paths = Vec::new();
    for output in outputs {
        let path = output.final_path.clone();
        if let Err(error) = output.commit_with_file_replace(false) {
            return Err(rollback_file_set(&committed_paths, &backups, error));
        }
        committed_paths.push(path);
    }

    // Old versions are no longer needed once every output has been published.
    // If permissions prevent cleanup, leave the uniquely named hidden backup
    // in place rather than reporting a failed write after publication.
    for (_, backup) in &backups {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

fn stage_existing_files(paths: &[PathBuf]) -> Result<Vec<StagedFile>, StageFailure> {
    let mut backups = Vec::new();
    for path in paths {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err((error, backups)),
        };
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            return Err((io::Error::new(io::ErrorKind::IsADirectory, format!("cannot replace directory {}", path.display())), backups));
        }

        let backup = match create_backup_placeholder(path) {
            Ok(backup) => backup,
            Err(error) => return Err((error, backups)),
        };
        if let Err(error) = replace_file_from_path(path, &backup) {
            let _ = fs::remove_file(&backup);
            return Err((error, backups));
        }
        backups.push((path.clone(), backup));
    }
    Ok(backups)
}

fn create_backup_placeholder(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("archive");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let backup = parent.join(format!("{TEMP_PREFIX}-backup-{name}-{}-{now}-{attempt}{TEMP_SUFFIX}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&backup) {
            Ok(file) => {
                drop(file);
                return Ok(backup);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate backup path for {}", path.display())))
}

fn rollback_file_set(committed_paths: &[PathBuf], backups: &[StagedFile], cause: io::Error) -> io::Error {
    let mut rollback_errors = Vec::new();
    for path in committed_paths.iter().rev() {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != io::ErrorKind::NotFound
        {
            rollback_errors.push(format!("removing new output {} failed: {error}", path.display()));
        }
    }
    for (path, backup) in backups.iter().rev() {
        if let Err(error) = replace_file_from_path(backup, path) {
            rollback_errors.push(format!("restoring {} failed: {error}", path.display()));
        }
    }
    if rollback_errors.is_empty() { cause } else { io::Error::other(format!("{cause}; rollback also failed: {}", rollback_errors.join("; "))) }
}

#[cfg(any(test, target_os = "linux", target_os = "android", not(any(target_os = "macos", target_os = "ios", windows))))]
fn fallback_hardlink_rename(from: &Path, to: &Path) -> io::Result<()> {
    match fs::hard_link(from, to) {
        Ok(()) => {
            let _ = fs::remove_file(from);
            Ok(())
        }
        Err(error) if matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported) && !to.exists() => {
            // Some app sandboxes (notably Android app filesystems)
            // reject hard links even within one directory. The
            // destination was validated as absent, so a same-volume
            // rename preserves the refuse policy without weakening
            // collision safety.
            fs::rename(from, to)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(unsafe_code)]
fn atomic_no_clobber_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from_c = CString::new(from.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let to_c = CString::new(to.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if ret == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
fn atomic_no_clobber_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const RENAME_NOREPLACE: libc::c_uint = 1;

    let from_c = CString::new(from.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let to_c = CString::new(to.as_os_str().as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, from_c.as_ptr(), libc::AT_FDCWD, to_c.as_ptr(), RENAME_NOREPLACE) };

    if ret == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    let raw = err.raw_os_error();
    if matches!(raw, Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)) {
        return fallback_hardlink_rename(from, to);
    }

    Err(err)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn atomic_no_clobber_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from_w: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to_w: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe { MoveFileExW(from_w.as_ptr(), to_w.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux", target_os = "android", windows)))]
fn atomic_no_clobber_rename(from: &Path, to: &Path) -> io::Result<()> {
    fallback_hardlink_rename(from, to)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) struct TemporaryFile {
    path: PathBuf,
    file: File,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl TemporaryFile {
    pub(crate) fn create(label: &str) -> io::Result<Self> {
        let parent = std::env::temp_dir();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let path = parent.join(format!("{TEMP_PREFIX}-{label}-{}-{now}-{attempt}{TEMP_SUFFIX}", std::process::id()));
            match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate temporary file for {label}")))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Writes secret bytes to `path` atomically: content goes to a temporary
/// sibling file, is synced, and is renamed into place, so a crash at any
/// point leaves either the previous file or the complete new file — never a
/// truncated mix. On Unix the file is created with owner-only permissions
/// (0o600).
///
/// The temporary file is allocated with `create_new` plus a retry loop, so
/// two concurrent writers can never clobber each other's temporary file.
pub(crate) fn write_atomic_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("secret");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());

    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temporary = parent.join(format!("{file_name}.tmp-{}-{now}-{attempt}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let write_result: io::Result<()> = (|| {
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                let mut permissions = file.metadata()?.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&temporary, permissions)?;
            }
            drop(file);
            replace_file_over_existing(&temporary, path)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            if error.kind() == io::ErrorKind::AlreadyExists {
                // `create_new` raced with another writer of the same unique
                // name; try the next candidate name.
                continue;
            }
            return Err(error);
        }
        #[cfg(unix)]
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        return Ok(());
    }

    Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("could not allocate temporary secret file for {}", path.display())))
}

#[cfg(not(windows))]
fn replace_file_over_existing(temporary: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary, path)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn replace_file_over_existing(temporary: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // MoveFileExW with REPLACE_EXISTING is the Windows equivalent of an
    // atomic rename-over-existing-file. WRITE_THROUGH ensures the rename is
    // flushed before the call returns.
    let result = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for AtomicOutputFile {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AtomicOutputFile, commit_file_set};
    use crate::test_support::TestDir;
    use std::fs;
    use std::io::Write as _;

    #[test]
    fn commit_without_replace_moves_temp_file_to_final_path() {
        let temp = TestDir::new("atomic_commit");
        let final_path = temp.path("archive.zip");
        let mut output = AtomicOutputFile::create(&final_path).unwrap();

        output.file_mut().unwrap().write_all(b"archive").unwrap();
        output.commit_with_file_replace(false).unwrap();

        assert_eq!(fs::read(&final_path).unwrap(), b"archive");
    }

    #[test]
    fn drop_removes_uncommitted_temp_file() {
        let temp = TestDir::new("atomic_drop");
        let final_path = temp.path("archive.zip");

        {
            let mut output = AtomicOutputFile::create(&final_path).unwrap();
            output.file_mut().unwrap().write_all(b"partial").unwrap();
        }

        assert!(!final_path.exists());
        assert_eq!(fs::read_dir(temp.path(".")).unwrap().count(), 0);
    }

    #[test]
    fn commit_without_replace_refuses_existing_final_path() {
        let temp = TestDir::new("atomic_existing");
        let final_path = temp.path("archive.zip");
        fs::write(&final_path, b"old").unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        let error = output.commit_with_file_replace(false).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&final_path).unwrap(), b"old");
    }

    #[test]
    fn commit_with_file_replace_replaces_existing_file() {
        let temp = TestDir::new("atomic_replace_file");
        let final_path = temp.path("archive.zip");
        fs::write(&final_path, b"old").unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        output.commit_with_file_replace(true).unwrap();

        assert_eq!(fs::read(&final_path).unwrap(), b"new");
    }

    #[test]
    fn commit_with_file_replace_refuses_existing_directory() {
        let temp = TestDir::new("atomic_replace_directory");
        let final_path = temp.path("archive.zip");
        fs::create_dir(&final_path).unwrap();
        let mut output = AtomicOutputFile::create(&final_path).unwrap();
        output.file_mut().unwrap().write_all(b"new").unwrap();

        let error = output.commit_with_file_replace(true).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
        assert!(final_path.is_dir());
    }

    #[test]
    fn file_set_failure_restores_replaced_and_obsolete_files() {
        let temp = TestDir::new("atomic_set_rollback");
        let first_path = temp.path("archive.z01");
        let second_path = temp.path("archive.zip");
        let obsolete_path = temp.path("archive.z02");
        fs::write(&first_path, b"old first").unwrap();
        fs::write(&second_path, b"old second").unwrap();
        fs::write(&obsolete_path, b"old obsolete").unwrap();

        let mut first = AtomicOutputFile::create(&first_path).unwrap();
        first.file_mut().unwrap().write_all(b"new first").unwrap();
        let mut second = AtomicOutputFile::create(&second_path).unwrap();
        second.file_mut().unwrap().write_all(b"new second").unwrap();
        fs::remove_file(second.temp_path()).unwrap();

        let error = commit_file_set(vec![first, second], std::slice::from_ref(&obsolete_path), true).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs::read(&first_path).unwrap(), b"old first");
        assert_eq!(fs::read(&second_path).unwrap(), b"old second");
        assert_eq!(fs::read(&obsolete_path).unwrap(), b"old obsolete");
        assert_eq!(fs::read_dir(temp.path(".")).unwrap().count(), 3);
    }

    #[test]
    fn file_set_failure_without_replace_removes_earlier_new_outputs() {
        let temp = TestDir::new("atomic_set_no_replace_rollback");
        let first_path = temp.path("first.zip");
        let second_path = temp.path("second.zip");
        fs::write(&second_path, b"existing").unwrap();
        let mut first = AtomicOutputFile::create(&first_path).unwrap();
        first.file_mut().unwrap().write_all(b"new first").unwrap();
        let mut second = AtomicOutputFile::create(&second_path).unwrap();
        second.file_mut().unwrap().write_all(b"new second").unwrap();

        let error = commit_file_set(vec![first, second], &[], false).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!first_path.exists());
        assert_eq!(fs::read(&second_path).unwrap(), b"existing");
    }

    #[test]
    fn file_set_success_removes_obsolete_siblings() {
        let temp = TestDir::new("atomic_set_remove_obsolete");
        let output_path = temp.path("archive.zip");
        let obsolete_path = temp.path("archive.z01");
        fs::write(&obsolete_path, b"stale").unwrap();
        let mut output = AtomicOutputFile::create(&output_path).unwrap();
        output.file_mut().unwrap().write_all(b"new archive").unwrap();

        commit_file_set(vec![output], std::slice::from_ref(&obsolete_path), true).unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), b"new archive");
        assert!(!obsolete_path.exists());
        assert_eq!(fs::read_dir(temp.path(".")).unwrap().count(), 1);
    }

    #[test]
    fn fallback_hardlink_rename_moves_file_and_removes_source() {
        let temp = TestDir::new("atomic_fallback_move");
        let src = temp.path("src.tmp");
        let dst = temp.path("dst.txt");
        fs::write(&src, b"payload").unwrap();

        super::fallback_hardlink_rename(&src, &dst).unwrap();

        assert!(!src.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"payload");
    }

    #[test]
    fn fallback_hardlink_rename_refuses_existing_destination() {
        let temp = TestDir::new("atomic_fallback_refuse");
        let src = temp.path("src.tmp");
        let dst = temp.path("dst.txt");
        fs::write(&src, b"new").unwrap();
        fs::write(&dst, b"old").unwrap();

        let error = super::fallback_hardlink_rename(&src, &dst).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&dst).unwrap(), b"old");
    }
}
