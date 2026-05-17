use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TEMP_PREFIX: &str = ".zmanager";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_TEMP_ATTEMPTS: u32 = 100;

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
        let file_name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("archive");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());

        for attempt in 0..MAX_TEMP_ATTEMPTS {
            let temp_path = parent.join(format!(
                "{TEMP_PREFIX}-{file_name}-{}-{now}-{attempt}{TEMP_SUFFIX}",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => {
                    return Ok(Self {
                        final_path: final_path.to_path_buf(),
                        temp_path,
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not allocate temporary output path for {}",
                final_path.display()
            ),
        ))
    }

    pub(crate) fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file.as_mut().ok_or_else(|| {
            io::Error::other(format!(
                "temporary output already finalized for {}",
                self.final_path.display()
            ))
        })
    }

    pub(crate) fn commit(mut self) -> io::Result<()> {
        self.commit_inner(false)
    }

    pub(crate) fn commit_with_replace(mut self, replace_existing: bool) -> io::Result<()> {
        self.commit_inner(replace_existing)
    }

    fn commit_inner(&mut self, replace_existing: bool) -> io::Result<()> {
        drop(self.file.take());
        if replace_existing {
            crate::safety::remove_destination_for_replace(&self.final_path)?;
        }
        fs::rename(&self.temp_path, &self.final_path)?;
        self.committed = true;
        Ok(())
    }
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
    use super::AtomicOutputFile;
    use std::fs;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn commit_moves_temp_file_to_final_path() {
        let temp = TestDir::new("atomic_commit");
        let final_path = temp.path("archive.zip");
        let mut output = AtomicOutputFile::create(&final_path).unwrap();

        output.file_mut().unwrap().write_all(b"archive").unwrap();
        output.commit().unwrap();

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

    struct TestDir {
        root: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("zmanager-{name}-{}-{now}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
            self.root.join(relative)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
