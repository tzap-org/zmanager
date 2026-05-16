use crate::manifest::{PlanOptions, plan_archive, plan_archives};
use crate::tar_zst_backend::{self, TarZstdCreateOptions, TarZstdError, TarZstdExtractReport};
use crate::zip_backend::{self, ZipBackendError, ZipCreateOptions, ZipCreateReport};
use crate::{libarchive_backend, libarchive_backend::LibarchiveError};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Long-running job kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobKind {
    /// ZIP creation.
    ZipCreate,
    /// ZIP extraction.
    ZipExtract,
    /// TAR.ZST creation.
    TarZstdCreate,
    /// TAR.ZST extraction.
    TarZstdExtract,
    /// Broad libarchive-backed extraction.
    ArchiveExtract,
}

/// Progress and lifecycle event emitted by archive jobs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JobEvent {
    /// Job started.
    Started {
        /// Job kind.
        kind: JobKind,
        /// Planned source bytes when known.
        total_bytes: Option<u64>,
    },
    /// An archive entry started processing.
    EntryStarted {
        /// Archive path.
        path: String,
        /// Entry bytes when known.
        bytes: Option<u64>,
    },
    /// Bytes were processed for an entry.
    BytesProcessed {
        /// Archive path when associated with a specific entry.
        path: Option<String>,
        /// Incremental bytes processed by this event.
        bytes: u64,
        /// Total bytes processed so far by this job context.
        total_bytes_processed: u64,
    },
    /// An archive entry finished processing.
    EntryFinished {
        /// Archive path.
        path: String,
        /// Entry bytes processed.
        bytes: u64,
    },
    /// Non-fatal warning.
    Warning {
        /// Warning message.
        message: String,
    },
    /// Job completed successfully.
    Completed {
        /// Entries written or extracted.
        entries: usize,
        /// Bytes written or extracted.
        bytes: u64,
    },
    /// Job failed.
    Failed {
        /// Failure message.
        message: String,
    },
    /// Job was cancelled cooperatively.
    Cancelled {
        /// Cancellation message.
        message: String,
    },
}

/// Consumer of job events.
pub trait JobEventSink {
    /// Receives one event.
    fn emit(&mut self, event: JobEvent);
}

impl<F> JobEventSink for F
where
    F: FnMut(JobEvent),
{
    fn emit(&mut self, event: JobEvent) {
        self(event);
    }
}

/// Shared cooperative cancellation token.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a new token in the non-cancelled state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Cancellation marker returned by cooperative job checks.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct JobCancelled;

impl fmt::Display for JobCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "job cancelled")
    }
}

impl std::error::Error for JobCancelled {}

/// Mutable job context passed into backends while a job is running.
pub struct JobContext<'a> {
    token: &'a CancellationToken,
    sink: &'a mut dyn JobEventSink,
    total_bytes_processed: u64,
}

impl<'a> JobContext<'a> {
    /// Creates a context backed by a cancellation token and event sink.
    pub fn new(token: &'a CancellationToken, sink: &'a mut dyn JobEventSink) -> Self {
        Self {
            token,
            sink,
            total_bytes_processed: 0,
        }
    }

    /// Emits an event.
    pub fn emit(&mut self, event: JobEvent) {
        self.sink.emit(event);
    }

    /// Emits an entry-started event.
    pub fn entry_started(&mut self, path: impl Into<String>, bytes: Option<u64>) {
        self.emit(JobEvent::EntryStarted {
            path: path.into(),
            bytes,
        });
    }

    /// Emits an entry-finished event.
    pub fn entry_finished(&mut self, path: impl Into<String>, bytes: u64) {
        self.emit(JobEvent::EntryFinished {
            path: path.into(),
            bytes,
        });
    }

    /// Emits a warning event.
    pub fn warning(&mut self, message: impl Into<String>) {
        self.emit(JobEvent::Warning {
            message: message.into(),
        });
    }

    /// Emits a bytes-processed event and updates cumulative progress.
    pub fn bytes_processed(&mut self, path: Option<&str>, bytes: u64) {
        self.total_bytes_processed += bytes;
        self.emit(JobEvent::BytesProcessed {
            path: path.map(ToOwned::to_owned),
            bytes,
            total_bytes_processed: self.total_bytes_processed,
        });
    }

    /// Returns an error if cancellation was requested.
    ///
    /// # Errors
    ///
    /// Returns [`JobCancelled`] when the shared token has been cancelled.
    pub fn check_cancelled(&self) -> Result<(), JobCancelled> {
        if self.token.is_cancelled() {
            Err(JobCancelled)
        } else {
            Ok(())
        }
    }
}

/// Runs a ZIP create job and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
/// Atomic cleanup is deferred to hardening work.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, ZIP creation, filesystem I/O, or
/// cancellation fails.
pub fn run_zip_create_job(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<ZipCreateReport, ZipBackendError> {
    let manifest = match plan_archive(source, &PlanOptions::default()) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = ZipBackendError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::ZipCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::ZipCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new(token, sink);
    let result = zip_backend::create_zip_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    finish_zip_create_result(result, sink)
}

/// Runs a ZIP create job for multiple source roots and emits lifecycle/progress
/// events.
///
/// Partial output state: cancellation can leave a partial destination archive.
/// Atomic cleanup is deferred to hardening work.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, ZIP creation, filesystem I/O, or
/// cancellation fails.
pub fn run_zip_create_job_from_sources(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<ZipCreateReport, ZipBackendError> {
    let manifest = match plan_archives(sources, &PlanOptions::default()) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = ZipBackendError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::ZipCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::ZipCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new(token, sink);
    let result = zip_backend::create_zip_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    finish_zip_create_result(result, sink)
}

/// Runs a ZIP extract job and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when ZIP reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_zip_extract_job(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<zip_backend::ZipExtractReport, ZipBackendError> {
    run_zip_extract_job_with_password(archive_path, destination, None, token, sink)
}

/// Runs a ZIP extract job with an optional password and emits
/// lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when ZIP reading, password validation,
/// extraction safety, filesystem I/O, or cancellation fails.
pub fn run_zip_extract_job_with_password(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<zip_backend::ZipExtractReport, ZipBackendError> {
    sink.emit(JobEvent::Started {
        kind: JobKind::ZipExtract,
        total_bytes: None,
    });
    let mut context = JobContext::new(token, sink);
    let result = zip_backend::extract_zip_with_context_and_password(
        archive_path,
        destination,
        crate::safety::ExtractionPolicy::default(),
        password,
        &mut context,
    );
    finish_zip_extract_result(result, sink)
}

/// Runs a TAR.ZST create job and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_tar_zst_create_job(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    run_tar_zst_create_job_with_plan_options(
        source,
        destination,
        options,
        &PlanOptions::default(),
        token,
        sink,
    )
}

/// Runs the clean source `.tar.zst` create profile and emits lifecycle/progress
/// events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_clean_source_tar_zst_create_job(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    run_tar_zst_create_job_with_plan_options(
        source,
        destination,
        options,
        &PlanOptions::clean_source(),
        token,
        sink,
    )
}

/// Runs the clean source `.tar.zst` create profile for multiple source roots
/// and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_clean_source_tar_zst_create_job_from_sources(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    run_tar_zst_create_job_from_sources_with_plan_options(
        sources,
        destination,
        options,
        &PlanOptions::clean_source(),
        token,
        sink,
    )
}

fn run_tar_zst_create_job_with_plan_options(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    let manifest = match plan_archive(source, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = TarZstdError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::TarZstdCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::TarZstdCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new(token, sink);
    let result = tar_zst_backend::create_tar_zst_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    finish_tar_zst_create_result(result, sink)
}

fn run_tar_zst_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &TarZstdCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = TarZstdError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::TarZstdCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::TarZstdCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new(token, sink);
    let result = tar_zst_backend::create_tar_zst_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    finish_tar_zst_create_result(result, sink)
}

/// Runs a TAR.ZST extract job and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`TarZstdError`] when TAR.ZST reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_tar_zst_extract_job(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<TarZstdExtractReport, TarZstdError> {
    sink.emit(JobEvent::Started {
        kind: JobKind::TarZstdExtract,
        total_bytes: None,
    });
    let mut context = JobContext::new(token, sink);
    let result = tar_zst_backend::extract_tar_zst_with_context(
        archive_path,
        destination,
        crate::safety::ExtractionPolicy::default(),
        &mut context,
    );
    finish_tar_zst_extract_result(result, sink)
}

/// Runs a broad libarchive extract job and emits coarse lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// libarchive extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive reading, extraction safety, or
/// filesystem I/O fails.
pub fn run_libarchive_extract_job(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<libarchive_backend::LibarchiveExtractReport, LibarchiveError> {
    sink.emit(JobEvent::Started {
        kind: JobKind::ArchiveExtract,
        total_bytes: None,
    });
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(LibarchiveError::Io {
            path: archive_path.as_ref().to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"),
        });
    }

    let result = libarchive_backend::extract_archive(
        archive_path,
        destination,
        crate::safety::ExtractionPolicy::default(),
    );
    finish_libarchive_extract_result(result, sink)
}

fn finish_zip_create_result(
    result: Result<ZipCreateReport, ZipBackendError>,
    sink: &mut dyn JobEventSink,
) -> Result<ZipCreateReport, ZipBackendError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(ZipBackendError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(ZipBackendError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_zip_extract_result(
    result: Result<zip_backend::ZipExtractReport, ZipBackendError>,
    sink: &mut dyn JobEventSink,
) -> Result<zip_backend::ZipExtractReport, ZipBackendError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(ZipBackendError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(ZipBackendError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_tar_zst_create_result(
    result: Result<tar_zst_backend::TarZstdCreateReport, TarZstdError>,
    sink: &mut dyn JobEventSink,
) -> Result<tar_zst_backend::TarZstdCreateReport, TarZstdError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(TarZstdError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(TarZstdError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_tar_zst_extract_result(
    result: Result<TarZstdExtractReport, TarZstdError>,
    sink: &mut dyn JobEventSink,
) -> Result<TarZstdExtractReport, TarZstdError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(TarZstdError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(TarZstdError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_libarchive_extract_result(
    result: Result<libarchive_backend::LibarchiveExtractReport, LibarchiveError>,
    sink: &mut dyn JobEventSink,
) -> Result<libarchive_backend::LibarchiveExtractReport, LibarchiveError> {
    match result {
        Ok(report) => {
            for warning in &report.warnings {
                sink.emit(JobEvent::Warning {
                    message: warning.clone(),
                });
            }
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CancellationToken, JobEvent, run_clean_source_tar_zst_create_job,
        run_clean_source_tar_zst_create_job_from_sources, run_tar_zst_create_job,
        run_zip_create_job, run_zip_create_job_from_sources, run_zip_extract_job,
    };
    use crate::archive_browser::list_entries;
    use crate::tar_zst_backend::TarZstdCreateOptions;
    use crate::zip_backend::{ZipBackendError, ZipCreateOptions, list_zip};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn zip_create_job_emits_ordered_events() {
        let temp = TestDir::new("zip_create_job_emits_ordered_events");
        temp.write_file("project/file.txt", b"hello");
        let mut events = Vec::new();

        run_zip_create_job(
            temp.path("project"),
            temp.path("archive.zip"),
            &ZipCreateOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert!(matches!(
            events.first(),
            Some(JobEvent::Started {
                kind: super::JobKind::ZipCreate,
                ..
            })
        ));
        assert!(events
            .iter()
            .any(|event| matches!(event, JobEvent::EntryStarted { path, .. } if path == "project/file.txt")));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, JobEvent::BytesProcessed { bytes: 5, .. }))
        );
        assert!(matches!(
            events.last(),
            Some(JobEvent::Completed {
                entries: 2,
                bytes: 5
            })
        ));
    }

    #[test]
    fn zip_extract_job_emits_failure_event() {
        let temp = TestDir::new("zip_extract_job_emits_failure_event");
        let mut events = Vec::new();

        let result = run_zip_extract_job(
            temp.path("missing.zip"),
            temp.path("out"),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        );

        assert!(result.is_err());
        assert!(matches!(events.first(), Some(JobEvent::Started { .. })));
        assert!(matches!(events.last(), Some(JobEvent::Failed { .. })));
    }

    #[test]
    fn zip_create_job_can_be_cancelled() {
        let temp = TestDir::new("zip_create_job_can_be_cancelled");
        temp.write_file("project/file.txt", b"hello");
        let token = CancellationToken::new();
        let token_for_sink = token.clone();
        let mut events = Vec::new();

        let result = run_zip_create_job(
            temp.path("project"),
            temp.path("archive.zip"),
            &ZipCreateOptions::default(),
            &token,
            &mut |event| {
                if matches!(event, JobEvent::EntryStarted { .. }) {
                    token_for_sink.cancel();
                }
                events.push(event);
            },
        );

        assert!(matches!(result, Err(ZipBackendError::Cancelled)));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, JobEvent::Cancelled { .. }))
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, JobEvent::Completed { .. }))
        );
    }

    #[test]
    fn zip_create_job_accepts_multiple_source_roots() {
        let temp = TestDir::new("zip_create_job_accepts_multiple_source_roots");
        temp.write_file("a.txt", b"a");
        temp.write_file("folder/b.txt", b"bb");
        let archive = temp.path("selection.zip");
        let mut events = Vec::new();

        let report = run_zip_create_job_from_sources(
            &[temp.path("a.txt"), temp.path("folder")],
            &archive,
            &ZipCreateOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert_eq!(report.written_entries, 3);
        assert_eq!(report.written_bytes, 3);
        assert!(matches!(
            events.first(),
            Some(JobEvent::Started {
                kind: super::JobKind::ZipCreate,
                total_bytes: Some(3),
            })
        ));

        let listing = list_zip(&archive).unwrap();
        let names = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["a.txt", "folder/", "folder/b.txt"]);
    }

    #[test]
    fn tar_zst_create_job_emits_entry_and_byte_events() {
        let temp = TestDir::new("tar_zst_create_job_emits_entry_and_byte_events");
        temp.write_file("project/file.txt", b"hello");
        let mut events = Vec::new();

        run_tar_zst_create_job(
            temp.path("project"),
            temp.path("archive.tar.zst"),
            &TarZstdCreateOptions {
                level: 1,
                threads: Some(1),
                preserve_metadata: true,
            },
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert!(matches!(
            events.first(),
            Some(JobEvent::Started {
                kind: super::JobKind::TarZstdCreate,
                ..
            })
        ));
        assert!(events
            .iter()
            .any(|event| matches!(event, JobEvent::EntryStarted { path, .. } if path == "project/file.txt")));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, JobEvent::BytesProcessed { bytes: 5, .. }))
        );
        assert!(matches!(
            events.last(),
            Some(JobEvent::Completed {
                entries: 2,
                bytes: 5
            })
        ));
    }

    #[test]
    fn clean_source_tar_zst_job_uses_clean_manifest_profile() {
        let temp = TestDir::new("clean_source_tar_zst_job_uses_clean_manifest_profile");
        temp.write_file("project/src/main.rs", b"fn main() {}\n");
        temp.write_file("project/node_modules/pkg/index.js", b"drop");
        let mut events = Vec::new();

        let report = run_clean_source_tar_zst_create_job(
            temp.path("project"),
            temp.path("project.clean.tar.zst"),
            &TarZstdCreateOptions {
                level: 1,
                threads: Some(1),
                preserve_metadata: true,
            },
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert_eq!(report.written_entries, 3);
        assert!(events
            .iter()
            .any(|event| matches!(event, JobEvent::EntryStarted { path, .. } if path == "project/src/main.rs")));
        assert!(!events
            .iter()
            .any(|event| matches!(event, JobEvent::EntryStarted { path, .. } if path.contains("node_modules"))));
    }

    #[test]
    fn clean_source_tar_zst_job_accepts_multiple_source_roots() {
        let temp = TestDir::new("clean_source_tar_zst_job_accepts_multiple_source_roots");
        temp.write_file("a.txt", b"a");
        temp.write_file("folder/b.txt", b"bb");
        temp.write_file("folder/node_modules/pkg/index.js", b"drop");
        let archive = temp.path("selection.clean.tar.zst");

        let report = run_clean_source_tar_zst_create_job_from_sources(
            &[temp.path("a.txt"), temp.path("folder")],
            &archive,
            &TarZstdCreateOptions {
                level: 1,
                threads: Some(1),
                preserve_metadata: true,
            },
            &CancellationToken::new(),
            &mut |_| {},
        )
        .unwrap();

        assert_eq!(report.written_entries, 3);
        assert_eq!(report.written_bytes, 3);

        let listing = list_entries(&archive).unwrap();
        let paths = listing
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["a.txt", "folder", "folder/b.txt"]);
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

        fn write_file(&self, relative: impl AsRef<Path>, contents: &[u8]) {
            let path = self.path(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
