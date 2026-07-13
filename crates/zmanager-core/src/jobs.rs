use crate::apple_archive_backend::{
    self, AppleArchiveCreateOptions, AppleArchiveCreateReport, AppleArchiveError,
};
use crate::manifest::{PlanOptions, plan_archive, plan_archives};
use crate::safety::ExtractionPolicy;
use crate::sevenz_backend::{SevenZCreateOptions, SevenZCreateReport};
use crate::tar_zst_backend::{self, TarZstdCreateOptions, TarZstdError, TarZstdExtractReport};
use crate::tzap_backend::{self, TzapCreateOptions, TzapCreateReport, TzapError};
use crate::zip_backend::{self, ZipBackendError, ZipCreateOptions, ZipCreateReport};
use crate::{
    libarchive_backend,
    libarchive_backend::LibarchiveError,
    rar_backend,
    rar_backend::RarBackendError,
    raw_stream_backend,
    raw_stream_backend::{RawStreamError, RawStreamFormat},
    sevenz_backend,
    sevenz_backend::SevenZError,
};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Long-running job kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobKind {
    /// ZIP creation.
    ZipCreate,
    /// ZIP extraction.
    ZipExtract,
    /// 7z creation.
    SevenZCreate,
    /// 7z extraction.
    SevenZExtract,
    /// RAR extraction.
    RarExtract,
    /// TAR.ZST creation.
    TarZstdCreate,
    /// TAR.ZST extraction.
    TarZstdExtract,
    /// TZAP creation.
    TzapCreate,
    /// TZAP extraction.
    TzapExtract,
    /// AppleArchive creation.
    AppleArchiveCreate,
    /// AppleArchive extraction.
    AppleArchiveExtract,
    /// Broad libarchive-backed extraction.
    ArchiveExtract,
    /// Raw single-file stream extraction.
    RawStreamExtract,
}

/// One observable phase of an archive job.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum JobPhase {
    /// Read and compress source payloads to determine the archive layout.
    PlanningPayload,
    /// Build indexes and metadata after the payload layout is known.
    PlanningMetadata,
    /// Read, compress, protect, and write payload blocks.
    EmittingPayload,
    /// Protect and write indexes, recovery metadata, footers, and trailers.
    EmittingMetadata,
    /// Publish temporary output files at their final paths.
    CommittingOutput,
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
        /// Most recently active archive paths, capped by the producer.
        recent_paths: Vec<String>,
        /// Incremental bytes processed by this event.
        bytes: u64,
        /// Total bytes processed so far by this job context.
        total_bytes_processed: u64,
    },
    /// A job entered a new observable phase.
    PhaseStarted {
        /// Newly active phase.
        phase: JobPhase,
        /// Total source bytes for this phase when known.
        total_bytes: Option<u64>,
    },
    /// Source bytes were processed within one observable phase.
    PhaseBytesProcessed {
        /// Active phase.
        phase: JobPhase,
        /// Archive path when associated with a specific entry.
        path: Option<String>,
        /// Most recently active archive paths, capped by the producer.
        recent_paths: Vec<String>,
        /// Incremental bytes processed by this event.
        bytes: u64,
        /// Total bytes processed so far within this phase.
        total_bytes_processed: u64,
        /// Total source bytes for this phase when known.
        total_bytes: Option<u64>,
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

/// Terminal outcome of a core archive execution.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobOutcome {
    /// The operation committed successfully.
    Completed,
    /// The operation failed.
    Failed,
    /// The operation observed cooperative cancellation before success.
    Cancelled,
}

/// Runtime-neutral projection of the latest raw progress facts.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct JobProgressState {
    pub processed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub processed_entries: u64,
    pub total_entries: Option<u64>,
    pub current_path: Option<String>,
    pub recent_paths: Vec<String>,
    pub active_phase: Option<JobPhase>,
    pub phase_processed_bytes: u64,
    pub phase_total_bytes: Option<u64>,
    pub warning_count: u64,
    pub outcome: Option<JobOutcome>,
}

impl JobProgressState {
    /// Applies one semantic event. The first terminal outcome is immutable.
    pub fn apply(&mut self, event: &JobEvent) {
        if self.outcome.is_some() {
            return;
        }
        match event {
            JobEvent::Started { total_bytes, .. } => self.total_bytes = *total_bytes,
            JobEvent::EntryStarted { path, .. } => self.record_path(path),
            JobEvent::BytesProcessed { path, recent_paths, total_bytes_processed, .. } => {
                self.processed_bytes = self.processed_bytes.max(*total_bytes_processed);
                self.record_paths(path.as_deref(), recent_paths);
            }
            JobEvent::PhaseStarted { phase, total_bytes } => {
                self.active_phase = Some(*phase);
                self.phase_processed_bytes = 0;
                self.phase_total_bytes = *total_bytes;
            }
            JobEvent::PhaseBytesProcessed { phase, path, recent_paths, total_bytes_processed, total_bytes, .. } => {
                if self.active_phase != Some(*phase) {
                    self.active_phase = Some(*phase);
                    self.phase_processed_bytes = 0;
                }
                self.phase_processed_bytes = self.phase_processed_bytes.max(*total_bytes_processed);
                self.phase_total_bytes = *total_bytes;
                self.record_paths(path.as_deref(), recent_paths);
            }
            JobEvent::EntryFinished { path, .. } => {
                self.processed_entries = self.processed_entries.saturating_add(1);
                self.record_path(path);
            }
            JobEvent::Warning { .. } => self.warning_count = self.warning_count.saturating_add(1),
            JobEvent::Completed { entries, bytes } => {
                self.processed_entries = self.processed_entries.max(*entries as u64);
                self.processed_bytes = self.processed_bytes.max(*bytes);
                self.outcome = Some(JobOutcome::Completed);
            }
            JobEvent::Failed { .. } => self.outcome = Some(JobOutcome::Failed),
            JobEvent::Cancelled { .. } => self.outcome = Some(JobOutcome::Cancelled),
        }
    }

    fn record_paths(&mut self, current: Option<&str>, recent: &[String]) {
        for path in recent { self.record_path(path); }
        if let Some(path) = current { self.record_path(path); }
    }

    fn record_path(&mut self, path: &str) {
        if let Some(index) = self.recent_paths.iter().position(|item| item == path) {
            self.recent_paths.remove(index);
        }
        self.recent_paths.push(path.to_owned());
        if self.recent_paths.len() > PROGRESS_RECENT_PATH_LIMIT {
            self.recent_paths.remove(0);
        }
        self.current_path = Some(path.to_owned());
    }
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

pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const PROGRESS_MIN_BYTE_STEP: u64 = 4 * 1024 * 1024;
pub(crate) const PROGRESS_RECENT_PATH_LIMIT: usize = 10;

pub(crate) struct ProgressBatch {
    pub(crate) path: Option<String>,
    pub(crate) recent_paths: Vec<String>,
    pub(crate) bytes: u64,
}

pub(crate) struct ProgressCoalescer {
    total_bytes: Option<u64>,
    pending_bytes: u64,
    latest_path: Option<String>,
    recent_paths: VecDeque<String>,
    last_emitted: Instant,
    emitted_once: bool,
}

impl ProgressCoalescer {
    pub(crate) fn new(total_bytes: Option<u64>) -> Self {
        Self {
            total_bytes,
            pending_bytes: 0,
            latest_path: None,
            recent_paths: VecDeque::new(),
            last_emitted: Instant::now(),
            emitted_once: false,
        }
    }

    pub(crate) fn reset(&mut self, total_bytes: Option<u64>) {
        self.total_bytes = total_bytes;
        self.pending_bytes = 0;
        self.latest_path = None;
        self.recent_paths.clear();
        self.last_emitted = Instant::now();
        self.emitted_once = false;
    }

    pub(crate) fn record(&mut self, path: Option<&str>, bytes: u64) -> Option<ProgressBatch> {
        if bytes == 0 {
            return None;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        if let Some(path) = path {
            if self.latest_path.as_deref() != Some(path) {
                self.latest_path = Some(path.to_owned());
            }
            if !self
                .recent_paths
                .back()
                .is_some_and(|recent| recent == path)
            {
                if let Some(position) = self.recent_paths.iter().position(|recent| recent == path) {
                    self.recent_paths.remove(position);
                }
                self.recent_paths.push_back(path.to_owned());
                if self.recent_paths.len() > PROGRESS_RECENT_PATH_LIMIT {
                    self.recent_paths.pop_front();
                }
            }
        }

        let one_percent = self.total_bytes.unwrap_or_default().div_ceil(100);
        let byte_step = PROGRESS_MIN_BYTE_STEP.max(one_percent);
        if !self.emitted_once
            || self.pending_bytes >= byte_step
            || self.last_emitted.elapsed() >= PROGRESS_INTERVAL
        {
            self.flush()
        } else {
            None
        }
    }

    pub(crate) fn flush(&mut self) -> Option<ProgressBatch> {
        if self.pending_bytes == 0 {
            return None;
        }
        self.emitted_once = true;
        self.last_emitted = Instant::now();
        Some(ProgressBatch {
            path: self.latest_path.take(),
            recent_paths: self.recent_paths.drain(..).collect(),
            bytes: std::mem::take(&mut self.pending_bytes),
        })
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
    progress: ProgressCoalescer,
    phase_bytes_processed: BTreeMap<JobPhase, u64>,
}

impl<'a> JobContext<'a> {
    /// Creates a context backed by a cancellation token and event sink.
    pub fn new(token: &'a CancellationToken, sink: &'a mut dyn JobEventSink) -> Self {
        Self::new_with_progress_total(token, sink, None)
    }

    /// Creates a context with a known logical byte total for progress batching.
    pub fn new_with_progress_total(
        token: &'a CancellationToken,
        sink: &'a mut dyn JobEventSink,
        total_bytes: Option<u64>,
    ) -> Self {
        Self {
            token,
            sink,
            total_bytes_processed: 0,
            progress: ProgressCoalescer::new(total_bytes),
            phase_bytes_processed: BTreeMap::new(),
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
        self.total_bytes_processed = self.total_bytes_processed.saturating_add(bytes);
        if let Some(batch) = self.progress.record(path, bytes) {
            self.emit_bytes_processed_batch(batch);
        }
    }

    /// Flushes pending format-neutral byte progress.
    pub fn flush_progress(&mut self) {
        if let Some(batch) = self.progress.flush() {
            self.emit_bytes_processed_batch(batch);
        }
    }

    fn emit_bytes_processed_batch(&mut self, batch: ProgressBatch) {
        self.emit(JobEvent::BytesProcessed {
            path: batch.path,
            recent_paths: batch.recent_paths,
            bytes: batch.bytes,
            total_bytes_processed: self.total_bytes_processed,
        });
    }

    /// Emits a phase-started event and resets that phase's byte counter.
    pub fn phase_started(&mut self, phase: JobPhase, total_bytes: Option<u64>) {
        self.phase_bytes_processed.insert(phase, 0);
        self.emit(JobEvent::PhaseStarted { phase, total_bytes });
    }

    /// Emits phase-scoped byte progress and updates its cumulative counter.
    pub fn phase_bytes_processed(
        &mut self,
        phase: JobPhase,
        path: Option<&str>,
        bytes: u64,
        total_bytes: Option<u64>,
    ) {
        let recent_paths = path.into_iter().map(ToOwned::to_owned).collect();
        self.phase_bytes_processed_with_recent_paths(phase, path, recent_paths, bytes, total_bytes);
    }

    /// Emits phase-scoped byte progress with a capped recent-path activity list.
    pub fn phase_bytes_processed_with_recent_paths(
        &mut self,
        phase: JobPhase,
        path: Option<&str>,
        recent_paths: Vec<String>,
        bytes: u64,
        total_bytes: Option<u64>,
    ) {
        let total_bytes_processed = {
            let processed = self.phase_bytes_processed.entry(phase).or_default();
            *processed = processed.saturating_add(bytes);
            *processed
        };
        self.emit(JobEvent::PhaseBytesProcessed {
            phase,
            path: path.map(ToOwned::to_owned),
            recent_paths,
            bytes,
            total_bytes_processed,
            total_bytes,
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

    /// Returns a clone of the cancellation token for reader adapters that
    /// cannot hold a borrow of the full job context.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.token.clone()
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
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = zip_backend::create_zip_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
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
    run_zip_create_job_from_sources_with_plan_options(
        sources,
        destination,
        options,
        &PlanOptions::default(),
        token,
        sink,
    )
}

/// Runs a ZIP create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
/// Atomic cleanup is deferred to hardening work.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when planning, ZIP creation, filesystem I/O, or
/// cancellation fails.
pub fn run_zip_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &ZipCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<ZipCreateReport, ZipBackendError> {
    let manifest = match plan_archives(sources, plan_options) {
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
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = zip_backend::create_zip_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
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
    run_zip_extract_job_with_password_and_policy(
        archive_path,
        destination,
        None,
        ExtractionPolicy::default(),
        token,
        sink,
    )
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
    run_zip_extract_job_with_password_and_policy(
        archive_path,
        destination,
        password,
        ExtractionPolicy::default(),
        token,
        sink,
    )
}

/// Runs a ZIP extract job with an optional password and explicit extraction
/// policy while emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`ZipBackendError`] when ZIP reading, password validation,
/// extraction safety, filesystem I/O, or cancellation fails.
pub fn run_zip_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<zip_backend::ZipExtractReport, ZipBackendError> {
    let total_bytes = match zip_backend::list_zip(archive_path.as_ref()) {
        Ok(listing) => Some(listing.entries.iter().map(|entry| entry.size).sum()),
        Err(_) => None,
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::ZipExtract,
        total_bytes,
    });
    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = zip_backend::extract_zip_with_context_and_password(
        archive_path,
        destination,
        policy,
        password,
        &mut context,
    );
    context.flush_progress();
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

/// Runs a TAR.ZST create job for multiple source roots and emits
/// lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_tar_zst_create_job_from_sources(
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
        &PlanOptions::default(),
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
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = tar_zst_backend::create_tar_zst_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
    finish_tar_zst_create_result(result, sink)
}

/// Runs a TAR.ZST create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TarZstdError`] when planning, TAR.ZST creation, filesystem I/O, or
/// cancellation fails.
pub fn run_tar_zst_create_job_from_sources_with_plan_options(
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
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = tar_zst_backend::create_tar_zst_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
    finish_tar_zst_create_result(result, sink)
}

/// Runs an AppleArchive create job for multiple source roots with explicit
/// planning options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when planning, AppleArchive creation,
/// filesystem I/O, or cancellation fails.
pub fn run_apple_archive_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &AppleArchiveCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = AppleArchiveError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::AppleArchiveCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::AppleArchiveCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = apple_archive_backend::create_apple_archive_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
    finish_apple_archive_create_result(result, sink)
}

/// Runs a 7z create job for multiple source roots with explicit planning
/// options and emits lifecycle events.
///
/// Partial output state: cancellation during 7z encoding is backend-limited.
///
/// # Errors
///
/// Returns [`SevenZError`] when planning, filesystem reads, or 7z writing fails.
pub fn run_7z_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &SevenZCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<SevenZCreateReport, SevenZError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = SevenZError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::SevenZCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::SevenZCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = sevenz_backend::create_7z_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
    finish_7z_create_result(result, sink)
}

fn finish_7z_create_result(
    result: Result<SevenZCreateReport, SevenZError>,
    sink: &mut dyn JobEventSink,
) -> Result<SevenZCreateReport, SevenZError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(SevenZError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(SevenZError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

/// Runs a TZAP create job for multiple source roots with explicit planning
/// options and emits lifecycle/progress events.
///
/// Partial output state: cancellation can leave a partial destination archive.
///
/// # Errors
///
/// Returns [`TzapError`] when planning, TZAP creation, filesystem I/O,
/// password key derivation, or cancellation fails.
pub fn run_tzap_create_job_from_sources_with_plan_options(
    sources: &[PathBuf],
    destination: impl AsRef<Path>,
    options: &TzapCreateOptions,
    plan_options: &PlanOptions,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<TzapCreateReport, TzapError> {
    let manifest = match plan_archives(sources, plan_options) {
        Ok(manifest) => manifest,
        Err(error) => {
            let error = TzapError::Plan(error);
            sink.emit(JobEvent::Started {
                kind: JobKind::TzapCreate,
                total_bytes: None,
            });
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::TzapCreate,
        total_bytes: Some(manifest.total_bytes),
    });
    let mut context = JobContext::new_with_progress_total(token, sink, Some(manifest.total_bytes));
    let result = tzap_backend::create_tzap_from_manifest_with_context(
        &manifest,
        destination,
        options,
        &mut context,
    );
    context.flush_progress();
    finish_tzap_create_result(result, sink)
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
    run_tar_zst_extract_job_with_policy(
        archive_path,
        destination,
        ExtractionPolicy::default(),
        token,
        sink,
    )
}

/// Runs a TAR.ZST extract job with an explicit extraction policy while emitting
/// lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`TarZstdError`] when TAR.ZST reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_tar_zst_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<TarZstdExtractReport, TarZstdError> {
    let total_bytes = tar_zst_backend::estimate_tar_zst_uncompressed_size(&archive_path).ok();
    sink.emit(JobEvent::Started {
        kind: JobKind::TarZstdExtract,
        total_bytes,
    });
    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = tar_zst_backend::extract_tar_zst_with_context(
        archive_path,
        destination,
        policy,
        &mut context,
    );
    context.flush_progress();
    finish_tar_zst_extract_result(result, sink)
}

/// Runs an AppleArchive extract job with an explicit extraction policy while
/// emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`AppleArchiveError`] when AppleArchive reading, extraction safety,
/// filesystem I/O, or cancellation fails.
pub fn run_apple_archive_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<apple_archive_backend::AppleArchiveExtractReport, AppleArchiveError> {
    let total_bytes = match apple_archive_backend::list_apple_archive(&archive_path) {
        Ok(listing) => {
            let total = listing
                .entries
                .iter()
                .filter_map(|entry| entry.size)
                .sum::<u64>();
            Some(total)
        }
        Err(_) => None,
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::AppleArchiveExtract,
        total_bytes,
    });
    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = apple_archive_backend::extract_apple_archive_with_context(
        archive_path,
        destination,
        policy,
        &mut context,
    );
    context.flush_progress();
    finish_apple_archive_extract_result(result, sink)
}

/// Runs a 7z extract job with an optional password and explicit extraction
/// policy while emitting lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// 7z extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`SevenZError`] when 7z reading, password validation, extraction
/// safety, or filesystem I/O fails.
pub fn run_7z_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<sevenz_backend::SevenZExtractReport, SevenZError> {
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(SevenZError::Io {
            path: archive_path.as_ref().to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"),
        });
    }

    let total_bytes = match sevenz_backend::list_7z(&archive_path, password) {
        Ok(listing) => Some(listing.entries.iter().map(|entry| entry.size).sum()),
        Err(_) => None,
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::SevenZExtract,
        total_bytes,
    });

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = sevenz_backend::extract_7z_with_context(
        archive_path,
        destination,
        password,
        policy,
        &mut context,
    );
    context.flush_progress();
    finish_7z_extract_result(result, sink)
}

/// Runs a RAR extract job with an optional password and explicit extraction
/// policy while emitting lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// RAR extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`RarBackendError`] when bundled `UnRAR` reading, password validation,
/// extraction safety, or filesystem I/O fails.
pub fn run_rar_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<rar_backend::RarExtractReport, RarBackendError> {
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(RarBackendError::Io {
            path: archive_path.as_ref().to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"),
        });
    }

    let listing = rar_backend::list_rar_with_password(&archive_path, password).ok();
    let total_bytes = listing
        .as_ref()
        .map(|listing| listing.entries.iter().map(|entry| entry.size).sum());
    sink.emit(JobEvent::Started {
        kind: JobKind::RarExtract,
        total_bytes,
    });

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = if let Some(listing) = listing {
        let entries = listing
            .entries
            .into_iter()
            .map(rar_backend::RarListEntry::into_unrar_entry)
            .collect::<Vec<_>>();
        rar_backend::extract_rar_entries_with_password_and_context(
            archive_path,
            destination,
            policy,
            password,
            entries,
            &mut context,
        )
    } else {
        rar_backend::extract_rar_with_password_and_context(
            archive_path,
            destination,
            policy,
            password,
            &mut context,
        )
    };
    context.flush_progress();
    finish_rar_extract_result(result, sink)
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
    run_libarchive_extract_job_with_password_and_policy(
        archive_path,
        destination,
        None,
        ExtractionPolicy::default(),
        token,
        sink,
    )
}

/// Runs a broad libarchive extract job with an optional password and explicit
/// extraction policy while emitting coarse lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// libarchive extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`LibarchiveError`] when libarchive reading, password validation,
/// extraction safety, or filesystem I/O fails.
pub fn run_libarchive_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<libarchive_backend::LibarchiveExtractReport, LibarchiveError> {
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(LibarchiveError::Io {
            path: archive_path.as_ref().to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"),
        });
    }

    let total_bytes = match libarchive_backend::list_archive_with_password(&archive_path, password)
    {
        Ok(listing) => {
            let mut total = 0_u64;
            let mut has_known_size = false;
            for entry in listing.entries {
                if let Ok(size) = u64::try_from(entry.size) {
                    has_known_size = true;
                    total = total.saturating_add(size);
                }
            }
            has_known_size.then_some(total)
        }
        Err(_) => None,
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::ArchiveExtract,
        total_bytes,
    });

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = libarchive_backend::extract_archive_with_password_and_context(
        archive_path,
        destination,
        policy,
        password,
        &mut context,
    );
    context.flush_progress();
    finish_libarchive_extract_result(result, sink)
}

/// Runs a raw single-file stream extract job with an explicit extraction policy
/// while emitting coarse lifecycle events.
///
/// Partial output state: cancellation is checked before extraction starts, but
/// raw stream extraction itself is synchronous in this v1 adapter.
///
/// # Errors
///
/// Returns [`RawStreamError`] when stream decoding, extraction safety, or
/// filesystem I/O fails.
pub fn run_raw_stream_extract_job_with_policy(
    archive_path: impl AsRef<Path>,
    format: RawStreamFormat,
    destination: impl AsRef<Path>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<raw_stream_backend::RawStreamExtractReport, RawStreamError> {
    let archive_path = archive_path.as_ref();
    let estimated_total_bytes =
        raw_stream_backend::estimate_raw_stream_uncompressed_size(archive_path, format);
    let source_size = archive_path.metadata().ok().map(|metadata| metadata.len());
    let track_source_progress = estimated_total_bytes.is_none()
        && raw_stream_backend::can_track_source_progress(format)
        && source_size.is_some_and(|size| size > 0);
    let total_bytes = if estimated_total_bytes.is_some() {
        estimated_total_bytes
    } else if track_source_progress {
        source_size
    } else {
        None
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::RawStreamExtract,
        total_bytes,
    });
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(RawStreamError::Io {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "job cancelled"),
        });
    }

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let progress_path = archive_path.to_string_lossy().into_owned();
    let result = raw_stream_backend::extract_raw_stream_with_progress(
        archive_path,
        format,
        destination,
        policy,
        Some(&mut |bytes| context.bytes_processed(Some(&progress_path), bytes)),
        track_source_progress,
    );
    context.flush_progress();
    finish_raw_stream_extract_result(result, sink)
}

/// Runs a TZAP extract job with a required password and explicit extraction
/// policy while emitting lifecycle/progress events.
///
/// Partial output state: cancellation can leave already-extracted files in the
/// destination directory.
///
/// # Errors
///
/// Returns [`TzapError`] when the password is missing, TZAP reading,
/// extraction safety, filesystem I/O, or cancellation fails.
pub fn run_tzap_extract_job_with_password_and_policy(
    archive_path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: Option<&str>,
    policy: ExtractionPolicy,
    token: &CancellationToken,
    sink: &mut dyn JobEventSink,
) -> Result<tzap_backend::TzapExtractReport, TzapError> {
    let total_bytes = match password.filter(|password| !password.is_empty()) {
        Some(password) => tzap_backend::list_tzap_index_entries_with_optional_password(
            archive_path.as_ref(),
            Some(password),
        )
        .ok()
        .map(|entries| entries.iter().map(|entry| entry.file_data_size).sum()),
        None => tzap_backend::list_tzap_index_entries_with_optional_password(
            archive_path.as_ref(),
            None,
        )
        .ok()
        .map(|entries| entries.iter().map(|entry| entry.file_data_size).sum()),
    };
    sink.emit(JobEvent::Started {
        kind: JobKind::TzapExtract,
        total_bytes,
    });
    if token.is_cancelled() {
        sink.emit(JobEvent::Cancelled {
            message: "job cancelled".to_owned(),
        });
        return Err(TzapError::Cancelled);
    }

    let mut context = JobContext::new_with_progress_total(token, sink, total_bytes);
    let result = tzap_backend::extract_tzap_with_optional_password_and_context_fast(
        archive_path,
        destination,
        policy,
        password,
        &mut context,
    );
    context.flush_progress();
    finish_tzap_extract_result(result, sink)
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

fn finish_tzap_create_result(
    result: Result<TzapCreateReport, TzapError>,
    sink: &mut dyn JobEventSink,
) -> Result<TzapCreateReport, TzapError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(TzapError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(TzapError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_apple_archive_create_result(
    result: Result<AppleArchiveCreateReport, AppleArchiveError>,
    sink: &mut dyn JobEventSink,
) -> Result<AppleArchiveCreateReport, AppleArchiveError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(AppleArchiveError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(AppleArchiveError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_tzap_extract_result(
    result: Result<tzap_backend::TzapExtractReport, TzapError>,
    sink: &mut dyn JobEventSink,
) -> Result<tzap_backend::TzapExtractReport, TzapError> {
    match result {
        Ok(report) => {
            sink.emit(JobEvent::Completed {
                entries: report.written_entries,
                bytes: report.written_bytes,
            });
            Ok(report)
        }
        Err(TzapError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(TzapError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_apple_archive_extract_result(
    result: Result<apple_archive_backend::AppleArchiveExtractReport, AppleArchiveError>,
    sink: &mut dyn JobEventSink,
) -> Result<apple_archive_backend::AppleArchiveExtractReport, AppleArchiveError> {
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
        Err(AppleArchiveError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(AppleArchiveError::Cancelled)
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

fn finish_7z_extract_result(
    result: Result<sevenz_backend::SevenZExtractReport, SevenZError>,
    sink: &mut dyn JobEventSink,
) -> Result<sevenz_backend::SevenZExtractReport, SevenZError> {
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
        Err(SevenZError::Cancelled) => {
            sink.emit(JobEvent::Cancelled {
                message: "job cancelled".to_owned(),
            });
            Err(SevenZError::Cancelled)
        }
        Err(error) => {
            sink.emit(JobEvent::Failed {
                message: error.to_string(),
            });
            Err(error)
        }
    }
}

fn finish_rar_extract_result(
    result: Result<rar_backend::RarExtractReport, RarBackendError>,
    sink: &mut dyn JobEventSink,
) -> Result<rar_backend::RarExtractReport, RarBackendError> {
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

fn finish_raw_stream_extract_result(
    result: Result<raw_stream_backend::RawStreamExtractReport, RawStreamError>,
    sink: &mut dyn JobEventSink,
) -> Result<raw_stream_backend::RawStreamExtractReport, RawStreamError> {
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
        CancellationToken, JobEvent, JobOutcome, JobPhase, JobProgressState,
        PROGRESS_MIN_BYTE_STEP, ProgressCoalescer,
        run_7z_create_job_from_sources_with_plan_options, run_clean_source_tar_zst_create_job,
        run_clean_source_tar_zst_create_job_from_sources, run_raw_stream_extract_job_with_policy,
        run_tar_zst_create_job, run_tzap_create_job_from_sources_with_plan_options,
        run_tzap_extract_job_with_password_and_policy, run_zip_create_job,
        run_zip_create_job_from_sources, run_zip_extract_job,
    };

    #[test]
    fn progress_projection_is_monotonic_bounded_and_terminal_is_immutable() {
        let mut state = JobProgressState::default();
        state.apply(&JobEvent::Started { kind: super::JobKind::ZipCreate, total_bytes: Some(10) });
        for index in 0..20 {
            state.apply(&JobEvent::BytesProcessed {
                path: Some(format!("file-{index}")), recent_paths: vec![], bytes: 1,
                total_bytes_processed: index + 1,
            });
        }
        state.apply(&JobEvent::Completed { entries: 20, bytes: 20 });
        let terminal = state.clone();
        state.apply(&JobEvent::Failed { message: "late".into() });
        assert_eq!(state, terminal);
        assert_eq!(state.outcome, Some(JobOutcome::Completed));
        assert_eq!(state.processed_bytes, 20);
        assert_eq!(state.recent_paths.len(), super::PROGRESS_RECENT_PATH_LIMIT);
        assert_eq!(state.current_path.as_deref(), Some("file-19"));
    }

    #[test]
    fn progress_projection_resets_only_phase_local_facts() {
        let mut state = JobProgressState::default();
        state.apply(&JobEvent::BytesProcessed { path: None, recent_paths: vec![], bytes: 5, total_bytes_processed: 5 });
        state.apply(&JobEvent::PhaseStarted { phase: JobPhase::PlanningPayload, total_bytes: Some(8) });
        state.apply(&JobEvent::PhaseBytesProcessed { phase: JobPhase::PlanningPayload, path: None, recent_paths: vec![], bytes: 4, total_bytes_processed: 4, total_bytes: Some(8) });
        state.apply(&JobEvent::PhaseStarted { phase: JobPhase::EmittingPayload, total_bytes: Some(8) });
        assert_eq!(state.processed_bytes, 5);
        assert_eq!(state.phase_processed_bytes, 0);
    }
    use crate::archive_browser::list_entries;
    use crate::raw_stream_backend::RawStreamFormat;
    use crate::safety::ExtractionPolicy;
    use crate::sevenz_backend::{SevenZCreateOptions, SevenZError};
    use crate::tar_zst_backend::TarZstdCreateOptions;
    use crate::tzap_backend::{TzapCreateOptions, TzapKeySource};
    use crate::zip_backend::{ZipBackendError, ZipCreateOptions, list_zip};
    use bzip2::Compression;
    use bzip2::write::BzEncoder;
    use std::fs;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn progress_coalescer_uses_one_percent_floor_and_caps_recent_paths() {
        let four_gib = 4 * 1024 * 1024 * 1024u64;
        let one_percent = four_gib.div_ceil(100);
        let mut progress = ProgressCoalescer::new(Some(four_gib));

        let first = progress.record(Some("file-00"), 1).unwrap();
        assert_eq!(first.path.as_deref(), Some("file-00"));
        assert_eq!(first.recent_paths, ["file-00"]);
        assert!(one_percent > PROGRESS_MIN_BYTE_STEP);
        assert!(progress.record(Some("file-01"), one_percent - 1).is_none());
        let one_percent_batch = progress.record(Some("file-02"), 1).unwrap();
        assert_eq!(one_percent_batch.bytes, one_percent);

        for index in 0..12 {
            assert!(
                progress
                    .record(Some(&format!("recent-{index:02}")), 1)
                    .is_none()
            );
        }
        let recent = progress.flush().unwrap();
        assert_eq!(recent.recent_paths.len(), 10);
        assert_eq!(
            recent.recent_paths.first().map(String::as_str),
            Some("recent-02")
        );
        assert_eq!(
            recent.recent_paths.last().map(String::as_str),
            Some("recent-11")
        );
        assert_eq!(recent.path.as_deref(), Some("recent-11"));
    }

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
        assert!(events.iter().any(|event| matches!(
            event,
            JobEvent::BytesProcessed {
                path: Some(path),
                recent_paths,
                bytes: 5,
                ..
            } if path == "project/file.txt"
                && recent_paths == &["project/file.txt".to_owned()]
        )));
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
    fn raw_stream_extract_job_emits_progress_events() {
        let temp = TestDir::new("raw_stream_extract_job_emits_progress_events");
        let archive_path = temp.path("payload.txt.zst");
        {
            let file = fs::File::create(&archive_path).unwrap();
            let mut encoder = zstd::stream::write::Encoder::new(file, 1).unwrap();
            encoder.write_all(b"hello world").unwrap();
            encoder.finish().unwrap();
        }
        let mut events = Vec::new();

        run_raw_stream_extract_job_with_policy(
            &archive_path,
            RawStreamFormat::Zstd,
            temp.path("out"),
            ExtractionPolicy::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert!(matches!(
            events.first(),
            Some(JobEvent::Started {
                kind: super::JobKind::RawStreamExtract,
                total_bytes: Some(_),
            })
        ));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, JobEvent::BytesProcessed { .. }))
        );
    }

    #[test]
    fn raw_stream_extract_progress_tracks_compressed_bytes_for_bz2() {
        let temp = TestDir::new("raw_stream_extract_progress_tracks_compressed_bytes_for_bz2");
        let archive_path = temp.path("payload.txt.bz2");
        {
            let file = fs::File::create(&archive_path).unwrap();
            let mut encoder = BzEncoder::new(file, Compression::best());
            let payload = vec![b'a'; 1_024 * 1_024 * 4];
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        let source_size = fs::metadata(&archive_path).unwrap().len();
        let mut events = Vec::new();

        run_raw_stream_extract_job_with_policy(
            &archive_path,
            RawStreamFormat::Bzip2,
            temp.path("out"),
            ExtractionPolicy::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        let last_progress = events.iter().rev().find_map(|event| {
            if let JobEvent::BytesProcessed {
                total_bytes_processed,
                ..
            } = event
            {
                Some(*total_bytes_processed)
            } else {
                None
            }
        });
        let Some(last_processed_bytes) = last_progress else {
            panic!("expected at least one progress event");
        };

        assert_eq!(
            events.first(),
            Some(&JobEvent::Started {
                kind: super::JobKind::RawStreamExtract,
                total_bytes: Some(source_size),
            })
        );
        assert!(last_processed_bytes <= source_size);
    }

    #[test]
    fn tzap_create_job_emits_phase_progress_through_output_commit() {
        let temp = TestDir::new("tzap_create_job_emits_progress_before_completion_for_large_file");
        let payload = large_tzap_progress_payload();
        temp.write_file("project/payload.bin", &payload);
        let mut events = Vec::new();

        run_tzap_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.tzap"),
            &test_tzap_create_options(),
            &crate::manifest::PlanOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        let phases = events
            .iter()
            .filter_map(|event| match event {
                JobEvent::PhaseStarted { phase, .. } => Some(*phase),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                JobPhase::PlanningPayload,
                JobPhase::PlanningMetadata,
                JobPhase::EmittingPayload,
                JobPhase::EmittingMetadata,
                JobPhase::CommittingOutput,
            ]
        );
        for phase in [JobPhase::PlanningPayload, JobPhase::EmittingPayload] {
            let phase_progress = events
                .iter()
                .filter_map(|event| match event {
                    JobEvent::PhaseBytesProcessed {
                        phase: event_phase,
                        total_bytes_processed,
                        ..
                    } if *event_phase == phase => Some(*total_bytes_processed),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(phase_progress.len() <= 2);
            let final_phase_total = phase_progress.last().copied();
            assert_eq!(final_phase_total, Some(payload.len() as u64));
        }
        assert!(matches!(events.last(), Some(JobEvent::Completed { .. })));
    }

    #[test]
    fn tzap_create_job_emits_entry_finished_during_multi_file_progress() {
        let temp = TestDir::new("tzap_create_job_emits_entry_finished_during_multi_file_progress");
        let payload = large_tzap_progress_payload();
        temp.write_file("project/one.bin", &payload);
        temp.write_file("project/two.bin", &payload);
        let mut events = Vec::new();

        run_tzap_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.tzap"),
            &test_tzap_create_options(),
            &crate::manifest::PlanOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        let first_finished_index = events
            .iter()
            .position(|event| matches!(event, JobEvent::EntryFinished { .. }))
            .expect("expected at least one entry-finished event");

        assert!(
            events
                .iter()
                .skip(first_finished_index + 1)
                .any(|event| matches!(event, JobEvent::BytesProcessed { .. })),
            "expected later byte progress after the first finished entry"
        );
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, JobEvent::PhaseBytesProcessed { path: None, .. }))
        );
    }

    #[test]
    fn tzap_phase_progress_caps_recent_paths_at_ten() {
        let temp = TestDir::new("tzap_phase_progress_caps_recent_paths_at_ten");
        for index in 0..12 {
            temp.write_file(format!("project/file-{index:02}.txt"), b"payload");
        }
        let mut events = Vec::new();

        run_tzap_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.tzap"),
            &test_tzap_create_options(),
            &crate::manifest::PlanOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        let phase_progress = events
            .iter()
            .filter_map(|event| match event {
                JobEvent::PhaseBytesProcessed {
                    path, recent_paths, ..
                } => Some((path, recent_paths)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!phase_progress.is_empty());
        for (path, recent_paths) in phase_progress {
            assert!(!recent_paths.is_empty());
            assert!(recent_paths.len() <= 10);
            assert_eq!(path.as_ref(), recent_paths.last());
        }
    }

    #[test]
    fn sevenz_create_job_emits_progress_before_completion_for_large_file() {
        let temp =
            TestDir::new("sevenz_create_job_emits_progress_before_completion_for_large_file");
        let payload = large_tzap_progress_payload();
        temp.write_file("project/payload.bin", &payload);
        let mut events = Vec::new();

        run_7z_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.7z"),
            &SevenZCreateOptions {
                level: Some(1),
                ..SevenZCreateOptions::default()
            },
            &crate::manifest::PlanOptions::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert_monotonic_progress_reaches_total_before_completion(&events, payload.len() as u64);
    }

    #[test]
    fn sevenz_create_job_can_be_cancelled_during_file_progress() {
        let temp = TestDir::new("sevenz_create_job_can_be_cancelled_during_file_progress");
        let payload = large_tzap_progress_payload();
        temp.write_file("project/payload.bin", &payload);
        let token = CancellationToken::new();
        let token_for_sink = token.clone();
        let mut events = Vec::new();

        let result = run_7z_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.7z"),
            &SevenZCreateOptions {
                level: Some(1),
                ..SevenZCreateOptions::default()
            },
            &crate::manifest::PlanOptions::default(),
            &token,
            &mut |event| {
                if matches!(event, JobEvent::BytesProcessed { .. }) {
                    token_for_sink.cancel();
                }
                events.push(event);
            },
        );

        assert!(matches!(result, Err(SevenZError::Cancelled)));
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
    fn tzap_extract_job_emits_progress_before_completion_for_large_file() {
        let temp = TestDir::new("tzap_extract_job_emits_progress_before_completion_for_large_file");
        let payload = large_tzap_progress_payload();
        temp.write_file("project/payload.bin", &payload);

        run_tzap_create_job_from_sources_with_plan_options(
            &[temp.path("project")],
            temp.path("archive.tzap"),
            &test_tzap_create_options(),
            &crate::manifest::PlanOptions::default(),
            &CancellationToken::new(),
            &mut |_| {},
        )
        .unwrap();

        let mut events = Vec::new();
        run_tzap_extract_job_with_password_and_policy(
            temp.path("archive.tzap"),
            temp.path("out"),
            None,
            ExtractionPolicy::default(),
            &CancellationToken::new(),
            &mut |event| events.push(event),
        )
        .unwrap();

        assert_monotonic_progress_reaches_total_before_completion(&events, payload.len() as u64);
        assert!(events.iter().all(|event| match event {
            JobEvent::BytesProcessed {
                path, recent_paths, ..
            } => path.is_some() && !recent_paths.is_empty(),
            _ => true,
        }));
        assert_eq!(
            fs::read(temp.path("out/project/payload.bin")).unwrap(),
            payload
        );
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
                replace_existing: false,
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
                replace_existing: false,
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
                replace_existing: false,
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

    fn large_tzap_progress_payload() -> Vec<u8> {
        (0..(512 * 1024)).map(|index| (index % 251) as u8).collect()
    }

    fn test_tzap_create_options() -> TzapCreateOptions {
        TzapCreateOptions {
            key_source: TzapKeySource::NoPassword,
            level: 1,
            preserve_metadata: true,
            replace_existing: false,
            volume_size: None,
            recovery_percentage: 0,
            volume_loss_tolerance: 0,
            x509_signing: None,
        }
    }

    fn assert_monotonic_progress_reaches_total_before_completion(
        events: &[JobEvent],
        expected_total: u64,
    ) {
        let progress_totals = progress_totals_before_completion(events);

        assert!(!progress_totals.is_empty());
        assert!(progress_totals.iter().all(|total| *total <= expected_total));
        assert!(
            progress_totals
                .windows(2)
                .all(|window| window[0] <= window[1])
        );
        assert_eq!(progress_totals.last(), Some(&expected_total));
    }

    fn progress_totals_before_completion(events: &[JobEvent]) -> Vec<u64> {
        let completed_index = events
            .iter()
            .position(|event| matches!(event, JobEvent::Completed { .. }))
            .expect("expected completed event");
        events[..completed_index]
            .iter()
            .filter_map(|event| match event {
                JobEvent::BytesProcessed {
                    total_bytes_processed,
                    ..
                } => Some(*total_bytes_processed),
                _ => None,
            })
            .collect()
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
