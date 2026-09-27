//! Shared per-entry extraction protocol for the archive backends.
//!
//! The native extraction backends (zip, tar zstd, Apple Archive,
//! 7z) used to each carry a private copy of the same per-entry skeleton:
//! cancellation checks, progress reporting, archive-root-directory skipping,
//! safety validation, skip-warning emission, and the deferred-directory
//! metadata pass (CR-118, CR-121). This module owns that protocol once.
//! Each backend keeps only what is genuinely its own: iterating its archive
//! reader and materializing entries into filesystem objects.
//!
//! Backends whose readers hand entries one at a time (zip, tar zstd,
//! TAR, Apple Archive, and other streaming readers call [`process_extraction_entry`] from their
//! own iteration loop. The 7z reader is callback-based and plans every entry
//! before any writes, so it calls [`process_planned_entry`] with the
//! pre-computed decision instead.

use crate::jobs::{JobCancelled, JobContext};
use crate::safety::{ExtractionDecision, ExtractionEntry, ExtractionSafetyError, ExtractionSafetyPlanner};
use std::io::{self, Write};
use std::path::Path;

/// The skip-and-warning fields every backend report shares; the shared loop
/// writes them through this trait so skip-warning emission happens in one
/// place. Written-entry/byte counters stay on the concrete reports because
/// backends count them in different orders and conditions.
pub(crate) trait ExtractReport {
    fn skipped_entries_mut(&mut self) -> &mut usize;
    fn warnings_mut(&mut self) -> &mut Vec<String>;
}

macro_rules! extract_report_impl {
    ($report:ty) => {
        impl ExtractReport for $report {
            fn skipped_entries_mut(&mut self) -> &mut usize {
                &mut self.skipped_entries
            }

            fn warnings_mut(&mut self) -> &mut Vec<String> {
                &mut self.warnings
            }
        }
    };
}

extract_report_impl!(crate::apple_archive_backend::AppleArchiveExtractReport);
extract_report_impl!(crate::raw_stream_backend::RawStreamExtractReport);
extract_report_impl!(crate::sevenz_backend::SevenZExtractReport);
extract_report_impl!(crate::zip_backend::ZipExtractReport);

/// A planned write decision, destructured from [`ExtractionDecision::Write`]
/// so backend materialization code never touches the planner's internals.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteDecision<'a> {
    pub destination_path: &'a Path,
    pub replace_existing: bool,
    pub link_target_path: Option<&'a Path>,
}

/// What the shared loop asks the backend to do with the current entry.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EntryAction<'a> {
    /// Discard the entry (policy skip, archive root directory, or another
    /// reason not to materialize it). Backends whose readers need the entry
    /// data consumed before advancing (Apple Archive, 7z) must
    /// skip or drain the data here.
    Skip,
    /// Materialize the entry at the planned destination.
    Write(WriteDecision<'a>),
}

/// Records a skipped entry: increments the counter and emits the warning to
/// both the report and (when present) the job context.
///
/// This is the single skip-warning path — every backend used to inline its
/// own copy, and 7z's copy dropped the `context.warning` call (CR-121).
pub(crate) fn skip_entry<R: ExtractReport>(report: &mut R, context: Option<&mut JobContext<'_>>, warning: impl Into<String>) {
    *report.skipped_entries_mut() += 1;
    let warning = warning.into();
    report.warnings_mut().push(warning.clone());
    if let Some(context) = context {
        context.warning(warning);
    }
}

/// Runs one archive entry through the shared extraction protocol.
///
/// The loop owns: cancellation checks, the archive-root-directory skip
/// (archive root metadata must never be applied to the destination root),
/// the `entry_started`/`entry_finished` progress pair, safety validation,
/// and skip-warning emission. The `materialize` closure performs the
/// backend's actual work for the entry — discard its data or write it —
/// and returns the number of bytes materialized.
pub(crate) fn process_extraction_entry<E, R>(
    report: &mut R,
    mut context: Option<&mut JobContext<'_>>,
    planner: &mut ExtractionSafetyPlanner<'_>,
    safety_entry: &ExtractionEntry,
    materialize: &mut impl FnMut(EntryAction<'_>, &mut R, Option<&mut JobContext<'_>>) -> Result<u64, E>,
) -> Result<u64, E>
where
    E: From<ExtractionSafetyError> + From<JobCancelled>,
    R: ExtractReport,
{
    // The archive root directory entry carries only the root's metadata and
    // has no usable archive path — safety normalization rejects it — so it
    // is skipped before validation. Applying its metadata to the destination
    // root would write archive metadata over the extraction root (and count
    // a spurious entry).
    if crate::extract_materialize::is_archive_root_directory(&safety_entry.archive_path, &safety_entry.kind) {
        materialize(EntryAction::Skip, report, context.as_deref_mut())?;
        skip_entry(report, context, "skipped archive root directory entry");
        return Ok(0);
    }

    process_planned_entry(report, context, safety_entry, planner.validate_entry(safety_entry)?, materialize)
}

/// Like [`process_extraction_entry`], but takes the decision from the caller
/// instead of the planner. The 7z backend uses this: its callback reader
/// plans every entry before any writes so a safety error leaves no partial
/// extraction. Callers must pass entries that already passed safety
/// planning, which rejects archive root directories.
pub(crate) fn process_planned_entry<E, R>(
    report: &mut R,
    mut context: Option<&mut JobContext<'_>>,
    safety_entry: &ExtractionEntry,
    decision: ExtractionDecision,
    materialize: &mut impl FnMut(EntryAction<'_>, &mut R, Option<&mut JobContext<'_>>) -> Result<u64, E>,
) -> Result<u64, E>
where
    E: From<JobCancelled>,
    R: ExtractReport,
{
    if let Some(context) = context.as_deref_mut() {
        context.check_cancelled()?;
    }

    if let Some(context) = context.as_deref_mut() {
        context.entry_started(&safety_entry.archive_path, safety_entry.uncompressed_size);
    }

    let processed = match decision {
        ExtractionDecision::Write { destination_path, replace_existing, link_target_path, .. } => materialize(
            EntryAction::Write(WriteDecision { destination_path: &destination_path, replace_existing, link_target_path: link_target_path.as_deref() }),
            report,
            context.as_deref_mut(),
        )?,
        ExtractionDecision::Skip { reason, .. } => {
            materialize(EntryAction::Skip, report, context.as_deref_mut())?;
            skip_entry(report, context.as_deref_mut(), format!("skipped {}: {reason}", safety_entry.archive_path));
            0
        }
    };

    if let Some(context) = context {
        context.entry_finished(&safety_entry.archive_path, processed);
    }
    Ok(processed)
}

/// Copies an archive entry's data into an atomic output file, checking
/// cancellation and reporting progress per chunk, then commits the file
/// atomically.
///
/// The caller supplies `read` because backends read entry data differently:
/// tar and zip entries implement `io::Read`, while 7z hands the callback a
/// `dyn Read`. The read closure keeps each
/// backend's error type, so read failures surface with the same variant they
/// do today; `io_error` maps filesystem failures into the backend error.
pub(crate) fn copy_file_entry<E>(
    destination_path: &Path,
    replace_existing: bool,
    archive_path: Option<&str>,
    mut context: Option<&mut JobContext<'_>>,
    io_buffer: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    io_error: impl Fn(io::Error, &Path) -> E,
) -> Result<u64, E>
where
    E: From<JobCancelled>,
{
    let mut output = crate::atomic_file::AtomicOutputFile::create(destination_path).map_err(|source| io_error(source, destination_path))?;
    let mut written_bytes = 0_u64;

    loop {
        if let Some(context) = context.as_deref_mut() {
            context.check_cancelled()?;
        }
        let read = read(io_buffer)?;
        if read == 0 {
            break;
        }
        output
            .file_mut()
            .map_err(|source| io_error(source, destination_path))?
            .write_all(&io_buffer[..read])
            .map_err(|source| io_error(source, destination_path))?;
        let read = read as u64;
        written_bytes += read;
        if let Some(context) = context.as_deref_mut() {
            context.bytes_processed(archive_path, read);
        }
    }

    output.commit_with_replace(replace_existing).map_err(|source| io_error(source, destination_path))?;
    Ok(written_bytes)
}

/// Output writer for backends whose readers push entry data into a writer
/// rather than exposing a `Read`: reports written bytes to the job context and
/// stops writing once the job is cancelled. Without a context it only forwards.
///
/// Cancellation is checked before each write, so no bytes land after it, and
/// it surfaces as an [`io::Error`] wrapping [`JobCancelled`] (see
/// [`is_job_cancelled`]). It must never be `ErrorKind::Interrupted`:
/// `write_all` and `io::copy` retry that kind, writing the same buffer again
/// for as long as the job stays cancelled.
pub(crate) struct JobProgressWriter<'a, 'b, W> {
    inner: W,
    context: Option<&'a mut JobContext<'b>>,
    archive_path: &'a str,
}

impl<'a, 'b, W> JobProgressWriter<'a, 'b, W> {
    pub(crate) fn new(inner: W, context: Option<&'a mut JobContext<'b>>, archive_path: &'a str) -> Self {
        Self { inner, context, archive_path }
    }
}

impl<W: Write> Write for JobProgressWriter<'_, '_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(context) = self.context.as_deref_mut() else {
            return self.inner.write(buffer);
        };
        context.check_cancelled().map_err(io::Error::other)?;
        let written = self.inner.write(buffer)?;
        context.bytes_processed(Some(self.archive_path), written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Whether an I/O error is the cancellation raised by [`JobProgressWriter`].
pub(crate) fn is_job_cancelled(error: &io::Error) -> bool {
    error.get_ref().is_some_and(<dyn std::error::Error + Send + Sync>::is::<JobCancelled>)
}

/// Applies metadata to deferred directory entries in reverse archive order,
/// so the deepest directories are stamped before their parents.
///
/// `M` is each backend's per-directory record (a `(path, …)` tuple or a
/// small metadata struct); the backend's `apply` closure destructures it and
/// maps errors into its own error type.
pub(crate) fn apply_deferred_directory_metadata<M, E>(directories: &[M], mut apply: impl FnMut(&M) -> Result<(), E>) -> Result<(), E> {
    for metadata in directories.iter().rev() {
        apply(metadata)?;
    }
    Ok(())
}

/// Error for a hardlink entry whose source member was not resolved by
/// extraction safety planning — an internal invariant, not a user input.
pub(crate) fn unresolved_hardlink_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "hardlink target was not resolved by extraction safety planning")
}

#[cfg(test)]
mod tests {
    use super::{JobProgressWriter, is_job_cancelled};
    use crate::jobs::{CancellationToken, JobContext, JobEvent};
    use std::io::Write;

    #[test]
    fn cancelled_progress_writer_fails_write_all_without_writing() {
        let token = CancellationToken::new();
        token.cancel();
        let mut sink = |_event: JobEvent| {};
        let mut context = JobContext::new(&token, &mut sink);
        let mut output = Vec::new();

        // `write_all` retries `ErrorKind::Interrupted`; a cancellation of that
        // kind would rewrite the buffer forever instead of returning.
        let error = JobProgressWriter::new(&mut output, Some(&mut context), "entry").write_all(b"payload").unwrap_err();

        assert!(is_job_cancelled(&error), "{error}");
        assert!(output.is_empty(), "no bytes may be written once the job is cancelled");
    }

    #[test]
    fn progress_writer_reports_written_bytes() {
        let token = CancellationToken::new();
        let mut processed = 0;
        let mut sink = |event: JobEvent| {
            if let JobEvent::BytesProcessed { total_bytes_processed, .. } = event {
                processed = total_bytes_processed;
            }
        };
        let mut context = JobContext::new(&token, &mut sink);
        let mut output = Vec::new();
        JobProgressWriter::new(&mut output, Some(&mut context), "entry").write_all(b"payload").unwrap();
        context.flush_progress();

        assert_eq!(output, b"payload");
        assert_eq!(processed, 7);
    }
}
