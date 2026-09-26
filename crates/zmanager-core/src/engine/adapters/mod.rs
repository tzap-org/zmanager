//! Archive format adapters for the core engine.

use std::path::Path;

use crate::engine::types::{ArchiveError, EntryId, ErrorKind, ExtractReport, SelectedExtractOptions, SessionDisposition};
use crate::jobs::{JobEvent, JobEventSink};
use crate::safety::{ExtractionSafetyError, OverwriteResolver, ReborrowedResolver};

/// Converts a listing position to the session-scoped engine `EntryId`.
///
/// Listing positions are `usize`. On the 32/64-bit targets `ZManager` supports
/// the conversion cannot overflow, and any duplicate identity — including a
/// hypothetical truncation collision — is rejected by the duplicate-id guard
/// in `ArchiveHandle::normalize_listing` before a listing is exposed.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn listing_entry_id(index: usize) -> EntryId {
    EntryId(index as u64)
}

/// Forwards the events of consecutive per-entry job contexts as one job.
///
/// Every job context starts its cumulative `total_*_processed` counters at
/// zero, so a batch run as one context per entry would report totals that
/// restart on every entry. This adds the finished entries' totals back in.
struct BatchProgressSink<'s, 'sink> {
    inner: &'s mut (dyn JobEventSink + 'sink),
    finished_bytes: u64,
    finished_entries: u64,
    current_bytes: u64,
    current_entries: u64,
}

impl<'s, 'sink> BatchProgressSink<'s, 'sink> {
    fn new(inner: &'s mut (dyn JobEventSink + 'sink)) -> Self {
        Self { inner, finished_bytes: 0, finished_entries: 0, current_bytes: 0, current_entries: 0 }
    }

    /// Folds the entry that just finished into the batch totals.
    fn finish_entry(&mut self) {
        self.finished_bytes = self.finished_bytes.saturating_add(std::mem::take(&mut self.current_bytes));
        self.finished_entries = self.finished_entries.saturating_add(std::mem::take(&mut self.current_entries));
    }
}

impl JobEventSink for BatchProgressSink<'_, '_> {
    fn emit(&mut self, mut event: JobEvent) {
        if let JobEvent::BytesProcessed { total_bytes_processed, total_entries_processed, .. } = &mut event {
            self.current_bytes = *total_bytes_processed;
            self.current_entries = *total_entries_processed;
            *total_bytes_processed = total_bytes_processed.saturating_add(self.finished_bytes);
            *total_entries_processed = total_entries_processed.saturating_add(self.finished_entries);
        }
        self.inner.emit(event);
    }
}

/// Extracts `entry_ids` one at a time through `extract_one`, as one job.
///
/// This is the fallback for adapters that cannot extract a selection in a
/// single pass. Each entry receives the caller's event sink (with cumulative
/// progress totals carried across entries) and overwrite resolver.
pub(crate) fn selected_extract_each(
    entry_ids: &[EntryId],
    options: &mut SelectedExtractOptions<'_>,
    mut extract_one: impl FnMut(EntryId, &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError>,
) -> Result<ExtractReport, ArchiveError> {
    let SelectedExtractOptions { destination, policy, tzap_restore_options, cancellation, event_sink, overwrite_resolver } = options;
    let mut batch_sink = event_sink.as_deref_mut().map(BatchProgressSink::new);
    let mut report = ExtractReport::default();
    for &entry_id in entry_ids {
        let mut resolver = overwrite_resolver.as_deref_mut().map(ReborrowedResolver::new);
        let mut entry_options = SelectedExtractOptions {
            destination: destination.clone(),
            policy: policy.clone(),
            tzap_restore_options: *tzap_restore_options,
            cancellation: cancellation.clone(),
            event_sink: batch_sink.as_mut().map(|sink| sink as &mut dyn JobEventSink),
            overwrite_resolver: resolver.as_mut().map(|resolver| resolver as &mut dyn OverwriteResolver),
        };
        let item_report = extract_one(entry_id, &mut entry_options)?;
        if let Some(sink) = batch_sink.as_mut() {
            sink.finish_entry();
        }
        report.written_entries = report.written_entries.saturating_add(item_report.written_entries);
        report.skipped_entries = report.skipped_entries.saturating_add(item_report.skipped_entries);
        report.written_bytes = report.written_bytes.saturating_add(item_report.written_bytes);
        report.warnings.extend(item_report.warnings);
    }
    Ok(report)
}

impl From<crate::backend_impl::backend_report::BackendReport> for ExtractReport {
    fn from(report: crate::backend_impl::backend_report::BackendReport) -> Self {
        extract_report(report.entries, report.skipped_entries, report.bytes, report.warnings)
    }
}

pub(crate) fn extract_report(written_entries: usize, skipped_entries: usize, written_bytes: u64, warnings: Vec<String>) -> ExtractReport {
    ExtractReport {
        written_entries: u64::try_from(written_entries).unwrap_or(u64::MAX),
        skipped_entries: u64::try_from(skipped_entries).unwrap_or(u64::MAX),
        written_bytes,
        warnings,
    }
}

/// Builds an `ArchiveError` for a backend failure with the engine's single
/// session-disposition rule: corruption or source mutation poisons the
/// session (`Unusable`); every other kind — transient I/O, safety
/// rejection, wrong credentials, caller errors — keeps the session usable.
///
/// All adapter error mappers must funnel through this helper so the rule has
/// exactly one implementation. Only `ArchiveHandle` source-validation paths
/// construct errors directly, because those always mark the session
/// unusable by definition.
pub(crate) fn adapter_error(path: &Path, kind: ErrorKind, message: impl Into<String>) -> ArchiveError {
    ArchiveError {
        kind,
        message: message.into(),
        disposition: if matches!(kind, ErrorKind::CorruptData | ErrorKind::SourceChanged) { SessionDisposition::Unusable } else { SessionDisposition::Usable },
        path: Some(path.to_path_buf()),
    }
}

pub(crate) fn safety_error_kind(error: &ExtractionSafetyError) -> ErrorKind {
    match error {
        ExtractionSafetyError::ExpandedSizeLimitExceeded { .. }
        | ExtractionSafetyError::ExpansionRatioLimitExceeded { .. }
        | ExtractionSafetyError::EntryCountLimitExceeded { .. } => ErrorKind::ResourceLimitExceeded,
        _ => ErrorKind::SafetyViolation,
    }
}

pub mod create;
pub mod native;
pub mod zip;

#[cfg(test)]
mod tests {
    use super::selected_extract_each;
    use crate::engine::types::{EntryId, ExtractReport, SelectedExtractOptions};
    use crate::jobs::{CancellationToken, JobContext, JobEvent};

    #[test]
    fn selected_extract_each_carries_progress_totals_across_entries() {
        let mut totals = Vec::new();
        let mut sink = |event| {
            if let JobEvent::BytesProcessed { total_bytes_processed, total_entries_processed, .. } = event {
                totals.push((total_bytes_processed, total_entries_processed));
            }
        };
        let mut options = SelectedExtractOptions { event_sink: Some(&mut sink), ..Default::default() };

        // Each entry runs in its own job context, as the per-entry fallback
        // adapters do, so each one's own totals start again at zero.
        selected_extract_each(&[EntryId(0), EntryId(1), EntryId(2)], &mut options, |_, entry_options| {
            let token = CancellationToken::new();
            let mut context = JobContext::new(&token, entry_options.event_sink.as_deref_mut().expect("the caller's sink reaches every entry"));
            context.bytes_processed(Some("file"), 10);
            context.entry_finished("file", 10);
            context.flush_progress();
            Ok(ExtractReport::default())
        })
        .unwrap();

        assert!(totals.windows(2).all(|pair| pair[0].0 <= pair[1].0 && pair[0].1 <= pair[1].1), "totals must never go backwards: {totals:?}");
        assert_eq!(totals.last(), Some(&(30, 3)));
    }
}
