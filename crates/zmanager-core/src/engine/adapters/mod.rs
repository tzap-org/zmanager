//! Archive format adapters for the core engine.

use std::path::Path;

use crate::engine::types::{ArchiveError, EntryId, ErrorKind, ExtractReport, SessionDisposition};
use crate::safety::ExtractionSafetyError;

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
