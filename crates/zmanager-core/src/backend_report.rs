//! Shared result type for native backend operations.
//!
//! Every native backend reports the same four things about an extract, test,
//! or list pass. They previously each declared a structurally identical
//! `*Report` struct, which also meant repeating the `ExtractReport` bridge and
//! the field-by-field conversion into the engine's own report type. The format
//! names are kept as aliases so backend code still reads in its own vocabulary.

/// Normalized native backend operation report.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct BackendReport {
    /// Entries written or verified.
    pub entries: usize,
    /// Entries skipped by selection or policy.
    pub skipped_entries: usize,
    /// Regular-file bytes written or verified.
    pub bytes: u64,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
}

impl crate::extract_loop::ExtractReport for BackendReport {
    fn skipped_entries_mut(&mut self) -> &mut usize {
        &mut self.skipped_entries
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.warnings
    }
}

/// Open a member's source, or record why the archive will not contain it.
///
/// One file the archiver cannot read must not cost the whole archive. GNU tar
/// warns and exits 2, bsdtar warns and exits 1, 7-Zip warns and exits 1 -- all
/// three still write an archive containing everything they could read, and for a
/// combined tool that is the behaviour people already expect. Refusing outright
/// means a backup of a live tree produces nothing because one file had the wrong
/// permissions or was removed while the scan was running.
///
/// Returns `None` when the member should be left out; the reason is already in
/// `warnings` by then, so callers skip the entry and carry on.
pub(crate) fn open_member_source(path: &std::path::Path, warnings: &mut Vec<String>) -> Option<std::fs::File> {
    match std::fs::File::open(path) {
        Ok(file) => Some(file),
        Err(error) => {
            warnings.push(format!("skipped {}: {error}", path.display()));
            None
        }
    }
}
