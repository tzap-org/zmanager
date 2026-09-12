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
