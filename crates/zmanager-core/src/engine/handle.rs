//! Stateful archive handle lifecycle and engine entry points (ARC-105).

use crate::archive_format::detect_archive_format;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterRegistry, ReadAdapterSession};
use crate::engine::source::{ArchiveSource, SourceFingerprint};
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, CreateReport, CreateRequest, DetectedArchive, EntryId, ErrorKind, ExtractOptions,
    ExtractReport, OpenOptions, SelectedExtractOptions, SessionDisposition, TestOptions, TestReport, normalize_engine_path,
};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ENGINE_ENTRY_ID: AtomicU64 = AtomicU64::new(1);

fn discover_related_source_paths(source: &ArchiveSource, format: FormatId) -> Result<Vec<PathBuf>, ArchiveError> {
    // Explicit volume sets are already the caller-owned source contract. Do
    // not rediscover siblings from the final path: doing so would silently
    // widen the source, fingerprint, size limit, and adapter input.
    let ArchiveSource::Path(primary_path) = source else {
        return Ok(Vec::new());
    };
    match format {
        FormatId::SEVEN_Z => crate::sevenz_backend::discover_7z_input_paths(primary_path)
            .map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(primary_path)),
        FormatId::TZAP => Ok(crate::tzap::discover_tzap_input_volume_paths(primary_path)),
        _ => Ok(Vec::new()),
    }
}

fn capture_source_fingerprint(source: &ArchiveSource) -> Result<(FormatId, Vec<PathBuf>, SourceFingerprint), ArchiveError> {
    let primary_path = source.primary_path();
    let kind = detect_archive_format(primary_path);
    let source_exists = primary_path.exists()
        || (matches!(kind, crate::archive_format::ArchiveFormatKind::SevenZ) && crate::sevenz_backend::has_existing_7z_input(primary_path))
        || (matches!(kind, crate::archive_format::ArchiveFormatKind::Tzap) && crate::tzap::has_existing_tzap_input_volume(primary_path));
    if !source_exists {
        return Err(ArchiveError::usable(ErrorKind::Io, format!("Archive path does not exist: {}", primary_path.display())).with_path(primary_path));
    }

    let format_id: Option<FormatId> = kind.into();
    let format = format_id.ok_or_else(|| {
        ArchiveError::usable(ErrorKind::InvalidFormat, format!("Unsupported or unrecognized archive format for {}", primary_path.display()))
            .with_path(primary_path)
    })?;
    let related_source_paths = discover_related_source_paths(source, format)?;
    let source_fingerprint = source
        .fingerprint_with_additional_paths(&related_source_paths)
        .map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(primary_path))?;

    if !source.paths().iter().all(|path| path.exists()) && !matches!(source, ArchiveSource::Path(_)) {
        return Err(ArchiveError::usable(ErrorKind::Io, "One or more explicitly supplied archive volumes do not exist").with_path(primary_path));
    }
    Ok((format, related_source_paths, source_fingerprint))
}

/// The stateful archive engine instance.
#[derive(Clone, Debug)]
pub struct ArchiveEngine {
    registry: AdapterRegistry,
}

impl ArchiveEngine {
    /// Creates a new `ArchiveEngine` wrapping an immutable `AdapterRegistry`.
    #[must_use]
    pub const fn new(registry: AdapterRegistry) -> Self {
        Self { registry }
    }

    /// Accesses the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    /// Returns the immutable operation capability snapshot for this engine.
    #[must_use]
    pub fn capability_snapshot(&self) -> Vec<crate::engine::types::FormatCapabilities> {
        self.registry.capability_snapshot()
    }

    /// Captures the filesystem snapshot used to bind a deferred operation to
    /// an archive source. Format-owned sibling volumes are included, so a
    /// logical path such as `archive.tzap` is bound to the complete source
    /// rather than only to its missing base path.
    pub fn capture_source_fingerprint(&self, source: &ArchiveSource) -> Result<SourceFingerprint, ArchiveError> {
        let (_, _, fingerprint) = capture_source_fingerprint(source)?;
        Ok(fingerprint)
    }

    /// Opens an archive handle for the given source path or volume set (ARC-105).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError`] if format detection fails or no adapter is registered.
    pub fn open(&self, source: ArchiveSource, options: OpenOptions) -> Result<ArchiveHandle, ArchiveError> {
        let primary_path = source.primary_path();
        let (format, related_source_paths, source_fingerprint) = capture_source_fingerprint(&source)?;

        if let Some(max_source_bytes) = options.limits.max_source_bytes
            && let Some(source_bytes) = source
                .length_hint_with_additional_paths(&related_source_paths)
                .map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(primary_path))?
            && source_bytes > max_source_bytes
        {
            return Err(ArchiveError::usable(
                ErrorKind::ResourceLimitExceeded,
                format!("Archive source is {source_bytes} bytes, exceeding the configured {max_source_bytes}-byte open limit"),
            )
            .with_path(primary_path));
        }

        let list_factory = self.registry.resolve(format, ArchiveOperation::List).ok_or_else(|| {
            ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No read adapter registered for format '{format}'")).with_path(primary_path)
        })?;
        let source_access = source.access_capability();
        let required_source_access = list_factory.descriptor().required_source_access;
        if source_access != required_source_access {
            return Err(ArchiveError::usable(
                ErrorKind::UnsupportedOperation,
                format!("Archive source access '{source_access:?}' is incompatible with format '{format}' (requires '{required_source_access:?}')"),
            )
            .with_path(primary_path));
        }

        let detected = DetectedArchive { format, source };

        Ok(ArchiveHandle {
            engine_registry: self.registry.clone(),
            detected,
            options,
            source_fingerprint,
            related_source_paths,
            session: None,
            listing: None,
            entry_ids: HashMap::new(),
            disposition: SessionDisposition::Usable,
        })
    }

    /// Creates and atomically commits one archive through a registered writer.
    ///
    /// Creation is deliberately one-shot and does not open a read session.
    /// The returned report is produced only after the writer has finalized its
    /// output and committed it to the requested destination.
    pub fn create(&self, request: &CreateRequest, context: &mut crate::jobs::JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        if request.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Archive destination must not be empty"));
        }
        let factory = self.registry.resolve_create(request.format()).ok_or_else(|| {
            ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No creation adapter registered for format '{}'", request.format()))
        })?;
        factory.create(request, context)
    }

    /// Streams one creation request through the registered writer adapter.
    pub fn create_to_writer(
        &self,
        request: &CreateRequest,
        writer: &mut dyn Write,
        context: &mut crate::jobs::JobContext<'_>,
    ) -> Result<CreateReport, ArchiveError> {
        let factory = self.registry.resolve_create(request.format()).ok_or_else(|| {
            ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No creation adapter registered for format '{}'", request.format()))
        })?;
        factory.create_to_writer(request, writer, context)
    }
}

/// Stateful handle representing an opened archive session (ARC-105).
pub struct ArchiveHandle {
    engine_registry: AdapterRegistry,
    detected: DetectedArchive,
    options: OpenOptions,
    source_fingerprint: crate::engine::source::SourceFingerprint,
    related_source_paths: Vec<std::path::PathBuf>,
    session: Option<Box<dyn ReadAdapterSession>>,
    listing: Option<ArchiveListing>,
    entry_ids: HashMap<EntryId, EntryId>,
    disposition: SessionDisposition,
}

impl std::fmt::Debug for ArchiveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveHandle").field("detected", &self.detected).field("disposition", &self.disposition).finish_non_exhaustive()
    }
}

impl ArchiveHandle {
    /// Returns the detected archive format and source layout.
    #[must_use]
    pub const fn detected(&self) -> &DetectedArchive {
        &self.detected
    }

    /// Returns the current session disposition (`Usable` or `Unusable`).
    #[must_use]
    pub const fn disposition(&self) -> SessionDisposition {
        self.disposition
    }

    fn validate_source(&mut self) -> Result<(), ArchiveError> {
        let current_related_source_paths = match discover_related_source_paths(&self.detected.source, self.detected.format) {
            Ok(paths) => paths,
            Err(error) => {
                self.disposition = SessionDisposition::Unusable;
                return Err(error.with_path(self.detected.source.primary_path()));
            }
        };
        if current_related_source_paths != self.related_source_paths {
            self.disposition = SessionDisposition::Unusable;
            return Err(ArchiveError::unusable(ErrorKind::SourceChanged, "Archive source volume set changed after this handle was opened")
                .with_path(self.detected.source.primary_path()));
        }
        let matches = match self.detected.source.matches_fingerprint_with_additional_paths(&self.source_fingerprint, &current_related_source_paths) {
            Ok(matches) => matches,
            Err(error) => {
                self.disposition = SessionDisposition::Unusable;
                return Err(ArchiveError::unusable(ErrorKind::Io, error.to_string()).with_path(self.detected.source.primary_path()));
            }
        };
        if !matches {
            self.disposition = SessionDisposition::Unusable;
            return Err(ArchiveError::unusable(ErrorKind::SourceChanged, "Archive source changed after this handle was opened")
                .with_path(self.detected.source.primary_path()));
        }
        Ok(())
    }

    fn finish_operation<T>(&mut self, result: Result<T, ArchiveError>) -> Result<T, ArchiveError> {
        // Native backends may use an owned reopenable cursor during the
        // operation. Validate after both success and failure so a source
        // replacement cannot leave an apparently retryable handle behind.
        let source_validation = self.validate_source();
        self.record_result(&result);
        source_validation?;
        result
    }

    fn session_for(&mut self, operation: ArchiveOperation) -> Result<&mut (dyn ReadAdapterSession + '_), ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        if self.engine_registry.resolve(self.detected.format, operation).is_none() {
            return Err(ArchiveError::usable(
                ErrorKind::UnsupportedOperation,
                format!("No {operation:?} adapter registered for format '{}'", self.detected.format),
            ));
        }
        if self.session.is_none() {
            self.validate_source()?;
            let factory = self.engine_registry.resolve(self.detected.format, operation).ok_or_else(|| {
                ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No {operation:?} adapter registered for format '{}'", self.detected.format))
            })?;
            match factory.open(self.detected.clone(), self.options.clone()) {
                Ok(session) => self.session = Some(session),
                Err(error) => {
                    if error.disposition == SessionDisposition::Unusable {
                        self.disposition = SessionDisposition::Unusable;
                    }
                    return Err(error);
                }
            }
        }
        match self.session.as_deref_mut() {
            Some(session) => Ok(session),
            None => Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive adapter session was not initialized")),
        }
    }

    fn record_result<T>(&mut self, result: &Result<T, ArchiveError>) {
        if result.as_ref().err().is_some_and(|error| error.disposition == SessionDisposition::Unusable) {
            self.disposition = SessionDisposition::Unusable;
        }
    }

    fn normalize_listing(&mut self, mut listing: ArchiveListing) -> Result<ArchiveListing, ArchiveError> {
        self.entry_ids.clear();
        let mut seen_ids = HashSet::with_capacity(listing.entries.len());
        for entry in &mut listing.entries {
            if !seen_ids.insert(entry.id) {
                return Err(ArchiveError::unusable(ErrorKind::CorruptData, format!("Archive adapter returned duplicate entry ID {}", entry.id)));
            }
            let adapter_id = entry.id;
            let engine_id = EntryId(NEXT_ENGINE_ENTRY_ID.fetch_add(1, Ordering::Relaxed));
            self.entry_ids.insert(engine_id, adapter_id);
            entry.id = engine_id;
            if let std::borrow::Cow::Owned(norm) = normalize_engine_path(&entry.path) {
                entry.path = norm;
            }
            if let Some(link_target) = &mut entry.link_target
                && let std::borrow::Cow::Owned(norm) = normalize_engine_path(link_target)
            {
                *link_target = norm;
            }
        }
        Ok(listing)
    }

    fn require_listed_entry(&self, entry_id: EntryId) -> Result<EntryId, ArchiveError> {
        self.entry_ids
            .get(&entry_id)
            .copied()
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("Entry ID {entry_id} is not present in this handle listing")))
    }

    /// Lists archive entries using the bound adapter (ARC-105, ARC-108).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError`] if the session is unusable or listing fails.
    pub fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
        if let Some(listing) = self.listing.clone() {
            self.validate_source()?;
            return Ok(listing);
        }
        let result = {
            let session = self.session_for(ArchiveOperation::List)?;
            session.list()
        };
        let result = result.and_then(|listing| self.normalize_listing(listing));
        let result = self.finish_operation(result);
        if let Ok(listing) = &result {
            self.listing = Some(listing.clone());
        }
        result
    }

    /// Verifies archive data using the adapter bound to this session.
    pub fn test(&mut self, options: &TestOptions) -> Result<TestReport, ArchiveError> {
        if options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive test was cancelled"));
        }
        let result = {
            let session = self.session_for(ArchiveOperation::Test)?;
            session.test(options)
        };
        self.finish_operation(result)
    }

    /// Extracts the complete archive using the adapter bound to this session.
    pub fn extract<'a>(&mut self, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        if options.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Extraction destination must not be empty"));
        }
        if options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive extraction was cancelled"));
        }

        // Keep credentials bound to the opened session available to the
        // normalized extraction request without borrowing the handle while an
        // overwrite resolver is active.
        if options.recipient_key.is_none() {
            options.recipient_key.clone_from(&self.options.recipient_key);
        }
        if options.recipient_key_bytes.is_none() {
            options.recipient_key_bytes.clone_from(&self.options.recipient_key_bytes);
        }
        if options.tzap_password.is_none() {
            options.tzap_password.clone_from(&self.options.password);
        }

        let result = {
            let session = self.session_for(ArchiveOperation::Extract)?;
            session.extract(options)
        };
        self.finish_operation(result)
    }

    /// Extracts one retained entry by its session-scoped ID.
    pub fn extract_selected(&mut self, entry_id: EntryId, options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        let adapter_entry_id = self.require_listed_entry(entry_id)?;
        if options.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Extraction destination must not be empty"));
        }
        if options.cancellation.as_ref().is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive extraction was cancelled"));
        }
        let result = {
            let session = self.session_for(ArchiveOperation::SelectedExtract)?;
            session.selected_extract(adapter_entry_id, options)
        };
        self.finish_operation(result)
    }

    /// Extracts a batch of retained entries by their session-scoped IDs.
    ///
    /// Formats whose reader can select many members from one traversal do
    /// this in a single pass; the rest fall back to extracting each entry in
    /// turn. Either way the caller's event sink and overwrite resolver stay
    /// live for the whole batch.
    pub fn extract_selected_many(&mut self, entry_ids: &[EntryId], options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        let mut adapter_entry_ids = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            adapter_entry_ids.push(self.require_listed_entry(entry_id)?);
        }
        if options.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Extraction destination must not be empty"));
        }
        if options.cancellation.as_ref().is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive extraction was cancelled"));
        }
        let result = {
            let session = self.session_for(ArchiveOperation::SelectedExtract)?;
            session.selected_extract_many(&adapter_entry_ids, options)
        };
        self.finish_operation(result)
    }

    /// Copies one retained regular-file entry to a caller-owned writer.
    pub fn copy_entry(&mut self, entry_id: EntryId, writer: &mut dyn Write) -> Result<CopyReport, ArchiveError> {
        let adapter_entry_id = self.require_listed_entry(entry_id)?;
        let result = {
            let session = self.session_for(ArchiveOperation::CopyToWriter)?;
            session.copy_to_writer(adapter_entry_id, writer)
        };
        self.finish_operation(result)
    }

    /// Consumes the handle and explicitly closes the archive session (ARC-105).
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` on clean close or `ArchiveError` on cleanup failure.
    pub fn close(mut self) -> Result<(), ArchiveError> {
        self.close_session()
    }

    fn close_session(&mut self) -> Result<(), ArchiveError> {
        if let Some(mut session) = self.session.take() {
            session.close()?;
        }
        Ok(())
    }
}

impl Drop for ArchiveHandle {
    fn drop(&mut self) {
        let _ = self.close_session();
    }
}

#[cfg(test)]
mod tests {
    use super::discover_related_source_paths;
    use crate::engine::format::FormatId;
    use crate::engine::source::ArchiveSource;

    #[test]
    fn explicit_volume_sets_are_not_widened_by_format_discovery() {
        let source = ArchiveSource::VolumeSet(vec!["archive.vol000.tzap".into(), "archive.vol001.tzap".into()]);

        assert!(discover_related_source_paths(&source, FormatId::TZAP).unwrap().is_empty());
        assert!(discover_related_source_paths(&source, FormatId::SEVEN_Z).unwrap().is_empty());
    }
}
