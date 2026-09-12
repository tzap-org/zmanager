//! Immutable operation registry and engine builder (ARC-104).

use crate::engine::format::FormatId;
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, ArchivePluginRole, CopyReport, CreateReport, CreateRequest, CredentialRequirement, DetectedArchive,
    EntryId, ErrorKind, ExtractOptions, ExtractReport, FormatCapabilities, HandleCapabilities, NavigationMode, OpenOptions, SelectedExtractOptions,
    TestOptions, TestReport,
};
use crate::jobs::JobContext;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;

/// Static metadata descriptor for an archive adapter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AdapterDescriptor {
    /// Opaque name/identifier for the adapter implementation.
    pub name: &'static str,
    /// Supported format identifier.
    pub format: FormatId,
    /// Supported operation set.
    pub operations: &'static [ArchiveOperation],
    /// Required source access capability.
    pub required_source_access: SourceAccess,
    /// Whether encryption is supported by this adapter.
    pub supports_encryption: bool,
}

impl AdapterDescriptor {
    /// Returns the navigation claim for the adapter implementation.
    ///
    /// ZIP sessions retain an indexed archive object and can address arbitrary
    /// retained entries directly. The current native adapters deliberately
    /// retain a stable selector but create a session-owned cursor and scan from
    /// its beginning for selected/copy operations, so their capability must
    /// remain `SequentialScan` even when those operations are registered.
    #[must_use]
    pub fn navigation(&self) -> NavigationMode {
        match self.format {
            FormatId::ZIP | FormatId::SPLIT_ZIP => NavigationMode::RandomAccess,
            _ => NavigationMode::SequentialScan,
        }
    }

    /// Returns the credential claim for this adapter.
    #[must_use]
    pub fn credential_requirement(&self) -> CredentialRequirement {
        if !self.supports_encryption {
            CredentialRequirement::None
        } else if self.format == FormatId::TZAP {
            CredentialRequirement::PasswordOrRecipientKey
        } else {
            CredentialRequirement::Password
        }
    }
}

/// Opened read session retained by one `ArchiveHandle`.
pub trait ReadAdapterSession: Send {
    /// Lists entries from the retained adapter session.
    fn list(&mut self) -> Result<ArchiveListing, ArchiveError>;

    /// Verifies selected entry payloads from the retained session.
    fn test(&mut self, options: &TestOptions) -> Result<TestReport, ArchiveError>;

    /// Extracts the complete archive from the retained session.
    fn extract<'a>(&mut self, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError>;

    /// Extracts one retained physical entry.
    fn selected_extract(&mut self, entry_id: EntryId, options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError>;

    /// Extracts a batch of retained physical entries in one pass when supported.
    fn selected_extract_many(&mut self, entry_ids: &[EntryId], options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        let mut report = ExtractReport::default();
        for &entry_id in entry_ids {
            // `options` is reborrowed per entry rather than copied into a
            // per-entry value: the copy could not carry the caller's event sink
            // or overwrite resolver (both are `&mut` and cannot be duplicated),
            // so a batch silently lost progress reporting and answered every
            // `OverwritePolicy::Ask` conflict with `OverwritePromptUnavailable`.
            let item_report = self.selected_extract(entry_id, options)?;
            report.written_entries = report.written_entries.saturating_add(item_report.written_entries);
            report.skipped_entries = report.skipped_entries.saturating_add(item_report.skipped_entries);
            report.written_bytes = report.written_bytes.saturating_add(item_report.written_bytes);
            report.warnings.extend(item_report.warnings);
        }
        Ok(report)
    }

    /// Copies one retained regular-file entry.
    fn copy_to_writer(&mut self, entry_id: EntryId, writer: &mut dyn Write) -> Result<CopyReport, ArchiveError>;

    /// Releases parser state, indexes, and temporary source resources.
    fn close(&mut self) -> Result<(), ArchiveError> {
        Ok(())
    }
}

/// Abstract factory trait implemented by read archive adapters.
pub trait ReadAdapterFactory: Send + Sync + 'static {
    /// Returns static metadata descriptor for this adapter.
    fn descriptor(&self) -> &'static AdapterDescriptor;

    /// Opens one retained session for the handle.
    fn open(self: Arc<Self>, archive: DetectedArchive, options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError>;
}

/// Abstract factory trait implemented by one-shot archive writers.
pub trait CreateAdapterFactory: Send + Sync {
    /// Returns static metadata descriptor for this writer.
    fn descriptor(&self) -> &'static AdapterDescriptor;

    /// Finalizes and atomically commits one creation request.
    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError>;

    /// Streams one creation request to a caller-owned writer when supported.
    fn create_to_writer(&self, _request: &CreateRequest, _writer: &mut dyn Write, _context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive creator does not support writer output"))
    }
}

/// Immutable registry mapping `(FormatId, ArchiveOperation)` to an adapter factory.
#[derive(Clone)]
pub struct AdapterRegistry {
    registrations: HashMap<(FormatId, ArchiveOperation), Arc<dyn ReadAdapterFactory>>,
    create_registrations: HashMap<FormatId, Arc<dyn CreateAdapterFactory>>,
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("read_registration_count", &self.registrations.len())
            .field("create_registration_count", &self.create_registrations.len())
            .finish()
    }
}

use std::fmt;

impl AdapterRegistry {
    /// Resolves an adapter factory for `(FormatId, ArchiveOperation)` deterministically.
    #[must_use]
    pub fn resolve(&self, format: FormatId, operation: ArchiveOperation) -> Option<Arc<dyn ReadAdapterFactory>> {
        self.registrations.get(&(format, operation)).cloned()
    }

    /// Resolves a one-shot writer for a format.
    #[must_use]
    pub fn resolve_create(&self, format: FormatId) -> Option<Arc<dyn CreateAdapterFactory>> {
        self.create_registrations.get(&format).cloned()
    }

    /// Derives capabilities for a given format from registered adapters.
    #[must_use]
    pub fn capabilities_for_format(&self, format: FormatId) -> Option<HandleCapabilities> {
        let mut ops = Vec::new();
        let mut source_access = SourceAccess::Seekable;
        let mut navigation = NavigationMode::SequentialScan;
        let mut credential_requirement = CredentialRequirement::None;
        let mut encryption = false;
        let mut found = false;
        let mut has_read = false;

        let mut registrations: Vec<_> = self.registrations.iter().filter(|((reg_format, _), _)| *reg_format == format).collect();
        registrations.sort_by_key(|((_, operation), _)| *operation);
        for ((_, op), factory) in registrations {
            found = true;
            has_read = true;
            ops.push(*op);
            let desc = factory.descriptor();
            source_access = desc.required_source_access;
            navigation = desc.navigation();
            credential_requirement = desc.credential_requirement();
            if desc.supports_encryption {
                encryption = true;
            }
        }

        if let Some(factory) = self.create_registrations.get(&format) {
            found = true;
            ops.push(ArchiveOperation::Create);
            if factory.descriptor().supports_encryption {
                encryption = true;
            }
            if !has_read {
                credential_requirement = factory.descriptor().credential_requirement();
            }
        }

        if found {
            Some(HandleCapabilities { format, source_access, navigation, credential_requirement, operations: ops, encryption_supported: encryption })
        } else {
            None
        }
    }

    /// Returns one capability row for every canonical recognized format.
    #[must_use]
    pub fn capability_snapshot(&self) -> Vec<FormatCapabilities> {
        crate::archive_format::FORMAT_CAPABILITIES
            .iter()
            .filter_map(|capability| {
                let format = FormatId::from_archive_format_kind(capability.kind)?;
                let registered = self.capabilities_for_format(format);
                let (platform_available, unavailable_reason) = match crate::archive_format::format_status(capability.kind) {
                    crate::archive_format::BackendStatus::Available => (registered.is_some(), None),
                    crate::archive_format::BackendStatus::UnsupportedPlatform => (false, Some("unsupported platform".to_owned())),
                    crate::archive_format::BackendStatus::Unavailable { reason } => (false, Some(reason.to_owned())),
                };
                let unavailable_reason = unavailable_reason.or_else(|| (!platform_available).then(|| "no registered operation adapter".to_owned()));
                Some(FormatCapabilities {
                    format,
                    recognized: true,
                    platform_available,
                    unavailable_reason,
                    operations: registered.as_ref().map_or_else(Vec::new, |value| value.operations.clone()),
                    source_access: registered.as_ref().map(|value| value.source_access),
                    navigation: registered.as_ref().map(|value| value.navigation),
                    credential_requirement: registered.as_ref().map_or(CredentialRequirement::None, |value| value.credential_requirement),
                    encryption_supported: registered.as_ref().is_some_and(|value| value.encryption_supported),
                    role: registered.as_ref().map(|value| {
                        let has_create = value.operations.contains(&ArchiveOperation::Create);
                        let has_read = value.operations.iter().any(|operation| *operation != ArchiveOperation::Create);
                        match (has_create, has_read) {
                            (true, true) => ArchivePluginRole::Both,
                            (true, false) => ArchivePluginRole::Archive,
                            (false, true | false) => ArchivePluginRole::Extraction,
                        }
                    }),
                })
            })
            .collect()
    }
}

/// Builder for constructing an immutable `AdapterRegistry` (ARC-104).
#[derive(Default)]
pub struct ArchiveEngineBuilder {
    registrations: HashMap<(FormatId, ArchiveOperation), Arc<dyn ReadAdapterFactory>>,
    create_registrations: HashMap<FormatId, Arc<dyn CreateAdapterFactory>>,
}

impl ArchiveEngineBuilder {
    /// Creates a new empty `ArchiveEngineBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a read adapter factory for all operations declared in its descriptor.
    ///
    /// # Errors
    ///
    /// Returns `ArchiveError` if an operation claim for `(FormatId, ArchiveOperation)` is ambiguous / duplicated.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register_read_adapter(&mut self, factory: Arc<dyn ReadAdapterFactory>) -> Result<(), ArchiveError> {
        let desc = factory.descriptor();
        if desc.operations.is_empty() {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Read adapter '{}' must claim at least one operation", desc.name)));
        }
        let mut claimed_operations = HashSet::with_capacity(desc.operations.len());
        for &op in desc.operations {
            if !claimed_operations.insert(op) {
                return Err(ArchiveError::usable(
                    ErrorKind::InvalidFormat,
                    format!("Ambiguous registration: adapter '{}' claims operation '{op:?}' more than once", desc.name),
                ));
            }
            let key = (desc.format, op);
            if self.registrations.contains_key(&key) {
                return Err(ArchiveError::usable(
                    ErrorKind::InvalidFormat,
                    format!("Ambiguous registration: operation '{op:?}' for format '{}' is already claimed", desc.format),
                ));
            }
        }
        if self
            .registrations
            .values()
            .filter(|factory| factory.descriptor().format == desc.format)
            .any(|factory| factory.descriptor().required_source_access != desc.required_source_access)
        {
            return Err(ArchiveError::usable(
                ErrorKind::InvalidFormat,
                format!("Ambiguous registration: source access for format '{}' has conflicting claims", desc.format),
            ));
        }
        if self.registrations.values().filter(|factory| factory.descriptor().format == desc.format).any(|factory| factory.descriptor().name != desc.name) {
            return Err(ArchiveError::usable(
                ErrorKind::InvalidFormat,
                format!("Ambiguous registration: read operations for format '{}' must share one opened session provider", desc.format),
            ));
        }
        if self.registrations.values().filter(|factory| factory.descriptor().format == desc.format).any(|registered| !Arc::ptr_eq(registered, &factory)) {
            return Err(ArchiveError::usable(
                ErrorKind::InvalidFormat,
                format!("Ambiguous registration: read operations for format '{}' must use one factory instance", desc.format),
            ));
        }
        for &op in desc.operations {
            self.registrations.insert((desc.format, op), factory.clone());
        }
        Ok(())
    }

    /// Registers a one-shot writer for the format declared by its descriptor.
    pub fn register_create_adapter(&mut self, factory: Arc<dyn CreateAdapterFactory>) -> Result<(), ArchiveError> {
        let desc = factory.descriptor();
        if !desc.operations.contains(&ArchiveOperation::Create) {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, format!("Creation adapter '{}' does not claim the Create operation", desc.name)));
        }
        if self.create_registrations.contains_key(&desc.format) {
            return Err(ArchiveError::usable(
                ErrorKind::InvalidFormat,
                format!("Ambiguous registration: creation for format '{}' is already claimed", desc.format),
            ));
        }
        self.create_registrations.insert(desc.format, factory);
        Ok(())
    }

    /// Builds the immutable `AdapterRegistry`.
    #[must_use]
    pub fn build(self) -> AdapterRegistry {
        AdapterRegistry { registrations: self.registrations, create_registrations: self.create_registrations }
    }
}
