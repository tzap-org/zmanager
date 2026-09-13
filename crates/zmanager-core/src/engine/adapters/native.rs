//! Native listing adapters for 7z, TAR.ZST, TZAP, RAR, `RawStreams`, Apple Archive, DMG, PKG, MSI, `VirtualDisks` (ARC-200).

use flate2::read::GzDecoder;
use std::cell::{Cell, OnceCell};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write as _};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apple_archive_backend;
use crate::apple_dmg_backend;
use crate::apple_pkg_backend;
use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory, ReadAdapterSession};
use crate::engine::source::{SourceAccess, SourceCursorFactory};
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, OpenOptions,
    SelectedExtractOptions, TestOptions, TestReport,
};
use crate::jobs::{CancellationToken, JobContext, JobEventSink};
use crate::msi_backend;
use crate::rar_backend;
use crate::raw_stream_backend;
use crate::sevenz_backend;
use crate::tzap;
use crate::virtual_disk_backend;

fn with_job_context<R>(
    cancellation: Option<&CancellationToken>,
    event_sink: Option<&mut (dyn JobEventSink + '_)>,
    f: impl FnOnce(&mut JobContext<'_>) -> R,
) -> R {
    let dummy_token = CancellationToken::new();
    let token = cancellation.unwrap_or(&dummy_token);
    let mut noop_sink = |_| {};
    let sink: &mut dyn JobEventSink = match event_sink {
        Some(s) => s,
        None => &mut noop_sink,
    };
    let mut context = JobContext::new(token, sink);
    f(&mut context)
}

/// Immutable context shared by every operation in one native read session.
///
/// The context is deliberately the only source/options value an adapter
/// receives. This keeps source ownership and cursor creation at the session
/// seam while allowing adapters to retain format-specific parser state later.
struct NativeReadContext {
    options: OpenOptions,
    cursor_factory: SourceCursorFactory,
    retained_entries: Vec<NativeEntrySelector>,
    retained_entry_indexes: HashMap<EntryId, usize>,
    selected_entry: Cell<Option<EntryId>>,
    /// Payload decoded once per session for formats whose container is a
    /// non-seekable compressed stream. Decoding is proportional to the whole
    /// archive, so re-running it per operation (or, worse, per selected entry)
    /// turns a batch into repeated full-archive decompressions. The decoded
    /// directory is retained for the session lifetime so every later operation
    /// reuses it.
    decoded_payload: OnceCell<DecodedPayload>,
}

/// A session-scoped decoded payload plus the temporary directory that owns it.
/// Dropping the session drops `_temporary`, which removes the decoded bytes.
struct DecodedPayload {
    _temporary: Option<crate::temp_names::TemporaryDirectory>,
    path: std::path::PathBuf,
}

/// Physical identity retained from the adapter's listing for one engine
/// session. Path and occurrence are stable enough to select the same physical
/// record when a legacy reader must create a fresh cursor from the session
/// source capability.
#[derive(Debug, Clone, Eq, PartialEq)]
struct NativeEntrySelector {
    id: EntryId,
    path: String,
    kind: BrowserEntryKind,
    occurrence: usize,
}

impl NativeReadContext {
    fn new(cursor_factory: SourceCursorFactory, options: OpenOptions) -> Self {
        Self {
            options,
            cursor_factory,
            retained_entries: Vec::new(),
            retained_entry_indexes: HashMap::new(),
            selected_entry: Cell::new(None),
            decoded_payload: OnceCell::new(),
        }
    }

    fn from_factory(cursor_factory: SourceCursorFactory, options: OpenOptions) -> Self {
        Self::new(cursor_factory, options)
    }

    fn retain_listing(&mut self, listing: &ArchiveListing) {
        let mut occurrences = HashMap::<String, usize>::new();
        self.retained_entries = listing
            .entries
            .iter()
            .map(|entry| {
                let occurrence = occurrences.entry(entry.path.clone()).or_insert(0_usize);
                let selector = NativeEntrySelector { id: entry.id, path: entry.path.clone(), kind: entry.kind, occurrence: *occurrence };
                *occurrence = occurrence.saturating_add(1);
                selector
            })
            .collect();
        self.retained_entry_indexes = self.retained_entries.iter().enumerate().map(|(index, entry)| (entry.id, index)).collect();
    }

    fn set_selected_entry(&self, entry_id: EntryId) {
        self.selected_entry.set(Some(entry_id));
    }

    fn retained_entry(&self, entry_id: EntryId) -> Result<&NativeEntrySelector, ArchiveError> {
        self.retained_entry_indexes
            .get(&entry_id)
            .and_then(|index| self.retained_entries.get(*index))
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("Entry ID {entry_id} is not present in the native session listing")))
    }

    fn selected_entry_selector(&self, entry_id: EntryId) -> Result<&NativeEntrySelector, ArchiveError> {
        debug_assert_eq!(self.selected_entry.get(), Some(entry_id));
        self.retained_entry(entry_id)
    }

    fn primary_path(&self) -> &std::path::Path {
        self.cursor_factory.source().primary_path()
    }

    fn options(&self) -> &OpenOptions {
        &self.options
    }

    fn open_primary_file(&self) -> Result<File, ArchiveError> {
        let path = self.primary_path();
        self.cursor_factory.open_primary_file().map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))
    }
}

/// The operation implementation owned by a native archive session.
///
/// Native backends expose format-specific readers with different ownership
/// models. This private seam keeps those details behind one retained engine
/// session. The session context owns the source and credentials; a backend may
/// request a fresh cursor from that context for an individual sequential pass
/// when its parser cannot be retained, but the engine never re-resolves an
/// adapter or bypasses the session.
trait NativeReadAdapter: Send + Sync + 'static {
    fn descriptor(&self) -> &'static AdapterDescriptor;

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError>;

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let _ = (archive, test_options);
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive verification is not supported for this archive format"))
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let _ = (archive, options);
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "full extraction is not supported for this archive format"))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let _ = (archive, entry_id, options);
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "selected extraction is not supported for this archive format"))
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut report = ExtractReport::default();
        for &entry_id in entry_ids {
            // This calls the adapter method directly, bypassing the session
            // wrapper that normally records the selection, so the per-entry
            // invariant `selected_entry_selector` asserts has to be maintained
            // here.
            archive.set_selected_entry(entry_id);
            // See `ReadAdapterSession::selected_extract_many`: reborrowing the
            // caller's options keeps the event sink and overwrite resolver live
            // for every entry in the batch.
            let item_report = self.selected_extract(archive, entry_id, options)?;
            report.written_entries = report.written_entries.saturating_add(item_report.written_entries);
            report.skipped_entries = report.skipped_entries.saturating_add(item_report.skipped_entries);
            report.written_bytes = report.written_bytes.saturating_add(item_report.written_bytes);
            report.warnings.extend(item_report.warnings);
        }
        Ok(report)
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let _ = (archive, entry_id, writer);
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "writer copy is not supported for this archive format"))
    }
}

/// A retained native session that owns its adapter, source context, and
/// cursor factory for its entire lifetime. Legacy native readers that accept
/// paths are invoked only with the path exposed by this context; they never
/// rediscover or receive source paths from callers.
struct NativeReadSession<T: NativeReadAdapter> {
    adapter: Arc<T>,
    context: NativeReadContext,
    closed: bool,
}

impl<T: NativeReadAdapter> NativeReadSession<T> {
    fn ensure_open(&self) -> Result<(), ArchiveError> {
        if self.closed { Err(ArchiveError::unusable(ErrorKind::UnsupportedOperation, "archive session is already closed")) } else { Ok(()) }
    }
}

impl<T: NativeReadAdapter> ReadAdapterSession for NativeReadSession<T> {
    fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
        self.ensure_open()?;
        let listing = self.adapter.list(&self.context)?;
        self.context.retain_listing(&listing);
        Ok(listing)
    }

    fn test(&mut self, options: &TestOptions) -> Result<TestReport, ArchiveError> {
        self.ensure_open()?;
        self.adapter.test(&self.context, options)
    }

    fn extract<'a>(&mut self, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        self.ensure_open()?;
        self.adapter.extract(&self.context, options)
    }

    fn selected_extract(&mut self, entry_id: EntryId, options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        self.ensure_open()?;
        self.context.set_selected_entry(entry_id);
        self.adapter.selected_extract(&self.context, entry_id, options)
    }

    fn selected_extract_many(&mut self, entry_ids: &[EntryId], options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        self.ensure_open()?;
        self.adapter.selected_extract_many(&self.context, entry_ids, options)
    }

    fn copy_to_writer(&mut self, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        self.ensure_open()?;
        self.context.set_selected_entry(entry_id);
        self.adapter.copy_to_writer(&self.context, entry_id, writer)
    }

    fn close(&mut self) -> Result<(), ArchiveError> {
        self.closed = true;
        Ok(())
    }
}

impl<T: NativeReadAdapter> ReadAdapterFactory for T {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        NativeReadAdapter::descriptor(self)
    }

    fn open(self: Arc<Self>, archive: DetectedArchive, options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
        let cursor_factory = archive.source.cursor_factory();
        Ok(Box::new(NativeReadSession { adapter: self, context: NativeReadContext::from_factory(cursor_factory, options), closed: false }))
    }
}

// --- GZIP (TAR.GZ) ---
static TAR_GZ_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_gz_lister",
    format: FormatId::TAR_GZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_adapter",
    format: FormatId::TAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native TAR.GZ listing and extraction adapter.
#[derive(Debug, Default)]
pub struct TarGzListAdapter;

impl NativeReadAdapter for TarGzListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_GZ_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let entries =
            crate::tar_backend::list_with_temp_root(decoder, path, archive.options().temp_root.as_deref()).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "gzip") })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let report = crate::tar_backend::test_with_temp_root(
            decoder,
            path,
            |entry_path| test_options.selects(entry_path),
            || test_options.is_cancelled(),
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                options.overwrite_resolver.as_deref_mut(),
                None,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_path_occurrence_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut selectors = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let selector = archive.retained_entry(entry_id)?;
            selectors.push(crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence });
        }
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_selectors_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                &selectors,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let decoder = GzDecoder::new(file);
        let written_bytes = crate::tar_backend::copy_by_path_occurrence_with_temp_root(
            decoder,
            path,
            crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
            writer,
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

/// Native plain TAR adapter factory.
#[derive(Debug, Default)]
pub struct TarListAdapter;

impl NativeReadAdapter for TarListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let entries = crate::tar_backend::list_with_temp_root(file, path, archive.options().temp_root.as_deref()).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "tar") })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let report = crate::tar_backend::test_with_temp_root(
            file,
            path,
            |entry_path| test_options.selects(entry_path),
            || test_options.is_cancelled(),
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_with_temp_root(
                file,
                path,
                &options.destination,
                options.policy.clone(),
                options.overwrite_resolver.as_deref_mut(),
                None,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_path_occurrence_with_temp_root(
                file,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut selectors = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let selector = archive.retained_entry(entry_id)?;
            selectors.push(crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence });
        }
        let file = archive.open_primary_file()?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_selectors_with_temp_root(
                file,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                &selectors,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let written_bytes = crate::tar_backend::copy_by_path_occurrence_with_temp_root(
            file,
            path,
            crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
            writer,
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_tar_entries(entries: Vec<crate::tar_backend::TarEntry>, method: &str) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: entry.size,
            compressed_size: None,
            modified: entry.modified,
            mode: entry.mode,
            encrypted: Some(false),
            method: Some(method.to_owned()),
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn tar_error(path: &std::path::Path, error: &crate::tar_backend::TarError) -> ArchiveError {
    let kind = match error {
        crate::tar_backend::TarError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::tar_backend::TarError::Cancelled => ErrorKind::Cancelled,
        crate::tar_backend::TarError::Io { .. } => ErrorKind::Io,
        crate::tar_backend::TarError::MissingLinkTarget { .. } => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

static AR_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_ar_adapter",
    format: FormatId::AR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CPIO_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cpio_adapter",
    format: FormatId::CPIO,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static DEB_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_deb_adapter",
    format: FormatId::DEB,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static RPM_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rpm_adapter",
    format: FormatId::RPM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CAB_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cab_adapter",
    format: FormatId::CAB,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static XAR_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_xar_adapter",
    format: FormatId::XAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static LHA_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_lha_adapter",
    format: FormatId::LHA,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static WARC_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_warc_adapter",
    format: FormatId::WARC,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static MTREE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_mtree_adapter",
    format: FormatId::MTREE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native Debian package adapter composing AR with the registered payload engines.
#[derive(Debug, Default)]
pub struct DebListAdapter;

impl NativeReadAdapter for DebListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &DEB_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::ar_backend::list(path).map_err(|error| ar_error(path, &error))?;
        crate::deb_backend::validate_member_layout(path, &entries).map_err(|error| deb_error(path, &error))?;
        Ok(ArchiveListing { entries: map_ar_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::ar_backend::list(path).map_err(|error| ar_error(path, &error))?;
        crate::deb_backend::validate_member_layout(path, &entries).map_err(|error| deb_error(path, &error))?;
        let report = crate::ar_backend::test(path, test_options).map_err(|error| ar_error(path, &error))?;
        crate::deb_backend::test_payload_members(path, &entries, test_options).map_err(|error| deb_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            crate::deb_backend::extract_deb_nested_with_overwrite_resolver(path, &options.destination, &options.policy, resolver)
        } else {
            crate::deb_backend::extract_deb_nested(path, &options.destination, &options.policy)
        }
        .map_err(|error| deb_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::ar_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| ar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn deb_error(path: &std::path::Path, error: &crate::deb_backend::DebError) -> ArchiveError {
    let kind = match error {
        crate::deb_backend::DebError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::deb_backend::DebError::Engine(source) => source.kind,
        crate::deb_backend::DebError::Ar(source) => match source {
            crate::ar_backend::ArError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::ar_backend::ArError::Cancelled => ErrorKind::Cancelled,
            crate::ar_backend::ArError::Io { .. } => ErrorKind::Io,
            crate::ar_backend::ArError::Invalid { .. } => ErrorKind::CorruptData,
        },
        crate::deb_backend::DebError::Tar(source) => match source {
            crate::tar_backend::TarError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::tar_backend::TarError::Cancelled => ErrorKind::Cancelled,
            crate::tar_backend::TarError::Io { .. } => ErrorKind::Io,
            crate::tar_backend::TarError::MissingLinkTarget { .. } => ErrorKind::CorruptData,
        },
        crate::deb_backend::DebError::RawStream(source) => match source {
            crate::raw_stream_backend::RawStreamError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::raw_stream_backend::RawStreamError::Io { .. } => ErrorKind::Io,
            crate::raw_stream_backend::RawStreamError::MissingOutputName { .. } => ErrorKind::CorruptData,
        },
        crate::deb_backend::DebError::Io { .. } => ErrorKind::Io,
        crate::deb_backend::DebError::MissingMember { .. } => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native RPM container adapter composing the bounded RPM reader with CPIO.
#[derive(Debug, Default)]
pub struct RpmListAdapter;

impl NativeReadAdapter for RpmListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RPM_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::rpm_backend::list(path).map_err(|error| rpm_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cpio_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::rpm_backend::test(path, test_options).map_err(|error| rpm_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::rpm_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| rpm_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::rpm_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| rpm_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn rpm_error(path: &std::path::Path, error: &crate::rpm_backend::RpmError) -> ArchiveError {
    let kind = match error {
        crate::rpm_backend::RpmError::Io { .. } => ErrorKind::Io,
        crate::rpm_backend::RpmError::Invalid { .. } => ErrorKind::CorruptData,
        crate::rpm_backend::RpmError::Cpio(source) => match source {
            crate::cpio_backend::CpioError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::cpio_backend::CpioError::Cancelled => ErrorKind::Cancelled,
            crate::cpio_backend::CpioError::Io { .. } => ErrorKind::Io,
            crate::cpio_backend::CpioError::Invalid { .. } => ErrorKind::CorruptData,
        },
        crate::rpm_backend::RpmError::RawStream(source) => match source {
            crate::raw_stream_backend::RawStreamError::Safety(safety) => crate::engine::adapters::safety_error_kind(safety),
            crate::raw_stream_backend::RawStreamError::Io { .. } => ErrorKind::Io,
            crate::raw_stream_backend::RawStreamError::MissingOutputName { .. } => ErrorKind::CorruptData,
        },
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native single-cabinet adapter backed by the maintained CAB reader.
#[derive(Debug, Default)]
pub struct CabListAdapter;

impl NativeReadAdapter for CabListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &CAB_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::cab_backend::list(path).map_err(|error| cab_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cab_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::cab_backend::test(path, test_options).map_err(|error| cab_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::cab_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| cab_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::cab_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| cab_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_cab_entries(entries: Vec<crate::cab_backend::CabEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: BrowserEntryKind::File,
            size: Some(entry.size),
            compressed_size: None,
            modified: entry.modified,
            mode: Some(entry.mode),
            encrypted: Some(false),
            method: Some("cab".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn cab_error(path: &std::path::Path, error: &crate::cab_backend::CabError) -> ArchiveError {
    let kind = match error {
        crate::cab_backend::CabError::Io { .. } => ErrorKind::Io,
        crate::cab_backend::CabError::Invalid { .. } => ErrorKind::CorruptData,
        crate::cab_backend::CabError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::cab_backend::CabError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native XAR adapter backed by the standalone `xara` reader.
#[derive(Debug, Default)]
pub struct XarListAdapter;

impl NativeReadAdapter for XarListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &XAR_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::xar_backend::list(path).map_err(|error| xar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_xar_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::xar_backend::test(path, test_options).map_err(|error| xar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::xar_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| xar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::xar_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| xar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_xar_entries(entries: Vec<crate::xar_backend::XarEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: Some(entry.size),
            compressed_size: None,
            encrypted: Some(false),
            method: Some("xar".to_owned()),
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn xar_error(path: &std::path::Path, error: &crate::xar_backend::XarError) -> ArchiveError {
    let kind = match error {
        crate::xar_backend::XarError::Io { .. } => ErrorKind::Io,
        crate::xar_backend::XarError::Parser { .. } => ErrorKind::CorruptData,
        crate::xar_backend::XarError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::xar_backend::XarError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native LHA/LZH adapter backed by `delharc`.
#[derive(Debug, Default)]
pub struct LhaListAdapter;

impl NativeReadAdapter for LhaListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &LHA_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::lha_backend::list(path).map_err(|error| lha_error(path, &error))?;
        Ok(ArchiveListing { entries: map_lha_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::lha_backend::test(path, test_options).map_err(|error| lha_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::lha_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| lha_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::lha_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| lha_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_lha_entries(entries: Vec<crate::lha_backend::LhaEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: Some(entry.size),
            compressed_size: None,
            encrypted: Some(false),
            method: Some("lha".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn lha_error(path: &std::path::Path, error: &crate::lha_backend::LhaError) -> ArchiveError {
    let kind = match error {
        crate::lha_backend::LhaError::Io { .. } => ErrorKind::Io,
        crate::lha_backend::LhaError::Invalid { .. } => ErrorKind::CorruptData,
        crate::lha_backend::LhaError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::lha_backend::LhaError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native WARC adapter backed by the streaming `warc` reader.
#[derive(Debug, Default)]
pub struct WarcListAdapter;

impl NativeReadAdapter for WarcListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &WARC_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::warc_backend::list(path).map_err(|error| warc_error(path, &error))?;
        Ok(ArchiveListing { entries: map_warc_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::warc_backend::test(path, test_options).map_err(|error| warc_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::warc_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| warc_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::warc_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| warc_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_warc_entries(entries: Vec<crate::warc_backend::WarcEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: BrowserEntryKind::File,
            size: Some(entry.size),
            compressed_size: None,
            encrypted: Some(false),
            method: Some(format!("warc/{}", entry.record_type)),
            ..EngineEntry::default()
        })
        .collect()
}

fn warc_error(path: &std::path::Path, error: &crate::warc_backend::WarcError) -> ArchiveError {
    let kind = match error {
        crate::warc_backend::WarcError::Io { .. } => ErrorKind::Io,
        crate::warc_backend::WarcError::Invalid { .. } => ErrorKind::CorruptData,
        crate::warc_backend::WarcError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::warc_backend::WarcError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native MTREE manifest adapter backed by the `mtree` parser.
#[derive(Debug, Default)]
pub struct MtreeListAdapter;

impl NativeReadAdapter for MtreeListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &MTREE_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::mtree_backend::list(path).map_err(|error| mtree_error(path, &error))?;
        Ok(ArchiveListing { entries: map_mtree_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::mtree_backend::test(path, test_options).map_err(|error| mtree_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::mtree_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| mtree_error(path, &error))?;
        Ok(report.into())
    }
}

fn map_mtree_entries(entries: Vec<crate::mtree_backend::MtreeEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: entry.size,
            compressed_size: None,
            encrypted: Some(false),
            method: Some(format!("mtree/{}", entry.file_type)),
            link_target: entry.link_target.map(|target| target.to_string_lossy().into_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn mtree_error(path: &std::path::Path, error: &crate::mtree_backend::MtreeError) -> ArchiveError {
    let kind = match error {
        crate::mtree_backend::MtreeError::Io { .. } => ErrorKind::Io,
        crate::mtree_backend::MtreeError::Invalid { .. } => ErrorKind::CorruptData,
        crate::mtree_backend::MtreeError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::mtree_backend::MtreeError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native CPIO reader adapter.
#[derive(Debug, Default)]
pub struct CpioListAdapter;

impl NativeReadAdapter for CpioListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &CPIO_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let source = cpio_source(archive)?;
        let entries = crate::cpio_backend::list(&source).map_err(|error| cpio_error(path, &error))?;
        Ok(ArchiveListing { entries: map_cpio_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let source = cpio_source(archive)?;
        let report = crate::cpio_backend::test(&source, test_options).map_err(|error| cpio_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let source = cpio_source(archive)?;
        let report = crate::cpio_backend::extract(
            &source,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| cpio_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let source = cpio_source(archive)?;
        let report = crate::cpio_backend::extract_by_path_occurrence(
            &source,
            &options.destination,
            options.policy.clone(),
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
            &selector.path,
            selector.occurrence,
            options.cancellation.as_ref(),
        )
        .map_err(|error| cpio_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let source = cpio_source(archive)?;
        let written_bytes =
            crate::cpio_backend::copy_by_path_occurrence(&source, &selector.path, selector.occurrence, writer).map_err(|error| cpio_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

/// Returns the readable cpio payload for this session, decoding a compressed
/// container at most once.
///
/// An uncompressed `.cpio` is read in place. A compressed container has no
/// seekable member index, so it is decoded to a temporary file; that decode
/// costs the whole archive, and every cpio operation needs it. Caching it on
/// the session keeps `list` + `extract`, and above all a selected-entry batch,
/// at one decode instead of one per call.
fn cpio_source(archive: &NativeReadContext) -> Result<std::path::PathBuf, ArchiveError> {
    if let Some(decoded) = archive.decoded_payload.get() {
        return Ok(decoded.path.clone());
    }

    let decoded = decode_cpio_payload(archive)?;
    let path = decoded.path.clone();
    // `get` above returned `None` and decoding cannot re-enter this function,
    // so the cell is still empty; ignoring the result keeps the success path
    // free of an unreachable panic.
    let _ = archive.decoded_payload.set(decoded);
    Ok(path)
}

fn decode_cpio_payload(archive: &NativeReadContext) -> Result<DecodedPayload, ArchiveError> {
    let path = archive.primary_path();
    let Some(format) = cpio_compression(path) else {
        return Ok(DecodedPayload { _temporary: None, path: path.to_path_buf() });
    };
    let io_error = |error: std::io::Error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path);
    let temporary = match archive.options().temp_root.as_deref() {
        Some(temp_root) => crate::temp_names::TemporaryDirectory::new_in(temp_root, "cpio-decode"),
        None => crate::temp_names::TemporaryDirectory::new("cpio-decode"),
    }
    .map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
    let decoded_path = temporary.path().join("payload.cpio");
    let mut decoder = {
        let file = archive.open_primary_file()?;
        raw_stream_backend::open_decoder_from_reader(file, format, path)
            .map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?
    };
    let mut output = File::create(&decoded_path).map_err(io_error)?;
    std::io::copy(&mut decoder, &mut output).map_err(io_error)?;
    output.flush().map_err(io_error)?;
    Ok(DecodedPayload { _temporary: Some(temporary), path: decoded_path })
}

fn cpio_compression(path: &std::path::Path) -> Option<raw_stream_backend::RawStreamFormat> {
    let name = path.file_name()?.to_str()?;
    if crate::strings::ends_with_ignore_ascii_case(name, ".cpgz") || crate::strings::ends_with_ignore_ascii_case(name, ".cpio.gz") {
        Some(raw_stream_backend::RawStreamFormat::Gzip)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.bz2") {
        Some(raw_stream_backend::RawStreamFormat::Bzip2)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.xz") {
        Some(raw_stream_backend::RawStreamFormat::Xz)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.lzma") {
        Some(raw_stream_backend::RawStreamFormat::Lzma)
    } else if crate::strings::ends_with_ignore_ascii_case(name, ".cpio.zst") {
        Some(raw_stream_backend::RawStreamFormat::Zstd)
    } else {
        None
    }
}

fn map_cpio_entries(entries: Vec<crate::cpio_backend::CpioEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: Some(entry.size),
            mode: Some(entry.mode),
            modified: entry.modified,
            method: Some("cpio".to_owned()),
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn cpio_error(path: &std::path::Path, error: &crate::cpio_backend::CpioError) -> ArchiveError {
    let kind = match error {
        crate::cpio_backend::CpioError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::cpio_backend::CpioError::Cancelled => ErrorKind::Cancelled,
        crate::cpio_backend::CpioError::Io { .. } => ErrorKind::Io,
        crate::cpio_backend::CpioError::Invalid { .. } => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native AR reader adapter.
#[derive(Debug, Default)]
pub struct ArListAdapter;

impl NativeReadAdapter for ArListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &AR_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::ar_backend::list(path).map_err(|error| ar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_ar_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::ar_backend::test(path, test_options).map_err(|error| ar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::ar_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            None,
            options.cancellation.as_ref(),
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let report = crate::ar_backend::extract_by_path_occurrence(
            path,
            &options.destination,
            options.policy.clone(),
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
            &selector.path,
            selector.occurrence,
            options.cancellation.as_ref(),
        )
        .map_err(|error| ar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            crate::ar_backend::copy_by_path_occurrence(path, &selector.path, selector.occurrence, writer).map_err(|error| ar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_ar_entries(entries: Vec<crate::ar_backend::ArEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: BrowserEntryKind::File,
            size: Some(entry.size),
            compressed_size: Some(entry.size),
            method: Some("ar".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn ar_error(path: &std::path::Path, error: &crate::ar_backend::ArError) -> ArchiveError {
    let kind = match error {
        crate::ar_backend::ArError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::ar_backend::ArError::Cancelled => ErrorKind::Cancelled,
        crate::ar_backend::ArError::Io { .. } => ErrorKind::Io,
        crate::ar_backend::ArError::Invalid { .. } => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

static TAR_BZ2_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_bz2_adapter",
    format: FormatId::TAR_BZ2,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_XZ_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_xz_adapter",
    format: FormatId::TAR_XZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LZMA_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_lzma_adapter",
    format: FormatId::TAR_LZMA,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LZ_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_lz_adapter",
    format: FormatId::TAR_LZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LZO_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_lzo_adapter",
    format: FormatId::TAR_LZO,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_COMPRESS_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_compress_adapter",
    format: FormatId::TAR_COMPRESS,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_LZ4_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_lz4_adapter",
    format: FormatId::TAR_LZ4,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static TAR_UU_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_uu_adapter",
    format: FormatId::TAR_UU,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native filtered-TAR adapter backed by the shared TAR reader.
#[derive(Debug, Clone, Copy)]
pub struct FilteredTarAdapter {
    format: FormatId,
    decoder: raw_stream_backend::RawStreamFormat,
    method: &'static str,
}

impl FilteredTarAdapter {
    /// Creates a filtered TAR adapter for one canonical format.
    #[must_use]
    pub const fn new(format: FormatId, decoder: raw_stream_backend::RawStreamFormat, method: &'static str) -> Self {
        Self { format, decoder, method }
    }

    fn open_reader(&self, archive: &NativeReadContext) -> Result<Box<dyn Read>, ArchiveError> {
        let file = archive.open_primary_file()?;
        raw_stream_backend::open_decoder_from_reader(file, self.decoder, archive.primary_path())
            .map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(archive.primary_path()))
    }
}

impl NativeReadAdapter for FilteredTarAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        match self.format {
            FormatId::TAR_BZ2 => &TAR_BZ2_DESCRIPTOR,
            FormatId::TAR_XZ => &TAR_XZ_DESCRIPTOR,
            FormatId::TAR_LZMA => &TAR_LZMA_DESCRIPTOR,
            FormatId::TAR_LZ => &TAR_LZ_DESCRIPTOR,
            FormatId::TAR_LZO => &TAR_LZO_DESCRIPTOR,
            FormatId::TAR_COMPRESS => &TAR_COMPRESS_DESCRIPTOR,
            FormatId::TAR_LZ4 => &TAR_LZ4_DESCRIPTOR,
            FormatId::TAR_UU => &TAR_UU_DESCRIPTOR,
            _ => unreachable!("filtered TAR adapter format is not a supported native TAR filter"),
        }
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let reader = self.open_reader(archive)?;
        let entries = crate::tar_backend::list_with_temp_root(reader, path, archive.options().temp_root.as_deref()).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, self.method) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let reader = self.open_reader(archive)?;
        let report = crate::tar_backend::test_with_temp_root(
            reader,
            path,
            |entry_path| test_options.selects(entry_path),
            || test_options.is_cancelled(),
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let reader = self.open_reader(archive)?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_with_temp_root(
                reader,
                path,
                &options.destination,
                options.policy.clone(),
                options.overwrite_resolver.as_deref_mut(),
                None,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let reader = self.open_reader(archive)?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_path_occurrence_with_temp_root(
                reader,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut selectors = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let selector = archive.retained_entry(entry_id)?;
            selectors.push(crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence });
        }
        let reader = self.open_reader(archive)?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_selectors_with_temp_root(
                reader,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                &selectors,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let reader = self.open_reader(archive)?;
        let written_bytes = crate::tar_backend::copy_by_path_occurrence_with_temp_root(
            reader,
            path,
            crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
            writer,
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn system_time_string(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_secs().to_string())
}

fn tzap_timestamp_string(seconds: i64, nanoseconds: u32) -> Option<String> {
    if seconds == 0 && nanoseconds == 0 {
        return None;
    }
    if nanoseconds == 0 {
        return Some(seconds.to_string());
    }
    let fraction = format!("{nanoseconds:09}");
    Some(format!("{seconds}.{}", fraction.trim_end_matches('0')))
}

fn sevenz_archive_error(error: sevenz_backend::SevenZError, path: &std::path::Path) -> ArchiveError {
    let (kind, message) = match error {
        sevenz_backend::SevenZError::PasswordRequired => (ErrorKind::PasswordRequired, "password required to decrypt 7z data".to_string()),
        sevenz_backend::SevenZError::InvalidPassword => (ErrorKind::WrongPassword, "provided 7z password is incorrect".to_string()),
        sevenz_backend::SevenZError::Io { source, .. } => (ErrorKind::Io, source.to_string()),
        sevenz_backend::SevenZError::Safety(source) => {
            let kind = crate::engine::adapters::safety_error_kind(&source);
            (kind, source.to_string())
        }
        sevenz_backend::SevenZError::Cancelled => (ErrorKind::Cancelled, "7z operation was cancelled".to_string()),
        sevenz_backend::SevenZError::VolumeSizeTooSmall { size, minimum } => {
            (ErrorKind::CorruptData, format!("7z volume size {size} bytes is smaller than the minimum {minimum} bytes"))
        }
        sevenz_backend::SevenZError::Plan(source) => (ErrorKind::InvalidFormat, source.to_string()),
        sevenz_backend::SevenZError::SevenZ(source) => (ErrorKind::CorruptData, source.to_string()),
    };
    crate::engine::adapters::adapter_error(path, kind, message)
}

fn tzap_error(path: &std::path::Path, error: &crate::tzap::TzapError) -> ArchiveError {
    let kind = match error {
        crate::tzap::TzapError::PasswordRequired | crate::tzap::TzapError::RecipientKeyRequired => ErrorKind::PasswordRequired,
        crate::tzap::TzapError::Cancelled => ErrorKind::Cancelled,
        crate::tzap::TzapError::Io { .. } => ErrorKind::Io,
        crate::tzap::TzapError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        _ => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

fn rar_error(path: &std::path::Path, error: &rar_backend::RarBackendError) -> ArchiveError {
    let message = error.to_string();
    // The existing RAR bridge intentionally reports both a missing and a
    // rejected password through the same message path; preserve that
    // compatibility while keeping the typed distinction for formats whose
    // backends expose it.
    let kind = if message.to_lowercase().contains("password") {
        ErrorKind::WrongPassword
    } else {
        match error {
            rar_backend::RarBackendError::Io { .. } => ErrorKind::Io,
            rar_backend::RarBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
            rar_backend::RarBackendError::Unrar(_)
            | rar_backend::RarBackendError::MissingLinkTarget { .. }
            | rar_backend::RarBackendError::InvalidLinkTarget { .. }
            | rar_backend::RarBackendError::DictionaryTooLarge { .. } => ErrorKind::CorruptData,
        }
    };
    crate::engine::adapters::adapter_error(path, kind, message)
}

fn raw_stream_error(path: &std::path::Path, error: &raw_stream_backend::RawStreamError) -> ArchiveError {
    let kind = match error {
        raw_stream_backend::RawStreamError::Io { .. } => ErrorKind::Io,
        raw_stream_backend::RawStreamError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        raw_stream_backend::RawStreamError::MissingOutputName { .. } => ErrorKind::InvalidFormat,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

fn apple_archive_error(path: &std::path::Path, error: &apple_archive_backend::AppleArchiveError) -> ArchiveError {
    let kind = match error {
        apple_archive_backend::AppleArchiveError::Unsupported => ErrorKind::UnsupportedOperation,
        apple_archive_backend::AppleArchiveError::Cancelled => ErrorKind::Cancelled,
        apple_archive_backend::AppleArchiveError::Io { .. } => ErrorKind::Io,
        apple_archive_backend::AppleArchiveError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        apple_archive_backend::AppleArchiveError::Plan(_) => ErrorKind::InvalidFormat,
        apple_archive_backend::AppleArchiveError::Native(_)
        | apple_archive_backend::AppleArchiveError::MissingLinkTarget { .. }
        | apple_archive_backend::AppleArchiveError::MissingFileData { .. }
        | apple_archive_backend::AppleArchiveError::EntryNotFound { .. }
        | apple_archive_backend::AppleArchiveError::StdoutSelectionNotSingleFile { .. } => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

fn dmg_error(path: &std::path::Path, error: &apple_dmg_backend::DmgBackendError) -> ArchiveError {
    let kind = match error {
        apple_dmg_backend::DmgBackendError::Plan(_) => ErrorKind::InvalidFormat,
        apple_dmg_backend::DmgBackendError::Io { .. } => ErrorKind::Io,
        apple_dmg_backend::DmgBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        apple_dmg_backend::DmgBackendError::Cancelled => ErrorKind::Cancelled,
        apple_dmg_backend::DmgBackendError::Dpp(_) => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

fn pkg_error(path: &std::path::Path, error: &apple_pkg_backend::PkgBackendError) -> ArchiveError {
    let kind = match error {
        apple_pkg_backend::PkgBackendError::Plan(_) => ErrorKind::InvalidFormat,
        apple_pkg_backend::PkgBackendError::Io { .. } => ErrorKind::Io,
        apple_pkg_backend::PkgBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        apple_pkg_backend::PkgBackendError::Cancelled => ErrorKind::Cancelled,
        apple_pkg_backend::PkgBackendError::Xara(_) | apple_pkg_backend::PkgBackendError::Pbzx(_) => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

fn msi_error(path: &std::path::Path, error: &msi_backend::MsiBackendError) -> ArchiveError {
    let kind = match error {
        msi_backend::MsiBackendError::Plan(_) => ErrorKind::InvalidFormat,
        msi_backend::MsiBackendError::Io { .. } => ErrorKind::Io,
        msi_backend::MsiBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        msi_backend::MsiBackendError::Cancelled => ErrorKind::Cancelled,
        msi_backend::MsiBackendError::Msi(_) | msi_backend::MsiBackendError::Cab(_) => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

// --- 7z ---
static SEVEN_Z_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_7z_lister",
    format: FormatId::SEVEN_Z,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native 7z listing adapter factory.
#[derive(Debug, Default)]
pub struct SevenZListAdapter;

impl NativeReadAdapter for SevenZListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &SEVEN_Z_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let listing = sevenz_backend::list_7z(primary_path, archive.options().password.as_deref()).map_err(|err| sevenz_archive_error(err, primary_path))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.name,
                kind: match entry.kind {
                    sevenz_backend::SevenZEntryKind::File => BrowserEntryKind::File,
                    sevenz_backend::SevenZEntryKind::Directory => BrowserEntryKind::Directory,
                    sevenz_backend::SevenZEntryKind::AntiItem => BrowserEntryKind::Special,
                },
                size: Some(entry.size),
                compressed_size: (entry.compressed_size > 0).then_some(entry.compressed_size),
                modified: entry.modified.and_then(system_time_string),
                mode: entry.mode,
                encrypted: None,
                method: None,
                crc: entry.crc,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = sevenz_backend::test_7z_with_password_filter(path, archive.options().password.as_deref(), |entry_path| test_options.selects(entry_path))
            .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            sevenz_backend::extract_7z_with_overwrite_resolver(
                path,
                &options.destination,
                archive.options().password.as_deref(),
                options.policy.clone(),
                resolver,
            )
        } else {
            sevenz_backend::extract_7z(path, &options.destination, archive.options().password.as_deref(), options.policy.clone())
        }
        .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let report = sevenz_backend::extract_7z_entry_by_name_occurrence(
            path,
            &options.destination,
            archive.options().password.as_deref(),
            options.policy.clone(),
            &selector.path,
            selector.occurrence,
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
        )
        .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut selectors = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let selector = archive.retained_entry(entry_id)?;
            selectors.push(sevenz_backend::SevenZEntrySelector { path: &selector.path, occurrence: selector.occurrence });
        }
        let report = sevenz_backend::extract_7z_entries_by_name_occurrence(
            path,
            &options.destination,
            archive.options().password.as_deref(),
            options.policy.clone(),
            &selectors,
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
        )
        .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            sevenz_backend::copy_7z_entry_by_name_occurrence(path, archive.options().password.as_deref(), &selector.path, selector.occurrence, writer)
                .map_err(|error| sevenz_archive_error(error, path))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- TAR.ZST ---
static TAR_ZST_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tar_zst_lister",
    format: FormatId::TAR_ZST,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native TAR.ZST listing adapter factory.
#[derive(Debug, Default)]
pub struct TarZstListAdapter;

impl NativeReadAdapter for TarZstListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TAR_ZST_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let entries =
            crate::tar_backend::list_with_temp_root(decoder, path, archive.options().temp_root.as_deref()).map_err(|error| tar_error(path, &error))?;
        Ok(ArchiveListing { entries: map_tar_entries(entries, "zstd") })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = crate::tar_backend::test_with_temp_root(
            decoder,
            path,
            |entry_path| test_options.selects(entry_path),
            || test_options.is_cancelled(),
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                options.overwrite_resolver.as_deref_mut(),
                None,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_path_occurrence_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut selectors = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let selector = archive.retained_entry(entry_id)?;
            selectors.push(crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence });
        }
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let report = with_job_context(options.cancellation.as_ref(), options.event_sink.as_deref_mut(), |context| {
            crate::tar_backend::extract_by_selectors_with_temp_root(
                decoder,
                path,
                &options.destination,
                options.policy.clone(),
                reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
                &selectors,
                options.cancellation.as_ref(),
                Some(context),
                archive.options().temp_root.as_deref(),
            )
        })
        .map_err(|error| tar_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let file = archive.open_primary_file()?;
        let decoder =
            zstd::stream::read::Decoder::new(file).map_err(|error| ArchiveError::usable(ErrorKind::InvalidFormat, error.to_string()).with_path(path))?;
        let written_bytes = crate::tar_backend::copy_by_path_occurrence_with_temp_root(
            decoder,
            path,
            crate::tar_backend::TarEntrySelector { path: &selector.path, occurrence: selector.occurrence },
            writer,
            archive.options().temp_root.as_deref(),
        )
        .map_err(|error| tar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- TZAP ---
static TZAP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_tzap_lister",
    format: FormatId::TZAP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native TZAP listing adapter factory.
#[derive(Debug, Default)]
pub struct TzapListAdapter;

impl NativeReadAdapter for TzapListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &TZAP_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let listing = match (archive.options().recipient_key_bytes(), archive.options().recipient_key_path()) {
            (Some(recipient_key_bytes), _) => tzap::list_tzap_index_with_recipient_key_bytes_list(primary_path, recipient_key_bytes),
            (None, Some(recipient_key)) => tzap::list_tzap_index_with_recipient_key(primary_path, recipient_key),
            (None, None) => tzap::list_tzap_index_with_optional_password(primary_path, archive.options().password.as_deref()),
        }
        .map_err(|error| tzap_error(primary_path, &error))?;

        let encrypted = listing.encrypted;
        let method = if encrypted {
            match listing.kdf_algo {
                tzap_core::format::KdfAlgo::Argon2id => "Zstd (Argon2id)",
                tzap_core::format::KdfAlgo::RecipientWrap => "Zstd (Recipient)",
                _ => "Zstd (Encrypted)",
            }
        } else {
            "Zstd"
        };
        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: match entry.kind {
                    tzap::TzapEntryKind::File => BrowserEntryKind::File,
                    tzap::TzapEntryKind::Directory => BrowserEntryKind::Directory,
                    tzap::TzapEntryKind::Symlink => BrowserEntryKind::Symlink,
                    tzap::TzapEntryKind::Hardlink => BrowserEntryKind::Hardlink,
                    tzap::TzapEntryKind::CharacterDevice | tzap::TzapEntryKind::BlockDevice | tzap::TzapEntryKind::Fifo => BrowserEntryKind::Special,
                },
                size: Some(entry.size),
                compressed_size: (entry.compressed_size != 0).then_some(entry.compressed_size),
                modified: tzap_timestamp_string(entry.mtime, entry.mtime_nanoseconds),
                mode: Some(entry.mode),
                encrypted: Some(encrypted),
                method: Some(method.to_owned()),
                crc: None,
                comment: None,
                link_target: entry.link_target,
                created: entry.created.and_then(|(seconds, nanoseconds)| tzap_timestamp_string(seconds, nanoseconds)),
                accessed: entry.accessed.and_then(|(seconds, nanoseconds)| tzap_timestamp_string(seconds, nanoseconds)),
                solid: Some(true),
                attributes: entry.attributes.map(|value| format!("{value:#010X}")),
                uid: entry.uid.and_then(|value| u32::try_from(value).ok()),
                gid: entry.gid.and_then(|value| u32::try_from(value).ok()),
                owner: entry.uname,
                group: entry.gname,
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let trust = test_options.tzap_x509_trust.clone().map(Into::into);
        let recipient_key_bytes = test_options.recipient_key_bytes.as_deref().or_else(|| archive.options().recipient_key_bytes());
        let recipient_key = test_options.recipient_key.as_deref().or(archive.options().recipient_key_path());
        let report = if let Some(recipient_key_bytes) = recipient_key_bytes {
            tzap::test_tzap_with_recipient_key_bytes_list_filter_and_x509_trust(
                path,
                recipient_key_bytes,
                |entry_path| test_options.selects(entry_path),
                trust.as_ref(),
            )
        } else if let Some(recipient_key) = recipient_key {
            tzap::test_tzap_with_recipient_key_filter_and_x509_trust(path, recipient_key, |entry_path| test_options.selects(entry_path), trust.as_ref())
        } else {
            tzap::test_tzap_with_optional_password_filter_and_x509_trust(
                path,
                archive.options().password.as_deref(),
                |entry_path| test_options.selects(entry_path),
                trust.as_ref(),
            )
        }
        .map_err(|error| tzap_error(path, &error))?;
        let mut warnings = Vec::new();
        if let Some(root_auth) = report.x509_root_auth {
            warnings.push(format!("TZAP root-auth verified for {}", root_auth.subject));
            warnings.extend(root_auth.diagnostics);
        }
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let key = if let Some(recipient_key_bytes) = options.recipient_key_bytes.as_deref() {
            tzap::TzapExtractKeySource::RecipientKeyBytesList(recipient_key_bytes)
        } else if let Some(recipient_key) = options.recipient_key.as_deref() {
            tzap::TzapExtractKeySource::RecipientKeyPath(recipient_key)
        } else if let Some(password) = options.tzap_password.as_deref() {
            tzap::TzapExtractKeySource::Password(password)
        } else {
            tzap::TzapExtractKeySource::None
        };
        let report = tzap::extract_tzap(
            tzap::TzapExtractRequest {
                key,
                policy: options.policy.clone(),
                restore_options: options.tzap_restore_options.unwrap_or_default().into(),
                overwrite_resolver: options.overwrite_resolver.as_deref_mut(),
                context: None,
                fast: false,
            },
            path,
            &options.destination,
        )
        .map_err(|error| tzap_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let destination_path = options.destination.join(&selector.path);
        // The retained selector comes from the original engine listing.  The
        // TZAP file operation resolves that exact path inside a newly opened
        // reader without re-listing or treating the engine ID as a fresh index.
        if matches!(selector.kind, BrowserEntryKind::Directory) {
            std::fs::create_dir_all(&destination_path).map_err(|error| ArchiveError::usable(ErrorKind::Io, error.to_string()).with_path(path))?;
            return Ok(ExtractReport { written_entries: 1, ..ExtractReport::default() });
        }
        if !matches!(selector.kind, BrowserEntryKind::File) {
            return Ok(ExtractReport {
                skipped_entries: 1,
                warnings: vec![format!("skipped unsupported TZAP entry {}", selector.path)],
                ..ExtractReport::default()
            });
        }
        let key = if let Some(recipient_key_bytes) = archive.options().recipient_key_bytes() {
            tzap::TzapExtractKeySource::RecipientKeyBytesList(recipient_key_bytes)
        } else if let Some(recipient_key) = archive.options().recipient_key_path() {
            tzap::TzapExtractKeySource::RecipientKeyPath(recipient_key)
        } else {
            tzap::TzapExtractKeySource::Password(archive.options().password.as_deref().unwrap_or(""))
        };
        let report = tzap::extract_tzap_file_to_destination(
            path,
            key,
            &selector.path,
            &destination_path,
            options.policy.overwrite == crate::safety::OverwritePolicy::Replace,
            options.tzap_restore_options.unwrap_or_default().into(),
        )
        .map_err(|error| tzap_error(path, &error))?;
        let Some(report) = report else {
            return Ok(ExtractReport { skipped_entries: 1, ..ExtractReport::default() });
        };
        Ok(ExtractReport { written_entries: 1, written_bytes: report.written_bytes, warnings: report.metadata_diagnostics, ..ExtractReport::default() })
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let key = if let Some(recipient_key_bytes) = archive.options().recipient_key_bytes() {
            tzap::TzapExtractKeySource::RecipientKeyBytesList(recipient_key_bytes)
        } else if let Some(recipient_key) = archive.options().recipient_key_path() {
            tzap::TzapExtractKeySource::RecipientKeyPath(recipient_key)
        } else {
            tzap::TzapExtractKeySource::Password(archive.options().password.as_deref().unwrap_or(""))
        };
        let report = tzap::copy_tzap_file_to_writer(path, key, &selector.path, writer).map_err(|error| tzap_error(path, &error))?;
        Ok(CopyReport { written_bytes: report.written_bytes })
    }
}

// --- RAR ---
static RAR_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_rar_lister",
    format: FormatId::RAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Exclusive Native RAR listing adapter factory (ARC-208).
#[derive(Debug, Default)]
pub struct RarListAdapter;

impl NativeReadAdapter for RarListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RAR_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let listing =
            rar_backend::list_rar_with_password(primary_path, archive.options().password.as_deref()).map_err(|error| rar_error(primary_path, &error))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: match entry.kind {
                    rar_backend::RarListEntryKind::File => BrowserEntryKind::File,
                    rar_backend::RarListEntryKind::FileCopy => BrowserEntryKind::FileCopy,
                    rar_backend::RarListEntryKind::Directory => BrowserEntryKind::Directory,
                    rar_backend::RarListEntryKind::Symlink => BrowserEntryKind::Symlink,
                    rar_backend::RarListEntryKind::Hardlink => BrowserEntryKind::Hardlink,
                    rar_backend::RarListEntryKind::Special => BrowserEntryKind::Special,
                },
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(entry.encrypted),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = rar_backend::test_rar_with_password_filter(path, archive.options().password.as_deref(), |entry_path| test_options.selects(entry_path))
            .map_err(|error| rar_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            rar_backend::extract_rar_with_overwrite_resolver_and_password(
                path,
                &options.destination,
                options.policy.clone(),
                archive.options().password.as_deref(),
                resolver,
            )
        } else {
            rar_backend::extract_rar_with_password(path, &options.destination, options.policy.clone(), archive.options().password.as_deref())
        }
        .map_err(|error| rar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let report = rar_backend::extract_rar_entry_by_path_occurrence(
            path,
            &options.destination,
            options.policy.clone(),
            archive.options().password.as_deref(),
            &selector.path,
            selector.occurrence,
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
        )
        .map_err(|error| rar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract_many(
        &self,
        archive: &NativeReadContext,
        entry_ids: &[EntryId],
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let path = archive.primary_path();
        let mut retained = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            retained.push(archive.retained_entry(entry_id)?);
        }
        let selectors =
            retained.iter().map(|selector| rar_backend::RarEntrySelector { path: &selector.path, occurrence: selector.occurrence }).collect::<Vec<_>>();
        let report = rar_backend::extract_rar_entries_by_path_occurrence(
            path,
            &options.destination,
            options.policy.clone(),
            archive.options().password.as_deref(),
            &selectors,
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
        )
        .map_err(|error| rar_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes =
            rar_backend::copy_rar_entry_by_path_occurrence(path, archive.options().password.as_deref(), &selector.path, selector.occurrence, writer)
                .map_err(|error| rar_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- Raw Streams ---
static RAW_STREAM_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_raw_stream_lister",
    format: FormatId::RAW_STREAM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native Raw Stream listing adapter factory.
#[derive(Debug, Default)]
pub struct RawStreamListAdapter;

impl NativeReadAdapter for RawStreamListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &RAW_STREAM_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(primary_path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(primary_path))?;

        let payload_name = raw_stream_backend::output_name_for_raw_stream(primary_path, format)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Could not determine raw stream output name").with_path(primary_path))?;

        let metadata = archive.open_primary_file()?.metadata().map_err(|err| ArchiveError::usable(ErrorKind::Io, err.to_string()).with_path(primary_path))?;

        let entry = EngineEntry {
            id: EntryId(0),
            path: payload_name,
            kind: BrowserEntryKind::File,
            size: None,
            compressed_size: Some(metadata.len()),
            modified: metadata.modified().ok().and_then(system_time_string),
            mode: None,
            encrypted: Some(false),
            method: Some(format.name().to_owned()),
            crc: None,
            comment: None,
            link_target: None,
            ..EngineEntry::default()
        };

        Ok(ArchiveListing { entries: vec![entry] })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let payload_name = raw_stream_backend::output_name_for_raw_stream(path, format)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Could not determine raw stream output name").with_path(path))?;
        if !test_options.selects(&payload_name) {
            return Ok(TestReport { tested_entries: 0, skipped_entries: 1, tested_bytes: 0, warnings: Vec::new() });
        }
        let tested_bytes = raw_stream_backend::test_raw_stream(path, format).map_err(|error| raw_stream_error(path, &error))?;
        Ok(TestReport { tested_entries: 1, skipped_entries: 0, tested_bytes, warnings: Vec::new() })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            raw_stream_backend::extract_raw_stream_with_overwrite_resolver(path, format, &options.destination, options.policy.clone(), resolver)
        } else {
            raw_stream_backend::extract_raw_stream(path, format, &options.destination, options.policy.clone())
        }
        .map_err(|error| raw_stream_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let selector = archive.selected_entry_selector(entry_id)?;
        if selector.kind != BrowserEntryKind::File {
            return Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "raw stream synthetic entry is not a regular file"));
        }
        let path = archive.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            raw_stream_backend::extract_raw_stream_with_overwrite_resolver(path, format, &options.destination, options.policy.clone(), resolver)
        } else {
            raw_stream_backend::extract_raw_stream(path, format, &options.destination, options.policy.clone())
        }
        .map_err(|error| raw_stream_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let selector = archive.selected_entry_selector(entry_id)?;
        if selector.kind != BrowserEntryKind::File {
            return Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "raw stream synthetic entry is not a regular file"));
        }
        let path = archive.primary_path();
        let format = raw_stream_backend::detect_raw_stream_format(path)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, "Not a recognized raw compression stream").with_path(path))?;
        let written_bytes = raw_stream_backend::copy_raw_stream_to_writer(path, format, writer).map_err(|error| raw_stream_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

// --- Apple Archive ---
static APPLE_ARCHIVE_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_apple_archive_lister",
    format: FormatId::APPLE_ARCHIVE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

/// Native Apple Archive listing adapter factory.
#[derive(Debug, Default)]
pub struct AppleArchiveListAdapter;

impl NativeReadAdapter for AppleArchiveListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &APPLE_ARCHIVE_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let listing = apple_archive_backend::list_apple_archive(primary_path, archive.options().password.as_deref())
            .map_err(|error| apple_archive_error(primary_path, &error))?;

        let entries = listing
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: match entry.kind {
                    apple_archive_backend::AppleArchiveEntryKind::File => BrowserEntryKind::File,
                    apple_archive_backend::AppleArchiveEntryKind::Directory => BrowserEntryKind::Directory,
                    apple_archive_backend::AppleArchiveEntryKind::Symlink => BrowserEntryKind::Symlink,
                    apple_archive_backend::AppleArchiveEntryKind::Device | apple_archive_backend::AppleArchiveEntryKind::Special => BrowserEntryKind::Special,
                },
                size: entry.size,
                compressed_size: None,
                modified: entry.modified.and_then(system_time_string),
                mode: entry.mode,
                encrypted: Some(false),
                method: None,
                crc: entry.crc,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report =
            apple_archive_backend::test_apple_archive_filter(path, |entry_path| test_options.selects(entry_path), archive.options().password.as_deref())
                .map_err(|error| apple_archive_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_archive_backend::extract_apple_archive_with_overwrite_resolver(
                path,
                &options.destination,
                options.policy.clone(),
                resolver,
                archive.options().password.as_deref(),
            )
        } else {
            apple_archive_backend::extract_apple_archive(path, &options.destination, options.policy.clone(), archive.options().password.as_deref())
        }
        .map_err(|error| apple_archive_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(
        &self,
        archive: &NativeReadContext,
        entry_id: EntryId,
        options: &mut SelectedExtractOptions<'_>,
    ) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let report = apple_archive_backend::extract_apple_archive_entry(
            path,
            &selector.path,
            &options.destination,
            options.policy.clone(),
            archive.options().password.as_deref(),
        )
        .map_err(|error| apple_archive_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let target_path = selector.path.clone();
        let target_occurrence = selector.occurrence;
        let mut occurrence = 0_usize;
        let report = apple_archive_backend::copy_apple_archive_files_to_writer(
            path,
            |entry_path| {
                let selected = entry_path == target_path && occurrence == target_occurrence;
                if entry_path == target_path {
                    occurrence = occurrence.saturating_add(1);
                }
                selected && !entry_path.is_empty()
            },
            writer,
            archive.options().password.as_deref(),
        )
        .map_err(|error| apple_archive_error(path, &error))?;
        Ok(CopyReport { written_bytes: report.written_bytes })
    }
}

// --- DMG ---
static DMG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_dmg_lister",
    format: FormatId::DMG,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native DMG listing adapter factory.
#[derive(Debug, Default)]
pub struct DmgListAdapter;

impl NativeReadAdapter for DmgListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &DMG_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let raw_entries = apple_dmg_backend::list_dmg(primary_path).map_err(|error| dmg_error(primary_path, &error))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: match entry.kind {
                    apple_dmg_backend::DmgEntryKind::File => BrowserEntryKind::File,
                    apple_dmg_backend::DmgEntryKind::Directory => BrowserEntryKind::Directory,
                    apple_dmg_backend::DmgEntryKind::Symlink => BrowserEntryKind::Symlink,
                },
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_dmg_backend::extract_dmg_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            apple_dmg_backend::extract_dmg(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| dmg_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- PKG ---
static PKG_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_pkg_lister",
    format: FormatId::PKG,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native PKG listing adapter factory.
#[derive(Debug, Default)]
pub struct PkgListAdapter;

impl NativeReadAdapter for PkgListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &PKG_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let raw_entries = apple_pkg_backend::list_pkg(primary_path).map_err(|error| pkg_error(primary_path, &error))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: match entry.kind {
                    apple_pkg_backend::PkgEntryKind::File => BrowserEntryKind::File,
                    apple_pkg_backend::PkgEntryKind::Directory => BrowserEntryKind::Directory,
                    apple_pkg_backend::PkgEntryKind::Symlink => BrowserEntryKind::Symlink,
                },
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: entry.link_target,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            apple_pkg_backend::extract_pkg_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            apple_pkg_backend::extract_pkg(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| pkg_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- MSI ---
static MSI_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_msi_lister",
    format: FormatId::MSI,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native MSI listing adapter factory.
#[derive(Debug, Default)]
pub struct MsiListAdapter;

impl NativeReadAdapter for MsiListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &MSI_LIST_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let raw_entries = msi_backend::list_msi(primary_path).map_err(|error| msi_error(primary_path, &error))?;

        let entries = raw_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| EngineEntry {
                id: crate::engine::adapters::listing_entry_id(index),
                path: entry.path,
                kind: BrowserEntryKind::File,
                size: Some(entry.size),
                compressed_size: None,
                modified: None,
                mode: None,
                encrypted: Some(false),
                method: None,
                crc: None,
                comment: None,
                link_target: None,
                ..EngineEntry::default()
            })
            .collect();

        Ok(ArchiveListing { entries })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = if let Some(resolver) = options.overwrite_resolver.as_deref_mut() {
            msi_backend::extract_msi_with_overwrite_resolver(path, &options.destination, options.policy.clone(), resolver)
        } else {
            msi_backend::extract_msi(path, &options.destination, options.policy.clone())
        }
        .map_err(|error| msi_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }
}

// --- Virtual Disks and optical filesystems (VHD, VMDK, UDF, ISO) ---

static ISO_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_iso_adapter",
    format: FormatId::ISO,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static VHD_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::VHD,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static VMDK_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::VMDK,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static UDF_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::UDF,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static VDI_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::VDI,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static NRG_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_nrg_adapter",
    format: FormatId::NRG,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static MDF_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_mdf_adapter",
    format: FormatId::MDF,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CDI_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cdi_adapter",
    format: FormatId::CDI,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static ISZ_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_isz_adapter",
    format: FormatId::ISZ,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CCD_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_ccd_adapter",
    format: FormatId::CCD,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static CUE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_cue_adapter",
    format: FormatId::CUE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static VHDX_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::VHDX,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static QCOW2_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::QCOW2,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static EWF_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::EWF,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static AD1_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_logical_container_lister",
    format: FormatId::AD1,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static DAR_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_logical_container_lister",
    format: FormatId::DAR,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static AFF4_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_logical_container_lister",
    format: FormatId::AFF4,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static RAW_DISK_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_virtual_disk_lister",
    format: FormatId::RAW_DISK,
    operations: &[ArchiveOperation::List, ArchiveOperation::Extract, ArchiveOperation::Test, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static SQUASHFS_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_squashfs_adapter",
    format: FormatId::SQUASHFS,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static APPIMAGE_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_appimage_adapter",
    format: FormatId::APPIMAGE,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

static WIM_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_wim_adapter",
    format: FormatId::WIM,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: false,
};

/// Native `SquashFS` listing and extraction adapter.
#[derive(Debug, Default)]
pub struct SquashfsListAdapter;

impl NativeReadAdapter for SquashfsListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &SQUASHFS_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::squashfs_backend::list(path).map_err(|error| squashfs_error(path, &error))?;
        Ok(ArchiveListing { entries: map_squashfs_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::squashfs_backend::test(path, test_options).map_err(|error| squashfs_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::squashfs_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| squashfs_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes = crate::squashfs_backend::copy_to_writer(path, &selector.path, writer).map_err(|error| squashfs_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_squashfs_entries(entries: Vec<crate::squashfs_backend::SquashfsEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(entry.index),
            path: entry.path,
            kind: entry.kind,
            size: Some(entry.size),
            compressed_size: None,
            link_target: entry.link_target,
            encrypted: Some(false),
            method: Some("squashfs".to_owned()),
            ..EngineEntry::default()
        })
        .collect()
}

fn squashfs_error(path: &std::path::Path, error: &crate::squashfs_backend::SquashfsBackendError) -> ArchiveError {
    let kind = match error {
        crate::squashfs_backend::SquashfsBackendError::Io { .. } => ErrorKind::Io,
        crate::squashfs_backend::SquashfsBackendError::Invalid { .. }
        | crate::squashfs_backend::SquashfsBackendError::Backhand(_)
        | crate::squashfs_backend::SquashfsBackendError::Plan(_) => ErrorKind::CorruptData,
        crate::squashfs_backend::SquashfsBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::squashfs_backend::SquashfsBackendError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native Linux `AppImage` adapter.
#[derive(Debug, Default)]
pub struct AppImageListAdapter;

impl NativeReadAdapter for AppImageListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &APPIMAGE_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::squashfs_backend::list(path).map_err(|error| squashfs_error(path, &error))?;
        Ok(ArchiveListing { entries: map_squashfs_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::squashfs_backend::test(path, test_options).map_err(|error| squashfs_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::squashfs_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| squashfs_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes = crate::squashfs_backend::copy_to_writer(path, &selector.path, writer).map_err(|error| squashfs_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

/// Native Microsoft Windows Imaging (WIM) adapter.
#[derive(Debug, Default)]
pub struct WimListAdapter;

impl NativeReadAdapter for WimListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        &WIM_DESCRIPTOR
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let path = archive.primary_path();
        let entries = crate::wim_backend::list(path).map_err(|error| wim_error(path, &error))?;
        Ok(ArchiveListing { entries: map_wim_entries(entries) })
    }

    fn test(&self, archive: &NativeReadContext, test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::wim_backend::test(path, test_options).map_err(|error| wim_error(path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.bytes,
            warnings: report.warnings,
        })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let report = crate::wim_backend::extract(
            path,
            &options.destination,
            options.policy.clone(),
            options.overwrite_resolver.as_deref_mut(),
            options.cancellation.as_ref(),
        )
        .map_err(|error| wim_error(path, &error))?;
        Ok(report.into())
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let written_bytes = crate::wim_backend::copy_to_writer(path, &selector.path, writer).map_err(|error| wim_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_wim_entries(entries: Vec<crate::wim_backend::WimEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                crate::wim_backend::WimEntryKind::File => BrowserEntryKind::File,
                crate::wim_backend::WimEntryKind::Directory => BrowserEntryKind::Directory,
                crate::wim_backend::WimEntryKind::Symlink => BrowserEntryKind::Symlink,
            };
            EngineEntry {
                id: crate::engine::adapters::listing_entry_id(entry.index),
                path: entry.path,
                kind,
                size: Some(entry.size),
                compressed_size: None,
                link_target: entry.link_target,
                encrypted: Some(false),
                method: Some("wim".to_owned()),
                ..EngineEntry::default()
            }
        })
        .collect()
}

fn wim_error(path: &std::path::Path, error: &crate::wim_backend::WimBackendError) -> ArchiveError {
    let kind = match error {
        crate::wim_backend::WimBackendError::Io { .. } => ErrorKind::Io,
        crate::wim_backend::WimBackendError::Invalid { .. } | crate::wim_backend::WimBackendError::Plan(_) => ErrorKind::CorruptData,
        // LZMS and solid resources are a well-formed image this build cannot
        // decode, not corruption; the message names the conversion command.
        crate::wim_backend::WimBackendError::Unsupported { .. } => ErrorKind::UnsupportedOperation,
        crate::wim_backend::WimBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        crate::wim_backend::WimBackendError::Cancelled => ErrorKind::Cancelled,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

/// Native Virtual Disk listing adapter factory.
#[derive(Debug)]
pub struct VirtualDiskListAdapter {
    format: FormatId,
}

impl VirtualDiskListAdapter {
    /// Every format this adapter serves, and how the backend must mount it:
    /// `Some(false)` for a disk or optical image, `Some(true)` for a logical
    /// container (AD1/DAR/AFF4 -- an arbitrary-path file tree with no sector
    /// stream), `None` for a format this adapter does not own.
    ///
    /// `new`, `extract`, `test`, and `copy_to_writer` all route through this one
    /// list, so a newly supported format is added in exactly one place. The
    /// per-format `virtual_disk_backend::extract_*` / `test_*` entry points are
    /// public API for FFI and desktop callers, but they all delegate to the same
    /// two inner routines, so enumerating them here would only be a way to get
    /// the routing out of sync with the constructor.
    fn mounts_as_logical_container(format: FormatId) -> Option<bool> {
        match format {
            FormatId::VHD
            | FormatId::VMDK
            | FormatId::UDF
            | FormatId::ISO
            | FormatId::VDI
            | FormatId::NRG
            | FormatId::MDF
            | FormatId::CDI
            | FormatId::ISZ
            | FormatId::CCD
            | FormatId::CUE
            | FormatId::VHDX
            | FormatId::QCOW2
            | FormatId::EWF
            | FormatId::RAW_DISK => Some(false),
            FormatId::AD1 | FormatId::DAR | FormatId::AFF4 => Some(true),
            _ => None,
        }
    }

    /// Resolves the mount class, or reports the format as unsupported.
    fn mount_class(&self, operation: &str) -> Result<bool, ArchiveError> {
        Self::mounts_as_logical_container(self.format)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("Unsupported virtual disk {operation} format '{}'", self.format)))
    }

    /// Creates a virtual disk, optical, or logical container adapter.
    #[must_use]
    pub(crate) fn new(format: FormatId) -> Option<Self> {
        Self::mounts_as_logical_container(format).map(|_| Self { format })
    }
}

impl NativeReadAdapter for VirtualDiskListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        match self.format {
            FormatId::ISO => &ISO_DESCRIPTOR,
            FormatId::VHD => &VHD_DESCRIPTOR,
            FormatId::VMDK => &VMDK_DESCRIPTOR,
            FormatId::UDF => &UDF_DESCRIPTOR,
            FormatId::VDI => &VDI_DESCRIPTOR,
            FormatId::NRG => &NRG_DESCRIPTOR,
            FormatId::MDF => &MDF_DESCRIPTOR,
            FormatId::CDI => &CDI_DESCRIPTOR,
            FormatId::ISZ => &ISZ_DESCRIPTOR,
            FormatId::CCD => &CCD_DESCRIPTOR,
            FormatId::CUE => &CUE_DESCRIPTOR,
            FormatId::VHDX => &VHDX_DESCRIPTOR,
            FormatId::QCOW2 => &QCOW2_DESCRIPTOR,
            FormatId::EWF => &EWF_DESCRIPTOR,
            FormatId::AD1 => &AD1_DESCRIPTOR,
            FormatId::DAR => &DAR_DESCRIPTOR,
            FormatId::AFF4 => &AFF4_DESCRIPTOR,
            FormatId::RAW_DISK => &RAW_DISK_DESCRIPTOR,
            _ => unreachable!("VirtualDiskListAdapter only accepts virtual disk and optical formats"),
        }
    }

    fn list(&self, archive: &NativeReadContext) -> Result<ArchiveListing, ArchiveError> {
        let primary_path = archive.primary_path();
        let allow_logical = self.mount_class("format")?;
        let raw_entries = virtual_disk_backend::list_container_inner(primary_path, allow_logical).map_err(|error| virtual_disk_error(primary_path, &error))?;
        Ok(ArchiveListing { entries: map_virtual_disk_entries(raw_entries) })
    }

    fn extract<'a>(&self, archive: &NativeReadContext, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let path = archive.primary_path();
        let allow_logical = self.mount_class("format")?;
        let report = virtual_disk_backend::extract_container_inner(
            path,
            &options.destination,
            options.policy.clone(),
            None,
            options.overwrite_resolver.as_deref_mut(),
            allow_logical,
        )
        .map_err(|error| virtual_disk_error(path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn test(&self, archive: &NativeReadContext, options: &TestOptions) -> Result<TestReport, ArchiveError> {
        let path = archive.primary_path();
        let allow_logical = self.mount_class("test")?;
        virtual_disk_backend::test_container_payloads(path, options, allow_logical).map_err(|error| virtual_disk_error(path, &error))
    }

    fn copy_to_writer(&self, archive: &NativeReadContext, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let path = archive.primary_path();
        let selector = archive.selected_entry_selector(entry_id)?;
        let allow_logical = self.mount_class("copy")?;
        let label = if allow_logical { "logical container" } else { "virtual disk" };
        let written_bytes = virtual_disk_backend::copy_container_by_path_occurrence(path, &selector.path, selector.occurrence, writer, allow_logical, label)
            .map_err(|error| virtual_disk_error(path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

fn map_virtual_disk_entries(entries: Vec<virtual_disk_backend::VirtualDiskListEntry>) -> Vec<EngineEntry> {
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| EngineEntry {
            id: crate::engine::adapters::listing_entry_id(index),
            path: entry.path,
            kind: match entry.kind {
                virtual_disk_backend::VirtualDiskEntryKind::File => BrowserEntryKind::File,
                virtual_disk_backend::VirtualDiskEntryKind::Directory => BrowserEntryKind::Directory,
                virtual_disk_backend::VirtualDiskEntryKind::Symlink => BrowserEntryKind::Symlink,
            },
            size: Some(entry.size),
            compressed_size: None,
            modified: None,
            mode: None,
            encrypted: Some(false),
            method: None,
            crc: None,
            comment: None,
            link_target: entry.link_target,
            ..EngineEntry::default()
        })
        .collect()
}

fn virtual_disk_error(path: &std::path::Path, error: &virtual_disk_backend::VirtualDiskBackendError) -> ArchiveError {
    let kind = match error {
        virtual_disk_backend::VirtualDiskBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        virtual_disk_backend::VirtualDiskBackendError::Cancelled => ErrorKind::Cancelled,
        virtual_disk_backend::VirtualDiskBackendError::Io { .. } => ErrorKind::Io,
        virtual_disk_backend::VirtualDiskBackendError::Plan(_) => ErrorKind::InvalidFormat,
        virtual_disk_backend::VirtualDiskBackendError::Vfs(_) | virtual_disk_backend::VirtualDiskBackendError::NotDiskImage(_) => ErrorKind::CorruptData,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::NativeEntrySelector;
    use super::NativeReadAdapter as _;
    use super::NativeReadContext;
    use super::VirtualDiskListAdapter;
    use crate::archive_browser::BrowserEntryKind;
    use crate::engine::format::FormatId;
    use crate::engine::source::ArchiveSource;
    use crate::engine::types::{ArchiveListing, DetectedArchive, EngineEntry, EntryId, OpenOptions};
    use crate::test_support::TestDir;
    use std::io::Read as _;

    /// `descriptor` still routes per format through a `match` that ends in
    /// `unreachable!`, so a format accepted by `VirtualDiskListAdapter::new`
    /// but missing a descriptor arm would panic in production rather than fail
    /// to compile. Walk the accepted set so the gap is a test failure instead.
    #[test]
    fn every_accepted_virtual_disk_format_has_a_consistent_descriptor() {
        let accepted = [
            FormatId::VHD,
            FormatId::VMDK,
            FormatId::UDF,
            FormatId::ISO,
            FormatId::VDI,
            FormatId::NRG,
            FormatId::MDF,
            FormatId::CDI,
            FormatId::ISZ,
            FormatId::CCD,
            FormatId::CUE,
            FormatId::VHDX,
            FormatId::QCOW2,
            FormatId::EWF,
            FormatId::AD1,
            FormatId::DAR,
            FormatId::AFF4,
            FormatId::RAW_DISK,
        ];

        for format in accepted {
            let adapter = VirtualDiskListAdapter::new(format).unwrap_or_else(|| panic!("{format} must be accepted"));
            let descriptor = adapter.descriptor();
            assert_eq!(descriptor.format, format, "descriptor for {format} names a different format");
            for operation in
                [super::ArchiveOperation::List, super::ArchiveOperation::Extract, super::ArchiveOperation::Test, super::ArchiveOperation::CopyToWriter]
            {
                assert!(descriptor.operations.contains(&operation), "{format} descriptor is missing {operation:?}");
            }
            // Every accepted format must classify; `mount_class` is what `list`,
            // `extract`, `test`, and `copy_to_writer` all route through.
            assert!(VirtualDiskListAdapter::mounts_as_logical_container(format).is_some(), "{format} has no mount class");
        }

        // The logical containers are the only ones mounted permissively.
        for format in [FormatId::AD1, FormatId::DAR, FormatId::AFF4] {
            assert_eq!(VirtualDiskListAdapter::mounts_as_logical_container(format), Some(true), "{format}");
        }
        for format in [FormatId::VHD, FormatId::ISO, FormatId::VHDX, FormatId::QCOW2, FormatId::EWF, FormatId::RAW_DISK] {
            assert_eq!(VirtualDiskListAdapter::mounts_as_logical_container(format), Some(false), "{format}");
        }

        // A format this adapter does not own is rejected, not silently accepted.
        for format in [FormatId::ZIP, FormatId::TAR, FormatId::SQUASHFS, FormatId::WIM] {
            assert!(VirtualDiskListAdapter::new(format).is_none(), "{format} must not be accepted");
        }
    }

    #[test]
    fn native_session_context_owns_source_cursor_factory() {
        let temp = TestDir::new("native-session-context");
        let path = temp.path("payload.tar");
        temp.write_file("payload.tar", b"native cursor source");
        let archive = DetectedArchive { format: FormatId::TAR, source: ArchiveSource::Path(path.clone()) };
        let context = NativeReadContext::new(archive.source.cursor_factory(), OpenOptions::default());

        assert_eq!(context.cursor_factory.source().primary_path(), path);
        let mut cursor = context.open_primary_file().unwrap();
        let mut contents = Vec::new();
        cursor.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"native cursor source");
        assert_eq!(context.cursor_factory.source().primary_path(), path);
    }

    #[test]
    fn native_cursor_factory_clones_owned_source_descriptors() {
        let source = ArchiveSource::Path("archive.tar".into());
        let factory = source.cursor_factory();
        assert_eq!(factory.source(), &source);
    }

    #[test]
    fn retained_native_selector_preserves_duplicate_physical_occurrences() {
        let source = ArchiveSource::Path("archive.7z".into());
        let archive = DetectedArchive { format: FormatId::SEVEN_Z, source };
        let mut context = NativeReadContext::new(archive.source.cursor_factory(), OpenOptions::default());
        context.retain_listing(&ArchiveListing {
            entries: vec![
                EngineEntry { id: EntryId(4), path: "duplicate.txt".to_owned(), kind: BrowserEntryKind::File, ..EngineEntry::default() },
                EngineEntry { id: EntryId(9), path: "duplicate.txt".to_owned(), kind: BrowserEntryKind::File, ..EngineEntry::default() },
            ],
        });

        assert_eq!(
            context.retained_entry(EntryId(4)).unwrap(),
            &NativeEntrySelector { id: EntryId(4), path: "duplicate.txt".to_owned(), kind: BrowserEntryKind::File, occurrence: 0 }
        );
        assert_eq!(context.retained_entry(EntryId(9)).unwrap().occurrence, 1);
    }
}
