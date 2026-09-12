//! Native ZIP listing adapter for single and supported split ZIP archives (ARC-106).

use std::path::PathBuf;
use std::sync::Arc;
use zip::ZipArchive;

use crate::archive_browser::BrowserEntryKind;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, ReadAdapterFactory, ReadAdapterSession};
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, OpenOptions,
    SelectedExtractOptions, TestOptions, TestReport,
};
use crate::zip_backend::ZipBackendError;

static ZIP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_zip_lister",
    format: FormatId::ZIP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::Seekable,
    supports_encryption: true,
};

static SPLIT_ZIP_LIST_DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
    name: "native_split_zip_lister",
    format: FormatId::SPLIT_ZIP,
    operations: &[ArchiveOperation::List, ArchiveOperation::Test, ArchiveOperation::Extract, ArchiveOperation::SelectedExtract, ArchiveOperation::CopyToWriter],
    required_source_access: SourceAccess::MultiVolumeSet,
    supports_encryption: true,
};

/// Native ZIP read adapter factory.
#[derive(Debug, Default)]
pub struct ZipListAdapter {
    format: FormatId,
}

impl ZipListAdapter {
    /// Creates a native ZIP list adapter factory for standard single-volume ZIP.
    #[must_use]
    pub const fn single_volume() -> Self {
        Self { format: FormatId::ZIP }
    }

    /// Creates a native ZIP list adapter factory for split-volume ZIP.
    #[must_use]
    pub const fn split_volume() -> Self {
        Self { format: FormatId::SPLIT_ZIP }
    }
}

struct ZipReadSession {
    archive: ZipArchive<Box<dyn crate::zip_split::ReadSeek>>,
    path: PathBuf,
    password: Option<String>,
    retained_entries: Vec<(EntryId, usize)>,
}

fn zip_archive_error(path: &std::path::Path, error: &ZipBackendError) -> ArchiveError {
    let kind = match &error {
        ZipBackendError::PasswordRequired => ErrorKind::PasswordRequired,
        ZipBackendError::InvalidPassword => ErrorKind::WrongPassword,
        ZipBackendError::Cancelled => ErrorKind::Cancelled,
        ZipBackendError::Safety(source) => crate::engine::adapters::safety_error_kind(source),
        ZipBackendError::Io { .. } => ErrorKind::Io,
        ZipBackendError::UnsupportedSplitZip { .. } => ErrorKind::UnsupportedOperation,
        ZipBackendError::Zip(_) | ZipBackendError::InvalidSymlinkTarget { .. } | ZipBackendError::VolumeSizeTooSmall { .. } => ErrorKind::CorruptData,
        ZipBackendError::Plan(_) => ErrorKind::InvalidFormat,
    };
    crate::engine::adapters::adapter_error(path, kind, error.to_string())
}

impl ReadAdapterSession for ZipReadSession {
    fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
        crate::zip_backend::list_zip_archive(&mut self.archive).map_err(|error| zip_archive_error(&self.path, &error)).map(|listing| {
            let mut entries = Vec::with_capacity(listing.entries.len());
            self.retained_entries.clear();
            for (index, entry) in listing.entries.into_iter().enumerate() {
                let id = crate::engine::adapters::listing_entry_id(index);
                self.retained_entries.push((id, index));
                entries.push(EngineEntry {
                    id,
                    path: entry.name,
                    kind: match entry.kind {
                        crate::zip_backend::ZipEntryKind::Directory => BrowserEntryKind::Directory,
                        crate::zip_backend::ZipEntryKind::Symlink => BrowserEntryKind::Symlink,
                        crate::zip_backend::ZipEntryKind::File => BrowserEntryKind::File,
                    },
                    size: Some(entry.size),
                    compressed_size: Some(entry.compressed_size),
                    encrypted: Some(entry.encrypted),
                    mode: entry.unix_mode,
                    method: Some(entry.method),
                    crc: Some(entry.crc),
                    comment: entry.comment,
                    ..EngineEntry::default()
                });
            }
            ArchiveListing { entries }
        })
    }

    fn test(&mut self, options: &TestOptions) -> Result<TestReport, ArchiveError> {
        if options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "ZIP test was cancelled").with_path(&self.path));
        }
        let report = crate::zip_backend::test_zip_archive(
            &mut self.archive,
            &self.path,
            self.password.as_deref(),
            || options.is_cancelled(),
            |path| options.selects(path),
        )
        .map_err(|error| zip_archive_error(&self.path, &error))?;
        Ok(TestReport {
            tested_entries: u64::try_from(report.tested_entries).unwrap_or(u64::MAX),
            skipped_entries: u64::try_from(report.skipped_entries).unwrap_or(u64::MAX),
            tested_bytes: report.tested_bytes,
            warnings: Vec::new(),
        })
    }

    fn extract<'a>(&mut self, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        let dummy_token = crate::jobs::CancellationToken::new();
        let token = options.cancellation.as_ref().unwrap_or(&dummy_token);
        let mut noop_sink = |_event: crate::jobs::JobEvent| {};
        let sink: &mut dyn crate::jobs::JobEventSink = match options.event_sink.as_mut() {
            Some(s) => &mut **s,
            None => &mut noop_sink,
        };
        let mut context = crate::jobs::JobContext::new(token, sink);
        let report = crate::zip_backend::extract_zip_archive(
            &mut self.archive,
            &self.path,
            &options.destination,
            options.policy.clone(),
            self.password.as_deref(),
            options.cancellation.as_ref(),
            Some(&mut context),
            options.overwrite_resolver.as_deref_mut(),
            None,
        )
        .map_err(|error| zip_archive_error(&self.path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract(&mut self, entry_id: EntryId, options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        let entry_index = self
            .retained_entries
            .iter()
            .find_map(|(retained_id, index)| (*retained_id == entry_id).then_some(*index))
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("ZIP entry ID {entry_id} is not present in the session listing")))?;
        let dummy_token = crate::jobs::CancellationToken::new();
        let token = options.cancellation.as_ref().unwrap_or(&dummy_token);
        let mut noop_sink = |_event: crate::jobs::JobEvent| {};
        let sink: &mut dyn crate::jobs::JobEventSink = match options.event_sink.as_mut() {
            Some(s) => &mut **s,
            None => &mut noop_sink,
        };
        let mut context = crate::jobs::JobContext::new(token, sink);
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let report = crate::zip_backend::extract_zip_archive(
            &mut self.archive,
            &self.path,
            &options.destination,
            options.policy.clone(),
            self.password.as_deref(),
            options.cancellation.as_ref(),
            Some(&mut context),
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
            Some(&[entry_index]),
        )
        .map_err(|error| zip_archive_error(&self.path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn selected_extract_many(&mut self, entry_ids: &[EntryId], options: &mut SelectedExtractOptions<'_>) -> Result<ExtractReport, ArchiveError> {
        let mut indices = Vec::with_capacity(entry_ids.len());
        for &entry_id in entry_ids {
            let entry_index = self
                .retained_entries
                .iter()
                .find_map(|(retained_id, index)| (*retained_id == entry_id).then_some(*index))
                .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("ZIP entry ID {entry_id} is not present in the session listing")))?;
            indices.push(entry_index);
        }
        let dummy_token = crate::jobs::CancellationToken::new();
        let token = options.cancellation.as_ref().unwrap_or(&dummy_token);
        let mut noop_sink = |_event: crate::jobs::JobEvent| {};
        let sink: &mut dyn crate::jobs::JobEventSink = match options.event_sink.as_mut() {
            Some(s) => &mut **s,
            None => &mut noop_sink,
        };
        let mut context = crate::jobs::JobContext::new(token, sink);
        let mut reborrowed_resolver = options.overwrite_resolver.as_deref_mut().map(crate::safety::ReborrowedResolver::new);
        let report = crate::zip_backend::extract_zip_archive(
            &mut self.archive,
            &self.path,
            &options.destination,
            options.policy.clone(),
            self.password.as_deref(),
            options.cancellation.as_ref(),
            Some(&mut context),
            reborrowed_resolver.as_mut().map(|resolver| resolver as &mut dyn crate::safety::OverwriteResolver),
            Some(&indices),
        )
        .map_err(|error| zip_archive_error(&self.path, &error))?;
        Ok(crate::engine::adapters::extract_report(report.written_entries, report.skipped_entries, report.written_bytes, report.warnings))
    }

    fn copy_to_writer(&mut self, entry_id: EntryId, writer: &mut dyn std::io::Write) -> Result<CopyReport, ArchiveError> {
        let entry_index = self
            .retained_entries
            .iter()
            .find_map(|(retained_id, index)| (*retained_id == entry_id).then_some(*index))
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("ZIP entry ID {entry_id} is not present in the session listing")))?;
        let written_bytes = crate::zip_backend::copy_zip_entry_from_archive(&mut self.archive, &self.path, self.password.as_deref(), entry_index, writer)
            .map_err(|error| zip_archive_error(&self.path, &error))?;
        Ok(CopyReport { written_bytes })
    }
}

impl ReadAdapterFactory for ZipListAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        if self.format == FormatId::SPLIT_ZIP { &SPLIT_ZIP_LIST_DESCRIPTOR } else { &ZIP_LIST_DESCRIPTOR }
    }

    fn open(self: Arc<Self>, archive: DetectedArchive, options: OpenOptions) -> Result<Box<dyn ReadAdapterSession>, ArchiveError> {
        let path = archive.source.primary_path().to_path_buf();
        let reader: Box<dyn crate::zip_split::ReadSeek> = if archive.source.paths().len() == 1 {
            // Single-file source: the cursor comes from the session-owned
            // source capability, never a caller-side path open.
            let file = archive
                .source
                .cursor_factory()
                .open_primary_file()
                .map_err(|source| zip_archive_error(&path, &ZipBackendError::Io { path: path.clone(), source }))?;
            Box::new(file)
        } else {
            // Explicit caller-owned volume set: the split readers open the
            // owned paths directly; the pre/post-operation source fingerprint
            // guards membership and mutation of every volume.
            crate::zip_split::open_zip_reader_from_paths(archive.source.paths()).map_err(|error| zip_archive_error(&path, &error))?
        };
        let zip_archive = ZipArchive::new(reader)
            .map_err(|error| ArchiveError::unusable(ErrorKind::CorruptData, format!("Failed to parse ZIP central directory: {error}")).with_path(&path))?;
        Ok(Box::new(ZipReadSession { archive: zip_archive, path, password: options.password, retained_entries: Vec::new() }))
    }
}
