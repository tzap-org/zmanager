//! Stateful archive engine and adapter seam (ARC-100 to ARC-111).

pub(crate) mod adapters;
pub mod format;
pub mod handle;
pub mod plugins;
pub mod registry;
pub mod source;
pub mod types;

use std::sync::Arc;

pub use format::FormatId;
pub use handle::{ArchiveEngine, ArchiveHandle};
pub use plugins::{ArchivePlugin, build_engine_with_plugins};
pub use registry::{AdapterDescriptor, AdapterRegistry, ArchiveEngineBuilder, CreateAdapterFactory, ReadAdapterFactory, ReadAdapterSession};
pub use source::{ArchiveSource, SourceAccess, SourceFingerprint, discover_split_zip_volumes, is_split_zip_archive_path};
pub use types::{
    AppleArchiveCompression, AppleArchiveCreateOptions, ArchiveError, ArchiveListing, ArchiveOperation, ArchivePluginRole, CopyReport, CreateOptions,
    CreateReport, CreateRequest, CredentialRequirement, DetectedArchive, EngineEntry, EntryId, ErrorKind, ExtractOptions, ExtractReport, FormatCapabilities,
    HandleCapabilities, NavigationMode, OpenLimits, OpenOptions, SelectedExtractOptions, SessionDisposition, SevenZCreateOptions, TarGzCreateOptions,
    TarZstdCreateOptions, TestOptions, TestReport, TzapCreateOptions, TzapKeySource, TzapRestoreOptions, TzapRestorePolicy, TzapX509SignerInspection,
    TzapX509SigningOptions, TzapX509TrustOptions, TzapX509VerificationReport, ZipCompression, ZipCreateOptions,
};

/// Engine-owned TZAP protocol operations used by hosted orchestration.
///
/// The archive implementation remains private to `zmanager-core`; callers
/// consume this narrow protocol seam instead of importing backend modules.
pub mod tzap {
    pub use crate::tzap::{
        TzapArchiveSignatureCheck, TzapArchiveSignerDetails, TzapArchiveStatusCheck, TzapArchiveTimeCheck, TzapArchiveTrustCheck, TzapArchiveVerification,
        TzapArchiveVerificationOutcome, TzapError, TzapPublicDisplaySummary, TzapPublicMetadataSummary, TzapPublicSignatureStatus, TzapPublicVolumeSummary,
        TzapTestReport, TzapX509SignerInspection, TzapX509SigningOptions, TzapX509TrustAnchor, TzapX509TrustOptions, TzapX509VerificationReport,
        inspect_tzap_x509_public_no_key_signer, inspect_tzap_x509_signer, resolve_default_signing_certificate_id, summarize_tzap_public_display,
        summarize_tzap_public_metadata, test_tzap_with_optional_password_filter_and_x509_trust, tzap_bootstrap_sidecar_path,
        tzap_x509_signing_options_from_inventory, verify_tzap_archive_public_no_key, verify_tzap_archive_public_no_key_with_signer_predicate,
        verify_tzap_x509_public_no_key,
    };
}

/// Returns whether a path is a supported raw single-file stream.
#[must_use]
pub fn is_raw_stream_path(path: impl AsRef<std::path::Path>) -> bool {
    crate::raw_stream_backend::detect_raw_stream_format(path).is_some()
}

/// Returns whether a path belongs to a TZAP archive or its volume set.
#[must_use]
pub fn is_tzap_archive_path(path: impl AsRef<std::path::Path>) -> bool {
    crate::tzap::is_tzap_archive_path(path.as_ref())
}

/// Returns whether a TZAP archive has any existing input volume.
#[must_use]
pub fn has_existing_tzap_input_volume(path: impl AsRef<std::path::Path>) -> bool {
    crate::tzap::has_existing_tzap_input_volume(path.as_ref())
}

/// Returns whether a path resolves to an existing 7z input file or volume
/// set through the engine's native 7z discovery rules.
#[must_use]
pub fn has_existing_7z_input_volume(path: impl AsRef<std::path::Path>) -> bool {
    crate::sevenz_backend::has_existing_7z_input(path.as_ref())
}

/// Returns the raw stream suffixes recognized by the engine.
#[must_use]
pub const fn raw_stream_suffixes() -> &'static [&'static str] {
    crate::raw_stream_backend::RAW_STREAM_SUFFIXES
}

/// Verifies a TZAP X.509 `RootAuth` footer through the engine-owned contract.
pub fn verify_tzap_x509_public_no_key(archive: impl AsRef<std::path::Path>, trust: &TzapX509TrustOptions) -> Result<TzapX509VerificationReport, ArchiveError> {
    let archive = archive.as_ref();
    let backend_trust = crate::tzap::TzapX509TrustOptions::from(trust.clone());
    crate::tzap::verify_tzap_x509_public_no_key(archive, &backend_trust)
        .map(Into::into)
        .map_err(|error| ArchiveError::usable(ErrorKind::CorruptData, error.to_string()).with_path(archive))
}

/// Inspects a TZAP X.509 `RootAuth` signer through the engine-owned contract.
pub fn inspect_tzap_x509_public_no_key_signer(archive: impl AsRef<std::path::Path>) -> Result<TzapX509SignerInspection, ArchiveError> {
    let archive = archive.as_ref();
    crate::tzap::inspect_tzap_x509_public_no_key_signer(archive)
        .map(Into::into)
        .map_err(|error| ArchiveError::usable(ErrorKind::CorruptData, error.to_string()).with_path(archive))
}

/// Default compile-time plugin packaging for Phase 1 listing.
#[derive(Debug, Default)]
pub struct DefaultArchivePlugin;

impl ArchivePlugin for DefaultArchivePlugin {
    fn name(&self) -> &'static str {
        "default_archive_plugin"
    }

    fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError> {
        // Native ZIP adapters
        builder.register_read_adapter(Arc::new(adapters::zip::ZipListAdapter::single_volume()))?;
        builder.register_read_adapter(Arc::new(adapters::zip::ZipListAdapter::split_volume()))?;

        // Native adapters for 7z, TAR.ZST, TZAP, RAR, LHA, RawStreams, Apple Archive, DMG, PKG, MSI, VirtualDisks
        builder.register_read_adapter(Arc::new(adapters::native::SevenZListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarZstListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarGzListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_BZ2,
            crate::raw_stream_backend::RawStreamFormat::Bzip2,
            "bzip2",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_XZ,
            crate::raw_stream_backend::RawStreamFormat::Xz,
            "xz",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_LZMA,
            crate::raw_stream_backend::RawStreamFormat::Lzma,
            "lzma",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_LZ,
            crate::raw_stream_backend::RawStreamFormat::Lzip,
            "lzip",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_LZO,
            crate::raw_stream_backend::RawStreamFormat::Lzo,
            "lzop",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_COMPRESS,
            crate::raw_stream_backend::RawStreamFormat::UnixCompress,
            "compress",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_LZ4,
            crate::raw_stream_backend::RawStreamFormat::Lz4,
            "lz4",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_UU,
            crate::raw_stream_backend::RawStreamFormat::Uu,
            "uuencode",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::ArListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::CpioListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::DebListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::RpmListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::CabListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::XarListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::LhaListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::WarcListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::MtreeListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TzapListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::RarListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::RawStreamListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::AppleArchiveListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::DmgListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::PkgListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::MsiListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::SquashfsListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::AppImageListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::WimListAdapter))?;
        for format in [
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
        ] {
            let adapter = adapters::native::VirtualDiskListAdapter::new(format)
                .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("unsupported virtual disk adapter format '{format}'")))?;
            builder.register_read_adapter(Arc::new(adapter))?;
        }

        // Native one-shot creation adapters.
        builder.register_create_adapter(Arc::new(adapters::create::ZipCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::SplitZipCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::SevenZCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TarZstdCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TarGzCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TzapCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::AppleArchiveCreateAdapter))?;

        Ok(())
    }
}

/// Creates a default pre-configured `ArchiveEngine` containing Phase 1 listing adapters.
///
/// # Errors
///
/// Returns `ArchiveError` if plugin registration fails.
pub fn create_default_engine() -> Result<ArchiveEngine, ArchiveError> {
    build_engine_with_plugins(&[&DefaultArchivePlugin])
}

/// Runs a complete extraction through the default engine and returns its
/// normalized report.
pub fn extract_with_default_engine<'a>(
    source: ArchiveSource,
    open_options: OpenOptions,
    options: &'a mut ExtractOptions<'a>,
) -> Result<ExtractReport, ArchiveError> {
    let engine = create_default_engine()?;
    let mut handle = engine.open(source, open_options)?;
    handle.extract(options)
}
