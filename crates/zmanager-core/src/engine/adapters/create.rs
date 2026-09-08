//! Native one-shot archive creation adapters (ARC-600/ARC-601).

use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterDescriptor, CreateAdapterFactory};
use crate::engine::types::{ArchiveError, ArchiveOperation, CreateOptions, CreateReport, CreateRequest, ErrorKind};
use crate::jobs::JobContext;

impl From<crate::engine::types::ZipCompression> for crate::zip_backend::ZipCompression {
    fn from(value: crate::engine::types::ZipCompression) -> Self {
        match value {
            crate::engine::types::ZipCompression::Store => Self::Store,
            crate::engine::types::ZipCompression::Deflate => Self::Deflate,
        }
    }
}

impl From<crate::engine::types::ZipCreateOptions> for crate::zip_backend::ZipCreateOptions {
    fn from(value: crate::engine::types::ZipCreateOptions) -> Self {
        Self {
            compression: value.compression.into(),
            level: value.level,
            preserve_metadata: value.preserve_metadata,
            replace_existing: value.replace_existing,
            password: value.password,
            volume_size: value.volume_size,
        }
    }
}

impl From<crate::engine::types::SevenZCreateOptions> for crate::sevenz_backend::SevenZCreateOptions {
    fn from(value: crate::engine::types::SevenZCreateOptions) -> Self {
        Self {
            solid: value.solid,
            level: value.level,
            threads: value.threads,
            chunk_size: value.chunk_size,
            preserve_metadata: value.preserve_metadata,
            password: value.password,
            encrypt_file_names: value.encrypt_file_names,
            replace_existing: value.replace_existing,
            volume_size: value.volume_size,
        }
    }
}

impl From<crate::engine::types::TarZstdCreateOptions> for crate::tar_zst_backend::TarZstdCreateOptions {
    fn from(value: crate::engine::types::TarZstdCreateOptions) -> Self {
        Self { level: value.level, threads: value.threads, preserve_metadata: value.preserve_metadata, replace_existing: value.replace_existing }
    }
}

impl From<crate::engine::types::TarGzCreateOptions> for crate::tar_gz_backend::TarGzCreateOptions {
    fn from(value: crate::engine::types::TarGzCreateOptions) -> Self {
        Self { level: value.level, preserve_metadata: value.preserve_metadata, replace_existing: value.replace_existing }
    }
}

impl From<crate::engine::types::AppleArchiveCompression> for crate::apple_archive_backend::AppleArchiveCompression {
    fn from(value: crate::engine::types::AppleArchiveCompression) -> Self {
        match value {
            crate::engine::types::AppleArchiveCompression::None => Self::None,
            crate::engine::types::AppleArchiveCompression::Lz4 => Self::Lz4,
            crate::engine::types::AppleArchiveCompression::Zlib => Self::Zlib,
            crate::engine::types::AppleArchiveCompression::Lzma => Self::Lzma,
            crate::engine::types::AppleArchiveCompression::Lzfse => Self::Lzfse,
            crate::engine::types::AppleArchiveCompression::Lzbitmap => Self::Lzbitmap,
        }
    }
}

impl From<crate::engine::types::AppleArchiveCreateOptions> for crate::apple_archive_backend::AppleArchiveCreateOptions {
    fn from(value: crate::engine::types::AppleArchiveCreateOptions) -> Self {
        Self {
            compression: value.compression.into(),
            block_size: value.block_size,
            threads: value.threads,
            preserve_metadata: value.preserve_metadata,
            replace_existing: value.replace_existing,
            password: value.password,
        }
    }
}

impl From<crate::engine::types::TzapRestorePolicy> for crate::tzap::TzapRestorePolicy {
    fn from(value: crate::engine::types::TzapRestorePolicy) -> Self {
        match value {
            crate::engine::types::TzapRestorePolicy::Content => Self::Content,
            crate::engine::types::TzapRestorePolicy::Portable => Self::Portable,
            crate::engine::types::TzapRestorePolicy::SameOs => Self::SameOs,
            crate::engine::types::TzapRestorePolicy::System => Self::System,
        }
    }
}

impl From<crate::engine::types::TzapRestoreOptions> for crate::tzap::TzapRestoreOptions {
    fn from(value: crate::engine::types::TzapRestoreOptions) -> Self {
        Self { policy: value.policy.into(), allow_degraded: value.allow_degraded, allow_absolute_symlinks: value.allow_absolute_symlinks }
    }
}

impl From<crate::engine::types::TzapX509TrustOptions> for crate::tzap::TzapX509TrustOptions {
    fn from(value: crate::engine::types::TzapX509TrustOptions) -> Self {
        Self {
            trusted_ca_certificates: value.trusted_ca_certificates,
            trusted_system_roots: value.trusted_system_roots,
            include_official_tzap_root: value.include_official_tzap_root,
        }
    }
}

impl From<crate::engine::types::TzapX509SigningOptions> for crate::tzap::TzapX509SigningOptions {
    fn from(value: crate::engine::types::TzapX509SigningOptions) -> Self {
        match value {
            crate::engine::types::TzapX509SigningOptions::Pkcs12 { identity, password } => Self::Pkcs12 { identity, password },
            crate::engine::types::TzapX509SigningOptions::CertificateAndKey { signing_certificate, signing_private_key, signing_chain } => {
                Self::CertificateAndKey { signing_certificate, signing_private_key, signing_chain }
            }
            crate::engine::types::TzapX509SigningOptions::InMemory { signing_certificate, signing_private_key, signing_chain } => {
                Self::InMemory { signing_certificate, signing_private_key, signing_chain }
            }
        }
    }
}

impl From<crate::tzap::TzapX509SigningOptions> for crate::engine::types::TzapX509SigningOptions {
    fn from(value: crate::tzap::TzapX509SigningOptions) -> Self {
        match value {
            crate::tzap::TzapX509SigningOptions::Pkcs12 { identity, password } => Self::Pkcs12 { identity, password },
            crate::tzap::TzapX509SigningOptions::CertificateAndKey { signing_certificate, signing_private_key, signing_chain } => {
                Self::CertificateAndKey { signing_certificate, signing_private_key, signing_chain }
            }
            crate::tzap::TzapX509SigningOptions::InMemory { signing_certificate, signing_private_key, signing_chain } => {
                Self::InMemory { signing_certificate, signing_private_key, signing_chain }
            }
        }
    }
}

impl From<crate::tzap::TzapX509VerificationReport> for crate::engine::types::TzapX509VerificationReport {
    fn from(value: crate::tzap::TzapX509VerificationReport) -> Self {
        Self {
            archive_root: value.archive_root,
            authenticator_id: value.authenticator_id,
            signer_identity_type: value.signer_identity_type,
            total_data_block_count: value.total_data_block_count,
            signed_at_unix_seconds: value.signed_at_unix_seconds,
            subject: value.subject,
            issuer: value.issuer,
            serial_number_hex: value.serial_number_hex,
            certificate_sha256: value.certificate_sha256,
            verified_chain_subjects: value.verified_chain_subjects,
            trust_anchor_subject: value.trust_anchor_subject,
            diagnostics: value.diagnostics,
        }
    }
}

impl From<crate::tzap::TzapX509SignerInspection> for crate::engine::types::TzapX509SignerInspection {
    fn from(value: crate::tzap::TzapX509SignerInspection) -> Self {
        Self {
            archive_root: value.archive_root,
            authenticator_id: value.authenticator_id,
            signer_identity_type: value.signer_identity_type,
            total_data_block_count: value.total_data_block_count,
            signed_at_unix_seconds: value.signed_at_unix_seconds,
            subject: value.subject,
            issuer: value.issuer,
            serial_number_hex: value.serial_number_hex,
            certificate_sha256: value.certificate_sha256,
            diagnostics: value.diagnostics,
        }
    }
}

impl From<crate::engine::types::TzapKeySource> for crate::tzap::TzapKeySource {
    fn from(value: crate::engine::types::TzapKeySource) -> Self {
        match value {
            crate::engine::types::TzapKeySource::Passphrase(password) => Self::Passphrase(password),
            crate::engine::types::TzapKeySource::RecipientCertificate(path) => Self::RecipientCertificate(path),
            crate::engine::types::TzapKeySource::RecipientCertificates(paths) => Self::RecipientCertificates(paths),
            crate::engine::types::TzapKeySource::RecipientPublicKeys(keys) => Self::RecipientPublicKeys(keys),
            crate::engine::types::TzapKeySource::NoPassword => Self::NoPassword,
        }
    }
}

impl From<crate::tzap::TzapKeySource> for crate::engine::types::TzapKeySource {
    fn from(value: crate::tzap::TzapKeySource) -> Self {
        match value {
            crate::tzap::TzapKeySource::Passphrase(password) => Self::Passphrase(password),
            crate::tzap::TzapKeySource::RecipientCertificate(path) => Self::RecipientCertificate(path),
            crate::tzap::TzapKeySource::RecipientCertificates(paths) => Self::RecipientCertificates(paths),
            crate::tzap::TzapKeySource::RecipientPublicKeys(keys) => Self::RecipientPublicKeys(keys),
            crate::tzap::TzapKeySource::NoPassword => Self::NoPassword,
        }
    }
}

impl From<crate::engine::types::TzapCreateOptions> for crate::tzap::TzapCreateOptions {
    fn from(value: crate::engine::types::TzapCreateOptions) -> Self {
        Self {
            key_source: value.key_source.into(),
            level: value.level,
            preserve_metadata: value.preserve_metadata,
            replace_existing: value.replace_existing,
            volume_size: value.volume_size,
            volume_count: value.volume_count,
            recovery_percentage: value.recovery_percentage,
            volume_loss_tolerance: value.volume_loss_tolerance,
            x509_signing: value.x509_signing.map(Into::into),
            emit_bootstrap_sidecar: value.emit_bootstrap_sidecar,
        }
    }
}

fn creation_error(path: &std::path::Path, error: impl std::fmt::Display) -> ArchiveError {
    let message = error.to_string();
    let lower = message.to_lowercase();
    let kind = if lower.contains("cancel") {
        ErrorKind::Cancelled
    } else if lower.contains("unsupported") {
        ErrorKind::UnsupportedOperation
    } else if lower.contains("permission") || lower.contains("i/o") || lower.contains("io failed") {
        ErrorKind::Io
    } else {
        ErrorKind::InvalidFormat
    };
    ArchiveError::usable(kind, message).with_path(path)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Native ZIP and split-ZIP writer.
#[derive(Debug, Default)]
pub struct ZipCreateAdapter;

impl CreateAdapterFactory for ZipCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_zip_creator",
            format: FormatId::ZIP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Zip(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "ZIP creator received non-ZIP options"));
        };
        let backend_options = crate::zip_backend::ZipCreateOptions::from(options.clone());
        let report = crate::zip_backend::create_zip_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::ZIP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }

    fn create_to_writer(&self, request: &CreateRequest, writer: &mut dyn std::io::Write, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Zip(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "ZIP creator received non-ZIP options"));
        };
        let backend_options = crate::zip_backend::ZipCreateOptions::from(options.clone());
        context.check_cancelled().map_err(|_| ArchiveError::usable(ErrorKind::Cancelled, "ZIP creation was cancelled"))?;
        if options.volume_size.is_some() {
            return Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "streaming ZIP output cannot be split"));
        }
        let (_, report) = crate::zip_backend::create_zip_stream_from_manifest(&request.manifest, writer, &backend_options)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::ZIP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native standard split-ZIP writer.
#[derive(Debug, Default)]
pub struct SplitZipCreateAdapter;

impl CreateAdapterFactory for SplitZipCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_split_zip_creator",
            format: FormatId::SPLIT_ZIP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Zip(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "split ZIP creator received non-ZIP options"));
        };
        if options.volume_size.is_none() {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "split ZIP creation requires a volume size"));
        }
        let backend_options = crate::zip_backend::ZipCreateOptions::from(options.clone());
        let report = crate::zip_backend::create_zip_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::SPLIT_ZIP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native 7z writer.
#[derive(Debug, Default)]
pub struct SevenZCreateAdapter;

impl CreateAdapterFactory for SevenZCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_7z_creator",
            format: FormatId::SEVEN_Z,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::SevenZ(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "7z creator received non-7z options"));
        };
        let backend_options = crate::sevenz_backend::SevenZCreateOptions::from(options.clone());
        let report = crate::sevenz_backend::create_7z_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::SEVEN_Z,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(report.encrypted),
            solid: Some(report.solid),
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native TAR.ZST writer.
#[derive(Debug, Default)]
pub struct TarZstdCreateAdapter;

impl CreateAdapterFactory for TarZstdCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tar_zstd_creator",
            format: FormatId::TAR_ZST,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: false,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::TarZstd(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TAR.ZST creator received non-TAR.ZST options"));
        };
        let backend_options = crate::tar_zst_backend::TarZstdCreateOptions::from(options.clone());
        let report = crate::tar_zst_backend::create_tar_zst_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::TAR_ZST,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}

/// Native TAR.GZ writer.
#[derive(Debug, Default)]
pub struct TarGzCreateAdapter;

impl CreateAdapterFactory for TarGzCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tar_gz_creator",
            format: FormatId::TAR_GZ,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: false,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::TarGz(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TAR.GZ creator received non-TAR.GZ options"));
        };
        let backend_options = crate::tar_gz_backend::TarGzCreateOptions::from(options.clone());
        let report = crate::tar_gz_backend::create_tar_gz_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::TAR_GZ,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}

/// Native TZAP writer.
#[derive(Debug, Default)]
pub struct TzapCreateAdapter;

impl CreateAdapterFactory for TzapCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_tzap_creator",
            format: FormatId::TZAP,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::Tzap(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "TZAP creator received non-TZAP options"));
        };
        let backend_options = crate::tzap::TzapCreateOptions::from(options.clone());
        let report = crate::tzap::create_tzap_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
            .map_err(|error| creation_error(&request.destination, error))?;
        let encrypted = !matches!(&backend_options.key_source, crate::tzap::TzapKeySource::NoPassword);
        Ok(CreateReport {
            format: FormatId::TZAP,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: count(report.volume_count),
            warnings: report.warnings,
        })
    }
}

/// Native Apple Archive writer.
#[derive(Debug, Default)]
pub struct AppleArchiveCreateAdapter;

impl CreateAdapterFactory for AppleArchiveCreateAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        static DESCRIPTOR: AdapterDescriptor = AdapterDescriptor {
            name: "native_apple_archive_creator",
            format: FormatId::APPLE_ARCHIVE,
            operations: &[ArchiveOperation::Create],
            required_source_access: crate::engine::source::SourceAccess::Seekable,
            supports_encryption: true,
        };
        &DESCRIPTOR
    }

    fn create(&self, request: &CreateRequest, context: &mut JobContext<'_>) -> Result<CreateReport, ArchiveError> {
        let CreateOptions::AppleArchive(options) = &request.options else {
            return Err(ArchiveError::usable(ErrorKind::InvalidFormat, "Apple Archive creator received non-Apple Archive options"));
        };
        let backend_options = crate::apple_archive_backend::AppleArchiveCreateOptions::from(options.clone());
        let report =
            crate::apple_archive_backend::create_apple_archive_from_manifest_with_context(&request.manifest, &request.destination, &backend_options, context)
                .map_err(|error| creation_error(&request.destination, error))?;
        Ok(CreateReport {
            format: FormatId::APPLE_ARCHIVE,
            written_entries: count(report.written_entries),
            written_bytes: report.written_bytes,
            encrypted: Some(backend_options.password.is_some()),
            solid: None,
            volume_size: None,
            volume_count: 1,
            warnings: report.warnings,
        })
    }
}
