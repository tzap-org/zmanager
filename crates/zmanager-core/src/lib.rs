//! Core engine primitives for `ZManager`.

// The public API predates the workspace-wide pedantic lint policy. Error
// documentation is tracked separately from behavioral and structural cleanup.
#![allow(clippy::missing_errors_doc)]

/// Generates the standard `From` impls shared by the archive-backend error
/// enums: planning, extraction safety, and cooperative cancellation (the
/// latter as a unit `Cancelled` variant). Backends without one of the
/// variants (for example the create-only tar.gz backend) keep their impls
/// written out.
#[macro_export]
macro_rules! backend_error_from_impls {
    ($error:ty) => {
        impl From<$crate::manifest::PlanError> for $error {
            fn from(source: $crate::manifest::PlanError) -> Self {
                Self::Plan(source)
            }
        }
        impl From<$crate::safety::ExtractionSafetyError> for $error {
            fn from(source: $crate::safety::ExtractionSafetyError) -> Self {
                Self::Safety(source)
            }
        }
        impl From<$crate::jobs::JobCancelled> for $error {
            fn from(_source: $crate::jobs::JobCancelled) -> Self {
                Self::Cancelled
            }
        }
    };
}

pub mod archive_format;
mod archive_split;
mod atomic_file;
mod backend_impl;
mod extract_loop;
mod extract_materialize;
mod gitignore;
mod segmented_reader;
mod sevenz_volume;
mod strings;
pub(crate) use backend_impl::mtree_backend;
pub(crate) use backend_impl::{
    apple_archive_backend, apple_dmg_backend, apple_pkg_backend, ar_backend, cab_backend, cpio_backend, deb_backend, lha_backend, lzop_decoder, msi_backend,
    rar_backend, raw_stream_backend, rpm_backend, sevenz_backend, squashfs_backend, tar_backend, tar_gz_backend, tar_zst_backend, unix_compress_decoder,
    uu_decoder, virtual_disk_backend, warc_backend, wim_backend, xar_backend, zip_backend,
};
mod tar_metadata;
mod temp_names;
#[cfg(test)]
mod test_support;
mod tzap;
pub(crate) mod wildcard;
#[doc(hidden)]
mod x509_fixture;
mod zip_split;

// Offline identity, catalog, signing, and verification remain part of the
// core contract in every profile. Hosted account, enrollment, status, and
// JSON-service modules are enabled only by the explicit hosted profile crate.
// Offline identity files retain the historical auth directory for source
// grouping, while their ownership is explicit at the crate root.
#[path = "auth/contact_card.rs"]
pub mod contact_card;
#[path = "auth/contact_snapshot.rs"]
pub mod contact_snapshot;
#[path = "auth/device_identity.rs"]
pub mod device_identity;
#[path = "auth/document_envelope.rs"]
pub mod document_envelope;
#[path = "auth/document_signing.rs"]
pub mod document_signing;
#[path = "auth/document_verification.rs"]
pub mod document_verification;
#[path = "auth/identity_catalog.rs"]
pub mod identity_catalog;
#[path = "auth/identity_migration.rs"]
pub mod identity_migration;
#[path = "auth/jcs.rs"]
pub mod jcs;
#[path = "auth/json_util.rs"]
pub(crate) mod json_util;
#[path = "auth/key_backup.rs"]
pub mod key_backup;
#[path = "auth/local_identity_store.rs"]
pub mod local_identity_store;
#[path = "auth/p256_signature.rs"]
pub mod p256_signature;

pub mod archive_browser;
pub mod engine;
pub mod jobs;
pub mod manifest;
pub mod safety;
pub mod secrets;
pub mod trust;
pub mod x509_format;

/// Hidden fixture-only access to adapter implementations.
///
/// Production callers must use [`engine`]. This compatibility namespace is
/// retained only because Cargo integration tests and sibling crate test
/// harnesses compile as external consumers; it is deliberately hidden from
/// generated API documentation and is not a supported product contract.
#[doc(hidden)]
pub mod backend_test_support {
    pub use super::backend_impl::mtree_backend;
    pub use super::backend_impl::{
        apple_archive_backend, apple_dmg_backend, apple_pkg_backend, ar_backend, cab_backend, cpio_backend, deb_backend, lha_backend, msi_backend, rar_backend,
        raw_stream_backend, rpm_backend, sevenz_backend, squashfs_backend, tar_backend, tar_gz_backend, tar_zst_backend, virtual_disk_backend, warc_backend,
        wim_backend, xar_backend, zip_backend,
    };
    pub mod tzap {
        pub use crate::tzap::*;
    }
    pub mod gitignore {
        pub use crate::gitignore::*;
    }
    pub mod jobs {
        pub use crate::jobs::ProgressCoalescer;
    }
    /// Real, signature-valid X.509 certificate chains for exercising
    /// signature/chain verification (contact cards, document envelopes, ...)
    /// from a sibling crate's own test harness.
    pub mod x509_factory {
        pub use crate::x509_fixture::*;
    }
}

mod hex;

/// The stable engine name used in diagnostics and health checks.
pub const ENGINE_NAME: &str = "zmanager-core";

/// Atomically writes secret material with the platform's private-file policy.
///
/// This small storage primitive is shared by offline identity migration and
/// the hosted session store; it contains no hosted protocol behavior.
pub fn write_atomic_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_file::write_atomic_secret_file(path, bytes)
}

pub(crate) const DEFAULT_IO_BUFFER_BYTES: usize = 128 * 1024;
pub(crate) const MEBIBYTE_BYTES: u64 = 1024 * 1024;

/// A minimal report proving that the Rust engine can be called.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HealthReport {
    /// Engine component that produced the report.
    pub engine: &'static str,
    /// Core crate version.
    pub version: &'static str,
    /// Whether the core crate considers itself ready to accept jobs.
    pub ready: bool,
}

impl HealthReport {
    /// Returns a human-readable one-line summary for CLI output.
    #[must_use]
    pub fn summary(&self) -> String {
        let status = if self.ready { "ready" } else { "not ready" };
        format!("{} {} ({status})", self.engine, self.version)
    }
}

/// Runs a lightweight engine health check.
#[must_use]
pub fn healthcheck() -> HealthReport {
    HealthReport { engine: ENGINE_NAME, version: env!("CARGO_PKG_VERSION"), ready: true }
}

#[cfg(test)]
mod tests {
    use super::{ENGINE_NAME, healthcheck};

    #[test]
    fn healthcheck_reports_ready_core() {
        let report = healthcheck();

        assert_eq!(report.engine, ENGINE_NAME);
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert!(report.ready);
    }

    #[test]
    fn healthcheck_summary_is_stable() {
        let report = healthcheck();
        let expected = format!("zmanager-core {} (ready)", env!("CARGO_PKG_VERSION"));

        assert_eq!(report.summary(), expected);
    }
}
