//! Core engine primitives for `ZManager`.

mod atomic_file;

pub mod apple_archive_backend;
pub mod archive_browser;
pub mod auth_client;
pub mod certificate_lifecycle;
pub mod contact_card;
pub mod deb_backend;
pub mod device_identity;
pub mod document_envelope;
pub mod document_signing;
pub mod document_verification;
pub mod enrollment_client;
pub mod jcs;
pub mod jobs;
pub mod libarchive_backend;
pub mod local_fake_tzap;
pub mod local_identity_store;
pub mod manifest;
pub mod p256_signature;
pub mod rar_backend;
pub mod raw_stream_backend;
pub mod safety;
pub mod secrets;
pub mod sevenz_backend;
pub mod status_client;
pub mod tar_gz_backend;
pub mod tar_zst_backend;
pub mod trust;
pub mod tzap_backend;
pub mod x509_format;
pub mod zip_backend;

/// The stable engine name used in diagnostics and health checks.
pub const ENGINE_NAME: &str = "zmanager-core";

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
    HealthReport {
        engine: ENGINE_NAME,
        version: env!("CARGO_PKG_VERSION"),
        ready: true,
    }
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
