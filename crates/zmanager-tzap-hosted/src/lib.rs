//! Hosted TZAP integration profile.
//!
//! `zmanager-core` is the offline archive and identity engine. This crate owns
//! hosted account, enrollment, status, local hosted-service orchestration, and
//! the HTTP transport seam. Shared offline domain modules are consumed from
//! the core crate, while hosted implementation modules are physically local.

// This crate preserves a mature hosted API surface moved out of core. Its
// error contracts are typed and tested; documenting every pre-existing
// fallible method is a separate documentation pass rather than a reason to
// leave clippy noise in the new product boundary.
#![allow(clippy::missing_errors_doc)]

mod hex;
mod json_util;
mod wire_profile;

pub use zmanager_core::{
    contact_card, device_identity, document_envelope, document_signing, document_verification, engine, identity_catalog, jcs, jobs, local_identity_store,
    manifest, p256_signature, safety, secrets, trust, x509_format,
};

#[cfg(any(not(feature = "keyring"), test))]
pub(crate) fn write_atomic_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    zmanager_core::write_atomic_secret_file(path, bytes)
}

#[path = "auth/auth_client.rs"]
pub mod auth_client;
#[path = "auth/backup_client.rs"]
pub mod backup_client;
#[path = "auth/certificate_lifecycle.rs"]
pub mod certificate_lifecycle;
#[path = "auth/crl.rs"]
pub(crate) mod crl;
#[path = "auth/enrollment_client.rs"]
pub mod enrollment_client;
#[path = "auth/http_client.rs"]
pub(crate) mod http_client;
#[path = "auth/intermediate_client.rs"]
pub mod intermediate_client;
#[cfg(feature = "keyring")]
#[path = "auth/keyring_store.rs"]
pub mod keyring_store;
#[path = "auth/local_tzap_service.rs"]
pub mod local_tzap_service;
#[cfg(feature = "reqwest-transport")]
#[path = "auth/reqwest_transport.rs"]
pub mod reqwest_transport;
#[path = "auth/status_client.rs"]
pub mod status_client;
#[path = "auth/tzap_service.rs"]
pub mod tzap_service;
#[path = "auth/tzap_service_auth.rs"]
pub mod tzap_service_auth;
