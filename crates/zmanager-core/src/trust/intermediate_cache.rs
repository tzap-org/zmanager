//! Local cache for intermediate certificates keyed by SHA-256 (design §7, Z4).
//!
//! Compact contact cards omit `intermediate_chain_der` to fit comfortably in
//! QR codes. Verifiers consult this local cache by the leaf certificate's
//! Authority Key Identifier (AKI) to assemble the full chain before
//! profile validation.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::trust::certificate_profile::{authority_key_identifier, subject_key_identifier};
use crate::trust::{format_certificate_sha256, parse_certificate_sha256};

/// Extracts the Authority Key Identifier (AKI) extension from a DER certificate.
#[must_use]
pub fn extract_authority_key_identifier(cert_der: &[u8]) -> Option<Vec<u8>> {
    X509Certificate::from_der(cert_der).ok().and_then(|(_, cert)| authority_key_identifier(&cert))
}

/// Extracts the Subject Key Identifier (SKI) extension from a DER certificate.
#[must_use]
pub fn extract_subject_key_identifier(cert_der: &[u8]) -> Option<Vec<u8>> {
    X509Certificate::from_der(cert_der).ok().and_then(|(_, cert)| subject_key_identifier(&cert))
}

#[derive(Debug)]
pub enum TzapIntermediateCacheError {
    Io(std::io::Error),
    CertificateParse(String),
    InvalidFingerprint(String),
}

impl fmt::Display for TzapIntermediateCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cache I/O error: {error}"),
            Self::CertificateParse(error) => write!(f, "invalid cached certificate: {error}"),
            Self::InvalidFingerprint(fp) => write!(f, "invalid certificate fingerprint: {fp}"),
        }
    }
}

impl std::error::Error for TzapIntermediateCacheError {}

impl From<std::io::Error> for TzapIntermediateCacheError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapIntermediateResolveError {
    /// The intermediate certificate was not in the local cache and an online
    /// fetch could not be performed (e.g. offline, connection refused, or no
    /// network endpoint configured).
    OfflineMiss {
        issuer_key_identifier: String,
        reason: String,
    },
    NotFound {
        issuer_key_identifier: String,
    },
    InvalidCertificate(String),
    Storage(String),
    Transport(String),
}

impl fmt::Display for TzapIntermediateResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OfflineMiss { issuer_key_identifier, reason } => {
                write!(f, "intermediate certificate for issuer '{issuer_key_identifier}' is not cached and could not be fetched (offline: {reason})")
            }
            Self::NotFound { issuer_key_identifier } => {
                write!(f, "intermediate certificate for issuer '{issuer_key_identifier}' was not found")
            }
            Self::InvalidCertificate(reason) => write!(f, "intermediate certificate is invalid: {reason}"),
            Self::Storage(reason) => write!(f, "intermediate cache storage error: {reason}"),
            Self::Transport(reason) => write!(f, "intermediate fetch transport error: {reason}"),
        }
    }
}

impl std::error::Error for TzapIntermediateResolveError {}

/// Trait for resolving an intermediate certificate by the child's Authority
/// Key Identifier (AKI).
pub trait TzapIntermediateResolver: fmt::Debug + Send + Sync {
    /// Resolves the intermediate certificate whose Subject Key Identifier
    /// matches the given `aki` bytes, returning its DER-encoded bytes.
    fn resolve_intermediate(&self, aki: &[u8]) -> Result<Option<Vec<u8>>, TzapIntermediateResolveError>;
}

/// Filesystem-backed cache storing intermediate certificates keyed by their
/// SHA-256 fingerprint (`<hex>.der`).
#[derive(Debug, Clone)]
pub struct TzapIntermediateCache {
    cache_dir: PathBuf,
}

impl TzapIntermediateCache {
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self { cache_dir: cache_dir.into() }
    }

    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Stores an intermediate certificate in the cache.
    ///
    /// Computes the SHA-256 fingerprint, ensures the directory exists, writes
    /// the DER bytes, and returns the canonical `sha256:...` fingerprint.
    pub fn store(&self, cert_der: &[u8]) -> Result<String, TzapIntermediateCacheError> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|error| TzapIntermediateCacheError::CertificateParse(error.to_string()))?;
        if subject_key_identifier(&cert).is_none() {
            return Err(TzapIntermediateCacheError::CertificateParse("intermediate certificate is missing SubjectKeyIdentifier extension".to_owned()));
        }
        let digest: [u8; 32] = Sha256::digest(cert_der).into();
        let fingerprint = format_certificate_sha256(&digest);
        let hex_name = crate::hex::hex_lower(&digest);
        fs::create_dir_all(&self.cache_dir)?;
        let file_path = self.cache_dir.join(format!("{hex_name}.der"));
        fs::write(&file_path, cert_der)?;
        Ok(fingerprint)
    }

    /// Retrieves an intermediate certificate by its `sha256:...` fingerprint.
    pub fn get_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Vec<u8>>, TzapIntermediateCacheError> {
        let digest = parse_certificate_sha256(fingerprint).map_err(|_| TzapIntermediateCacheError::InvalidFingerprint(fingerprint.to_owned()))?;
        let hex_name = crate::hex::hex_lower(&digest);
        let file_path = self.cache_dir.join(format!("{hex_name}.der"));
        if file_path.exists() {
            let bytes = fs::read(&file_path)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    /// Finds a cached intermediate certificate whose Subject Key Identifier
    /// (SKI) matches the given `aki` bytes.
    pub fn get_by_aki(&self, aki: &[u8]) -> Result<Option<Vec<u8>>, TzapIntermediateCacheError> {
        if !self.cache_dir.is_dir() {
            return Ok(None);
        }
        let entries = match fs::read_dir(&self.cache_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(TzapIntermediateCacheError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("der") {
                let bytes = fs::read(&path)?;
                if X509Certificate::from_der(&bytes).is_ok_and(|(_, cert)| subject_key_identifier(&cert).as_deref() == Some(aki)) {
                    return Ok(Some(bytes));
                }
            }
        }
        Ok(None)
    }

    /// Lists all cached intermediate certificate DERs.
    pub fn list_intermediates(&self) -> Result<Vec<Vec<u8>>, TzapIntermediateCacheError> {
        if !self.cache_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        let entries = match fs::read_dir(&self.cache_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(TzapIntermediateCacheError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("der") {
                let bytes = fs::read(&path)?;
                results.push(bytes);
            }
        }
        Ok(results)
    }
}

impl TzapIntermediateResolver for TzapIntermediateCache {
    fn resolve_intermediate(&self, aki: &[u8]) -> Result<Option<Vec<u8>>, TzapIntermediateResolveError> {
        self.get_by_aki(aki).map_err(|error| TzapIntermediateResolveError::Storage(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::x509_factory::{intermediate_certificate, p256_private_key, root_certificate};

    #[test]
    fn test_intermediate_cache_store_and_lookup_by_aki_and_sha256() {
        let temp_dir = std::env::temp_dir().join(format!("tzap-cache-test-{}", rand::random::<u64>()));
        let cache = TzapIntermediateCache::new(&temp_dir);

        let root_key = p256_private_key();
        let intermediate_key = p256_private_key();
        let root = root_certificate(&root_key);
        let intermediate = intermediate_certificate(&intermediate_key, root.as_ref(), root_key.as_ref(), root.as_ref());
        let intermediate_der = intermediate.to_der().unwrap();

        let ski = extract_subject_key_identifier(&intermediate_der).expect("intermediate must have SKI");
        assert!(!ski.is_empty());

        // Cache is initially empty
        assert_eq!(cache.get_by_aki(&ski).unwrap(), None);

        // Store
        let fingerprint = cache.store(&intermediate_der).unwrap();
        assert!(fingerprint.starts_with("sha256:"));

        // Lookup by fingerprint
        let retrieved_by_fp = cache.get_by_fingerprint(&fingerprint).unwrap().expect("must find by fingerprint");
        assert_eq!(retrieved_by_fp, intermediate_der);

        // Lookup by AKI (matching SKI)
        let retrieved_by_aki = cache.get_by_aki(&ski).unwrap().expect("must find by AKI");
        assert_eq!(retrieved_by_aki, intermediate_der);

        // Resolver trait lookup
        let resolved = cache.resolve_intermediate(&ski).unwrap().expect("resolver must find by AKI");
        assert_eq!(resolved, intermediate_der);

        let _ = fs::remove_dir_all(temp_dir);
    }
}
