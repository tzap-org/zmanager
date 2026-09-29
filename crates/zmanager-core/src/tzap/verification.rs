//! Shared TZAP archive verification model.
//!
//! Defined in `zmanager-core` and shared with desktop, CLI, and mobile (D1/Z7).
//! The verification result consists of one derived [`TzapArchiveVerificationOutcome`]
//! plus four orthogonal checks:
//!
//! - [`TzapArchiveSignatureCheck`]: ok, absent, invalid, `unsupported_profile`, `volumes_incomplete`
//! - [`TzapArchiveTrustCheck`]: `production_root`, `staging_root`, untrusted
//! - [`TzapArchiveTimeCheck`]: `valid_at_signing`, `expired_since_signing`, `expired_at_signing`
//! - [`TzapArchiveStatusCheck`]: `fresh_valid`, `before_revocation`, revoked, suspended, unavailable

use super::{TzapError, TzapPublicSignatureStatus, TzapX509TrustAnchor, TzapX509TrustOptions};
use crate::trust::{canonical_serial_hex, format_certificate_sha256};
use crate::tzap::display::inspect_tzap_public_footer_signature_from;
use crate::tzap::open::{discover_tzap_input_volume_paths, open_tzap_input_volume_readers, summarize_tzap_public_metadata_from};
use crate::tzap::x509::{claimed_signing_time, classify_x509_trust_anchor, load_x509_trusted_roots};
use crate::x509_format::x509_name_to_string;
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use tzap_core::format::FormatError;
use tzap_core::{ArchiveReadAt, public_no_key_verify_readers_with};
use tzap_plugin_signing::x509_chain::{X509_AUTHENTICATOR_ID, verify_root_auth_footer_at_time};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Outcome of the combined verification (D1).
///
/// Derived deterministically in Rust from the four orthogonal checks. Only
/// [`TzapArchiveVerificationOutcome::Verified`] represents full success against
/// an authoritative production root; any caveats or degraded axes result in
/// [`TzapArchiveVerificationOutcome::VerifiedWithCaveat`], [`TzapArchiveVerificationOutcome::NotSigned`],
/// [`TzapArchiveVerificationOutcome::Unverifiable`], or [`TzapArchiveVerificationOutcome::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapArchiveVerificationOutcome {
    Verified,
    VerifiedWithCaveat,
    NotSigned,
    Unverifiable,
    Failed,
}

impl TzapArchiveVerificationOutcome {
    /// Total derivation function from the four orthogonal checks (D1).
    ///
    /// Evaluated in strict priority order — first match wins:
    /// 1. `signature == Absent` -> `NotSigned`
    /// 2. `signature in {UnsupportedProfile, VolumesIncomplete}` -> `Unverifiable`
    /// 3. `signature == Invalid` -> `Failed`
    /// 4. `trust == Untrusted` -> `Failed`
    /// 5. `certificate_time == ExpiredAtSigning` -> `Failed`
    /// 6. `status in {Revoked, Suspended}` -> `Failed`
    /// 7. `trust == ProductionRoot && certificate_time == ValidAtSigning && status == FreshValid` -> `Verified`
    /// 8. else -> `VerifiedWithCaveat`
    #[must_use]
    pub fn derive(sig: TzapArchiveSignatureCheck, trust: TzapArchiveTrustCheck, time: TzapArchiveTimeCheck, status: &TzapArchiveStatusCheck) -> Self {
        if sig == TzapArchiveSignatureCheck::Absent {
            return Self::NotSigned;
        }
        if matches!(sig, TzapArchiveSignatureCheck::UnsupportedProfile | TzapArchiveSignatureCheck::VolumesIncomplete) {
            return Self::Unverifiable;
        }
        if sig == TzapArchiveSignatureCheck::Invalid {
            return Self::Failed;
        }
        if trust == TzapArchiveTrustCheck::Untrusted {
            return Self::Failed;
        }
        if time == TzapArchiveTimeCheck::ExpiredAtSigning {
            return Self::Failed;
        }
        if matches!(status, TzapArchiveStatusCheck::Revoked { .. } | TzapArchiveStatusCheck::Suspended) {
            return Self::Failed;
        }
        if trust == TzapArchiveTrustCheck::ProductionRoot
            && time == TzapArchiveTimeCheck::ValidAtSigning
            && matches!(status, TzapArchiveStatusCheck::FreshValid)
        {
            Self::Verified
        } else {
            Self::VerifiedWithCaveat
        }
    }
}

/// Evaluation of the archive's cryptographic commitment and digital signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapArchiveSignatureCheck {
    Ok,
    Absent,
    Invalid,
    UnsupportedProfile,
    VolumesIncomplete,
}

/// Evaluation of the certificate chain's trust anchor (D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapArchiveTrustCheck {
    ProductionRoot,
    StagingRoot,
    Untrusted,
}

impl From<TzapX509TrustAnchor> for TzapArchiveTrustCheck {
    fn from(anchor: TzapX509TrustAnchor) -> Self {
        match anchor {
            TzapX509TrustAnchor::ProductionRoot => Self::ProductionRoot,
            TzapX509TrustAnchor::StagingRoot => Self::StagingRoot,
            TzapX509TrustAnchor::Untrusted => Self::Untrusted,
        }
    }
}

impl From<TzapArchiveTrustCheck> for TzapX509TrustAnchor {
    fn from(check: TzapArchiveTrustCheck) -> Self {
        match check {
            TzapArchiveTrustCheck::ProductionRoot => Self::ProductionRoot,
            TzapArchiveTrustCheck::StagingRoot => Self::StagingRoot,
            TzapArchiveTrustCheck::Untrusted => Self::Untrusted,
        }
    }
}

/// Evaluation of the certificate validity window against signing time and
/// verifier current time (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TzapArchiveTimeCheck {
    ValidAtSigning,
    ExpiredSinceSigning,
    ExpiredAtSigning,
}

impl TzapArchiveTimeCheck {
    /// Classifies validity of the signing certificate.
    #[must_use]
    pub fn classify(not_before_unix_seconds: i64, not_after_unix_seconds: i64, signed_at_unix_seconds: i64, verifier_now_unix_seconds: i64) -> Self {
        if signed_at_unix_seconds < not_before_unix_seconds || signed_at_unix_seconds >= not_after_unix_seconds {
            Self::ExpiredAtSigning
        } else if verifier_now_unix_seconds >= not_after_unix_seconds {
            Self::ExpiredSinceSigning
        } else {
            Self::ValidAtSigning
        }
    }
}

/// Online certificate status evaluation (D1, D6, D12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TzapArchiveStatusCheck {
    FreshValid,
    BeforeRevocation { revoked_at_unix_seconds: i64, reason: Option<String> },
    Revoked { revoked_at_unix_seconds: i64, reason: Option<String> },
    Suspended,
    Unavailable { reason: Option<String> },
}

/// Signer details extracted from the verified leaf certificate.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TzapArchiveSignerDetails {
    pub subject: String,
    pub display_name: Option<String>,
    pub organization: Option<String>,
    pub certificate_sha256: [u8; 32],
    pub certificate_sha256_hex: String,
    pub issuer: String,
    pub serial_number_hex: String,
    pub signed_at_unix_seconds: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaf_certificate_der: Vec<u8>,
}

impl TzapArchiveSignerDetails {
    /// Extracts signer details from raw leaf certificate DER and claimed signing time.
    ///
    /// # Errors
    ///
    /// Returns an error string if DER parsing or serial number extraction fails.
    pub fn from_leaf_der_and_signed_at(leaf_der: &[u8], signed_at_unix_seconds: i64) -> Result<Self, String> {
        let x509 = X509::from_der(leaf_der).map_err(|error| format!("invalid leaf certificate DER: {error}"))?;
        let subject = x509_name_to_string(x509.subject_name());
        let issuer = x509_name_to_string(x509.issuer_name());

        let display_name = x509.subject_name().entries_by_nid(Nid::COMMONNAME).next().and_then(|entry| entry.data().to_string().ok());
        let organization = x509.subject_name().entries_by_nid(Nid::ORGANIZATIONNAME).next().and_then(|entry| entry.data().to_string().ok());

        let certificate_sha256 = openssl::sha::sha256(leaf_der);
        let certificate_sha256_hex = format_certificate_sha256(&certificate_sha256);

        let (remaining, parsed) = X509Certificate::from_der(leaf_der).map_err(|error| format!("invalid leaf certificate DER parsing: {error}"))?;
        if !remaining.is_empty() {
            return Err("trailing DER bytes in leaf certificate".to_owned());
        }
        let serial_number_hex = canonical_serial_hex(parsed.raw_serial()).map_err(|error| format!("invalid serial number in leaf certificate: {error:?}"))?;

        Ok(Self {
            subject,
            display_name,
            organization,
            certificate_sha256,
            certificate_sha256_hex,
            issuer,
            serial_number_hex,
            signed_at_unix_seconds,
            leaf_certificate_der: leaf_der.to_vec(),
        })
    }
}

/// The unified TZAP archive verification result model (D1/Z7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TzapArchiveVerification {
    pub outcome: TzapArchiveVerificationOutcome,
    pub signature: TzapArchiveSignatureCheck,
    pub trust: TzapArchiveTrustCheck,
    pub certificate_time: TzapArchiveTimeCheck,
    pub status: TzapArchiveStatusCheck,
    pub signer: Option<TzapArchiveSignerDetails>,
    pub signer_is_this_device: bool,
}

impl TzapArchiveVerification {
    /// Creates a verification result, deriving `outcome` deterministically from the 4 checks.
    #[must_use]
    pub fn new(
        signature: TzapArchiveSignatureCheck,
        trust: TzapArchiveTrustCheck,
        certificate_time: TzapArchiveTimeCheck,
        status: TzapArchiveStatusCheck,
        signer: Option<TzapArchiveSignerDetails>,
        signer_is_this_device: bool,
    ) -> Self {
        let outcome = TzapArchiveVerificationOutcome::derive(signature, trust, certificate_time, &status);
        Self { outcome, signature, trust, certificate_time, status, signer, signer_is_this_device }
    }

    /// Factory for an unsigned archive.
    #[must_use]
    pub fn unsigned() -> Self {
        Self::new(
            TzapArchiveSignatureCheck::Absent,
            TzapArchiveTrustCheck::Untrusted,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            None,
            false,
        )
    }

    /// Factory for an archive with missing sibling volumes.
    #[must_use]
    pub fn incomplete_volumes() -> Self {
        Self::new(
            TzapArchiveSignatureCheck::VolumesIncomplete,
            TzapArchiveTrustCheck::Untrusted,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: Some("missing archive volumes".to_owned()) },
            None,
            false,
        )
    }

    /// Factory for an archive with an unsupported signature profile.
    #[must_use]
    pub fn unsupported_profile() -> Self {
        Self::new(
            TzapArchiveSignatureCheck::UnsupportedProfile,
            TzapArchiveTrustCheck::Untrusted,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: Some("unsupported signature profile".to_owned()) },
            None,
            false,
        )
    }

    /// Factory for an archive with an invalid or tampered signature.
    #[must_use]
    pub fn invalid_signature() -> Self {
        Self::new(
            TzapArchiveSignatureCheck::Invalid,
            TzapArchiveTrustCheck::Untrusted,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: Some("invalid signature or commitment".to_owned()) },
            None,
            false,
        )
    }

    /// Headline label chosen from the most significant degraded axis, according to the copy contract.
    #[must_use]
    pub fn headline_label(&self) -> &'static str {
        match self.outcome {
            TzapArchiveVerificationOutcome::Verified => "Verified Now",
            TzapArchiveVerificationOutcome::NotSigned => "Not Signed",
            TzapArchiveVerificationOutcome::Unverifiable => match self.signature {
                TzapArchiveSignatureCheck::UnsupportedProfile => "Signature Not Supported",
                _ => "Verification Unavailable",
            },
            TzapArchiveVerificationOutcome::Failed => {
                if self.signature == TzapArchiveSignatureCheck::Invalid {
                    "Signature Invalid"
                } else if self.trust == TzapArchiveTrustCheck::Untrusted {
                    "Signer Not Trusted"
                } else if self.certificate_time == TzapArchiveTimeCheck::ExpiredAtSigning {
                    "Signed With an Expired Certificate"
                } else {
                    match &self.status {
                        TzapArchiveStatusCheck::Revoked { .. } => "Certificate Revoked",
                        TzapArchiveStatusCheck::Suspended => "Certificate Suspended",
                        _ => "Signature Invalid",
                    }
                }
            }
            TzapArchiveVerificationOutcome::VerifiedWithCaveat => {
                // Order of significance: status (revocation first), then certificate_time, then trust.
                match &self.status {
                    TzapArchiveStatusCheck::BeforeRevocation { .. } => "Signed Before Revocation",
                    TzapArchiveStatusCheck::Unavailable { .. } => "Signature Valid — Status Not Checked",
                    _ => {
                        if self.certificate_time == TzapArchiveTimeCheck::ExpiredSinceSigning {
                            "Certificate Has Since Expired"
                        } else if self.trust == TzapArchiveTrustCheck::StagingRoot {
                            "Verified — Test Certificate"
                        } else {
                            "Signature Valid — Status Not Checked"
                        }
                    }
                }
            }
        }
    }
}

/// Verifies a TZAP archive public-no-key commitment, signature, and certificate chain
/// without contacting the online status service.
///
/// Sets the `status` axis to [`TzapArchiveStatusCheck::Unavailable`]. Callers with
/// network access can compose online status using `zmanager-tzap-hosted`.
///
/// # Errors
///
/// Returns [`TzapError::Io`] if files cannot be accessed.
pub fn verify_tzap_archive_public_no_key(
    archive: impl AsRef<Path>,
    trust: &TzapX509TrustOptions,
    verifier_now_unix_seconds: i64,
) -> Result<TzapArchiveVerification, TzapError> {
    verify_tzap_archive_public_no_key_with_signer_predicate(archive, trust, verifier_now_unix_seconds, |_| false)
}

/// Twin of [`verify_tzap_archive_public_no_key`] accepting a predicate to determine
/// if the verified signer is this device's own identity.
///
/// # Errors
///
/// Returns [`TzapError::Io`] if files cannot be accessed.
pub fn verify_tzap_archive_public_no_key_with_signer_predicate(
    archive: impl AsRef<Path>,
    trust: &TzapX509TrustOptions,
    verifier_now_unix_seconds: i64,
    is_own_signer: impl Fn(&[u8; 32]) -> bool,
) -> Result<TzapArchiveVerification, TzapError> {
    let archive_path = archive.as_ref();
    // The metadata (volume-completeness) and footer-signature passes share
    // one volume discovery and one open of the first volume, the way
    // `summarize_tzap_public_display` does internally, instead of running
    // two independent full metadata passes (one here, one hidden inside a
    // second call to `summarize_tzap_public_display`) that re-discover and
    // re-open every volume for the same archive.
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let Some(first_volume_path) = volume_paths.iter().find(|path| path.exists()) else {
        return Ok(TzapArchiveVerification::invalid_signature());
    };
    let mut first_volume_file = match File::open(first_volume_path) {
        Ok(file) => file,
        Err(source) => return Err(TzapError::Io { path: first_volume_path.clone(), source }),
    };

    let metadata_summary = match summarize_tzap_public_metadata_from(archive_path, &volume_paths, &mut first_volume_file) {
        Ok(summary) => summary,
        Err(TzapError::Io { path, source }) => return Err(TzapError::Io { path, source }),
        Err(_) => return Ok(TzapArchiveVerification::invalid_signature()),
    };

    if !metadata_summary.missing_volume_indices.is_empty() || metadata_summary.present_volume_count < metadata_summary.expected_volume_count {
        return Ok(TzapArchiveVerification::incomplete_volumes());
    }

    // The metadata pass read the first volume's headers through this handle
    // with seek-based reads, so rewind it before the footer pass reuses it.
    if let Err(source) = first_volume_file.seek(SeekFrom::Start(0)) {
        return Err(TzapError::Io { path: first_volume_path.clone(), source });
    }
    let signature = match inspect_tzap_public_footer_signature_from(archive_path, &volume_paths, &mut first_volume_file) {
        Ok(status) => status,
        Err(error) => TzapPublicSignatureStatus::Unavailable { reason: error.to_string() },
    };

    match &signature {
        TzapPublicSignatureStatus::Unsigned => return Ok(TzapArchiveVerification::unsigned()),
        TzapPublicSignatureStatus::Unavailable { reason } => {
            if reason.contains("missing volume") {
                return Ok(TzapArchiveVerification::incomplete_volumes());
            }
            return Ok(TzapArchiveVerification::unsupported_profile());
        }
        TzapPublicSignatureStatus::NotAuthentic { .. } => return Ok(TzapArchiveVerification::invalid_signature()),
        TzapPublicSignatureStatus::Signed { .. } => {}
    }

    let volumes = open_tzap_input_volume_readers(archive_path)?;
    let volume_refs = volumes.iter().map(|file| file as &dyn ArchiveReadAt).collect::<Vec<_>>();
    let trusted_roots_der = load_x509_trusted_roots(trust)?;

    let mut captured_signer = None;
    let mut captured_trust = TzapArchiveTrustCheck::Untrusted;
    let mut captured_time = TzapArchiveTimeCheck::ValidAtSigning;
    let mut verification_failed = false;

    let verification_result = public_no_key_verify_readers_with(&volume_refs, |footer, archive_root| {
        if footer.authenticator_id != X509_AUTHENTICATOR_ID {
            return Err(FormatError::ReaderUnsupported("X.509 trust can only verify X.509 RootAuth"));
        }
        let Ok(signed_at) = claimed_signing_time(footer, archive_root) else {
            verification_failed = true;
            return Ok(false);
        };

        let Ok((remaining, parsed_leaf)) = X509Certificate::from_der(&footer.signer_identity_bytes) else {
            verification_failed = true;
            return Ok(false);
        };
        if !remaining.is_empty() {
            verification_failed = true;
            return Ok(false);
        }

        let not_before = parsed_leaf.validity().not_before.timestamp();
        let not_after = parsed_leaf.validity().not_after.timestamp();
        captured_time = TzapArchiveTimeCheck::classify(not_before, not_after, signed_at, verifier_now_unix_seconds);

        let Ok(signer_details) = TzapArchiveSignerDetails::from_leaf_der_and_signed_at(&footer.signer_identity_bytes, signed_at) else {
            verification_failed = true;
            return Ok(false);
        };

        if verify_root_auth_footer_at_time(
            footer,
            archive_root,
            &trusted_roots_der,
            trust.trusted_system_roots,
            trust.include_official_tzap_root,
            Some(signed_at),
        )
        .is_ok()
        {
            captured_trust = classify_x509_trust_anchor(footer, archive_root, trust, signed_at).into();
        } else {
            captured_trust = TzapArchiveTrustCheck::Untrusted;
        }

        captured_signer = Some(signer_details);
        Ok(true)
    });

    if let (Ok(_), false, Some(signer)) = (&verification_result, verification_failed, captured_signer) {
        let is_this_device = is_own_signer(&signer.certificate_sha256);
        let status = TzapArchiveStatusCheck::Unavailable { reason: Some("offline verification".to_owned()) };
        Ok(TzapArchiveVerification::new(TzapArchiveSignatureCheck::Ok, captured_trust, captured_time, status, Some(signer), is_this_device))
    } else if matches!(verification_result, Err(FormatError::ReaderUnsupported(_))) {
        Ok(TzapArchiveVerification::unsupported_profile())
    } else {
        Ok(TzapArchiveVerification::invalid_signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn outcome_mapping_matches_plan_table_exactly() {
        // valid_now: verified
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Verified);
        assert_eq!(res.headline_label(), "Verified Now");

        // valid_test_anchor: verified_with_caveat + trust: staging_root
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::StagingRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(res.headline_label(), "Verified — Test Certificate");

        // valid_offline and status_unavailable: verified_with_caveat + status: unavailable
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Unavailable { reason: None },
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(res.headline_label(), "Signature Valid — Status Not Checked");

        // valid_before_revocation: verified_with_caveat + status: before_revocation
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::BeforeRevocation { revoked_at_unix_seconds: 1000, reason: Some("renewed".to_owned()) },
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(res.headline_label(), "Signed Before Revocation");

        // expired_since_signing: verified_with_caveat + certificate_time: expired_since_signing
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ExpiredSinceSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::VerifiedWithCaveat);
        assert_eq!(res.headline_label(), "Certificate Has Since Expired");

        // unsigned: not_signed
        let res = TzapArchiveVerification::unsigned();
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::NotSigned);
        assert_eq!(res.signature, TzapArchiveSignatureCheck::Absent);
        assert_eq!(res.headline_label(), "Not Signed");

        // incomplete_volumes: unverifiable + signature: volumes_incomplete
        let res = TzapArchiveVerification::incomplete_volumes();
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Unverifiable);
        assert_eq!(res.signature, TzapArchiveSignatureCheck::VolumesIncomplete);
        assert_eq!(res.headline_label(), "Verification Unavailable");

        // unsupported: unverifiable + signature: unsupported_profile
        let res = TzapArchiveVerification::unsupported_profile();
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Unverifiable);
        assert_eq!(res.signature, TzapArchiveSignatureCheck::UnsupportedProfile);
        assert_eq!(res.headline_label(), "Signature Not Supported");

        // invalid_signature: failed + signature: invalid
        let res = TzapArchiveVerification::invalid_signature();
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(res.signature, TzapArchiveSignatureCheck::Invalid);
        assert_eq!(res.headline_label(), "Signature Invalid");

        // untrusted_signer: failed + trust: untrusted
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::Untrusted,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(res.trust, TzapArchiveTrustCheck::Untrusted);
        assert_eq!(res.headline_label(), "Signer Not Trusted");

        // expired_at_signing: failed + certificate_time: expired_at_signing
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ExpiredAtSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(res.certificate_time, TzapArchiveTimeCheck::ExpiredAtSigning);
        assert_eq!(res.headline_label(), "Signed With an Expired Certificate");

        // revoked: failed + status: revoked
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Revoked { revoked_at_unix_seconds: 1000, reason: Some("key_compromise".to_owned()) },
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(res.headline_label(), "Certificate Revoked");

        // suspended: failed + status: suspended
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::Suspended,
            None,
            false,
        );
        assert_eq!(res.outcome, TzapArchiveVerificationOutcome::Failed);
        assert_eq!(res.headline_label(), "Certificate Suspended");
    }

    #[test]
    fn verified_is_reachable_only_with_production_anchor_validity_at_signing_and_fresh_valid() {
        // Base case: verified
        let outcome = TzapArchiveVerificationOutcome::derive(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::ProductionRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            &TzapArchiveStatusCheck::FreshValid,
        );
        assert_eq!(outcome, TzapArchiveVerificationOutcome::Verified);

        // Staging anchor caps below verified:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::StagingRoot,
                TzapArchiveTimeCheck::ValidAtSigning,
                &TzapArchiveStatusCheck::FreshValid,
            ),
            TzapArchiveVerificationOutcome::VerifiedWithCaveat
        );

        // Untrusted anchor fails:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::Untrusted,
                TzapArchiveTimeCheck::ValidAtSigning,
                &TzapArchiveStatusCheck::FreshValid,
            ),
            TzapArchiveVerificationOutcome::Failed
        );

        // Expired since signing caps below verified:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::ProductionRoot,
                TzapArchiveTimeCheck::ExpiredSinceSigning,
                &TzapArchiveStatusCheck::FreshValid,
            ),
            TzapArchiveVerificationOutcome::VerifiedWithCaveat
        );

        // Expired at signing fails:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::ProductionRoot,
                TzapArchiveTimeCheck::ExpiredAtSigning,
                &TzapArchiveStatusCheck::FreshValid,
            ),
            TzapArchiveVerificationOutcome::Failed
        );

        // Unavailable status caps below verified:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::ProductionRoot,
                TzapArchiveTimeCheck::ValidAtSigning,
                &TzapArchiveStatusCheck::Unavailable { reason: None },
            ),
            TzapArchiveVerificationOutcome::VerifiedWithCaveat
        );

        // Revocation before signing caps below verified:
        assert_eq!(
            TzapArchiveVerificationOutcome::derive(
                TzapArchiveSignatureCheck::Ok,
                TzapArchiveTrustCheck::ProductionRoot,
                TzapArchiveTimeCheck::ValidAtSigning,
                &TzapArchiveStatusCheck::BeforeRevocation { revoked_at_unix_seconds: 1000, reason: Some("renewed".to_owned()) },
            ),
            TzapArchiveVerificationOutcome::VerifiedWithCaveat
        );
    }

    #[test]
    fn headline_precedence_order_status_then_time_then_trust() {
        // When both status (BeforeRevocation) and trust (StagingRoot) are degraded,
        // status wins:
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::StagingRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::BeforeRevocation { revoked_at_unix_seconds: 1000, reason: Some("renewed".to_owned()) },
            None,
            false,
        );
        assert_eq!(res.headline_label(), "Signed Before Revocation");

        // When both certificate_time (ExpiredSinceSigning) and trust (StagingRoot) are degraded,
        // certificate_time wins over trust:
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::StagingRoot,
            TzapArchiveTimeCheck::ExpiredSinceSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.headline_label(), "Certificate Has Since Expired");

        // Only trust degraded:
        let res = TzapArchiveVerification::new(
            TzapArchiveSignatureCheck::Ok,
            TzapArchiveTrustCheck::StagingRoot,
            TzapArchiveTimeCheck::ValidAtSigning,
            TzapArchiveStatusCheck::FreshValid,
            None,
            false,
        );
        assert_eq!(res.headline_label(), "Verified — Test Certificate");
    }

    #[test]
    fn time_check_classification_bounds() {
        // [100, 200)
        // Valid when signed at 150, verifier now 180 (< 200)
        assert_eq!(TzapArchiveTimeCheck::classify(100, 200, 150, 180), TzapArchiveTimeCheck::ValidAtSigning);
        // Valid when signed at 150, but verifier now 250 (>= 200)
        assert_eq!(TzapArchiveTimeCheck::classify(100, 200, 150, 250), TzapArchiveTimeCheck::ExpiredSinceSigning);
        // Signed before not_before
        assert_eq!(TzapArchiveTimeCheck::classify(100, 200, 99, 150), TzapArchiveTimeCheck::ExpiredAtSigning);
        // Signed after not_after
        assert_eq!(TzapArchiveTimeCheck::classify(100, 200, 200, 250), TzapArchiveTimeCheck::ExpiredAtSigning);
    }
}
