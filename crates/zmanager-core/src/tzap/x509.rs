//! TZAP X.509 `RootAuth` support: signer loading, recipient private-key
//! lookup, verification report mapping, public no-key verification, signer
//! inspection, and raw authenticator parsing.

use super::TzapError;
use crate::secrets::{SecretBytes, SecretString};
use crate::tzap::open::{
    open_tzap_archive, open_tzap_archive_with_key_options, open_tzap_archive_with_key_options_multi, open_tzap_archive_with_recipient_key,
    open_tzap_input_volume_readers,
};
use crate::tzap::write::TzapCreateOptions;
use crate::x509_format::x509_name_to_string;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use rand::RngCore as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tzap_core::WriterOptions;
use tzap_core::format::{FORMAT_VERSION, FormatError, VOLUME_FORMAT_REV};
use tzap_core::reader::{PublicNoKeyDiagnostic, RecipientWrapRecordContext, RootAuthDiagnostic};
use tzap_core::wire::RecipientRecordV1;
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::{ArchiveReadAt, MasterKey, OpenedArchive, TarEntryKind, public_no_key_verify_readers_with};
use tzap_plugin_keywrap::{
    ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup, RecipientRecordInput, RecipientRecordMetadata,
    dispatch_key_wrap_record, wrap_master_key_for_recipient,
};
use tzap_plugin_signing::x509_chain::{
    X509_AUTHENTICATOR_ID, X509RootAuthReport, X509RootAuthSigner, certificate_der_from_pem_or_der, certificates_der_from_pem_or_der,
    verify_root_auth_footer_at_time, verify_root_auth_signature,
};

// The official root literals live in `trust::` (pinned there too), so the
// pin set and the embedded certificates cannot drift. `trust::` is also the
// one place the PEM files are embedded (`include_bytes!`) — this module
// reuses that embedding rather than keeping its own copy.
const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str = crate::trust::TZAP_PRODUCTION_ROOT_SHA256;
use crate::trust::{OFFICIAL_TZAP_ROOT_CERT_PEM, OFFICIAL_TZAP_STAGING_ROOT_PEM};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TzapX509SigningOptions {
    /// PKCS#12 signing identity containing the leaf certificate, private key,
    /// and optional intermediate certificates.
    Pkcs12 {
        /// PKCS#12 identity file path.
        identity: PathBuf,
        /// PKCS#12 import password.
        password: SecretString,
    },
    /// Advanced PEM/DER signing inputs.
    CertificateAndKey {
        /// PEM or DER leaf signing certificate. PEM bundles may include
        /// intermediate certificates after the leaf certificate.
        signing_certificate: PathBuf,
        /// PEM or DER private key matching the leaf signing certificate.
        signing_private_key: PathBuf,
        /// Optional PEM or DER intermediate certificates.
        signing_chain: Vec<PathBuf>,
    },
    /// Validated in-memory signing material resolved from a secure store.
    InMemory {
        /// Leaf signing certificate in PEM or DER form.
        signing_certificate: Vec<u8>,
        /// Matching private key. This value is redacted and zeroized on drop.
        signing_private_key: SecretBytes,
        /// Optional intermediate certificates in PEM or DER form.
        signing_chain: Vec<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TzapX509TrustOptions {
    /// PEM or DER trusted CA certificates.
    pub trusted_ca_certificates: Vec<PathBuf>,
    /// Allow OpenSSL's default system trust roots.
    pub trusted_system_roots: bool,
    /// Include `ZManager`'s embedded official TZAP root certificate.
    pub include_official_tzap_root: bool,
}

impl TzapX509TrustOptions {
    /// Returns whether verification has any trust source to use.
    #[must_use]
    pub fn has_trust_source(&self) -> bool {
        self.include_official_tzap_root || !self.trusted_ca_certificates.is_empty() || self.trusted_system_roots
    }
}

/// Resolves the in-memory X.509 signing material for a locally enrolled
/// certificate (CR-113: moved from the CLI so the tzap JSON service's share
/// endpoint uses the same battle-tested resolution rules).
pub fn tzap_x509_signing_options_from_inventory(
    store: &impl crate::local_identity_store::TzapLocalIdentityStore,
    account_key: &str,
    certificate_id: &str,
    now_unix_seconds: u64,
) -> Result<TzapX509SigningOptions, String> {
    use crate::local_identity_store::TzapLocalCertificateState;
    use crate::trust::TzapCertificateStatus;

    let inventory = store.load_inventory(account_key).map_err(|error| error.to_string())?;
    let certificate = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == certificate_id)
        .ok_or_else(|| format!("certificate not found: {certificate_id}"))?;
    if certificate.state != TzapLocalCertificateState::Active {
        return Err(format!("certificate is not active: {}", certificate.state.as_str()));
    }
    if now_unix_seconds < certificate.not_before_unix_seconds {
        return Err("certificate is not yet valid".to_owned());
    }
    if now_unix_seconds >= certificate.not_after_unix_seconds {
        return Err("certificate is expired".to_owned());
    }
    if inventory.emergency_blocklist.blocked_issuer_sha256.contains(&certificate.issuer_certificate_sha256) {
        return Err("certificate issuer is locally blocked".to_owned());
    }
    if inventory
        .certificate_status_cache
        .iter()
        .any(|status| status.certificate_sha256 == certificate.certificate_sha256 && status.status != TzapCertificateStatus::Valid)
    {
        return Err("certificate status blocks signing".to_owned());
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|key| key.key_id == certificate.signing_key_id)
        .ok_or_else(|| "certificate signing key is missing".to_owned())?;
    Ok(TzapX509SigningOptions::InMemory {
        signing_certificate: certificate.leaf_certificate_der.clone(),
        signing_private_key: signing_key.private_key_der.clone(),
        signing_chain: certificate.intermediate_chain_der.clone(),
    })
}

/// Turns a stored default-signing-key preference into a concrete certificate
/// id (Z8): the newest usable certificate for that signing key — active,
/// time-valid at `now_unix_seconds`, not locally blocklisted, and free of a
/// cached non-valid status. This is the only place that resolution rule is
/// implemented. The durable preference — *which signing key* is the default
/// — is stored by the caller: mobile keeps only that preference, and the
/// CLI's `--signing-identity` (with no certificate id given) answers the
/// same question through this function, so mobile and the CLI always select
/// the same certificate for the same inventory and clock.
///
/// "Newest" is the usable candidate with the latest `not_before_unix_seconds`:
/// a renewal's certificate always has a later `not_before` than the
/// predecessor it supersedes, so this is what makes renewal take effect for
/// new signing without a separate "current certificate" pointer to update.
///
/// # Errors
///
/// Returns an error message when no enrolled certificate for `signing_key_id`
/// is currently usable.
pub fn resolve_default_signing_certificate_id(
    inventory: &crate::local_identity_store::TzapLocalIdentityInventory,
    signing_key_id: &str,
    now_unix_seconds: u64,
) -> Result<String, String> {
    inventory
        .enrolled_certificates
        .iter()
        .filter(|certificate| certificate.signing_key_id == signing_key_id)
        .filter(|certificate| certificate_is_usable_for_signing(certificate, inventory, now_unix_seconds))
        .max_by_key(|certificate| certificate.not_before_unix_seconds)
        .map(|certificate| certificate.certificate_id.clone())
        .ok_or_else(|| format!("no usable certificate found for signing key: {signing_key_id}"))
}

/// The usability gate [`resolve_default_signing_certificate_id`] applies to
/// each candidate: the same four checks `tzap_x509_signing_options_from_inventory`
/// applies to a caller-chosen certificate id, applied here across candidates
/// for a signing key instead. Kept separate from that function rather than
/// factored through it, so its existing per-failure error messages (used
/// when a caller names a specific, unusable certificate) are undisturbed.
fn certificate_is_usable_for_signing(
    certificate: &crate::local_identity_store::TzapEnrolledCertificateRecord,
    inventory: &crate::local_identity_store::TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> bool {
    use crate::local_identity_store::TzapLocalCertificateState;
    use crate::trust::TzapCertificateStatus;

    certificate.state == TzapLocalCertificateState::Active
        && now_unix_seconds >= certificate.not_before_unix_seconds
        && now_unix_seconds < certificate.not_after_unix_seconds
        && !inventory.emergency_blocklist.blocked_issuer_sha256.contains(&certificate.issuer_certificate_sha256)
        && !inventory
            .certificate_status_cache
            .iter()
            .any(|status| status.certificate_sha256 == certificate.certificate_sha256 && status.status != TzapCertificateStatus::Valid)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509VerificationReport {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time as Unix seconds.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Subjects in the verified chain.
    pub verified_chain_subjects: Vec<String>,
    /// Trust anchor subject, when OpenSSL reported one.
    pub trust_anchor_subject: Option<String>,
    /// Which trust anchor actually validated the chain, derived in Rust from
    /// the chain itself rather than inferred from `trust_anchor_subject`
    /// (Z2). Both official TZAP roots remain trusted in every build; this is
    /// what lets a caller require a production anchor for a "fully verified"
    /// outcome while a staging-anchored chain still verifies under its own
    /// label. Any anchor other than the two pinned official roots — a custom
    /// or system root the caller separately configured — reports
    /// [`TzapX509TrustAnchor::Untrusted`] here: this classification exists to
    /// answer "production or staging, or neither", not to relitigate whether
    /// the underlying chain verification succeeded.
    pub trust_anchor: TzapX509TrustAnchor,
    /// Root-auth verification diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TzapX509TrustAnchor {
    ProductionRoot,
    StagingRoot,
    Untrusted,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapX509SignerInspection {
    /// Verified archive root commitment.
    pub archive_root: [u8; 32],
    /// `RootAuth` authenticator identifier.
    pub authenticator_id: u16,
    /// `RootAuth` signer identity type.
    pub signer_identity_type: u16,
    /// Number of data blocks covered by the `RootAuth` footer.
    pub total_data_block_count: u64,
    /// Signer-claimed signing time as Unix seconds.
    pub signed_at_unix_seconds: i64,
    /// Leaf certificate subject.
    pub subject: String,
    /// Leaf certificate issuer.
    pub issuer: String,
    /// Leaf certificate serial number.
    pub serial_number_hex: String,
    /// SHA-256 fingerprint of the leaf certificate.
    pub certificate_sha256: [u8; 32],
    /// Root-auth inspection diagnostics reported by `tzap`.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapTestReport {
    /// Number of entries in the archive.
    pub entries: usize,
    /// Number of entries selected by the filter.
    pub tested_entries: usize,
    /// Number of entries skipped by the filter.
    pub skipped_entries: usize,
    /// Total selected regular-file bytes.
    pub tested_bytes: u64,
    /// Verified X.509 `RootAuth` details when trust options were supplied.
    pub x509_root_auth: Option<TzapX509VerificationReport>,
}

pub(crate) fn load_x509_signer(options: &TzapX509SigningOptions) -> Result<X509RootAuthSigner, TzapError> {
    match options {
        TzapX509SigningOptions::Pkcs12 { identity, password } => load_x509_signer_from_pkcs12(identity, password),
        TzapX509SigningOptions::CertificateAndKey { signing_certificate, signing_private_key, signing_chain } => {
            load_x509_signer_from_certificate_files(signing_certificate, signing_private_key, signing_chain)
        }
        TzapX509SigningOptions::InMemory { signing_certificate, signing_private_key, signing_chain } => {
            X509RootAuthSigner::from_pem_or_der(signing_certificate, signing_private_key.expose_secret(), signing_chain.clone(), current_unix_seconds_i64()?)
                .map_err(|source| TzapError::X509RootAuth(source.to_string()))
        }
    }
}

fn load_x509_signer_from_certificate_files(
    signing_certificate: &Path,
    signing_private_key: &Path,
    signing_chain: &[PathBuf],
) -> Result<X509RootAuthSigner, TzapError> {
    let certificate = read_x509_input_file(signing_certificate)?;
    let mut certificate_der = certificates_der_from_pem_or_der(&certificate).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let leaf_certificate_der = certificate_der.remove(0);
    let private_key = read_x509_input_file(signing_private_key)?;
    let mut chain_der = certificate_der;
    chain_der.extend(load_x509_certificate_files(signing_chain)?);
    X509RootAuthSigner::from_pem_or_der(&leaf_certificate_der, &private_key, chain_der, current_unix_seconds_i64()?)
        .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

fn load_x509_signer_from_pkcs12(identity: &Path, password: &SecretString) -> Result<X509RootAuthSigner, TzapError> {
    let identity_bytes = read_x509_input_file(identity)?;
    let pkcs12 = Pkcs12::from_der(&identity_bytes).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let parsed = pkcs12.parse2(password.expose_secret()).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    let certificate = parsed.cert.ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no certificate".to_owned()))?;
    let private_key = parsed.pkey.ok_or_else(|| TzapError::X509RootAuth("PKCS#12 identity has no private key".to_owned()))?;
    let chain_der = parsed
        .ca
        .map(|chain| {
            chain.iter().map(|certificate| certificate.to_der().map_err(|source| TzapError::X509RootAuth(source.to_string()))).collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    X509RootAuthSigner::new(
        certificate.to_der().map_err(|source| TzapError::X509RootAuth(source.to_string()))?,
        private_key,
        chain_der,
        current_unix_seconds_i64()?,
    )
    .map_err(|source| TzapError::X509RootAuth(source.to_string()))
}

pub(crate) fn load_x509_certificate_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = read_x509_input_file(path)?;
        let mut parsed = certificates_der_from_pem_or_der(&bytes).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
        certificates.append(&mut parsed);
    }
    Ok(certificates)
}

fn read_x509_input_file(path: &Path) -> Result<Vec<u8>, TzapError> {
    fs::read(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })
}

pub(crate) fn load_x509_trusted_roots(trust: &TzapX509TrustOptions) -> Result<Vec<Vec<u8>>, TzapError> {
    let mut certificates = Vec::new();
    if trust.include_official_tzap_root {
        certificates.push(
            certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).map_err(|source| {
                TzapError::X509RootAuth(format!("failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}: {source}"))
            })?,
        );
        // Staging is trusted by default alongside production (see
        // `trust::OFFICIAL_TZAP_ROOT_PINS`).
        certificates.push(certificate_der_from_pem_or_der(OFFICIAL_TZAP_STAGING_ROOT_PEM).map_err(|source| {
            TzapError::X509RootAuth(format!("failed to parse embedded TZAP staging root certificate {}: {source}", crate::trust::TZAP_STAGING_ROOT_SHA256))
        })?);
    }
    certificates.extend(load_x509_certificate_files(&trust.trusted_ca_certificates)?);
    Ok(certificates)
}

pub(crate) fn validate_recipient_wrap_create_options(options: &TzapCreateOptions) -> Result<(), TzapError> {
    if options.volume_size.is_some() || options.volume_count.is_some_and(|count| count > 1) || options.volume_loss_tolerance != 0 {
        return Err(TzapError::Format(FormatError::WriterUnsupported(
            "recipient certificate encryption is currently supported only for single-volume TZAP create",
        )));
    }
    Ok(())
}

pub(crate) fn build_recipient_wrap_record_from_certificate_path(
    recipient_certificate_path: &Path,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<RecipientRecordV1, TzapError> {
    let recipient_certificate = load_single_x509_certificate_file("recipient certificate", recipient_certificate_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    build_recipient_wrap_record_from_certificate_der(&recipient_certificate, master_key, &archive_identity)
}

pub(crate) fn build_recipient_wrap_record_from_certificate_der(
    recipient_certificate: &[u8],
    master_key: &MasterKey,
    archive_identity: &KeyWrapArchiveIdentity,
) -> Result<RecipientRecordV1, TzapError> {
    let master_key_bytes = master_key.0;
    for suite in [KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305, KeyWrapSuite::P256HkdfSha256Aes256Gcm] {
        match wrap_master_key_for_recipient(archive_identity.clone(), recipient_certificate, &master_key_bytes, suite) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(&outcome)),
        }
    }
    Err(TzapError::Format(FormatError::WriterUnsupported("recipient certificate is not supported by keywrap-v1 suites")))
}

/// Wraps a raw recipient SPKI in a throwaway self-signed certificate so the
/// keywrap plugin's cert-only API can consume it.
///
/// The recipient identity recorded in the archive is therefore this synthetic
/// certificate, not the recipient's real one. See the design note
/// `adr/2026-08-06-synthetic-recipient-certificate.md` in the private
/// implementation-docs repo; revisit when the plugin accepts raw SPKI.
pub(crate) fn synthetic_recipient_certificate_der(public_key_spki_der: &[u8]) -> Result<Vec<u8>, TzapError> {
    let public_key =
        PKey::<Public>::public_key_from_der(public_key_spki_der).map_err(|source| TzapError::KeyWrap(format!("recipient public key is invalid: {source}")))?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|source| TzapError::KeyWrap(format!("recipient certificate key failed: {source}")))?;
    let issuer_key = PKey::from_ec_key(EcKey::generate(&group).map_err(|source| TzapError::KeyWrap(format!("recipient certificate key failed: {source}")))?)
        .map_err(|source| TzapError::KeyWrap(format!("recipient certificate key failed: {source}")))?;
    let mut name = openssl::x509::X509NameBuilder::new().map_err(|source| TzapError::KeyWrap(format!("recipient certificate name failed: {source}")))?;
    name.append_entry_by_text("CN", "ZManager Contact Recipient")
        .map_err(|source| TzapError::KeyWrap(format!("recipient certificate name failed: {source}")))?;
    let name = name.build();
    let mut builder = X509::builder().map_err(|source| TzapError::KeyWrap(format!("recipient certificate failed: {source}")))?;
    builder.set_version(2).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let serial = BigNum::from_u32(1)
        .and_then(|number| number.to_asn1_integer())
        .map_err(|source| TzapError::KeyWrap(format!("recipient certificate serial failed: {source}")))?;
    builder.set_serial_number(&serial).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.set_subject_name(&name).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.set_issuer_name(&name).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.set_pubkey(&public_key).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let not_before = Asn1Time::days_from_now(0).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let not_after = Asn1Time::days_from_now(365).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.set_not_before(&not_before).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.set_not_after(&not_after).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .append_extension(BasicConstraints::new().critical().build().map_err(|source| TzapError::KeyWrap(source.to_string()))?)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder
        .append_extension(KeyUsage::new().critical().key_agreement().build().map_err(|source| TzapError::KeyWrap(source.to_string()))?)
        .map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    let subject_key_identifier = {
        let context = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new().build(&context).map_err(|source| TzapError::KeyWrap(source.to_string()))?
    };
    builder.append_extension(subject_key_identifier).map_err(|source| TzapError::KeyWrap(source.to_string()))?;
    builder.sign(&issuer_key, MessageDigest::sha256()).map_err(|source| TzapError::KeyWrap(format!("recipient certificate signing failed: {source}")))?;
    builder.build().to_der().map_err(|source| TzapError::KeyWrap(format!("recipient certificate DER failed: {source}")))
}

pub(crate) fn load_single_x509_certificate_file(label: &'static str, path: &Path) -> Result<Vec<u8>, TzapError> {
    let bytes = read_x509_input_file(path)?;
    let certificates =
        certificates_der_from_pem_or_der(&bytes).map_err(|source| TzapError::KeyWrap(format!("failed to parse {label} {}: {source}", path.display())))?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] | [_, _, ..] => Err(TzapError::KeyWrap(format!("{label} must contain exactly one X.509 certificate"))),
    }
}

pub(crate) fn recipient_wrap_archive_identity_for_writer(options: &mut WriterOptions) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity { archive_uuid, session_id, format_version: FORMAT_VERSION, volume_format_rev: VOLUME_FORMAT_REV }
}

fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn key_wrap_outcome_error(outcome: &KeyWrapOutcome) -> TzapError {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient profile")),
        KeyWrapOutcome::UnsupportedArchiveIdentity => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap archive identity")),
        KeyWrapOutcome::UnsupportedRecipientIdentity => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient identity")),
        KeyWrapOutcome::UnsupportedSuite => TzapError::Format(FormatError::ReaderUnsupported("unsupported keywrap recipient suite")),
        KeyWrapOutcome::CertificatePolicyRejected => TzapError::Format(FormatError::ReaderUnsupported("recipient certificate policy rejected")),
        KeyWrapOutcome::InvalidRecord => TzapError::Format(FormatError::InvalidArchive("invalid keywrap recipient record")),
        KeyWrapOutcome::NoMatchingPrivateKey => TzapError::KeyWrap("no matching recipient private key for archive".to_owned()),
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => {
            TzapError::Format(FormatError::WriterInvariant("keywrap success outcome cannot be converted to error"))
        }
    }
}

/// One candidate recipient private key considered when unwrapping a TZAP
/// keywrap record. A device that has rotated its recipient key holds several
/// of these at once (its active key plus any retired ones), and the lookup
/// tries each until one matches the record's certificate.
#[derive(Debug)]
struct RecipientPrivateKeyCandidate {
    private_key_bytes: Vec<u8>,
    private_key_spki_der: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct TzapRecipientPrivateKeyLookup {
    candidates: Vec<RecipientPrivateKeyCandidate>,
}

impl PrivateKeyLookup for TzapRecipientPrivateKeyLookup {
    fn lookup_private_key(
        &self,
        _archive_identity: &KeyWrapArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        let certificate_spki_der =
            X509::from_der(recipient_identity_bytes).ok().and_then(|certificate| certificate.public_key().ok()?.public_key_to_der().ok());
        // Prefer an exact SPKI match first, in candidate order, so a device
        // holding both an active and a retired key always unwraps to the key
        // the record actually names rather than whichever was listed first.
        if let Some(certificate_spki_der) = certificate_spki_der.as_ref() {
            for candidate in &self.candidates {
                if candidate.private_key_spki_der.as_ref() == Some(certificate_spki_der) {
                    return Some(candidate.private_key_bytes.clone());
                }
            }
        }
        // A candidate with no derivable SPKI (a raw 32-byte key) cannot be
        // compared against the record, so it is offered unconditionally, as
        // the single-key lookup always did.
        self.candidates.iter().find(|candidate| candidate.private_key_spki_der.is_none()).map(|candidate| candidate.private_key_bytes.clone())
    }
}

pub(crate) fn load_recipient_private_key_lookup(path: &Path) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    let bytes = fs::read(path).map_err(|source| TzapError::Io { path: path.to_path_buf(), source })?;
    load_recipient_private_key_lookup_from_bytes(&bytes, &path.display().to_string())
}

pub(crate) fn load_recipient_private_key_lookup_from_bytes(bytes: &[u8], description: &str) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    load_recipient_private_key_lookup_from_bytes_list(std::slice::from_ref(&bytes.to_vec()), description)
}

/// Plural form of [`load_recipient_private_key_lookup_from_bytes`] for a
/// device holding several recipient private keys at once (design §9.4): the
/// resulting lookup tries every candidate's SPKI against each record.
///
/// # Errors
///
/// Returns [`TzapError`] when `key_bytes_list` is empty or any entry cannot be
/// parsed as a recipient private key.
pub(crate) fn load_recipient_private_key_lookup_from_bytes_list(
    key_bytes_list: &[Vec<u8>],
    description: &str,
) -> Result<TzapRecipientPrivateKeyLookup, TzapError> {
    if key_bytes_list.is_empty() {
        return Err(TzapError::KeyWrap(format!("no recipient private key candidates supplied for {description}")));
    }
    let candidates = key_bytes_list
        .iter()
        .enumerate()
        .map(|(index, bytes)| parse_recipient_private_key_candidate(bytes, &format!("{description} #{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TzapRecipientPrivateKeyLookup { candidates })
}

fn parse_recipient_private_key_candidate(bytes: &[u8], description: &str) -> Result<RecipientPrivateKeyCandidate, TzapError> {
    if bytes.len() == 32 {
        return Ok(RecipientPrivateKeyCandidate { private_key_bytes: bytes.to_vec(), private_key_spki_der: None });
    }
    let private_key = if bytes.starts_with(b"-----BEGIN") { PKey::private_key_from_pem(bytes) } else { PKey::private_key_from_der(bytes) }
        .map_err(|source| TzapError::KeyWrap(format!("failed to parse recipient private key {description}: {source}")))?;
    let private_key_bytes =
        private_key.private_key_to_der().map_err(|source| TzapError::KeyWrap(format!("failed to normalize recipient private key {description}: {source}")))?;
    let private_key_spki_der = private_key.public_key_to_der().ok();
    Ok(RecipientPrivateKeyCandidate { private_key_bytes, private_key_spki_der })
}

#[derive(Debug, Default)]
pub(crate) struct RecipientWrapOpenStats {
    records_seen: usize,
    no_matching_private_key: usize,
    invalid_record_or_unwrap: usize,
    unsupported_record: usize,
    candidate_count: usize,
}

pub(crate) fn recipient_wrap_candidates_for_record(
    context: &RecipientWrapRecordContext<'_>,
    lookup: &TzapRecipientPrivateKeyLookup,
    stats: &mut RecipientWrapOpenStats,
) -> Vec<[u8; 32]> {
    stats.records_seen += 1;
    let input = RecipientRecordInput {
        archive_identity: KeyWrapArchiveIdentity {
            archive_uuid: context.archive_identity.archive_uuid,
            session_id: context.archive_identity.session_id,
            format_version: context.archive_identity.format_version,
            volume_format_rev: context.archive_identity.volume_format_rev,
        },
        metadata: RecipientRecordMetadata {
            profile_id: context.record.profile_id,
            recipient_identity_type: context.record.recipient_identity_type,
            recipient_identity_digest: context.record.recipient_identity_digest,
        },
        recipient_identity_bytes: context.record.recipient_identity_bytes.clone(),
        profile_payload_bytes: context.record.profile_payload_bytes.clone(),
    };
    match dispatch_key_wrap_record(input, lookup) {
        KeyWrapOutcome::UnwrappedCandidateMasterKey { master_key, .. } => {
            stats.candidate_count += 1;
            vec![master_key]
        }
        KeyWrapOutcome::NoMatchingPrivateKey => {
            stats.no_matching_private_key += 1;
            Vec::new()
        }
        KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::CertificatePolicyRejected => {
            stats.invalid_record_or_unwrap += 1;
            Vec::new()
        }
        KeyWrapOutcome::UnsupportedProfileId
        | KeyWrapOutcome::UnsupportedArchiveIdentity
        | KeyWrapOutcome::UnsupportedRecipientIdentity
        | KeyWrapOutcome::UnsupportedSuite => {
            stats.unsupported_record += 1;
            Vec::new()
        }
    }
}

pub(crate) fn recipient_wrap_open_error(source: FormatError, stats: &RecipientWrapOpenStats) -> TzapError {
    if !matches!(source, FormatError::KeyMaterialMismatch) {
        return TzapError::Format(source);
    }
    if stats.candidate_count > 0 {
        return TzapError::KeyWrap(format!("{source}: recipient private key unwrapped a candidate, but archive header HMAC did not verify"));
    }
    if stats.records_seen == 0 {
        return TzapError::KeyWrap(format!("{source}: recipient-wrap archive has no recipient records"));
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return TzapError::KeyWrap(format!("{source}: no matching recipient private key for archive"));
    }
    TzapError::KeyWrap(format!("{source}: recipient private key did not match any recipient record or failed recipient unwrap"))
}

fn current_unix_seconds_i64() -> Result<i64, TzapError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|source| TzapError::X509RootAuth(source.to_string()))?.as_secs();
    i64::try_from(seconds).map_err(|_| TzapError::X509RootAuth("current Unix time exceeds i64".to_owned()))
}

/// Extracts the signer-claimed signing time from a footer's authenticator
/// envelope, via the trustless "assertion-1" check (no chain or trust
/// evaluation, so this is cheap and doesn't require a decision about trust
/// roots yet). Needed before full chain verification can even run at the
/// right time (Z3): `RootAuthFooterV1` carries no plain `signed_at` field —
/// it's inside the authenticator value that only signature parsing exposes.
pub(crate) fn claimed_signing_time(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> Result<i64, TzapError> {
    verify_root_auth_signature(footer, archive_root).map(|report| report.signed_at_unix_seconds).map_err(|error| TzapError::X509RootAuth(error.to_string()))
}

/// Classifies which trust anchor validated a footer that has already
/// verified successfully against `trust`'s combined trust store (Z2).
///
/// Rather than inferring the answer from `X509RootAuthReport`'s subject
/// string, this re-runs footer verification against each official root in
/// isolation and reports whichever one independently succeeds. Both official
/// roots are small, embedded, and verification is cheap relative to archive
/// size (it never touches bulk data), so the extra check is not a meaningful
/// cost. Only meaningful when `trust.include_official_tzap_root` is set;
/// otherwise neither official root was in play and the answer is always
/// [`TzapX509TrustAnchor::Untrusted`] by definition of that variant (see its
/// doc comment on [`TzapX509VerificationReport::trust_anchor`]).
///
/// `chain_validation_time_unix_seconds` must be the same time basis the main
/// verification used (Z3: the footer's claimed signing time) — reclassifying
/// at a different time could disagree with a verification that already
/// succeeded, e.g. misreporting `Untrusted` for a since-expired official
/// root that was valid, and validated the chain, at signing time.
pub(crate) fn classify_x509_trust_anchor(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trust: &TzapX509TrustOptions,
    chain_validation_time_unix_seconds: i64,
) -> TzapX509TrustAnchor {
    if !trust.include_official_tzap_root {
        return TzapX509TrustAnchor::Untrusted;
    }
    let Ok(production_root_der) = certificate_der_from_pem_or_der(crate::trust::OFFICIAL_TZAP_ROOT_CERT_PEM) else {
        return TzapX509TrustAnchor::Untrusted;
    };
    let Ok(staging_root_der) = certificate_der_from_pem_or_der(crate::trust::OFFICIAL_TZAP_STAGING_ROOT_PEM) else {
        return TzapX509TrustAnchor::Untrusted;
    };
    classify_x509_trust_anchor_against(footer, archive_root, &production_root_der, &staging_root_der, chain_validation_time_unix_seconds)
}

/// The comparison half of [`classify_x509_trust_anchor`], taking the two
/// official root DERs as parameters instead of reading the embedded PEM
/// constants directly. Split out so tests can substitute test roots for the
/// real (private-key-less, from this crate's perspective) production and
/// staging roots.
fn classify_x509_trust_anchor_against(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    production_root_der: &[u8],
    staging_root_der: &[u8],
    chain_validation_time_unix_seconds: i64,
) -> TzapX509TrustAnchor {
    if verify_root_auth_footer_at_time(footer, archive_root, &[production_root_der.to_vec()], false, false, Some(chain_validation_time_unix_seconds)).is_ok() {
        return TzapX509TrustAnchor::ProductionRoot;
    }
    if verify_root_auth_footer_at_time(footer, archive_root, &[staging_root_der.to_vec()], false, false, Some(chain_validation_time_unix_seconds)).is_ok() {
        return TzapX509TrustAnchor::StagingRoot;
    }
    TzapX509TrustAnchor::Untrusted
}

fn verify_opened_x509_root_auth(opened: &OpenedArchive, trust: &TzapX509TrustOptions) -> Result<TzapX509VerificationReport, TzapError> {
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut trust_anchor = TzapX509TrustAnchor::Untrusted;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| {
            // Z3: validate the chain at the footer's claimed signing time
            // rather than verifier-now, so an archive doesn't stop verifying
            // ~90 days after signing purely because the signing certificate
            // has since expired. `signed_at_unix_seconds` is signer-claimed
            // and covered by the signature, so it can't be altered by a
            // third party, but a dishonest signer could backdate it — this
            // defends against honest expiry, not a dishonest signer.
            let signed_at_unix_seconds = match claimed_signing_time(footer, archive_root) {
                Ok(value) => value,
                Err(error) => {
                    x509_error = Some(error.to_string());
                    return Ok(false);
                }
            };
            match verify_root_auth_footer_at_time(
                footer,
                archive_root,
                &trusted_roots_der,
                trust.trusted_system_roots,
                trust.include_official_tzap_root,
                Some(signed_at_unix_seconds),
            ) {
                Ok(value) => {
                    trust_anchor = classify_x509_trust_anchor(footer, archive_root, trust, signed_at_unix_seconds);
                    report = Some(value);
                    Ok(true)
                }
                Err(error) => {
                    x509_error = Some(error.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 RootAuth verification report")))?;

    Ok(x509_report_from_verification(
        verification.archive_root,
        verification.authenticator_id,
        verification.signer_identity_type,
        verification.total_data_block_count,
        report,
        trust_anchor,
        &verification.diagnostics,
        root_auth_diagnostic_labels,
    ))
}

/// Maps a successful X.509 `RootAuth` verification and its tzap-plugin report
/// into the public [`TzapX509VerificationReport`], rendering diagnostics with
/// the verification flavor's label function.
#[allow(clippy::too_many_arguments)]
fn x509_report_from_verification<Diagnostics>(
    archive_root: [u8; 32],
    authenticator_id: u16,
    signer_identity_type: u16,
    total_data_block_count: u64,
    report: X509RootAuthReport,
    trust_anchor: TzapX509TrustAnchor,
    diagnostics: &[Diagnostics],
    diagnostics_labels: fn(&[Diagnostics]) -> Vec<String>,
) -> TzapX509VerificationReport {
    TzapX509VerificationReport {
        archive_root,
        authenticator_id,
        signer_identity_type,
        total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: report.subject,
        issuer: report.issuer,
        serial_number_hex: report.serial_number_hex,
        certificate_sha256: report.certificate_sha256,
        verified_chain_subjects: report.verified_chain_subjects,
        trust_anchor_subject: report.trust_anchor_subject,
        trust_anchor,
        diagnostics: diagnostics_labels(diagnostics),
    }
}

fn root_auth_diagnostic_labels(diagnostics: &[RootAuthDiagnostic]) -> Vec<String> {
    diagnostics.iter().map(|diagnostic| diagnostic.label().to_owned()).collect()
}

fn public_no_key_diagnostic_labels(diagnostics: &[PublicNoKeyDiagnostic]) -> Vec<String> {
    diagnostics.iter().map(|diagnostic| diagnostic.label().to_owned()).collect()
}

/// Tests `.tzap` archive readability and integrity with a filter.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened or verified.
pub fn test_tzap_with_password_filter(archive: impl AsRef<Path>, password: &str, selector: impl Fn(&str) -> bool) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(archive, Some(password), selector, None)
}

/// Tests `.tzap` archive readability and integrity with optional X.509 `RootAuth` verification.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: &str,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    test_tzap_with_optional_password_filter_and_x509_trust(archive, Some(password), selector, x509_trust)
}

/// Tests `.tzap` archive readability and integrity with an optional passphrase.
///
/// When `password` is [`None`], unencrypted archives are opened without a key,
/// and legacy no-secret raw-key archives are opened with tzap's all-zero key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_optional_password_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    password: Option<&str>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

/// Tests recipient-wrapped `.tzap` readability and integrity with a private key.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_recipient_key_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    recipient_private_key: impl AsRef<Path>,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive_with_recipient_key(archive, recipient_private_key)?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

/// Tests recipient-wrapped `.tzap` readability and integrity with an
/// in-memory private key, for callers that must not write key material to
/// disk.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub fn test_tzap_with_recipient_key_bytes_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    recipient_private_key_bytes: &[u8],
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive_with_key_options(archive, None, None, Some(recipient_private_key_bytes))?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

/// Plural form of [`test_tzap_with_recipient_key_bytes_filter_and_x509_trust`]
/// for a device holding several recipient private keys at once (design §9.4).
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, verified, or when
/// requested X.509 `RootAuth` verification fails.
pub(crate) fn test_tzap_with_recipient_key_bytes_list_filter_and_x509_trust(
    archive: impl AsRef<Path>,
    recipient_private_key_bytes_list: &[Vec<u8>],
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    let opened = open_tzap_archive_with_key_options_multi(archive, None, None, Some(recipient_private_key_bytes_list))?;
    test_opened_tzap_archive(&opened, selector, x509_trust)
}

fn test_opened_tzap_archive(
    opened: &OpenedArchive,
    selector: impl Fn(&str) -> bool,
    x509_trust: Option<&TzapX509TrustOptions>,
) -> Result<TzapTestReport, TzapError> {
    opened.verify()?;
    let x509_root_auth = match x509_trust.filter(|trust| trust.has_trust_source()) {
        Some(trust) if should_verify_opened_x509_root_auth(opened, trust) => Some(verify_opened_x509_root_auth(opened, trust)?),
        _ => None,
    };
    let entries = opened.list_files()?;
    let mut tested_entries = 0usize;
    let mut tested_bytes = 0u64;
    for entry in &entries {
        if selector(&entry.path) {
            tested_entries += 1;
            if entry.kind == TarEntryKind::Regular {
                tested_bytes = tested_bytes.saturating_add(entry.file_data_size);
            }
        }
    }
    Ok(TzapTestReport { entries: entries.len(), tested_entries, skipped_entries: entries.len().saturating_sub(tested_entries), tested_bytes, x509_root_auth })
}

fn should_verify_opened_x509_root_auth(opened: &OpenedArchive, trust: &TzapX509TrustOptions) -> bool {
    let explicit_trust = !trust.trusted_ca_certificates.is_empty() || trust.trusted_system_roots;
    let has_x509_root_auth = opened.root_auth_footer.as_ref().is_some_and(|footer| footer.authenticator_id == X509_AUTHENTICATOR_ID);
    explicit_trust || has_x509_root_auth
}

/// Verifies a TZAP X.509 `RootAuth` without the archive key.
///
/// This checks the public data-block commitment and X.509 authenticator, but it
/// does not decrypt entries or prove that recovery/parity material is complete.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive volumes cannot be read, the public
/// commitment does not verify, or X.509 trust validation fails.
pub fn verify_tzap_x509_public_no_key(archive: impl AsRef<Path>, trust: &TzapX509TrustOptions) -> Result<TzapX509VerificationReport, TzapError> {
    if !trust.has_trust_source() {
        return Err(TzapError::X509RootAuth("X.509 verification requires trusted roots".to_owned()));
    }

    let archive_path = archive.as_ref();
    let volumes = open_tzap_input_volume_readers(archive_path)?;
    let volume_refs = volumes.iter().map(|file| file as &dyn ArchiveReadAt).collect::<Vec<_>>();
    let trusted_roots_der = load_x509_trusted_roots(trust)?;
    let mut report = None;
    let mut trust_anchor = TzapX509TrustAnchor::Untrusted;
    let mut x509_error = None;
    let verification = public_no_key_verify_readers_with(&volume_refs, |footer, archive_root| {
        if footer.authenticator_id != X509_AUTHENTICATOR_ID {
            return Err(FormatError::ReaderUnsupported("X.509 trust can only verify X.509 RootAuth"));
        }
        // Z3: same signing-time basis as verify_opened_x509_root_auth — see
        // its comment for why the footer's own claimed time is used instead
        // of verifier-now.
        let signed_at_unix_seconds = match claimed_signing_time(footer, archive_root) {
            Ok(value) => value,
            Err(error) => {
                x509_error = Some(error.to_string());
                return Ok(false);
            }
        };
        match verify_root_auth_footer_at_time(
            footer,
            archive_root,
            &trusted_roots_der,
            trust.trusted_system_roots,
            trust.include_official_tzap_root,
            Some(signed_at_unix_seconds),
        ) {
            Ok(value) => {
                trust_anchor = classify_x509_trust_anchor(footer, archive_root, trust, signed_at_unix_seconds);
                report = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        }
    })
    .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let report = report.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 public no-key verification report")))?;

    Ok(x509_report_from_verification(
        verification.archive_root,
        verification.authenticator_id,
        verification.signer_identity_type,
        verification.total_data_block_count,
        report,
        trust_anchor,
        &verification.diagnostics,
        public_no_key_diagnostic_labels,
    ))
}

/// Inspects a TZAP X.509 `RootAuth` signer without validating trust roots.
///
/// This verifies archive content, `RootAuth` commitments, and the `RootAuth`
/// signature made by the embedded leaf certificate. It intentionally does not
/// validate that certificate against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when the archive cannot be opened, the `RootAuth`
/// signature does not match the embedded certificate, or the archive is not
/// signed with the X.509 `RootAuth` profile.
pub fn inspect_tzap_x509_signer(archive: impl AsRef<Path>, password: Option<&str>) -> Result<TzapX509SignerInspection, TzapError> {
    let opened = open_tzap_archive(archive, password)?;
    inspect_opened_x509_signer(&opened)
}

/// Inspects a TZAP X.509 `RootAuth` signer without the archive key or trust roots.
///
/// This checks the public data-block commitment and the `RootAuth` signature, but
/// does not decrypt entries, prove recovery/parity material is complete, or
/// validate the certificate chain against a trusted root.
///
/// # Errors
///
/// Returns [`TzapError`] when public no-key inspection cannot read the volume
/// set, the `RootAuth` signature does not match the embedded certificate, or the
/// archive is not signed with the X.509 `RootAuth` profile.
pub fn inspect_tzap_x509_public_no_key_signer(archive: impl AsRef<Path>) -> Result<TzapX509SignerInspection, TzapError> {
    let archive_path = archive.as_ref();
    let volumes = open_tzap_input_volume_readers(archive_path)?;
    let volume_refs = volumes.iter().map(|file| file as &dyn ArchiveReadAt).collect::<Vec<_>>();
    let mut inspection = None;
    let mut x509_error = None;
    let verification = public_no_key_verify_readers_with(&volume_refs, |footer, archive_root| match inspect_x509_root_auth_footer(footer, archive_root) {
        Ok(value) => {
            inspection = Some(value);
            Ok(true)
        }
        Err(error) => {
            x509_error = Some(error.to_string());
            Ok(false)
        }
    })
    .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 public no-key signer inspection report")))?;
    inspection.diagnostics = public_no_key_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

fn inspect_opened_x509_signer(opened: &OpenedArchive) -> Result<TzapX509SignerInspection, TzapError> {
    let mut inspection = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| match inspect_x509_root_auth_footer(footer, archive_root) {
            Ok(value) => {
                inspection = Some(value);
                Ok(true)
            }
            Err(error) => {
                x509_error = Some(error.to_string());
                Ok(false)
            }
        })
        .map_err(|source| if let Some(detail) = x509_error { TzapError::X509RootAuth(format!("{source}: {detail}")) } else { TzapError::Format(source) })?;
    let mut inspection = inspection.ok_or(TzapError::Format(FormatError::InvalidArchive("missing X.509 signer inspection report")))?;
    inspection.diagnostics = root_auth_diagnostic_labels(&verification.diagnostics);
    Ok(inspection)
}

pub(crate) fn inspect_x509_root_auth_footer(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> Result<TzapX509SignerInspection, TzapError> {
    // All crypto is delegated to the plugin's trust-less assertion-1 check
    // (scheme-aware: RSA-PKCS1 / ECDSA / RSA-PSS). This wrapper only adds the
    // display fields derived from the embedded leaf certificate.
    let report = verify_root_auth_signature(footer, archive_root).map_err(|error| TzapError::X509RootAuth(error.to_string()))?;
    let leaf_certificate = X509::from_der(&footer.signer_identity_bytes).map_err(|source| TzapError::X509RootAuth(source.to_string()))?;
    Ok(TzapX509SignerInspection {
        archive_root: *archive_root,
        authenticator_id: footer.authenticator_id,
        signer_identity_type: footer.signer_identity_type,
        total_data_block_count: footer.total_data_block_count,
        signed_at_unix_seconds: report.signed_at_unix_seconds,
        subject: x509_name_to_string(leaf_certificate.subject_name()),
        issuer: x509_name_to_string(leaf_certificate.issuer_name()),
        serial_number_hex: leaf_certificate
            .serial_number()
            .to_bn()
            .and_then(|serial| serial.to_hex_str())
            .map_err(|source| TzapError::X509RootAuth(source.to_string()))?
            .to_string(),
        certificate_sha256: report.certificate_sha256,
        diagnostics: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{TzapX509TrustAnchor, TzapX509TrustOptions, classify_x509_trust_anchor_against, load_x509_trusted_roots};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509NameBuilder};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tzap_core::format::{FORMAT_VERSION, VOLUME_FORMAT_REV};
    use tzap_core::wire::RootAuthFooterV1;
    use tzap_core::writer::RootAuthSigningRequest;
    use tzap_plugin_signing::x509_chain::{X509_AUTHENTICATOR_ID, X509_SIGNER_IDENTITY_TYPE_DER_CERT, X509RootAuthSigner};

    #[test]
    fn x509_trust_options_can_include_embedded_official_root() {
        let trust = TzapX509TrustOptions { trusted_ca_certificates: Vec::new(), trusted_system_roots: false, include_official_tzap_root: true };

        let roots = load_x509_trusted_roots(&trust).unwrap();

        assert_eq!(roots.len(), 2);
        assert_eq!(crate::trust::certificate_sha256_identifier_for_der(&roots[0]), crate::trust::TZAP_PRODUCTION_ROOT_SHA256);
        assert_eq!(crate::trust::certificate_sha256_identifier_for_der(&roots[1]), crate::trust::TZAP_STAGING_ROOT_SHA256);
        let root = X509::from_der(&roots[0]).unwrap();
        assert_eq!(crate::x509_format::x509_name_to_string(root.subject_name()), "CN=TZAP Production Root CA 2026, O=TZAP, C=AU");
        let staging = X509::from_der(&roots[1]).unwrap();
        assert_eq!(crate::x509_format::x509_name_to_string(staging.subject_name()), "CN=TZAP Staging Root CA 2026, O=TZAP, C=AU");
    }

    #[test]
    fn trust_anchor_classification_distinguishes_production_staging_and_untrusted() {
        // Z2: derived by actually re-verifying against each candidate root in
        // isolation, never by matching a subject string.
        let (production_stand_in, production_key) = test_ca_cert("Stand-in Production Root");
        let (staging_stand_in, _staging_key) = test_ca_cert("Stand-in Staging Root");
        let (untrusted_root, untrusted_key) = test_ca_cert("Some Other Root");
        let (leaf_cert, leaf_key) = test_leaf_cert("Archive Signer", &production_stand_in, &production_key);
        let (footer, archive_root) = signed_footer(&leaf_cert, &leaf_key, Vec::new());
        let now = now_unix_seconds();

        assert_eq!(
            classify_x509_trust_anchor_against(&footer, &archive_root, &production_stand_in.to_der().unwrap(), &staging_stand_in.to_der().unwrap(), now),
            TzapX509TrustAnchor::ProductionRoot
        );
        assert_eq!(
            classify_x509_trust_anchor_against(&footer, &archive_root, &staging_stand_in.to_der().unwrap(), &production_stand_in.to_der().unwrap(), now),
            TzapX509TrustAnchor::StagingRoot
        );
        assert_eq!(
            classify_x509_trust_anchor_against(&footer, &archive_root, &untrusted_root.to_der().unwrap(), &staging_stand_in.to_der().unwrap(), now),
            TzapX509TrustAnchor::Untrusted
        );
        let _ = untrusted_key;
    }

    #[test]
    fn trust_anchor_classification_is_untrusted_when_official_root_is_not_in_play() {
        let trust = TzapX509TrustOptions { trusted_ca_certificates: Vec::new(), trusted_system_roots: false, include_official_tzap_root: false };
        let (root_cert, root_key) = test_ca_cert("Custom Root");
        let (leaf_cert, leaf_key) = test_leaf_cert("Archive Signer", &root_cert, &root_key);
        let (footer, archive_root) = signed_footer(&leaf_cert, &leaf_key, Vec::new());

        assert_eq!(super::classify_x509_trust_anchor(&footer, &archive_root, &trust, now_unix_seconds()), TzapX509TrustAnchor::Untrusted);
    }

    fn test_ca_cert(cn: &str) -> (X509, PKey<Private>) {
        test_ca_cert_valid_from(cn, now_unix_seconds())
    }

    #[test]
    fn signing_time_validation_extracts_and_uses_the_footers_claimed_time() {
        // Z3: an archive signed while its certificate was valid must keep
        // verifying after that certificate has since expired, and the time
        // used for that check must come from the footer itself, not from
        // wherever the test happens to run.
        let signed_at = now_unix_seconds() - 30 * 86_400; // 30 days ago
        let (root_cert, root_key) = test_ca_cert_valid_from("Stand-in Production Root", signed_at - 86_400);
        let (leaf_cert, leaf_key) = test_leaf_cert_valid_between("Archive Signer", &root_cert, &root_key, signed_at - 3_600, signed_at + 3_600);
        let (footer, archive_root) = signed_footer_at(&leaf_cert, &leaf_key, Vec::new(), signed_at);

        assert_eq!(super::claimed_signing_time(&footer, &archive_root).unwrap(), signed_at);

        let other_root_der = test_ca_cert("Stand-in Staging Root").0.to_der().unwrap();
        let now = now_unix_seconds();
        // Reclassifying at verifier-now would fail: the leaf's validity
        // window (signed_at +/- 1h) is long past. At the extracted signing
        // time, it succeeds.
        assert_eq!(
            classify_x509_trust_anchor_against(&footer, &archive_root, &root_cert.to_der().unwrap(), &other_root_der, now),
            TzapX509TrustAnchor::Untrusted
        );
        assert_eq!(
            classify_x509_trust_anchor_against(&footer, &archive_root, &root_cert.to_der().unwrap(), &other_root_der, signed_at),
            TzapX509TrustAnchor::ProductionRoot
        );
    }

    fn test_ca_cert_valid_from(cn: &str, not_before: i64) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::from_unix(not_before).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_leaf_cert(cn: &str, ca_cert: &X509, ca_key: &PKey<Private>) -> (X509, PKey<Private>) {
        test_leaf_cert_valid_between(cn, ca_cert, ca_key, now_unix_seconds(), now_unix_seconds() + 365 * 86_400)
    }

    fn test_leaf_cert_valid_between(cn: &str, ca_cert: &X509, ca_key: &PKey<Private>, not_before: i64, not_after: i64) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::from_unix(not_before).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::from_unix(not_after).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn now_unix_seconds() -> i64 {
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
    }

    fn signed_footer(leaf_cert: &X509, leaf_key: &PKey<Private>, chain_der: Vec<Vec<u8>>) -> (RootAuthFooterV1, [u8; 32]) {
        signed_footer_at(leaf_cert, leaf_key, chain_der, now_unix_seconds())
    }

    fn signed_footer_at(leaf_cert: &X509, leaf_key: &PKey<Private>, chain_der: Vec<Vec<u8>>, signed_at_unix_seconds: i64) -> (RootAuthFooterV1, [u8; 32]) {
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key.clone(), chain_der, signed_at_unix_seconds).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: tzap_core::format::ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let value = signer.authenticator_value_for_request(&request).unwrap();
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };
        (footer, request.archive_root)
    }

    mod default_signing_certificate_resolution {
        use super::super::resolve_default_signing_certificate_id;
        use crate::local_identity_store::{
            TzapCertificateStatusCacheRecord, TzapEmergencyBlocklistState, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
            TzapLocalIdentityInventory, TzapSignDeviceRouting,
        };
        use crate::trust::{self, TzapCertificatePublicMetadata, TzapCertificateStatus, TzapIdentityAssurance};

        const SIGNING_KEY: &str = "device-key-1";
        const OTHER_KEY: &str = "device-key-2";

        #[test]
        fn picks_the_newest_usable_certificate_for_the_signing_key() {
            let inventory = inventory_with(vec![
                certificate("cert-old", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 200),
                certificate("cert-new", SIGNING_KEY, TzapLocalCertificateState::Active, 150, 250),
            ]);

            assert_eq!(resolve_default_signing_certificate_id(&inventory, SIGNING_KEY, 180).unwrap(), "cert-new");
        }

        #[test]
        fn skips_inactive_expired_not_yet_valid_blocklisted_and_status_blocked_candidates() {
            let mut inventory = inventory_with(vec![
                certificate("cert-revoked", SIGNING_KEY, TzapLocalCertificateState::Revoked, 100, 900),
                certificate("cert-expired", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 150),
                certificate("cert-not-yet-valid", SIGNING_KEY, TzapLocalCertificateState::Active, 500, 900),
                certificate("cert-blocklisted", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 900),
                certificate("cert-status-blocked", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 900),
                certificate("cert-good", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 900),
            ]);
            inventory.emergency_blocklist = TzapEmergencyBlocklistState {
                blocked_root_sha256: Vec::new(),
                blocked_issuer_sha256: vec![issuer_sha("cert-blocklisted")],
                updated_at_unix_seconds: None,
            };
            inventory.certificate_status_cache.push(TzapCertificateStatusCacheRecord {
                certificate_sha256: leaf_sha("cert-status-blocked"),
                status: TzapCertificateStatus::Suspended,
                this_update_unix_seconds: 100,
                next_update_unix_seconds: 900,
            });

            assert_eq!(resolve_default_signing_certificate_id(&inventory, SIGNING_KEY, 200).unwrap(), "cert-good");
        }

        #[test]
        fn ignores_candidates_for_a_different_signing_key() {
            let inventory = inventory_with(vec![
                certificate("cert-mine", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 900),
                certificate("cert-newer-but-not-mine", OTHER_KEY, TzapLocalCertificateState::Active, 500, 900),
            ]);

            assert_eq!(resolve_default_signing_certificate_id(&inventory, SIGNING_KEY, 200).unwrap(), "cert-mine");
        }

        #[test]
        fn errors_when_no_certificate_is_usable() {
            let inventory = inventory_with(Vec::new());
            assert!(resolve_default_signing_certificate_id(&inventory, SIGNING_KEY, 200).is_err());

            let inventory = inventory_with(vec![certificate("cert-expired", SIGNING_KEY, TzapLocalCertificateState::Active, 100, 150)]);
            assert!(resolve_default_signing_certificate_id(&inventory, SIGNING_KEY, 200).is_err());
        }

        fn inventory_with(certificates: Vec<TzapEnrolledCertificateRecord>) -> TzapLocalIdentityInventory {
            let mut inventory = TzapLocalIdentityInventory::empty();
            inventory.enrolled_certificates = certificates;
            inventory
        }

        fn certificate(
            id: &str,
            signing_key_id: &str,
            state: TzapLocalCertificateState,
            not_before_unix_seconds: u64,
            not_after_unix_seconds: u64,
        ) -> TzapEnrolledCertificateRecord {
            TzapEnrolledCertificateRecord {
                certificate_id: id.to_owned(),
                certificate_sha256: leaf_sha(id),
                issuer_certificate_sha256: issuer_sha(id),
                issuer_key_identifier: "AQIDBA".to_owned(),
                serial_number: "01".to_owned(),
                leaf_certificate_der: vec![0x30, 0x01],
                intermediate_chain_der: vec![vec![0x30, 0x02]],
                not_before_unix_seconds,
                not_after_unix_seconds,
                renewal_grace_period_days: None,
                renewal_recommended_within_days: None,
                public_metadata: TzapCertificatePublicMetadata {
                    version: 1,
                    public_signer_id: "psign_0123456789ABCDEFGH".to_owned(),
                    public_org_id: None,
                    public_device_id: "pdev_0123456789ABCDEFGH".to_owned(),
                    assurance_level: TzapIdentityAssurance::OauthVerifiedEmail,
                    policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
                },
                sign_device_id: "sign-device-1".to_owned(),
                sign_device_routing: TzapSignDeviceRouting::Personal,
                signing_key_id: signing_key_id.to_owned(),
                state,
            }
        }

        // Each certificate gets its own leaf/issuer fingerprint (derived from
        // its id) so per-certificate blocklist/status-cache fixtures target
        // exactly one candidate without affecting the others.
        fn leaf_sha(id: &str) -> String {
            trust::sha256_identifier(format!("leaf:{id}").as_bytes())
        }

        fn issuer_sha(id: &str) -> String {
            trust::sha256_identifier(format!("issuer:{id}").as_bytes())
        }
    }
}
