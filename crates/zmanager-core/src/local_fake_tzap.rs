//! Deterministic local fake TZAP service operations for obligation harnesses.

use crate::auth_client::{SESSION_AUDIENCE_SIGN_TZAP, TzapAuthError, TzapSessionRecord};
use crate::certificate_lifecycle::TzapRetirementCompletion;
use crate::device_identity::{TzapDeviceCsrOptions, generate_device_signing_key_and_csr};
use crate::local_identity_store::{
    TzapDeviceSigningKeyRecord, TzapEnrolledCertificateRecord, TzapLocalCertificateState,
    TzapLocalIdentityInventory, TzapLocalIdentityStore, TzapLocalIdentityStoreError,
    TzapSignDeviceRouting,
};
use crate::trust::{self, TzapCertificatePublicMetadata};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Extension, X509NameBuilder, X509Ref};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer as _, X509Certificate};

const FAKE_ROOT_CN: &str = "ZManager Local Fake TZAP Root";
const FAKE_PLATFORM_CN: &str = "ZManager Local Fake TZAP Platform";
const FAKE_SIGNER_CN: &str = "ZManager Local Fake TZAP Signer";
const FAKE_SIGNER_ID: &str = "psign_0123456789ABCDEFGH";
const FAKE_DEVICE_ID: &str = "pdev_0123456789ABCDEFGH";
const FAKE_CERTIFICATE_ID_PREFIX: &str = "fake-cert-";
const FAKE_RENEWED_CERTIFICATE_ID_PREFIX: &str = "fake-renewed-cert-";
const FAKE_SIGN_DEVICE_ID_PREFIX: &str = "fake-sign-device-";
const FAKE_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalFakeServiceOptions {
    pub account_key: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapLocalFakeRetirementReport {
    pub completion: TzapRetirementCompletion,
    pub attempted_sign_device_ids: Vec<String>,
}

#[derive(Debug)]
pub enum TzapLocalFakeServiceError {
    Auth(TzapAuthError),
    Store(TzapLocalIdentityStoreError),
    Crypto(String),
    CertificateNotFound,
    SessionExpired,
}

impl fmt::Display for TzapLocalFakeServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "fake TZAP auth failed: {error}"),
            Self::Store(error) => write!(f, "fake TZAP store update failed: {error}"),
            Self::Crypto(reason) => write!(f, "fake TZAP certificate generation failed: {reason}"),
            Self::CertificateNotFound => write!(f, "certificate was not found locally"),
            Self::SessionExpired => write!(f, "session expired"),
        }
    }
}

impl std::error::Error for TzapLocalFakeServiceError {}

impl From<TzapAuthError> for TzapLocalFakeServiceError {
    fn from(error: TzapAuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<TzapLocalIdentityStoreError> for TzapLocalFakeServiceError {
    fn from(error: TzapLocalIdentityStoreError) -> Self {
        Self::Store(error)
    }
}

pub fn enroll_local_fake_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalFakeServiceOptions,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalFakeServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let signing_key = ensure_device_signing_key(&mut inventory, options.now_unix_seconds)?;
    let record = issue_fake_certificate(
        &signing_key,
        fake_certificate_id(
            FAKE_CERTIFICATE_ID_PREFIX,
            inventory.enrolled_certificates.len() + 1,
        ),
        options.now_unix_seconds,
    )?;
    inventory
        .enrolled_certificates
        .retain(|existing| existing.certificate_sha256 != record.certificate_sha256);
    inventory.enrolled_certificates.push(record.clone());
    store.save_inventory(&options.account_key, inventory)?;
    Ok(record)
}

pub fn renew_local_fake_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalFakeServiceOptions,
    certificate_id: &str,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalFakeServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let previous = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == certificate_id)
        .cloned()
        .ok_or(TzapLocalFakeServiceError::CertificateNotFound)?;
    if !matches!(previous.state, TzapLocalCertificateState::Active) {
        return Err(TzapLocalFakeServiceError::CertificateNotFound);
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|record| record.key_id == previous.signing_key_id)
        .cloned()
        .ok_or(TzapLocalFakeServiceError::CertificateNotFound)?;
    let record = issue_fake_certificate(
        &signing_key,
        fake_certificate_id(
            FAKE_RENEWED_CERTIFICATE_ID_PREFIX,
            inventory.enrolled_certificates.len() + 1,
        ),
        options.now_unix_seconds,
    )?;
    inventory.enrolled_certificates.push(record.clone());
    store.save_inventory(&options.account_key, inventory)?;
    Ok(record)
}

pub fn revoke_local_fake_certificate(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalFakeServiceOptions,
    certificate_id: &str,
) -> Result<TzapRetirementCompletion, TzapLocalFakeServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let mut found = false;
    for certificate in &mut inventory.enrolled_certificates {
        if certificate.certificate_id == certificate_id {
            certificate.state = TzapLocalCertificateState::Revoked;
            found = true;
        }
    }
    if !found {
        return Err(TzapLocalFakeServiceError::CertificateNotFound);
    }
    store.save_inventory(&options.account_key, inventory)?;
    Ok(TzapRetirementCompletion::Complete)
}

pub fn retire_local_fake_device(
    store: &mut impl TzapLocalIdentityStore,
    session: &TzapSessionRecord,
    options: &TzapLocalFakeServiceOptions,
) -> Result<TzapLocalFakeRetirementReport, TzapLocalFakeServiceError> {
    require_active_sign_session(session, options.now_unix_seconds)?;
    let mut inventory = store.load_inventory(&options.account_key)?;
    let mut attempted = Vec::new();
    for certificate in &mut inventory.enrolled_certificates {
        if certificate.state == TzapLocalCertificateState::Active
            && matches!(
                certificate.sign_device_routing,
                TzapSignDeviceRouting::Personal
            )
        {
            attempted.push(certificate.sign_device_id.clone());
            certificate.state = TzapLocalCertificateState::Revoked;
        }
    }
    store.save_inventory(&options.account_key, inventory)?;
    Ok(TzapLocalFakeRetirementReport {
        completion: TzapRetirementCompletion::Complete,
        attempted_sign_device_ids: attempted,
    })
}

fn require_active_sign_session(
    session: &TzapSessionRecord,
    now_unix_seconds: u64,
) -> Result<(), TzapLocalFakeServiceError> {
    session.require_audience(SESSION_AUDIENCE_SIGN_TZAP)?;
    if session.is_expired_at(now_unix_seconds) {
        return Err(TzapLocalFakeServiceError::SessionExpired);
    }
    Ok(())
}

fn ensure_device_signing_key(
    inventory: &mut TzapLocalIdentityInventory,
    now_unix_seconds: u64,
) -> Result<TzapDeviceSigningKeyRecord, TzapLocalFakeServiceError> {
    if let Some(record) = inventory.device_signing_keys.first() {
        return Ok(record.clone());
    }
    let material = generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let record = TzapDeviceSigningKeyRecord {
        key_id: material.public_key_fingerprint.clone(),
        public_key_fingerprint: material.public_key_fingerprint,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: now_unix_seconds,
        label: Some("Local fake TZAP signing key".to_owned()),
    };
    inventory.device_signing_keys.push(record.clone());
    Ok(record)
}

fn issue_fake_certificate(
    signing_key: &TzapDeviceSigningKeyRecord,
    certificate_id: String,
    now_unix_seconds: u64,
) -> Result<TzapEnrolledCertificateRecord, TzapLocalFakeServiceError> {
    let leaf_key = PKey::private_key_from_der(signing_key.private_key_der.expose_secret())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let chain = certificate_chain_for_leaf_key(leaf_key.as_ref(), now_unix_seconds)?;
    Ok(TzapEnrolledCertificateRecord {
        certificate_id,
        certificate_sha256: chain.leaf_sha256,
        issuer_certificate_sha256: chain.platform_sha256,
        issuer_key_identifier: chain.issuer_key_identifier,
        serial_number: chain.serial_number,
        leaf_certificate_der: chain.leaf_der,
        intermediate_chain_der: vec![chain.platform_der, chain.root_der],
        not_before_unix_seconds: now_unix_seconds,
        not_after_unix_seconds: now_unix_seconds.saturating_add(FAKE_VALIDITY_SECONDS),
        public_metadata: public_metadata(),
        sign_device_id: fake_sign_device_id(&signing_key.public_key_fingerprint),
        sign_device_routing: TzapSignDeviceRouting::Personal,
        signing_key_id: signing_key.key_id.clone(),
        state: TzapLocalCertificateState::Active,
    })
}

#[derive(Debug)]
struct IssuedChain {
    leaf_der: Vec<u8>,
    platform_der: Vec<u8>,
    root_der: Vec<u8>,
    leaf_sha256: String,
    platform_sha256: String,
    issuer_key_identifier: String,
    serial_number: String,
}

fn certificate_chain_for_leaf_key(
    leaf_key: &PKeyRef<Private>,
    now_unix_seconds: u64,
) -> Result<IssuedChain, TzapLocalFakeServiceError> {
    let root_key = p256_private_key()?;
    let platform_key = p256_private_key()?;
    let root = root_certificate(root_key.as_ref(), now_unix_seconds)?;
    let platform = intermediate_certificate(
        platform_key.as_ref(),
        root.as_ref(),
        root_key.as_ref(),
        root.as_ref(),
        now_unix_seconds,
    )?;
    let leaf = leaf_certificate(
        leaf_key,
        platform.as_ref(),
        platform_key.as_ref(),
        platform.as_ref(),
        now_unix_seconds,
    )?;
    let leaf_der = leaf
        .to_der()
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let platform_der = platform
        .to_der()
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let root_der = root
        .to_der()
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let platform_parsed = parse_certificate(&platform_der, "platform")?;
    let leaf_parsed = parse_certificate(&leaf_der, "leaf")?;
    Ok(IssuedChain {
        issuer_key_identifier: URL_SAFE_NO_PAD.encode(
            subject_key_identifier(&platform_parsed).ok_or_else(|| {
                TzapLocalFakeServiceError::Crypto("platform certificate missing SKI".to_owned())
            })?,
        ),
        serial_number: trust::canonical_serial_hex(leaf_parsed.raw_serial())
            .map_err(|_| TzapLocalFakeServiceError::Crypto("invalid serial".to_owned()))?,
        leaf_sha256: sha256_identifier(&leaf_der),
        platform_sha256: sha256_identifier(&platform_der),
        leaf_der,
        platform_der,
        root_der,
    })
}

fn root_certificate(
    key: &PKeyRef<Private>,
    now_unix_seconds: u64,
) -> Result<X509, TzapLocalFakeServiceError> {
    let mut builder = base_certificate_builder(FAKE_ROOT_CN, key, None, now_unix_seconds)?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(2)
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    append_subject_key_identifier(&mut builder, None)?;
    builder
        .sign(key, MessageDigest::sha256())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    Ok(builder.build())
}

fn intermediate_certificate(
    key: &PKeyRef<Private>,
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    aki_source: &X509Ref,
    now_unix_seconds: u64,
) -> Result<X509, TzapLocalFakeServiceError> {
    let mut builder =
        base_certificate_builder(FAKE_PLATFORM_CN, key, Some(issuer_cert), now_unix_seconds)?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    append_subject_key_identifier(&mut builder, None)?;
    append_authority_key_identifier(&mut builder, aki_source)?;
    append_der_extension(
        &mut builder,
        "2.5.29.32",
        false,
        &certificate_policies_der(&[trust::TZAP_OID_CA_POLICY])?,
    )?;
    append_der_extension(&mut builder, "2.5.29.31", false, &[0x30, 0x00])?;
    builder
        .sign(issuer_key, MessageDigest::sha256())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    Ok(builder.build())
}

fn leaf_certificate(
    key: &PKeyRef<Private>,
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    aki_source: &X509Ref,
    now_unix_seconds: u64,
) -> Result<X509, TzapLocalFakeServiceError> {
    let mut builder =
        base_certificate_builder(FAKE_SIGNER_CN, key, Some(issuer_cert), now_unix_seconds)?;
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let mut eku = ExtendedKeyUsage::new();
    eku.other(trust::TZAP_OID_DOCUMENT_SIGNING_EKU);
    builder
        .append_extension(
            eku.build()
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    append_authority_key_identifier(&mut builder, aki_source)?;
    append_der_extension(
        &mut builder,
        "2.5.29.32",
        false,
        &certificate_policies_der(&[trust::TZAP_OID_LEAF_POLICY])?,
    )?;
    append_der_extension(
        &mut builder,
        trust::TZAP_OID_METADATA_EXTENSION,
        false,
        &metadata_extension_bytes()?,
    )?;
    builder
        .sign(issuer_key, MessageDigest::sha256())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    Ok(builder.build())
}

fn base_certificate_builder(
    common_name: &str,
    key: &PKeyRef<Private>,
    issuer: Option<&X509Ref>,
    now_unix_seconds: u64,
) -> Result<openssl::x509::X509Builder, TzapLocalFakeServiceError> {
    let mut name = X509NameBuilder::new()
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    name.append_entry_by_text("CN", common_name)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let name = name.build();
    let mut builder =
        X509::builder().map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .set_version(2)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let serial = serial_number(now_unix_seconds)?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .set_subject_name(&name)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    if let Some(issuer) = issuer {
        builder
            .set_issuer_name(issuer.subject_name())
            .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    } else {
        builder
            .set_issuer_name(&name)
            .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    }
    builder
        .set_pubkey(key)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let not_before = Asn1Time::from_unix(i64::try_from(now_unix_seconds).unwrap_or(i64::MAX))
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let not_after = Asn1Time::from_unix(
        i64::try_from(now_unix_seconds.saturating_add(FAKE_VALIDITY_SECONDS)).unwrap_or(i64::MAX),
    )
    .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    Ok(builder)
}

fn p256_private_key() -> Result<PKey<Private>, TzapLocalFakeServiceError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let key = EcKey::generate(&group)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    PKey::from_ec_key(key).map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))
}

fn serial_number(
    now_unix_seconds: u64,
) -> Result<openssl::asn1::Asn1Integer, TzapLocalFakeServiceError> {
    let serial = (now_unix_seconds % u64::from(u32::MAX - 1)) + 1;
    BigNum::from_u32(u32::try_from(serial).unwrap())
        .and_then(|number| number.to_asn1_integer())
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))
}

fn append_subject_key_identifier(
    builder: &mut openssl::x509::X509Builder,
    issuer: Option<&X509Ref>,
) -> Result<(), TzapLocalFakeServiceError> {
    let extension = {
        let context = builder.x509v3_context(issuer, None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?
    };
    builder
        .append_extension(extension)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))
}

fn append_authority_key_identifier(
    builder: &mut openssl::x509::X509Builder,
    issuer: &X509Ref,
) -> Result<(), TzapLocalFakeServiceError> {
    let extension = {
        let context = builder.x509v3_context(Some(issuer), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?
    };
    builder
        .append_extension(extension)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))
}

fn append_der_extension(
    builder: &mut openssl::x509::X509Builder,
    oid: &str,
    critical: bool,
    contents: &[u8],
) -> Result<(), TzapLocalFakeServiceError> {
    let oid = Asn1Object::from_str(oid)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    let contents = Asn1OctetString::new_from_bytes(contents)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?;
    builder
        .append_extension(
            X509Extension::new_from_der(&oid, critical, &contents)
                .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?,
        )
        .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))
}

fn certificate_policies_der(policies: &[&str]) -> Result<Vec<u8>, TzapLocalFakeServiceError> {
    let policy_infos = policies
        .iter()
        .map(|policy| der_oid(policy).map(|oid| der_sequence(&oid)))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    Ok(der_sequence(&policy_infos))
}

fn der_oid(oid: &str) -> Result<Vec<u8>, TzapLocalFakeServiceError> {
    Ok(der_wrap(
        0x06,
        Asn1Object::from_str(oid)
            .map_err(|error| TzapLocalFakeServiceError::Crypto(error.to_string()))?
            .as_slice(),
    ))
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x30, contents)
}

fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(contents.len()));
    out.extend(contents);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn metadata_extension_bytes() -> Result<Vec<u8>, TzapLocalFakeServiceError> {
    crate::jcs::canonicalize_json_bytes(&json!({
        "version": 1,
        "public_signer_id": FAKE_SIGNER_ID,
        "public_org_id": Value::Null,
        "public_device_id": FAKE_DEVICE_ID,
        "assurance_level": "oauth_verified_email",
        "policy_oid": trust::TZAP_OID_LEAF_POLICY,
    }))
    .map_err(|error| TzapLocalFakeServiceError::Crypto(format!("{error:?}")))
}

fn public_metadata() -> TzapCertificatePublicMetadata {
    TzapCertificatePublicMetadata {
        version: 1,
        public_signer_id: FAKE_SIGNER_ID.to_owned(),
        public_org_id: None,
        public_device_id: FAKE_DEVICE_ID.to_owned(),
        assurance_level: trust::TzapIdentityAssurance::OauthVerifiedEmail,
        policy_oid: trust::TZAP_OID_LEAF_POLICY.to_owned(),
    }
}

fn subject_key_identifier(certificate: &X509Certificate<'_>) -> Option<Vec<u8>> {
    certificate.iter_extensions().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension() {
            Some(identifier.0.to_vec())
        } else {
            None
        }
    })
}

fn parse_certificate<'a>(
    der: &'a [u8],
    label: &'static str,
) -> Result<X509Certificate<'a>, TzapLocalFakeServiceError> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|error| TzapLocalFakeServiceError::Crypto(format!("{label}: {error}")))?;
    if remaining.is_empty() {
        Ok(certificate)
    } else {
        Err(TzapLocalFakeServiceError::Crypto(format!(
            "{label}: trailing DER bytes"
        )))
    }
}

fn sha256_identifier(bytes: &[u8]) -> String {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    trust::format_sha256_identifier(&digest)
}

fn fake_certificate_id(prefix: &str, index: usize) -> String {
    format!("{prefix}{index}")
}

fn fake_sign_device_id(public_key_fingerprint: &str) -> String {
    let suffix = public_key_fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(public_key_fingerprint)
        .chars()
        .take(16)
        .collect::<String>();
    format!("{FAKE_SIGN_DEVICE_ID_PREFIX}{suffix}")
}
