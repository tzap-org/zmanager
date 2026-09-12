//! Shared X.509 test-certificate factory (CR-125).
//!
//! Consolidated from the near-identical copies that used to live in the
//! contact-card and document-verification test modules. Deliberately **not**
//! `#[cfg(test)]`-gated (unlike the rest of `test_support`): sibling crates'
//! own test harnesses (for example `zmanager-mobile-core`'s contact-book
//! tests) compile as external consumers of this crate, where `cfg(test)`
//! never applies, so a real certificate-chain fixture usable from outside
//! this crate has to live in an always-compiled, `#[doc(hidden)]` module --
//! see [`crate::backend_test_support`], which re-exports this one.

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509, X509Extension, X509Ref};
use serde_json::json;

#[derive(Clone, Copy, Default)]
pub struct ChainConfig {
    pub omit_leaf_policy: bool,
}

pub struct CertificateFixture {
    pub chain_der: Vec<Vec<u8>>,
    pub leaf_key: PKey<Private>,
    pub root_sha256: String,
    pub root_der: Vec<u8>,
}

#[must_use]
pub fn certificate_fixture(config: ChainConfig) -> CertificateFixture {
    let root_key = p256_private_key();
    let platform_key = p256_private_key();
    let leaf_key = p256_private_key();
    let root = root_certificate(&root_key);
    let platform = intermediate_certificate(&platform_key, root.as_ref(), root_key.as_ref(), root.as_ref());
    let leaf = leaf_certificate(&leaf_key, platform.as_ref(), platform_key.as_ref(), platform.as_ref(), config);
    let root_der = root.to_der().unwrap();
    CertificateFixture {
        chain_der: vec![leaf.to_der().unwrap(), platform.to_der().unwrap(), root_der.clone()],
        leaf_key,
        root_sha256: crate::trust::sha256_identifier(&root_der),
        root_der,
    }
}

pub fn root_certificate(key: &PKeyRef<Private>) -> X509 {
    let mut builder = base_certificate_builder("TZAP Test Root", key, None);
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(2).build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    append_subject_key_identifier(&mut builder, None);
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

pub fn intermediate_certificate(key: &PKeyRef<Private>, issuer_cert: &X509Ref, issuer_key: &PKeyRef<Private>, aki_source: &X509Ref) -> X509 {
    let mut builder = base_certificate_builder("TZAP Platform Intermediate", key, Some(issuer_cert));
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    append_subject_key_identifier(&mut builder, None);
    append_authority_key_identifier(&mut builder, aki_source);
    append_der_extension(&mut builder, "2.5.29.32", false, &certificate_policies_der(&[crate::trust::TZAP_OID_CA_POLICY]));
    append_der_extension(&mut builder, "2.5.29.31", false, &[0x30, 0x00]);
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

pub fn leaf_certificate(key: &PKeyRef<Private>, issuer_cert: &X509Ref, issuer_key: &PKeyRef<Private>, aki_source: &X509Ref, config: ChainConfig) -> X509 {
    let mut builder = base_certificate_builder("TZAP Test Signer", key, Some(issuer_cert));
    builder.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().critical().build().unwrap()).unwrap();
    builder.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
    builder.append_extension(leaf_eku()).unwrap();
    append_authority_key_identifier(&mut builder, aki_source);
    if !config.omit_leaf_policy {
        append_der_extension(&mut builder, "2.5.29.32", false, &certificate_policies_der(&[crate::trust::TZAP_OID_LEAF_POLICY]));
    }
    append_der_extension(&mut builder, crate::trust::TZAP_OID_METADATA_EXTENSION, false, &metadata_extension_bytes());
    builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

pub fn base_certificate_builder(common_name: &str, key: &PKeyRef<Private>, issuer: Option<&X509Ref>) -> openssl::x509::X509Builder {
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    if let Some(issuer) = issuer {
        builder.set_issuer_name(issuer.subject_name()).unwrap();
    } else {
        builder.set_issuer_name(&name).unwrap();
    }
    builder.set_pubkey(key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
    builder
}

#[must_use]
pub fn p256_private_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

#[must_use]
pub fn serial_number() -> openssl::asn1::Asn1Integer {
    BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap()
}

pub fn append_subject_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: Option<&X509Ref>) {
    let extension = {
        let context = builder.x509v3_context(issuer, None);
        SubjectKeyIdentifier::new().build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

pub fn append_authority_key_identifier(builder: &mut openssl::x509::X509Builder, issuer: &X509Ref) {
    let extension = {
        let context = builder.x509v3_context(Some(issuer), None);
        AuthorityKeyIdentifier::new().keyid(true).build(&context).unwrap()
    };
    builder.append_extension(extension).unwrap();
}

#[must_use]
pub fn leaf_eku() -> X509Extension {
    let mut eku = ExtendedKeyUsage::new();
    eku.other(crate::trust::TZAP_OID_DOCUMENT_SIGNING_EKU);
    eku.build().unwrap()
}

pub fn append_der_extension(builder: &mut openssl::x509::X509Builder, oid: &str, critical: bool, contents: &[u8]) {
    let oid = Asn1Object::from_str(oid).unwrap();
    let contents = Asn1OctetString::new_from_bytes(contents).unwrap();
    builder.append_extension(X509Extension::new_from_der(&oid, critical, &contents).unwrap()).unwrap();
}

#[must_use]
pub fn certificate_policies_der(policies: &[&str]) -> Vec<u8> {
    let policy_infos = policies.iter().flat_map(|policy| der_sequence(&der_oid(policy))).collect::<Vec<_>>();
    der_sequence(&policy_infos)
}

#[must_use]
pub fn der_oid(oid: &str) -> Vec<u8> {
    der_wrap(0x06, Asn1Object::from_str(oid).unwrap().as_slice())
}

#[must_use]
pub fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_wrap(0x30, contents)
}

#[must_use]
pub fn der_wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(contents.len()));
    out.extend(contents);
    out
}

#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

#[must_use]
pub fn metadata_extension_bytes() -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&json!({
        "version": 1,
        "public_signer_id": "psign_0123456789ABCDEFGH",
        "public_org_id": "porg_0123456789ABCDEFGH",
        "public_device_id": "pdev_0123456789ABCDEFGH",
        "assurance_level": "oauth_verified_email",
        "policy_oid": crate::trust::TZAP_OID_LEAF_POLICY,
    }))
    .unwrap()
}
