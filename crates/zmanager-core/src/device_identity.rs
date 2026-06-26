//! Local TZAP device-signing key generation and CSR helpers.

use crate::secrets::SecretBytes;
use crate::trust;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
use sha2::{Digest as _, Sha256};
use std::fmt;

pub const DEVICE_CSR_COMMON_NAME: &str = "TZAP Device Signing Key";
pub const RECIPIENT_ENCRYPTION_KEY_ALGORITHM: &str = "P-256-SPKI";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDeviceCsrOptions {
    pub common_name: String,
}

impl Default for TzapDeviceCsrOptions {
    fn default() -> Self {
        Self {
            common_name: DEVICE_CSR_COMMON_NAME.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapDeviceSigningKeyMaterial {
    pub private_key_der: SecretBytes,
    pub public_key_spki_der: Vec<u8>,
    pub public_key_fingerprint: String,
    pub csr_der: Vec<u8>,
    pub csr_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapRecipientEncryptionKeyMaterial {
    pub algorithm: &'static str,
    pub private_key_der: SecretBytes,
    pub public_key_spki_der: Vec<u8>,
    pub public_key_fingerprint: String,
}

#[derive(Debug)]
pub enum TzapDeviceIdentityError {
    EmptyCommonName,
    RecipientKeyReusesSigningKey,
    Crypto(ErrorStack),
}

impl From<ErrorStack> for TzapDeviceIdentityError {
    fn from(err: ErrorStack) -> Self {
        Self::Crypto(err)
    }
}

impl fmt::Display for TzapDeviceIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommonName => write!(f, "device CSR common name is empty"),
            Self::RecipientKeyReusesSigningKey => {
                write!(f, "recipient encryption key reuses signing key material")
            }
            Self::Crypto(err) => write!(f, "device identity crypto operation failed: {err}"),
        }
    }
}

impl std::error::Error for TzapDeviceIdentityError {}

pub fn generate_device_signing_key_and_csr(
    options: &TzapDeviceCsrOptions,
) -> Result<TzapDeviceSigningKeyMaterial, TzapDeviceIdentityError> {
    if options.common_name.is_empty() {
        return Err(TzapDeviceIdentityError::EmptyCommonName);
    }

    let private_key = generate_p256_private_key()?;
    let public_key_spki_der = private_key.public_key_to_der()?;
    let public_key_fingerprint = spki_fingerprint(&public_key_spki_der);
    let csr_der = build_device_csr(&private_key, options)?;
    let csr_sha256 = csr_fingerprint(&csr_der);

    Ok(TzapDeviceSigningKeyMaterial {
        private_key_der: SecretBytes::from(private_key.private_key_to_der()?),
        public_key_spki_der,
        public_key_fingerprint,
        csr_der,
        csr_sha256,
    })
}

pub fn generate_recipient_encryption_key()
-> Result<TzapRecipientEncryptionKeyMaterial, TzapDeviceIdentityError> {
    let private_key = generate_p256_private_key()?;
    let public_key_spki_der = private_key.public_key_to_der()?;
    let public_key_fingerprint = spki_fingerprint(&public_key_spki_der);

    Ok(TzapRecipientEncryptionKeyMaterial {
        algorithm: RECIPIENT_ENCRYPTION_KEY_ALGORITHM,
        private_key_der: SecretBytes::from(private_key.private_key_to_der()?),
        public_key_spki_der,
        public_key_fingerprint,
    })
}

pub fn ensure_recipient_key_is_distinct_from_signing_key(
    signing_public_key_fingerprint: &str,
    recipient_public_key_fingerprint: &str,
) -> Result<(), TzapDeviceIdentityError> {
    if signing_public_key_fingerprint == recipient_public_key_fingerprint {
        Err(TzapDeviceIdentityError::RecipientKeyReusesSigningKey)
    } else {
        Ok(())
    }
}

fn generate_p256_private_key() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    PKey::from_ec_key(key)
}

fn build_device_csr(
    private_key: &PKey<Private>,
    options: &TzapDeviceCsrOptions,
) -> Result<Vec<u8>, ErrorStack> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", &options.common_name)?;

    let mut builder = X509ReqBuilder::new()?;
    builder.set_subject_name(&name.build())?;
    builder.set_pubkey(private_key)?;
    builder.sign(private_key, MessageDigest::sha256())?;
    builder.build().to_der()
}

fn spki_fingerprint(spki_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(spki_der).into();
    trust::format_spki_sha256(&digest)
}

fn csr_fingerprint(csr_der: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(csr_der).into();
    trust::format_csr_sha256(&digest)
}

#[cfg(test)]
mod tests {
    use super::{
        DEVICE_CSR_COMMON_NAME, RECIPIENT_ENCRYPTION_KEY_ALGORITHM, TzapDeviceCsrOptions,
        TzapDeviceIdentityError, ensure_recipient_key_is_distinct_from_signing_key,
        generate_device_signing_key_and_csr, generate_recipient_encryption_key,
    };
    use crate::trust;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::X509Req;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn device_signing_key_generation_returns_p256_key_and_csr() {
        let material =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();

        assert!(!material.private_key_der.is_empty());
        assert!(!material.public_key_spki_der.is_empty());
        assert!(trust::parse_spki_sha256(&material.public_key_fingerprint).is_ok());
        assert!(trust::parse_csr_sha256(&material.csr_sha256).is_ok());
        assert_eq!(
            format!("{:?}", material.private_key_der),
            "SecretBytes([redacted])"
        );

        let private_key =
            PKey::private_key_from_der(material.private_key_der.expose_secret()).unwrap();
        assert_eq!(
            private_key.ec_key().unwrap().group().curve_name().unwrap(),
            Nid::X9_62_PRIME256V1
        );

        let csr = X509Req::from_der(&material.csr_der).unwrap();
        assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
        let subject = csr.subject_name();
        let common_name = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
        assert_eq!(
            common_name.data().as_utf8().unwrap().to_string(),
            DEVICE_CSR_COMMON_NAME
        );

        let csr_digest: [u8; 32] = Sha256::digest(&material.csr_der).into();
        assert_eq!(material.csr_sha256, trust::format_csr_sha256(&csr_digest));
    }

    #[test]
    fn device_csr_options_reject_empty_common_name() {
        assert!(matches!(
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions {
                common_name: String::new()
            }),
            Err(TzapDeviceIdentityError::EmptyCommonName)
        ));
    }

    #[test]
    fn recipient_encryption_key_generation_is_separate_from_signing_keys() {
        let signing_key =
            generate_device_signing_key_and_csr(&TzapDeviceCsrOptions::default()).unwrap();
        let recipient_key = generate_recipient_encryption_key().unwrap();

        assert_eq!(recipient_key.algorithm, RECIPIENT_ENCRYPTION_KEY_ALGORITHM);
        assert!(!recipient_key.private_key_der.is_empty());
        assert!(!recipient_key.public_key_spki_der.is_empty());
        assert!(trust::parse_spki_sha256(&recipient_key.public_key_fingerprint).is_ok());
        ensure_recipient_key_is_distinct_from_signing_key(
            &signing_key.public_key_fingerprint,
            &recipient_key.public_key_fingerprint,
        )
        .unwrap();

        let private_key =
            PKey::private_key_from_der(recipient_key.private_key_der.expose_secret()).unwrap();
        assert_eq!(
            private_key.ec_key().unwrap().group().curve_name().unwrap(),
            Nid::X9_62_PRIME256V1
        );
    }

    #[test]
    fn recipient_key_distinctness_rejects_reused_signing_fingerprint() {
        let fingerprint = trust::format_spki_sha256(&[0x42; 32]);

        assert!(matches!(
            ensure_recipient_key_is_distinct_from_signing_key(&fingerprint, &fingerprint),
            Err(TzapDeviceIdentityError::RecipientKeyReusesSigningKey)
        ));
    }
}
