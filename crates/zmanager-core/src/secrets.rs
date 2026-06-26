use std::fmt;
use std::ops::Deref;
use zeroize::Zeroize;

/// Owned password material that redacts debug output and zeroizes on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString {
    value: String,
}

impl SecretString {
    /// Stores a password for later borrowed use.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrows the secret for backend APIs that accept string slices.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }

    /// Returns whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.expose_secret()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Owned binary secret material that redacts debug output and zeroizes on drop.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretBytes {
    value: Vec<u8>,
}

impl SecretBytes {
    #[must_use]
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
        }
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.value
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose_secret()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString};

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretString::from("correct horse");

        assert_eq!(format!("{secret:?}"), "SecretString([redacted])");

        let bytes = SecretBytes::from(b"private key".as_slice());
        assert_eq!(format!("{bytes:?}"), "SecretBytes([redacted])");
        assert_eq!(bytes.expose_secret(), b"private key");
    }
}
