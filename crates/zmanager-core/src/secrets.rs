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

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretString::from("correct horse");

        assert_eq!(format!("{secret:?}"), "SecretString([redacted])");
    }
}
