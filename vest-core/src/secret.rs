//! Secret-bearing string wrappers with redacted Debug/Display.
//!
//! This is not an OS credential store. Values may still live in process memory.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A string that must never appear in Debug/Display output.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the secret for authorised use (HTTP auth headers, etc.).
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let secret = SecretString::new("SUPER_SECRET_TEST_KEY_123");
        let debug = format!("{:?}", secret);
        let display = format!("{}", secret);
        assert!(!debug.contains("SUPER_SECRET"));
        assert!(!display.contains("SUPER_SECRET"));
        assert!(debug.contains("REDACTED"));
        assert_eq!(secret.expose(), "SUPER_SECRET_TEST_KEY_123");
    }

    #[test]
    fn serde_does_not_emit_plaintext() {
        let secret = SecretString::new("SUPER_SECRET_TEST_KEY_123");
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("SUPER_SECRET"));
        assert!(json.contains("REDACTED"));
    }
}
