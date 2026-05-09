//! Strongly-typed PLC DID identifiers with parsing and validation.
//!
//! A `Did` represents a validated `did:plc:` identifier consisting of the
//! prefix followed by exactly 24 lowercase base32 characters derived from
//! the SHA-256 hash of the genesis operation.

use crate::errors::PLCDIDError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use super::encoding::is_valid_base32;

/// The prefix for all did:plc identifiers.
pub const DID_PLC_PREFIX: &str = "did:plc:";

/// The length of the identifier portion (24 characters).
pub const IDENTIFIER_LENGTH: usize = 24;

/// The total length of a valid did:plc string (32 characters).
pub const TOTAL_LENGTH: usize = 32; // "did:plc:" (8) + identifier (24)

/// A validated did:plc identifier.
///
/// A did:plc consists of the prefix "did:plc:" followed by exactly 24
/// lowercase base32 characters (using alphabet `abcdefghijklmnopqrstuvwxyz234567`).
///
/// The identifier is derived from the SHA-256 hash of the genesis operation,
/// base32-encoded and truncated to 24 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    /// The full did:plc:xyz.. string
    full: String,
    /// The 24-character identifier portion
    identifier: String,
}

impl Did {
    /// Parse and validate a DID string.
    ///
    /// Returns `PLCDIDError::InvalidDidFormat` if the string doesn't start with
    /// "did:plc:", the total length isn't exactly 32 characters, or the identifier
    /// portion contains invalid base32 characters.
    pub fn parse(s: &str) -> Result<Self, PLCDIDError> {
        Self::validate_format(s)?;

        let identifier = s[DID_PLC_PREFIX.len()..].to_string();

        Ok(Self {
            full: s.to_string(),
            identifier,
        })
    }

    /// Create a DID from a validated identifier (without the "did:plc:" prefix).
    ///
    /// Returns `PLCDIDError::InvalidDidFormat` if the identifier is not exactly
    /// 24 characters or contains invalid base32 characters.
    pub fn from_identifier(identifier: &str) -> Result<Self, PLCDIDError> {
        if identifier.len() != IDENTIFIER_LENGTH {
            return Err(PLCDIDError::InvalidDidFormat {
                details: format!(
                    "Identifier must be exactly {} characters, got {}",
                    IDENTIFIER_LENGTH,
                    identifier.len()
                ),
            });
        }

        if !is_valid_base32(identifier) {
            return Err(PLCDIDError::InvalidDidFormat {
                details: "Identifier contains invalid base32 characters".to_string(),
            });
        }

        Ok(Self {
            full: format!("{}{}", DID_PLC_PREFIX, identifier),
            identifier: identifier.to_string(),
        })
    }

    /// Get the 24-character identifier portion (without "did:plc:" prefix).
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Get the full DID string including "did:plc:" prefix.
    pub fn as_str(&self) -> &str {
        &self.full
    }

    /// Validate the format of a DID string without constructing a Did instance.
    fn validate_format(s: &str) -> Result<(), PLCDIDError> {
        if !s.starts_with(DID_PLC_PREFIX) {
            return Err(PLCDIDError::InvalidDidFormat {
                details: format!(
                    "DID must start with '{}', got '{}'",
                    DID_PLC_PREFIX,
                    s.chars().take(8).collect::<String>()
                ),
            });
        }

        if s.len() != TOTAL_LENGTH {
            return Err(PLCDIDError::InvalidDidFormat {
                details: format!(
                    "DID must be exactly {} characters, got {}",
                    TOTAL_LENGTH,
                    s.len()
                ),
            });
        }

        let identifier = &s[DID_PLC_PREFIX.len()..];

        if !is_valid_base32(identifier) {
            return Err(PLCDIDError::InvalidDidFormat {
                details: "Identifier contains invalid base32 characters".to_string(),
            });
        }

        Ok(())
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full)
    }
}

impl FromStr for Did {
    type Err = PLCDIDError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.full)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_did() {
        let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        assert_eq!(did.identifier(), "ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(did.as_str(), "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
    }

    #[test]
    fn test_invalid_prefix() {
        assert!(Did::parse("did:web:example.com").is_err());
        assert!(Did::parse("DID:PLC:ewvi7nxzyoun6zhxrhs64oiz").is_err());
    }

    #[test]
    fn test_invalid_length() {
        assert!(Did::parse("did:plc:tooshort").is_err());
        assert!(Did::parse("did:plc:wayyyyyyyyyyyyyyyyyyyyyyytooooooolong").is_err());
    }

    #[test]
    fn test_invalid_characters() {
        // Contains 0, 1, 8, 9 which are not in base32 alphabet
        assert!(Did::parse("did:plc:012345678901234567890123").is_err());
        // Contains uppercase
        assert!(Did::parse("did:plc:EWVI7NXZYOUN6ZHXRHS64OIZ").is_err());
    }

    #[test]
    fn test_from_identifier() {
        let did = Did::from_identifier("ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        assert_eq!(did.as_str(), "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
    }

    #[test]
    fn test_display() {
        let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        assert_eq!(format!("{}", did), "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
    }

    #[test]
    fn test_serialization() {
        let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, "\"did:plc:ewvi7nxzyoun6zhxrhs64oiz\"");

        let deserialized: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, deserialized);
    }

    #[test]
    fn test_from_str() {
        let did: Did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz".parse().unwrap();
        assert_eq!(did.identifier(), "ewvi7nxzyoun6zhxrhs64oiz");
    }
}
