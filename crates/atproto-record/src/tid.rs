//! Timestamp Identifier (TID) generation and parsing.
//!
//! TIDs are 64-bit integers encoded as 13-character base32-sortable strings, combining
//! a microsecond timestamp with a random clock identifier for collision resistance.
//! They provide a sortable, distributed identifier scheme for AT Protocol records.
//!
//! ## Format
//!
//! - **Length**: Always 13 ASCII characters
//! - **Encoding**: Base32-sortable character set (`234567abcdefghijklmnopqrstuvwxyz`)
//! - **Structure**: 64-bit big-endian integer with:
//!   - Bit 0 (top): Always 0
//!   - Bits 1-53: Microseconds since UNIX epoch
//!   - Bits 54-63: Random 10-bit clock identifier
//!
//! ## Example
//!
//! ```
//! use atproto_record::tid::Tid;
//!
//! // Generate a new TID
//! let tid = Tid::new();
//! let tid_str = tid.to_string();
//! assert_eq!(tid_str.len(), 13);
//!
//! // Parse a TID string
//! let parsed = tid_str.parse::<Tid>().unwrap();
//! assert_eq!(tid, parsed);
//!
//! // TIDs are sortable by timestamp
//! let tid1 = Tid::new();
//! std::thread::sleep(std::time::Duration::from_micros(10));
//! let tid2 = Tid::new();
//! assert!(tid1 < tid2);
//! ```

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::TidError;

/// Base32-sortable character set for TID encoding.
///
/// This character set maintains lexicographic sort order when encoded TIDs
/// are compared as strings, ensuring timestamp ordering is preserved.
const BASE32_SORTABLE: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Reverse lookup table for base32-sortable decoding.
///
/// Maps ASCII character values to their corresponding 5-bit values.
/// Invalid characters are marked with 0xFF.
const BASE32_DECODE: [u8; 256] = {
    let mut table = [0xFF; 256];
    table[b'2' as usize] = 0;
    table[b'3' as usize] = 1;
    table[b'4' as usize] = 2;
    table[b'5' as usize] = 3;
    table[b'6' as usize] = 4;
    table[b'7' as usize] = 5;
    table[b'a' as usize] = 6;
    table[b'b' as usize] = 7;
    table[b'c' as usize] = 8;
    table[b'd' as usize] = 9;
    table[b'e' as usize] = 10;
    table[b'f' as usize] = 11;
    table[b'g' as usize] = 12;
    table[b'h' as usize] = 13;
    table[b'i' as usize] = 14;
    table[b'j' as usize] = 15;
    table[b'k' as usize] = 16;
    table[b'l' as usize] = 17;
    table[b'm' as usize] = 18;
    table[b'n' as usize] = 19;
    table[b'o' as usize] = 20;
    table[b'p' as usize] = 21;
    table[b'q' as usize] = 22;
    table[b'r' as usize] = 23;
    table[b's' as usize] = 24;
    table[b't' as usize] = 25;
    table[b'u' as usize] = 26;
    table[b'v' as usize] = 27;
    table[b'w' as usize] = 28;
    table[b'x' as usize] = 29;
    table[b'y' as usize] = 30;
    table[b'z' as usize] = 31;
    table
};

/// Timestamp Identifier (TID) for AT Protocol records.
///
/// A TID combines a microsecond-precision timestamp with a random clock identifier
/// to create a sortable, collision-resistant identifier. TIDs are represented as
/// 13-character base32-sortable strings.
///
/// ## Monotonicity
///
/// The TID generator ensures monotonically increasing values even when the system
/// clock moves backwards or multiple TIDs are generated within the same microsecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tid(u64);

/// Thread-local state for monotonic TID generation.
///
/// Tracks the last generated timestamp and clock identifier to ensure
/// monotonically increasing TID values.
static LAST_TID: Mutex<Option<(u64, u16)>> = Mutex::new(None);

impl Tid {
    /// The length of a TID string in characters.
    pub const LENGTH: usize = 13;

    /// Maximum valid timestamp value (53 bits).
    const MAX_TIMESTAMP: u64 = (1u64 << 53) - 1;

    /// Bitmask for extracting the 10-bit clock identifier.
    const CLOCK_ID_MASK: u64 = 0x3FF;

    /// Creates a new TID with the current timestamp and a random clock identifier.
    ///
    /// This function ensures monotonically increasing TID values by tracking the
    /// last generated TID and incrementing the clock identifier when necessary.
    ///
    /// # Example
    ///
    /// ```
    /// use atproto_record::tid::Tid;
    ///
    /// let tid = Tid::new();
    /// println!("Generated TID: {}", tid);
    /// ```
    pub fn new() -> Self {
        Self::new_with_time(Self::current_timestamp_micros())
    }

    /// Creates a new TID with a specific timestamp (for testing).
    ///
    /// # Arguments
    ///
    /// * `timestamp_micros` - Microseconds since UNIX epoch
    ///
    /// # Panics
    ///
    /// Panics if the timestamp exceeds 53 bits (year 2255+).
    pub fn new_with_time(timestamp_micros: u64) -> Self {
        assert!(
            timestamp_micros <= Self::MAX_TIMESTAMP,
            "Timestamp exceeds 53-bit maximum"
        );

        let mut last = LAST_TID.lock().unwrap();

        let clock_id = if let Some((last_timestamp, last_clock)) = *last {
            if timestamp_micros > last_timestamp {
                // New timestamp, generate random clock ID
                Self::random_clock_id()
            } else if timestamp_micros == last_timestamp {
                // Same timestamp, increment clock ID
                if last_clock == Self::CLOCK_ID_MASK as u16 {
                    // Clock ID overflow, use random
                    Self::random_clock_id()
                } else {
                    last_clock + 1
                }
            } else {
                // Clock moved backwards, use last timestamp + 1
                let adjusted_timestamp = last_timestamp + 1;
                let adjusted_clock = Self::random_clock_id();
                *last = Some((adjusted_timestamp, adjusted_clock));
                return Self::from_parts(adjusted_timestamp, adjusted_clock);
            }
        } else {
            // First TID, generate random clock ID
            Self::random_clock_id()
        };

        *last = Some((timestamp_micros, clock_id));
        Self::from_parts(timestamp_micros, clock_id)
    }

    /// Creates a TID from timestamp and clock identifier components.
    ///
    /// # Arguments
    ///
    /// * `timestamp_micros` - Microseconds since UNIX epoch (53 bits max)
    /// * `clock_id` - Random clock identifier (10 bits max)
    ///
    /// # Panics
    ///
    /// Panics if timestamp exceeds 53 bits or clock_id exceeds 10 bits.
    pub fn from_parts(timestamp_micros: u64, clock_id: u16) -> Self {
        assert!(
            timestamp_micros <= Self::MAX_TIMESTAMP,
            "Timestamp exceeds 53-bit maximum"
        );
        assert!(
            clock_id <= Self::CLOCK_ID_MASK as u16,
            "Clock ID exceeds 10-bit maximum"
        );

        // Combine: top bit 0, 53 bits timestamp, 10 bits clock ID
        let value = (timestamp_micros << 10) | (clock_id as u64);
        Tid(value)
    }

    /// Returns the timestamp component in microseconds since UNIX epoch.
    ///
    /// # Example
    ///
    /// ```
    /// use atproto_record::tid::Tid;
    ///
    /// let tid = Tid::new();
    /// let timestamp = tid.timestamp_micros();
    /// println!("Timestamp: {} μs", timestamp);
    /// ```
    pub fn timestamp_micros(&self) -> u64 {
        self.0 >> 10
    }

    /// Returns the clock identifier component (10 bits).
    ///
    /// # Example
    ///
    /// ```
    /// use atproto_record::tid::Tid;
    ///
    /// let tid = Tid::new();
    /// let clock_id = tid.clock_id();
    /// println!("Clock ID: {}", clock_id);
    /// ```
    pub fn clock_id(&self) -> u16 {
        (self.0 & Self::CLOCK_ID_MASK) as u16
    }

    /// Returns the raw 64-bit integer value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Encodes the TID as a 13-character base32-sortable string.
    ///
    /// # Example
    ///
    /// ```
    /// use atproto_record::tid::Tid;
    ///
    /// let tid = Tid::new();
    /// let encoded = tid.encode();
    /// assert_eq!(encoded.len(), 13);
    /// ```
    pub fn encode(&self) -> String {
        let mut chars = [0u8; Self::LENGTH];
        let mut value = self.0;

        // Encode from right to left (least significant to most significant)
        for i in (0..Self::LENGTH).rev() {
            chars[i] = BASE32_SORTABLE[(value & 0x1F) as usize];
            value >>= 5;
        }

        // BASE32_SORTABLE only contains valid UTF-8 ASCII characters
        String::from_utf8(chars.to_vec()).expect("base32-sortable encoding is always valid UTF-8")
    }

    /// Decodes a base32-sortable string into a TID.
    ///
    /// # Errors
    ///
    /// Returns [`TidError::InvalidLength`] if the string is not exactly 13 characters.
    /// Returns [`TidError::InvalidCharacter`] if the string contains invalid characters.
    /// Returns [`TidError::InvalidFormat`] if the decoded value has the top bit set.
    ///
    /// # Example
    ///
    /// ```
    /// use atproto_record::tid::Tid;
    ///
    /// let tid_str = "3jzfcijpj2z2a";
    /// let tid = Tid::decode(tid_str).unwrap();
    /// assert_eq!(tid.to_string(), tid_str);
    /// ```
    pub fn decode(s: &str) -> Result<Self, TidError> {
        if s.len() != Self::LENGTH {
            return Err(TidError::InvalidLength {
                expected: Self::LENGTH,
                actual: s.len(),
            });
        }

        let bytes = s.as_bytes();
        let mut value: u64 = 0;

        for (i, &byte) in bytes.iter().enumerate() {
            let decoded = BASE32_DECODE[byte as usize];
            if decoded == 0xFF {
                return Err(TidError::InvalidCharacter {
                    character: byte as char,
                    position: i,
                });
            }
            value = (value << 5) | (decoded as u64);
        }

        // Verify top bit is 0
        if value & (1u64 << 63) != 0 {
            return Err(TidError::InvalidFormat {
                reason: "Top bit must be 0".to_string(),
            });
        }

        Ok(Tid(value))
    }

    /// Gets the current timestamp in microseconds since UNIX epoch.
    fn current_timestamp_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_micros() as u64
    }

    /// Generates a random 10-bit clock identifier.
    fn random_clock_id() -> u16 {
        use rand::Rng;
        let mut rng = rand::rng();
        (rng.next_u32() as u16) & (Self::CLOCK_ID_MASK as u16)
    }
}

impl Default for Tid {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl FromStr for Tid {
    type Err = TidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

impl serde::Serialize for Tid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> serde::Deserialize<'de> for Tid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tid_encode_decode() {
        let tid = Tid::new();
        let encoded = tid.encode();
        assert_eq!(encoded.len(), Tid::LENGTH);

        let decoded = Tid::decode(&encoded).unwrap();
        assert_eq!(tid, decoded);
    }

    #[test]
    fn test_tid_from_parts() {
        let timestamp = 1234567890123456u64;
        let clock_id = 42u16;
        let tid = Tid::from_parts(timestamp, clock_id);

        assert_eq!(tid.timestamp_micros(), timestamp);
        assert_eq!(tid.clock_id(), clock_id);
    }

    #[test]
    fn test_tid_monotonic() {
        let tid1 = Tid::new();
        std::thread::sleep(std::time::Duration::from_micros(10));
        let tid2 = Tid::new();

        assert!(tid1 < tid2);
    }

    #[test]
    fn test_tid_same_timestamp() {
        let timestamp = 1234567890123456u64;
        let tid1 = Tid::new_with_time(timestamp);
        let tid2 = Tid::new_with_time(timestamp);

        // Should have different clock IDs or incremented clock ID
        assert!(tid1 < tid2 || tid1.clock_id() + 1 == tid2.clock_id());
    }

    #[test]
    fn test_tid_string_roundtrip() {
        let tid = Tid::new();
        let s = tid.to_string();
        let parsed: Tid = s.parse().unwrap();
        assert_eq!(tid, parsed);
    }

    #[test]
    fn test_tid_serde() {
        let tid = Tid::new();
        let json = serde_json::to_string(&tid).unwrap();
        let parsed: Tid = serde_json::from_str(&json).unwrap();
        assert_eq!(tid, parsed);
    }

    #[test]
    fn test_tid_valid_examples() {
        // Examples from the specification
        let examples = ["3jzfcijpj2z2a", "7777777777777", "2222222222222"];

        for example in &examples {
            let tid = Tid::decode(example).unwrap();
            assert_eq!(&tid.encode(), example);
        }
    }

    #[test]
    fn test_tid_invalid_length() {
        let result = Tid::decode("123");
        assert!(matches!(result, Err(TidError::InvalidLength { .. })));
    }

    #[test]
    fn test_tid_invalid_character() {
        let result = Tid::decode("123456789012!");
        assert!(matches!(result, Err(TidError::InvalidCharacter { .. })));
    }

    #[test]
    fn test_tid_first_char_range() {
        // First character must be in valid range per spec
        let tid = Tid::new();
        let encoded = tid.encode();
        let first_char = encoded.chars().next().unwrap();

        // First char must be 234567abcdefghij (values 0-15 in base32-sortable)
        assert!("234567abcdefghij".contains(first_char));
    }

    #[test]
    fn test_tid_sortability() {
        // TIDs with increasing timestamps should sort correctly as strings
        let tid1 = Tid::from_parts(1000000, 0);
        let tid2 = Tid::from_parts(2000000, 0);
        let tid3 = Tid::from_parts(3000000, 0);

        let s1 = tid1.to_string();
        let s2 = tid2.to_string();
        let s3 = tid3.to_string();

        assert!(s1 < s2);
        assert!(s2 < s3);
        assert!(s1 < s3);
    }

    #[test]
    fn test_tid_clock_backward() {
        // Simulate clock moving backwards
        let timestamp1 = 2000000u64;
        let tid1 = Tid::new_with_time(timestamp1);

        let timestamp2 = 1000000u64; // Earlier timestamp
        let tid2 = Tid::new_with_time(timestamp2);

        // TID should still be monotonically increasing
        assert!(tid2 > tid1);
    }
}
