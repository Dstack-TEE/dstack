// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A utility crate for parsing and handling memory sizes with serde support.
//!
//! This crate provides functionality to parse memory size strings with various
//! suffixes (K, M, G, T) and hexadecimal values, with optional serde serialization
//! and deserialization support.
//!
//! # Examples
//!
//! ```
//! use size_parser::MemorySize;
//!
//! // Parse from string
//! let size = MemorySize::parse("2G").unwrap();
//! assert_eq!(size.bytes(), 2 * 1024 * 1024 * 1024);
//!
//! // Parse hexadecimal
//! let size = MemorySize::parse("0x1000").unwrap();
//! assert_eq!(size.bytes(), 4096);
//!
//! // Create from bytes
//! let size = MemorySize::from_bytes(1024);
//! assert_eq!(size.bytes(), 1024);
//!
//! // Using FromStr trait
//! let size: MemorySize = "2G".parse().unwrap();
//! assert_eq!(size.bytes(), 2 * 1024 * 1024 * 1024);
//! ```

use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors that can occur when parsing memory sizes
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MemorySizeError {
    #[error("Empty memory size")]
    Empty,
    #[error("Invalid hexadecimal value: {0}")]
    InvalidHex(String),
    #[error("Invalid numeric value: {0}")]
    InvalidNumber(String),
    #[error("Unknown memory size suffix: {0}")]
    UnknownSuffix(char),
    #[error("Overflow in memory size calculation")]
    Overflow,
}

/// A memory size value that can be parsed from strings with various formats
/// and optionally serialized/deserialized with serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemorySize {
    bytes: u64,
}

impl MemorySize {
    /// Create a new MemorySize from a number of bytes
    pub fn from_bytes(bytes: u64) -> Self {
        Self { bytes }
    }

    /// Get the memory size in bytes
    pub fn bytes(self) -> u64 {
        self.bytes
    }

    /// Get the memory size in kilobytes (1024 bytes)
    pub fn kilobytes(self) -> f64 {
        self.bytes as f64 / 1024.0
    }

    /// Get the memory size in megabytes (1024^2 bytes)
    pub fn megabytes(self) -> f64 {
        self.bytes as f64 / (1024.0 * 1024.0)
    }

    /// Get the memory size in gigabytes (1024^3 bytes)
    pub fn gigabytes(self) -> f64 {
        self.bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get the memory size in terabytes (1024^4 bytes)
    pub fn terabytes(self) -> f64 {
        self.bytes as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
    }

    /// Parse a memory size value that can be decimal or hexadecimal (with 0x prefix)
    ///
    /// Supports the following formats:
    /// - Plain numbers: "1024", "2048"
    /// - Hexadecimal: "0x1000", "0X2000"
    /// - With suffixes: "2K", "4M", "1G", "2T" (case-insensitive)
    ///
    /// Suffixes use binary (1024-based) multipliers:
    /// - K/k: 1024 bytes
    /// - M/m: 1024^2 bytes
    /// - G/g: 1024^3 bytes
    /// - T/t: 1024^4 bytes
    pub fn parse(s: &str) -> Result<Self, MemorySizeError> {
        let s = s.trim();

        if s.is_empty() {
            return Err(MemorySizeError::Empty);
        }

        // Handle hexadecimal values
        if s.starts_with("0x") || s.starts_with("0X") {
            let hex_str = &s[2..];
            let bytes = u64::from_str_radix(hex_str, 16)
                .map_err(|_| MemorySizeError::InvalidHex(hex_str.to_string()))?;
            return Ok(Self::from_bytes(bytes));
        }

        // Handle plain numbers (all digits)
        if s.chars().all(|c| c.is_ascii_digit()) {
            let bytes = s
                .parse::<u64>()
                .map_err(|_| MemorySizeError::InvalidNumber(s.to_string()))?;
            return Ok(Self::from_bytes(bytes));
        }

        // Handle numbers with suffixes
        let len = s.len();
        if len == 0 {
            return Err(MemorySizeError::Empty);
        }

        let last_char = s.chars().last().unwrap();
        let multiplier = match last_char.to_ascii_lowercase() {
            'k' => 1024u64,
            'm' => 1024u64.saturating_mul(1024),
            'g' => 1024u64.saturating_mul(1024).saturating_mul(1024),
            't' => 1024u64
                .saturating_mul(1024)
                .saturating_mul(1024)
                .saturating_mul(1024),
            _ => return Err(MemorySizeError::UnknownSuffix(last_char)),
        };

        let num_part = &s[0..len - 1];
        let num = num_part
            .parse::<u64>()
            .map_err(|_| MemorySizeError::InvalidNumber(num_part.to_string()))?;

        let bytes = num
            .checked_mul(multiplier)
            .ok_or(MemorySizeError::Overflow)?;

        Ok(Self::from_bytes(bytes))
    }

    /// Format the memory size in a human-readable way
    pub fn format_human(&self) -> String {
        const UNITS: &[(&str, u64)] = &[
            ("T", 1024u64.pow(4)),
            ("G", 1024u64.pow(3)),
            ("M", 1024u64.pow(2)),
            ("K", 1024),
        ];

        for &(unit, size) in UNITS {
            if self.bytes >= size {
                let value = self.bytes / size;
                let remainder = self.bytes % size;
                if remainder == 0 {
                    return format!("{}{}", value, unit);
                } else {
                    let fractional = remainder as f64 / size as f64;
                    return format!("{:.1}{}", value as f64 + fractional, unit);
                }
            }
        }

        format!("{}", self.bytes)
    }
}

impl FromStr for MemorySize {
    type Err = MemorySizeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for MemorySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_human())
    }
}

impl From<u64> for MemorySize {
    fn from(bytes: u64) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<MemorySize> for u64 {
    fn from(size: MemorySize) -> Self {
        size.bytes
    }
}

#[cfg(feature = "serde")]
impl Serialize for MemorySize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // Serialize as human-readable string for JSON, YAML, etc.
            serializer.serialize_str(&self.format_human())
        } else {
            // Serialize as raw bytes for binary formats
            serializer.serialize_u64(self.bytes)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MemorySize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};
        use std::fmt;

        struct MemorySizeVisitor;

        impl<'de> Visitor<'de> for MemorySizeVisitor {
            type Value = MemorySize;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a memory size string or u64")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                MemorySize::parse(value).map_err(E::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(MemorySize::from_bytes(value))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(MemorySizeVisitor)
        } else {
            deserializer.deserialize_u64(MemorySizeVisitor)
        }
    }
}

/// Parse a memory size string into bytes (for compatibility with existing code)
pub fn parse_memory_size(s: &str) -> Result<u64, MemorySizeError> {
    MemorySize::parse(s).map(|size| size.bytes())
}

/// Generic serde support for using memory size parsing with field attributes
///
/// This module provides functions that can be used with `#[serde(with = "memory_size::human_size")]`
/// to serialize and deserialize memory sizes as human-readable strings directly into any numeric type
/// that can be converted to/from u64.
///
/// # Example
///
/// ```rust
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Config {
///     #[serde(with = "size_parser::human_size")]
///     memory_size: u64,
///     #[serde(with = "size_parser::human_size")]
///     buffer_size: usize,
///     #[serde(with = "size_parser::human_size")]
///     cache_size: u32,
/// }
///
/// let config = Config {
///     memory_size: 2 * 1024 * 1024 * 1024, // 2GB
///     buffer_size: 512 * 1024,             // 512KB
///     cache_size: 64 * 1024,               // 64KB
/// };
///
/// // Serializes as: {"memory_size": "2G", "buffer_size": "512K", "cache_size": "64K"}
/// let json = serde_json::to_string(&config).unwrap();
///
/// // Can deserialize from human-readable formats
/// let config: Config = serde_json::from_str(r#"{"memory_size": "1G", "buffer_size": "256K", "cache_size": "32K"}"#).unwrap();
/// assert_eq!(config.memory_size, 1024 * 1024 * 1024);
/// assert_eq!(config.buffer_size, 256 * 1024);
/// assert_eq!(config.cache_size, 32 * 1024);
/// ```
#[cfg(feature = "serde")]
pub mod human_size {
    use super::MemorySize;
    use serde::{de::Error, Deserializer, Serializer};
    use std::convert::{TryFrom, TryInto};

    /// Serialize a numeric memory size as a human-readable string
    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Copy + TryInto<u64>,
        T::Error: std::fmt::Display,
    {
        let bytes: u64 = (*value).try_into().map_err(|e| {
            serde::ser::Error::custom(format!("memory size conversion error: {}", e))
        })?;
        let memory_size = MemorySize::from_bytes(bytes);

        if serializer.is_human_readable() {
            serializer.serialize_str(&memory_size.format_human())
        } else {
            serializer.serialize_u64(bytes)
        }
    }

    /// Deserialize a memory size from a human-readable string into any numeric type
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<u64>,
        T::Error: std::fmt::Display,
    {
        use serde::de::Visitor;
        use std::fmt;

        struct MemorySizeVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for MemorySizeVisitor<T>
        where
            T: TryFrom<u64>,
            T::Error: std::fmt::Display,
        {
            type Value = T;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a memory size string or number")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = MemorySize::parse(value)
                    .map(|size| size.bytes())
                    .map_err(E::custom)?;

                T::try_from(bytes)
                    .map_err(|e| E::custom(format!("memory size conversion error: {}", e)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::try_from(value)
                    .map_err(|e| E::custom(format!("memory size conversion error: {}", e)))
            }

            fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::try_from(value as u64)
                    .map_err(|e| E::custom(format!("memory size conversion error: {}", e)))
            }

            fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if value < 0 {
                    return Err(E::custom("memory size cannot be negative"));
                }
                T::try_from(value as u64)
                    .map_err(|e| E::custom(format!("memory size conversion error: {}", e)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if value < 0 {
                    return Err(E::custom("memory size cannot be negative"));
                }
                T::try_from(value as u64)
                    .map_err(|e| E::custom(format!("memory size conversion error: {}", e)))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(MemorySizeVisitor(std::marker::PhantomData))
        } else {
            deserializer.deserialize_u64(MemorySizeVisitor(std::marker::PhantomData))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain_numbers() {
        assert_eq!(MemorySize::parse("1024").unwrap().bytes(), 1024);
        assert_eq!(MemorySize::parse("2048").unwrap().bytes(), 2048);
        assert_eq!(MemorySize::parse("0").unwrap().bytes(), 0);
    }

    #[test]
    fn test_parse_hexadecimal() {
        assert_eq!(MemorySize::parse("0x1000").unwrap().bytes(), 4096);
        assert_eq!(MemorySize::parse("0X2000").unwrap().bytes(), 8192);
        assert_eq!(MemorySize::parse("0xff").unwrap().bytes(), 255);
    }

    #[test]
    fn test_parse_with_suffixes() {
        assert_eq!(MemorySize::parse("1K").unwrap().bytes(), 1024);
        assert_eq!(MemorySize::parse("2k").unwrap().bytes(), 2048);
        assert_eq!(MemorySize::parse("1M").unwrap().bytes(), 1024 * 1024);
        assert_eq!(MemorySize::parse("2m").unwrap().bytes(), 2 * 1024 * 1024);
        assert_eq!(MemorySize::parse("1G").unwrap().bytes(), 1024 * 1024 * 1024);
        assert_eq!(
            MemorySize::parse("2g").unwrap().bytes(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(MemorySize::parse("1T").unwrap().bytes(), 1024u64.pow(4));
        assert_eq!(MemorySize::parse("2t").unwrap().bytes(), 2 * 1024u64.pow(4));
    }

    #[test]
    fn test_parse_errors() {
        assert!(matches!(MemorySize::parse(""), Err(MemorySizeError::Empty)));
        assert!(matches!(
            MemorySize::parse("   "),
            Err(MemorySizeError::Empty)
        ));
        assert!(matches!(
            MemorySize::parse("abc"),
            Err(MemorySizeError::UnknownSuffix('c'))
        ));
        assert!(matches!(
            MemorySize::parse("0xgg"),
            Err(MemorySizeError::InvalidHex(_))
        ));
        assert!(matches!(
            MemorySize::parse("abcK"),
            Err(MemorySizeError::InvalidNumber(_))
        ));
    }

    #[test]
    fn test_format_human() {
        assert_eq!(MemorySize::from_bytes(1024).format_human(), "1K");
        assert_eq!(MemorySize::from_bytes(1024 * 1024).format_human(), "1M");
        assert_eq!(
            MemorySize::from_bytes(1024 * 1024 * 1024).format_human(),
            "1G"
        );
        assert_eq!(MemorySize::from_bytes(1024u64.pow(4)).format_human(), "1T");
        assert_eq!(MemorySize::from_bytes(1536).format_human(), "1.5K");
        assert_eq!(MemorySize::from_bytes(512).format_human(), "512");
    }

    #[test]
    fn test_conversions() {
        let size = MemorySize::from_bytes(2 * 1024 * 1024 * 1024);
        assert_eq!(size.kilobytes(), 2.0 * 1024.0 * 1024.0);
        assert_eq!(size.megabytes(), 2.0 * 1024.0);
        assert_eq!(size.gigabytes(), 2.0);
        assert_eq!(size.terabytes(), 2.0 / 1024.0);
    }

    #[test]
    fn test_from_str() {
        let size: MemorySize = "2G".parse().unwrap();
        assert_eq!(size.bytes(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_display() {
        let size = MemorySize::from_bytes(1024);
        assert_eq!(format!("{}", size), "1K");
    }

    #[test]
    fn test_compatibility_function() {
        assert_eq!(parse_memory_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_size("0x1000").unwrap(), 4096);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_json() {
        let size = MemorySize::from_bytes(2 * 1024 * 1024 * 1024);

        // Test serialization
        let json = serde_json::to_string(&size).unwrap();
        assert_eq!(json, "\"2G\"");

        // Test deserialization
        let deserialized: MemorySize = serde_json::from_str("\"1G\"").unwrap();
        assert_eq!(deserialized.bytes(), 1024 * 1024 * 1024);

        // Test deserialization from various formats
        let from_k: MemorySize = serde_json::from_str("\"512K\"").unwrap();
        assert_eq!(from_k.bytes(), 512 * 1024);

        let from_hex: MemorySize = serde_json::from_str("\"0x1000\"").unwrap();
        assert_eq!(from_hex.bytes(), 4096);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_generic_human_size_field_attribute() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Config {
            #[serde(with = "crate::human_size")]
            memory_size: u64,
            #[serde(with = "crate::human_size")]
            buffer_size: usize,
            #[serde(with = "crate::human_size")]
            cache_size: u32,
            // Regular field without custom serialization
            threads: u32,
        }

        let config = Config {
            memory_size: 2 * 1024 * 1024 * 1024, // 2GB
            buffer_size: 512 * 1024,             // 512KB
            cache_size: 64 * 1024,               // 64KB
            threads: 4,
        };

        // Test serialization
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            json,
            r#"{"memory_size":"2G","buffer_size":"512K","cache_size":"64K","threads":4}"#
        );

        // Test deserialization from human-readable format
        let json_input =
            r#"{"memory_size":"1G","buffer_size":"256K","cache_size":"32K","threads":8}"#;
        let deserialized: Config = serde_json::from_str(json_input).unwrap();

        assert_eq!(deserialized.memory_size, 1024 * 1024 * 1024);
        assert_eq!(deserialized.buffer_size, 256 * 1024);
        assert_eq!(deserialized.cache_size, 32 * 1024);
        assert_eq!(deserialized.threads, 8);

        // Test deserialization from various formats
        let from_hex: Config = serde_json::from_str(r#"{"memory_size":"0x40000000","buffer_size":"0x1000","cache_size":"0x800","threads":2}"#).unwrap();
        assert_eq!(from_hex.memory_size, 0x40000000);
        assert_eq!(from_hex.buffer_size, 0x1000);
        assert_eq!(from_hex.cache_size, 0x800);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_human_size_overflow_handling() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Config {
            #[serde(with = "crate::human_size")]
            small_size: u32,
        }

        // Test that values too large for u32 are handled gracefully
        let json_input = r#"{"small_size":"8G"}"#; // 8GB > u32::MAX
        let result: Result<Config, _> = serde_json::from_str(json_input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conversion error"));
    }
}
