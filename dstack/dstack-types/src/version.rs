// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;

/// Parsed semantic version with major, minor, and patch components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    /// Create a new version with the given components.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a version string into a Version struct.
    ///
    /// Handles various version formats:
    /// - Standard: "0.5.6"
    /// - Two segments: "0.5" (patch defaults to 0)
    /// - With extra parts: "0.5.6.1"
    /// - With prerelease: "0.5.6-alpha.0", "0.5.6-rc1"
    /// - With build metadata: "0.5.6+dcap.0"
    /// - Git describe format: "0.5.6-10-g1234abc"
    /// - Mixed: "0.5.6-alpha.0+dcap.0"
    ///
    /// The prerelease and build metadata parts are truncated.
    /// Returns None if the version string is empty or cannot be parsed.
    pub fn parse(version: &str) -> Option<Self> {
        let version = version.trim();
        if version.is_empty() {
            return None;
        }

        // Strip prerelease (-...) and build metadata (+...) suffixes
        // Find the first occurrence of '-' or '+'
        let version = version
            .split_once(['-', '+'])
            .map(|(v, _)| v)
            .unwrap_or(version);

        // Split by '.' and parse the first three components
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        // Patch is optional, defaults to 0
        let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        // Ignore extra parts like "0.5.6.1"

        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard() {
        let v = Version::parse("0.5.6").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_two_segments() {
        let v = Version::parse("0.5").unwrap();
        assert_eq!(v, Version::new(0, 5, 0));
    }

    #[test]
    fn test_parse_with_extra_parts() {
        let v = Version::parse("0.5.6.1").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_with_prerelease() {
        assert_eq!(
            Version::parse("0.5.6-alpha.0").unwrap(),
            Version::new(0, 5, 6)
        );
        assert_eq!(Version::parse("0.5.6-rc1").unwrap(), Version::new(0, 5, 6));
        assert_eq!(
            Version::parse("0.5.6-beta2").unwrap(),
            Version::new(0, 5, 6)
        );
    }

    #[test]
    fn test_parse_git_describe() {
        // git describe format: tag-commits-ghash
        let v = Version::parse("0.5.6-10-g1234abc").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_with_build_metadata() {
        let v = Version::parse("0.5.6+dcap.0").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_mixed() {
        let v = Version::parse("0.5.6-alpha.0+dcap.0").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_with_whitespace() {
        let v = Version::parse("  0.5.6  ").unwrap();
        assert_eq!(v, Version::new(0, 5, 6));
    }

    #[test]
    fn test_parse_empty() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("   ").is_none());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(Version::parse("invalid").is_none());
        assert!(Version::parse("1").is_none());
        assert!(Version::parse("v").is_none());
        assert!(Version::parse("abc.def.ghi").is_none());
    }

    #[test]
    fn test_comparison() {
        assert!(Version::new(0, 5, 6) > Version::new(0, 5, 5));
        assert!(Version::new(0, 5, 6) < Version::new(0, 5, 7));
        assert!(Version::new(0, 5, 6) < Version::new(0, 6, 0));
        assert!(Version::new(0, 5, 6) < Version::new(1, 0, 0));
        assert!(Version::new(0, 5, 6) == Version::new(0, 5, 6));
        // Two segments comparison
        assert!(Version::new(0, 5, 0) < Version::new(0, 5, 6));
    }

    #[test]
    fn test_display() {
        let v = Version::new(0, 5, 6);
        assert_eq!(v.to_string(), "0.5.6");
    }
}
