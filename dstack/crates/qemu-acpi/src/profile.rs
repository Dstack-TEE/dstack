// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use core::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QemuVersion {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
}

impl QemuVersion {
    pub const fn new(major: u32, minor: u32, micro: u32) -> Self {
        Self {
            major,
            minor,
            micro,
        }
    }

    /// Map a QEMU version onto the ACPI compatibility profile to generate with.
    ///
    /// Versions newer than the newest modeled profile fall back to
    /// [`Compatibility::LATEST`] rather than failing: most QEMU releases do not
    /// change the Q35 ACPI ABI, so extrapolating is right far more often than
    /// not, and when it is wrong the generated blobs simply do not match the
    /// measured ones. Refusing to generate turns every such deployment into a
    /// verification error, which is the same outcome with less information, so
    /// the caller is left to decide what a mismatch means.
    ///
    /// Versions older than 8.0 return `None`: their ABI was never modeled, and
    /// clamping *down* to the oldest profile would be a guess in the direction
    /// where QEMU's ACPI output is known to differ.
    pub const fn compatibility(self) -> Option<Compatibility> {
        match (self.major, self.minor) {
            (8, _) => Some(Compatibility::V8),
            (9, 0..=1) => Some(Compatibility::V9Pre92),
            (9, _) => Some(Compatibility::V9_2),
            (10, _) => Some(Compatibility::V10),
            (11, 0) => Some(Compatibility::V11_0),
            (11, 1..) => Some(Compatibility::V11_1),
            (12.., _) => Some(Compatibility::LATEST),
            _ => None,
        }
    }
}

impl fmt::Display for QemuVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)
    }
}

impl FromStr for QemuVersion {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split('.');
        let major = parts
            .next()
            .ok_or("missing major")?
            .parse()
            .map_err(|_| "invalid major")?;
        let minor = parts
            .next()
            .ok_or("missing minor")?
            .parse()
            .map_err(|_| "invalid minor")?;
        let micro = parts
            .next()
            .ok_or("missing micro")?
            .parse()
            .map_err(|_| "invalid micro")?;
        if parts.next().is_some() {
            return Err("too many version components");
        }
        Ok(Self::new(major, minor, micro))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Compatibility {
    V8,
    V9Pre92,
    V9_2,
    V10,
    V11_0,
    V11_1,
}

impl Compatibility {
    /// Newest modeled profile, used for QEMU versions released after it.
    /// Update this together with every new profile.
    pub const LATEST: Self = Self::V11_1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_map_to_their_own_profile() {
        let cases = [
            ((8, 2, 2), Compatibility::V8),
            ((9, 1, 0), Compatibility::V9Pre92),
            ((9, 2, 1), Compatibility::V9_2),
            ((10, 0, 0), Compatibility::V10),
            ((11, 0, 3), Compatibility::V11_0),
            ((11, 1, 0), Compatibility::V11_1),
        ];
        for ((major, minor, micro), expected) in cases {
            assert_eq!(
                QemuVersion::new(major, minor, micro).compatibility(),
                Some(expected),
                "{major}.{minor}.{micro}"
            );
        }
    }

    /// A QEMU release newer than the newest modeled profile must still produce
    /// blobs: if its ACPI ABI is unchanged they match, and if it changed the
    /// caller sees a digest mismatch instead of a "cannot generate" error.
    #[test]
    fn versions_newer_than_the_newest_profile_clamp_to_it() {
        for version in [
            QemuVersion::new(11, 9, 0),
            QemuVersion::new(12, 0, 0),
            QemuVersion::new(99, 4, 1),
        ] {
            assert_eq!(version.compatibility(), Some(Compatibility::LATEST));
        }
    }

    #[test]
    fn versions_older_than_the_oldest_profile_are_rejected() {
        for version in [QemuVersion::new(7, 2, 0), QemuVersion::new(0, 0, 0)] {
            assert_eq!(version.compatibility(), None);
        }
    }
}
