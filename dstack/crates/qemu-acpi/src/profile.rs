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

    pub const fn compatibility(self) -> Option<Compatibility> {
        match (self.major, self.minor) {
            (8, _) => Some(Compatibility::V8),
            (9, 0..=1) => Some(Compatibility::V9Pre92),
            (9, _) => Some(Compatibility::V9_2),
            (10, _) => Some(Compatibility::V10),
            (11, 0) => Some(Compatibility::V11_0),
            (11, 1..) => Some(Compatibility::V11_1),
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
