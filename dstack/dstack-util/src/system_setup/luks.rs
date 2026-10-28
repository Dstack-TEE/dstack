// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The subset of the LUKS2 on-disk format that `validate_luks2_headers`
//! checks. Fields it does not inspect are not modeled; serde ignores them.
//! See <https://gitlab.com/cryptsetup/LUKS2-docs/blob/main/luks2_doc_wip.pdf>.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{de::IgnoredAny, Deserialize};
use serde_with::{serde_as, DisplayFromStr};

/// Size of the binary header that precedes each JSON area.
pub(super) const BINARY_HEADER_SIZE: u64 = 4096;

pub(super) struct LuksHeader {
    pub magic: [u8; 6],
    pub version: u16,
    pub hdr_size: u64,
    pub label: [u8; 48],
    pub csum_alg: [u8; 32],
    pub subsystem: [u8; 48],
    pub hdr_offset: u64,
}

impl LuksHeader {
    /// Decodes the big-endian binary header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        fn field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
            let bytes = data
                .get(offset..offset + N)
                .context("LUKS header is truncated")?;
            Ok(bytes.try_into()?)
        }
        Ok(Self {
            magic: field(data, 0)?,
            version: u16::from_be_bytes(field(data, 6)?),
            hdr_size: u64::from_be_bytes(field(data, 8)?),
            label: field(data, 24)?,
            csum_alg: field(data, 72)?,
            subsystem: field(data, 208)?,
            hdr_offset: u64::from_be_bytes(field(data, 256)?),
        })
    }
}

#[derive(Deserialize)]
pub(super) struct LuksJson {
    pub keyslots: HashMap<u8, LuksKeyslot>,
    pub tokens: HashMap<u8, IgnoredAny>,
    pub segments: HashMap<u8, LuksSegment>,
    pub digests: HashMap<u8, LuksDigest>,
    pub config: LuksConfig,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksKeyslot {
    Luks2 {
        key_size: u16,
        area: LuksArea,
        kdf: LuksKdf,
        af: LuksAf,
        #[serde(default)]
        priority: Option<IgnoredAny>,
    },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksArea {
    Raw {
        encryption: String,
        key_size: u32,
        #[serde_as(as = "DisplayFromStr")]
        offset: u64,
        #[serde_as(as = "DisplayFromStr")]
        size: u64,
    },
}

/// Salt and iterations are left unchecked on purpose: the passphrase is
/// high-entropy and KMS-derived, so attacker-chosen values buy nothing without
/// it (see security report #552).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksKdf {
    Pbkdf2 {
        hash: String,
    },
    #[serde(other)]
    Unsupported,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksAf {
    Luks1 { hash: String, stripes: u16 },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksSegment {
    Crypt {
        #[serde_as(as = "DisplayFromStr")]
        offset: u64,
        size: String,
        #[serde_as(as = "DisplayFromStr")]
        iv_tweak: u64,
        encryption: String,
        sector_size: u16,
        #[serde(default)]
        integrity: Option<IgnoredAny>,
        #[serde(default)]
        flags: Option<IgnoredAny>,
    },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum LuksDigest {
    Pbkdf2 {
        #[serde_as(as = "Vec<DisplayFromStr>")]
        keyslots: Vec<u8>,
        #[serde_as(as = "Vec<DisplayFromStr>")]
        segments: Vec<u8>,
        hash: String,
    },
}

#[serde_as]
#[derive(Deserialize)]
pub(super) struct LuksConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub keyslots_size: u64,
    #[serde(default)]
    pub flags: Option<IgnoredAny>,
    #[serde(default)]
    pub requirements: Option<IgnoredAny>,
}
