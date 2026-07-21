// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! On-disk dstack volume envelope shared by builders and guests.

use std::io::Cursor;

use binrw::{binrw, BinRead, BinWrite};

pub const DSTACK_VOLUME_MAGIC: &[u8; 16] = b"DSTACK_VOLUME\0\0\0";
pub const DSTACK_VOLUME_HEADER_SIZE: usize = 4096;
pub const DSTACK_VOLUME_FORMAT_VERSION: u16 = 1;
pub const DSTACK_VOLUME_KIND_VERITY: u32 = 1;

#[binrw]
#[brw(little, magic = b"DSTACK_VOLUME\0\0\0")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackVolumeHeader {
    pub format_version: u16,
    pub header_size: u16,
    pub kind: u32,
    pub kind_version: u32,
    pub flags: u32,
    pub root_hash: [u8; 32],
    pub data_block_size: u32,
    pub hash_block_size: u32,
}

impl DstackVolumeHeader {
    pub fn new_verity(root_hash: [u8; 32]) -> Self {
        Self {
            format_version: DSTACK_VOLUME_FORMAT_VERSION,
            header_size: DSTACK_VOLUME_HEADER_SIZE as u16,
            kind: DSTACK_VOLUME_KIND_VERITY,
            kind_version: 1,
            flags: 0,
            root_hash,
            data_block_size: 4096,
            hash_block_size: 4096,
        }
    }

    pub fn encode(&self) -> binrw::BinResult<[u8; DSTACK_VOLUME_HEADER_SIZE]> {
        let mut block = [0u8; DSTACK_VOLUME_HEADER_SIZE];
        self.write(&mut Cursor::new(&mut block[..]))?;
        Ok(block)
    }

    pub fn decode(block: &[u8]) -> binrw::BinResult<Self> {
        if block.len() < DSTACK_VOLUME_HEADER_SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "volume header is truncated: {} < {DSTACK_VOLUME_HEADER_SIZE}",
                    block.len()
                ),
            });
        }
        let header = Self::read(&mut Cursor::new(block))?;
        if header.format_version != DSTACK_VOLUME_FORMAT_VERSION {
            return Err(binrw::Error::AssertFail {
                pos: 16,
                message: format!(
                    "unsupported volume format version {}",
                    header.format_version
                ),
            });
        }
        if header.header_size as usize != DSTACK_VOLUME_HEADER_SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 18,
                message: format!("invalid volume header size {}", header.header_size),
            });
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VerityVolume, VolumeTarget};

    #[test]
    fn volume_header_round_trip() {
        let expected = DstackVolumeHeader::new_verity([0x5a; 32]);
        let encoded = expected.encode().unwrap();
        assert_eq!(&encoded[..16], b"DSTACK_VOLUME\0\0\0");
        assert_eq!(DstackVolumeHeader::decode(&encoded).unwrap(), expected);
    }

    #[test]
    fn verity_volume_validates_root_and_target_during_deserialization() {
        let volume: VerityVolume = serde_json::from_value(serde_json::json!({
            "verity_root": "5a".repeat(32),
            "target": "/run/models"
        }))
        .unwrap();
        assert_eq!(volume.verity_root, [0x5a; 32]);
        assert_eq!(volume.target, VolumeTarget::Mount("/run/models".into()));

        assert!(serde_json::from_value::<VerityVolume>(serde_json::json!({
            "verity_root": "abcd",
            "target": "docker"
        }))
        .is_err());
        assert!(serde_json::from_value::<VerityVolume>(serde_json::json!({
            "verity_root": "5a".repeat(32),
            "target": "relative/path"
        }))
        .is_err());
    }
}
