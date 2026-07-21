// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! On-disk dstack volume envelope shared by builders and guests.

use std::io::Cursor;

use binrw::{binrw, BinRead, BinWrite};

pub const DSTACK_VOLUME_MAGIC: &[u8; 16] = b"DSTACK_VOLUME\0\0\0";
pub const DSTACK_VOLUME_HEADER_SIZE: usize = 4096;
pub const DSTACK_VOLUME_KIND_VERITY: u32 = 1;

#[binrw]
#[brw(little, magic = b"DSTACK_VOLUME\0\0\0")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackVolumeHeader {
    pub kind: u32,
    pub root_hash: [u8; 32],
}

impl DstackVolumeHeader {
    pub fn new_verity(root_hash: [u8; 32]) -> Self {
        Self {
            kind: DSTACK_VOLUME_KIND_VERITY,
            root_hash,
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
        Self::read(&mut Cursor::new(block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dstack_types::VerityVolume;

    #[test]
    fn volume_header_round_trip() {
        let expected = DstackVolumeHeader::new_verity([0x5a; 32]);
        let encoded = expected.encode().unwrap();
        assert_eq!(&encoded[..16], b"DSTACK_VOLUME\0\0\0");
        assert_eq!(DstackVolumeHeader::decode(&encoded).unwrap(), expected);
    }

    #[test]
    fn verity_volume_validates_root_and_target_during_deserialization(
    ) -> Result<(), serde_json::Error> {
        let volume: VerityVolume = serde_json::from_value(serde_json::json!({
            "verity_root": "5a".repeat(32),
            "target": "/run/models"
        }))?;
        assert_eq!(volume.verity_root, [0x5a; 32]);
        assert_eq!(volume.target, std::path::PathBuf::from("/run/models"));
        assert_eq!(
            serde_json::to_value(&volume)?["verity_root"],
            "5a".repeat(32)
        );

        assert!(serde_json::from_value::<VerityVolume>(serde_json::json!({
            "verity_root": "abcd",
            "target": "/run/models"
        }))
        .is_err());
        assert!(serde_json::from_value::<VerityVolume>(serde_json::json!({
            "verity_root": "5a".repeat(32),
            "target": "relative/path"
        }))
        .is_err());
        Ok(())
    }
}
