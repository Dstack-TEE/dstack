// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Helpers for synthesising the UEFI variable byte blobs that OVMF measures
//! into RTMR[0] as `EV_EFI_VARIABLE_BOOT2` events.
//!
//! For the BootOrder / Boot####  variables the TCG PFP spec digest is taken
//! over the *variable data* portion only (not the full `UEFI_VARIABLE_DATA`
//! struct), so we just build the on-the-wire variable contents here.

use crate::utf16_encode;

/// Build the raw bytes of a `BootOrder` UEFI variable from a sequence of boot
/// option numbers — each entry is a little-endian `u16` referring to a
/// `Boot####` variable.
pub fn boot_order_bytes(entries: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 2);
    for &entry in entries {
        out.extend_from_slice(&entry.to_le_bytes());
    }
    out
}

/// An `EFI_DEVICE_PATH_PROTOCOL` node.
#[derive(Clone, Copy)]
pub struct DevicePathNode<'a> {
    pub r#type: u8,
    pub subtype: u8,
    pub data: &'a [u8],
}

impl DevicePathNode<'_> {
    fn write_to(self, buf: &mut Vec<u8>) {
        let len = 4 + self.data.len();
        buf.push(self.r#type);
        buf.push(self.subtype);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
        buf.extend_from_slice(self.data);
    }
}

/// `END_ENTIRE_DEVICE_PATH` terminator.
pub const END_OF_DEVICE_PATH: DevicePathNode<'static> = DevicePathNode {
    r#type: 0x7f,
    subtype: 0xff,
    data: &[],
};

/// `MEDIA_DEVICE_PATH / Firmware Volume` node (`type=4, subtype=7`).
pub fn fv_node(guid_le: &[u8; 16]) -> DevicePathNode<'_> {
    DevicePathNode {
        r#type: 0x04,
        subtype: 0x07,
        data: guid_le,
    }
}

/// `MEDIA_DEVICE_PATH / Firmware File` node (`type=4, subtype=6`).
pub fn fv_file_node(guid_le: &[u8; 16]) -> DevicePathNode<'_> {
    DevicePathNode {
        r#type: 0x04,
        subtype: 0x06,
        data: guid_le,
    }
}

/// Build the raw bytes of a `Boot####` UEFI variable — the on-the-wire form of
/// `EFI_LOAD_OPTION { Attributes, FilePathListLength, Description, FilePathList,
/// OptionalData }`.
///
/// The description is automatically NUL-terminated in UTF-16LE.
pub fn boot_option_bytes(
    attributes: u32,
    description: &str,
    file_path_nodes: &[DevicePathNode<'_>],
    optional_data: &[u8],
) -> Vec<u8> {
    // Serialise the device-path list first so we know its length.
    let mut file_path = Vec::new();
    for node in file_path_nodes {
        node.write_to(&mut file_path);
    }

    let mut desc = utf16_encode(description);
    desc.extend_from_slice(&[0x00, 0x00]); // NUL terminator

    let mut out = Vec::with_capacity(4 + 2 + desc.len() + file_path.len() + optional_data.len());
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&(file_path.len() as u16).to_le_bytes());
    out.extend_from_slice(&desc);
    out.extend_from_slice(&file_path);
    out.extend_from_slice(optional_data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    fn sha384(bytes: &[u8]) -> String {
        hex::encode(Sha384::new_with_prefix(bytes).finalize())
    }

    #[test]
    fn boot_option_round_trip_sample() {
        // Trivial sanity check: a load option with one MEDIA_FV_FILE node and
        // an empty description should serialise to a 4 (Attrs) + 2 (FpLen) +
        // 2 (NUL) + (4 + 16) (FV_FILE) + 4 (END) = 32 byte blob, and
        // round-tripping the descriptive string survives.
        let blob = boot_option_bytes(1, "", &[fv_file_node(&[0; 16]), END_OF_DEVICE_PATH], &[]);
        assert_eq!(blob.len(), 4 + 2 + 2 + 20 + 4);
        assert_eq!(&blob[0..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&blob[4..6], &[0x18, 0x00]); // FilePathListLength = 24
                                                // Description is just a NUL terminator (two bytes of 0).
        assert_eq!(&blob[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn boot_order_encodes_u16_le_entries() {
        assert_eq!(
            boot_order_bytes(&[0x0000, 0x0001]),
            vec![0x00, 0x00, 0x01, 0x00]
        );
        assert_eq!(
            boot_order_bytes(&[0x1234, 0xabcd]),
            vec![0x34, 0x12, 0xcd, 0xab]
        );
        assert_eq!(
            sha384(&boot_order_bytes(&[0x0000, 0x0001])),
            "52b9a02de946b947364b57d8210c63113b9058996e2a3ba7cead54af11ae0873b085d1e52bc01e4febe57ca05ca1332b"
        );
    }
}
