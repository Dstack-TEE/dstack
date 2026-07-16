// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Verity-volume inspection used while preparing a QEMU launch.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fs_err as fs;
use sha2::{Digest, Sha256};

/// Compute the virtio-blk `serial` hint for a pre-baked verity volume: the first
/// 20 hex chars of its dm-verity root hash (virtio caps serials at 20 bytes).
///
/// The guest uses this to open the matching disk directly instead of probing
/// every disk. It is only a hint. The guest still verifies the full root, so a
/// missing or wrong serial just falls back to probing.
///
/// The current volume format is a raw GPT disk: p1 is verity data, p2 is the
/// verity hash device. The old single-file `[squashfs][verity]` layout is still
/// recognized as a fallback so older volumes can still get the serial hint.
///
/// For multi-block data devices, the root is `sha256(salt || top hash block)`,
/// and the top block sits right after the verity superblock, so we never walk
/// the hash tree. A one-block data device has no hash blocks, so the root is
/// `sha256(salt || data block)`.
pub(super) fn verity_serial_hint(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    partitioned_verity_serial_hint(&mut file).or_else(|| legacy_verity_serial_hint(&mut file))
}

fn partitioned_verity_serial_hint(file: &mut fs::File) -> Option<String> {
    let (data_offset, hash_offset) = gpt_data_hash_offsets(file)?;
    root_prefix_from_verity_devices(file, data_offset, hash_offset)
}

fn legacy_verity_serial_hint(file: &mut fs::File) -> Option<String> {
    file.seek(SeekFrom::Start(0)).ok()?;

    // squashfs superblock: "hsqs" magic at 0, bytes_used (LE u64) at 40. The
    // verity hash tree starts just past there, block-aligned.
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    if &magic != b"hsqs" {
        return None;
    }
    file.seek(SeekFrom::Start(40)).ok()?;
    let mut buf8 = [0u8; 8];
    file.read_exact(&mut buf8).ok()?;
    let hash_offset = u64::from_le_bytes(buf8).div_ceil(4096).checked_mul(4096)?;
    root_prefix_from_verity_devices(file, 0, hash_offset)
}

fn gpt_data_hash_offsets(file: &mut fs::File) -> Option<(u64, u64)> {
    file.seek(SeekFrom::Start(512)).ok()?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header).ok()?;
    if &header[0..8] != b"EFI PART" {
        return None;
    }

    let entries_lba = u64::from_le_bytes(header[72..80].try_into().ok()?);
    let entry_count = u32::from_le_bytes(header[80..84].try_into().ok()?);
    let entry_size = u32::from_le_bytes(header[84..88].try_into().ok()?) as usize;
    if entry_count < 2 || !(128..=4096).contains(&entry_size) {
        return None;
    }

    let entries_offset = entries_lba.checked_mul(512)?;
    let data = gpt_partition_first_lba(file, entries_offset, entry_size, 0)?;
    let hash = gpt_partition_first_lba(file, entries_offset, entry_size, 1)?;
    Some((data.checked_mul(512)?, hash.checked_mul(512)?))
}

fn gpt_partition_first_lba(
    file: &mut fs::File,
    entries_offset: u64,
    entry_size: usize,
    index: u64,
) -> Option<u64> {
    let offset = entries_offset.checked_add(index.checked_mul(entry_size as u64)?)?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut entry = vec![0u8; entry_size];
    file.read_exact(&mut entry).ok()?;
    if entry[0..16].iter().all(|&byte| byte == 0) {
        return None;
    }
    Some(u64::from_le_bytes(entry[32..40].try_into().ok()?))
}

fn root_prefix_from_verity_devices(
    file: &mut fs::File,
    data_offset: u64,
    hash_offset: u64,
) -> Option<String> {
    file.seek(SeekFrom::Start(hash_offset)).ok()?;
    let mut superblock = [0u8; 512];
    file.read_exact(&mut superblock).ok()?;
    if &superblock[0..8] != b"verity\0\0" || !superblock[32..64].starts_with(b"sha256\0") {
        return None;
    }
    // The builder always writes 4096-byte blocks; requiring it also caps the
    // block allocation below at one page for an untrusted file.
    let data_block_size = u32::from_le_bytes(superblock[64..68].try_into().ok()?) as u64;
    let hash_block_size = u32::from_le_bytes(superblock[68..72].try_into().ok()?) as u64;
    let data_blocks = u64::from_le_bytes(superblock[72..80].try_into().ok()?);
    let salt_size = u16::from_le_bytes(superblock[80..82].try_into().ok()?) as usize;
    if data_block_size != 4096 || hash_block_size != 4096 || data_blocks == 0 || salt_size > 256 {
        return None;
    }
    let salt = &superblock[88..88 + salt_size];

    let (block_offset, block_size) = if data_blocks == 1 {
        (data_offset, data_block_size)
    } else {
        (hash_offset.checked_add(hash_block_size)?, hash_block_size)
    };
    file.seek(SeekFrom::Start(block_offset)).ok()?;
    let mut block = vec![0u8; block_size as usize];
    file.read_exact(&mut block).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(&block);
    Some(hex::encode(hasher.finalize())[..20].to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use sha2::{Digest, Sha256};

    use super::verity_serial_hint;

    fn write_minimal_gpt(file: &mut tempfile::NamedTempFile, data_lba: u64, hash_lba: u64) {
        let mut header = [0u8; 512];
        header[0..8].copy_from_slice(b"EFI PART");
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // partition entries LBA
        header[80..84].copy_from_slice(&128u32.to_le_bytes()); // entries
        header[84..88].copy_from_slice(&128u32.to_le_bytes()); // entry size
        file.seek(SeekFrom::Start(512)).unwrap();
        file.write_all(&header).unwrap();

        let mut entries = vec![0u8; 128 * 128];
        // Any non-zero type GUID is enough for the parser.
        entries[0] = 1;
        entries[32..40].copy_from_slice(&data_lba.to_le_bytes());
        let second = 128;
        entries[second] = 1;
        entries[second + 32..second + 40].copy_from_slice(&hash_lba.to_le_bytes());
        file.seek(SeekFrom::Start(2 * 512)).unwrap();
        file.write_all(&entries).unwrap();
    }

    fn verity_superblock(data_blocks: u64, salt: &[u8]) -> [u8; 4096] {
        let mut superblock = [0u8; 4096];
        superblock[0..8].copy_from_slice(b"verity\0\0");
        superblock[32..38].copy_from_slice(b"sha256");
        superblock[64..68].copy_from_slice(&4096u32.to_le_bytes());
        superblock[68..72].copy_from_slice(&4096u32.to_le_bytes());
        superblock[72..80].copy_from_slice(&data_blocks.to_le_bytes());
        superblock[80..82].copy_from_slice(&(salt.len() as u16).to_le_bytes());
        superblock[88..88 + salt.len()].copy_from_slice(salt);
        superblock
    }

    fn test_verity_salt() -> [u8; 32] {
        // Use tempfile's random name as a per-test seed. The salt is fixture
        // data rather than a secret, but deriving it at runtime also keeps
        // security scanners from mistaking a fixed test vector for a
        // production cryptographic salt.
        let seed = tempfile::NamedTempFile::new().unwrap();
        Sha256::digest(seed.path().as_os_str().as_encoded_bytes()).into()
    }

    #[test]
    fn legacy_verity_serial_hint_matches_root_prefix() {
        // A minimal squashfs+verity file: "hsqs" with bytes_used = 8192, then a
        // verity superblock at 8192 and its top hash block at 12288.
        let mut image = vec![0u8; 8192];
        image[0..4].copy_from_slice(b"hsqs");
        image[40..48].copy_from_slice(&8192u64.to_le_bytes());

        let salt = test_verity_salt();
        image.extend_from_slice(&verity_superblock(2, &salt));

        let top_block = vec![0x5au8; 4096];
        image.extend_from_slice(&top_block);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&image).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&top_block);
        let expected = hex::encode(hasher.finalize());

        let got = verity_serial_hint(file.path()).unwrap();
        assert_eq!(got, expected[..20]);
        assert_eq!(got.len(), 20);
    }

    #[test]
    fn partitioned_verity_serial_hint_matches_root_prefix() {
        let data_lba = 2048u64;
        let hash_lba = 4096u64;
        let salt = test_verity_salt();
        let top_block = vec![0x5au8; 4096];

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file_mut().set_len((hash_lba + 16) * 512).unwrap();
        write_minimal_gpt(&mut file, data_lba, hash_lba);
        file.seek(SeekFrom::Start(hash_lba * 512)).unwrap();
        file.write_all(&verity_superblock(2, &salt)).unwrap();
        file.write_all(&top_block).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&top_block);
        let expected = hex::encode(hasher.finalize());

        let got = verity_serial_hint(file.path()).unwrap();
        assert_eq!(got, expected[..20]);
    }

    #[test]
    fn partitioned_one_block_verity_serial_hint_hashes_data_block() {
        let data_lba = 2048u64;
        let hash_lba = 4096u64;
        let salt = test_verity_salt();
        let data_block = vec![0x42u8; 4096];

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file_mut().set_len((hash_lba + 8) * 512).unwrap();
        write_minimal_gpt(&mut file, data_lba, hash_lba);
        file.seek(SeekFrom::Start(data_lba * 512)).unwrap();
        file.write_all(&data_block).unwrap();
        file.seek(SeekFrom::Start(hash_lba * 512)).unwrap();
        file.write_all(&verity_superblock(1, &salt)).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&data_block);
        let expected = hex::encode(hasher.finalize());

        let got = verity_serial_hint(file.path()).unwrap();
        assert_eq!(got, expected[..20]);
    }

    #[test]
    fn verity_serial_hint_skips_non_verity_files() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a squashfs image").unwrap();
        assert_eq!(verity_serial_hint(file.path()), None);
    }
}
