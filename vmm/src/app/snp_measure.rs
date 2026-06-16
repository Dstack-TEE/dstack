// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP launch-measurement metadata extracted by the VMM.
//!
//! The KMS/verifier must not be configured with one local OVMF binary: a VMM can
//! launch many image/OVMF versions. Instead, the VMM records the measured OVMF
//! launch digest seed and OVMF SEV metadata in `.sys-config.json`; the guest then
//! forwards that self-contained launch input to KMS with its attestation.

use anyhow::{bail, Context, Result};
use fs_err as fs;
use serde::Serialize;
use sha2::{Digest, Sha384};
use std::path::Path;

const LD_BYTES: usize = 48;
const ZEROS_LD: [u8; LD_BYTES] = [0u8; LD_BYTES];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct OvmfSectionParam {
    pub gpa: u64,
    pub size: u64,
    /// Raw OVMF SEV metadata section type:
    /// 1=SNP_SEC_MEMORY, 2=SNP_SECRETS, 3=CPUID, 4=SVSM_CAA,
    /// 0x10=SNP_KERNEL_HASHES.
    pub section_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OvmfMeasurementInfo {
    /// 48-byte GCTX launch digest after measuring the OVMF binary bytes.
    pub ovmf_hash: String,
    pub sev_hashes_table_gpa: u64,
    pub sev_es_reset_eip: u32,
    pub sections: Vec<OvmfSectionParam>,
}

pub(crate) fn ovmf_measurement_info(path: impl AsRef<Path>) -> Result<OvmfMeasurementInfo> {
    let ovmf = OvmfInfo::load(path.as_ref())?;
    let mut gctx = Gctx::new();
    gctx.update_normal_pages(ovmf.gpa, &ovmf.data);
    Ok(OvmfMeasurementInfo {
        ovmf_hash: hex::encode(gctx.ld),
        sev_hashes_table_gpa: ovmf.sev_hashes_table_gpa,
        sev_es_reset_eip: ovmf.sev_es_reset_eip,
        sections: ovmf.sections,
    })
}

struct Gctx {
    ld: [u8; LD_BYTES],
}

impl Gctx {
    fn new() -> Self {
        Self { ld: ZEROS_LD }
    }

    /// SNP spec §8.17.2 PAGE_INFO layout (112 bytes): current digest,
    /// contents digest, length, page type, permissions/reserved, and GPA.
    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8; LD_BYTES]) {
        let mut buf = [0u8; 0x70];
        buf[..LD_BYTES].copy_from_slice(&self.ld);
        buf[48..96].copy_from_slice(contents);
        buf[96..98].copy_from_slice(&0x70u16.to_le_bytes());
        buf[98] = page_type;
        buf[104..112].copy_from_slice(&gpa.to_le_bytes());
        let mut digest = [0u8; LD_BYTES];
        digest.copy_from_slice(&Sha384::digest(buf));
        self.ld = digest;
    }

    fn sha384(data: &[u8]) -> [u8; LD_BYTES] {
        let mut out = [0u8; LD_BYTES];
        out.copy_from_slice(&Sha384::digest(data));
        out
    }

    fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) {
        for (i, chunk) in data.chunks(4096).enumerate() {
            self.update(0x01, start_gpa + (i * 4096) as u64, &Self::sha384(chunk));
        }
    }
}

struct OvmfInfo {
    data: Vec<u8>,
    gpa: u64,
    sections: Vec<OvmfSectionParam>,
    sev_hashes_table_gpa: u64,
    sev_es_reset_eip: u32,
}

const GUID_FOOTER_TABLE: [u8; 16] = [
    0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
];
const GUID_SEV_HASH_TABLE_RV: [u8; 16] = [
    0x1f, 0x37, 0x55, 0x72, 0x3b, 0x3a, 0x04, 0x4b, 0x92, 0x7b, 0x1d, 0xa6, 0xef, 0xa8, 0xd4, 0x54,
];
const GUID_SEV_ES_RESET_BLK: [u8; 16] = [
    0xde, 0x71, 0xf7, 0x00, 0x7e, 0x1a, 0xcb, 0x4f, 0x89, 0x0e, 0x68, 0xc7, 0x7e, 0x2f, 0xb4, 0x4e,
];
const GUID_SEV_META_DATA: [u8; 16] = [
    0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47, 0xa7, 0x5e, 0x55, 0x85, 0xa7, 0xbf, 0x67, 0xcc,
];

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn validate_section_type(value: u32) -> Result<()> {
    match value {
        1 | 2 | 3 | 4 | 0x10 => Ok(()),
        _ => bail!("unknown ovmf section_type {value:#x}"),
    }
}

impl OvmfInfo {
    fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)
            .with_context(|| format!("cannot read ovmf binary '{}'", path.display()))?;
        let size = data.len();
        let gpa = (0x1_0000_0000u64)
            .checked_sub(size as u64)
            .context("ovmf binary is larger than 4 gib")?;

        const ENTRY_HDR: usize = 18;
        let footer_off = size.saturating_sub(32 + ENTRY_HDR);
        if footer_off + ENTRY_HDR > size {
            bail!("ovmf binary too small to contain footer table");
        }
        if data[footer_off + 2..footer_off + 18] != GUID_FOOTER_TABLE {
            bail!("ovmf footer guid not found");
        }
        let footer_total_size = read_u16_le(&data, footer_off) as usize;
        if footer_total_size < ENTRY_HDR {
            bail!("ovmf footer table has invalid total size");
        }
        let table_size = footer_total_size - ENTRY_HDR;
        if table_size > footer_off {
            bail!("ovmf footer table is out of bounds");
        }
        let table_start = footer_off - table_size;
        let table_bytes = &data[table_start..footer_off];

        let mut sev_hashes_table_gpa = 0u64;
        let mut sev_es_reset_eip = 0u32;
        let mut meta_offset_from_end = None;

        let mut pos = table_bytes.len();
        while pos >= ENTRY_HDR {
            let entry_off = pos - ENTRY_HDR;
            let entry_size = read_u16_le(table_bytes, entry_off) as usize;
            if entry_size < ENTRY_HDR || entry_size > pos {
                bail!("ovmf footer table has invalid entry size");
            }
            let guid = &table_bytes[entry_off + 2..entry_off + 18];
            let data_start = pos - entry_size;
            let data_end = pos - ENTRY_HDR;
            let entry_data = &table_bytes[data_start..data_end];

            if guid == GUID_SEV_HASH_TABLE_RV && entry_data.len() >= 4 {
                sev_hashes_table_gpa = read_u32_le(entry_data, 0) as u64;
            } else if guid == GUID_SEV_ES_RESET_BLK && entry_data.len() >= 4 {
                sev_es_reset_eip = read_u32_le(entry_data, 0);
            } else if guid == GUID_SEV_META_DATA && entry_data.len() >= 4 {
                meta_offset_from_end = Some(read_u32_le(entry_data, 0) as usize);
            }
            pos -= entry_size;
        }

        if sev_hashes_table_gpa == 0 {
            bail!("ovmf sev hash table entry not found in footer table");
        }
        if sev_es_reset_eip == 0 {
            bail!("ovmf sev_es_reset_block entry not found in footer table");
        }

        let mut sections = Vec::new();
        let off_from_end = meta_offset_from_end
            .ok_or_else(|| anyhow::anyhow!("ovmf sev metadata entry not found in footer table"))?;
        if off_from_end > size {
            bail!("ovmf sev metadata offset exceeds file size");
        }
        let meta_start = size - off_from_end;
        if meta_start + 16 > size {
            bail!("ovmf sev metadata header out of bounds");
        }
        if &data[meta_start..meta_start + 4] != b"ASEV" {
            bail!("ovmf sev metadata has bad signature");
        }
        let meta_version = read_u32_le(&data, meta_start + 8);
        if meta_version != 1 {
            bail!("ovmf sev metadata has unsupported version {meta_version}");
        }
        let num_items = read_u32_le(&data, meta_start + 12) as usize;
        let items_start = meta_start + 16;
        if items_start + num_items * 12 > size {
            bail!("ovmf sev metadata sections out of bounds");
        }
        for i in 0..num_items {
            let off = items_start + i * 12;
            let section_type = read_u32_le(&data, off + 8);
            validate_section_type(section_type)?;
            sections.push(OvmfSectionParam {
                gpa: read_u32_le(&data, off) as u64,
                size: read_u32_le(&data, off + 4) as u64,
                section_type,
            });
        }

        Ok(Self {
            data,
            gpa,
            sections,
            sev_hashes_table_gpa,
            sev_es_reset_eip,
        })
    }
}
