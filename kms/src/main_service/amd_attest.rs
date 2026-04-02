// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0
//
// AMD SEV-SNP attestation verification.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha256, Sha384};
use std::fs;

use crate::config::SevSnpMeasureConfig;

// =============================================================================
// HARDCODED ROOT OF TRUST (ARK)
// =============================================================================

// AMD Genoa ARK certificate (DER, base64-encoded).
// This is the absolute Root of Trust for AMD EPYC Genoa (4th gen) processors.
// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
const GENOA_ARK_DER_B64: &str = "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";

/// Result of a successfully verified AMD SNP attestation.
#[derive(Debug, Clone)]
pub struct VerifiedAmdReport {
    /// 48-byte SNP MEASUREMENT (GCTX launch digest, hardware-attested).
    pub measurement: [u8; 48],
    /// 64-byte report_data field set by the VM when calling snpguest report.
    pub report_data: [u8; 64],
    /// 64-byte chip_id: unique identifier of the AMD processor.
    pub chip_id: [u8; 64],
}

/// Input required for AMD attestation verification.
pub struct AmdAttestInput<'a> {
    /// Raw 1184-byte SNP attestation report binary.
    pub report: &'a [u8],
    /// ASK (AMD SEV Key) certificate in PEM format.
    pub ask_pem: &'a [u8],
    /// VCEK (Versioned Chip Endorsement Key) certificate in PEM format.
    pub vcek_pem: &'a [u8],
}

/// Verify AMD SEV-SNP attestation.
///
/// Workflow:
/// 1. Parse the SNP attestation report.
/// 2. Load the hardcoded ARK (Genoa Root of Trust).
/// 3. Parse the provided ASK and VCEK certificates.
/// 4. Verify the certificate chain: ARK → ASK → VCEK.
/// 5. Verify the report signature using the VCEK public key.
/// 6. Return the verified measurement, report_data, and chip_id.
///
/// The returned `measurement` is the hardware-attested GCTX launch digest
/// that covers OVMF, kernel, initrd, and cmdline (including compose_hash +
/// rootfs_hash). The auth webhook can use this for its allowlist checks.
pub fn verify_amd_attestation(input: &AmdAttestInput<'_>) -> Result<VerifiedAmdReport> {
    // 1. Parse the attestation report (1184 bytes).
    let report = AttestationReport::from_bytes(input.report)
        .map_err(|e| anyhow::anyhow!("SNP report parse failed: {e}"))?;

    // 2. Load hardcoded Genoa ARK (Root of Trust).
    let ark_der = STANDARD
        .decode(GENOA_ARK_DER_B64)
        .context("Failed to base64-decode hardcoded ARK")?;
    let ark = Certificate::from_der(&ark_der)
        .map_err(|e| anyhow::anyhow!("ARK DER parse failed: {e:?}"))?;

    // 3. Parse the provided ASK and VCEK from PEM.
    let ask = Certificate::from_pem(input.ask_pem)
        .map_err(|e| anyhow::anyhow!("ASK PEM parse failed: {e:?}"))?;
    let vcek = Certificate::from_pem(input.vcek_pem)
        .map_err(|e| anyhow::anyhow!("VCEK PEM parse failed: {e:?}"))?;

    // 4. Verify certificate chain: ARK → ASK → VCEK.
    let ca_chain = ca::Chain { ark, ask };
    let chain = Chain {
        ca: ca_chain,
        vek: vcek.clone(),
    };
    chain
        .verify()
        .map_err(|e| anyhow::anyhow!("AMD cert chain verification failed: {e:?}"))?;

    // 5. Verify report signature using the VCEK public key.
    (&vcek, &report)
        .verify()
        .map_err(|e| anyhow::anyhow!("SNP report signature verification failed: {e:?}"))?;

    // 6. Extract verified fields.
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(
        report
            .measurement
            .as_ref()
            .get(..48)
            .context("measurement too short")?,
    );

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(
        report
            .report_data
            .as_ref()
            .get(..64)
            .context("report_data too short")?,
    );

    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(
        report
            .chip_id
            .as_ref()
            .get(..64)
            .context("chip_id too short")?,
    );

    Ok(VerifiedAmdReport {
        measurement,
        report_data,
        chip_id,
    })
}

/// Verify that `app_id` is non-empty (prevents deriving keys for a zero app_id).
pub fn validate_app_id(app_id: &[u8]) -> Result<()> {
    if app_id.is_empty() {
        bail!("app_id must not be empty");
    }
    if app_id.iter().all(|&b| b == 0) {
        bail!("app_id must not be all-zeros");
    }
    Ok(())
}

// =============================================================================
// Pure-Rust SNP MEASUREMENT recomputation
// =============================================================================
//
// Ports the sev-snp-measure Python algorithm to Rust without any additional
// dependencies: SHA-384 (GCTX) and SHA-256 (SevHashes) use `sha2` which is
// already a direct dep; OVMF parsing and VMSA page construction are implemented
// below from the AMD spec and the sev-snp-measure source.
//
// References:
//   AMD SNP spec §8.17.2 – PAGE_INFO / GCTX
//   https://github.com/IBM/sev-snp-measure
//   https://github.com/virtee/sev/tree/main/src/measurement

// -------- GCTX (SHA-384 launch digest accumulator) ---------------------------

const LD_BYTES: usize = 48;
const ZEROS_LD: [u8; LD_BYTES] = [0u8; LD_BYTES];
// VMSA page GPA: (u64)(-1) page-aligned, bits >51 cleared.
const VMSA_GPA: u64 = 0x0000_FFFF_FFFF_F000;

struct Gctx {
    ld: [u8; LD_BYTES],
}

impl Gctx {
    fn new() -> Self {
        Self { ld: ZEROS_LD }
    }

    fn from_ovmf_hash(hex: &str) -> Result<Self> {
        let raw = hex::decode(hex).context("ovmf_hash is not valid hex")?;
        let ld: [u8; LD_BYTES] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("ovmf_hash must be 48 bytes (96 hex chars)"))?;
        Ok(Self { ld })
    }

    /// SNP spec §8.17.2 Table 67 – PAGE_INFO layout (0x70 = 112 bytes total):
    ///  [ 0..48)   – current launch digest
    ///  [48..96)   – contents (SHA-384 of page data, or all-zeros)
    ///  [96..98)   – length u16 LE = 0x70
    ///  [98]       – page_type
    ///  [99..104)  – is_imi(1) + vmpl3/2/1_perms(3) + reserved(1) = 0
    ///  [104..112) – gpa u64 LE
    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8; LD_BYTES]) {
        let mut buf = [0u8; 0x70];
        buf[..LD_BYTES].copy_from_slice(&self.ld);
        buf[48..96].copy_from_slice(contents);
        buf[96..98].copy_from_slice(&0x70u16.to_le_bytes());
        buf[98] = page_type;
        // buf[99..104] stay 0
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

    fn update_zero_pages(&mut self, gpa: u64, len: usize) {
        for i in (0..len).step_by(4096) {
            self.update(0x03, gpa + i as u64, &ZEROS_LD);
        }
    }

    fn update_secrets_page(&mut self, gpa: u64) {
        self.update(0x05, gpa, &ZEROS_LD);
    }

    fn update_cpuid_page(&mut self, gpa: u64) {
        self.update(0x06, gpa, &ZEROS_LD);
    }

    fn update_vmsa_page(&mut self, page: &[u8]) {
        self.update(0x02, VMSA_GPA, &Self::sha384(page));
    }
}

// -------- SevHashes page construction ----------------------------------------
//
// GUID values in little-endian (Windows / mixed-endian RFC 4122) byte order.
// Computed as: time_low(LE u32) + time_mid(LE u16) + time_hi(LE u16) +
//              clock_seq_hi(u8) + clock_seq_lo(u8) + node(6 u8, unchanged).
//
//   9438d606-4f22-4cc9-b479-a793d411fd21  → table header
//   4de79437-abd2-427f-b835-d5b172d2045b  → kernel entry
//   44baf731-3a2f-4bd7-9af1-41e29169781d  → initrd entry
//   97d02dd8-bd20-4c94-aa78-e7714d36ab2a  → cmdline entry

const GUID_LE_HASH_TABLE_HEADER: [u8; 16] = [
    0x06, 0xd6, 0x38, 0x94, 0x22, 0x4f, 0xc9, 0x4c, 0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21,
];
const GUID_LE_KERNEL_ENTRY: [u8; 16] = [
    0x37, 0x94, 0xe7, 0x4d, 0xd2, 0xab, 0x7f, 0x42, 0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b,
];
const GUID_LE_INITRD_ENTRY: [u8; 16] = [
    0x31, 0xf7, 0xba, 0x44, 0x2f, 0x3a, 0xd7, 0x4b, 0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d,
];
const GUID_LE_CMDLINE_ENTRY: [u8; 16] = [
    0xd8, 0x2d, 0xd0, 0x97, 0x20, 0xbd, 0x94, 0x4c, 0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a,
];

/// One `SevHashTableEntry`: guid(16) + length_u16(2) + sha256_hash(32) = 50 bytes.
fn sev_entry(guid: &[u8; 16], hash: &[u8; 32]) -> [u8; 50] {
    let mut e = [0u8; 50];
    e[..16].copy_from_slice(guid);
    e[16..18].copy_from_slice(&50u16.to_le_bytes());
    e[18..].copy_from_slice(hash);
    e
}

/// Build the 4096-byte SNP kernel-hashes page from pre-computed SHA-256 hashes.
///
/// Replicates the binary layout that QEMU places in the `SNP_KERNEL_HASHES`
/// OVMF metadata section so the GCTX measurement matches exactly:
///
///   SevHashTable (168 bytes):
///     guid(16) + length_u16(2) + cmdline_entry(50) + initrd_entry(50) + kernel_entry(50)
///   Padded to next multiple of 16 → 176 bytes
///   Placed at `page_offset` within a 4096-byte zero page.
///
/// * `kernel_hash_hex` – 64-char hex (SHA-256 of the kernel bzImage)
/// * `initrd_hash_hex` – 64-char hex (SHA-256 of the initrd); `""` → hash of empty bytes
/// * `append`          – kernel cmdline WITHOUT trailing `\0`
/// * `page_offset`     – byte offset within the page (`ovmf.sev_hashes_table_gpa() & 0xfff`)
fn build_sev_hashes_page(
    kernel_hash_hex: &str,
    initrd_hash_hex: &str,
    append: &str,
    page_offset: usize,
) -> Result<[u8; 4096]> {
    let kernel_hash: [u8; 32] = hex::decode(kernel_hash_hex)
        .context("kernel_hash_hex: not valid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("kernel_hash must be 32 bytes (64 hex chars)"))?;

    let initrd_hash: [u8; 32] = if initrd_hash_hex.is_empty() {
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha256::digest(b""));
        h
    } else {
        hex::decode(initrd_hash_hex)
            .context("initrd_hash_hex: not valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("initrd_hash must be 32 bytes (64 hex chars)"))?
    };

    let mut cmdline_bytes = append.as_bytes().to_vec();
    cmdline_bytes.push(0); // NUL terminator, same as QEMU
    let mut cmdline_hash = [0u8; 32];
    cmdline_hash.copy_from_slice(&Sha256::digest(&cmdline_bytes));

    let cmdline_entry = sev_entry(&GUID_LE_CMDLINE_ENTRY, &cmdline_hash);
    let initrd_entry = sev_entry(&GUID_LE_INITRD_ENTRY, &initrd_hash);
    let kernel_entry = sev_entry(&GUID_LE_KERNEL_ENTRY, &kernel_hash);

    // SevHashTable: guid(16) + length(2) + cmdline(50) + initrd(50) + kernel(50) = 168 bytes
    const TABLE_SIZE: usize = 16 + 2 + 50 + 50 + 50; // 168
    let mut table = [0u8; TABLE_SIZE];
    table[..16].copy_from_slice(&GUID_LE_HASH_TABLE_HEADER);
    table[16..18].copy_from_slice(&(TABLE_SIZE as u16).to_le_bytes());
    table[18..68].copy_from_slice(&cmdline_entry);
    table[68..118].copy_from_slice(&initrd_entry);
    table[118..168].copy_from_slice(&kernel_entry);

    // Pad to next multiple of 16: (168 + 15) & !15 = 176 → 8 bytes padding.
    const PADDED: usize = (TABLE_SIZE + 15) & !(15usize);
    let mut padded = [0u8; PADDED];
    padded[..TABLE_SIZE].copy_from_slice(&table);

    if page_offset + PADDED > 4096 {
        bail!("SevHashTable (offset={page_offset}, size={PADDED}) overflows 4096-byte page");
    }
    let mut page = [0u8; 4096];
    page[page_offset..page_offset + PADDED].copy_from_slice(&padded);
    Ok(page)
}

// -------- OVMF binary parser -------------------------------------------------
//
// Parses the OVMF footer table (at the end of the binary) and the SEV metadata
// section to extract the information needed for GCTX computation.
// Translated directly from sev-snp-measure/sevsnpmeasure/ovmf.py.

/// Sections declared by the OVMF SEV Metadata.
#[derive(Debug, PartialEq)]
enum SectionType {
    SnpSecMemory = 1,
    SnpSecrets = 2,
    Cpuid = 3,
    SvsmCaa = 4,
    SnpKernelHashes = 0x10,
}

impl SectionType {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::SnpSecMemory),
            2 => Some(Self::SnpSecrets),
            3 => Some(Self::Cpuid),
            4 => Some(Self::SvsmCaa),
            0x10 => Some(Self::SnpKernelHashes),
            _ => None,
        }
    }
}

struct MetadataSection {
    gpa: u32,
    size: u32,
    section_type: SectionType,
}

struct OvmfInfo {
    data: Vec<u8>,
    gpa: u64, // = 4 GiB - data.len()
    sections: Vec<MetadataSection>,
    sev_hashes_table_gpa: u64,
    sev_es_reset_eip: u32,
}

// GUIDs stored as little-endian bytes (Windows / mixed-endian RFC 4122 layout).
// Format: time_low(4 LE) + time_mid(2 LE) + time_hi(2 LE) + clock_hi + clock_lo + node(6).
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

impl OvmfInfo {
    fn load(path: &str) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("Cannot read OVMF binary '{path}'"))?;
        let size = data.len();
        // 4 GiB – size gives us the GPA base where OVMF is mapped.
        let gpa = (0x1_0000_0000u64)
            .checked_sub(size as u64)
            .context("OVMF binary is larger than 4 GiB")?;

        // --- parse footer table ---
        // The OVMF table footer entry is at: data[size-32-18 .. size-32]
        // Entry layout: size_u16(2) + guid_le(16)
        const ENTRY_HDR: usize = 18; // sizeof(OvmfFooterTableEntry)
        let footer_off = size.saturating_sub(32 + ENTRY_HDR);
        if footer_off + ENTRY_HDR > size {
            bail!("OVMF binary too small to contain footer table");
        }
        if data[footer_off + 2..footer_off + 18] != GUID_FOOTER_TABLE {
            bail!("OVMF footer GUID not found – is this an AMD SEV OVMF file?");
        }
        let footer_total_size = read_u16_le(&data, footer_off) as usize;
        if footer_total_size < ENTRY_HDR {
            bail!("OVMF footer table: invalid total size {footer_total_size}");
        }
        let table_size = footer_total_size - ENTRY_HDR;
        // table_bytes = data[footer_off - table_size .. footer_off]
        let table_start = footer_off.saturating_sub(table_size);
        let table_bytes = &data[table_start..footer_off];

        let mut sev_hashes_table_gpa: u64 = 0;
        let mut sev_es_reset_eip: u32 = 0;
        let mut meta_offset_from_end: Option<usize> = None;

        let mut pos = table_bytes.len();
        while pos >= ENTRY_HDR {
            let entry_off = pos - ENTRY_HDR;
            let entry_size = read_u16_le(table_bytes, entry_off) as usize;
            if entry_size < ENTRY_HDR || entry_size > pos {
                bail!("OVMF footer table: invalid entry size {entry_size} at pos {pos}");
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

        if sev_es_reset_eip == 0 {
            bail!("OVMF: SEV_ES_RESET_BLOCK entry not found in footer table");
        }

        // --- parse SEV metadata sections ---
        let mut sections = Vec::new();
        if let Some(off_from_end) = meta_offset_from_end {
            if off_from_end > size {
                bail!("OVMF SEV metadata offset {off_from_end} exceeds file size {size}");
            }
            let meta_start = size - off_from_end;
            // Header: signature[4] + size(u32) + version(u32) + num_items(u32) = 16 bytes
            if meta_start + 16 > size {
                bail!("OVMF: SEV metadata header out of bounds");
            }
            if &data[meta_start..meta_start + 4] != b"ASEV" {
                bail!("OVMF: bad SEV metadata signature (expected 'ASEV')");
            }
            let meta_version = read_u32_le(&data, meta_start + 8);
            if meta_version != 1 {
                bail!("OVMF: unsupported SEV metadata version {meta_version}");
            }
            let num_items = read_u32_le(&data, meta_start + 12) as usize;
            // Each section desc: gpa(u32) + size(u32) + type(u32) = 12 bytes
            let items_start = meta_start + 16;
            if items_start + num_items * 12 > size {
                bail!("OVMF: SEV metadata sections out of bounds");
            }
            for i in 0..num_items {
                let off = items_start + i * 12;
                let sec_gpa = read_u32_le(&data, off);
                let sec_size = read_u32_le(&data, off + 4);
                let sec_type = read_u32_le(&data, off + 8);
                let section_type = SectionType::from_u32(sec_type).with_context(|| {
                    format!("OVMF: unknown section type {sec_type:#x} in metadata item {i}")
                })?;
                sections.push(MetadataSection {
                    gpa: sec_gpa,
                    size: sec_size,
                    section_type,
                });
            }
        };

        Ok(OvmfInfo {
            data,
            gpa,
            sections,
            sev_hashes_table_gpa,
            sev_es_reset_eip,
        })
    }
}

// -------- VMSA page builder (QEMU mode, SNP) ---------------------------------
//
// Builds the 4 KiB VMSA page (SevEsSaveArea) for one vCPU at a given EIP,
// matching QEMU's initial register state.
// Translated from sev-snp-measure/sevsnpmeasure/vmsa.py :: VMSA.build_save_area.
//
// The struct layout (pack=1, all little-endian) is fixed by the AMD APM Volume 2
// Table B-4 and the Linux kernel struct sev_es_work_area.
//
// Offset constants below are the byte offsets of each field within the 4096-byte
// SevEsSaveArea structure (verified against the Python ctypes struct definition).
//
// VmcbSeg layout (16 bytes each):
//   +0  selector  u16
//   +2  attrib    u16
//   +4  limit     u32
//   +8  base      u64
fn write_u16_le_at(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32_le_at(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64_le_at(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn write_vmcb_seg(buf: &mut [u8], off: usize, selector: u16, attrib: u16, limit: u32, base: u64) {
    write_u16_le_at(buf, off, selector);
    write_u16_le_at(buf, off + 2, attrib);
    write_u32_le_at(buf, off + 4, limit);
    write_u64_le_at(buf, off + 8, base);
}

/// Compute the 32-bit AMD CPUID signature from (family, model, stepping).
/// AMD CPUID Specification #25481, Section: Fn0000_0001_EAX.
fn amd_cpu_sig(family: u32, model: u32, stepping: u32) -> u32 {
    let (family_low, family_high) = if family > 0xf {
        (0xf, (family - 0xf) & 0xff)
    } else {
        (family, 0)
    };
    let model_low = model & 0xf;
    let model_high = (model >> 4) & 0xf;
    (family_high << 20)
        | (model_high << 16)
        | (family_low << 8)
        | (model_low << 4)
        | (stepping & 0xf)
}

/// Map a QEMU vcpu-type string (case-insensitive) to its AMD CPUID signature.
fn vcpu_sig_from_type(vcpu_type: &str) -> Result<u32> {
    match vcpu_type.to_lowercase().as_str() {
        "epyc" | "epyc-v1" | "epyc-v2" | "epyc-ibpb" | "epyc-v3" | "epyc-v4"
            => Ok(amd_cpu_sig(23, 1, 2)),
        "epyc-rome" | "epyc-rome-v1" | "epyc-rome-v2" | "epyc-rome-v3"
            => Ok(amd_cpu_sig(23, 49, 0)),
        "epyc-milan" | "epyc-milan-v1" | "epyc-milan-v2"
            => Ok(amd_cpu_sig(25, 1, 1)),
        "epyc-genoa" | "epyc-genoa-v1"
            => Ok(amd_cpu_sig(25, 17, 0)),
        other => bail!("Unknown vcpu_type: {other:?}. Supported: EPYC, EPYC-v4, EPYC-Rome, EPYC-Milan, EPYC-Genoa (and -v1/-v2/-v3 variants)"),
    }
}

/// Build a 4096-byte VMSA page for QEMU/SNP at the given EIP.
///
/// * `eip`           – reset vector EIP (0xfffffff0 for BSP, or sev_es_reset_eip for AP)
/// * `vcpu_sig`      – AMD CPUID signature (placed in RDX)
/// * `sev_features`  – guest features bitmask (= cfg.guest_features)
fn build_vmsa_page(eip: u32, vcpu_sig: u32, sev_features: u64) -> Box<[u8; 4096]> {
    let mut page = Box::new([0u8; 4096]);
    let p = page.as_mut_slice();

    // QEMU initial segment state (from vmsa.py build_save_area for VMMType.QEMU)
    let cs_base = (eip as u64) & 0xffff_0000;
    let rip = (eip as u64) & 0x0000_ffff;

    // Segment registers (VmcbSeg: selector,attrib,limit,base)
    write_vmcb_seg(p, 0x000, 0, 0x0093, 0xffff, 0); // es
    write_vmcb_seg(p, 0x010, 0xf000, 0x009b, 0xffff, cs_base); // cs
    write_vmcb_seg(p, 0x020, 0, 0x0093, 0xffff, 0); // ss
    write_vmcb_seg(p, 0x030, 0, 0x0093, 0xffff, 0); // ds
    write_vmcb_seg(p, 0x040, 0, 0x0093, 0xffff, 0); // fs
    write_vmcb_seg(p, 0x050, 0, 0x0093, 0xffff, 0); // gs
    write_vmcb_seg(p, 0x060, 0, 0x0000, 0xffff, 0); // gdtr
    write_vmcb_seg(p, 0x070, 0, 0x0082, 0xffff, 0); // ldtr
    write_vmcb_seg(p, 0x080, 0, 0x0000, 0xffff, 0); // idtr
    write_vmcb_seg(p, 0x090, 0, 0x008b, 0xffff, 0); // tr

    // Control / status registers
    write_u64_le_at(p, 0x0D0, 0x1000); // efer  (SVME)
    write_u64_le_at(p, 0x148, 0x40); // cr4   (MCE)
    write_u64_le_at(p, 0x158, 0x10); // cr0   (PE)
    write_u64_le_at(p, 0x160, 0x400); // dr7
    write_u64_le_at(p, 0x168, 0xffff_0ff0); // dr6
    write_u64_le_at(p, 0x170, 0x2); // rflags
    write_u64_le_at(p, 0x178, rip); // rip
    write_u64_le_at(p, 0x268, 0x0007_0406_0007_0406); // g_pat (PAT MSR)
    write_u64_le_at(p, 0x310, vcpu_sig as u64); // rdx   (CPUID sig)
    write_u64_le_at(p, 0x3B0, sev_features); // sev_features
    write_u64_le_at(p, 0x3E8, 0x1); // xcr0
    write_u32_le_at(p, 0x408, 0x1f80); // mxcsr
    write_u16_le_at(p, 0x410, 0x037f); // x87_fcw

    page
}

// -------- Top-level measurement entry point ----------------------------------

/// One OVMF SEV metadata section descriptor supplied from the VM request.
///
/// The launcher extracts these values from the OVMF binary before VM launch
/// and passes them to the guest.  Any lie about these values causes MEASUREMENT
/// mismatch ⇒ the KMS rejects the request.
pub struct OvmfSectionParam {
    pub gpa: u32,
    pub size: u32,
    /// Raw `section_type` value: 1=SNP_SEC_MEMORY, 2=SNP_SECRETS, 3=CPUID,
    /// 4=SVSM_CAA, 0x10=SNP_KERNEL_HASHES.
    pub section_type: u32,
}

/// Per-request inputs for [`compute_expected_measurement`].
///
/// Separate from [`SevSnpMeasureConfig`] (KMS host config) so the function
/// stays within the clippy argument-count limit.
pub struct MeasurementInput<'a> {
    /// 96-char hex GCTX seed for OVMF pages; `""` → compute from file.
    pub ovmf_hash: &'a str,
    /// GPA of the SevHashTable (from request; ignored when loading OVMF file).
    pub sev_hashes_table_gpa: u64,
    /// AP reset EIP (from request; ignored when loading OVMF file).
    pub sev_es_reset_eip: u32,
    /// Sections from request; empty → fall back to loading file.
    pub ovmf_sections: &'a [OvmfSectionParam],
    /// 64-char hex SHA-256 of the kernel.
    pub kernel_hash: &'a str,
    /// 64-char hex SHA-256 of the initrd (`""` = empty initrd).
    pub initrd_hash: &'a str,
    /// vCPU count (must match the VM launch value).
    pub vcpus: u32,
    /// QEMU CPU model string, e.g. `"EPYC-v4"`.
    pub vcpu_type: &'a str,
    /// 64-char hex placed in `docker_compose_hash=` cmdline arg.
    pub compose_hash: &'a str,
    /// 64-char hex placed in `rootfs_hash=` cmdline arg.
    pub rootfs_hash: &'a str,
    /// Optional 64-char hex placed in `docker_additional_files_hash=`.
    pub docker_files_hash: Option<&'a str>,
}

/// Recompute the expected SNP MEASUREMENT in pure Rust.
///
/// Two code paths:
///
/// 1. **VM-provided OVMF metadata** (`input.ovmf_sections` is non-empty):
///    The KMS never needs the OVMF file on disk.  `input.ovmf_hash` *must*
///    be provided.
///
/// 2. **OVMF file on KMS disk** (`input.ovmf_sections` is empty):
///    The KMS reads `cfg.ovmf_path` (which must be `Some`).
///
/// Returns the expected 48-byte GCTX launch digest.
pub fn compute_expected_measurement(
    cfg: &SevSnpMeasureConfig,
    input: &MeasurementInput<'_>,
) -> Result<[u8; 48]> {
    let ovmf_hash = input.ovmf_hash;
    let sev_hashes_table_gpa = input.sev_hashes_table_gpa;
    let sev_es_reset_eip = input.sev_es_reset_eip;
    let ovmf_sections = input.ovmf_sections;
    let kernel_hash = input.kernel_hash;
    let initrd_hash = input.initrd_hash;
    let vcpus = input.vcpus;
    let vcpu_type_str = input.vcpu_type;
    let compose_hash = input.compose_hash;
    let rootfs_hash = input.rootfs_hash;
    let docker_files_hash = input.docker_files_hash;
    // Reconstruct the kernel cmdline exactly as produced by the VM launcher.
    let mut cmdline = format!(
        "console=ttyS0 loglevel=7 docker_compose_hash={compose_hash} rootfs_hash={rootfs_hash}"
    );
    if let Some(dh) = docker_files_hash {
        if !dh.is_empty() {
            cmdline.push_str(&format!(" docker_additional_files_hash={dh}"));
        }
    }

    // Determine the GCTX initial state, the effective sev_hashes_table_gpa,
    // the effective sev_es_reset_eip, and the ordered section list.
    let (mut gctx, eff_hashes_gpa, eff_reset_eip, resolved_sections);
    if !ovmf_sections.is_empty() {
        // Path 1: VM provided all OVMF metadata.  No OVMF file needed.
        if ovmf_hash.is_empty() {
            bail!(
                "ovmf_hash must be provided in the request when ovmf_sections \
                 are given (KMS does not have the OVMF file on disk)"
            );
        }
        gctx = Gctx::from_ovmf_hash(ovmf_hash)?;
        eff_hashes_gpa = sev_hashes_table_gpa;
        eff_reset_eip = sev_es_reset_eip;
        resolved_sections = ovmf_sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let section_type = SectionType::from_u32(s.section_type).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unknown section_type {:#x} in ovmf_sections[{i}]",
                        s.section_type
                    )
                })?;
                Ok(MetadataSection {
                    gpa: s.gpa,
                    size: s.size,
                    section_type,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    } else {
        // Path 2: Load OVMF binary from KMS disk.
        let path = cfg.ovmf_path.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "SNP MEASUREMENT verification requires either ovmf_sections in the \
                 request or ovmf_path \
                 configured in [core.sev_snp] on the KMS host"
            )
        })?;
        let ovmf = OvmfInfo::load(path)?;
        gctx = if ovmf_hash.is_empty() {
            let mut g = Gctx::new();
            g.update_normal_pages(ovmf.gpa, &ovmf.data);
            g
        } else {
            Gctx::from_ovmf_hash(ovmf_hash)?
        };
        eff_hashes_gpa = ovmf.sev_hashes_table_gpa;
        eff_reset_eip = ovmf.sev_es_reset_eip;
        resolved_sections = ovmf.sections;
    }

    // Feed SEV metadata sections in order (mirrors snp_update_metadata_pages).
    let mut has_kernel_hashes_section = false;
    for sec in &resolved_sections {
        let gpa = sec.gpa as u64;
        let size = sec.size as usize;
        match sec.section_type {
            SectionType::SnpSecMemory => gctx.update_zero_pages(gpa, size),
            SectionType::SnpSecrets => gctx.update_secrets_page(gpa),
            SectionType::Cpuid => gctx.update_cpuid_page(gpa),
            SectionType::SvsmCaa => gctx.update_zero_pages(gpa, size),
            SectionType::SnpKernelHashes => {
                has_kernel_hashes_section = true;
                if eff_hashes_gpa == 0 {
                    bail!("SNP_KERNEL_HASHES section present but sev_hashes_table_gpa is 0");
                }
                let page_offset = (eff_hashes_gpa & 0xfff) as usize;
                let page = build_sev_hashes_page(kernel_hash, initrd_hash, &cmdline, page_offset)?;
                gctx.update_normal_pages(gpa, &page);
            }
        }
    }
    if !has_kernel_hashes_section {
        bail!(
            "OVMF metadata does not include a SNP_KERNEL_HASHES section — \
               kernel/initrd hashes cannot be incorporated into the measurement"
        );
    }

    // Add one VMSA page per vCPU (BSP first, then APs).
    let vcpu_sig = vcpu_sig_from_type(vcpu_type_str)?;
    let bsp_vmsa = build_vmsa_page(0xffff_fff0, vcpu_sig, cfg.guest_features);
    let ap_vmsa = build_vmsa_page(eff_reset_eip, vcpu_sig, cfg.guest_features);

    for i in 0..vcpus as usize {
        let vmsa_page = if i == 0 {
            bsp_vmsa.as_ref()
        } else {
            ap_vmsa.as_ref()
        };
        gctx.update_vmsa_page(vmsa_page);
    }

    Ok(gctx.ld)
}

// =============================================================================
// Manual integration test: compute MEASUREMENT from sev_image_fingerprints.json
// =============================================================================
//
// Run with:
//   FINGERPRINTS=/path/to/sev_image_fingerprints.json \
//   COMPOSE_HASH=<64-hex>   \
//   ROOTFS_HASH=<64-hex>    \
//   [DOCKER_FILES_HASH=<64-hex>] \
//   [OVMF_PATH=/path/to/ovmf.fd] \
//   cargo test -p dstack-kms -- --ignored amd::compute_measurement_from_fingerprints --nocapture
//
// FINGERPRINTS must be a JSON file with the following fields, e.g.:
//   {
//     "kernel_hash":            "<64 hex>",
//     "initrd_hash":            "<64 hex>",
//     "vcpus":                  1,
//     "vcpu_type":              "EPYC",
//     "ovmf_hash":              "<96 hex>",
//     "sev_hashes_table_gpa":   <u64>,
//     "sev_es_reset_eip":       <u32>,
//     "ovmf_sections": [{"gpa":<u32>,"size":<u32>,"section_type":<u32>}, ...]
//   }
//
// COMPOSE_HASH and ROOTFS_HASH are the SHA-256 hashes used in the kernel
// cmdline (same values that snpguest / the VM inserts into the attestation
// report request).
//
// Compare the printed measurement against:
//   snpguest display report att-report.bin  →  Measurement field
// or:
//   sev-snp-measure --mode snp --vcpus 1 --vcpu-type EPYC \
//     --ovmf ovmf.fd --kernel bzImage --initrd initramfs.cpio.gz \
//     --append "console=ttyS0 loglevel=7 docker_compose_hash=... rootfs_hash=..."

#[cfg(test)]
mod amd {
    use super::*;
    use serde::Deserialize;
    use std::env;

    #[derive(Debug, Deserialize)]
    struct FingerprintSection {
        gpa: u32,
        size: u32,
        section_type: u32,
    }

    #[derive(Debug, Deserialize)]
    struct FingerprintsFile {
        kernel_hash: String,
        #[serde(default)]
        initrd_hash: String,
        #[serde(default = "default_vcpus")]
        vcpus: u32,
        #[serde(default = "default_vcpu_type")]
        vcpu_type: String,
        #[serde(default)]
        ovmf_hash: String,
        #[serde(default)]
        ovmf_path: Option<String>,
        #[serde(default = "default_guest_features_test")]
        guest_features: u64,
        #[serde(default)]
        sev_hashes_table_gpa: u64,
        #[serde(default)]
        sev_es_reset_eip: u32,
        #[serde(default)]
        ovmf_sections: Vec<FingerprintSection>,
    }

    fn default_vcpus() -> u32 {
        1
    }
    fn default_vcpu_type() -> String {
        "EPYC".to_string()
    }
    fn default_guest_features_test() -> u64 {
        1
    }

    /// Read `sev_image_fingerprints.json` and compute the SNP MEASUREMENT.
    ///
    /// Marked `#[ignore]` so it only runs when explicitly requested (see
    /// the comment block above for the exact cargo test invocation).
    #[test]
    #[ignore]
    fn compute_measurement_from_fingerprints() {
        // ---- read env vars ------------------------------------------------
        let fp_path = env::var("FINGERPRINTS")
            .expect("FINGERPRINTS env var must point to sev_image_fingerprints.json");
        let compose_hash = env::var("COMPOSE_HASH")
            .expect("COMPOSE_HASH env var must be set (SHA-256 hex of docker-compose.yaml)");
        let rootfs_hash = env::var("ROOTFS_HASH")
            .expect("ROOTFS_HASH env var must be set (SHA-256 hex of rootfs ISO)");
        let docker_files_hash = env::var("DOCKER_FILES_HASH").ok();
        let ovmf_path_override = env::var("OVMF_PATH").ok();

        // ---- parse fingerprints file --------------------------------------
        let raw = std::fs::read_to_string(&fp_path)
            .unwrap_or_else(|e| panic!("Cannot read {fp_path}: {e}"));
        let fp: FingerprintsFile =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Cannot parse {fp_path}: {e}"));

        println!("--- sev_image_fingerprints ---");
        println!("  kernel_hash:          {}", fp.kernel_hash);
        println!("  initrd_hash:          {}", fp.initrd_hash);
        println!("  vcpus:                {}", fp.vcpus);
        println!("  vcpu_type:            {}", fp.vcpu_type);
        println!("  ovmf_hash:            {}", fp.ovmf_hash);
        println!("  sev_hashes_table_gpa: {:#x}", fp.sev_hashes_table_gpa);
        println!("  sev_es_reset_eip:     {:#x}", fp.sev_es_reset_eip);
        println!("  guest_features:       {:#x}", fp.guest_features);
        println!("  ovmf_sections:        {} entries", fp.ovmf_sections.len());
        for (i, s) in fp.ovmf_sections.iter().enumerate() {
            println!(
                "    [{i}] gpa={:#x}  size={:#x}  type={}",
                s.gpa, s.size, s.section_type
            );
        }
        println!("--- inputs ---");
        println!("  compose_hash:         {compose_hash}");
        println!("  rootfs_hash:          {rootfs_hash}");
        if let Some(dh) = &docker_files_hash {
            println!("  docker_files_hash:    {dh}");
        }
        if let Some(op) = &ovmf_path_override {
            println!("  OVMF_PATH override:   {op}");
        }

        // ---- build config ------------------------------------------------
        let effective_ovmf_path = ovmf_path_override.or(fp.ovmf_path).or_else(|| {
            // If sections are provided the path is optional
            if !fp.ovmf_sections.is_empty() {
                None
            } else {
                panic!(
                    "No ovmf_path in fingerprints and OVMF_PATH env var not set. \
                            Either add ovmf_path to the JSON or set OVMF_PATH."
                )
            }
        });

        let cfg = SevSnpMeasureConfig {
            ovmf_path: effective_ovmf_path,
            guest_features: fp.guest_features,
        };

        // ---- convert sections --------------------------------------------
        let sections: Vec<OvmfSectionParam> = fp
            .ovmf_sections
            .iter()
            .map(|s| OvmfSectionParam {
                gpa: s.gpa,
                size: s.size,
                section_type: s.section_type,
            })
            .collect();

        // ---- compute -----------------------------------------------------
        let measurement = compute_expected_measurement(
            &cfg,
            &fp.ovmf_hash,
            fp.sev_hashes_table_gpa,
            fp.sev_es_reset_eip,
            &sections,
            &fp.kernel_hash,
            &fp.initrd_hash,
            fp.vcpus,
            &fp.vcpu_type,
            &compose_hash,
            &rootfs_hash,
            docker_files_hash.as_deref(),
        )
        .expect("compute_expected_measurement failed");

        println!("--- result ---");
        println!("MEASUREMENT = {}", hex::encode(measurement));
        println!();
        println!("Compare with `snpguest display report att-report.bin` → Measurement field");
    }
}
