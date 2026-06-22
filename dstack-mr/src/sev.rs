// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP launch-measurement recomputation and `os_image_hash` derivation.
//!
//! This is the single source of truth shared by `dstack-kms` (key release) and
//! `dstack-verifier` (attestation verification). It recomputes the expected SNP
//! launch `MEASUREMENT` from self-contained launch inputs (the
//! `sev_snp_measurement` document a VMM embeds in `vm_config`) and derives the
//! image-invariant `os_image_hash`.
//!
//! It deals only in primitive, hardware-verified values (`measurement`,
//! `host_data`) so it can stay free of attestation/RA-TLS types and be reused by
//! both the KMS and the verifier without a dependency cycle. Verifying the report
//! signature/collateral is the caller's job; this module recomputes the launch
//! measurement and checks it against the already-verified one.

use anyhow::{bail, Context, Result};
use dstack_types::mr_config::MrConfigV3;
use sha2::{Digest, Sha256, Sha384};
use std::fs;
use std::path::Path;

const LD_BYTES: usize = 48;
const ZEROS_LD: [u8; LD_BYTES] = [0u8; LD_BYTES];
/// Maximum number of vCPUs accepted in a measurement input.
pub const MAX_VCPUS: u32 = 512;
/// Maximum number of OVMF metadata sections accepted in a measurement input.
pub const MAX_OVMF_SECTIONS: usize = 64;
/// 64 GiB worth of 4 KiB pages — upper bound on measured OVMF metadata pages.
pub const MAX_OVMF_METADATA_PAGES: u64 = 16_777_216;
// VMSA page GPA: (u64)(-1) page-aligned, bits >51 cleared.
const VMSA_GPA: u64 = 0x0000_FFFF_FFFF_F000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct OvmfSectionParam {
    pub gpa: u64,
    pub size: u64,
    /// Raw OVMF SEV metadata section type:
    /// 1=SNP_SEC_MEMORY, 2=SNP_SECRETS, 3=CPUID, 4=SVSM_CAA,
    /// 0x10=SNP_KERNEL_HASHES.
    pub section_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementInput {
    /// Original image kernel cmdline used for SNP measured launch.
    pub base_cmdline: Option<String>,
    /// 48-byte OVMF GCTX launch digest seed supplied by the VMM.
    pub ovmf_hash: String,
    /// 32-byte kernel SHA-256 hash.
    pub kernel_hash: String,
    /// 32-byte initrd SHA-256 hash. An empty string is treated as the SHA-256 of
    /// an empty initrd, matching QEMU/sev-snp-measure behavior.
    pub initrd_hash: String,
    /// GPA of the SevHashTable, from OVMF footer metadata.
    pub sev_hashes_table_gpa: u64,
    /// AP reset EIP, from OVMF footer metadata.
    pub sev_es_reset_eip: u32,
    pub vcpus: u32,
    pub vcpu_type: Option<String>,
    /// SNP guest features bitmask used at launch. QEMU uses 0x1 for SNP with
    /// kernel hashes enabled in the current VMM path.
    pub guest_features: u64,
    #[serde(deserialize_with = "deserialize_ovmf_sections_bounded")]
    pub ovmf_sections: Vec<OvmfSectionParam>,
}

fn deserialize_ovmf_sections_bounded<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<OvmfSectionParam>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedOvmfSections;

    impl<'de> serde::de::Visitor<'de> for BoundedOvmfSections {
        type Value = Vec<OvmfSectionParam>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_OVMF_SECTIONS} OVMF metadata sections"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<OvmfSectionParam>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut sections =
                Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_OVMF_SECTIONS));
            while let Some(section) = seq.next_element()? {
                if sections.len() >= MAX_OVMF_SECTIONS {
                    return Err(serde::de::Error::custom(format!(
                        "ovmf section count must not exceed {MAX_OVMF_SECTIONS}"
                    )));
                }
                sections.push(section);
            }
            Ok(sections)
        }
    }

    deserializer.deserialize_seq(BoundedOvmfSections)
}

/// Validate a `MeasurementInput` for shape/bounds before recomputation.
pub fn validate_measurement_input(input: &MeasurementInput) -> Result<()> {
    if input.guest_features == 0 {
        bail!("guest_features must be non-zero");
    }

    rootfs_hash_from_cmdline(input.base_cmdline.as_deref())?;
    decode_required_hex("kernel_hash", &input.kernel_hash, 32)?;
    decode_optional_hex("initrd_hash", &input.initrd_hash, 32)?;
    if input.vcpus == 0 {
        bail!("vcpus must be greater than zero");
    }
    if input.vcpus > MAX_VCPUS {
        bail!("vcpus must not exceed {MAX_VCPUS}");
    }
    match input.vcpu_type.as_deref() {
        Some(vcpu_type) if !vcpu_type.trim().is_empty() => {
            vcpu_sig_from_type(vcpu_type)?;
        }
        _ => bail!("vcpu_type is required"),
    }

    if input.ovmf_sections.is_empty() {
        bail!("ovmf_sections are required for amd sev-snp");
    }

    decode_required_hex("ovmf_hash", &input.ovmf_hash, 48)?;
    if input.ovmf_sections.len() > MAX_OVMF_SECTIONS {
        bail!("ovmf section count must not exceed {MAX_OVMF_SECTIONS}");
    }
    if input.sev_hashes_table_gpa == 0 {
        bail!("sev_hashes_table_gpa must be non-zero");
    }
    if input.sev_es_reset_eip == 0 {
        bail!("sev_es_reset_eip must be non-zero");
    }

    let mut has_kernel_hashes_section = false;
    let mut measured_pages = 0u64;
    for section in &input.ovmf_sections {
        if section.size == 0 {
            bail!("ovmf section size must be greater than zero");
        }
        let pages = section.size.div_ceil(4096);
        measured_pages = measured_pages
            .checked_add(pages)
            .ok_or_else(|| anyhow::anyhow!("ovmf metadata page count overflow"))?;
        if measured_pages > MAX_OVMF_METADATA_PAGES {
            bail!("ovmf metadata page count must not exceed {MAX_OVMF_METADATA_PAGES}");
        }
        let section_type = SectionType::from_u32(section.section_type).ok_or_else(|| {
            anyhow::anyhow!("unknown ovmf section_type {:#x}", section.section_type)
        })?;
        has_kernel_hashes_section |= section_type == SectionType::SnpKernelHashes;
    }
    if !has_kernel_hashes_section {
        bail!("ovmf metadata does not include a snp_kernel_hashes section");
    }

    Ok(())
}

pub fn decode_required_hex(name: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    decode_optional_hex(name, value, expected_len)
}

pub fn decode_optional_hex(name: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be valid hex"))?;
    if bytes.len() != expected_len {
        bail!("{name} must be {expected_len} bytes");
    }
    Ok(bytes)
}

struct Gctx {
    ld: [u8; LD_BYTES],
}

impl Gctx {
    fn new() -> Self {
        Self { ld: ZEROS_LD }
    }

    fn from_ovmf_hash(hex_value: &str) -> Result<Self> {
        let raw = hex::decode(hex_value).context("ovmf_hash must be valid hex")?;
        let ld: [u8; LD_BYTES] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("ovmf_hash must be 48 bytes"))?;
        Ok(Self { ld })
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

fn sev_entry(guid: &[u8; 16], hash: &[u8; 32]) -> [u8; 50] {
    let mut entry = [0u8; 50];
    entry[..16].copy_from_slice(guid);
    entry[16..18].copy_from_slice(&50u16.to_le_bytes());
    entry[18..].copy_from_slice(hash);
    entry
}

fn build_sev_hashes_page(
    kernel_hash_hex: &str,
    initrd_hash_hex: &str,
    append: &str,
    page_offset: usize,
) -> Result<[u8; 4096]> {
    let kernel_hash: [u8; 32] = hex::decode(kernel_hash_hex)
        .context("kernel_hash must be valid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("kernel_hash must be 32 bytes"))?;

    let initrd_hash: [u8; 32] = if initrd_hash_hex.is_empty() {
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha256::digest(b""));
        h
    } else {
        hex::decode(initrd_hash_hex)
            .context("initrd_hash must be valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("initrd_hash must be 32 bytes"))?
    };

    let mut cmdline_bytes = append.as_bytes().to_vec();
    cmdline_bytes.push(0);
    let mut cmdline_hash = [0u8; 32];
    cmdline_hash.copy_from_slice(&Sha256::digest(&cmdline_bytes));

    let cmdline_entry = sev_entry(&GUID_LE_CMDLINE_ENTRY, &cmdline_hash);
    let initrd_entry = sev_entry(&GUID_LE_INITRD_ENTRY, &initrd_hash);
    let kernel_entry = sev_entry(&GUID_LE_KERNEL_ENTRY, &kernel_hash);

    const TABLE_SIZE: usize = 16 + 2 + 50 + 50 + 50;
    let mut table = [0u8; TABLE_SIZE];
    table[..16].copy_from_slice(&GUID_LE_HASH_TABLE_HEADER);
    table[16..18].copy_from_slice(&(TABLE_SIZE as u16).to_le_bytes());
    table[18..68].copy_from_slice(&cmdline_entry);
    table[68..118].copy_from_slice(&initrd_entry);
    table[118..168].copy_from_slice(&kernel_entry);

    const PADDED: usize = (TABLE_SIZE + 15) & !(15usize);
    if page_offset + PADDED > 4096 {
        bail!("sev hash table overflows 4096-byte page");
    }
    let mut page = [0u8; 4096];
    page[page_offset..page_offset + TABLE_SIZE].copy_from_slice(&table);
    Ok(page)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    SnpSecMemory = 1,
    SnpSecrets = 2,
    Cpuid = 3,
    SvsmCaa = 4,
    SnpKernelHashes = 0x10,
}

impl SectionType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::SnpSecMemory),
            2 => Some(Self::SnpSecrets),
            3 => Some(Self::Cpuid),
            4 => Some(Self::SvsmCaa),
            0x10 => Some(Self::SnpKernelHashes),
            _ => None,
        }
    }
}

pub struct MetadataSection {
    pub gpa: u64,
    pub size: u64,
    pub section_type: SectionType,
}

pub struct OvmfInfo {
    pub data: Vec<u8>,
    pub gpa: u64,
    pub sections: Vec<MetadataSection>,
    pub sev_hashes_table_gpa: u64,
    pub sev_es_reset_eip: u32,
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

const FOUR_GIB: u64 = 0x1_0000_0000;
const OVMF_RESET_VECTOR_TAIL_SIZE: usize = 32;
const OVMF_FOOTER_ENTRY_SIZE: usize = 18; // u16 size + GUID
const SEV_META_HEADER_SIZE: usize = 16;
const SEV_META_SECTION_SIZE: usize = 12;

struct OvmfFooter {
    sev_hashes_table_gpa: u64,
    sev_es_reset_eip: u32,
    metadata_offset_from_end: usize,
}

struct OvmfFooterEntry<'a> {
    guid: &'a [u8],
    data: &'a [u8],
}

fn checked_slice<'a>(buf: &'a [u8], off: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("{what} offset overflow"))?;
    buf.get(off..end)
        .ok_or_else(|| anyhow::anyhow!("{what} out of bounds"))
}

fn read_u16_le_at(buf: &[u8], off: usize, what: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        checked_slice(buf, off, 2, what)?.try_into().unwrap(),
    ))
}

fn read_u32_le_at(buf: &[u8], off: usize, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        checked_slice(buf, off, 4, what)?.try_into().unwrap(),
    ))
}

fn ovmf_gpa(size: usize) -> Result<u64> {
    FOUR_GIB
        .checked_sub(u64::try_from(size).context("ovmf binary size does not fit in u64")?)
        .context("ovmf binary is larger than 4 gib")
}

fn ovmf_footer_table_bytes(data: &[u8]) -> Result<&[u8]> {
    let footer_off = data
        .len()
        .checked_sub(OVMF_RESET_VECTOR_TAIL_SIZE + OVMF_FOOTER_ENTRY_SIZE)
        .context("ovmf binary too small to contain footer table")?;
    let footer = checked_slice(data, footer_off, OVMF_FOOTER_ENTRY_SIZE, "ovmf footer")?;
    if footer[2..] != GUID_FOOTER_TABLE {
        bail!("ovmf footer guid not found");
    }

    let footer_total_size = read_u16_le_at(data, footer_off, "ovmf footer size")? as usize;
    if footer_total_size < OVMF_FOOTER_ENTRY_SIZE {
        bail!("ovmf footer table has invalid total size");
    }

    let table_size = footer_total_size - OVMF_FOOTER_ENTRY_SIZE;
    let table_start = footer_off
        .checked_sub(table_size)
        .context("ovmf footer table is out of bounds")?;
    checked_slice(data, table_start, table_size, "ovmf footer table")
}

fn ovmf_footer_entries(table: &[u8]) -> Result<Vec<OvmfFooterEntry<'_>>> {
    let mut entries = Vec::new();
    let mut end = table.len();
    while end >= OVMF_FOOTER_ENTRY_SIZE {
        let header_off = end - OVMF_FOOTER_ENTRY_SIZE;
        let entry_size = read_u16_le_at(table, header_off, "ovmf footer entry size")? as usize;
        if entry_size < OVMF_FOOTER_ENTRY_SIZE || entry_size > end {
            bail!("ovmf footer table has invalid entry size");
        }

        let data_start = end - entry_size;
        entries.push(OvmfFooterEntry {
            guid: checked_slice(table, header_off + 2, 16, "ovmf footer entry guid")?,
            data: checked_slice(
                table,
                data_start,
                entry_size - OVMF_FOOTER_ENTRY_SIZE,
                "ovmf footer entry data",
            )?,
        });
        end = data_start;
    }
    Ok(entries)
}

fn parse_ovmf_footer(data: &[u8]) -> Result<OvmfFooter> {
    let mut sev_hashes_table_gpa = None;
    let mut sev_es_reset_eip = None;
    let mut metadata_offset_from_end = None;

    for entry in ovmf_footer_entries(ovmf_footer_table_bytes(data)?)? {
        if entry.data.len() < 4 {
            continue;
        }
        if entry.guid == GUID_SEV_HASH_TABLE_RV {
            sev_hashes_table_gpa =
                Some(read_u32_le_at(entry.data, 0, "ovmf sev hash table entry")? as u64);
        } else if entry.guid == GUID_SEV_ES_RESET_BLK {
            sev_es_reset_eip = Some(read_u32_le_at(entry.data, 0, "ovmf sev-es reset entry")?);
        } else if entry.guid == GUID_SEV_META_DATA {
            metadata_offset_from_end =
                Some(read_u32_le_at(entry.data, 0, "ovmf sev metadata entry")? as usize);
        }
    }

    let sev_hashes_table_gpa =
        sev_hashes_table_gpa.context("ovmf sev hash table entry not found in footer table")?;
    if sev_hashes_table_gpa == 0 {
        bail!("ovmf sev hash table entry is zero");
    }

    let sev_es_reset_eip =
        sev_es_reset_eip.context("ovmf sev_es_reset_block entry not found in footer table")?;
    if sev_es_reset_eip == 0 {
        bail!("ovmf sev_es_reset_block entry is zero");
    }

    let metadata_offset_from_end =
        metadata_offset_from_end.context("ovmf sev metadata entry not found in footer table")?;
    Ok(OvmfFooter {
        sev_hashes_table_gpa,
        sev_es_reset_eip,
        metadata_offset_from_end,
    })
}

fn parse_ovmf_metadata_sections(
    data: &[u8],
    offset_from_end: usize,
) -> Result<Vec<MetadataSection>> {
    let meta_start = data
        .len()
        .checked_sub(offset_from_end)
        .context("ovmf sev metadata offset exceeds file size")?;
    let header = checked_slice(
        data,
        meta_start,
        SEV_META_HEADER_SIZE,
        "ovmf sev metadata header",
    )?;
    if &header[..4] != b"ASEV" {
        bail!("ovmf sev metadata has bad signature");
    }
    let meta_version = read_u32_le_at(header, 8, "ovmf sev metadata version")?;
    if meta_version != 1 {
        bail!("ovmf sev metadata has unsupported version {meta_version}");
    }

    let num_items = read_u32_le_at(header, 12, "ovmf sev metadata item count")? as usize;
    let sections_size = num_items
        .checked_mul(SEV_META_SECTION_SIZE)
        .context("ovmf sev metadata sections size overflow")?;
    let sections_start = meta_start
        .checked_add(SEV_META_HEADER_SIZE)
        .context("ovmf sev metadata sections offset overflow")?;
    let section_bytes = checked_slice(
        data,
        sections_start,
        sections_size,
        "ovmf sev metadata sections",
    )?;

    section_bytes
        .chunks_exact(SEV_META_SECTION_SIZE)
        .map(|section| {
            let section_type_value = read_u32_le_at(section, 8, "ovmf section_type")?;
            let section_type = SectionType::from_u32(section_type_value).ok_or_else(|| {
                anyhow::anyhow!("unknown ovmf section_type {section_type_value:#x}")
            })?;
            Ok(MetadataSection {
                gpa: read_u32_le_at(section, 0, "ovmf section gpa")? as u64,
                size: read_u32_le_at(section, 4, "ovmf section size")? as u64,
                section_type,
            })
        })
        .collect()
}

impl OvmfInfo {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read(path)
            .with_context(|| format!("cannot read ovmf binary '{}'", path.display()))?;
        Self::parse(data)
    }

    fn parse(data: Vec<u8>) -> Result<Self> {
        let footer = parse_ovmf_footer(&data)?;
        Ok(Self {
            gpa: ovmf_gpa(data.len())?,
            sections: parse_ovmf_metadata_sections(&data, footer.metadata_offset_from_end)?,
            sev_hashes_table_gpa: footer.sev_hashes_table_gpa,
            sev_es_reset_eip: footer.sev_es_reset_eip,
            data,
        })
    }
}

fn write_u16_le_at(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le_at(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le_at(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_vmcb_seg(buf: &mut [u8], off: usize, selector: u16, attrib: u16, limit: u32, base: u64) {
    write_u16_le_at(buf, off, selector);
    write_u16_le_at(buf, off + 2, attrib);
    write_u32_le_at(buf, off + 4, limit);
    write_u64_le_at(buf, off + 8, base);
}

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

fn vcpu_sig_from_type(vcpu_type: &str) -> Result<u32> {
    match vcpu_type.trim().to_lowercase().as_str() {
        "epyc" | "epyc-v1" | "epyc-v2" | "epyc-ibpb" | "epyc-v3" | "epyc-v4" => {
            Ok(amd_cpu_sig(23, 1, 2))
        }
        "epyc-rome" | "epyc-rome-v1" | "epyc-rome-v2" | "epyc-rome-v3" => {
            Ok(amd_cpu_sig(23, 49, 0))
        }
        "epyc-milan" | "epyc-milan-v1" | "epyc-milan-v2" => Ok(amd_cpu_sig(25, 1, 1)),
        "epyc-genoa" | "epyc-genoa-v1" => Ok(amd_cpu_sig(25, 17, 0)),
        other => bail!("unknown vcpu_type {other:?}"),
    }
}

fn build_vmsa_page(eip: u32, vcpu_sig: u32, sev_features: u64) -> Box<[u8; 4096]> {
    let mut page = Box::new([0u8; 4096]);
    let p = page.as_mut_slice();

    let cs_base = (eip as u64) & 0xffff_0000;
    let rip = (eip as u64) & 0x0000_ffff;

    write_vmcb_seg(p, 0x000, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x010, 0xf000, 0x009b, 0xffff, cs_base);
    write_vmcb_seg(p, 0x020, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x030, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x040, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x050, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x060, 0, 0x0000, 0xffff, 0);
    write_vmcb_seg(p, 0x070, 0, 0x0082, 0xffff, 0);
    write_vmcb_seg(p, 0x080, 0, 0x0000, 0xffff, 0);
    write_vmcb_seg(p, 0x090, 0, 0x008b, 0xffff, 0);

    write_u64_le_at(p, 0x0D0, 0x1000);
    write_u64_le_at(p, 0x148, 0x40);
    write_u64_le_at(p, 0x158, 0x10);
    write_u64_le_at(p, 0x160, 0x400);
    write_u64_le_at(p, 0x168, 0xffff_0ff0);
    write_u64_le_at(p, 0x170, 0x2);
    write_u64_le_at(p, 0x178, rip);
    write_u64_le_at(p, 0x268, 0x0007_0406_0007_0406);
    write_u64_le_at(p, 0x310, vcpu_sig as u64);
    write_u64_le_at(p, 0x3B0, sev_features);
    write_u64_le_at(p, 0x3E8, 0x1);
    write_u32_le_at(p, 0x408, 0x1f80);
    write_u16_le_at(p, 0x410, 0x037f);

    page
}

/// Recompute the AMD SEV-SNP launch `MEASUREMENT` from self-contained inputs.
pub fn compute_expected_measurement(input: &MeasurementInput) -> Result<[u8; 48]> {
    let vcpu_type = input
        .vcpu_type
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("vcpu_type is required"))?;

    let cmdline = match input.base_cmdline.as_deref() {
        Some(base) if !base.trim().is_empty() => base.trim().to_string(),
        _ => "console=ttyS0 loglevel=7".to_string(),
    };
    let resolved_sections = input
        .ovmf_sections
        .iter()
        .map(|section| {
            let section_type = SectionType::from_u32(section.section_type).ok_or_else(|| {
                anyhow::anyhow!("unknown ovmf section_type {:#x}", section.section_type)
            })?;
            Ok(MetadataSection {
                gpa: section.gpa,
                size: section.size,
                section_type,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut gctx = Gctx::from_ovmf_hash(&input.ovmf_hash)?;
    let effective_hashes_gpa = input.sev_hashes_table_gpa;
    let effective_reset_eip = input.sev_es_reset_eip;

    let mut has_kernel_hashes_section = false;
    for section in &resolved_sections {
        let gpa = section.gpa;
        let size = usize::try_from(section.size)
            .map_err(|_| anyhow::anyhow!("ovmf section size is too large"))?;
        match section.section_type {
            SectionType::SnpSecMemory => gctx.update_zero_pages(gpa, size),
            SectionType::SnpSecrets => gctx.update_secrets_page(gpa),
            SectionType::Cpuid => gctx.update_cpuid_page(gpa),
            SectionType::SvsmCaa => gctx.update_zero_pages(gpa, size),
            SectionType::SnpKernelHashes => {
                has_kernel_hashes_section = true;
                if effective_hashes_gpa == 0 {
                    bail!("snp_kernel_hashes section present but sev_hashes_table_gpa is 0");
                }
                let page_offset = (effective_hashes_gpa & 0xfff) as usize;
                let page = build_sev_hashes_page(
                    &input.kernel_hash,
                    &input.initrd_hash,
                    &cmdline,
                    page_offset,
                )?;
                gctx.update_normal_pages(gpa, &page);
            }
        }
    }
    if !has_kernel_hashes_section {
        bail!("ovmf metadata does not include a snp_kernel_hashes section");
    }

    let vcpu_sig = vcpu_sig_from_type(vcpu_type)?;
    let bsp_vmsa = build_vmsa_page(0xffff_fff0, vcpu_sig, input.guest_features);
    let ap_vmsa = build_vmsa_page(effective_reset_eip, vcpu_sig, input.guest_features);

    for i in 0..input.vcpus as usize {
        let vmsa_page = if i == 0 {
            bsp_vmsa.as_ref()
        } else {
            ap_vmsa.as_ref()
        };
        gctx.update_vmsa_page(vmsa_page);
    }

    Ok(gctx.ld)
}

/// Project a verified `MeasurementInput` to the shared image-invariant
/// measurement (excludes per-deployment fields like vcpus).
fn sev_os_image_measurement(
    input: &MeasurementInput,
) -> Result<dstack_types::SevOsImageMeasurement> {
    Ok(dstack_types::SevOsImageMeasurement {
        rootfs_hash: rootfs_hash_from_cmdline(input.base_cmdline.as_deref())?,
        base_cmdline: input.base_cmdline.clone(),
        ovmf_hash: input.ovmf_hash.clone(),
        kernel_hash: input.kernel_hash.clone(),
        initrd_hash: input.initrd_hash.clone(),
        sev_hashes_table_gpa: input.sev_hashes_table_gpa,
        sev_es_reset_eip: input.sev_es_reset_eip,
        ovmf_sections: input
            .ovmf_sections
            .iter()
            .map(|s| dstack_types::OvmfSection {
                gpa: s.gpa,
                size: s.size,
                section_type: s.section_type,
            })
            .collect(),
    })
}

/// Derive the OS image hash from a self-contained SNP measurement document.
///
/// os_image_hash identifies the OS image only, so it covers exactly the
/// image-determined measurement inputs and EXCLUDES per-deployment values
/// (`vcpus`, `vcpu_type`, `guest_features`). Hashing the full
/// `MeasurementInput` made the same image hash differently per vCPU count,
/// which broke per-image on-chain allow-listing. App/config identity is bound
/// separately by MrConfigV3/HOST_DATA. The canonical hashing lives in
/// `dstack_types::SevOsImageMeasurement` so the image build can reproduce the
/// same value as `digest.sev.txt`.
pub fn snp_measurement_os_image_hash(measurement_document: &str) -> Result<Vec<u8>> {
    let input: MeasurementInput = serde_json::from_str(measurement_document)
        .context("failed to parse sev-snp measurement document for os_image_hash")?;
    Ok(sev_os_image_measurement(&input)?.os_image_hash().to_vec())
}

/// OVMF launch-measurement metadata: the GCTX launch digest of the firmware
/// bytes plus the SEV footer fields needed to recompute the launch measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvmfMeasurementInfo {
    /// 48-byte GCTX launch digest (hex) after measuring the OVMF binary bytes.
    pub ovmf_hash: String,
    pub sev_hashes_table_gpa: u64,
    pub sev_es_reset_eip: u32,
    pub sections: Vec<OvmfSectionParam>,
}

/// Parse an OVMF (SEV firmware) binary and compute its launch-measurement
/// metadata: the GCTX digest over the firmware bytes plus the SEV footer fields.
pub fn ovmf_measurement_info(path: &Path) -> Result<OvmfMeasurementInfo> {
    let ovmf = OvmfInfo::load(path)?;
    let mut gctx = Gctx::new();
    gctx.update_normal_pages(ovmf.gpa, &ovmf.data);
    Ok(OvmfMeasurementInfo {
        ovmf_hash: hex::encode(gctx.ld),
        sev_hashes_table_gpa: ovmf.sev_hashes_table_gpa,
        sev_es_reset_eip: ovmf.sev_es_reset_eip,
        sections: ovmf
            .sections
            .into_iter()
            .map(|s| OvmfSectionParam {
                gpa: s.gpa,
                size: s.size,
                section_type: s.section_type as u32,
            })
            .collect(),
    })
}

/// The subset of an image's `metadata.json` needed to compute the SEV
/// os_image_hash. Kept local (rather than depending on the VMM `ImageInfo`) so
/// `dstack-mr` stays self-contained.
#[derive(Debug, serde::Deserialize)]
struct ImageMetadata {
    #[serde(default)]
    cmdline: Option<String>,
    kernel: String,
    initrd: String,
    #[serde(default)]
    bios: Option<String>,
    #[serde(default, rename = "bios-sev")]
    bios_sev: Option<String>,
}

fn file_sha256_hex(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(data)))
}

pub fn rootfs_hash_from_cmdline(cmdline: Option<&str>) -> Result<String> {
    let rootfs_hash = cmdline
        .unwrap_or_default()
        .split_whitespace()
        .find_map(|param| param.strip_prefix("dstack.rootfs_hash="))
        .map(ToString::to_string)
        .context("dstack.rootfs_hash is required in amd sev-snp measured cmdline")?;
    Ok(hex::encode(decode_required_hex(
        "dstack.rootfs_hash",
        &rootfs_hash,
        32,
    )?))
}

/// Compute the AMD SEV-SNP `os_image_hash` from an OS image directory containing
/// `metadata.json` plus the SEV firmware, kernel and initrd.
///
/// This is the canonical producer of `digest.sev.txt`. The value equals the
/// `os_image_hash` the KMS and verifier derive from a hardware-verified launch
/// measurement, because both go through [`snp_measurement_os_image_hash`] /
/// `dstack_types::SevOsImageMeasurement`.
pub fn sev_os_image_hash_for_image_dir(image_dir: &Path) -> Result<[u8; 32]> {
    let meta_path = image_dir.join("metadata.json");
    let meta_str = fs::read_to_string(&meta_path)
        .with_context(|| format!("cannot read {}", meta_path.display()))?;
    let meta: ImageMetadata =
        serde_json::from_str(&meta_str).context("failed to parse image metadata.json")?;

    // Measure the firmware the guest actually launches with: prefer the SEV
    // firmware (bios-sev), fall back to the generic bios.
    let bios = meta
        .bios_sev
        .as_deref()
        .or(meta.bios.as_deref())
        .context("bios-sev/bios is required for amd sev-snp os_image_hash")?;
    let ovmf = ovmf_measurement_info(&image_dir.join(bios))?;

    let measurement = dstack_types::SevOsImageMeasurement {
        rootfs_hash: rootfs_hash_from_cmdline(meta.cmdline.as_deref())?,
        base_cmdline: meta.cmdline.as_deref().map(|c| c.trim().to_string()),
        ovmf_hash: ovmf.ovmf_hash,
        kernel_hash: file_sha256_hex(&image_dir.join(&meta.kernel))?,
        initrd_hash: file_sha256_hex(&image_dir.join(&meta.initrd))?,
        sev_hashes_table_gpa: ovmf.sev_hashes_table_gpa,
        sev_es_reset_eip: ovmf.sev_es_reset_eip,
        ovmf_sections: ovmf
            .sections
            .into_iter()
            .map(|s| dstack_types::OvmfSection {
                gpa: s.gpa,
                size: s.size,
                section_type: s.section_type,
            })
            .collect(),
    };
    Ok(measurement.os_image_hash())
}

/// `sha256(MEASUREMENT || HOST_DATA)` — the SNP aggregated identity digest.
pub fn snp_mr_aggregated_digest(measurement: &[u8; 48], host_data: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(measurement);
    h.update(host_data);
    h.finalize().to_vec()
}

/// Validate the shape of an MrConfigV3 document carried by HOST_DATA.
pub fn validate_mr_config(mr_config: &MrConfigV3) -> Result<()> {
    if mr_config.version != 3 {
        bail!("mr_config version must be 3");
    }
    ensure_len("mr_config.app_id", &mr_config.app_id, 20)?;
    ensure_len("mr_config.compose_hash", &mr_config.compose_hash, 32)?;
    if !mr_config.instance_id.is_empty() {
        ensure_len("mr_config.instance_id", &mr_config.instance_id, 20)?;
    }
    Ok(())
}

fn ensure_len(name: &str, value: &[u8], expected_len: usize) -> Result<()> {
    if value.len() != expected_len {
        bail!("{name} must be {expected_len} bytes");
    }
    Ok(())
}

/// Check that the hardware-verified `HOST_DATA` equals the hash of the supplied
/// MrConfigV3 document, binding app/config identity to the report.
pub fn validate_snp_mr_config_binding(
    host_data: &[u8; 32],
    mr_config_document: &str,
) -> Result<MrConfigV3> {
    let mr_config = MrConfigV3::from_document(mr_config_document)
        .context("invalid amd sev-snp mr_config document")?;
    let expected = MrConfigV3::snp_host_data_from_document(mr_config_document);
    if expected != *host_data {
        bail!("amd sev-snp host_data mismatch");
    }
    validate_mr_config(&mr_config)?;
    Ok(mr_config)
}

#[derive(Debug, serde::Deserialize)]
struct SevSnpMeasurementVmConfig {
    sev_snp_measurement: Option<String>,
    mr_config: Option<String>,
}

/// Launch inputs extracted from a VMM-produced `vm_config` string.
pub struct SnpLaunchInputs {
    pub input: MeasurementInput,
    /// Raw `sev_snp_measurement` document used for os_image_hash derivation.
    pub measurement_document: String,
    /// Raw MrConfigV3 document bound by HOST_DATA.
    pub mr_config_document: String,
}

/// Parse the SNP launch-measurement inputs (`sev_snp_measurement`) and the
/// `mr_config` document out of a VMM `vm_config` JSON string.
///
/// The fields are intentionally explicit so missing SNP launch inputs fail
/// closed instead of falling back to TDX event-log decoding. Both the top-level
/// shape and the legacy nested `vm_config` string shape are accepted.
pub fn parse_snp_inputs_from_vm_config(vm_config: &str) -> Result<SnpLaunchInputs> {
    let value: serde_json::Value =
        serde_json::from_str(vm_config).context("failed to parse vm_config for amd sev-snp")?;
    let parsed: SevSnpMeasurementVmConfig = serde_json::from_value(value.clone())
        .context("failed to parse vm_config for amd sev-snp")?;
    let nested = value
        .get("vm_config")
        .and_then(|value| value.as_str())
        .map(|vm_config| {
            serde_json::from_str::<SevSnpMeasurementVmConfig>(vm_config)
                .context("failed to parse nested vm_config for amd sev-snp")
        })
        .transpose()?;
    let measurement_document = parsed
        .sev_snp_measurement
        .or_else(|| {
            nested
                .as_ref()
                .and_then(|nested| nested.sev_snp_measurement.clone())
        })
        .ok_or_else(|| anyhow::anyhow!("sev_snp_measurement is required for amd sev-snp"))?;
    let input: MeasurementInput = serde_json::from_str(&measurement_document)
        .context("invalid amd sev-snp measurement document")?;
    let mr_config_document = parsed
        .mr_config
        .or_else(|| nested.and_then(|nested| nested.mr_config))
        .ok_or_else(|| anyhow::anyhow!("mr_config is required for amd sev-snp"))?;
    MrConfigV3::from_document(&mr_config_document)
        .context("invalid amd sev-snp mr_config document")?;
    Ok(SnpLaunchInputs {
        input,
        measurement_document,
        mr_config_document,
    })
}

/// The verified SNP image binding produced by [`verify_sev_launch`].
#[derive(Debug, Clone)]
pub struct SevImageBinding {
    /// Image-invariant os_image_hash derived from the (now measurement-bound)
    /// launch inputs.
    pub os_image_hash: Vec<u8>,
    /// App/config identity bound by HOST_DATA.
    pub mr_config: MrConfigV3,
}

/// End-to-end SNP launch verification against an already hardware-verified
/// report.
///
/// Given the verified `MEASUREMENT` and `HOST_DATA` from a report whose
/// signature/collateral have already been checked, this:
///   1. parses `sev_snp_measurement` + `mr_config` from `vm_config`,
///   2. recomputes the launch measurement and checks it equals `measurement`
///      (this is what makes the otherwise-untrusted launch inputs trustworthy),
///   3. checks `HOST_DATA` binds the `mr_config` document, and
///   4. derives the image-invariant `os_image_hash`.
pub fn verify_sev_launch(
    verified_measurement: &[u8; 48],
    verified_host_data: &[u8; 32],
    vm_config: &str,
) -> Result<SevImageBinding> {
    let inputs = parse_snp_inputs_from_vm_config(vm_config)?;
    validate_measurement_input(&inputs.input)?;
    let expected = compute_expected_measurement(&inputs.input)?;
    if &expected != verified_measurement {
        bail!("amd sev-snp measurement mismatch");
    }
    let mr_config = validate_snp_mr_config_binding(verified_host_data, &inputs.mr_config_document)?;
    let os_image_hash = snp_measurement_os_image_hash(&inputs.measurement_document)?;
    Ok(SevImageBinding {
        os_image_hash,
        mr_config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_input() -> MeasurementInput {
        let rootfs_hash = hex_of(0x33, 32);
        MeasurementInput {
            base_cmdline: Some(format!("console=ttyS0 dstack.rootfs_hash={rootfs_hash}")),
            ovmf_hash: hex_of(0x44, 48),
            kernel_hash: hex_of(0x55, 32),
            initrd_hash: hex_of(0x66, 32),
            sev_hashes_table_gpa: 0x80_1000,
            sev_es_reset_eip: 0xffff_fff0,
            vcpus: 2,
            vcpu_type: Some("epyc-v4".to_string()),
            guest_features: 1,
            ovmf_sections: vec![
                OvmfSectionParam {
                    gpa: 0x100000,
                    size: 0x2000,
                    section_type: 1,
                },
                OvmfSectionParam {
                    gpa: 0x80_0000,
                    size: 0x1000,
                    section_type: 0x10,
                },
                OvmfSectionParam {
                    gpa: 0x81_0000,
                    size: 0x1000,
                    section_type: 2,
                },
                OvmfSectionParam {
                    gpa: 0x82_0000,
                    size: 0x1000,
                    section_type: 3,
                },
            ],
        }
    }

    fn measurement_document(input: &MeasurementInput) -> String {
        serde_json::to_string(input).expect("measurement input should serialize")
    }

    #[test]
    fn measurement_input_does_not_carry_standalone_rootfs_hash() {
        let value = serde_json::to_value(valid_input()).expect("serialize measurement input");
        assert!(value.get("rootfs_hash").is_none());
        serde_json::from_value::<MeasurementInput>(value).expect("measurement input parses");
    }

    #[test]
    fn measurement_document_rejects_standalone_rootfs_hash() {
        let mut value = serde_json::to_value(valid_input()).expect("serialize measurement input");
        value["rootfs_hash"] = serde_json::Value::String(hex_of(0x34, 32));
        let err = serde_json::from_value::<MeasurementInput>(value)
            .expect_err("standalone rootfs_hash must reject");
        assert!(
            err.to_string().contains("unknown field `rootfs_hash`"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn snp_os_image_hash_covers_image_fields_only() {
        let input = valid_input();
        let os_image_hash =
            |i: &MeasurementInput| snp_measurement_os_image_hash(&measurement_document(i)).unwrap();
        let baseline = os_image_hash(&input);

        // Image-determined fields MUST change the os_image_hash.
        let image_cases: Vec<(&str, fn(&mut MeasurementInput))> = vec![
            ("base_cmdline.rootfs_hash", |i| {
                i.base_cmdline = Some(format!(
                    "console=ttyS0 dstack.rootfs_hash={}",
                    hex_of(0x34, 32)
                ))
            }),
            ("base_cmdline", |i| {
                i.base_cmdline = Some(format!(
                    "console=ttyS0 loglevel=8 dstack.rootfs_hash={}",
                    hex_of(0x33, 32)
                ))
            }),
            ("ovmf_hash", |i| i.ovmf_hash = hex_of(0x45, 48)),
            ("kernel_hash", |i| i.kernel_hash = hex_of(0x56, 32)),
            ("initrd_hash", |i| i.initrd_hash = hex_of(0x67, 32)),
            ("sev_hashes_table_gpa", |i| i.sev_hashes_table_gpa += 0x1000),
            ("sev_es_reset_eip", |i| i.sev_es_reset_eip = 0xffff_0000),
            ("ovmf_sections.gpa", |i| i.ovmf_sections[0].gpa += 0x1000),
            ("ovmf_sections.size", |i| i.ovmf_sections[0].size += 0x1000),
            ("ovmf_sections.section_type", |i| {
                i.ovmf_sections[0].section_type = 4
            }),
        ];
        for (name, mutate) in image_cases {
            let mut changed = input.clone();
            mutate(&mut changed);
            assert_ne!(
                baseline,
                os_image_hash(&changed),
                "{name} must change the SNP os_image_hash"
            );
        }

        // Per-deployment fields MUST NOT change the os_image_hash (the same OS
        // image must hash identically regardless of vCPU count, CPU model, etc.).
        let deployment_cases: Vec<(&str, fn(&mut MeasurementInput))> = vec![
            ("vcpus", |i| i.vcpus = 3),
            ("vcpu_type", |i| {
                i.vcpu_type = Some("epyc-milan".to_string())
            }),
            ("guest_features", |i| i.guest_features = 3),
        ];
        for (name, mutate) in deployment_cases {
            let mut changed = input.clone();
            mutate(&mut changed);
            assert_eq!(
                baseline,
                os_image_hash(&changed),
                "{name} must NOT change the SNP os_image_hash"
            );
        }
    }

    #[test]
    fn gctx_update_is_deterministic_and_order_sensitive() {
        let contents = Gctx::sha384(b"page");
        let mut first = Gctx::new();
        first.update(0x01, 0x1000, &contents);
        assert_eq!(
            hex::encode(first.ld),
            "3ebc1a70acc0bae5ae2788fae29a0371f983b19a68faf9843064f36040f58571ce5bb6bcdc9c361087073f8cffd92635"
        );

        let mut second = Gctx::new();
        second.update(0x01, 0x2000, &contents);
        assert_ne!(first.ld, second.ld);
    }

    #[test]
    fn builds_sev_hashes_page_at_requested_offset() {
        let page = build_sev_hashes_page(&hex_of(0x55, 32), "", "console=ttyS0", 0x80)
            .expect("sev hashes page should build");
        assert_eq!(&page[..0x80], &[0u8; 0x80]);
        assert_eq!(&page[0x80..0x90], &GUID_LE_HASH_TABLE_HEADER);
        assert_eq!(u16::from_le_bytes([page[0x90], page[0x91]]), 168);
        assert_eq!(
            &page[0x92..0xa2],
            &GUID_LE_CMDLINE_ENTRY,
            "cmdline entry must be first"
        );
        let empty_hash = Sha256::digest(b"");
        assert_eq!(&page[0x80 + 68 + 18..0x80 + 68 + 50], empty_hash.as_slice());
    }

    #[test]
    fn vcpu_type_mapping_is_strict() {
        assert_eq!(
            vcpu_sig_from_type("EPYC-v4").unwrap(),
            amd_cpu_sig(23, 1, 2)
        );
        assert_eq!(
            vcpu_sig_from_type("epyc-genoa-v1").unwrap(),
            amd_cpu_sig(25, 17, 0)
        );
        let err = vcpu_sig_from_type("not-a-cpu").expect_err("unknown vcpu should reject");
        assert!(err.to_string().contains("unknown vcpu_type"));
    }

    #[test]
    fn measurement_vector_does_not_drift() {
        let input = valid_input();
        let expected = compute_expected_measurement(&input).unwrap();
        assert_eq!(
            hex::encode(expected),
            "88b48404819692fd2a5068f1a07bf1973bbcaa1314adc670705f9388762a759faf889f8e2c71fe1ec892554415257960",
            "synthetic measurement vector should not drift silently"
        );
    }

    /// Real `sev_snp_measurement` document captured from a live dstack SEV-SNP
    /// CVM (the same fixture used by `dstack-attest/tests/sev_snp_verify.rs`).
    const REAL_MEASUREMENT_DOC: &str = r#"{"base_cmdline":"console=ttyS0 init=/init panic=1 net.ifnames=0 biosdevname=0 mce=off oops=panic pci=noearly pci=nommconf random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock dstack.rootfs_hash=ca5adaef0ac3a36108035925763b48a5818f634e700fbaab561d419fd30d7121 dstack.rootfs_size=490713088","ovmf_hash":"ffb57e393469a497c0e3b07bd1c97d8611e555f464d14491837665893ac642b263a71f9507ff100a847897fe0c3f8c6f","kernel_hash":"dd9ea274ce9a07090b22e8284b0c841b65c021c2d15ca57d0f16731089dd226c","initrd_hash":"5f844c4a2ca5a3d0711b3db38293b21ba929bb8e0b3c5bc1a779a57f69221c19","sev_hashes_table_gpa":8457216,"sev_es_reset_eip":8433668,"vcpus":2,"vcpu_type":"EPYC-v4","guest_features":1,"ovmf_sections":[{"gpa":8388608,"size":36864,"section_type":1},{"gpa":8429568,"size":12288,"section_type":1},{"gpa":8441856,"size":4096,"section_type":2},{"gpa":8445952,"size":4096,"section_type":3},{"gpa":8450048,"size":4096,"section_type":4},{"gpa":8458240,"size":61440,"section_type":1},{"gpa":8454144,"size":4096,"section_type":16}]}"#;

    #[test]
    fn real_fixture_recomputes_measurement_and_os_image_hash() {
        let input: MeasurementInput =
            serde_json::from_str(REAL_MEASUREMENT_DOC).expect("real measurement doc parses");
        validate_measurement_input(&input).expect("real measurement input is valid");

        // Recomputed launch measurement must equal the hardware-signed value
        // from the captured report (see sev_snp_fixture.README.md).
        let measurement = compute_expected_measurement(&input).expect("recompute measurement");
        assert_eq!(
            hex::encode(measurement),
            "7f51e17f72a04d5422cb2c00998166536019a217376f3aa45a630e59c805a599847ff250dbffcd07e1ba639771d6f05d",
        );

        // os_image_hash derived from the same document must match the value the
        // CVM advertised in its vm_config (and digest.sev.txt).
        let os_image_hash =
            snp_measurement_os_image_hash(REAL_MEASUREMENT_DOC).expect("derive os_image_hash");
        assert_eq!(
            hex::encode(os_image_hash),
            "32b4767373ad7fa0f9c418925006194d5c3f5619529f309fe81156789fecd8bc",
        );
    }

    // ---- Forged-quote / tampered-input coverage for `verify_sev_launch` ----
    //
    // These build a self-consistent (launch-inputs, mr_config, MEASUREMENT,
    // HOST_DATA) tuple, then forge one piece at a time and require rejection. The
    // hardware report's MEASUREMENT/HOST_DATA are simulated by the values we pass
    // as "verified"; on real hardware they come from the signed report, so an
    // attacker cannot change them to match forged inputs.

    fn synthetic_mr_config() -> MrConfigV3 {
        MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            dstack_types::KeyProviderKind::None,
            Vec::new(),
            vec![0x33; 20],
        )
    }

    fn synthetic_vm_config(input: &MeasurementInput, mr_config: &MrConfigV3) -> String {
        serde_json::json!({
            "sev_snp_measurement": serde_json::to_string(input).expect("serialize input"),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string()
    }

    /// Returns `(input, mr_config, verified_measurement, verified_host_data, vm_config)`
    /// for an honest, internally-consistent SNP launch.
    fn honest_case() -> (MeasurementInput, MrConfigV3, [u8; 48], [u8; 32], String) {
        let input = valid_input();
        let mr_config = synthetic_mr_config();
        let host_data = MrConfigV3::snp_host_data_from_document(&mr_config.to_canonical_json());
        let measurement = compute_expected_measurement(&input).expect("measurement");
        let vm_config = synthetic_vm_config(&input, &mr_config);
        (input, mr_config, measurement, host_data, vm_config)
    }

    #[test]
    fn verify_sev_launch_accepts_consistent_inputs() {
        let (input, mr_config, measurement, host_data, vm_config) = honest_case();
        let binding = verify_sev_launch(&measurement, &host_data, &vm_config)
            .expect("honest launch verifies");
        assert_eq!(
            binding.os_image_hash,
            snp_measurement_os_image_hash(&serde_json::to_string(&input).unwrap()).unwrap()
        );
        assert_eq!(binding.mr_config.app_id, mr_config.app_id);
    }

    #[test]
    fn verify_sev_launch_rejects_forged_measurement() {
        let (_input, _mr, measurement, host_data, vm_config) = honest_case();
        let mut forged = measurement;
        forged[0] ^= 0xff;
        let err = verify_sev_launch(&forged, &host_data, &vm_config)
            .expect_err("forged hardware measurement must reject");
        assert!(
            err.to_string().contains("amd sev-snp measurement mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verify_sev_launch_rejects_forged_host_data() {
        let (_input, _mr, measurement, host_data, vm_config) = honest_case();
        let mut forged = host_data;
        forged[0] ^= 0xff;
        let err = verify_sev_launch(&measurement, &forged, &vm_config)
            .expect_err("forged hardware host_data must reject");
        assert!(
            err.to_string().contains("amd sev-snp host_data mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verify_sev_launch_rejects_tampered_measured_inputs() {
        // Fields that feed the launch MEASUREMENT: tampering the advertised
        // inputs while keeping the honest hardware MEASUREMENT is caught by the
        // measurement-equality check, so the (would-be different) os_image_hash
        // never gets a chance to be trusted.
        let (input, mr_config, measurement, host_data, _vm_config) = honest_case();
        let cases: Vec<(&str, fn(&mut MeasurementInput))> = vec![
            ("base_cmdline", |i| {
                i.base_cmdline = Some(format!(
                    "console=ttyS0 evil=1 dstack.rootfs_hash={}",
                    hex_of(0x33, 32)
                ))
            }),
            ("ovmf_hash", |i| i.ovmf_hash = hex_of(0x99, 48)),
            ("kernel_hash", |i| i.kernel_hash = hex_of(0x99, 32)),
            ("initrd_hash", |i| i.initrd_hash = hex_of(0x99, 32)),
            // Only the in-page offset (& 0xfff) of the hash table is measured, so
            // tamper the low bits to actually move the measured table position.
            ("sev_hashes_table_gpa", |i| i.sev_hashes_table_gpa += 0x40),
            ("sev_es_reset_eip", |i| i.sev_es_reset_eip = 0xffff_0000),
            ("ovmf_sections.gpa", |i| i.ovmf_sections[0].gpa += 0x1000),
            ("vcpus", |i| i.vcpus = 4),
            ("vcpu_type", |i| {
                i.vcpu_type = Some("epyc-milan".to_string())
            }),
            ("guest_features", |i| i.guest_features = 3),
        ];
        for (name, mutate) in cases {
            let mut tampered = input.clone();
            mutate(&mut tampered);
            let vm_config = synthetic_vm_config(&tampered, &mr_config);
            let err = match verify_sev_launch(&measurement, &host_data, &vm_config) {
                Ok(binding) => panic!(
                    "{name} tampering was accepted; derived os_image_hash {}",
                    hex::encode(binding.os_image_hash)
                ),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains("amd sev-snp measurement mismatch"),
                "{name}: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn tampering_cmdline_rootfs_hash_rejects_launch() {
        // rootfs identity comes from the measured kernel cmdline. Tampering it
        // changes both the SNP MEASUREMENT and the derived os_image_hash.
        let (input, mr_config, measurement, host_data, vm_config) = honest_case();
        let honest = verify_sev_launch(&measurement, &host_data, &vm_config)
            .expect("honest launch verifies");

        let mut tampered = input.clone();
        tampered.base_cmdline = Some(format!(
            "console=ttyS0 dstack.rootfs_hash={}",
            hex_of(0x99, 32)
        ));
        let tampered_vm = synthetic_vm_config(&tampered, &mr_config);
        let err = verify_sev_launch(&measurement, &host_data, &tampered_vm)
            .expect_err("tampered rootfs hash in cmdline must not verify");
        assert!(
            err.to_string().contains("amd sev-snp measurement mismatch"),
            "unexpected error: {err:?}"
        );
        let tampered_hash =
            snp_measurement_os_image_hash(&serde_json::to_string(&tampered).unwrap()).unwrap();
        assert_ne!(
            honest.os_image_hash, tampered_hash,
            "a tampered rootfs hash must change the derived os_image_hash"
        );
    }

    #[test]
    fn verify_sev_launch_rejects_tampered_mr_config() {
        // Changing app/compose/instance identity changes the MrConfigV3 document,
        // so the honest HOST_DATA no longer binds it.
        let (input, _mr, measurement, host_data, _vm) = honest_case();
        let evil_mr_configs = [
            MrConfigV3::new(
                vec![0xee; 20],
                vec![0x22; 32],
                dstack_types::KeyProviderKind::None,
                Vec::new(),
                vec![0x33; 20],
            ),
            MrConfigV3::new(
                vec![0x11; 20],
                vec![0xee; 32],
                dstack_types::KeyProviderKind::None,
                Vec::new(),
                vec![0x33; 20],
            ),
            MrConfigV3::new(
                vec![0x11; 20],
                vec![0x22; 32],
                dstack_types::KeyProviderKind::None,
                Vec::new(),
                vec![0xee; 20],
            ),
        ];
        for evil in evil_mr_configs {
            let vm_config = synthetic_vm_config(&input, &evil);
            let err = verify_sev_launch(&measurement, &host_data, &vm_config)
                .expect_err("substituted mr_config must reject");
            assert!(
                err.to_string().contains("amd sev-snp host_data mismatch"),
                "unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn verify_sev_launch_ignores_advertised_os_image_hash() {
        // The os_image_hash is derived from the measurement-bound inputs; a
        // top-level attacker-advertised os_image_hash is ignored entirely.
        let (input, mr_config, measurement, host_data, _vm) = honest_case();
        let bogus = vec![0xde; 32];
        let vm_config = serde_json::json!({
            "os_image_hash": hex::encode(&bogus),
            "sev_snp_measurement": serde_json::to_string(&input).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();
        let binding = verify_sev_launch(&measurement, &host_data, &vm_config)
            .expect("bogus advertised os_image_hash is ignored, not fatal");
        let expected =
            snp_measurement_os_image_hash(&serde_json::to_string(&input).unwrap()).unwrap();
        assert_eq!(binding.os_image_hash, expected);
        assert_ne!(binding.os_image_hash, bogus);
    }

    #[test]
    fn swapping_os_image_changes_hash_and_is_rejected() {
        // An attacker booting a different OS image cannot present an allowed
        // image's inputs: the booted image's MEASUREMENT differs from the
        // advertised inputs' recomputed measurement.
        let honest = valid_input();
        let honest_hash =
            snp_measurement_os_image_hash(&serde_json::to_string(&honest).unwrap()).unwrap();

        let mut malicious = honest.clone();
        malicious.kernel_hash = hex_of(0xab, 32); // different kernel == different image
        let malicious_measurement = compute_expected_measurement(&malicious).unwrap();
        let malicious_hash =
            snp_measurement_os_image_hash(&serde_json::to_string(&malicious).unwrap()).unwrap();
        assert_ne!(
            honest_hash, malicious_hash,
            "different image must hash differently"
        );

        let mr_config = synthetic_mr_config();
        let host_data = MrConfigV3::snp_host_data_from_document(&mr_config.to_canonical_json());
        // Hardware measured the malicious image, but the quote advertises the
        // honest (allowed) inputs.
        let vm_config = synthetic_vm_config(&honest, &mr_config);
        let err = verify_sev_launch(&malicious_measurement, &host_data, &vm_config)
            .expect_err("advertised honest inputs must not pass for a different booted image");
        assert!(
            err.to_string().contains("amd sev-snp measurement mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verify_sev_launch_requires_measurement_and_mr_config() {
        let (input, mr_config, measurement, host_data, _vm) = honest_case();

        let no_measurement =
            serde_json::json!({ "mr_config": mr_config.to_canonical_json() }).to_string();
        let err = verify_sev_launch(&measurement, &host_data, &no_measurement)
            .expect_err("missing sev_snp_measurement must fail closed");
        assert!(
            err.to_string().contains("sev_snp_measurement is required"),
            "unexpected error: {err:?}"
        );

        let no_mr_config =
            serde_json::json!({ "sev_snp_measurement": serde_json::to_string(&input).unwrap() })
                .to_string();
        let err = verify_sev_launch(&measurement, &host_data, &no_mr_config)
            .expect_err("missing mr_config must fail closed");
        assert!(
            err.to_string().contains("mr_config is required"),
            "unexpected error: {err:?}"
        );
    }
}
