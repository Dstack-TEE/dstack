// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use hex_literal::hex;
use scale::Decode;
use sha2::{Digest, Sha384};

use crate::num::read_le;
use crate::{measure_log, measure_sha384, utf16_encode, Machine, OvmfVariant, RtmrLog};

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_GRANULARITY: usize = 0x100;

const ATTRIBUTE_MR_EXTEND: u32 = 0x00000001;
const ATTRIBUTE_PAGE_AUG: u32 = 0x00000002;

const TDVF_SECTION_TD_HOB: u32 = 0x02;
const TDVF_SECTION_TEMP_MEM: u32 = 0x03;

/// Largest section count accepted from a firmware image. Real TDVF metadata
/// describes six sections -- BFV, CFV, TD_HOB and three TEMP_MEM ranges -- so
/// this is an order of magnitude of headroom, and it matches the limit the
/// OVMF/SEV metadata parser already applies (`sev::MAX_OVMF_SECTIONS`).
pub(crate) const MAX_TDVF_SECTIONS: usize = 64;

/// Size of each `TdvfSection` record in the section table.
const TDVF_SECTION_SIZE: usize = 32;

/// Largest number of guest pages the whole section table may ask to be
/// measured. Real TDVF metadata measures 0x41a000 bytes across its six
/// sections -- 1050 pages, 4.10 MiB -- so 256 MiB of pages is about sixty
/// times the headroom any firmware needs. Without it a page-aligned
/// `memory_data_size` of 0x1000_0000_0000 is 2^36 SHA-384 updates, with
/// nothing between the file and the hash loop to stop it.
const MAX_MEASURED_PAGES: u64 = 0x1_0000;

pub enum PageAddOrder {
    TwoPass,
    SinglePass,
}

#[derive(Debug, Clone)]
pub(crate) struct AcpiTableHashes {
    pub loader: Vec<u8>,
    pub rsdp: Vec<u8>,
    pub tables: Vec<u8>,
}

pub(crate) fn rtmr0_log_from_td_hob_hash_with_acpi_hashes(
    td_hob_hash: Vec<u8>,
    ovmf_variant: OvmfVariant,
    acpi_hashes: &AcpiTableHashes,
) -> Result<RtmrLog> {
    let cfv_image_hash = hex!("344BC51C980BA621AAA00DA3ED7436F7D6E549197DFE699515DFA2C6583D95E6412AF21C097D473155875FFD561D6790");

    let secureboot_hash =
        measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "SecureBoot")?;
    let pk_hash = measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "PK")?;
    let kek_hash = measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "KEK")?;
    let db_hash = measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "db")?;
    let dbx_hash = measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbx")?;
    let separator_hash = measure_sha384(&[0x00, 0x00, 0x00, 0x00]);

    let log = match ovmf_variant {
        OvmfVariant::Pre202505 => {
            // Boot0000 = OVMF UiApp (fixed digest for pre-202505 firmware).
            let boot000_hash = hex!("23ADA07F5261F12F34A0BD8E46760962D6B4D576A416F1FEA1C64BC656B1D28EACF7047AE6E967C58FD2A98BFA74C298");
            vec![
                td_hob_hash,
                cfv_image_hash.to_vec(),
                secureboot_hash,
                pk_hash,
                kek_hash,
                db_hash,
                dbx_hash,
                separator_hash,
                acpi_hashes.loader.clone(),
                acpi_hashes.rsdp.clone(),
                acpi_hashes.tables.clone(),
                measure_sha384(&[0x00, 0x00]), // BootOrder (raw 2 bytes in legacy OVMF)
                boot000_hash.to_vec(),
            ]
        }
    };

    Ok(log)
}

/// Helper to decode little-endian integers from byte slice using scale codec
fn decode_le<T: Decode>(data: &[u8], context: &str) -> Result<T> {
    T::decode(&mut &data[..])
        .with_context(|| format!("failed to decode {} as little-endian", context))
}

#[derive(Debug, Decode)]
struct TdvfSection {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    sec_type: u32,
    attributes: u32,
}

#[derive(Debug, Decode)]
struct TdvfDescriptor {
    signature: [u8; 4], // "TDVF"
    _length: u32,
    version: u32,
    num_sections: u32,
}

#[derive(Debug)]
pub(crate) struct Tdvf<'a> {
    fw: &'a [u8],
    sections: Vec<TdvfSection>,
}

/// Encodes a GUID string into its binary representation.
fn encode_guid(guid_str: &str) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(16);
    let atoms: Vec<&str> = guid_str.split('-').collect();

    if atoms.len() != 5 {
        return Err(anyhow!("Invalid GUID format"));
    }

    for (idx, atom) in atoms.iter().enumerate() {
        let raw = hex::decode(atom).context("Failed to decode hex in GUID")?;

        if idx <= 2 {
            // Little-endian: reverse the bytes
            for i in (0..raw.len()).rev() {
                data.push(raw[i]);
            }
        } else {
            // Big-endian: keep as-is
            data.extend_from_slice(&raw);
        }
    }

    Ok(data)
}

/// Measures an EFI variable event.
fn measure_tdx_efi_variable(vendor_guid: &str, var_name: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    data.extend_from_slice(&encode_guid(vendor_guid)?);
    data.extend_from_slice(&(var_name.len() as u64).to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend(utf16_encode(var_name));
    Ok(measure_sha384(&data))
}

impl<'a> Tdvf<'a> {
    /// Parse TDVF firmware metadata
    ///
    /// This function uses scale codec for clean, panic-free parsing.
    /// Correctness is verified by integration test in tests/tdvf_parse.rs
    /// which ensures identical measurements to the original implementation.
    pub fn parse(fw: &'a [u8]) -> Result<Tdvf<'a>> {
        const TDX_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
        const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
        const BYTES_AFTER_TABLE_FOOTER: usize = 32;

        if fw.len() < BYTES_AFTER_TABLE_FOOTER {
            bail!("TDVF firmware too small");
        }
        let offset = fw.len() - BYTES_AFTER_TABLE_FOOTER;
        let encoded_footer_guid = encode_guid(TABLE_FOOTER_GUID)?;
        if offset < 16 {
            bail!("TDVF firmware offset too small for GUID");
        }
        let guid = &fw[offset - 16..offset];

        if guid != encoded_footer_guid {
            bail!("Failed to parse TDVF metadata: Invalid footer GUID");
        }

        if offset < 18 {
            bail!("TDVF firmware offset too small for tables length");
        }
        let tables_len = decode_le::<u16>(&fw[offset - 18..offset - 16], "tables length")? as usize;
        if tables_len == 0 || tables_len > offset.saturating_sub(18) {
            bail!("Failed to parse TDVF metadata: Invalid tables length");
        }
        let table_start = offset.saturating_sub(18).saturating_sub(tables_len);
        let tables = &fw[table_start..offset - 18];
        let mut offset = tables.len();

        let mut data: Option<&[u8]> = None;
        let encoded_guid = encode_guid(TDX_METADATA_OFFSET_GUID)?;
        loop {
            // `tables` starts 18 bytes before the real table, which is exactly
            // the footer entry the walk has already consumed, so an offset of
            // 18 means every entry has been visited. Reading one more "entry"
            // there would interpret whatever precedes the table as a length.
            if offset <= 18 {
                break;
            }
            let guid = &tables[offset - 16..offset];
            let entry_len = read_le::<u16>(tables, offset - 18, "entry length")? as usize;
            // An entry's length covers its own 18-byte length+GUID header, so
            // anything shorter is malformed -- and a zero-length entry leaves
            // `offset` where it is, walking the table forever. The OVMF/SEV
            // footer walk rejects the same shape in `ovmf_footer_entries`.
            if entry_len < 18 || entry_len > offset.saturating_sub(18) {
                bail!("Failed to parse TDVF metadata: Invalid entry length");
            }
            if guid == encoded_guid {
                let entry_start = offset.saturating_sub(18).saturating_sub(entry_len);
                data = Some(&tables[entry_start..offset - 18]);
                break;
            }
            offset = offset.saturating_sub(entry_len);
        }

        let data = data.context("Failed to parse TDVF metadata: Missing TDVF metadata")?;

        if data.len() < 4 {
            bail!("TDVF metadata data too small");
        }
        let tdvf_meta_offset_raw =
            decode_le::<u32>(&data[data.len() - 4..], "TDVF metadata offset")? as usize;
        if tdvf_meta_offset_raw > fw.len() {
            bail!("TDVF metadata offset exceeds firmware size");
        }
        let tdvf_meta_offset = fw.len() - tdvf_meta_offset_raw;

        // Decode TDVF descriptor using scale codec
        let descriptor = TdvfDescriptor::decode(&mut &fw[tdvf_meta_offset..])
            .context("failed to decode TDVF descriptor")?;

        if &descriptor.signature != b"TDVF" {
            bail!("Failed to parse TDVF metadata: Invalid TDVF descriptor");
        }
        if descriptor.version != 1 {
            bail!("Failed to parse TDVF metadata: Unsupported TDVF version");
        }
        let num_sections = descriptor.num_sections as usize;
        if num_sections > MAX_TDVF_SECTIONS {
            bail!("TDVF metadata declares {num_sections} sections, more than the {MAX_TDVF_SECTIONS} supported");
        }

        let mut meta = Tdvf {
            fw,
            sections: Vec::new(),
        };

        // Decode all sections using scale codec
        let mut total_pages = 0u64;
        for i in 0..num_sections {
            // `num_sections` is a raw `u32` from the file, so the table it
            // describes need not be inside the image. Slice with `get` rather
            // than indexing: release builds abort on panic, so an out-of-range
            // start would take down the whole measuring process instead of
            // failing this one image.
            let sec_offset = tdvf_meta_offset + 16 + TDVF_SECTION_SIZE * i;
            let record = fw
                .get(sec_offset..sec_offset + TDVF_SECTION_SIZE)
                .with_context(|| {
                    format!(
                        "TDVF section {i} at offset {sec_offset} is outside the {}-byte firmware",
                        fw.len()
                    )
                })?;
            let s = TdvfSection::decode(&mut &record[..])
                .with_context(|| format!("failed to decode TDVF section {}", i))?;

            if s.memory_address % PAGE_SIZE != 0 {
                bail!("Failed to parse TDVF metadata: Section memory address not aligned");
            }
            if s.memory_data_size < s.raw_data_size as u64 {
                bail!("Failed to parse TDVF metadata: Section memory data size less than raw");
            }
            if s.memory_data_size % PAGE_SIZE != 0 {
                bail!("Failed to parse TDVF metadata: Section memory data size not aligned");
            }
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0
                && s.raw_data_size as u64 > s.memory_data_size
            {
                bail!("Failed to parse TDVF metadata: Section raw data size less than memory");
            }
            // MR.EXTEND hashes one page of firmware bytes per measured page,
            // so it reads `memory_data_size` bytes from `data_offset` -- not
            // `raw_data_size`. Nothing above ties either to the image, and the
            // read is what panics, so check the declared range here, before
            // any of it is measured.
            let measured_size = if s.attributes & ATTRIBUTE_MR_EXTEND != 0 {
                s.memory_data_size
            } else {
                s.raw_data_size as u64
            };
            let data_end = (s.data_offset as u64)
                .checked_add(measured_size)
                .with_context(|| format!("TDVF section {i} data range overflows"))?;
            if data_end > fw.len() as u64 {
                bail!(
                    "TDVF section {i} data range {}..{data_end} is outside the {}-byte firmware",
                    s.data_offset,
                    fw.len()
                );
            }
            // The guest address of a measured page is `memory_address + page *
            // PAGE_SIZE`, and both halves come from the file. In a release
            // build that addition wraps silently and measures the wrong
            // addresses; in a debug build it panics.
            if s.memory_address.checked_add(s.memory_data_size).is_none() {
                bail!(
                    "TDVF section {i} guest address range wraps past the end of the address space"
                );
            }
            // `memory_data_size` alone decides how many pages get hashed, so
            // an unconstrained one is an unbounded amount of work.
            total_pages = total_pages
                .checked_add(s.memory_data_size / PAGE_SIZE)
                .with_context(|| format!("TDVF section {i} page count overflows"))?;
            if total_pages > MAX_MEASURED_PAGES {
                bail!("TDVF metadata asks to measure {total_pages} pages, more than the {MAX_MEASURED_PAGES} supported");
            }

            meta.sections.push(s);
        }

        Ok(meta)
    }

    fn compute_mrtd(&self, variant: PageAddOrder) -> Result<Vec<u8>> {
        let mut h = Sha384::new();

        let mem_page_add = |h: &mut Sha384, s: &TdvfSection, page: u64| -> Result<()> {
            if s.attributes & ATTRIBUTE_PAGE_AUG == 0 {
                let mut buf = [0u8; 128];
                buf[..12].copy_from_slice(b"MEM.PAGE.ADD");
                let gpa = page
                    .checked_mul(PAGE_SIZE)
                    .and_then(|offset| s.memory_address.checked_add(offset))
                    .context("TDVF section guest address wraps")?;
                buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                h.update(buf);
            }
            Ok(())
        };

        let mr_extend = |h: &mut Sha384, s: &TdvfSection, page: u64| -> Result<()> {
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0 {
                for i in 0..(PAGE_SIZE as usize / MR_EXTEND_GRANULARITY) {
                    let mut buf = [0u8; 128];
                    buf[..9].copy_from_slice(b"MR.EXTEND");
                    let gpa = page
                        .checked_mul(PAGE_SIZE)
                        .and_then(|offset| offset.checked_add((i * MR_EXTEND_GRANULARITY) as u64))
                        .and_then(|offset| s.memory_address.checked_add(offset))
                        .context("TDVF section guest address wraps")?;
                    buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                    h.update(buf);

                    let chunk_offset = s.data_offset as usize
                        + (page * PAGE_SIZE) as usize
                        + i * MR_EXTEND_GRANULARITY;
                    let chunk = self
                        .fw
                        .get(chunk_offset..chunk_offset + MR_EXTEND_GRANULARITY)
                        .context("TDVF section data is outside the firmware")?;
                    h.update(chunk);
                }
            }
            Ok(())
        };

        for s in &self.sections {
            let num_pages = s.memory_data_size / PAGE_SIZE;
            match variant {
                PageAddOrder::TwoPass => {
                    for page in 0..num_pages {
                        mem_page_add(&mut h, s, page)?;
                    }
                    for page in 0..num_pages {
                        mr_extend(&mut h, s, page)?;
                    }
                }
                PageAddOrder::SinglePass => {
                    for page in 0..num_pages {
                        mem_page_add(&mut h, s, page)?;
                        mr_extend(&mut h, s, page)?;
                    }
                }
            }
        }
        Ok(h.finalize().to_vec())
    }

    pub(crate) fn mrtd_single_pass(&self) -> Result<Vec<u8>> {
        self.compute_mrtd(PageAddOrder::SinglePass)
    }

    pub(crate) fn mrtd_two_pass(&self) -> Result<Vec<u8>> {
        self.compute_mrtd(PageAddOrder::TwoPass)
    }

    pub fn mrtd(&self, machine: &Machine) -> Result<Vec<u8>> {
        let opts = machine
            .versioned_options()
            .context("Failed to get versioned options")?;
        self.compute_mrtd(if opts.two_pass_add_pages {
            PageAddOrder::TwoPass
        } else {
            PageAddOrder::SinglePass
        })
    }

    /// Build the compact TdHobWitnessV1 byte string for this TDVF.
    ///
    /// The witness contains only the accepted TD HOB/TEMP_MEM ranges needed to
    /// reconstruct the TD HOB for any VM memory size. All addresses/sizes are
    /// represented in 4 KiB pages using unsigned LEB128 varints:
    ///
    ///   varuint base_page
    ///   varuint td_hob_page_delta
    ///   varuint range_count
    ///   repeated range_count:
    ///     varuint start_page_delta
    ///     varuint page_count
    ///
    /// `base_page` is the minimum accepted range start page. Deltas are relative
    /// to it. Ranges are sorted by start page and intentionally not merged; the
    /// TD HOB measurement code emits adjacent accepted ranges as separate HOB
    /// resources when TDVF metadata describes them separately.
    pub(crate) fn td_hob_witness_v1(&self) -> Result<Vec<u8>> {
        fn put_varuint(mut value: u64, out: &mut Vec<u8>) {
            loop {
                let mut byte = (value & 0x7f) as u8;
                value >>= 7;
                if value != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if value == 0 {
                    break;
                }
            }
        }

        let mut ranges = Vec::<(u64, u64)>::new();
        let mut td_hob_page = None;

        for s in &self.sections {
            if matches!(s.sec_type, TDVF_SECTION_TD_HOB | TDVF_SECTION_TEMP_MEM) {
                let start_page = s.memory_address / PAGE_SIZE;
                let page_count = s.memory_data_size / PAGE_SIZE;
                if page_count == 0 {
                    bail!("TD HOB witness range must not be empty");
                }
                ranges.push((start_page, page_count));
            }
            if s.sec_type == TDVF_SECTION_TD_HOB
                && td_hob_page.replace(s.memory_address / PAGE_SIZE).is_some()
            {
                bail!("TDVF metadata contains more than one TD_HOB section");
            }
        }

        if ranges.is_empty() {
            bail!("TDVF metadata has no TD_HOB/TEMP_MEM sections");
        }
        let td_hob_page = td_hob_page.context("TDVF metadata is missing TD_HOB section")?;

        ranges.sort_by_key(|&(start_page, _)| start_page);
        let mut prev_end = None;
        for &(start_page, page_count) in &ranges {
            if let Some(end) = prev_end {
                if start_page < end {
                    bail!("TD HOB witness ranges must not overlap");
                }
            }
            prev_end = Some(start_page + page_count);
        }

        let base_page = ranges[0].0;
        if td_hob_page < base_page {
            bail!("TD_HOB page is below TD HOB witness base page");
        }

        let mut out = Vec::with_capacity(4 + ranges.len() * 2);
        put_varuint(base_page, &mut out);
        put_varuint(td_hob_page - base_page, &mut out);
        put_varuint(ranges.len() as u64, &mut out);
        for (start_page, page_count) in ranges {
            put_varuint(start_page - base_page, &mut out);
            put_varuint(page_count, &mut out);
        }
        Ok(out)
    }

    #[allow(dead_code)]
    pub fn rtmr0(&self, machine: &Machine) -> Result<Vec<u8>> {
        Ok(measure_log(&self.rtmr0_log(machine)?))
    }

    pub fn rtmr0_log(&self, machine: &Machine) -> Result<RtmrLog> {
        let tables = machine.build_tables()?;
        let acpi_hashes = AcpiTableHashes {
            tables: measure_sha384(&tables.tables),
            rsdp: measure_sha384(&tables.rsdp),
            loader: measure_sha384(&tables.loader),
        };
        self.rtmr0_log_with_acpi_hashes(machine.memory_size, machine.ovmf_variant, &acpi_hashes)
    }

    pub(crate) fn rtmr0_log_with_acpi_hashes(
        &self,
        memory_size: u64,
        ovmf_variant: OvmfVariant,
        acpi_hashes: &AcpiTableHashes,
    ) -> Result<RtmrLog> {
        let td_hob_hash = self.measure_td_hob(memory_size)?;
        rtmr0_log_from_td_hob_hash_with_acpi_hashes(td_hob_hash, ovmf_variant, acpi_hashes)
    }

    fn measure_td_hob(&self, memory_size: u64) -> Result<Vec<u8>> {
        let mut memory_acceptor = MemoryAcceptor::new(0, memory_size);
        let mut td_hob = Vec::new();

        let mut td_hob_base_addr = 0x809000u64;
        for s in &self.sections {
            if let TDVF_SECTION_TD_HOB | TDVF_SECTION_TEMP_MEM = s.sec_type {
                let end = s
                    .memory_address
                    .checked_add(s.memory_data_size)
                    .context("TDVF section guest address wraps")?;
                memory_acceptor.accept(s.memory_address, end);
            }
            if s.sec_type == TDVF_SECTION_TD_HOB {
                td_hob_base_addr = s.memory_address;
            }
        }

        td_hob.extend_from_slice(&[0x01, 0x00]); // HobType
        td_hob.extend_from_slice(&56u16.to_le_bytes()); // HobLength
        td_hob.extend_from_slice(&[0u8; 4]); // Reserved
        td_hob.extend_from_slice(&9u32.to_le_bytes()); // Version
        td_hob.extend_from_slice(&[0u8; 4]); // BootMode
        td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryTop
        td_hob.extend_from_slice(&[0u8; 8]); // EfiMemoryBottom
        td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryTop
        td_hob.extend_from_slice(&[0u8; 8]); // EfiFreeMemoryBottom
        td_hob.extend_from_slice(&[0u8; 8]); // EfiEndOfHobList (placeholder)

        let mut add_memory_resource_hob = |resource_type: u8, start: u64, length: u64| {
            td_hob.extend_from_slice(&[0x03, 0x00]); // HobType
            td_hob.extend_from_slice(&48u16.to_le_bytes()); // HobLength
            td_hob.extend_from_slice(&[0u8; 4]); // Reserved
            td_hob.extend_from_slice(&[0u8; 16]); // Owner
            td_hob.extend_from_slice(&resource_type.to_le_bytes());
            td_hob.extend_from_slice(&[0u8; 3]); // Padding for resource type
            td_hob.extend_from_slice(&7u32.to_le_bytes()); // ResourceAttribute
            td_hob.extend_from_slice(&start.to_le_bytes());
            td_hob.extend_from_slice(&length.to_le_bytes());
        };

        let (_, last_start, last_end) = memory_acceptor.ranges.pop().context("No ranges")?;

        for (accepted, start, end) in memory_acceptor.ranges {
            if end < start {
                bail!("Invalid memory range: end < start");
            }
            let size = end - start;
            if accepted {
                add_memory_resource_hob(0x00, start, size);
            } else {
                add_memory_resource_hob(0x07, start, size);
            }
        }

        if last_end < last_start {
            bail!("Invalid last memory range: end < start");
        }
        if memory_size >= 0xB0000000 {
            if last_start < 0x80000000u64 {
                add_memory_resource_hob(0x07, last_start, 0x80000000u64 - last_start);
            }
            if last_end > 0x80000000u64 {
                add_memory_resource_hob(0x07, 0x100000000, last_end - 0x80000000u64);
            }
        } else {
            add_memory_resource_hob(0x07, last_start, last_end - last_start);
        }

        let end_of_hob_list = td_hob_base_addr
            .checked_add(td_hob.len() as u64 + 8)
            .context("TD HOB end-of-list address overflows")?;
        td_hob[48..56].copy_from_slice(&end_of_hob_list.to_le_bytes());

        Ok(measure_sha384(&td_hob))
    }
}

struct MemoryAcceptor {
    ranges: Vec<(bool, u64, u64)>,
}

impl MemoryAcceptor {
    fn new(start: u64, size: u64) -> Self {
        Self {
            ranges: vec![(false, start, start + size)],
        }
    }

    fn accept(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        let mut new_ranges = Vec::new();

        for &(is_accepted, range_start, range_end) in &self.ranges {
            if is_accepted || range_end <= start || range_start >= end {
                new_ranges.push((is_accepted, range_start, range_end));
            } else {
                if range_start < start {
                    new_ranges.push((false, range_start, start));
                }
                if range_end > end {
                    new_ranges.push((false, end, range_end));
                }
            }
        }
        new_ranges.push((true, start, end));
        new_ranges.sort_by_key(|&(_, start, _)| start);
        self.ranges = new_ranges;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn td_hob_witness_v1_encodes_current_dstack_ranges_compactly() -> Result<()> {
        let tdvf = Tdvf {
            fw: &[],
            sections: vec![
                TdvfSection {
                    data_offset: 0,
                    raw_data_size: 0,
                    memory_address: 0x810000,
                    memory_data_size: 0x10000,
                    sec_type: TDVF_SECTION_TEMP_MEM,
                    attributes: 0,
                },
                TdvfSection {
                    data_offset: 0,
                    raw_data_size: 0,
                    memory_address: 0x80b000,
                    memory_data_size: 0x2000,
                    sec_type: TDVF_SECTION_TEMP_MEM,
                    attributes: 0,
                },
                TdvfSection {
                    data_offset: 0,
                    raw_data_size: 0,
                    memory_address: 0x809000,
                    memory_data_size: 0x2000,
                    sec_type: TDVF_SECTION_TD_HOB,
                    attributes: 0,
                },
                TdvfSection {
                    data_offset: 0,
                    raw_data_size: 0,
                    memory_address: 0x800000,
                    memory_data_size: 0x6000,
                    sec_type: TDVF_SECTION_TEMP_MEM,
                    attributes: 0,
                },
            ],
        };

        assert_eq!(
            hex::encode(tdvf.td_hob_witness_v1()?),
            "80100904000609020b021010"
        );
        Ok(())
    }

    const TDX_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
    const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
    const BYTES_AFTER_TABLE_FOOTER: usize = 32;
    const GUID_TABLE_HEADER_SIZE: usize = 18;

    /// Runs `f` on a worker thread so that a parser which never terminates
    /// fails on a deadline instead of hanging the whole test run. The blobs
    /// here are attacker-shaped, and a missing termination guard shows up as a
    /// hang rather than as a wrong answer.
    fn within_deadline<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        use std::sync::mpsc::{channel, RecvTimeoutError};

        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => panic!("{what} did not finish within 5s"),
            Err(RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
        }
    }

    fn parse_within_deadline(fw: Vec<u8>) -> Result<(), String> {
        within_deadline("Tdvf::parse", move || {
            Tdvf::parse(&fw)
                .map(|_| ())
                .map_err(|err| format!("{err:#}"))
        })
    }

    /// Closes `payload` the way a real image does: the GUIDed table, a footer
    /// entry whose size covers the table including itself, and the 32-byte
    /// reset vector.
    fn fw_with_guid_table(payload: &[u8], table: &[u8]) -> Vec<u8> {
        let mut fw = payload.to_vec();
        fw.extend_from_slice(table);
        fw.extend_from_slice(&((table.len() + GUID_TABLE_HEADER_SIZE) as u16).to_le_bytes());
        fw.extend_from_slice(&encode_guid(TABLE_FOOTER_GUID).unwrap());
        fw.extend_from_slice(&[0u8; BYTES_AFTER_TABLE_FOOTER]);
        fw
    }

    /// A real entry size covers its own 18-byte header, so zero is impossible
    /// -- and it never advances the backwards walk over the table.
    #[test]
    fn parse_rejects_a_zero_length_guid_table_entry() {
        let mut table = 0u16.to_le_bytes().to_vec();
        table.extend_from_slice(&[0u8; 16]); // any GUID but the metadata one
        let fw = fw_with_guid_table(&[0u8; 64], &table);

        let err = parse_within_deadline(fw).expect_err("a zero-length entry must be rejected");
        assert!(err.contains("entry length"), "unexpected error: {err}");
    }

    /// A firmware whose table simply has no metadata entry must report that,
    /// not walk off the front of the table.
    #[test]
    fn parse_reports_a_table_without_the_metadata_entry() {
        let mut table = 22u16.to_le_bytes().to_vec();
        table.extend_from_slice(&[0u8; 16]);
        let mut entry = vec![0u8; 4];
        entry.extend_from_slice(&table);
        let fw = fw_with_guid_table(&[0u8; 64], &entry);

        let err =
            parse_within_deadline(fw).expect_err("a table without the entry must be rejected");
        assert!(
            err.contains("Missing TDVF metadata"),
            "unexpected error: {err}"
        );
    }

    fn mrtd_within_deadline(fw: Vec<u8>) -> Result<(), String> {
        within_deadline("Tdvf::parse + mrtd", move || {
            let tdvf = Tdvf::parse(&fw).map_err(|err| format!("{err:#}"))?;
            tdvf.mrtd_two_pass()
                .map(|_| ())
                .map_err(|err| format!("{err:#}"))
        })
    }

    fn section_record(
        data_offset: u32,
        raw_data_size: u32,
        memory_address: u64,
        memory_data_size: u64,
        sec_type: u32,
        attributes: u32,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(TDVF_SECTION_SIZE);
        out.extend_from_slice(&data_offset.to_le_bytes());
        out.extend_from_slice(&raw_data_size.to_le_bytes());
        out.extend_from_slice(&memory_address.to_le_bytes());
        out.extend_from_slice(&memory_data_size.to_le_bytes());
        out.extend_from_slice(&sec_type.to_le_bytes());
        out.extend_from_slice(&attributes.to_le_bytes());
        out
    }

    /// Builds a blob the parser accepts: `payload_len` bytes of section data, a
    /// TDVF descriptor declaring `declared_sections`, the raw `sections`
    /// records, and a GUIDed table pointing back at the descriptor.
    fn tdvf_fw(payload_len: usize, sections: &[u8], declared_sections: u32) -> Vec<u8> {
        let mut payload = vec![0u8; payload_len];
        let meta_offset = payload.len();
        payload.extend_from_slice(b"TDVF");
        payload.extend_from_slice(&(16 + sections.len() as u32).to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes()); // version
        payload.extend_from_slice(&declared_sections.to_le_bytes());
        payload.extend_from_slice(sections);

        let offset_field = payload.len();
        let mut table = vec![0u8; 4]; // the descriptor's offset from the end
        table.extend_from_slice(&((4 + GUID_TABLE_HEADER_SIZE) as u16).to_le_bytes());
        table.extend_from_slice(&encode_guid(TDX_METADATA_OFFSET_GUID).unwrap());

        let mut fw = fw_with_guid_table(&payload, &table);
        let offset_from_end = (fw.len() - meta_offset) as u32;
        fw[offset_field..offset_field + 4].copy_from_slice(&offset_from_end.to_le_bytes());
        fw
    }

    /// `num_sections` is a raw `u32` from the file, so it can claim far more
    /// sections than the blob holds. The records here are all-zero ones, which
    /// pass every per-section check, so nothing but the table limit stops the
    /// walk early.
    #[test]
    fn parse_rejects_more_sections_than_the_blob_holds() {
        let fw = tdvf_fw(0x40, &vec![0u8; TDVF_SECTION_SIZE * 200], u32::MAX);

        let err =
            parse_within_deadline(fw).expect_err("an impossible section count must be rejected");
        assert!(err.contains("sections"), "unexpected error: {err}");
    }

    /// MR.EXTEND hashes `memory_data_size` bytes from `data_offset`, which only
    /// `memory_data_size >= raw_data_size` used to constrain.
    #[test]
    fn parse_rejects_a_section_whose_data_runs_past_the_blob() {
        let section = section_record(0, 0x1000, 0x1000, 0x100000, 0, ATTRIBUTE_MR_EXTEND);
        let fw = tdvf_fw(0x1000, &section, 1);

        let err = mrtd_within_deadline(fw).expect_err("an out-of-range section must be rejected");
        assert!(err.contains("firmware"), "unexpected error: {err}");
    }

    /// `memory_data_size` is a page-aligned `u64` from the file, and it alone
    /// decides how many pages get hashed.
    #[test]
    fn parse_rejects_a_section_larger_than_any_real_firmware_measures() {
        let section = section_record(0, 0, 0x800000, 0x1000_0000_0000, TDVF_SECTION_TEMP_MEM, 0);
        let fw = tdvf_fw(0x40, &section, 1);

        let err = mrtd_within_deadline(fw).expect_err("an oversized section must be rejected");
        assert!(err.contains("pages"), "unexpected error: {err}");
    }

    /// The measured guest address is `memory_address + page * PAGE_SIZE`, and
    /// both halves come from the file.
    #[test]
    fn parse_rejects_a_section_whose_guest_address_wraps() {
        let section = section_record(
            0,
            0,
            0xffff_ffff_ffff_f000,
            0x2000,
            TDVF_SECTION_TEMP_MEM,
            0,
        );
        let fw = tdvf_fw(0x40, &section, 1);

        let err = mrtd_within_deadline(fw).expect_err("a wrapping section must be rejected");
        assert!(err.contains("wraps"), "unexpected error: {err}");
    }
}
