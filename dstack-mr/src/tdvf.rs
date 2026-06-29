// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use hex_literal::hex;
use scale::Decode;
use sha2::{Digest, Sha384};

use crate::acpi::Tables;
use crate::num::read_le;
use crate::uefi_var::{
    boot_option_bytes, boot_order_bytes, fv_file_node, fv_node, END_OF_DEVICE_PATH,
};
use crate::{measure_log, measure_sha384, utf16_encode, Machine, OvmfVariant, RtmrLog};

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_GRANULARITY: usize = 0x100;

// OVMF firmware-volume identifiers used by edk2-stable202505. These are baked
// into the OVMF binary at build time; if the firmware is regenerated against a
// different EDK2 source these constants may need refreshing.
//
// Each GUID is stored in the on-the-wire little-endian byte form OVMF puts in
// the EFI_DEVICE_PATH MEDIA_FV / MEDIA_FV_FILE nodes — the first three GUID
// fields are byte-swapped relative to the canonical string form.
//
// canonical: 7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1
const OVMF_FV_GUID_LE: [u8; 16] = [
    0xc9, 0xbd, 0xb8, 0x7c, 0xeb, 0xf8, 0x34, 0x4f, 0xaa, 0xea, 0x3e, 0xe4, 0xaf, 0x65, 0x16, 0xa1,
];
// canonical: eec25bdc-67f2-4d95-b1d5-f81b2039d11d  (MdeModulePkg UiApp)
const OVMF_UIAPP_FILE_GUID_LE: [u8; 16] = [
    0xdc, 0x5b, 0xc2, 0xee, 0xf2, 0x67, 0x95, 0x4d, 0xb1, 0xd5, 0xf8, 0x1b, 0x20, 0x39, 0xd1, 0x1d,
];
// canonical: 462caa21-7614-4503-836e-8ab6f4662331  (MdeModulePkg BootMaintenance / FrontPage)
const OVMF_FRONTPAGE_FILE_GUID_LE: [u8; 16] = [
    0x21, 0xaa, 0x2c, 0x46, 0x14, 0x76, 0x03, 0x45, 0x83, 0x6e, 0x8a, 0xb6, 0xf4, 0x66, 0x23, 0x31,
];

const ATTRIBUTE_MR_EXTEND: u32 = 0x00000001;
const ATTRIBUTE_PAGE_AUG: u32 = 0x00000002;

const TDVF_SECTION_TD_HOB: u32 = 0x02;
const TDVF_SECTION_TEMP_MEM: u32 = 0x03;

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
        OvmfVariant::Stable202505 => {
            // edk2-stable202505 emits 17 RTMR[0] events instead of 13.
            // Everything except the three QEMU-generated ACPI blob digests is
            // derivable from dstack's launch policy and the shipped OVMF build.

            // fw_cfg `BootMenu` is a u16; dstack doesn't pass `-boot
            // menu=on`, so it defaults to 0x0000.
            let bootmenu_fwcfg_hash = measure_sha384(&[0x00, 0x00]);

            // fw_cfg `bootorder` is the NUL-separated list of QEMU device
            // paths whose backing devices have `bootindex` set. For
            // `-kernel` boot, QEMU (hw/i386/x86.c::x86_load_linux) injects
            // a single option ROM with `bootindex = 0`:
            //   * `linuxboot_dma.bin`  if fw_cfg DMA is enabled (q35 default)
            //   * `linuxboot.bin`      otherwise
            // dstack-vmm always uses q35 → DMA is on → the bootorder file
            // contains just the single path below (31 bytes, trailing NUL).
            // No other dstack device gets an implicit bootindex.
            //
            // Verified end-to-end: gdb-attached the live QEMU and called
            // get_boot_devices_list() — returned exactly these 31 bytes.
            let bootorder_fwcfg_hash = measure_sha384(b"/rom@genroms/linuxboot_dma.bin\0");

            // EV_EFI_VARIABLE_AUTHORITY: OVMF emits this once during BDS even
            // when Secure Boot is disabled. The 32-byte event blob in the log is
            // a sentinel; the actual measured payload is OVMF-internal.
            // Captured digest is a constant for the edk2-stable202505 build
            // dstack ships.
            let variable_authority_hash =
                hex!("FB66919801F1DFC9C4C273B6A739380790CB0FD3CB706A42F6AC050510EBC8618E7FBA53A1564522F5C6F0DC9E1F41A6");

            // BootOrder UEFI variable holds [0x0000, 0x0001] — the two boot
            // options OVMF's BDS publishes (UiApp and FrontPage). The TCG digest
            // for `EV_EFI_VARIABLE_BOOT2` is over the raw variable data, NOT a
            // UEFI_VARIABLE_DATA wrapper.
            let boot_order_var_hash = measure_sha384(&boot_order_bytes(&[0x0000, 0x0001]));

            // Boot0000 = OVMF's BootManagerMenuApp; Boot0001 = "EFI Firmware
            // Setup" (FrontPage). Both live in the OVMF FV and are baked into
            // the firmware at build time. The attribute bits and descriptions
            // come from MdeModulePkg's BdsBootManagerLib in edk2-stable202505.
            //   0x101 = LOAD_OPTION_ACTIVE | LOAD_OPTION_CATEGORY_APP
            //   0x109 = + LOAD_OPTION_HIDDEN
            let boot0000_hash = measure_sha384(&boot_option_bytes(
                0x0000_0109,
                "BootManagerMenuApp",
                &[
                    fv_node(&OVMF_FV_GUID_LE),
                    fv_file_node(&OVMF_UIAPP_FILE_GUID_LE),
                    END_OF_DEVICE_PATH,
                ],
                &[],
            ));
            let boot0001_hash = measure_sha384(&boot_option_bytes(
                0x0000_0101,
                "EFI Firmware Setup",
                &[
                    fv_node(&OVMF_FV_GUID_LE),
                    fv_file_node(&OVMF_FRONTPAGE_FILE_GUID_LE),
                    END_OF_DEVICE_PATH,
                ],
                &[],
            ));
            vec![
                td_hob_hash,
                cfv_image_hash.to_vec(),
                bootmenu_fwcfg_hash,
                bootorder_fwcfg_hash.to_vec(),
                secureboot_hash,
                pk_hash,
                kek_hash,
                db_hash,
                dbx_hash,
                separator_hash,
                acpi_hashes.loader.clone(),
                acpi_hashes.rsdp.clone(),
                acpi_hashes.tables.clone(),
                variable_authority_hash.to_vec(),
                boot_order_var_hash,
                boot0000_hash,
                boot0001_hash,
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
            if offset < 18 {
                break;
            }
            let guid = &tables[offset - 16..offset];
            let entry_len = read_le::<u16>(tables, offset - 18, "entry length")? as usize;
            if entry_len > offset.saturating_sub(18) {
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

        let mut meta = Tdvf {
            fw,
            sections: Vec::new(),
        };

        // Decode all sections using scale codec
        for i in 0..num_sections {
            let sec_offset = tdvf_meta_offset + 16 + 32 * i;
            let s = TdvfSection::decode(&mut &fw[sec_offset..])
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

            meta.sections.push(s);
        }

        Ok(meta)
    }

    fn compute_mrtd(&self, variant: PageAddOrder) -> Result<Vec<u8>> {
        let mut h = Sha384::new();

        let mem_page_add = |h: &mut Sha384, s: &TdvfSection, page: u64| {
            if s.attributes & ATTRIBUTE_PAGE_AUG == 0 {
                let mut buf = [0u8; 128];
                buf[..12].copy_from_slice(b"MEM.PAGE.ADD");
                let gpa = s.memory_address + page * PAGE_SIZE;
                buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                h.update(buf);
            }
        };

        let mr_extend = |h: &mut Sha384, s: &TdvfSection, page: u64| {
            if s.attributes & ATTRIBUTE_MR_EXTEND != 0 {
                for i in 0..(PAGE_SIZE as usize / MR_EXTEND_GRANULARITY) {
                    let mut buf = [0u8; 128];
                    buf[..9].copy_from_slice(b"MR.EXTEND");
                    let gpa =
                        s.memory_address + page * PAGE_SIZE + (i * MR_EXTEND_GRANULARITY) as u64;
                    buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                    h.update(buf);

                    let chunk_offset = s.data_offset as usize
                        + (page * PAGE_SIZE) as usize
                        + i * MR_EXTEND_GRANULARITY;
                    h.update(&self.fw[chunk_offset..chunk_offset + MR_EXTEND_GRANULARITY]);
                }
            }
        };

        for s in &self.sections {
            let num_pages = s.memory_data_size / PAGE_SIZE;
            match variant {
                PageAddOrder::TwoPass => {
                    for page in 0..num_pages {
                        mem_page_add(&mut h, s, page);
                    }
                    for page in 0..num_pages {
                        mr_extend(&mut h, s, page);
                    }
                }
                PageAddOrder::SinglePass => {
                    for page in 0..num_pages {
                        mem_page_add(&mut h, s, page);
                        mr_extend(&mut h, s, page);
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
        let (rtmr0_log, _) = self.rtmr0_log(machine)?;
        Ok(measure_log(&rtmr0_log))
    }

    pub fn rtmr0_log(&self, machine: &Machine) -> Result<(RtmrLog, Tables)> {
        let tables = machine.build_tables()?;
        let acpi_hashes = AcpiTableHashes {
            tables: measure_sha384(&tables.tables),
            rsdp: measure_sha384(&tables.rsdp),
            loader: measure_sha384(&tables.loader),
        };
        let log = self.rtmr0_log_with_acpi_hashes(
            machine.memory_size,
            machine.ovmf_variant,
            &acpi_hashes,
        )?;
        Ok((log, tables))
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
                memory_acceptor.accept(s.memory_address, s.memory_address + s.memory_data_size);
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

        let end_of_hob_list = td_hob_base_addr + td_hob.len() as u64 + 8;
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
}
