use anyhow::{anyhow, bail, Context, Result};
use hex_literal::hex;
use sha2::{Digest, Sha384};

use crate::num::read_le;
use crate::util::debug_print_log;
use crate::{measure_log, measure_sha384, utf16_encode, Machine};

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_GRANULARITY: usize = 0x100;

const ATTRIBUTE_MR_EXTEND: u32 = 0x00000001;
const ATTRIBUTE_PAGE_AUG: u32 = 0x00000002;

const TDVF_SECTION_TD_HOB: u32 = 0x02;
const TDVF_SECTION_TEMP_MEM: u32 = 0x03;

pub enum PageAddOrder {
    TwoPass,
    SinglePass,
}

#[derive(Debug)]
struct TdvfSection {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    sec_type: u32,
    attributes: u32,
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
    pub fn parse(fw: &'a [u8]) -> Result<Tdvf<'a>> {
        const TDX_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
        const TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
        const BYTES_AFTER_TABLE_FOOTER: usize = 32;

        let offset = fw.len() - BYTES_AFTER_TABLE_FOOTER;
        let encoded_footer_guid = encode_guid(TABLE_FOOTER_GUID)?;
        let guid = &fw[offset - 16..offset];

        if guid != encoded_footer_guid {
            bail!("Failed to parse TDVF metadata: Invalid footer GUID");
        }

        let tables_len =
            u16::from_le_bytes(fw[offset - 18..offset - 16].try_into().unwrap()) as usize;
        if tables_len == 0 || tables_len > offset - 18 {
            bail!("Failed to parse TDVF metadata: Invalid tables length");
        }
        let tables = &fw[offset - 18 - tables_len..offset - 18];
        let mut offset = tables.len();

        let mut data: Option<&[u8]> = None;
        let encoded_guid = encode_guid(TDX_METADATA_OFFSET_GUID)?;
        loop {
            if offset < 18 {
                break;
            }
            let guid = &tables[offset - 16..offset];
            let entry_len = read_le::<u16>(tables, offset - 18, "entry length")? as usize;
            if entry_len > offset - 18 {
                bail!("Failed to parse TDVF metadata: Invalid entry length");
            }
            if guid == encoded_guid {
                data = Some(&tables[offset - 18 - entry_len..offset - 18]);
                break;
            }
            offset -= entry_len;
        }

        let data = data.context("Failed to parse TDVF metadata: Missing TDVF metadata")?;

        let tdvf_meta_offset =
            u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap()) as usize;
        let tdvf_meta_offset = fw.len() - tdvf_meta_offset;
        let tdvf_meta_desc = &fw[tdvf_meta_offset..tdvf_meta_offset + 16];

        if &tdvf_meta_desc[..4] != b"TDVF" {
            bail!("Failed to parse TDVF metadata: Invalid TDVF descriptor");
        }
        let tdvf_version = u32::from_le_bytes(tdvf_meta_desc[8..12].try_into().unwrap());
        if tdvf_version != 1 {
            bail!("Failed to parse TDVF metadata: Unsupported TDVF version");
        }
        let num_sections = u32::from_le_bytes(tdvf_meta_desc[12..16].try_into().unwrap()) as usize;

        let mut meta = Tdvf {
            fw,
            sections: Vec::new(),
        };
        for i in 0..num_sections {
            let sec_offset = tdvf_meta_offset + 16 + 32 * i;
            let sec_data = &fw[sec_offset..sec_offset + 32];
            let s = TdvfSection {
                data_offset: u32::from_le_bytes(sec_data[0..4].try_into().unwrap()),
                raw_data_size: u32::from_le_bytes(sec_data[4..8].try_into().unwrap()),
                memory_address: u64::from_le_bytes(sec_data[8..16].try_into().unwrap()),
                memory_data_size: u64::from_le_bytes(sec_data[16..24].try_into().unwrap()),
                sec_type: u32::from_le_bytes(sec_data[24..28].try_into().unwrap()),
                attributes: u32::from_le_bytes(sec_data[28..32].try_into().unwrap()),
            };

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

    pub fn mrtd(&self, machine: &Machine) -> Result<Vec<u8>> {
        self.compute_mrtd(if machine.two_pass_add_pages {
            PageAddOrder::TwoPass
        } else {
            PageAddOrder::SinglePass
        })
    }

    pub fn rtmr0(&self, machine: &Machine) -> Result<Vec<u8>> {
        let td_hob_hash = self.measure_td_hob(machine.memory_size)?;
        let cfv_image_hash = hex!("344BC51C980BA621AAA00DA3ED7436F7D6E549197DFE699515DFA2C6583D95E6412AF21C097D473155875FFD561D6790");
        let boot000_hash = hex!("23ADA07F5261F12F34A0BD8E46760962D6B4D576A416F1FEA1C64BC656B1D28EACF7047AE6E967C58FD2A98BFA74C298");

        let tables = machine.build_tables()?;
        let acpi_tables_hash = measure_sha384(&tables.tables);
        let acpi_rsdp_hash = measure_sha384(&tables.rsdp);
        let acpi_loader_hash = measure_sha384(&tables.loader);

        // RTMR0 calculation

        let rtmr0_log = vec![
            td_hob_hash,
            cfv_image_hash.to_vec(),
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "SecureBoot")?,
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "PK")?,
            measure_tdx_efi_variable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "KEK")?,
            measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "db")?,
            measure_tdx_efi_variable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbx")?,
            measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
            acpi_loader_hash,
            acpi_rsdp_hash,
            acpi_tables_hash,
            measure_sha384(&[0x00, 0x00]), // BootOrder
            boot000_hash.to_vec(),
        ];
        debug_print_log("RTMR0", &rtmr0_log);
        Ok(measure_log(&rtmr0_log))
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

        let (_, last_start, last_end) = memory_acceptor.ranges.pop().expect("No ranges");

        for (accepted, start, end) in memory_acceptor.ranges {
            if accepted {
                add_memory_resource_hob(0x00, start, end - start);
            } else {
                add_memory_resource_hob(0x07, start, end - start);
            }
        }

        if memory_size >= 0xB0000000 {
            add_memory_resource_hob(0x07, last_start, 0x80000000u64 - last_start);
            add_memory_resource_hob(0x07, 0x100000000, last_end - 0x80000000u64);
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
