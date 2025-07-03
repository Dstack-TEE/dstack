use crate::{measure_log, measure_sha384, num::read_le, utf16_encode, util::debug_print_log};
use anyhow::{bail, Context, Result};
use object::pe;
use sha2::{Digest, Sha384};

/// Calculates the Authenticode hash of a PE/COFF file
fn authenticode_sha384_hash(data: &[u8]) -> Result<Vec<u8>> {
    let lfanew_offset = 0x3c;
    let lfanew: u32 = read_le(data, lfanew_offset, "DOS header")?;

    let pe_sig_offset = lfanew as usize;
    let pe_sig: u32 = read_le(data, pe_sig_offset, "PE signature offset")?;
    if pe_sig != pe::IMAGE_NT_SIGNATURE {
        bail!("Invalid PE signature");
    }

    let coff_header_offset = pe_sig_offset + 4;
    let optional_header_size =
        read_le::<u16>(data, coff_header_offset + 16, "COFF header size")? as usize;

    let optional_header_offset = coff_header_offset + 20;
    let magic: u16 = read_le(data, optional_header_offset, "header magic")?;

    let is_pe32_plus = magic == 0x20b;

    let checksum_offset = optional_header_offset + 64;
    let checksum_end = checksum_offset + 4;

    let data_dir_offset = optional_header_offset + if is_pe32_plus { 112 } else { 96 };
    let cert_dir_offset = data_dir_offset + (pe::IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
    let cert_dir_end = cert_dir_offset + 8;

    let size_of_headers_offset = optional_header_offset + 60;
    let size_of_headers = read_le::<u32>(data, size_of_headers_offset, "size_of_headers")? as usize;

    let mut hasher = Sha384::new();
    hasher.update(&data[0..checksum_offset]);
    hasher.update(&data[checksum_end..cert_dir_offset]);
    hasher.update(&data[cert_dir_end..size_of_headers]);

    let mut sum_of_bytes_hashed = size_of_headers;

    let num_sections_offset = coff_header_offset + 2;
    let num_sections = read_le::<u16>(data, num_sections_offset, "number of sections")? as usize;

    let section_table_offset = optional_header_offset + optional_header_size;
    let section_size = 40;

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i * section_size);

        let ptr_raw_data_offset = section_offset + 20;
        let ptr_raw_data =
            read_le::<u32>(data, ptr_raw_data_offset, "pointer_to_raw_data")? as usize;

        let size_raw_data_offset = section_offset + 16;
        let size_raw_data =
            read_le::<u32>(data, size_raw_data_offset, "size_of_raw_data")? as usize;

        if size_raw_data > 0 {
            sections.push((ptr_raw_data, size_raw_data));
        }
    }

    sections.sort_by_key(|&(offset, _)| offset);

    for (offset, size) in sections {
        let start = offset;
        let end = start + size;

        if end <= data.len() {
            hasher.update(&data[start..end]);
        } else {
            let available_size = data.len().saturating_sub(start);
            if available_size > 0 {
                hasher.update(&data[start..start + available_size]);
            }
        }

        sum_of_bytes_hashed += size;
    }

    let file_size = data.len();

    let cert_table_addr_offset = cert_dir_offset;
    let cert_table_size_offset = cert_dir_offset + 4;

    let cert_table_addr =
        read_le::<u32>(data, cert_table_addr_offset, "certificate table address")? as usize;
    let cert_table_size =
        read_le::<u32>(data, cert_table_size_offset, "certificate table size")? as usize;

    if cert_table_addr > 0 && cert_table_size > 0 && file_size > sum_of_bytes_hashed {
        let trailing_data_len = file_size - sum_of_bytes_hashed;

        if trailing_data_len > cert_table_size {
            let hashed_trailing_len = trailing_data_len - cert_table_size;
            let trailing_start = sum_of_bytes_hashed;

            if trailing_start + hashed_trailing_len <= data.len() {
                hasher.update(&data[trailing_start..trailing_start + hashed_trailing_len]);
            }
        }
    }
    let remainder = file_size % 8;
    if remainder != 0 {
        let padding = vec![0u8; 8 - remainder];
        hasher.update(&padding);
    }
    Ok(hasher.finalize().to_vec())
}

/// Patches the kernel image as qemu does.
fn patch_kernel(
    kernel_data: &[u8],
    initrd_size: u32,
    mem_size: u64,
    acpi_data_size: u32,
) -> Result<Vec<u8>> {
    const MIN_KERNEL_LENGTH: usize = 0x1000;
    if kernel_data.len() < MIN_KERNEL_LENGTH {
        bail!("the kernel image is too short");
    }

    let mut kd = kernel_data.to_vec();

    let protocol = u16::from_le_bytes(kd[0x206..0x208].try_into().unwrap());

    let (real_addr, cmdline_addr) = if protocol < 0x200 || (kd[0x211] & 0x01) == 0 {
        (0x90000_u32, 0x9a000_u32)
    } else {
        (0x10000_u32, 0x20000_u32)
    };

    if protocol >= 0x200 {
        kd[0x210] = 0xb0; // type_of_loader = Qemu v0
    }
    if protocol >= 0x201 {
        kd[0x211] |= 0x80; // loadflags |= CAN_USE_HEAP
        let heap_end_ptr = cmdline_addr - real_addr - 0x200;
        kd[0x224..0x228].copy_from_slice(&heap_end_ptr.to_le_bytes());
    }
    if protocol >= 0x202 {
        kd[0x228..0x22C].copy_from_slice(&cmdline_addr.to_le_bytes());
    } else {
        kd[0x20..0x22].copy_from_slice(&0xa33f_u16.to_le_bytes());
        let offset = (cmdline_addr - real_addr) as u16;
        kd[0x22..0x24].copy_from_slice(&offset.to_le_bytes());
    }

    if initrd_size > 0 {
        if protocol < 0x200 {
            bail!("the kernel image is too old for ramdisk");
        }
        let mut initrd_max = if protocol >= 0x20c {
            let xlf = u16::from_le_bytes(kd[0x236..0x238].try_into().unwrap());
            if (xlf & 0x40) != 0 {
                u32::MAX
            } else {
                0x37ffffff
            }
        } else if protocol >= 0x203 {
            let max = u32::from_le_bytes(kd[0x22c..0x230].try_into().unwrap());
            if max == 0 {
                0x37ffffff
            } else {
                max
            }
        } else {
            0x37ffffff
        };

        let lowmem = if mem_size < 0xb0000000 {
            0xb0000000
        } else {
            0x80000000
        };
        let below_4g_mem_size = if mem_size >= lowmem {
            lowmem as u32
        } else {
            mem_size as u32
        };

        if initrd_max >= below_4g_mem_size - acpi_data_size {
            initrd_max = below_4g_mem_size - acpi_data_size - 1;
        }
        if initrd_size >= initrd_max {
            bail!("initrd is too large");
        }

        let initrd_addr = (initrd_max - initrd_size) & !4095;
        kd[0x218..0x21C].copy_from_slice(&initrd_addr.to_le_bytes());
        kd[0x21C..0x220].copy_from_slice(&initrd_size.to_le_bytes());
    }
    Ok(kd)
}

/// Measures a QEMU-patched TDX kernel image.
pub(crate) fn measure_kernel(
    kernel_data: &[u8],
    initrd_size: u32,
    mem_size: u64,
    acpi_data_size: u32,
) -> Result<Vec<u8>> {
    let kd = patch_kernel(kernel_data, initrd_size, mem_size, acpi_data_size)
        .context("Failed to patch kernel")?;
    let kernel_hash = authenticode_sha384_hash(&kd).context("Failed to compute kernel hash")?;
    let rtmr1_log = vec![
        kernel_hash,
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        measure_sha384(b"Exit Boot Services Invocation"),
        measure_sha384(b"Exit Boot Services Returned with Success"),
    ];
    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Measures the kernel command line by converting to UTF-16LE and hashing.
pub(crate) fn measure_cmdline(cmdline: &str) -> Vec<u8> {
    let mut utf16_cmdline = utf16_encode(cmdline);
    utf16_cmdline.extend([0, 0]);
    measure_sha384(&utf16_cmdline)
}
