// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

//! Construction of QEMU's `etc/table-loader` and `etc/acpi/rsdp` blobs.
//!
//! QEMU records one fixed-size (128-byte) loader command whenever an ACPI
//! table needs allocation, pointer relocation, or a checksum. Command order is
//! observable and therefore part of the measured ACPI ABI.

use crate::{AcpiBlobs, Error};

const LOADER_COMMAND_SIZE: usize = 128;
const LOADER_FILE_NAME_SIZE: usize = 56;
const LOADER_BLOB_SIZE: usize = 4096;
const ACPI_HEADER_SIZE: u32 = 36;
const ACPI_CHECKSUM_OFFSET: u32 = 9;

const TABLES_FILE: &str = "etc/acpi/tables";
const RSDP_FILE: &str = "etc/acpi/rsdp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableLocation {
    offset: u32,
    checksum_offset: u32,
    length: u32,
}

fn malformed(message: impl Into<String>) -> Error {
    Error::MalformedTables(message.into())
}

fn append_file_name(output: &mut Vec<u8>, file_name: &str) -> Result<(), Error> {
    if file_name.len() > LOADER_FILE_NAME_SIZE {
        return Err(malformed("fw_cfg file name exceeds QEMU loader limit"));
    }
    output.extend_from_slice(file_name.as_bytes());
    output.resize(output.len() + LOADER_FILE_NAME_SIZE - file_name.len(), 0);
    Ok(())
}

fn finish_command(output: &mut Vec<u8>, payload_size: usize) -> Result<(), Error> {
    let padding = LOADER_COMMAND_SIZE
        .checked_sub(payload_size)
        .ok_or_else(|| malformed("fw_cfg loader command exceeds 128 bytes"))?;
    output.resize(output.len() + padding, 0);
    Ok(())
}

fn append_allocate(
    output: &mut Vec<u8>,
    file_name: &str,
    alignment: u32,
    zone: u8,
) -> Result<(), Error> {
    output.extend_from_slice(&1u32.to_le_bytes());
    append_file_name(output, file_name)?;
    output.extend_from_slice(&alignment.to_le_bytes());
    output.push(zone);
    finish_command(output, 4 + LOADER_FILE_NAME_SIZE + 4 + 1)
}

fn append_add_pointer(
    output: &mut Vec<u8>,
    destination_file: &str,
    source_file: &str,
    offset: u32,
    pointer_size: u8,
) -> Result<(), Error> {
    output.extend_from_slice(&2u32.to_le_bytes());
    append_file_name(output, destination_file)?;
    append_file_name(output, source_file)?;
    output.extend_from_slice(&offset.to_le_bytes());
    output.push(pointer_size);
    finish_command(output, 4 + 2 * LOADER_FILE_NAME_SIZE + 4 + 1)
}

fn append_add_checksum(
    output: &mut Vec<u8>,
    file_name: &str,
    checksum_offset: u32,
    start: u32,
    length: u32,
) -> Result<(), Error> {
    output.extend_from_slice(&3u32.to_le_bytes());
    append_file_name(output, file_name)?;
    output.extend_from_slice(&checksum_offset.to_le_bytes());
    output.extend_from_slice(&start.to_le_bytes());
    output.extend_from_slice(&length.to_le_bytes());
    finish_command(output, 4 + LOADER_FILE_NAME_SIZE + 3 * 4)
}

fn parse_table_locations(tables: &[u8]) -> Result<Vec<([u8; 4], TableLocation)>, Error> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    while offset < tables.len() {
        // QEMU pads the blob with zeroes after the final table.
        if tables.get(offset..offset + 4) == Some(&[0, 0, 0, 0]) {
            break;
        }
        let signature: [u8; 4] = tables
            .get(offset..offset.saturating_add(4))
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| malformed("truncated ACPI table signature"))?;
        let length = tables
            .get(offset.saturating_add(4)..offset.saturating_add(8))
            .and_then(|bytes| <&[u8; 4]>::try_from(bytes).ok())
            .map(|bytes| u32::from_le_bytes(*bytes))
            .ok_or_else(|| malformed("truncated ACPI table header"))?;
        if length < ACPI_HEADER_SIZE {
            return Err(malformed("invalid ACPI table length"));
        }
        let next = offset
            .checked_add(length as usize)
            .filter(|next| *next <= tables.len())
            .ok_or_else(|| malformed("ACPI table extends beyond blob"))?;
        let table_offset = u32::try_from(offset)
            .map_err(|_| malformed("ACPI table offset exceeds 32-bit loader ABI"))?;
        let checksum_offset = table_offset
            .checked_add(ACPI_CHECKSUM_OFFSET)
            .ok_or_else(|| malformed("ACPI checksum offset overflow"))?;
        result.push((
            signature,
            TableLocation {
                offset: table_offset,
                checksum_offset,
                length,
            },
        ));
        offset = next;
    }
    Ok(result)
}

fn required_table(
    locations: &[([u8; 4], TableLocation)],
    signature: &[u8; 4],
) -> Result<TableLocation, Error> {
    locations
        .iter()
        .find_map(|(candidate, location)| (candidate == signature).then_some(*location))
        .ok_or_else(|| malformed(String::from_utf8_lossy(signature).into_owned()))
}

fn optional_table(
    locations: &[([u8; 4], TableLocation)],
    signature: &[u8; 4],
) -> Option<TableLocation> {
    locations
        .iter()
        .find_map(|(candidate, location)| (candidate == signature).then_some(*location))
}

fn append_table_checksum(output: &mut Vec<u8>, table: TableLocation) -> Result<(), Error> {
    append_add_checksum(
        output,
        TABLES_FILE,
        table.checksum_offset,
        table.offset,
        table.length,
    )
}

pub(crate) fn finish(tables: Vec<u8>) -> Result<AcpiBlobs, Error> {
    let locations = parse_table_locations(&tables)?;
    let dsdt = required_table(&locations, b"DSDT")?;
    let fadt = required_table(&locations, b"FACP")?;
    let madt = required_table(&locations, b"APIC")?;
    let srat = optional_table(&locations, b"SRAT");
    let mcfg = required_table(&locations, b"MCFG")?;
    let waet = required_table(&locations, b"WAET")?;
    let rsdt = required_table(&locations, b"RSDT")?;

    let mut rsdp = b"RSD PTR \0BOCHS \0".to_vec();
    rsdp.extend_from_slice(&rsdt.offset.to_le_bytes());

    let mut loader = Vec::with_capacity(LOADER_BLOB_SIZE);
    append_allocate(&mut loader, RSDP_FILE, 16, 2)?;
    append_allocate(&mut loader, TABLES_FILE, 64, 1)?;

    // This sequence mirrors QEMU's build order. In particular, SRAT is built
    // between MADT and MCFG only for NUMA configurations.
    append_table_checksum(&mut loader, dsdt)?;
    for (offset, pointer_size) in [(36, 4), (40, 4), (140, 8)] {
        append_add_pointer(
            &mut loader,
            TABLES_FILE,
            TABLES_FILE,
            fadt.offset
                .checked_add(offset)
                .ok_or_else(|| malformed("FADT pointer offset overflow"))?,
            pointer_size,
        )?;
    }
    append_table_checksum(&mut loader, fadt)?;
    append_table_checksum(&mut loader, madt)?;
    if let Some(srat) = srat {
        append_table_checksum(&mut loader, srat)?;
    }
    append_table_checksum(&mut loader, mcfg)?;
    append_table_checksum(&mut loader, waet)?;

    let rsdt_payload_length = rsdt
        .length
        .checked_sub(ACPI_HEADER_SIZE)
        .ok_or_else(|| malformed("RSDT shorter than ACPI header"))?;
    if rsdt_payload_length % 4 != 0 {
        return Err(malformed("RSDT entry area is not 32-bit aligned"));
    }
    for entry_offset in (ACPI_HEADER_SIZE..rsdt.length).step_by(4) {
        append_add_pointer(
            &mut loader,
            TABLES_FILE,
            TABLES_FILE,
            rsdt.offset
                .checked_add(entry_offset)
                .ok_or_else(|| malformed("RSDT pointer offset overflow"))?,
            4,
        )?;
    }
    append_table_checksum(&mut loader, rsdt)?;
    append_add_pointer(&mut loader, RSDP_FILE, TABLES_FILE, 16, 4)?;
    append_add_checksum(&mut loader, RSDP_FILE, 8, 0, 20)?;

    if loader.len() > LOADER_BLOB_SIZE {
        return Err(malformed("fw_cfg loader exceeds QEMU allocation"));
    }
    loader.resize(LOADER_BLOB_SIZE, 0);
    Ok(AcpiBlobs {
        tables,
        rsdp,
        loader,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_and_invalid_tables() {
        assert!(parse_table_locations(b"DSDT").is_err());

        let mut short = [0u8; 36];
        short[..4].copy_from_slice(b"DSDT");
        short[4..8].copy_from_slice(&35u32.to_le_bytes());
        assert!(parse_table_locations(&short).is_err());

        short[4..8].copy_from_slice(&37u32.to_le_bytes());
        assert!(parse_table_locations(&short).is_err());
    }
}
