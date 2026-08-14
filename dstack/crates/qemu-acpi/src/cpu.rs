// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

use crate::aml_encode::{integer, package};
use crate::Error;

fn hex_digit(value: u32) -> u8 {
    match value & 0xf {
        0..=9 => b'0' + (value & 0xf) as u8,
        _ => b'A' + ((value & 0xf) as u8 - 10),
    }
}
fn name(index: u32) -> [u8; 4] {
    [
        b'C',
        hex_digit(index >> 8),
        hex_digit(index >> 4),
        hex_digit(index),
    ]
}

fn method(method_name: &[u8; 4], flags: u8, terms: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::with_capacity(5 + terms.len());
    body.extend_from_slice(method_name);
    body.push(flags);
    body.extend_from_slice(terms);
    package(&[0x14], &body)
}

fn status(index: u32) -> Result<Vec<u8>, Error> {
    let mut terms = vec![0xa4]; // Return
    terms.extend_from_slice(b"CSTA");
    terms.extend_from_slice(&integer(index));
    method(b"_STA", 0x08, &terms)
}

fn mat(index: u32, x2apic: bool) -> Result<Vec<u8>, Error> {
    let mut entry = Vec::new();
    if x2apic {
        entry.extend_from_slice(&[9, 16, 0, 0]);
        entry.extend_from_slice(&index.to_le_bytes());
        entry.extend_from_slice(&1u32.to_le_bytes());
        entry.extend_from_slice(&index.to_le_bytes());
    } else {
        entry.extend_from_slice(&[0, 8, index as u8, index as u8]);
        entry.extend_from_slice(&1u32.to_le_bytes());
    }
    let mut buffer = integer(entry.len() as u32);
    buffer.extend_from_slice(&entry);
    let buffer = package(&[0x11], &buffer)?;
    let mut out = vec![0x08];
    out.extend_from_slice(b"_MAT");
    out.extend_from_slice(&buffer);
    Ok(out)
}

fn eject(index: u32) -> Result<Vec<u8>, Error> {
    let mut call = b"CEJ0".to_vec();
    call.extend_from_slice(&integer(index));
    method(b"_EJ0", 1, &call)
}

fn ost(index: u32) -> Result<Vec<u8>, Error> {
    let mut call = b"COST".to_vec();
    call.extend_from_slice(&integer(index));
    call.extend_from_slice(&[0x68, 0x69, 0x6a]);
    method(b"_OST", 0x0b, &call)
}

pub(crate) fn object(index: u32, numa: bool) -> Result<Vec<u8>, Error> {
    let x2apic = index >= 255;
    let mut body = Vec::new();
    body.extend_from_slice(&name(index));
    if x2apic {
        body.extend_from_slice(&[0x08]);
        body.extend_from_slice(b"_HID");
        body.extend_from_slice(&[0x0d]);
        body.extend_from_slice(b"ACPI0007\0");
        body.extend_from_slice(&[0x08]);
        body.extend_from_slice(b"_UID");
        body.extend_from_slice(&integer(index));
    } else {
        body.push(index as u8); // ProcID
        body.extend_from_slice(&0u32.to_le_bytes()); // PblkAddr
        body.push(0); // PblkLen
    }
    body.extend_from_slice(&status(index)?);
    body.extend_from_slice(&mat(index, x2apic)?);
    if index != 0 {
        body.extend_from_slice(&eject(index)?);
    }
    body.extend_from_slice(&ost(index)?);
    if numa {
        body.extend_from_slice(&[0x08, b'_', b'P', b'X', b'M', 0x00]);
    }
    package(if x2apic { &[0x5b, 0x82] } else { &[0x5b, 0x83] }, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_processor_matches_qemu() -> Result<(), Error> {
        let Ok(expected) = hex::decode("5b83450443303031010000000000140c5f53544108a44353544101085f4d4154110b0a080008010101000000140b5f454a300143454a3001140e5f4f53540b434f53540168696a") else { panic!("valid test vector") };
        assert_eq!(object(1, false)?, expected);
        Ok(())
    }

    #[test]
    fn multi_byte_integer_processor_matches_qemu() -> Result<(), Error> {
        let Ok(expected) = hex::decode("5b83480443303032020000000000140d5f53544108a4435354410a02085f4d4154110b0a080008020201000000140c5f454a300143454a300a02140f5f4f53540b434f53540a0268696a") else { panic!("valid test vector") };
        assert_eq!(object(2, false)?, expected);
        Ok(())
    }
}
