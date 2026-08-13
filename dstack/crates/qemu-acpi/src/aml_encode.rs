// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0
use crate::Error;
use alloc::vec::Vec;
extern crate alloc;
fn encode_pkg_length(value: usize) -> Result<Vec<u8>, Error> {
    if value < 0x40 {
        return Ok(vec![value as u8]);
    }
    let follow = if value < 0x1000 {
        1
    } else if value < 0x100000 {
        2
    } else if value < 0x10000000 {
        3
    } else {
        return Err(Error::MalformedTables("AML package exceeds 256 MiB".into()));
    };
    let mut out = vec![((follow << 6) as u8) | (value as u8 & 0x0f)];
    for index in 0..follow {
        out.push((value >> (4 + index * 8)) as u8);
    }
    Ok(out)
}
pub(crate) fn integer(value: u32) -> Vec<u8> {
    match value {
        0 => vec![0],
        1 => vec![1],
        2..=0xff => vec![0x0a, value as u8],
        0x100..=0xffff => {
            let mut out = vec![0x0b];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0x0c];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}
pub(crate) fn package(opcode: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut total = body
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::MalformedTables("AML package size overflow".into()))?;
    loop {
        let length = encode_pkg_length(total)?;
        let adjusted = body
            .len()
            .checked_add(length.len())
            .ok_or_else(|| Error::MalformedTables("AML package size overflow".into()))?;
        if adjusted == total {
            let capacity = opcode
                .len()
                .checked_add(total)
                .ok_or_else(|| Error::MalformedTables("AML package size overflow".into()))?;
            let mut out = Vec::with_capacity(capacity);
            out.extend_from_slice(opcode);
            out.extend_from_slice(&length);
            out.extend_from_slice(body);
            return Ok(out);
        }
        total = adjusted;
    }
}
