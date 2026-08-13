// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0
use crate::Error;
use alloc::vec::Vec;
extern crate alloc;
pub(crate) fn decode_pkg_length(data: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    let lead = *data
        .get(offset)
        .ok_or_else(|| Error::MalformedTables("truncated AML package length".into()))?;
    let follow = usize::from(lead >> 6);
    let encoded = data
        .get(
            offset
                ..offset
                    .checked_add(follow + 1)
                    .ok_or_else(|| Error::MalformedTables("AML offset overflow".into()))?,
        )
        .ok_or_else(|| Error::MalformedTables("truncated AML package length".into()))?;
    if follow == 0 {
        return Ok((usize::from(lead & 0x3f), 1));
    }
    let mut value = usize::from(lead & 0x0f);
    for (index, byte) in encoded[1..].iter().enumerate() {
        value |= usize::from(*byte) << (4 + index * 8);
    }
    Ok((value, follow + 1))
}
pub(crate) fn encode_pkg_length(value: usize) -> Result<Vec<u8>, Error> {
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
pub(crate) fn adjust_package(
    data: &mut Vec<u8>,
    offset: usize,
    amount: isize,
) -> Result<isize, Error> {
    let (old, old_width) = decode_pkg_length(data, offset)?;
    let base = old
        .checked_add_signed(amount)
        .ok_or_else(|| Error::MalformedTables("invalid AML package adjustment".into()))?;
    let mut new = base;
    loop {
        let encoded = encode_pkg_length(new)?;
        let adjusted = base
            .checked_add(encoded.len())
            .and_then(|v| v.checked_sub(old_width))
            .ok_or_else(|| Error::MalformedTables("invalid AML package adjustment".into()))?;
        if adjusted == new {
            let end = offset
                .checked_add(old_width)
                .ok_or_else(|| Error::MalformedTables("AML offset overflow".into()))?;
            if end > data.len() {
                return Err(Error::MalformedTables(
                    "truncated AML package length".into(),
                ));
            }
            data.splice(offset..end, encoded.iter().copied());
            return Ok(encoded.len() as isize - old_width as isize);
        }
        new = adjusted;
    }
}
pub(crate) fn grow_package(
    data: &mut Vec<u8>,
    offset: usize,
    amount: usize,
) -> Result<isize, Error> {
    let amount = isize::try_from(amount)
        .map_err(|_| Error::MalformedTables("AML package growth exceeds isize".into()))?;
    adjust_package(data, offset, amount)
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_length_round_trip() -> Result<(), Error> {
        for value in [0, 1, 0x3f, 0x40, 0xfff, 0x1000, 0xfffff, 0x100000] {
            let encoded = encode_pkg_length(value)?;
            assert_eq!(decode_pkg_length(&encoded, 0)?, (value, encoded.len()));
        }
        Ok(())
    }
    #[test]
    fn malformed_package_lengths_are_rejected() {
        assert!(decode_pkg_length(&[], 0).is_err());
        assert!(decode_pkg_length(&[0x40], 0).is_err());
    }
}
