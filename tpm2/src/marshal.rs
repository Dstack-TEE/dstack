// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM 2.0 marshalling/unmarshalling utilities
//!
//! Provides serialization and deserialization for TPM structures.

use anyhow::{bail, Result};

/// Buffer for building TPM commands
#[derive(Debug, Default)]
pub struct CommandBuffer {
    data: Vec<u8>,
}

impl CommandBuffer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn put_u8(&mut self, v: u8) {
        self.data.push(v);
    }

    pub fn put_u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Put a TPM2B structure (2-byte size prefix + data)
    pub fn put_tpm2b(&mut self, data: &[u8]) {
        self.put_u16(data.len() as u16);
        self.put_bytes(data);
    }

    /// Put an empty TPM2B structure
    pub fn put_tpm2b_empty(&mut self) {
        self.put_u16(0);
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Update a u32 at a specific position (for size fields)
    pub fn update_u32(&mut self, pos: usize, v: u32) {
        self.data[pos..pos + 4].copy_from_slice(&v.to_be_bytes());
    }
}

/// Buffer for parsing TPM responses
#[derive(Debug)]
pub struct ResponseBuffer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ResponseBuffer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("buffer underflow reading u8");
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            bail!("buffer underflow reading u16");
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            bail!("buffer underflow reading u32");
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            bail!("buffer underflow reading u64");
        }
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    pub fn get_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.pos + len > self.data.len() {
            bail!(
                "buffer underflow reading {} bytes (remaining: {})",
                len,
                self.remaining()
            );
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// Get a TPM2B structure (2-byte size prefix + data)
    pub fn get_tpm2b(&mut self) -> Result<Vec<u8>> {
        let size = self.get_u16()? as usize;
        self.get_bytes(size)
    }

    /// Get remaining bytes
    pub fn get_remaining(&mut self) -> Vec<u8> {
        let v = self.data[self.pos..].to_vec();
        self.pos = self.data.len();
        v
    }

    /// Skip bytes
    pub fn skip(&mut self, len: usize) -> Result<()> {
        if self.pos + len > self.data.len() {
            bail!("buffer underflow skipping {} bytes", len);
        }
        self.pos += len;
        Ok(())
    }

    /// Peek at bytes without advancing position
    pub fn peek_bytes(&self, len: usize) -> Result<&[u8]> {
        if self.pos + len > self.data.len() {
            bail!("buffer underflow peeking {} bytes", len);
        }
        Ok(&self.data[self.pos..self.pos + len])
    }
}

/// Trait for types that can be marshalled to TPM format
pub trait Marshal {
    fn marshal(&self, buf: &mut CommandBuffer);

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = CommandBuffer::new();
        self.marshal(&mut buf);
        buf.into_vec()
    }
}

/// Trait for types that can be unmarshalled from TPM format
pub trait Unmarshal: Sized {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self>;

    fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut buf = ResponseBuffer::new(data);
        Self::unmarshal(&mut buf)
    }
}

// Implement Marshal for primitive types
impl Marshal for u8 {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u8(*self);
    }
}

impl Marshal for u16 {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(*self);
    }
}

impl Marshal for u32 {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u32(*self);
    }
}

impl Marshal for u64 {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u64(*self);
    }
}

// Implement Unmarshal for primitive types
impl Unmarshal for u8 {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        buf.get_u8()
    }
}

impl Unmarshal for u16 {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        buf.get_u16()
    }
}

impl Unmarshal for u32 {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        buf.get_u32()
    }
}

impl Unmarshal for u64 {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        buf.get_u64()
    }
}
