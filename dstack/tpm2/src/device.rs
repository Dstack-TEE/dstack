// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM device communication layer
//!
//! Provides low-level communication with TPM devices via /dev/tpmrm0 or /dev/tpm0.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use super::constants::*;
use super::marshal::*;

/// Maximum TPM command/response size
const TPM_MAX_COMMAND_SIZE: usize = 4096;

/// TPM device handle
pub struct TpmDevice {
    file: File,
    path: String,
}

impl TpmDevice {
    /// Open a TPM device
    pub fn open(path: &str) -> Result<Self> {
        // Strip "device:" prefix if present
        let device_path = path.strip_prefix("device:").unwrap_or(path);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .with_context(|| format!("failed to open TPM device: {}", device_path))?;

        Ok(Self {
            file,
            path: device_path.to_string(),
        })
    }

    /// Detect and open the default TPM device
    pub fn detect() -> Result<Self> {
        if Path::new("/dev/tpmrm0").exists() {
            Self::open("/dev/tpmrm0")
        } else if Path::new("/dev/tpm0").exists() {
            Self::open("/dev/tpm0")
        } else {
            bail!("TPM device not found")
        }
    }

    /// Get the device path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Send a command to the TPM and receive the response
    pub fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        // Write command
        self.file
            .write_all(command)
            .context("failed to write TPM command")?;

        // Read response
        let mut response = vec![0u8; TPM_MAX_COMMAND_SIZE];
        let n = self
            .file
            .read(&mut response)
            .context("failed to read TPM response")?;

        response.truncate(n);
        Ok(response)
    }

    /// Execute a TPM command and parse the response
    pub fn execute(&mut self, command: &[u8]) -> Result<TpmResponse> {
        let response_bytes = self.transmit(command)?;
        TpmResponse::parse(&response_bytes)
    }
}

/// TPM command builder
pub struct TpmCommand {
    buf: CommandBuffer,
}

impl TpmCommand {
    /// Create a new command without sessions
    pub fn new(command_code: TpmCc) -> Self {
        let mut buf = CommandBuffer::with_capacity(256);

        // Header: tag (2) + size (4) + command code (4)
        buf.put_u16(TpmSt::NoSessions.to_u16());
        buf.put_u32(0); // Size placeholder
        buf.put_u32(command_code.to_u32());

        Self { buf }
    }

    /// Create a new command with sessions
    pub fn with_sessions(command_code: TpmCc) -> Self {
        let mut buf = CommandBuffer::with_capacity(256);

        // Header: tag (2) + size (4) + command code (4)
        buf.put_u16(TpmSt::Sessions.to_u16());
        buf.put_u32(0); // Size placeholder
        buf.put_u32(command_code.to_u32());

        Self { buf }
    }

    /// Add a handle to the command
    pub fn add_handle(&mut self, handle: u32) {
        self.buf.put_u32(handle);
    }

    /// Add raw bytes to the command
    pub fn add_bytes(&mut self, data: &[u8]) {
        self.buf.put_bytes(data);
    }

    /// Add a u8 value
    pub fn add_u8(&mut self, v: u8) {
        self.buf.put_u8(v);
    }

    /// Add a u16 value
    pub fn add_u16(&mut self, v: u16) {
        self.buf.put_u16(v);
    }

    /// Add a u32 value
    pub fn add_u32(&mut self, v: u32) {
        self.buf.put_u32(v);
    }

    /// Add a TPM2B structure
    pub fn add_tpm2b(&mut self, data: &[u8]) {
        self.buf.put_tpm2b(data);
    }

    /// Add an empty TPM2B structure
    pub fn add_tpm2b_empty(&mut self) {
        self.buf.put_tpm2b_empty();
    }

    /// Add a marshallable structure
    pub fn add<T: Marshal>(&mut self, value: &T) {
        value.marshal(&mut self.buf);
    }

    /// Add password authorization session (null auth)
    pub fn add_null_auth_area(&mut self) {
        // Authorization area size (4 bytes)
        // Session handle (4) + nonce (2) + attributes (1) + auth (2) = 9 bytes minimum
        let auth_size: u32 = 4 + 2 + 1 + 2; // 9 bytes for null auth

        self.buf.put_u32(auth_size);
        self.buf.put_u32(tpm_rh::PW); // Password session handle
        self.buf.put_u16(0); // Empty nonce
        self.buf.put_u8(0); // Session attributes (continue = 0)
        self.buf.put_u16(0); // Empty auth value
    }

    /// Add a policy session authorization
    pub fn add_policy_auth(&mut self, session_handle: u32) {
        let auth_size: u32 = 4 + 2 + 1 + 2;

        self.buf.put_u32(auth_size);
        self.buf.put_u32(session_handle);
        self.buf.put_u16(0); // Empty nonce
        self.buf.put_u8(TpmaSa::CONTINUE_SESSION); // Continue session
        self.buf.put_u16(0); // Empty auth value
    }

    /// Finalize the command and return the bytes
    pub fn finalize(mut self) -> Vec<u8> {
        // Update the size field
        let size = self.buf.len() as u32;
        self.buf.update_u32(2, size);
        self.buf.into_vec()
    }

    /// Get current buffer for inspection
    pub fn buffer(&self) -> &CommandBuffer {
        &self.buf
    }
}

/// TPM response parser
#[derive(Debug)]
pub struct TpmResponse {
    pub tag: TpmSt,
    pub response_code: u32,
    pub data: Vec<u8>,
}

impl TpmResponse {
    /// Parse a TPM response
    pub fn parse(response: &[u8]) -> Result<Self> {
        if response.len() < 10 {
            bail!("TPM response too short: {} bytes", response.len());
        }

        let mut buf = ResponseBuffer::new(response);

        let tag_raw = buf.get_u16()?;
        let tag = TpmSt::from_u16(tag_raw)
            .ok_or_else(|| anyhow::anyhow!("invalid response tag: 0x{:04x}", tag_raw))?;

        let size = buf.get_u32()? as usize;
        if response.len() < size {
            bail!(
                "TPM response size mismatch: expected {}, got {}",
                size,
                response.len()
            );
        }

        let response_code = buf.get_u32()?;

        // Remaining data after header
        let data = response[10..size].to_vec();

        Ok(Self {
            tag,
            response_code,
            data,
        })
    }

    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        self.response_code == 0
    }

    /// Get error description
    pub fn error_description(&self) -> String {
        if self.is_success() {
            "success".to_string()
        } else {
            format!("TPM error: 0x{:08x}", self.response_code)
        }
    }

    /// Ensure the response is successful
    pub fn ensure_success(&self) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            bail!("{}", self.error_description())
        }
    }

    /// Get a response buffer for parsing the data
    pub fn data_buffer(&self) -> ResponseBuffer<'_> {
        ResponseBuffer::new(&self.data)
    }

    /// Skip the parameter size field (for commands with sessions)
    pub fn skip_parameter_size(&self) -> Result<ResponseBuffer<'_>> {
        let mut buf = self.data_buffer();
        if self.tag == TpmSt::Sessions {
            let _param_size = buf.get_u32()?;
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_builder() {
        let mut cmd = TpmCommand::new(TpmCc::GetRandom);
        cmd.add_u16(32); // Request 32 random bytes

        let bytes = cmd.finalize();

        // Check header
        assert_eq!(&bytes[0..2], &[0x80, 0x01]); // TPM_ST_NO_SESSIONS
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x01, 0x7B]); // TPM_CC_GetRandom

        // Check size
        let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        assert_eq!(size as usize, bytes.len());
    }

    #[test]
    fn test_response_parse() {
        // Minimal success response
        let response = vec![
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // Size = 10
            0x00, 0x00, 0x00, 0x00, // TPM_RC_SUCCESS
        ];

        let parsed = TpmResponse::parse(&response).unwrap();
        assert!(parsed.is_success());
        assert!(parsed.data.is_empty());
    }
}
