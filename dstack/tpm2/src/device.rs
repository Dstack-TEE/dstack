// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM device communication layer
//!
//! Provides low-level communication with TPM devices via /dev/tpmrm0 or /dev/tpm0.

use anyhow::{Context, Result, bail};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use super::constants::*;
use super::marshal::*;

/// Maximum TPM command/response size
const TPM_MAX_COMMAND_SIZE: usize = 4096;

/// TPM device handle
trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

pub struct TpmDevice {
    transport: Box<dyn ReadWrite>,
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
            transport: Box::new(file),
            path: device_path.to_string(),
        })
    }

    /// Create a TPM device over an already connected byte stream.
    pub fn from_stream(stream: impl Read + Write + 'static, name: impl Into<String>) -> Self {
        Self {
            transport: Box::new(stream),
            path: name.into(),
        }
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
        self.transport
            .write_all(command)
            .context("failed to write TPM command")?;

        // Read the fixed header first so stream transports cannot return a
        // partial response and leave bytes for the next transaction.
        let mut header = [0u8; 10];
        self.transport
            .read_exact(&mut header)
            .context("failed to read TPM response header")?;
        let response_size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        if !(header.len()..=TPM_MAX_COMMAND_SIZE).contains(&response_size) {
            bail!("invalid TPM response size: {response_size}");
        }
        let mut response = Vec::with_capacity(response_size);
        response.extend_from_slice(&header);
        response.resize(response_size, 0);
        self.transport
            .read_exact(&mut response[header.len()..])
            .context("failed to read TPM response body")?;
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
    fn with_tag_and_code(tag: TpmSt, command_code: u32) -> Self {
        let mut buf = CommandBuffer::with_capacity(256);

        // Header: tag (2) + size (4) + command code (4)
        buf.put_u16(tag.to_u16());
        buf.put_u32(0); // Size placeholder
        buf.put_u32(command_code);

        Self { buf }
    }

    /// Create a new command without sessions
    pub fn new(command_code: TpmCc) -> Self {
        Self::with_tag_and_code(TpmSt::NoSessions, command_code.to_u32())
    }

    /// Create a new command with sessions
    pub fn with_sessions(command_code: TpmCc) -> Self {
        Self::with_tag_and_code(TpmSt::Sessions, command_code.to_u32())
    }

    /// Create a new command with sessions using a raw command code.
    pub fn with_sessions_raw(command_code: u32) -> Self {
        Self::with_tag_and_code(TpmSt::Sessions, command_code)
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

    /// Add password authorization with a non-empty auth value.
    pub fn add_password_auth_area(&mut self, auth: &[u8]) {
        let auth_size: u32 = (4 + 2 + 1 + 2 + auth.len()) as u32;

        self.buf.put_u32(auth_size);
        self.buf.put_u32(tpm_rh::PW); // Password session handle
        self.buf.put_u16(0); // Empty nonce
        self.buf.put_u8(0); // Session attributes
        self.buf.put_u16(auth.len() as u16);
        self.buf.put_bytes(auth);
    }

    /// Add a precomputed authorization area.
    pub fn add_auth_area(&mut self, auth_area: &[u8]) {
        self.buf.put_u32(auth_area.len() as u32);
        self.buf.put_bytes(auth_area);
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

    /// Serialize this response back to TPM wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = 10 + self.data.len();
        let mut response = Vec::with_capacity(size);
        response.extend_from_slice(&self.tag.to_u16().to_be_bytes());
        response.extend_from_slice(&(size as u32).to_be_bytes());
        response.extend_from_slice(&self.response_code.to_be_bytes());
        response.extend_from_slice(&self.data);
        response
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

/// Add a command to a successful TPM_CAP_COMMANDS response.
///
/// Responses for other capabilities, TPM errors, and paginated command lists
/// are returned unchanged.
pub fn add_command_capability(response: &[u8], command_code: u32) -> Result<Vec<u8>> {
    let mut response = TpmResponse::parse(response)?;
    if !response.is_success() {
        return Ok(response.to_bytes());
    }
    let mut buf = response.data_buffer();
    let more_data = buf.get_u8()? != 0;
    let capability = buf.get_u32()?;
    if capability != TpmCap::Commands as u32 || more_data {
        return Ok(response.to_bytes());
    }
    let count = buf.get_u32()? as usize;
    let mut attributes = Vec::with_capacity(count + 1);
    for _ in 0..count {
        attributes.push(buf.get_u32()?);
    }
    if attributes.contains(&command_code) {
        return Ok(response.to_bytes());
    }
    const COMMAND_INDEX_AND_VENDOR_MASK: u32 = 0x2000_ffff;
    let sort_key = command_code & COMMAND_INDEX_AND_VENDOR_MASK;
    let insertion = attributes
        .iter()
        .position(|attributes| attributes & COMMAND_INDEX_AND_VENDOR_MASK > sort_key)
        .unwrap_or(attributes.len());
    attributes.insert(insertion, command_code);

    let mut data = Vec::with_capacity(9 + attributes.len() * 4);
    data.push(u8::from(more_data));
    data.extend_from_slice(&(TpmCap::Commands as u32).to_be_bytes());
    data.extend_from_slice(&(attributes.len() as u32).to_be_bytes());
    for attributes in attributes {
        data.extend_from_slice(&attributes.to_be_bytes());
    }
    response.data = data;
    Ok(response.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_a_vendor_command_to_command_capabilities() {
        let response = TpmResponse {
            tag: TpmSt::NoSessions,
            response_code: 0,
            data: {
                let mut data = vec![0];
                data.extend_from_slice(&(TpmCap::Commands as u32).to_be_bytes());
                data.extend_from_slice(&1u32.to_be_bytes());
                data.extend_from_slice(&0x2000_1000u32.to_be_bytes());
                data
            },
        }
        .to_bytes();
        let response = add_command_capability(&response, 0x2000_0001).unwrap();
        let response = TpmResponse::parse(&response).unwrap();
        let mut data = response.data_buffer();
        assert_eq!(data.get_u8().unwrap(), 0);
        assert_eq!(data.get_u32().unwrap(), TpmCap::Commands as u32);
        assert_eq!(data.get_u32().unwrap(), 2);
        assert_eq!(data.get_u32().unwrap(), 0x2000_0001);
        assert_eq!(data.get_u32().unwrap(), 0x2000_1000);
    }

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
    fn raw_command_includes_auth_area() {
        let mut cmd = TpmCommand::with_sessions_raw(0x2000_0001);
        cmd.add_handle(0x0180_1000);
        cmd.add_handle(0x0180_1000);
        cmd.add_auth_area(&[0xaa, 0xbb, 0xcc]);

        let bytes = cmd.finalize();

        assert_eq!(&bytes[0..2], &[0x80, 0x02]);
        assert_eq!(
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            25
        );
        assert_eq!(&bytes[6..10], &[0x20, 0x00, 0x00, 0x01]);
        assert_eq!(&bytes[10..14], &[0x01, 0x80, 0x10, 0x00]);
        assert_eq!(&bytes[14..18], &[0x01, 0x80, 0x10, 0x00]);
        assert_eq!(&bytes[18..22], &[0x00, 0x00, 0x00, 0x03]);
        assert_eq!(&bytes[22..25], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn password_auth_area_includes_auth_value() {
        let mut cmd = TpmCommand::with_sessions(TpmCc::NvWrite);
        cmd.add_handle(0x0180_1000);
        cmd.add_handle(0x0180_1000);
        cmd.add_password_auth_area(&[0x11, 0x22, 0x33]);
        cmd.add_tpm2b(&[0x44]);
        cmd.add_u16(0);

        let bytes = cmd.finalize();

        assert_eq!(&bytes[0..2], &[0x80, 0x02]);
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x01, 0x37]);
        assert_eq!(&bytes[18..22], &[0x00, 0x00, 0x00, 0x0c]);
        assert_eq!(&bytes[22..26], &[0x40, 0x00, 0x00, 0x09]);
        assert_eq!(&bytes[26..28], &[0x00, 0x00]); // nonce
        assert_eq!(bytes[28], 0x00); // session attributes
        assert_eq!(&bytes[29..31], &[0x00, 0x03]);
        assert_eq!(&bytes[31..34], &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_response_parse() {
        // Minimal success response
        let response = vec![
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // Size = 10
            0x00, 0x00, 0x00, 0x00, // TPM_RC_SUCCESS
        ];

        let parsed = match TpmResponse::parse(&response) {
            Ok(parsed) => parsed,
            Err(error) => panic!("failed to parse minimal TPM response: {error}"),
        };
        assert!(parsed.is_success());
        assert!(parsed.data.is_empty());
    }
}
