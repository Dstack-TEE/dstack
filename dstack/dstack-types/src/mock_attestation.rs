// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal localhost client for the development tee-simulator.

use std::io::{Read, Write};
use std::net::TcpStream;

pub fn request(platform: &str, report_data: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(base) = std::env::var("DSTACK_MOCK_ATTESTATION_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    let authority = base.trim_start_matches("http://").trim_end_matches('/');
    let mut stream = TcpStream::connect(authority)?;
    let path = format!("/attest/{platform}");
    write!(stream, "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", report_data.len())?;
    stream.write_all(report_data)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid mock attestation HTTP response"))?;
    let headers = std::str::from_utf8(&response[..split])?;
    if !headers.starts_with("HTTP/1.1 200") {
        anyhow::bail!(
            "mock attestation request failed: {}",
            headers.lines().next().unwrap_or(headers)
        );
    }
    Ok(Some(response[split + 4..].to_vec()))
}
