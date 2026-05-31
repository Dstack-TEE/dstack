// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Serialize, Deserialize)]
struct QuoteRequest<'a> {
    quote: &'a [u8],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteResponse {
    pub encrypted_key: Vec<u8>,
    pub provider_quote: Vec<u8>,
}

pub async fn get_key(quote: Vec<u8>, address: IpAddr, port: u16) -> Result<QuoteResponse> {
    if quote.len() > 1024 * 1024 {
        bail!("Quote is too long");
    }
    let mut tcp_stream = TcpStream::connect((address, port))
        .await
        .context("Failed to connect to key provider")?;
    let payload = QuoteRequest { quote: &quote };
    let serialized = serde_json::to_vec(&payload)?;
    let length = serialized.len() as u32;
    tcp_stream
        .write_all(&length.to_be_bytes())
        .await
        .context("Failed to write length")?;
    tcp_stream
        .write_all(&serialized)
        .await
        .context("Failed to write payload")?;

    let mut response_length = [0; 4];
    tcp_stream
        .read_exact(&mut response_length)
        .await
        .context("Failed to read response length")?;
    let response_length = u32::from_be_bytes(response_length);
    let mut response = vec![0; response_length as usize];
    tcp_stream
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;
    let response: QuoteResponse =
        serde_json::from_slice(&response).context("Failed to deserialize response")?;
    Ok(response)
}
