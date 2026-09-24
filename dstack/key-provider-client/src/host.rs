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

/// Matches the frame bound the local key provider enforces on its side.
const MAX_RESPONSE_SIZE: usize = 8 * 1024 * 1024;

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
    let response_length = u32::from_be_bytes(response_length) as usize;
    if response_length > MAX_RESPONSE_SIZE {
        bail!("key provider response is {response_length} bytes; maximum is {MAX_RESPONSE_SIZE}");
    }
    let mut response = vec![0; response_length];
    tcp_stream
        .read_exact(&mut response)
        .await
        .context("Failed to read response")?;
    let response: QuoteResponse =
        serde_json::from_slice(&response).context("Failed to deserialize response")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn rejects_oversized_response_before_allocating_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        });

        let error = get_key(vec![1, 2, 3], addr.ip(), addr.port())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("maximum"), "{error:#}");
        server.await.unwrap();
    }
}
