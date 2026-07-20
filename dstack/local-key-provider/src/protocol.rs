// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProviderError;

// The existing client caps the binary quote at 1 MiB. JSON represents every
// byte as a decimal number, so its framed representation can approach 4 MiB.
const MAX_QUOTE_SIZE: usize = 1024 * 1024;
const MAX_FRAME_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct QuoteRequest {
    pub quote: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub encrypted_key: Vec<u8>,
    pub provider_quote: Vec<u8>,
}

pub async fn read_request<R>(reader: &mut R) -> Result<QuoteRequest, ProviderError>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(ProviderError::InvalidRequest(format!(
            "frame length {length} is outside 1..={MAX_FRAME_SIZE}"
        )));
    }

    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    let request: QuoteRequest = serde_json::from_slice(&frame)?;
    if request.quote.len() > MAX_QUOTE_SIZE {
        return Err(ProviderError::InvalidRequest(format!(
            "quote is {} bytes; maximum is {MAX_QUOTE_SIZE}",
            request.quote.len()
        )));
    }
    Ok(request)
}

pub async fn write_response<W>(
    writer: &mut W,
    response: &QuoteResponse,
) -> Result<(), ProviderError>
where
    W: AsyncWrite + Unpin,
{
    let frame = serde_json::to_vec(response)?;
    let length = u32::try_from(frame.len())
        .map_err(|_| ProviderError::InvalidRequest("response frame is too large".into()))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_the_existing_length_prefixed_json_protocol() {
        let payload = br#"{"quote":[1,2,3,255]}"#;
        let mut wire = Vec::from((payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);

        let request = read_request(&mut wire.as_slice()).await.unwrap();
        assert_eq!(request.quote, [1, 2, 3, 255]);
    }

    #[tokio::test]
    async fn rejects_oversized_frames_before_allocating_them() {
        let bytes = ((MAX_FRAME_SIZE + 1) as u32).to_be_bytes();
        let mut wire = bytes.as_slice();
        let error = read_request(&mut wire).await.unwrap_err();
        assert!(matches!(error, ProviderError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn writes_a_compatible_response() {
        let response = QuoteResponse {
            encrypted_key: vec![1, 2],
            provider_quote: vec![3, 4],
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &response).await.unwrap();

        let length = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(length, wire.len() - 4);
        assert_eq!(
            &wire[4..],
            br#"{"encrypted_key":[1,2],"provider_quote":[3,4]}"#
        );
    }
}
