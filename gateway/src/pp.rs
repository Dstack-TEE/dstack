// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use proxy_protocol::{version1 as v1, version2 as v2, ProxyHeader};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

use crate::config::ProxyConfig;

const V1_PROTOCOL_PREFIX: &str = "PROXY";
const V1_PREFIX_LEN: usize = 5;
const V1_MAX_LENGTH: usize = 107;
const V1_TERMINATOR: &[u8] = b"\r\n";

const V2_PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
const V2_PREFIX_LEN: usize = 12;
const V2_MINIMUM_LEN: usize = 16;
const V2_LENGTH_INDEX: usize = 14;
const READ_BUFFER_LEN: usize = 512;
const V2_MAX_LENGTH: usize = 2048;

pub(crate) async fn get_inbound_pp_header(
    inbound: TcpStream,
    config: &ProxyConfig,
) -> Result<(TcpStream, ProxyHeader)> {
    if config.inbound_pp_enabled {
        read_proxy_header(inbound).await
    } else {
        let header = create_inbound_pp_header(&inbound);
        Ok((inbound, header))
    }
}

pub struct DisplayAddr<'a>(pub &'a ProxyHeader);

impl std::fmt::Display for DisplayAddr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ProxyHeader::Version2 { addresses, .. } => match addresses {
                v2::ProxyAddresses::Ipv4 { source, .. } => write!(f, "{}", source),
                v2::ProxyAddresses::Ipv6 { source, .. } => write!(f, "{}", source),
                v2::ProxyAddresses::Unix { .. } => write!(f, "<unix>"),
                v2::ProxyAddresses::Unspec => write!(f, "<unspec>"),
            },
            ProxyHeader::Version1 { addresses, .. } => match addresses {
                v1::ProxyAddresses::Ipv4 { source, .. } => write!(f, "{}", source),
                v1::ProxyAddresses::Ipv6 { source, .. } => write!(f, "{}", source),
                v1::ProxyAddresses::Unknown => write!(f, "<unknown>"),
            },
            _ => write!(f, "<unknown ver>"),
        }
    }
}

fn create_inbound_pp_header(inbound: &TcpStream) -> ProxyHeader {
    // When PROXY protocol is disabled, create a synthetic header from the actual TCP connection
    let peer_addr = inbound.peer_addr().ok();
    let local_addr = inbound.local_addr().ok();

    match (peer_addr, local_addr) {
        (Some(SocketAddr::V4(source)), Some(SocketAddr::V4(destination))) => {
            ProxyHeader::Version2 {
                command: v2::ProxyCommand::Proxy,
                transport_protocol: v2::ProxyTransportProtocol::Stream,
                addresses: v2::ProxyAddresses::Ipv4 {
                    source,
                    destination,
                },
            }
        }
        (Some(SocketAddr::V6(source)), Some(SocketAddr::V6(destination))) => {
            ProxyHeader::Version2 {
                command: v2::ProxyCommand::Proxy,
                transport_protocol: v2::ProxyTransportProtocol::Stream,
                addresses: v2::ProxyAddresses::Ipv6 {
                    source,
                    destination,
                },
            }
        }
        _ => ProxyHeader::Version2 {
            command: v2::ProxyCommand::Proxy,
            transport_protocol: v2::ProxyTransportProtocol::Stream,
            addresses: v2::ProxyAddresses::Unspec,
        },
    }
}

async fn read_proxy_header<I>(mut stream: I) -> Result<(I, ProxyHeader)>
where
    I: AsyncRead + Unpin,
{
    let mut buffer = [0; READ_BUFFER_LEN];
    let mut dynamic_buffer = None;

    stream.read_exact(&mut buffer[..V1_PREFIX_LEN]).await?;

    if &buffer[..V1_PREFIX_LEN] == V1_PROTOCOL_PREFIX.as_bytes() {
        read_v1_header(&mut stream, &mut buffer).await?;
    } else {
        stream
            .read_exact(&mut buffer[V1_PREFIX_LEN..V2_MINIMUM_LEN])
            .await?;
        if &buffer[..V2_PREFIX_LEN] == V2_PROTOCOL_PREFIX {
            dynamic_buffer = read_v2_header(&mut stream, &mut buffer).await?;
        } else {
            bail!("No valid Proxy Protocol header detected");
        }
    }

    let mut buffer = dynamic_buffer.as_deref().unwrap_or(&buffer[..]);

    let header =
        proxy_protocol::parse(&mut buffer).context("failed to parse proxy protocol header")?;
    Ok((stream, header))
}

async fn read_v2_header<I>(
    mut stream: I,
    buffer: &mut [u8; READ_BUFFER_LEN],
) -> Result<Option<Vec<u8>>>
where
    I: AsyncRead + Unpin,
{
    let length =
        u16::from_be_bytes([buffer[V2_LENGTH_INDEX], buffer[V2_LENGTH_INDEX + 1]]) as usize;
    let full_length = V2_MINIMUM_LEN + length;

    if full_length > V2_MAX_LENGTH {
        bail!("V2 Proxy Protocol header is too long");
    }

    if full_length > READ_BUFFER_LEN {
        let mut dynamic_buffer = Vec::with_capacity(full_length);
        dynamic_buffer.extend_from_slice(&buffer[..V2_MINIMUM_LEN]);
        dynamic_buffer.resize(full_length, 0);
        stream
            .read_exact(&mut dynamic_buffer[V2_MINIMUM_LEN..full_length])
            .await?;

        Ok(Some(dynamic_buffer))
    } else {
        stream
            .read_exact(&mut buffer[V2_MINIMUM_LEN..full_length])
            .await?;

        Ok(None)
    }
}

async fn read_v1_header<I>(mut stream: I, buffer: &mut [u8; READ_BUFFER_LEN]) -> Result<()>
where
    I: AsyncRead + Unpin,
{
    let mut end_found = false;
    for i in V1_PREFIX_LEN..V1_MAX_LENGTH {
        buffer[i] = stream.read_u8().await?;

        if [buffer[i - 1], buffer[i]] == V1_TERMINATOR {
            end_found = true;
            break;
        }
    }
    if !end_found {
        bail!("No valid Proxy Protocol header detected");
    }

    Ok(())
}
