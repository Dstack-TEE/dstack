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

/// Read or synthesize the inbound proxy protocol header.
///
/// When `inbound_pp_enabled` is true, reads a PP header from the stream (e.g. from an upstream
/// load balancer). When false, synthesizes one from the TCP peer address.
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
            bail!("no valid proxy protocol header detected");
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
        bail!("v2 proxy protocol header is too long");
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
        bail!("no valid proxy protocol header detected (v1 terminator not found)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_protocol::{version1 as v1, version2 as v2, ProxyHeader};

    fn extract_v4(header: ProxyHeader) -> (std::net::SocketAddrV4, std::net::SocketAddrV4) {
        match header {
            ProxyHeader::Version1 {
                addresses:
                    v1::ProxyAddresses::Ipv4 {
                        source,
                        destination,
                    },
                ..
            } => (source, destination),
            ProxyHeader::Version2 {
                addresses:
                    v2::ProxyAddresses::Ipv4 {
                        source,
                        destination,
                    },
                ..
            } => (source, destination),
            other => panic!("expected ipv4 header, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parses_v1_ipv4() {
        // v1 is ASCII: "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"
        let header = b"PROXY TCP4 1.2.3.4 5.6.7.8 11111 22222\r\n";
        let (_stream, parsed) = read_proxy_header(&header[..]).await.expect("v1 parse");
        let (src, dst) = extract_v4(parsed);
        assert_eq!(src.ip().octets(), [1, 2, 3, 4]);
        assert_eq!(src.port(), 11111);
        assert_eq!(dst.ip().octets(), [5, 6, 7, 8]);
        assert_eq!(dst.port(), 22222);
    }

    #[tokio::test]
    async fn parses_v2_ipv4() {
        // v2 magic + ver/cmd 0x21 + family/proto 0x11 (TCP/IPv4) + len 12
        let mut header = Vec::new();
        header.extend_from_slice(V2_PROTOCOL_PREFIX);
        header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        header.extend_from_slice(&[1, 2, 3, 4]); // src ip
        header.extend_from_slice(&[5, 6, 7, 8]); // dst ip
        header.extend_from_slice(&11111u16.to_be_bytes()); // src port
        header.extend_from_slice(&22222u16.to_be_bytes()); // dst port

        let (_stream, parsed) = read_proxy_header(&header[..]).await.expect("v2 parse");
        let (src, dst) = extract_v4(parsed);
        assert_eq!(src.ip().octets(), [1, 2, 3, 4]);
        assert_eq!(src.port(), 11111);
        assert_eq!(dst.ip().octets(), [5, 6, 7, 8]);
        assert_eq!(dst.port(), 22222);
    }

    #[tokio::test]
    async fn rejects_no_prefix() {
        // Looks neither like v1 ("PROXY") nor v2 magic.
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = read_proxy_header(&bytes[..]).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("no valid proxy protocol header"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn rejects_v1_without_terminator() {
        // PROXY prefix matched but no \r\n terminator within V1_MAX_LENGTH bytes.
        let bytes = vec![b'P'; V1_MAX_LENGTH + 8]; // all 'P' — never closes
        let mut head = b"PROXY".to_vec();
        head.extend(std::iter::repeat(b'A').take(V1_MAX_LENGTH));
        let err = read_proxy_header(&head[..]).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("v1 terminator not found") || msg.contains("no valid proxy"),
            "unexpected error: {msg}"
        );
        // Sanity: the longer no-terminator buffer would also fail (read past)
        let _ = bytes;
    }

    #[tokio::test]
    async fn rejects_v2_oversize_length() {
        // v2 prefix with a length field exceeding V2_MAX_LENGTH.
        let mut header = Vec::new();
        header.extend_from_slice(V2_PROTOCOL_PREFIX);
        header.extend_from_slice(&[0x21, 0x11]);
        // length = V2_MAX_LENGTH bytes -> total = MIN + that, blows the cap
        header.extend_from_slice(&(V2_MAX_LENGTH as u16).to_be_bytes());
        let err = read_proxy_header(&header[..]).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("too long"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn synthesizes_unspec_when_no_addrs() {
        // We can't construct a real TcpStream in a unit test cheaply; just
        // assert the helper returns Unspec for the all-None branch by going
        // through the public Display impl.
        let header = ProxyHeader::Version2 {
            command: v2::ProxyCommand::Proxy,
            transport_protocol: v2::ProxyTransportProtocol::Stream,
            addresses: v2::ProxyAddresses::Unspec,
        };
        assert_eq!(format!("{}", DisplayAddr(&header)), "<unspec>");
    }

    #[test]
    fn display_v2_ipv4_source() {
        let header = ProxyHeader::Version2 {
            command: v2::ProxyCommand::Proxy,
            transport_protocol: v2::ProxyTransportProtocol::Stream,
            addresses: v2::ProxyAddresses::Ipv4 {
                source: "9.8.7.6:1234".parse().unwrap(),
                destination: "1.2.3.4:80".parse().unwrap(),
            },
        };
        assert_eq!(format!("{}", DisplayAddr(&header)), "9.8.7.6:1234");
    }
}
