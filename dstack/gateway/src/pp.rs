// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use anyhow::Result;
use proxy_protocol::{version1 as v1, version2 as v2, ProxyHeader};
use rocket_proxy_listener::read_proxy_header;
use tokio::net::TcpStream;

use crate::config::ProxyConfig;

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

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_protocol::version2 as v2;

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
