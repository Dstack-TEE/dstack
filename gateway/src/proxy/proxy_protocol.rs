// PROXY Protocol implementation
// Specification references:
// - v1: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
// - v2: https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

const PROXY_V1_PREFIX: &[u8] = b"PROXY ";
const PROXY_V2_SIGNATURE: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
const PROXY_V2_VERSION: u8 = 0x21; // Version 2, PROXY command

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// Parsed PROXY Protocol header information
///
/// Contains all fields defined in the PROXY Protocol specification.
/// Even though `version` and `destination` are not currently used in our implementation,
/// they are retained for completeness and future extensibility as per the protocol spec.
#[derive(Debug, Clone)]
pub struct ProxyProtocolHeader {
    #[allow(dead_code)] // Part of PROXY Protocol spec, kept for completeness
    pub version: ProxyProtocolVersion,
    pub source: SocketAddr,
    #[allow(dead_code)] // Part of PROXY Protocol spec, may be used for advanced routing
    pub destination: SocketAddr,
    pub raw_header: Vec<u8>,
}

impl ProxyProtocolHeader {
    /// Creates a new PROXY Protocol header with the given parameters
    /// This constructor is provided for testing and future extensibility
    #[allow(dead_code)]
    pub fn new(
        version: ProxyProtocolVersion,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        let raw_header = match version {
            ProxyProtocolVersion::V1 => build_v1_header(&source, &destination),
            ProxyProtocolVersion::V2 => build_v2_header(&source, &destination),
        };
        Self {
            version,
            source,
            destination,
            raw_header,
        }
    }
}

pub fn parse_proxy_protocol(buffer: &[u8]) -> io::Result<Option<ProxyProtocolHeader>> {
    if buffer.is_empty() {
        return Ok(None);
    }

    // Try V2 first (binary protocol with fixed signature)
    if buffer.len() >= PROXY_V2_SIGNATURE.len()
        && buffer.starts_with(PROXY_V2_SIGNATURE)
    {
        return parse_v2(buffer);
    }

    // Try V1 (text protocol)
    if buffer.len() >= PROXY_V1_PREFIX.len() && buffer.starts_with(PROXY_V1_PREFIX) {
        return parse_v1(buffer);
    }

    // No PROXY protocol header found
    Ok(None)
}

fn parse_v1(buffer: &[u8]) -> io::Result<Option<ProxyProtocolHeader>> {
    // Find the end of the V1 header (CRLF)
    let header_end = buffer
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "V1 header incomplete"))?;

    let header_line = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in V1 header"))?;

    let parts: Vec<&str> = header_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid V1 header format",
        ));
    }

    match parts[1] {
        "UNKNOWN" => {
            // UNKNOWN connections - preserve but use placeholder addresses
            let raw_header = buffer[..header_end + 2].to_vec();
            Ok(Some(ProxyProtocolHeader {
                version: ProxyProtocolVersion::V1,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                raw_header,
            }))
        }
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid V1 TCP header format",
                ));
            }

            let src_ip = IpAddr::from_str(parts[2])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid source IP"))?;
            let dst_ip = IpAddr::from_str(parts[3])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid destination IP"))?;
            let src_port = parts[4]
                .parse::<u16>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid source port"))?;
            let dst_port = parts[5]
                .parse::<u16>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid destination port"))?;

            let raw_header = buffer[..header_end + 2].to_vec();
            Ok(Some(ProxyProtocolHeader {
                version: ProxyProtocolVersion::V1,
                source: SocketAddr::new(src_ip, src_port),
                destination: SocketAddr::new(dst_ip, dst_port),
                raw_header,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported V1 protocol family",
        )),
    }
}

fn parse_v2(buffer: &[u8]) -> io::Result<Option<ProxyProtocolHeader>> {
    if buffer.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 header too short",
        ));
    }

    let version_command = buffer[12];
    if version_command >> 4 != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid V2 version",
        ));
    }

    let command = version_command & 0x0F;
    let family = buffer[13];
    let header_len = u16::from_be_bytes([buffer[14], buffer[15]]) as usize;

    if buffer.len() < 16 + header_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 header incomplete",
        ));
    }

    // LOCAL command means connection was made directly to the proxy
    if command == 0 {
        let raw_header = buffer[..16 + header_len].to_vec();
        return Ok(Some(ProxyProtocolHeader {
            version: ProxyProtocolVersion::V2,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            raw_header,
        }));
    }

    // PROXY command
    if command != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid V2 command",
        ));
    }

    let addresses = match family >> 4 {
        0x1 => {
            // AF_INET (IPv4)
            if header_len < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "V2 IPv4 addresses incomplete",
                ));
            }
            let src_ip = Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]);
            let dst_ip = Ipv4Addr::new(buffer[20], buffer[21], buffer[22], buffer[23]);
            let src_port = u16::from_be_bytes([buffer[24], buffer[25]]);
            let dst_port = u16::from_be_bytes([buffer[26], buffer[27]]);

            (
                SocketAddr::new(IpAddr::V4(src_ip), src_port),
                SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
            )
        }
        0x2 => {
            // AF_INET6 (IPv6)
            if header_len < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "V2 IPv6 addresses incomplete",
                ));
            }
            let src_ip = Ipv6Addr::new(
                u16::from_be_bytes([buffer[16], buffer[17]]),
                u16::from_be_bytes([buffer[18], buffer[19]]),
                u16::from_be_bytes([buffer[20], buffer[21]]),
                u16::from_be_bytes([buffer[22], buffer[23]]),
                u16::from_be_bytes([buffer[24], buffer[25]]),
                u16::from_be_bytes([buffer[26], buffer[27]]),
                u16::from_be_bytes([buffer[28], buffer[29]]),
                u16::from_be_bytes([buffer[30], buffer[31]]),
            );
            let dst_ip = Ipv6Addr::new(
                u16::from_be_bytes([buffer[32], buffer[33]]),
                u16::from_be_bytes([buffer[34], buffer[35]]),
                u16::from_be_bytes([buffer[36], buffer[37]]),
                u16::from_be_bytes([buffer[38], buffer[39]]),
                u16::from_be_bytes([buffer[40], buffer[41]]),
                u16::from_be_bytes([buffer[42], buffer[43]]),
                u16::from_be_bytes([buffer[44], buffer[45]]),
                u16::from_be_bytes([buffer[46], buffer[47]]),
            );
            let src_port = u16::from_be_bytes([buffer[48], buffer[49]]);
            let dst_port = u16::from_be_bytes([buffer[50], buffer[51]]);

            (
                SocketAddr::new(IpAddr::V6(src_ip), src_port),
                SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
            )
        }
        _ => {
            // AF_UNSPEC or unsupported
            let raw_header = buffer[..16 + header_len].to_vec();
            return Ok(Some(ProxyProtocolHeader {
                version: ProxyProtocolVersion::V2,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                raw_header,
            }));
        }
    };

    let raw_header = buffer[..16 + header_len].to_vec();
    Ok(Some(ProxyProtocolHeader {
        version: ProxyProtocolVersion::V2,
        source: addresses.0,
        destination: addresses.1,
        raw_header,
    }))
}

pub fn build_v1_header(source: &SocketAddr, destination: &SocketAddr) -> Vec<u8> {
    let protocol = match (source.is_ipv4(), destination.is_ipv4()) {
        (true, true) => "TCP4",
        (false, false) => "TCP6",
        _ => "UNKNOWN",
    };

    if protocol == "UNKNOWN" {
        return b"PROXY UNKNOWN\r\n".to_vec();
    }

    format!(
        "PROXY {} {} {} {} {}\r\n",
        protocol,
        source.ip(),
        destination.ip(),
        source.port(),
        destination.port()
    )
    .into_bytes()
}

pub fn build_v2_header(source: &SocketAddr, destination: &SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(64);

    // Signature
    header.extend_from_slice(PROXY_V2_SIGNATURE);

    // Version and command (0x21 = version 2, PROXY command)
    header.push(PROXY_V2_VERSION);

    // Family and protocol
    let (family, addr_len) = match (source.is_ipv4(), destination.is_ipv4()) {
        (true, true) => (0x11, 12), // AF_INET, STREAM
        (false, false) => (0x21, 36), // AF_INET6, STREAM
        _ => (0x00, 0), // AF_UNSPEC
    };
    header.push(family);

    // Address length
    header.extend_from_slice(&(addr_len as u16).to_be_bytes());

    // Addresses
    match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {}
    }

    header
}

/// Returns the maximum possible header length for a given PROXY Protocol version
///
/// As defined in the PROXY Protocol specification:
/// - V1: Maximum 108 bytes (including CRLF)
/// - V2: Maximum 52 bytes (16 byte fixed header + 36 bytes for IPv6 addresses)
///
/// This is useful for buffer allocation and protocol validation.
#[allow(dead_code)]
pub fn header_max_len(version: ProxyProtocolVersion) -> usize {
    match version {
        ProxyProtocolVersion::V1 => 108, // Max V1 header length per spec
        ProxyProtocolVersion::V2 => 16 + 36, // Fixed header + max IPv6 addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_ipv4() {
        let header = b"PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n";
        let result = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert_eq!(result.source.to_string(), "192.168.1.1:56324");
        assert_eq!(result.destination.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_parse_v1_ipv6() {
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        let result = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert_eq!(result.source.port(), 56324);
        assert_eq!(result.destination.port(), 443);
    }

    #[test]
    fn test_parse_v1_unknown() {
        let header = b"PROXY UNKNOWN\r\n";
        let result = parse_proxy_protocol(header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V1);
        assert_eq!(result.source.port(), 0);
        assert_eq!(result.destination.port(), 0);
    }

    #[test]
    fn test_parse_v2_ipv4() {
        let mut header = Vec::new();
        header.extend_from_slice(PROXY_V2_SIGNATURE);
        header.push(0x21); // Version 2, PROXY command
        header.push(0x11); // AF_INET, STREAM
        header.extend_from_slice(&12u16.to_be_bytes()); // Address length

        // Source and destination addresses
        header.extend_from_slice(&[192, 168, 1, 1]); // Source IP
        header.extend_from_slice(&[10, 0, 0, 1]); // Dest IP
        header.extend_from_slice(&56324u16.to_be_bytes()); // Source port
        header.extend_from_slice(&443u16.to_be_bytes()); // Dest port

        let result = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert_eq!(result.source.to_string(), "192.168.1.1:56324");
        assert_eq!(result.destination.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_parse_v2_ipv6() {
        let mut header = Vec::new();
        header.extend_from_slice(PROXY_V2_SIGNATURE);
        header.push(0x21); // Version 2, PROXY command
        header.push(0x21); // AF_INET6, STREAM
        header.extend_from_slice(&36u16.to_be_bytes()); // Address length

        // IPv6 addresses (simplified)
        header.extend_from_slice(&[0u8; 16]); // Source IP
        header.extend_from_slice(&[0u8; 16]); // Dest IP
        header.extend_from_slice(&56324u16.to_be_bytes()); // Source port
        header.extend_from_slice(&443u16.to_be_bytes()); // Dest port

        let result = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert_eq!(result.source.port(), 56324);
        assert_eq!(result.destination.port(), 443);
    }

    #[test]
    fn test_parse_v2_local() {
        let mut header = Vec::new();
        header.extend_from_slice(PROXY_V2_SIGNATURE);
        header.push(0x20); // Version 2, LOCAL command
        header.push(0x00); // AF_UNSPEC
        header.extend_from_slice(&0u16.to_be_bytes()); // No addresses

        let result = parse_proxy_protocol(&header).unwrap().unwrap();

        assert_eq!(result.version, ProxyProtocolVersion::V2);
        assert_eq!(result.source.port(), 0);
        assert_eq!(result.destination.port(), 0);
    }

    #[test]
    fn test_no_proxy_protocol() {
        let header = b"GET / HTTP/1.1\r\n";
        let result = parse_proxy_protocol(header).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_v1_header() {
        let source = SocketAddr::from_str("192.168.1.1:56324").unwrap();
        let dest = SocketAddr::from_str("10.0.0.1:443").unwrap();

        let header = build_v1_header(&source, &dest);
        let header_str = String::from_utf8(header.clone()).unwrap();

        assert!(header_str.starts_with("PROXY TCP4"));
        assert!(header_str.contains("192.168.1.1"));
        assert!(header_str.contains("10.0.0.1"));
        assert!(header_str.contains("56324"));
        assert!(header_str.contains("443"));
        assert!(header_str.ends_with("\r\n"));
    }

    #[test]
    fn test_build_v2_header() {
        let source = SocketAddr::from_str("192.168.1.1:56324").unwrap();
        let dest = SocketAddr::from_str("10.0.0.1:443").unwrap();

        let header = build_v2_header(&source, &dest);

        assert!(header.starts_with(PROXY_V2_SIGNATURE));
        assert_eq!(header[12], 0x21); // Version 2, PROXY command
        assert_eq!(header[13], 0x11); // AF_INET, STREAM

        // Parse it back to verify
        let parsed = parse_proxy_protocol(&header).unwrap().unwrap();
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.destination, dest);
    }

    #[test]
    fn test_roundtrip() {
        let source = SocketAddr::from_str("192.168.1.1:56324").unwrap();
        let dest = SocketAddr::from_str("10.0.0.1:443").unwrap();

        // Test V1 roundtrip
        let v1_header = build_v1_header(&source, &dest);
        let v1_parsed = parse_proxy_protocol(&v1_header).unwrap().unwrap();
        assert_eq!(v1_parsed.source, source);
        assert_eq!(v1_parsed.destination, dest);

        // Test V2 roundtrip
        let v2_header = build_v2_header(&source, &dest);
        let v2_parsed = parse_proxy_protocol(&v2_header).unwrap().unwrap();
        assert_eq!(v2_parsed.source, source);
        assert_eq!(v2_parsed.destination, dest);
    }
}