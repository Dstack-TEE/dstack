// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! host-port helpers. The VMM does not auto-allocate host ports, so the client
//! picks a free one and passes it explicitly in the VM configuration.

use anyhow::{bail, Context, Result};
use dstack_vmm_rpc::PortMapping;
use std::net::TcpListener;

/// pick a currently-free TCP port on loopback by binding to port 0.
///
/// inherently racy (the port could be taken before the VMM binds it), but fine
/// for a single interactive deploy; the VMM will surface a bind conflict.
pub fn free_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to find a free host port")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

/// whether `addr:port` can be bound right now. Best-effort and racy, but it
/// catches the common "another service already owns this port" case so an
/// install can refuse before it starts changing the host.
pub fn tcp_port_free(addr: &str, port: u16) -> bool {
    TcpListener::bind((addr, port)).is_ok()
}

/// parse a `--port` spec into a [`PortMapping`], auto-allocating the host port
/// when it is omitted, `0`, or `auto`. Accepted forms:
///
/// * `<vm>`                      — auto host port, tcp, 127.0.0.1
/// * `<host>:<vm>`               — tcp, 127.0.0.1
/// * `<proto>:<host>:<vm>`
/// * `<proto>:<addr>:<host>:<vm>`
pub fn parse_port(spec: &str) -> Result<PortMapping> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (proto, addr, host, vm) = match parts.as_slice() {
        [vm] => ("tcp", "127.0.0.1", "auto", *vm),
        [host, vm] => ("tcp", "127.0.0.1", *host, *vm),
        [proto, host, vm] => (*proto, "127.0.0.1", *host, *vm),
        [proto, addr, host, vm] => (*proto, *addr, *host, *vm),
        _ => bail!(
            "invalid --port '{spec}': expected vm | host:vm | proto:host:vm | proto:addr:host:vm"
        ),
    };
    if !matches!(proto, "tcp" | "udp") {
        bail!("invalid protocol in --port '{spec}': expected tcp or udp");
    }
    let vm_port = parse_port_number(vm, "vm", spec)? as u32;
    let host_port: u32 = if host.is_empty() || host == "auto" || host == "0" {
        free_local_port()? as u32
    } else {
        parse_port_number(host, "host", spec)? as u32
    };
    Ok(PortMapping {
        protocol: proto.to_string(),
        host_address: addr.to_string(),
        host_port,
        vm_port,
    })
}

fn parse_port_number(value: &str, label: &str, spec: &str) -> Result<u16> {
    let port: u16 = value
        .parse()
        .with_context(|| format!("invalid {label} port in '{spec}'"))?;
    if port == 0 {
        bail!("invalid {label} port in --port '{spec}': port must be between 1 and 65535");
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_direct_host_mapping() {
        let p = parse_port("8080:80").unwrap();
        assert_eq!(p.protocol, "tcp");
        assert_eq!(p.host_address, "127.0.0.1");
        assert_eq!(p.host_port, 8080);
        assert_eq!(p.vm_port, 80);
    }

    #[test]
    fn rejects_invalid_protocol_and_port_ranges() {
        assert!(parse_port("sctp:8080:80").is_err());
        assert!(parse_port("70000:80").is_err());
        assert!(parse_port("8080:0").is_err());
    }
}
