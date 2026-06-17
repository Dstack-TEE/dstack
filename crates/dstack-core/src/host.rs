// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! host environment checks used by `dstackup` — SGX presence and the primary IP.

use anyhow::{bail, Result};
use std::net::{IpAddr, UdpSocket};
use std::path::Path;

/// presence of the SGX device nodes the local key provider needs.
#[derive(Debug, Clone, Copy)]
pub struct Sgx {
    pub enclave: bool,
    pub provision: bool,
}

impl Sgx {
    pub fn ok(&self) -> bool {
        self.enclave && self.provision
    }
}

/// check for `/dev/sgx_enclave` and `/dev/sgx_provision`.
pub fn check_sgx() -> Sgx {
    Sgx {
        enclave: Path::new("/dev/sgx_enclave").exists(),
        provision: Path::new("/dev/sgx_provision").exists(),
    }
}

/// require SGX, with a clear message if it is missing (design decision: fail fast
/// rather than silently degrade to a host-mode KMS with no real attestation).
pub fn require_sgx() -> Result<()> {
    let sgx = check_sgx();
    if !sgx.ok() {
        let mut missing = Vec::new();
        if !sgx.enclave {
            missing.push("/dev/sgx_enclave");
        }
        if !sgx.provision {
            missing.push("/dev/sgx_provision");
        }
        bail!(
            "sgx not available (missing {}); dstack requires Intel SGX for the local key provider — enable SGX in BIOS, or run on a TDX+SGX host",
            missing.join(", ")
        );
    }
    Ok(())
}

/// best-effort primary routable IPv4 of this host.
///
/// uses the standard UDP-connect trick: connecting a datagram socket sends no
/// packets but makes the kernel pick the source address it would route from.
pub fn detect_host_ip() -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(socket.local_addr()?.ip())
}

/// whether `ip` is a link-local address (169.254/16) — usable, but a poor
/// default for a dashboard SAN or KMS bootstrap domain.
pub fn is_link_local(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_link_local())
}
