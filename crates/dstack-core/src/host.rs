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

/// CID windows already spoken for on this host. vsock CIDs are a global
/// resource, so a second VMM must avoid these. Two sources, unioned:
///
/// * the `[cid_start, cid_start+cid_pool_size)` pool of every other running
///   `dstack-vmm` (read from the `-c <config>` it was launched with) — this
///   catches the reserved pool even when that VMM has no live CVM right now,
///   and
/// * any live `guest-cid=<n>` from a running QEMU, as a 1-wide range (covers a
///   VMM whose config we couldn't read).
///
/// Best-effort: unreadable cmdlines/configs are skipped. Ranges are half-open
/// `[start, end)`.
pub fn occupied_cid_ranges() -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return ranges;
    };
    for entry in entries.flatten() {
        let Ok(data) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        // cmdline is NUL-separated argv.
        let args: Vec<String> = data
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if args.is_empty() {
            continue;
        }
        // (a) another dstack-vmm's reserved pool, from its config.
        let is_vmm = Path::new(&args[0]).file_name().and_then(|f| f.to_str()) == Some("dstack-vmm");
        if is_vmm {
            if let Some(cfg) = arg_value(&args, "-c").or_else(|| arg_value(&args, "--config")) {
                if let Some((start, size)) = read_cid_pool(&cfg) {
                    ranges.push((start, start.saturating_add(size)));
                }
            }
        }
        // (b) any live guest-cid token.
        for arg in &args {
            for tok in arg.split([',', ' ']) {
                if let Some(rest) = tok.strip_prefix("guest-cid=") {
                    if let Ok(n) = rest.trim().parse::<u32>() {
                        ranges.push((n, n.saturating_add(1)));
                    }
                }
            }
        }
    }
    ranges
}

/// value following `flag` in an argv (`-c foo` → `foo`).
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

/// read `[cvm]` `cid_start` / `cid_pool_size` from a vmm.toml by line scan
/// (avoids a toml dependency; tolerates partial configs — size defaults 1000).
fn read_cid_pool(config_path: &str) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(config_path).ok()?;
    let mut start = None;
    let mut size = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("cid_start") {
            start = parse_toml_u32(v);
        } else if let Some(v) = l.strip_prefix("cid_pool_size") {
            size = parse_toml_u32(v);
        }
    }
    Some((start?, size.unwrap_or(1000)))
}

/// parse the `= <u32>` that follows a key (tolerating a trailing `# comment`).
fn parse_toml_u32(after_key: &str) -> Option<u32> {
    after_key
        .trim_start()
        .strip_prefix('=')?
        .split('#')
        .next()?
        .trim()
        .parse()
        .ok()
}
