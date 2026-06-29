// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup` — host setup and lifecycle for a dstack host.
//!
//! Local + privileged only (touches `/dev/sgx`, systemd, local files, the local
//! VMM socket). Day-to-day app operations live in the separate `dstack` binary.
//!
//! Modules: `cli` (arg parsing), `install`/`destroy` (the commands), `state`
//! (install-state persistence), `systemd` (unit management), `cid` (CID-window
//! allocation).

mod cid;
mod cli;
mod destroy;
mod image;
mod install;
mod state;
mod systemd;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use dstack_cli_core::host::{self, Platform};
use dstack_cli_core::layout::InstallLayout;
use dstack_cli_core::vmm::{Vmm, DEFAULT_HOST};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Status { prefix } => {
            let host = cli
                .host
                .clone()
                .unwrap_or_else(|| default_host(prefix.as_deref()));
            let platform = default_platform(prefix.as_deref()).or_else(host::Platform::detect);
            cmd_status(&host, platform).await
        }
        Command::Install(opts) => install::cmd_install(opts).await,
        Command::Image(cmd) => image::cmd_image(cmd).await,
        Command::Destroy { prefix, purge } => destroy::cmd_destroy(prefix.as_deref(), purge).await,
    }
}

fn default_host(prefix: Option<&str>) -> String {
    state::read_state(&InstallLayout::new(prefix).state_dir)
        .and_then(|s| (!s.client_url.is_empty()).then_some(s.client_url))
        .unwrap_or_else(|| DEFAULT_HOST.to_string())
}

fn default_platform(prefix: Option<&str>) -> Option<Platform> {
    state::read_state(&InstallLayout::new(prefix).state_dir)
        .and_then(|s| host::Platform::parse_opt(&s.platform).ok().flatten())
}

async fn cmd_status(host: &str, platform: Option<Platform>) -> Result<()> {
    match platform {
        Some(Platform::Tdx) => {
            let sgx = host::check_sgx();
            println!("platform: tdx");
            println!(
                "sgx:      enclave={}  provision={}  => {}",
                sgx.enclave,
                sgx.provision,
                if sgx.ok() { "ok" } else { "missing" }
            );
        }
        Some(Platform::AmdSevSnp) => {
            let sev = host::check_sev();
            println!("platform: amd-sev-snp");
            println!(
                "sev:      /dev/sev={}  => {}",
                sev,
                if sev { "ok" } else { "missing" }
            );
        }
        None => {
            println!("platform: undetected");
            let sgx = host::check_sgx();
            println!(
                "sgx:      enclave={}  provision={}  => {}",
                sgx.enclave,
                sgx.provision,
                if sgx.ok() { "ok" } else { "missing" }
            );
            let sev = host::check_sev();
            println!(
                "sev:      /dev/sev={}  => {}",
                sev,
                if sev { "ok" } else { "missing" }
            );
        }
    }
    match host::detect_host_ip() {
        Ok(ip) => {
            let note = if host::is_link_local(&ip) {
                "  (link-local)"
            } else {
                ""
            };
            println!("host ip:  {ip}{note}");
        }
        Err(e) => println!("host ip:  (undetected: {e})"),
    }
    print!("vmm:      {host} => ");
    match Vmm::connect(host) {
        Ok(vmm) => match vmm.status().await {
            Ok(s) => println!("reachable ({} vms)", s.vms.len()),
            Err(e) => println!("unreachable ({e})"),
        },
        Err(e) => println!("invalid endpoint ({e})"),
    }
    Ok(())
}
