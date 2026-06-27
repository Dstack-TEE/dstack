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
use dstack_cli_core::host;
use dstack_cli_core::vmm::{Vmm, DEFAULT_HOST};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host.as_deref().unwrap_or(DEFAULT_HOST);
    match cli.command {
        Command::Status => cmd_status(host).await,
        Command::Install(opts) => {
            let _ = host; // install uses its own prefix-derived endpoint
            install::cmd_install(opts).await
        }
        Command::Image(cmd) => image::cmd_image(cmd),
        Command::Destroy { prefix, purge } => destroy::cmd_destroy(&prefix, purge).await,
    }
}

async fn cmd_status(host: &str) -> Result<()> {
    let sgx = host::check_sgx();
    println!(
        "sgx:      enclave={}  provision={}  => {}",
        sgx.enclave,
        sgx.provision,
        if sgx.ok() { "ok" } else { "MISSING" }
    );
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
