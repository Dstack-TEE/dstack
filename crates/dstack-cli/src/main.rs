// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack` — client for deploying and managing apps on a dstack host.
//!
//! Works against a local VMM (unix socket) or a remote one (`--host` + `--token`).
//! Setup/host tasks live in the separate `dstackup` binary.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use dstack_cli_core::vmm::{Vmm, DEFAULT_HOST};
use dstack_cli_core::{compose, ports, rpc};

#[derive(Parser)]
#[command(
    name = "dstack",
    version,
    about = "client for deploying and managing dstack apps"
)]
struct Cli {
    /// VMM endpoint: `unix:/path/to/vmm.sock` (local) or `http(s)://host:port` (remote).
    /// Defaults to the local control socket.
    #[arg(long, global = true)]
    host: Option<String>,

    /// auth token for a remote VMM.
    #[arg(long, global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Deploy an app from a docker-compose file.
    Run {
        /// path to the docker-compose file.
        compose: String,
        /// app name.
        #[arg(long, default_value = "app")]
        name: String,
        /// guest OS image version (required to actually deploy).
        #[arg(long)]
        image: Option<String>,
        /// vCPUs.
        #[arg(long, default_value_t = 2)]
        vcpu: u32,
        /// memory in MB (matches vmm-cli's default; images with a large
        /// initramfs-rootfs may need more — raise it if the guest fails early).
        #[arg(long, default_value_t = 1024)]
        memory: u32,
        /// disk size in GB.
        #[arg(long, default_value_t = 20)]
        disk: u32,
        /// expose a port: `vm` | `host:vm` | `proto:host:vm` | `proto:addr:host:vm`
        /// (host omitted/`auto`/`0` ⇒ a free host port is picked). Repeatable.
        #[arg(long = "port", value_name = "SPEC")]
        ports: Vec<String>,
        /// deploy in non-KMS mode (ephemeral keys; no KMS required).
        #[arg(long)]
        no_kms: bool,
        /// register the app's compose hash in this auth-allowlist.json (local,
        /// KMS mode) so the KMS will issue it keys. Usually the path printed by
        /// `dstackup install`.
        #[arg(long, value_name = "PATH")]
        allowlist: Option<String>,
        /// build + hash the compose and print it, without deploying.
        #[arg(long)]
        dry_run: bool,
    },
    /// List deployed apps.
    Ls,
    /// Show recent logs for an app.
    Logs {
        /// app, instance, or VM id.
        id: String,
        /// number of trailing log lines to fetch.
        #[arg(long, default_value_t = 200)]
        lines: u32,
    },
    /// Show details for an app.
    Info {
        /// app or instance id.
        id: String,
    },
    /// Upgrade an app to a new compose.
    Upgrade {
        /// app or instance id.
        id: String,
        /// path to the new docker-compose file.
        compose: String,
    },
    /// Scaffold a new app project in the current directory.
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // remote-auth wiring lands with the TLS+token transport.
    let _ = &cli.token;
    let host = cli.host.as_deref().unwrap_or(DEFAULT_HOST);

    match cli.command {
        Command::Ls => cmd_ls(host).await,
        Command::Logs { id, lines } => cmd_logs(host, &id, lines).await,
        Command::Run {
            compose,
            name,
            image,
            vcpu,
            memory,
            disk,
            ports,
            no_kms,
            allowlist,
            dry_run,
        } => {
            cmd_run(
                host,
                &compose,
                &name,
                image.as_deref(),
                vcpu,
                memory,
                disk,
                &ports,
                no_kms,
                allowlist.as_deref(),
                dry_run,
            )
            .await
        }
        Command::Info { .. } => stub("info"),
        Command::Upgrade { .. } => stub("upgrade"),
        Command::Init => stub("init"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run(
    host: &str,
    compose_path: &str,
    name: &str,
    image: Option<&str>,
    vcpu: u32,
    memory: u32,
    disk: u32,
    port_specs: &[String],
    no_kms: bool,
    allowlist: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let yaml = std::fs::read_to_string(compose_path)
        .with_context(|| format!("reading compose file '{compose_path}'"))?;
    let app_compose = compose::build_app_compose(name, &yaml, !no_kms);

    let mut port_maps = Vec::new();
    for spec in port_specs {
        port_maps.push(ports::parse_port(spec)?);
    }

    let mut cfg = rpc::VmConfiguration {
        name: name.to_string(),
        image: image.unwrap_or_default().to_string(),
        compose_file: app_compose.clone(),
        vcpu,
        memory,
        disk_size: disk,
        ports: port_maps.clone(),
        ..Default::default()
    };

    let vmm = Vmm::connect(host)?;
    let hash = vmm.get_compose_hash(&cfg).await?;
    let app_id = short(&hash, 40);
    cfg.app_id = Some(app_id.clone());
    println!("compose hash: {hash}");
    println!("app id:       {app_id}");

    if dry_run {
        println!("--- app-compose ---\n{app_compose}");
        println!("(dry run — not deploying)");
        return Ok(());
    }
    if cfg.image.is_empty() {
        bail!("an image is required to deploy (pass --image <version>)");
    }

    // register the compose hash so the KMS will issue keys (KMS mode, local).
    if let Some(path) = allowlist {
        dstack_cli_core::config::register_app_in_allowlist(
            std::path::Path::new(path),
            &app_id,
            &hash,
        )
        .with_context(|| format!("registering app in {path}"))?;
        println!("registered compose hash in {path}");
        println!("  (the KMS issues keys only if this is the allowlist its auth webhook serves)");
    } else if !no_kms {
        println!("note: no --allowlist given; a KMS-mode app needs its compose hash registered to get keys");
    }

    let id = vmm.create_vm(cfg).await?;
    println!("deployed: vm {id}");
    if port_maps.is_empty() {
        println!("(no ports mapped — add --port <vm_port> to expose the app)");
    }
    for p in &port_maps {
        let addr = if p.host_address.is_empty() {
            "127.0.0.1"
        } else {
            &p.host_address
        };
        println!("  app :{} -> http://{}:{}/", p.vm_port, addr, p.host_port);
    }
    Ok(())
}

fn stub(name: &str) -> Result<()> {
    // exit non-zero so `dstack <stub> && next` doesn't proceed as if it worked.
    bail!(
        "dstack {name}: not yet implemented ({})",
        dstack_cli_core::user_agent()
    )
}

async fn cmd_ls(host: &str) -> Result<()> {
    let vmm = Vmm::connect(host)?;
    let resp = vmm.status().await?;
    if resp.vms.is_empty() {
        println!("no apps deployed");
        return Ok(());
    }
    println!(
        "{:<14}  {:<22}  {:<10}  {:<14}  APP ID",
        "ID", "NAME", "STATUS", "UPTIME"
    );
    for vm in resp.vms {
        println!(
            "{:<14}  {:<22}  {:<10}  {:<14}  {}",
            short(&vm.id, 12),
            trunc(&vm.name, 22),
            trunc(&vm.status, 10),
            trunc(&vm.uptime, 14),
            short(&vm.app_id, 40),
        );
    }
    Ok(())
}

async fn cmd_logs(host: &str, id: &str, lines: u32) -> Result<()> {
    let vmm = Vmm::connect(host)?;
    let logs = vmm.logs(id, lines).await?;
    print!("{logs}");
    Ok(())
}

/// first `n` chars of an id-like string.
fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// truncate to `n` chars with an ellipsis if longer.
fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
