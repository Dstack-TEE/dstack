// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack` — client for deploying and managing apps on a dstack host.
//!
//! Works against a local VMM (unix socket) or a remote one (`--host` + `--token`).
//! Setup/host tasks live in the separate `dstackup` binary.
//!
//! Command names follow the `phala` CLI where it makes sense (`deploy`, `apps`,
//! `logs`, a global `-j/--json`).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use dstack_cli_core::layout::InstallLayout;
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
    /// Defaults to the local `dstackup install` endpoint, then the local control socket.
    #[arg(long, global = true)]
    host: Option<String>,

    /// local `dstackup install` prefix to read defaults from. Omit for the default system install.
    #[arg(long, global = true, value_name = "DIR")]
    prefix: Option<String>,

    /// auth token for a remote VMM.
    #[arg(long, global = true)]
    token: Option<String>,

    /// machine-readable JSON output (honored by `deploy` and `apps`).
    #[arg(long, short = 'j', global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Deploy an app from a docker-compose file.
    Deploy {
        /// path to the docker-compose file.
        compose: Option<String>,
        /// path to the docker-compose file.
        #[arg(long = "compose", short = 'c', value_name = "PATH")]
        compose_file: Option<String>,
        /// app name.
        #[arg(long, short = 'n', default_value = "app")]
        name: String,
        /// guest OS image name. Defaults to the image selected by `dstackup install`.
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
        /// register the app's compose hash in this auth-allowlist.json. Defaults
        /// to the local allowlist from `dstackup install`.
        #[arg(long, value_name = "PATH")]
        allowlist: Option<String>,
        /// build + hash the compose and print it, without deploying.
        #[arg(long)]
        dry_run: bool,
    },
    /// List deployed apps.
    Apps,
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
    /// Scaffold a new app project in the current directory.
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // remote-auth wiring lands with the TLS+token transport.
    let _ = &cli.token;
    let defaults = LocalDefaults::read(cli.prefix.as_deref());
    let use_local_defaults = cli.host.is_none();
    let host = cli
        .host
        .clone()
        .or_else(|| defaults.as_ref().and_then(|d| d.client_url.clone()))
        .unwrap_or_else(|| DEFAULT_HOST.to_string());
    let json = cli.json;

    match cli.command {
        Command::Apps => cmd_apps(&host, json).await,
        Command::Logs { id, lines } => cmd_logs(&host, &id, lines).await,
        Command::Deploy {
            compose,
            compose_file,
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
            let compose = resolve_compose_arg(compose, compose_file)?;
            let image = if use_local_defaults {
                image.or_else(|| defaults.as_ref().and_then(|d| d.image.clone()))
            } else {
                image
            };
            let allowlist = if use_local_defaults {
                allowlist.or_else(|| {
                    (!no_kms)
                        .then(|| defaults.as_ref().and_then(LocalDefaults::allowlist_path))
                        .flatten()
                })
            } else {
                allowlist
            };
            cmd_deploy(
                &host,
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
                json,
            )
            .await
        }
        Command::Info { .. } => stub("info"),
        Command::Init => stub("init"),
    }
}

fn resolve_compose_arg(positional: Option<String>, flagged: Option<String>) -> Result<String> {
    match (positional, flagged) {
        (Some(path), None) | (None, Some(path)) => Ok(path),
        (Some(_), Some(_)) => bail!("pass the compose file once: either as <COMPOSE> or with -c"),
        (None, None) => bail!("missing compose file: pass -c <docker-compose.yaml>"),
    }
}

struct LocalDefaults {
    client_url: Option<String>,
    image: Option<String>,
    allowlist_path: Option<String>,
}

impl LocalDefaults {
    fn read(prefix: Option<&str>) -> Option<Self> {
        let path = InstallLayout::state_path_for_prefix(prefix);
        let body = std::fs::read_to_string(path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        Some(Self::from_value(&v))
    }

    fn from_value(v: &serde_json::Value) -> Self {
        Self {
            client_url: v
                .get("client_url")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            image: v
                .get("image")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            allowlist_path: v
                .get("allowlist_path")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        }
    }

    fn allowlist_path(&self) -> Option<String> {
        self.allowlist_path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_install_defaults() {
        let value = serde_json::json!({
            "client_url": "http://127.0.0.1:19080",
            "image": "dstack-0.5.11",
            "allowlist_path": "/tmp/dstack/etc/dstack/auth-allowlist.json"
        });
        let defaults = LocalDefaults::from_value(&value);
        assert_eq!(
            defaults.client_url.as_deref(),
            Some("http://127.0.0.1:19080")
        );
        assert_eq!(defaults.image.as_deref(), Some("dstack-0.5.11"));
        assert_eq!(
            defaults.allowlist_path().as_deref(),
            Some("/tmp/dstack/etc/dstack/auth-allowlist.json")
        );
    }

    #[test]
    fn reads_local_install_defaults_from_prefix() {
        let install_root =
            std::env::temp_dir().join(format!("dstack-cli-state-test-{}", std::process::id()));
        let state_dir = install_root.join("var/lib/dstack");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join(dstack_cli_core::layout::STATE_FILE),
            r#"{
              "client_url": "http://127.0.0.1:29080",
              "image": "dstack-0.5.12",
              "allowlist_path": "/tmp/custom-dstack/etc/dstack/auth-allowlist.json"
            }"#,
        )
        .unwrap();

        let prefix = dstack_cli_core::layout::path_string(&install_root);
        let defaults = LocalDefaults::read(Some(&prefix)).unwrap();
        assert_eq!(
            defaults.client_url.as_deref(),
            Some("http://127.0.0.1:29080")
        );
        assert_eq!(defaults.image.as_deref(), Some("dstack-0.5.12"));
        assert_eq!(
            defaults.allowlist_path().as_deref(),
            Some("/tmp/custom-dstack/etc/dstack/auth-allowlist.json")
        );

        let _ = std::fs::remove_dir_all(install_root);
    }

    #[test]
    fn parses_phala_style_deploy_flags() {
        let cli = Cli::parse_from([
            "dstack",
            "deploy",
            "-n",
            "hello",
            "-c",
            "examples/hello-nginx/docker-compose.yaml",
            "--port",
            "8080:80",
        ]);
        match cli.command {
            Command::Deploy {
                compose,
                compose_file,
                name,
                ports,
                ..
            } => {
                assert_eq!(compose, None);
                assert_eq!(
                    compose_file.as_deref(),
                    Some("examples/hello-nginx/docker-compose.yaml")
                );
                assert_eq!(name, "hello");
                assert_eq!(ports, vec!["8080:80"]);
            }
            _ => panic!("expected deploy command"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_deploy(
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
    json: bool,
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
    if !json {
        println!("compose hash: {hash}");
        println!("app id:       {app_id}");
    }

    if dry_run {
        if json {
            print_json(&serde_json::json!({
                "composeHash": hash,
                "appId": app_id,
                "appCompose": app_compose,
                "dryRun": true,
            }));
        } else {
            println!("--- app-compose ---\n{app_compose}");
            println!("(dry run — not deploying)");
        }
        return Ok(());
    }
    if cfg.image.is_empty() {
        bail!(
            "an image is required to deploy: run `dstackup install` first, or pass --image <name>"
        );
    }

    // register the compose hash so the KMS will issue keys (KMS mode, local).
    if let Some(path) = allowlist {
        dstack_cli_core::config::register_app_in_allowlist(
            std::path::Path::new(path),
            &app_id,
            &hash,
        )
        .with_context(|| format!("registering app in {path}"))?;
        if !json {
            println!("registered compose hash in {path}");
            println!(
                "  (the KMS issues keys only if this is the allowlist its auth webhook serves)"
            );
        }
    } else if !no_kms && !json {
        println!("note: no --allowlist given; a KMS-mode app needs its compose hash registered to get keys");
    }

    let id = vmm.create_vm(cfg).await?;
    if json {
        let ports: Vec<_> = port_maps
            .iter()
            .map(|p| {
                serde_json::json!({
                    "vmPort": p.vm_port,
                    "hostPort": p.host_port,
                    "hostAddress": host_addr(p),
                })
            })
            .collect();
        print_json(&serde_json::json!({
            "vmId": id,
            "appId": app_id,
            "composeHash": hash,
            "ports": ports,
        }));
    } else {
        println!("deployed: vm {id}");
        if port_maps.is_empty() {
            println!("(no ports mapped — add --port <vm_port> to expose the app)");
        }
        for p in &port_maps {
            println!(
                "  app :{} -> http://{}:{}/",
                p.vm_port,
                host_addr(p),
                p.host_port
            );
        }
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

async fn cmd_apps(host: &str, json: bool) -> Result<()> {
    let vmm = Vmm::connect(host)?;
    let resp = vmm.status().await?;
    if json {
        let arr: Vec<_> = resp
            .vms
            .iter()
            .map(|vm| {
                serde_json::json!({
                    "id": vm.id,
                    "name": vm.name,
                    "status": vm.status,
                    "uptime": vm.uptime,
                    "appId": vm.app_id,
                })
            })
            .collect();
        print_json(&serde_json::Value::Array(arr));
        return Ok(());
    }
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

/// the host address a port maps to (loopback when unset).
fn host_addr(p: &rpc::PortMapping) -> &str {
    if p.host_address.is_empty() {
        "127.0.0.1"
    } else {
        &p.host_address
    }
}

/// print a value as pretty JSON (infallible via Value's Display).
fn print_json(v: &serde_json::Value) {
    println!("{v:#}");
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
