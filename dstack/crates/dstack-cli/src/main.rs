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
use clap::{Parser, Subcommand, ValueEnum};
use dstack_cli_core::layout::InstallLayout;
use dstack_cli_core::vmm::{Vmm, DEFAULT_HOST};
use dstack_cli_core::{compose, ports, rpc};
use fs_err as fs;

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

    /// auth token for a VMM with `[auth]` enabled (sent as `Authorization:
    /// Bearer`). Falls back to `DSTACK_VMM_TOKEN`, then the token written by
    /// `dstackup install`.
    #[arg(long, global = true)]
    token: Option<String>,

    /// machine-readable JSON output (honored by `deploy` and `apps`).
    #[arg(long, short = 'j', global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ComposeRunner {
    #[default]
    DockerCompose,
    NerdctlCompose,
}

impl ComposeRunner {
    fn as_str(self) -> &'static str {
        match self {
            Self::DockerCompose => "docker-compose",
            Self::NerdctlCompose => "nerdctl-compose",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Snapshotter {
    Overlayfs,
    Stargz,
}

impl Snapshotter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Overlayfs => "overlayfs",
            Self::Stargz => "stargz",
        }
    }
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
        /// memory in MB.
        #[arg(long, default_value_t = 2048)]
        memory: u32,
        /// disk size in GB.
        #[arg(long, default_value_t = 20)]
        disk: u32,
        /// expose a port: `vm` | `host:vm` | `proto:host:vm` | `proto:addr:host:vm`,
        /// each optionally suffixed `@<nic>` to name the NIC it enters through
        /// (host omitted/`auto`/`0` ⇒ a free host port is picked). Repeatable.
        #[arg(long = "port", value_name = "SPEC")]
        ports: Vec<String>,
        /// attach a verity volume, as printed by `dstack verity`: the file name
        /// in the vmm's volumes_dir, its verity_root, and the target
        /// (an absolute mount path). Repeatable.
        #[arg(long = "volume", value_name = "NAME:VERITY_ROOT:TARGET")]
        volumes: Vec<String>,
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
        /// compose frontend used inside the guest.
        #[arg(long, value_enum, default_value = "docker-compose")]
        runner: ComposeRunner,
        /// containerd snapshotter (supported only with --runner nerdctl-compose).
        #[arg(long, value_enum)]
        snapshotter: Option<Snapshotter>,
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
    /// Build a read-only verity data volume from a directory or filesystem image.
    ///
    /// The build needs no daemon or TEE. It prints a verity_root to paste into
    /// the deploy command. See docs/verity-volumes.md.
    Verity {
        /// Pack this directory into a read-only data volume.
        #[arg(long, value_name = "PATH")]
        dir: Option<String>,
        /// wrap an existing filesystem image instead of building squashfs. The
        /// guest mounts it read-only after dm-verity verification.
        #[arg(long = "fs-image", value_name = "PATH", conflicts_with = "dir")]
        fs_image: Option<String>,
        /// where to write the volume.
        #[arg(long, short = 'o', default_value = "verity.img")]
        output: String,
        /// squashfs compression: `none` (the default), `zstd`, or `gzip`.
        #[arg(long, value_enum, default_value_t, conflicts_with = "fs_image")]
        compress: CompressionArg,
    },
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum CompressionArg {
    #[default]
    None,
    Zstd,
    Gzip,
}

impl From<CompressionArg> for dstack_volume::Compression {
    fn from(value: CompressionArg) -> Self {
        match value {
            CompressionArg::None => Self::None,
            CompressionArg::Zstd => Self::Zstd,
            CompressionArg::Gzip => Self::Gzip,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // progress (e.g. `verity` pulling layers) goes to stderr so it never mixes
    // with `--json` on stdout. RUST_LOG overrides.
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,dstack_volume=info")),
        )
        .init();
    let cli = Cli::parse();
    let defaults = LocalDefaults::read(cli.prefix.as_deref());
    let use_local_defaults = cli.host.is_none();
    let host = cli
        .host
        .clone()
        .or_else(|| defaults.as_ref().and_then(|d| d.client_url.clone()))
        .unwrap_or_else(|| DEFAULT_HOST.to_string());
    // auth token: --token, then DSTACK_VMM_TOKEN, then the token file written
    // by `dstackup install` (local defaults only).
    let token = cli
        .token
        .clone()
        .or_else(|| std::env::var("DSTACK_VMM_TOKEN").ok())
        .filter(|t| !t.trim().is_empty())
        .or_else(|| {
            use_local_defaults
                .then(|| defaults.as_ref().and_then(LocalDefaults::token))
                .flatten()
        });
    let token = token.as_deref();
    let json = cli.json;

    match cli.command {
        Command::Apps => cmd_apps(&host, token, json).await,
        Command::Logs { id, lines } => cmd_logs(&host, token, &id, lines).await,
        Command::Deploy {
            compose,
            compose_file,
            name,
            image,
            vcpu,
            memory,
            disk,
            ports,
            volumes,
            no_kms,
            allowlist,
            dry_run,
            runner,
            snapshotter,
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
                token,
                &compose,
                &name,
                image.as_deref(),
                vcpu,
                memory,
                disk,
                &ports,
                &volumes,
                no_kms,
                allowlist.as_deref(),
                dry_run,
                json,
                runner,
                snapshotter,
            )
            .await
        }
        Command::Info { .. } => stub("info"),
        Command::Init => stub("init"),
        Command::Verity {
            dir,
            fs_image,
            output,
            compress,
        } => cmd_verity(dir.as_deref(), fs_image.as_deref(), &output, compress, json).await,
    }
}

async fn cmd_verity(
    dir: Option<&str>,
    fs_image: Option<&str>,
    output: &str,
    compress: CompressionArg,
    json: bool,
) -> Result<()> {
    let result = dstack_volume::verity(dstack_volume::VerityOptions {
        dir: dir.map(std::path::PathBuf::from),
        fs_image: fs_image.map(std::path::PathBuf::from),
        output: output.into(),
        compress: compress.into(),
    })
    .await?;

    let volume_size = fs::metadata(&result.output)
        .with_context(|| format!("stat {}", result.output.display()))?
        .len();

    if json {
        print_json(&serde_json::json!({
            "verityRoot": result.verity_root,
            "output": result.output.display().to_string(),
            "dataSize": result.data_size,
            "volumeSize": volume_size,
        }));
        return Ok(());
    }

    let mib = volume_size as f64 / 1_048_576.0;
    println!("wrote {} ({mib:.1} MiB)", result.output.display());
    let file = result
        .output
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| result.output.display().to_string());
    // a data volume mounts at a path you choose; it must be writable (the guest
    // rootfs is read-only), e.g. under /run.
    let target = "/run/models";
    println!("\ncopy {file} into the vmm's volumes_dir, then deploy with:");
    println!(
        "  dstack deploy -c docker-compose.yaml --volume {file}:{}:{target}",
        result.verity_root
    );
    println!("  (change {target} to your mount path)");
    Ok(())
}

/// Parse a `--volume` spec `NAME:VERITY_ROOT:TARGET`.
///
/// `NAME` is the volume file in the vmm's volumes_dir. `VERITY_ROOT` and `TARGET`
/// become a measured `verity_volumes` entry in the app-compose, so the guest only
/// seeds content matching the attested root. `dstack verity` prints the exact
/// spec to paste.
///
/// `TARGET` is an absolute read-only mount path in the guest.
fn parse_volume(spec: &str) -> Result<dstack_types::VerityVolume> {
    let mut parts = spec.splitn(3, ':');
    let name = parts.next().unwrap_or_default();
    let (root, target) = match (parts.next(), parts.next()) {
        (Some(root), Some(target)) if !root.is_empty() && !target.is_empty() => (root, target),
        _ => bail!("--volume must be NAME:VERITY_ROOT:TARGET (as printed by `dstack verity`), got '{spec}'"),
    };
    if name.is_empty()
        || name.contains('/')
        || name.contains("..")
        || name.contains(',')
        || name.contains('=')
    {
        bail!("volume name '{name}' must be a bare file name (no '/', '..', ',', '=')");
    }
    if root.len() != 64 || !root.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verity_root '{root}' must be 64 hex chars (copy it from `dstack verity`)");
    }
    if !target.starts_with('/') {
        bail!("target '{target}' must be an absolute path");
    }
    let mut verity_root = [0; 32];
    hex::decode_to_slice(root, &mut verity_root).context("decoding verity_root")?;
    Ok(dstack_types::VerityVolume {
        source: name.to_string(),
        verity_root,
        target: target.into(),
    })
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
    client_token_path: Option<String>,
    image: Option<String>,
    allowlist_path: Option<String>,
}

impl LocalDefaults {
    fn read(prefix: Option<&str>) -> Option<Self> {
        let path = InstallLayout::state_path_for_prefix(prefix);
        let body = fs::read_to_string(path).ok()?;
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
            client_token_path: v
                .get("client_token_path")
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

    /// read the VMM API token from the file recorded by `dstackup install`.
    fn token(&self) -> Option<String> {
        let path = self.client_token_path.as_ref()?;
        let token = std::fs::read_to_string(path).ok()?;
        let token = token.trim();
        (!token.is_empty()).then(|| token.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_deploy(
    host: &str,
    token: Option<&str>,
    compose_path: &str,
    name: &str,
    image: Option<&str>,
    vcpu: u32,
    memory: u32,
    disk: u32,
    port_specs: &[String],
    volume_specs: &[String],
    no_kms: bool,
    allowlist: Option<&str>,
    dry_run: bool,
    json: bool,
    runner: ComposeRunner,
    snapshotter: Option<Snapshotter>,
) -> Result<()> {
    if matches!(runner, ComposeRunner::DockerCompose) && snapshotter.is_some() {
        bail!("--snapshotter is only supported with --runner nerdctl-compose");
    }
    let yaml = fs::read_to_string(compose_path)
        .with_context(|| format!("reading compose file '{compose_path}'"))?;

    let port_maps = port_specs
        .iter()
        .map(|s| ports::parse_port(s))
        .collect::<Result<Vec<_>>>()?;
    let parsed_volumes = volume_specs
        .iter()
        .map(|s| parse_volume(s))
        .collect::<Result<Vec<_>>>()?;
    dstack_types::validate_verity_volumes(&parsed_volumes).map_err(anyhow::Error::msg)?;

    // each --volume declares a measured verity_volumes entry, so the built
    // app-compose (and thus app_id) binds the attested roots.
    let app_compose = compose::build_app_compose_with_runtime_and_volumes(
        name,
        &yaml,
        !no_kms,
        runner.as_str(),
        snapshotter.map(Snapshotter::as_str),
        &parsed_volumes,
    );

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

    let vmm = Vmm::connect_with_token(host, token)?;
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
            println!("(no ports mapped - add --port <host_port>:<vm_port> to expose the app)");
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

async fn cmd_apps(host: &str, token: Option<&str>, json: bool) -> Result<()> {
    let vmm = Vmm::connect_with_token(host, token)?;
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

async fn cmd_logs(host: &str, token: Option<&str>, id: &str, lines: u32) -> Result<()> {
    let vmm = Vmm::connect_with_token(host, token)?;
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
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
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

        let _ = fs::remove_dir_all(install_root);
    }

    #[test]
    fn parses_volume_specs() {
        let root = "a".repeat(64);
        let data = parse_volume(&format!("weights.img:{root}:/models/llama")).unwrap();
        assert_eq!(data.source, "weights.img");
        assert_eq!(data.verity_root, [0xaa; 32]);
        assert_eq!(data.target, std::path::Path::new("/models/llama"));

        assert!(parse_volume("weights.img").is_err()); // missing verity_root:target
        assert!(parse_volume(&format!("weights.img:{root}")).is_err()); // missing target
        assert!(parse_volume(&format!("../escape.img:{root}:/models")).is_err()); // path separator
        assert!(parse_volume("x.img:nothex:/models").is_err()); // verity_root not hex
        assert!(parse_volume(&format!("x.img:{root}:docker")).is_err()); // docker seed removed
        assert!(parse_volume(&format!("x.img:{root}:relative/path")).is_err()); // bad target
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
                memory,
                ports,
                ..
            } => {
                assert_eq!(compose, None);
                assert_eq!(
                    compose_file.as_deref(),
                    Some("examples/hello-nginx/docker-compose.yaml")
                );
                assert_eq!(name, "hello");
                assert_eq!(memory, 2048);
                assert_eq!(ports, vec!["8080:80"]);
            }
            _ => panic!("expected deploy command"),
        }
    }

    #[test]
    fn parses_verity_fs_image_flag() {
        let cli = Cli::parse_from(["dstack", "verity", "--fs-image", "rootfs.ext4"]);
        match cli.command {
            Command::Verity { dir, fs_image, .. } => {
                assert_eq!(dir, None);
                assert_eq!(fs_image.as_deref(), Some("rootfs.ext4"));
            }
            _ => panic!("expected verity command"),
        }

        assert!(Cli::try_parse_from([
            "dstack",
            "verity",
            "--dir",
            "data",
            "--fs-image",
            "rootfs.ext4"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dstack",
            "verity",
            "--fs-image",
            "rootfs.ext4",
            "--compress",
            "zstd"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "dstack",
            "verity",
            "--dir",
            "data",
            "--compress",
            "invalid"
        ])
        .is_err());
    }
}
