// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup` — host setup and lifecycle for a dstack host.
//!
//! Local + privileged only (touches `/dev/sgx`, systemd, local files, the local
//! VMM socket). Day-to-day app operations live in the separate `dstack` binary.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use dstack_core::config::{self, HostConfig, VmmRender};
use dstack_core::vmm::{Vmm, DEFAULT_HOST};
use dstack_core::{host, ports, rpc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as PCommand;
use std::time::Duration;

/// what an install put in place, recorded so re-runs are idempotent and
/// `destroy` can reverse it cleanly.
#[derive(Serialize, Deserialize, Default)]
struct State {
    prefix: String,
    client_url: String,
    auth_port: u16,
    /// systemd unit names (without the `.service` suffix).
    #[serde(default)]
    vmm_unit: String,
    #[serde(default)]
    auth_unit: String,
    #[serde(default)]
    kms_vm_id: Option<String>,
    #[serde(default)]
    kms_url: String,
    /// docker-compose project for a key provider we started ourselves.
    #[serde(default)]
    kp_own_project: Option<String>,
}

fn state_path(prefix: &Path) -> PathBuf {
    prefix.join("dstackup-state.json")
}

fn read_state(prefix: &Path) -> Option<State> {
    let body = fs::read_to_string(state_path(prefix)).ok()?;
    serde_json::from_str(&body).ok()
}

fn write_state(prefix: &Path, st: &State) -> Result<()> {
    write(&state_path(prefix), &serde_json::to_string_pretty(st)?)
}

/// systemd unit name (no `.service` suffix): `dstack-<base>` or, with an
/// instance, `dstack-<base>-<instance>` (so a fresh install coexists with an
/// existing `dstack-vmm.service`).
fn unit_name(base: &str, instance: &Option<String>) -> String {
    match instance {
        Some(i) if !i.is_empty() => format!("dstack-{base}-{i}"),
        _ => format!("dstack-{base}"),
    }
}

/// spawn an external tool (systemctl/docker/curl) with a sanitized `PATH`, so a
/// hijacked environment can't substitute a different binary while we run as root.
fn tool(bin: &str) -> PCommand {
    let mut c = PCommand::new(bin);
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

fn systemctl(args: &[&str]) -> bool {
    tool("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// size of a VMM's CID pool (matches `config::VmmRender` default).
const CID_POOL_SIZE: u32 = 1000;
/// default CID pool start when nothing else is using that range.
const DEFAULT_CID_START: u32 = 1000;

/// whether `[start, start+CID_POOL_SIZE)` intersects any occupied range.
fn cid_window_overlaps(start: u32, occupied: &[(u32, u32)]) -> bool {
    let end = start.saturating_add(CID_POOL_SIZE);
    occupied.iter().any(|&(s, e)| start < e && s < end)
}

/// the lowest pool-aligned CID block at or above every occupied range. We jump
/// above the highest reservation rather than packing into a free gap below it —
/// simpler, and the result is always collision-free.
fn next_free_cid_block(occupied: &[(u32, u32)]) -> u32 {
    let max_end = occupied
        .iter()
        .map(|&(_, e)| e)
        .max()
        .unwrap_or(DEFAULT_CID_START);
    (max_end.div_ceil(CID_POOL_SIZE) * CID_POOL_SIZE).max(DEFAULT_CID_START)
}

/// choose a CID window `[start, start+CID_POOL_SIZE)` that won't collide with a
/// VMM already running on this host. With an explicit `--cid-start`, honor it
/// but refuse on overlap; without one, use the default unless it's taken, then
/// move to the next free block.
fn pick_cid_start(explicit: Option<u32>, occupied: &[(u32, u32)]) -> Result<u32> {
    match explicit {
        Some(n) => {
            if cid_window_overlaps(n, occupied) {
                bail!(
                    "--cid-start {n} overlaps a CID range already reserved on this host; \
                     pick a free start, e.g. --cid-start {}",
                    next_free_cid_block(occupied)
                );
            }
            Ok(n)
        }
        None if !cid_window_overlaps(DEFAULT_CID_START, occupied) => Ok(DEFAULT_CID_START),
        None => {
            let start = next_free_cid_block(occupied);
            println!("  [ok] cid-start {start} (avoids CIDs already reserved by another VMM)");
            Ok(start)
        }
    }
}

fn unit_active(unit: &str) -> bool {
    systemctl(&["is-active", "--quiet", &format!("{unit}.service")])
}

/// write a unit file, reload systemd, and enable+start it (idempotent).
fn install_unit(unit: &str, contents: &str) -> Result<()> {
    let path = format!("/etc/systemd/system/{unit}.service");
    fs::write(&path, contents).with_context(|| format!("writing {path}"))?;
    systemctl(&["daemon-reload"]);
    if !systemctl(&["enable", "--now", &format!("{unit}.service")]) {
        bail!("failed to enable+start {unit}.service");
    }
    Ok(())
}

/// stop, disable, and remove a unit (idempotent — missing unit is fine).
fn remove_unit(unit: &str) {
    let svc = format!("{unit}.service");
    let _ = systemctl(&["disable", "--now", &svc]);
    let _ = fs::remove_file(format!("/etc/systemd/system/{svc}"));
}

fn auth_unit_file(bin: &str, allowlist: &Path, port: u16, prefix: &Path) -> String {
    // bind 127.0.0.1 deliberately: the webhook decides key release, so it must
    // never be reachable off-host. CVMs still reach it at 10.0.2.2:<port> via
    // user-mode networking (NAT), which maps to the host loopback.
    format!(
        "[Unit]\nDescription=dstack auth webhook\nAfter=network.target\n\n[Service]\n\
         ExecStart={bin} --config {cfg} --address 127.0.0.1 --port {port}\n\
         Restart=always\nRestartSec=2\nWorkingDirectory={wd}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        cfg = allowlist.display(),
        wd = prefix.display(),
    )
}

fn vmm_unit_file(bin: &str, config: &Path, prefix: &Path, auth_unit: &str) -> String {
    // KillMode defaults to control-group, so `systemctl stop` tears down the
    // VMM + supervisor + CVM qemus together (deterministic teardown).
    format!(
        "[Unit]\nDescription=dstack VMM\nAfter=network.target docker.service {auth}.service\nWants={auth}.service\n\n\
         [Service]\nExecStart={bin} -c {cfg}\nRestart=always\nRestartSec=2\n\
         TimeoutStopSec=120\nWorkingDirectory={wd}\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        auth = auth_unit,
        cfg = config.display(),
        wd = prefix.display(),
    )
}

#[derive(Parser)]
#[command(name = "dstackup", version, about = "set up and manage a dstack host")]
struct Cli {
    /// VMM control socket / endpoint to talk to (for status and attach).
    #[arg(long, global = true)]
    host: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// `Install` carries all the host-setup flags; the size gap to `Status`/`Destroy`
// is irrelevant for a CLI enum constructed once at startup.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Bring up the host stack: SGX preflight, render configs, and start the
    /// VMM + auth webhook. (Gramine bring-up and KMS-in-CVM bootstrap follow.)
    Install {
        /// expose the dashboard on this IP (default: bind localhost only —
        /// reach it via an SSH tunnel).
        #[arg(long, value_name = "IP")]
        expose: Option<String>,

        /// guest OS image version to deploy.
        #[arg(long, value_name = "VERSION")]
        image: Option<String>,

        /// install prefix for configs, certs, run state.
        #[arg(long, default_value = "/var/lib/dstack")]
        prefix: String,

        /// systemd instance suffix: units become `dstack-vmm-<instance>` etc.,
        /// so a fresh install coexists with an existing `dstack-vmm.service`.
        #[arg(long)]
        instance: Option<String>,

        /// guest image directory (default: <prefix>/images).
        #[arg(long)]
        image_path: Option<String>,

        /// dstack-vmm binary.
        #[arg(long, default_value = "dstack-vmm")]
        vmm_bin: String,

        /// dstack-auth binary.
        #[arg(long, default_value = "dstack-auth")]
        auth_bin: String,

        /// dstack-supervisor binary.
        #[arg(long, default_value = "dstack-supervisor")]
        supervisor_bin: String,

        /// qemu binary.
        #[arg(long, default_value = "/usr/bin/qemu-system-x86_64")]
        qemu: String,

        /// dashboard TCP port.
        #[arg(long, default_value_t = 9080)]
        dashboard_port: u16,

        /// auth webhook port.
        #[arg(long, default_value_t = 8001)]
        auth_port: u16,

        /// host-api vsock port (raise to coexist with an existing VMM on 10000).
        #[arg(long, default_value_t = 10000)]
        host_api_port: u32,

        /// CID pool start (default: auto — the first free block, so it coexists
        /// with any VMM already running on this host).
        #[arg(long)]
        cid_start: Option<u32>,

        /// use an existing key provider at ADDR:PORT instead of running our own.
        #[arg(long, value_name = "ADDR:PORT")]
        use_existing_key_provider: Option<String>,

        /// port for our own key provider (when not using an existing one).
        #[arg(long, default_value_t = 3443)]
        key_provider_port: u16,

        /// key-provider build/compose directory (to start our own).
        #[arg(long)]
        key_provider_src: Option<String>,

        /// KMS container image.
        #[arg(long, default_value = config::DEFAULT_KMS_IMAGE)]
        kms_image: String,

        /// host port for the KMS RPC (default: an auto-picked free port).
        #[arg(long)]
        kms_port: Option<u16>,

        /// skip the KMS-in-CVM deploy (bring up VMM + auth only).
        #[arg(long)]
        no_kms: bool,

        /// proceed even if the app OS image can't be pinned (no digest.txt) —
        /// apps will boot any unmeasured image and still get keys. NOT recommended.
        #[arg(long)]
        allow_unpinned_image: bool,

        /// render + write configs only; do not start any process.
        #[arg(long)]
        no_start: bool,
    },
    /// Show the health of the host stack.
    Status,
    /// Tear down the deployment (keeps configs + KMS keys unless --purge).
    Destroy {
        /// install prefix to tear down.
        #[arg(long, default_value = "/var/lib/dstack")]
        prefix: String,
        /// also wipe the prefix (configs + KMS keys).
        #[arg(long)]
        purge: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host.as_deref().unwrap_or(DEFAULT_HOST);
    match cli.command {
        Command::Status => cmd_status(host).await,
        Command::Install {
            expose,
            image,
            prefix,
            instance,
            image_path,
            vmm_bin,
            auth_bin,
            supervisor_bin,
            qemu,
            dashboard_port,
            auth_port,
            host_api_port,
            cid_start,
            use_existing_key_provider,
            key_provider_port,
            key_provider_src,
            kms_image,
            kms_port,
            no_kms,
            allow_unpinned_image,
            no_start,
        } => {
            let opts = InstallOpts {
                expose,
                image,
                prefix,
                instance,
                image_path,
                vmm_bin,
                auth_bin,
                supervisor_bin,
                qemu,
                dashboard_port,
                auth_port,
                host_api_port,
                cid_start,
                use_existing_key_provider,
                key_provider_port,
                key_provider_src,
                kms_image,
                kms_port,
                no_kms,
                allow_unpinned_image,
                no_start,
            };
            let _ = host; // install uses its own prefix-derived endpoint
            cmd_install(opts).await
        }
        Command::Destroy { prefix, purge } => cmd_destroy(&prefix, purge).await,
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

struct InstallOpts {
    expose: Option<String>,
    image: Option<String>,
    prefix: String,
    instance: Option<String>,
    image_path: Option<String>,
    vmm_bin: String,
    auth_bin: String,
    supervisor_bin: String,
    qemu: String,
    dashboard_port: u16,
    auth_port: u16,
    host_api_port: u32,
    cid_start: Option<u32>,
    use_existing_key_provider: Option<String>,
    key_provider_port: u16,
    key_provider_src: Option<String>,
    kms_image: String,
    kms_port: Option<u16>,
    no_kms: bool,
    allow_unpinned_image: bool,
    no_start: bool,
}

async fn cmd_install(o: InstallOpts) -> Result<()> {
    // --expose is not safe yet: the rendered vmm.toml binds the VM-control
    // plane with neither TLS nor an auth token (the management RPCs are not
    // behind an auth guard), so exposing it would hand deploy/destroy to anyone
    // who can reach the IP. Refuse until the TLS+token transport lands; the
    // supported path is localhost + an SSH tunnel.
    if let Some(ip) = &o.expose {
        bail!(
            "--expose {ip} is not yet safe: it would bind the VM-control plane on \
             {ip}:{port} with no TLS and no auth. reach the dashboard over an SSH \
             tunnel instead: ssh -L {port}:127.0.0.1:{port} <host>",
            port = o.dashboard_port
        );
    }

    println!("dstackup install — preflight");

    // 1. hardware gate (fail fast on non-SGX hosts).
    host::require_sgx()?;
    println!("  [ok] sgx present");

    // 2. host IP (informational; used as the bind/SAN when --expose is set).
    match host::detect_host_ip() {
        Ok(ip) if host::is_link_local(&ip) => {
            println!("  [!]  host ip {ip} is link-local")
        }
        Ok(ip) => println!("  [ok] host ip: {ip}"),
        Err(e) => println!("  [!]  could not detect host ip: {e}"),
    }

    // 3. resolve paths (no side effects yet).
    let prefix = Path::new(&o.prefix);
    let run_dir = prefix.join("run");
    let images = o
        .image_path
        .clone()
        .unwrap_or_else(|| prefix.join("images").display().to_string());

    // 4. preflight — fail BEFORE any side effect (key provider, dirs, units), so
    //    a CID/port clash or a missing os-image pin can't half-install the host.
    let cid_start = pick_cid_start(o.cid_start, &host::occupied_cid_ranges())?;
    preflight_ports(&o)?;
    let os_image_hash = resolve_image_pin(&o, &images)?;

    // 5. lay out the prefix.
    for dir in [prefix.to_path_buf(), prefix.join("certs"), run_dir.clone()] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    // 6. resolve the key provider — run our own unless told to use an existing one.
    let (kp_addr, kp_port, kp_own_project) = resolve_key_provider(&o)?;

    // read prior state up front so re-runs are idempotent.
    let mut st = read_state(prefix).unwrap_or_default();

    // KMS host port + URL, known up front so the VMM can inject kms_urls into
    // app CVMs (the guest reaches the KMS at 10.0.2.2:<port> via user-net).
    let kms_port: u16 = if o.no_kms {
        0
    } else if let Some(p) = o.kms_port {
        p
    } else if let Some(p) = st.kms_url.rsplit(':').next().and_then(|s| s.parse().ok()) {
        p // reuse the port a prior install assigned
    } else {
        ports::free_local_port()?
    };
    let kms_urls = if o.no_kms {
        vec![]
    } else {
        vec![format!("https://10.0.2.2:{kms_port}")]
    };

    // 7. render configs.
    let bind = o.expose.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    let dashboard_addr = format!("tcp:{bind}:{}", o.dashboard_port);
    let client_url = format!("http://{bind}:{}", o.dashboard_port);

    let vmm = config::vmm_toml(&VmmRender {
        dashboard_addr: dashboard_addr.clone(),
        image_path: images.clone(),
        qemu_path: o.qemu.clone(),
        run_dir: run_dir.display().to_string(),
        vm_path: prefix.join("vm").display().to_string(),
        supervisor_exe: o.supervisor_bin.clone(),
        cid_start,
        host_api_port: o.host_api_port,
        key_provider_addr: kp_addr,
        key_provider_port: kp_port as u32,
        kms_urls: kms_urls.clone(),
        ..Default::default()
    });
    // the KMS-in-CVM reaches the host auth webhook at 10.0.2.2:<auth_port>.
    // The KMS's own image download-verify stays off for the single-node flow
    // (it would need a published image source), but we PIN the app OS image in
    // the webhook allowlist (resolved in preflight, fail-closed): digest.txt
    // holds the measured image hash the KMS reports for an app, so an app cannot
    // boot under a different, unmeasured image and still receive keys.
    // bootAuth/kms ignores osImages, so the KMS bootstrap itself is unaffected.
    let host_cfg = HostConfig {
        auth_webhook_url: format!("http://10.0.2.2:{}", o.auth_port),
        os_image_hash: os_image_hash.unwrap_or_default(),
        verify_os_image: false,
        ..Default::default()
    };
    let kms = config::kms_toml(&host_cfg);
    let allowlist = config::auth_allowlist_json(&host_cfg);

    let vmm_path = prefix.join("vmm.toml");
    let kms_path = prefix.join("kms.toml");
    let allow_path = prefix.join("auth-allowlist.json");
    write(&vmm_path, &vmm)?;
    write(&kms_path, &kms)?;
    write(&allow_path, &allowlist)?;
    println!(
        "  [ok] wrote {}, {}, {}",
        vmm_path.display(),
        kms_path.display(),
        allow_path.display()
    );

    if o.no_start {
        println!("  (--no-start: configs written; not starting any process)");
        return Ok(());
    }

    st.prefix = prefix.display().to_string();
    st.client_url = client_url.clone();
    st.auth_port = o.auth_port;
    let auth_unit = unit_name("auth", &o.instance);
    let vmm_unit = unit_name("vmm", &o.instance);

    // 8. auth webhook systemd unit (idempotent).
    if unit_active(&auth_unit) {
        println!("  [ok] {auth_unit}.service already active");
    } else {
        install_unit(
            &auth_unit,
            &auth_unit_file(&o.auth_bin, &allow_path, o.auth_port, prefix),
        )
        .context("installing the auth webhook unit")?;
        println!(
            "  [ok] started {auth_unit}.service on 127.0.0.1:{}",
            o.auth_port
        );
    }
    st.auth_unit = auth_unit.clone();

    // 9. VMM systemd unit (idempotent).
    if vmm_reachable(&client_url).await {
        println!("  [ok] VMM already serving at {client_url}");
    } else {
        install_unit(
            &vmm_unit,
            &vmm_unit_file(&o.vmm_bin, &vmm_path, prefix, &auth_unit),
        )
        .context("installing the VMM unit")?;
        println!("  [ok] started {vmm_unit}.service");
        print!("  [..] waiting for VMM at {client_url} ");
        if wait_ready(&client_url, Duration::from_secs(25)).await {
            println!("=> ready");
        } else {
            println!("=> not ready within timeout (journalctl -u {vmm_unit})");
        }
    }
    st.vmm_unit = vmm_unit.clone();

    // persist what we have so far (so a later step / destroy can see it).
    st.kp_own_project = kp_own_project;
    write_state(prefix, &st)?;

    // 10. deploy + bootstrap the KMS-in-CVM (idempotent).
    if o.no_kms {
        println!("  (--no-kms: skipping KMS deploy)");
    } else {
        let vmm = Vmm::connect(&client_url)?;
        let existing = match &st.kms_vm_id {
            Some(id) if vmm.has_vm(id).await => Some(id.clone()),
            _ => None,
        };
        if let Some(id) = existing {
            println!("  [ok] KMS CVM already deployed (vm {id})");
        } else {
            let img = o
                .image
                .clone()
                .context("kms deploy needs --image <version> (or pass --no-kms)")?;
            let compose = config::kms_app_compose(&kms, &o.kms_image);
            let cfg = rpc::VmConfiguration {
                name: "dstack-kms".into(),
                image: img.clone(),
                compose_file: compose,
                vcpu: 4,
                memory: 8192,
                disk_size: 20,
                ports: vec![rpc::PortMapping {
                    protocol: "tcp".into(),
                    host_address: "127.0.0.1".into(),
                    host_port: kms_port as u32,
                    vm_port: 8000,
                }],
                ..Default::default()
            };
            println!("  [..] deploying KMS CVM (os {img}, kms {})", o.kms_image);
            let vm_id = vmm
                .create_vm(cfg)
                .await
                .context("createVm for the kms cvm failed")?;
            print!("  [..] waiting for KMS bootstrap on :{kms_port} ");
            if wait_kms_ready(kms_port, Duration::from_secs(240)).await {
                println!("=> bootstrapped");
            } else {
                println!("=> not ready in time (check `dstack logs {vm_id}` / VMM log)");
            }
            st.kms_vm_id = Some(vm_id);
            st.kms_url = format!("https://10.0.2.2:{kms_port}");
            write_state(prefix, &st)?;
        }
    }

    println!();
    println!("dashboard: {client_url}  (localhost — reach it via an SSH tunnel)");
    if !st.kms_url.is_empty() {
        println!(
            "kms:       {}  (apps reach it via this address)",
            st.kms_url
        );
    }
    println!(
        "deploy an app with: dstack --host {client_url} run <compose> --image {} --port <vm_port> --allowlist {}",
        o.image.as_deref().unwrap_or("<ver>"),
        allow_path.display()
    );
    Ok(())
}

/// resolve the key provider for this install. Returns (addr, port, own_project).
fn resolve_key_provider(o: &InstallOpts) -> Result<(String, u16, Option<String>)> {
    if let Some(ep) = &o.use_existing_key_provider {
        let (addr, port) = split_addr_port(ep)?;
        println!("  [ok] using existing key provider at {addr}:{port}");
        return Ok((addr, port, None));
    }
    // run our own (default).
    let src = o.key_provider_src.as_deref().context(
        "no key provider: pass --use-existing-key-provider ADDR:PORT, or --key-provider-src DIR to run our own",
    )?;
    let project = format!("dstack-kp-{}", o.key_provider_port);
    let status = tool("docker")
        .args([
            "compose",
            "-p",
            &project,
            "-f",
            &format!("{src}/docker-compose.yaml"),
            "up",
            "-d",
        ])
        .status()
        .context("running docker compose for the key provider")?;
    if !status.success() {
        bail!("failed to start our own key provider (docker compose up)");
    }
    println!(
        "  [ok] started our own key provider (project {project}, :{})",
        o.key_provider_port
    );
    Ok(("127.0.0.1".to_string(), o.key_provider_port, Some(project)))
}

fn split_addr_port(ep: &str) -> Result<(String, u16)> {
    let (addr, port) = ep
        .rsplit_once(':')
        .with_context(|| format!("expected ADDR:PORT, got '{ep}'"))?;
    Ok((
        addr.to_string(),
        port.parse()
            .with_context(|| format!("bad port in '{ep}'"))?,
    ))
}

/// read the measured OS-image hash from the guest image's `digest.txt`
/// (`<images>/<image>/digest.txt`), used to pin which image apps may boot.
/// Returns None when there's no image selected or no readable digest.
fn resolve_os_image_hash(images: &str, image: Option<&str>) -> Option<String> {
    let img = image?;
    let path = Path::new(images).join(img).join("digest.txt");
    let hash = fs::read_to_string(path).ok()?.trim().to_string();
    (!hash.is_empty()).then_some(hash)
}

/// resolve the OS-image pin, failing CLOSED: in KMS mode a missing/empty
/// `digest.txt` is a hard error (an unpinned app could boot any unmeasured
/// image and still get keys), unless the operator opts out with
/// `--allow-unpinned-image`. Returns Some(hash) to pin, or None when pinning is
/// deliberately off (`--no-kms`, or the explicit opt-out).
fn resolve_image_pin(o: &InstallOpts, images: &str) -> Result<Option<String>> {
    let hash = resolve_os_image_hash(images, o.image.as_deref());
    match &hash {
        Some(h) => println!("  [ok] pinning app os image {h}"),
        None if o.no_kms => {}
        None if o.allow_unpinned_image => {
            println!("  [!]  app os image NOT pinned (--allow-unpinned-image) — apps' image is unchecked")
        }
        None => bail!(
            "no os-image pin: could not read a digest.txt for image {:?} under {images} — an app \
             could boot any unmeasured image and still get keys. fix --image/--image-path, or pass \
             --allow-unpinned-image to proceed unpinned (not recommended)",
            o.image.as_deref().unwrap_or("<none>")
        ),
    }
    Ok(hash)
}

/// fail BEFORE any side effect if a port we need is already taken, so a clash
/// refuses cleanly instead of half-installing. CIDs auto-offset (see
/// `pick_cid_start`); ports are user-facing, so we refuse with guidance rather
/// than silently moving the address the operator will connect to.
fn preflight_ports(o: &InstallOpts) -> Result<()> {
    let bind = o.expose.clone().unwrap_or_else(|| "127.0.0.1".to_string());
    for (what, flag, port) in [
        ("dashboard", "--dashboard-port", o.dashboard_port),
        ("auth webhook", "--auth-port", o.auth_port),
    ] {
        if !ports::tcp_port_free(&bind, port) {
            bail!("{what} port {bind}:{port} is already in use; pass {flag} <free-port>");
        }
    }
    if !o.no_kms && host::other_vmm_host_api_ports().contains(&o.host_api_port) {
        bail!(
            "host-api vsock port {} is already reserved by another dstack-vmm; pass --host-api-port <free-port>",
            o.host_api_port
        );
    }
    Ok(())
}

/// poll the KMS `GetMeta` RPC (self-signed TLS) via curl until it bootstraps.
async fn wait_kms_ready(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if kms_get_meta_ok(port) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// is the KMS bootstrapped and answering on `port`? curl (not the typed
/// client) because the KMS serves self-signed RA-TLS we deliberately don't
/// verify here (`-k`); but require curl to actually succeed AND a parsed,
/// non-empty `ca_cert` field — so an error body or a partial response that
/// merely contains the substring can't read as "ready". A real success here
/// also confirms it's our KMS bound to this exact port (port-verification).
fn kms_get_meta_ok(port: u16) -> bool {
    let out = tool("curl")
        .args([
            "-sk",
            "--max-time",
            "4",
            "-X",
            "POST",
            &format!("https://127.0.0.1:{port}/prpc/KMS.GetMeta?json"),
            "-d",
            "{}",
        ])
        .output();
    let Ok(out) = out else { return false };
    if !out.status.success() {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|v| {
            v.get("ca_cert")
                .and_then(|c| c.as_str())
                .map(|s| !s.is_empty())
        })
        .unwrap_or(false)
}

/// tear down what `install` started; idempotent. Keeps the prefix (configs +
/// KMS keys) unless `--purge`.
async fn cmd_destroy(prefix: &str, purge: bool) -> Result<()> {
    let prefix = Path::new(prefix);
    println!("dstackup destroy ({})", prefix.display());
    match read_state(prefix) {
        Some(st) => {
            // gracefully stop the KMS CVM first so its keys flush to disk
            // (unless we purge). Stopping the VMM unit below reaps the supervisor
            // and the CVM qemu via the unit's cgroup. Look it up by recorded id
            // AND by name, so an install that died before persisting kms_vm_id
            // (or a torn state file) doesn't leave the CVM orphaned.
            if let Ok(vmm) = Vmm::connect(&st.client_url) {
                let mut target = st.kms_vm_id.clone();
                if target.is_none() {
                    if let Ok(s) = vmm.status().await {
                        target = s
                            .vms
                            .iter()
                            .find(|v| v.name == "dstack-kms")
                            .map(|v| v.id.clone());
                    }
                }
                if let Some(id) = target {
                    if vmm.has_vm(&id).await {
                        let _ = vmm.stop_vm(&id).await;
                        println!("  stopping KMS CVM (vm {id})");
                    }
                }
            }
            // stop + remove the units. `systemctl stop` is synchronous and tears
            // down the whole unit cgroup (VMM + supervisor + CVM qemu), so the
            // host is back to baseline when this returns.
            if !st.vmm_unit.is_empty() {
                remove_unit(&st.vmm_unit);
                println!("  stopped {}.service", st.vmm_unit);
            }
            if !st.auth_unit.is_empty() {
                remove_unit(&st.auth_unit);
                println!("  stopped {}.service", st.auth_unit);
            }
            systemctl(&["daemon-reload"]);
            // stop our own key provider, if we started one.
            if let Some(project) = &st.kp_own_project {
                let _ = tool("docker")
                    .args(["compose", "-p", project, "down"])
                    .status();
                println!("  stopped key provider (project {project})");
            }
            // remove the runtime-state marker so a later install starts fresh.
            let _ = fs::remove_file(state_path(prefix));
        }
        None => println!(
            "  no install state at {} (nothing running to stop)",
            prefix.display()
        ),
    }

    if purge {
        if prefix.exists() {
            fs::remove_dir_all(prefix).with_context(|| format!("purging {}", prefix.display()))?;
            println!("  purged {} (configs + KMS keys wiped)", prefix.display());
        }
    } else {
        println!(
            "  configs + KMS keys kept at {} (use --purge to wipe)",
            prefix.display()
        );
    }
    Ok(())
}

/// write a file atomically (temp + rename), so a crash mid-write never leaves
/// a torn config or state file.
fn write(path: &Path, body: &str) -> Result<()> {
    dstack_core::fsutil::write_atomic(path, body)
        .with_context(|| format!("writing {}", path.display()))
}

/// one-shot liveness probe of the VMM.
async fn vmm_reachable(client_url: &str) -> bool {
    match Vmm::connect(client_url) {
        Ok(vmm) => vmm.status().await.is_ok(),
        Err(_) => false,
    }
}

/// poll the VMM `Status` RPC until it succeeds or the deadline passes.
async fn wait_ready(client_url: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(vmm) = Vmm::connect(client_url) {
            if vmm.status().await.is_ok() {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_default_when_range_free() {
        assert_eq!(pick_cid_start(None, &[]).unwrap(), 1000);
        // a pool entirely above the default window leaves it free.
        assert_eq!(pick_cid_start(None, &[(2000, 3000)]).unwrap(), 1000);
    }

    #[test]
    fn cid_auto_offsets_past_an_existing_vmm() {
        // another VMM reserving [1000,2000) -> jump to 2000.
        assert_eq!(pick_cid_start(None, &[(1000, 2000)]).unwrap(), 2000);
        // its reserved pool plus a stray live CVM at 2500 -> jump past it.
        assert_eq!(
            pick_cid_start(None, &[(1000, 2000), (2500, 2501)]).unwrap(),
            3000
        );
    }

    #[test]
    fn cid_explicit_honored_or_refused() {
        assert_eq!(pick_cid_start(Some(2000), &[(1000, 2000)]).unwrap(), 2000);
        assert!(pick_cid_start(Some(1000), &[(1000, 2000)]).is_err());
    }
}
