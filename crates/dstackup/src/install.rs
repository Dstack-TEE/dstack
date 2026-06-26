// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstackup install` — bring up the host stack and bootstrap the KMS-in-CVM.

use crate::cid::pick_cid_start;
use crate::cli::InstallOpts;
use crate::state::{read_state, write, write_state};
use crate::systemd::{auth_unit_file, install_unit, tool, unit_active, unit_name, vmm_unit_file};
use anyhow::{bail, Context, Result};
use dstack_cli_core::config::{self, HostConfig, VmmRender};
use dstack_cli_core::host::Platform;
use dstack_cli_core::vmm::Vmm;
use dstack_cli_core::{host, ports, rpc};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub(crate) async fn cmd_install(o: InstallOpts) -> Result<()> {
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

    // 1. resolve the platform (auto-detects the host) and gate on the host
    //    actually supporting it: TDX needs SGX (local key provider); SNP needs
    //    /dev/sev.
    let platform = match host::Platform::parse_opt(&o.platform)? {
        Some(p) => p,
        None => host::Platform::detect().unwrap_or(host::Platform::Tdx),
    };
    host::require_platform(platform)?;
    println!("  [ok] platform: {}", platform.vmm_str());

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
    let os_image_hash = resolve_image_pin(&o, &images, platform)?;

    // 5. lay out the prefix.
    for dir in [prefix.to_path_buf(), prefix.join("certs"), run_dir.clone()] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    // 6. resolve the key provider — run our own unless told to use an existing
    //    one (TDX only; SNP has no SGX gramine provider).
    let (kp_addr, kp_port, kp_own_project) = resolve_key_provider(&o, platform)?;

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
        platform,
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
        platform,
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
            let compose = config::kms_app_compose(&kms, &o.kms_image, platform);
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
fn resolve_key_provider(
    o: &InstallOpts,
    platform: Platform,
) -> Result<(String, u16, Option<String>)> {
    if let Some(ep) = &o.use_existing_key_provider {
        let (addr, port) = split_addr_port(ep)?;
        println!("  [ok] using existing key provider at {addr}:{port}");
        return Ok((addr, port, None));
    }
    // AMD SEV-SNP has no SGX gramine key provider; the rendered [key_provider]
    // block is unused (the KMS-in-CVM runs with local_key_provider_enabled =
    // false), so don't require or start one.
    if platform == Platform::AmdSevSnp {
        println!("  [ok] no local key provider (sev-snp)");
        return Ok(("127.0.0.1".to_string(), o.key_provider_port, None));
    }
    // TDX: run our own gramine provider (default).
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
fn resolve_os_image_hash(images: &str, image: Option<&str>, platform: Platform) -> Option<String> {
    let img = image?;
    // SNP measures a different image, recorded in digest.sev.txt; TDX uses digest.txt.
    let digest_file = match platform {
        Platform::AmdSevSnp => "digest.sev.txt",
        Platform::Tdx => "digest.txt",
    };
    let path = Path::new(images).join(img).join(digest_file);
    let hash = fs::read_to_string(path).ok()?.trim().to_string();
    (!hash.is_empty()).then_some(hash)
}

/// resolve the OS-image pin, failing CLOSED: in KMS mode a missing/empty
/// `digest.txt` is a hard error (an unpinned app could boot any unmeasured
/// image and still get keys), unless the operator opts out with
/// `--allow-unpinned-image`. Returns Some(hash) to pin, or None when pinning is
/// deliberately off (`--no-kms`, or the explicit opt-out).
fn resolve_image_pin(o: &InstallOpts, images: &str, platform: Platform) -> Result<Option<String>> {
    let hash = resolve_os_image_hash(images, o.image.as_deref(), platform);
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
